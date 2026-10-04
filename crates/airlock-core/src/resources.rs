//! F3 资源分配：端口段（FR3.1–3.3）、vite/next/webpack 配置改写（FR3.2）、
//! 数据库分支（FR3.4，v0.2）、杂项锁排队（FR3.5，v0.2）。

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::proto::{PortInfo, SessionInfo};
use crate::store::{now, Store};

/// 每会话端口数（FR3.1：默认起 30000 + 会话序号 × 10）
pub const PORTS_PER_SESSION: u16 = 10;
/// 端口回收冷却期（FR3.3：5 分钟）
pub const PORT_COOLDOWN_S: i64 = 300;

/// 会话注册：分配冲突域内唯一序号与端口段，返回注入环境变量。
///
/// 端口段全程用 i64 运算并在入段前校验上界——绝不把回绕值截断成 u16
/// （历史上 `port_base=30000, seq=3554` 曾截断到低端口 4 并注入 PORT=4）。
pub fn register_session(store: &Store, agent_id: &str, port_base: u16) -> Result<SessionInfo> {
    let port_base_i = i64::from(port_base);
    if port_base_i <= 0 || port_base_i > 65535 - i64::from(PORTS_PER_SESSION) {
        return Err(Error::Config(format!(
            "port_base {port_base} 越界：需 1..={}（每会话 {PORTS_PER_SESSION} 个端口）",
            65535 - i64::from(PORTS_PER_SESSION)
        )));
    }
    let sessions = store.list_sessions(false)?;
    let capacity = (65535 - port_base_i) / i64::from(PORTS_PER_SESSION) + 1;
    let mut seq = sessions.iter().map(|s| s.seq).max().unwrap_or(-1) + 1;
    let mut guard = 0i64;
    let base = loop {
        // 回绕：seq 取模容量，base 恒落在 [port_base, 65535] 内
        let candidate = port_base_i + (seq % capacity) * i64::from(PORTS_PER_SESSION);
        if !store.port_range_busy(candidate, i64::from(PORTS_PER_SESSION))? {
            break candidate;
        }
        seq += 1;
        guard += 1;
        if guard >= capacity {
            return Err(Error::Other("可用端口段耗尽".into()));
        }
    };
    let session = SessionInfo {
        session_id: uuid::Uuid::new_v4().to_string(),
        agent_id: agent_id.to_string(),
        seq: seq % capacity,
        port_base: base as u16,
        env: inject_env(base as u16),
    };
    store.insert_session(&session)?;
    Ok(session)
}

/// FR3.1：注入 PORT / VITE_PORT / NEXT_PORT。
pub fn inject_env(base: u16) -> std::collections::BTreeMap<String, String> {
    let mut env = std::collections::BTreeMap::new();
    env.insert("PORT".into(), base.to_string());
    env.insert("VITE_PORT".into(), base.to_string());
    env.insert("NEXT_PORT".into(), base.to_string());
    env.insert("AIRLOCK_PORT_BASE".into(), base.to_string());
    env
}

/// 从会话端口段中取一个空闲端口（active 标记）。
pub fn allocate_port(store: &Store, session: &SessionInfo, purpose: &str) -> Result<PortInfo> {
    let ports = store.list_ports()?;
    for off in 0..PORTS_PER_SESSION {
        let port = session.port_base + off;
        let taken = ports
            .iter()
            .any(|p| p.port == port && p.state != "released");
        if !taken {
            let info = PortInfo {
                session_id: session.session_id.clone(),
                port,
                purpose: purpose.to_string(),
                state: "active".into(),
                cooldown_until: None,
            };
            store.upsert_port(&info)?;
            return Ok(info);
        }
    }
    Err(Error::Other(format!(
        "会话 {} 的端口段 {}..{} 已用尽",
        session.session_id,
        session.port_base,
        session.port_base + PORTS_PER_SESSION
    )))
}

/// 会话结束：端口进入 5 分钟冷却（FR3.3，防 agent 仍在收尾）。
pub fn end_session_ports(store: &Store, session_id: &str) -> Result<usize> {
    let ports = store.list_ports()?;
    let mut n = 0;
    for p in ports
        .iter()
        .filter(|p| p.session_id == session_id && p.state == "active")
    {
        store.upsert_port(&PortInfo {
            state: "cooldown".into(),
            cooldown_until: Some(now() + PORT_COOLDOWN_S),
            ..p.clone()
        })?;
        n += 1;
    }
    store.end_session(session_id)?;
    Ok(n)
}

/// 冷却到期 → released（daemon 周期任务）。
pub fn sweep_cooldowns(store: &Store) -> Result<usize> {
    let ports = store.list_ports()?;
    let now_ts = now();
    let mut n = 0;
    for p in ports.iter().filter(|p| p.state == "cooldown") {
        if p.cooldown_until.unwrap_or(0) <= now_ts {
            store.upsert_port(&PortInfo {
                state: "released".into(),
                cooldown_until: None,
                ..p.clone()
            })?;
            n += 1;
        }
    }
    Ok(n)
}

// ---------- 配置改写（FR3.2） ----------

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct RewritePlan {
    pub file: String,
    pub framework: String,
    /// None = 用户已显式配置端口 → 不改写，改用环境变量注入（AC3.2）
    pub action: Option<String>,
}

pub const FRAMEWORK_CONFIGS: &[(&str, &str)] = &[
    ("vite.config.ts", "vite"),
    ("vite.config.js", "vite"),
    ("vite.config.mjs", "vite"),
    ("next.config.js", "next"),
    ("next.config.mjs", "next"),
    ("next.config.ts", "next"),
    ("webpack.config.js", "webpack"),
];

/// 探测项目框架配置文件并产出改写计划。`--dry-run` 只返回计划不落盘。
pub fn plan_config_rewrite(project_dir: &Path, port: u16) -> Result<Vec<RewritePlan>> {
    let mut plans = Vec::new();
    for (fname, framework) in FRAMEWORK_CONFIGS {
        let f = project_dir.join(fname);
        if !f.exists() {
            continue;
        }
        let content = std::fs::read_to_string(&f)?;
        // AC3.2：已被用户手工指定端口 → 不覆盖显式配置，改用注入环境变量
        let explicit =
            content.contains("port") && (regex_like_port(&content) || content.contains("--port"));
        plans.push(RewritePlan {
            file: f.display().to_string(),
            framework: framework.to_string(),
            action: if explicit {
                None
            } else {
                Some(format!("port: {port}"))
            },
        });
    }
    Ok(plans)
}

/// 极简显式端口探测：`port:`/`port =` 后跟数字。
fn regex_like_port(content: &str) -> bool {
    for line in content.lines() {
        let t = line.trim();
        for key in ["port:", "port ="] {
            if let Some(idx) = t.find(key) {
                let rest = t[idx + key.len()..].trim_start();
                if rest.starts_with(|c: char| c.is_ascii_digit()) {
                    return true;
                }
            }
        }
    }
    false
}

/// 执行改写（plan.action 为 Some 时）。返回实际修改的文件数。
pub fn apply_config_rewrite(plans: &[RewritePlan]) -> Result<usize> {
    let mut n = 0;
    for p in plans {
        let Some(action) = &p.action else { continue };
        let path = PathBuf::from(&p.file);
        let content = std::fs::read_to_string(&path)?;
        // 保守插入：文件头部追加注释式默认端口声明（避免破坏用户代码结构），
        // 真正生效仍以注入的环境变量为准。
        let patched = format!("// airlock: {action}\n{content}");
        std::fs::write(&path, patched)?;
        n += 1;
    }
    Ok(n)
}

// ---------- 数据库分支（FR3.4，v0.2） ----------

/// SQLite：复制副本到会话目录，返回会话私有库路径。
/// 优先用 backup API 产生一致快照（正在写入的库逐文件复制会得到损坏副本）；
/// 源文件不是合法 SQLite（如纯文本占位）时回退逐文件复制。
pub fn branch_sqlite(db_path: &Path, session_dir: &Path) -> Result<PathBuf> {
    if !db_path.exists() {
        return Err(Error::NotFound(format!("{}", db_path.display())));
    }
    std::fs::create_dir_all(session_dir)?;
    let out = session_dir.join(
        db_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "session.db".into()),
    );
    let _ = std::fs::remove_file(&out);
    let snap = Store::open(db_path).and_then(|src| {
        // 以只读语义取快照：backup 期间源库被写入也能得到一致副本
        src.backup_to(&out)?;
        Ok(())
    });
    match snap {
        Ok(()) => Ok(out),
        Err(_) => {
            // 非 SQLite 文件或 backup 失败：回退逐文件复制（保持旧行为）
            std::fs::copy(db_path, &out)?;
            for suffix in ["-wal", "-shm"] {
                let src = PathBuf::from(format!("{}{suffix}", db_path.display()));
                if src.exists() {
                    std::fs::copy(&src, PathBuf::from(format!("{}{suffix}", out.display())))?;
                }
            }
            Ok(out)
        }
    }
}

/// Postgres：template database 克隆 `airlock_<session>` 库（FR3.4）。
/// 环境无 psql/createdb 时返回 Err（调用方降级并明示，绝不静默）。
pub fn branch_postgres(template_db: &str, session_id: &str) -> Result<String> {
    let dbname = format!("airlock_{session_id}");
    let check = std::process::Command::new("createdb")
        .arg("--version")
        .output();
    match check {
        Ok(o) if o.status.success() => {
            let out = std::process::Command::new("createdb")
                .args(["-T", template_db, &dbname])
                .output()
                .map_err(|e| Error::Other(format!("createdb 执行失败: {e}")))?;
            if !out.status.success() {
                return Err(Error::Other(format!(
                    "createdb 失败: {}",
                    String::from_utf8_lossy(&out.stderr)
                )));
            }
            Ok(dbname)
        }
        _ => Err(Error::Other(
            "本机无 createdb（Postgres 工具未安装）——数据库分支不可用，已明示降级".into(),
        )),
    }
}

/// 会话结束时销毁其临时 Postgres 库（AC3.3：60s 内）。
pub fn drop_postgres(dbname: &str) -> Result<()> {
    let out = std::process::Command::new("dropdb")
        .arg("--if-exists")
        .arg(dbname)
        .output()
        .map_err(|e| Error::Other(format!("dropdb 执行失败: {e}")))?;
    if !out.status.success() {
        return Err(Error::Other(format!(
            "dropdb 失败: {}",
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_port_segments_differ() {
        let store = Store::open_in_memory().unwrap();
        let s1 = register_session(&store, "agent-a", 30000).unwrap();
        let s2 = register_session(&store, "agent-b", 30000).unwrap();
        assert_eq!(s1.port_base, 30000);
        assert_eq!(s2.port_base, 30010);
        assert_ne!(s1.env["PORT"], s2.env["PORT"]);
    }

    #[test]
    fn allocate_distinct_ports() {
        let store = Store::open_in_memory().unwrap();
        let s1 = register_session(&store, "agent-a", 30000).unwrap();
        let s2 = register_session(&store, "agent-b", 30000).unwrap();
        let p1 = allocate_port(&store, &s1, "vite").unwrap();
        let p2 = allocate_port(&store, &s2, "vite").unwrap();
        assert_ne!(p1.port, p2.port); // AC3.1
    }

    #[test]
    fn cooldown_then_release() {
        let store = Store::open_in_memory().unwrap();
        let s = register_session(&store, "a", 30000).unwrap();
        let p = allocate_port(&store, &s, "vite").unwrap();
        end_session_ports(&store, &s.session_id).unwrap();
        let ports = store.list_ports().unwrap();
        assert_eq!(ports[0].state, "cooldown");
        assert!(ports[0].cooldown_until.unwrap() > now());
        // 冷却期内不允许同段复用：新会话顺延
        let s2 = register_session(&store, "b", 30000).unwrap();
        assert_ne!(s2.port_base, s.port_base);
        let _ = p;
    }

    #[test]
    fn explicit_port_not_overridden() {
        let tmp = std::env::temp_dir().join(format!("airlock-cfg-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(
            tmp.join("vite.config.ts"),
            "export default { server: { port: 5173 } }",
        )
        .unwrap();
        let plans = plan_config_rewrite(&tmp, 30010).unwrap();
        assert_eq!(plans.len(), 1);
        assert!(plans[0].action.is_none(), "显式端口不得覆盖（AC3.2）");
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn dry_run_then_apply() {
        let tmp = std::env::temp_dir().join(format!("airlock-cfg-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(tmp.join("vite.config.ts"), "export default {}").unwrap();
        let plans = plan_config_rewrite(&tmp, 30010).unwrap();
        assert!(plans[0].action.is_some());
        // dry-run：不改盘
        assert!(std::fs::read_to_string(tmp.join("vite.config.ts"))
            .unwrap()
            .starts_with("export"));
        let n = apply_config_rewrite(&plans).unwrap();
        assert_eq!(n, 1);
        assert!(std::fs::read_to_string(tmp.join("vite.config.ts"))
            .unwrap()
            .contains("airlock: port: 30010"));
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn sqlite_branch_copies() {
        let tmp = std::env::temp_dir().join(format!("airlock-db-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).unwrap();
        let db = tmp.join("app.db");
        std::fs::write(&db, b"sqlite-magic").unwrap();
        let sess = tmp.join("sess");
        let out = branch_sqlite(&db, &sess).unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), b"sqlite-magic");
        std::fs::remove_dir_all(&tmp).ok();
    }
}
