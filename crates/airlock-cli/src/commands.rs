//! CLI 命令实现（§5.1 命令空间）。P5：CLI/TUI/MCP 渲染同一份租约表 + 审计日志。

use std::path::{Path, PathBuf};

use airlock_core::config::Config;
use airlock_core::enforce::{
    resolve_layer, AdvisoryBackend, BpfLsmBackend, EnforcementBackend, LandlockBackend,
};
use airlock_core::error::{Error, Result};
use airlock_core::messages;
use airlock_core::paths::Domain;
use airlock_core::proto::{self, ClaimOk, StatusReport};
use airlock_core::store::{now, Store};

use crate::output::Output;

/// 客户端上下文：冲突域 + 配置 + 输出档位 + 会话（client-state 复用）。
pub struct Ctx {
    pub domain: Domain,
    pub cfg: Config,
    pub out: Output,
    pub exe: PathBuf,
    /// `--config` 指定的配置文件（自愈拉起 daemon 时透传，避免配置漂移）
    pub config_path: Option<PathBuf>,
}

impl Ctx {
    pub fn new(root: Option<&Path>, config: Option<&Path>, out: Output) -> Result<Ctx> {
        let domain =
            Domain::discover(root).map_err(|e| Error::Config(format!("无法解析冲突域: {e}")))?;
        let cfg = Config::load(config, &domain.root)?;
        let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("airlock"));
        Ok(Ctx {
            domain,
            cfg,
            out,
            exe,
            config_path: config.map(|p| p.to_path_buf()),
        })
    }

    /// 连接 daemon；不可达时按 P2/P7 fail-open 并显式警告。
    pub fn client(&self) -> Result<proto::Client> {
        proto::Client::connect(&self.domain.socket_path())
    }

    /// 连接 daemon；不可达时尝试自愈拉起（P3 零配置：MCP/agent 场景不要求用户手工起 daemon）。
    pub fn client_or_heal(&self) -> Result<proto::Client> {
        if let Ok(c) = self.client() {
            return Ok(c);
        }
        let dir = self.exe.parent().unwrap_or(std::path::Path::new("."));
        let mut cmd = std::process::Command::new(dir.join("airlockd"));
        cmd.arg("--root").arg(&self.domain.root);
        if let Some(cfg) = &self.config_path {
            // 与 CLI 同一份配置：heartbeat/TTL/enforcement 不漂移
            cmd.arg("--config").arg(cfg);
        }
        let spawned = cmd
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .is_ok();
        if spawned {
            for _ in 0..50 {
                if let Ok(c) = self.client() {
                    return Ok(c);
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
        self.client()
    }

    /// 当前会话 ID：env > client-state > 新注册（并持久化）。
    pub fn session(&self) -> Result<(String, String)> {
        let agent = std::env::var("AIRLOCK_AGENT_ID").unwrap_or_else(|_| "cli".into());
        if let Ok(sid) = std::env::var("AIRLOCK_SESSION_ID") {
            if !sid.is_empty() {
                return Ok((agent, sid));
            }
        }
        // client-state 复用
        let state_path = self.domain.dir.join("client.json");
        if let Ok(text) = std::fs::read_to_string(&state_path) {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
                if let Some(sid) = v.get("session_id").and_then(|s| s.as_str()) {
                    let stored_agent = v
                        .get("agent_id")
                        .and_then(|s| s.as_str())
                        .unwrap_or(&agent)
                        .to_string();
                    return Ok((stored_agent, sid.to_string()));
                }
            }
        }
        let mut c = self.client()?;
        let v = c.call("register", &serde_json::json!({ "agent_id": agent }))?;
        let sid = v
            .get("session_id")
            .and_then(|s| s.as_str())
            .ok_or_else(|| Error::Other("daemon 未返回 session_id".into()))?
            .to_string();
        let _ = std::fs::write(
            &state_path,
            serde_json::json!({ "session_id": sid, "agent_id": agent }).to_string(),
        );
        Ok((agent, sid))
    }
}

fn human_ts(ts: i64) -> String {
    // 带日期的 UTC 时间（跨天日志不再只有时分秒）
    airlock_core::store::ts_humane(ts)
}

fn remaining(expires_at: i64) -> String {
    let s = expires_at - now();
    if s <= 0 {
        "已过期".into()
    } else {
        format!("{:02}:{:02} 剩余", s / 60, s % 60)
    }
}

// ---------- claim ----------

pub fn claim(
    ctx: &Ctx,
    glob_pattern: &str,
    intent: Option<&str>,
    ttl: Option<&str>,
) -> Result<i32> {
    let (agent, session) = ctx.session()?;
    let mut c = ctx.client()?;
    let mut params = serde_json::json!({
        "agent_id": agent,
        "session_id": session,
        "glob": glob_pattern,
    });
    if let Some(i) = intent {
        params["intent"] = serde_json::json!(i);
    }
    if let Some(t) = ttl {
        // 时长格式（30m / 1h / 1800）在客户端解析，daemon 仍只收秒数
        let secs = crate::run::parse_ttl(t)
            .ok_or_else(|| Error::Config(format!("--ttl 无法解析：{t}（如 30m / 1h / 1800）")))?;
        params["ttl_s"] = serde_json::json!(secs);
    }
    let v = c.call("claim", &params)?;
    let ok: ClaimOk = serde_json::from_value(v)?;
    if ctx.out.json {
        println!("{}", serde_json::to_string_pretty(&ok)?);
        return Ok(0);
    }
    let line = format!(
        "{} {} ({})",
        ctx.out.green("✓ 租约已建立"),
        ok.lease.id,
        ok.lease.glob
    );
    ctx.out.println_stdout(&line);
    if ok.prediction.risk != "none" {
        ctx.out.println_stdout(&ctx.out.yellow(&format!(
            "⚠ 预测：{}（涉及租约 {}）——同目录语义冲突高发，建议确认分工",
            ok.prediction.risk,
            ok.prediction.with_leases.join(", ")
        )));
    }
    ctx.out.println_stdout(&ctx.out.grey(
        "  提示：纯 CLI 租约不自动续约（TTL 后过期）；长任务请用 `airlock run`/MCP（自动续约）或定期 `airlock heartbeat`。",
    ));
    Ok(0)
}

// ---------- release / heartbeat ----------

pub fn release(ctx: &Ctx, lease_id: Option<&str>, all: bool) -> Result<i32> {
    let (agent, session) = ctx.session()?;
    let mut c = ctx.client()?;
    let params = if all {
        serde_json::json!({ "session_id": session, "agent_id": agent })
    } else {
        let id = lease_id.ok_or_else(|| Error::Config("需要 lease_id 或 --all".into()))?;
        serde_json::json!({ "lease_id": id, "agent_id": agent, "session_id": session })
    };
    let v = c.call("release", &params)?;
    let n = v.get("released").and_then(|r| r.as_i64()).unwrap_or(0);
    ctx.out
        .either(&v, &ctx.out.green(&format!("✓ 已释放 {n} 条租约")));
    if n == 0 && !all {
        return Ok(3);
    }
    Ok(0)
}

pub fn heartbeat(ctx: &Ctx, lease_id: &str) -> Result<i32> {
    let (agent, session) = ctx.session()?;
    let mut c = ctx.client()?;
    let v = c.call(
        "heartbeat",
        &serde_json::json!({ "lease_id": lease_id, "agent_id": agent, "session_id": session }),
    )?;
    ctx.out.either(&v, &ctx.out.green("✓ 心跳已续约"));
    Ok(0)
}

pub fn report_cost(ctx: &Ctx, lease_id: &str, tokens: u64, cost_cents: u64) -> Result<i32> {
    let mut c = ctx.client()?;
    let v = c.call(
        "report_cost",
        &serde_json::json!({ "lease_id": lease_id, "tokens": tokens, "cost_cents": cost_cents }),
    )?;
    ctx.out.either(&v, &ctx.out.green("✓ 成本已上报"));
    Ok(0)
}

pub fn rollback(ctx: &Ctx, lease_id: &str) -> Result<i32> {
    let (agent, session) = ctx.session()?;
    let mut c = ctx.client()?;
    let v = c.call(
        "rollback",
        &serde_json::json!({ "lease_id": lease_id, "agent_id": agent, "session_id": session }),
    )?;
    let restored = v.get("files_restored").and_then(|r| r.as_u64()).unwrap_or(0);
    ctx.out.either(
        &v,
        &ctx.out.green(&format!("✓ 已回滚租约 {lease_id}，恢复了 {restored} 个文件")),
    );
    Ok(0)
}

pub fn list_snapshots(ctx: &Ctx) -> Result<i32> {
    let mut c = ctx.client()?;
    let v = c.call("snapshots", &serde_json::json!({}))?;
    ctx.out.either(&v, &ctx.out.green("✓ 快照列表"));
    Ok(0)
}

// ---------- status ----------

pub fn status(ctx: &Ctx, free: bool) -> Result<i32> {
    let mut c = ctx.client()?;
    let v = c.call("status", &serde_json::json!({}))?;
    let report: StatusReport = serde_json::from_value(v)?;
    if free {
        // status --free：无冲突的一级目录清单（rejection 建议引用）
        let store = Store::open(&ctx.domain.db_path())?;
        let alts = airlock_core::lease::free_alternatives(
            &store,
            &ctx.domain.root,
            &ctx.domain.id,
            "<none>",
        )?;
        if ctx.out.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({ "free_alternatives": alts }))?
            );
        } else {
            for a in alts {
                println!("{a}");
            }
        }
        return Ok(0);
    }
    if ctx.out.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(0);
    }
    let layer_badge = format!("{} ({})", report.layer.id, report.layer.name);
    ctx.out.println_stdout(&format!(
        "冲突域 {} · {} · 强制层 {}",
        report.conflict_domain,
        if report.is_git {
            "git"
        } else {
            "非 git（仅 advisory）"
        },
        if report.layer.id == "L0" {
            ctx.out.yellow(&layer_badge)
        } else {
            ctx.out.green(&layer_badge)
        }
    ));
    if let Some(gap) = report.protection_gap_s {
        ctx.out
            .println_stdout(&ctx.out.yellow(&messages::protection_gap(gap)));
    }
    ctx.out.println_stdout("租约：");
    for l in &report.leases {
        let state_disp = if l.state == "active" {
            remaining(l.expires_at)
        } else {
            ctx.out.grey(&l.state)
        };
        let intent = l.intent.as_deref().unwrap_or("-");
        ctx.out.println_stdout(&format!(
            "  {} {} {:<12} {}  intent: {intent}",
            l.agent_id,
            l.glob,
            state_disp,
            ctx.out.grey(&format!("({})", short_id(&l.id)))
        ));
    }
    if report.leases.is_empty() {
        ctx.out.println_stdout(&ctx.out.grey("  （无）"));
    }
    let ports: Vec<String> = report
        .ports
        .iter()
        .map(|p| format!("{} :{} {}", short_id(&p.session_id), p.port, p.purpose))
        .collect();
    ctx.out
        .println_stdout(&format!("资源：{}", ports.join("  ")));
    Ok(0)
}

fn short_id(id: &str) -> String {
    id.chars().take(8).collect()
}

// ---------- log ----------

pub fn log(ctx: &Ctx, verify: bool, since: Option<&str>) -> Result<i32> {
    let mut c = ctx.client()?;
    if verify {
        let v = c.call("verify", &serde_json::json!({}))?;
        let intact = v.get("intact").and_then(|x| x.as_bool()).unwrap_or(false);
        let broken: Vec<i64> = v
            .get("broken_seqs")
            .and_then(|x| serde_json::from_value(x.clone()).unwrap_or_default())
            .unwrap_or_default();
        if ctx.out.json {
            println!("{}", serde_json::to_string_pretty(&v)?);
        } else if intact {
            ctx.out
                .println_stdout(&ctx.out.green("✓ 审计日志 hash 链完整"));
        } else {
            ctx.out.println_stdout(
                &ctx.out
                    .red(&format!("✗ 审计日志断链，位置 seq: {broken:?}")),
            );
        }
        return Ok(if intact { 0 } else { 5 }); // 断链 = 完整性错误，不是「未找到」
    }
    let since_ts = since.map(parse_since).transpose()?.flatten();
    let v = c.call(
        "log",
        &serde_json::json!({ "since_ts": since_ts, "limit": 500 }),
    )?;
    let entries: Vec<airlock_core::proto::AuditEntry> = serde_json::from_value(v)?;
    if ctx.out.json {
        println!("{}", serde_json::to_string_pretty(&entries)?);
        return Ok(0);
    }
    for e in entries {
        let detail = e.detail.as_ref().map(|d| d.to_string()).unwrap_or_default();
        ctx.out.println_stdout(&format!(
            "{} seq={} {} actor={}/{} path={} lease={} layer={} {}",
            human_ts(e.ts),
            e.seq,
            e.event,
            e.actor.agent,
            short_id(&e.actor.session),
            e.path,
            e.lease_id
                .as_deref()
                .map(short_id)
                .unwrap_or_else(|| "-".into()),
            e.layer,
            detail
        ));
    }
    Ok(0)
}

fn parse_since(s: &str) -> Result<Option<i64>> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(None);
    }
    let (num, unit): (String, String) = s.chars().partition(|c| c.is_ascii_digit());
    let n: i64 = num
        .parse()
        .map_err(|_| Error::Config(format!("无法解析 --since {s}")))?;
    let mult = match unit.as_str() {
        "s" | "" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        other => {
            return Err(Error::Config(format!(
                "未知时间单位 {other}（支持 s/m/h/d）"
            )))
        }
    };
    Ok(Some(now() - n * mult))
}

// ---------- doctor ----------

pub fn doctor(ctx: &Ctx) -> Result<i32> {
    let mut checks: Vec<(String, String, bool)> = Vec::new(); // (项, 详情, 正常?)
    let layer = resolve_layer(&ctx.cfg.enforcement);
    // daemon 可达性
    let daemon_ok = ctx.client().is_ok();
    checks.push((
        "daemon".into(),
        if daemon_ok {
            "运行中".into()
        } else {
            "不可达（agent 将 fail-open 无保护运行——P2：绝不静默）".into()
        },
        daemon_ok,
    ));
    // git 仓库
    checks.push((
        "冲突域".into(),
        if ctx.domain.is_git {
            format!("git 仓库（{}）", ctx.domain.id)
        } else {
            "非 git 目录——仅 L1 advisory 可用（§8.2）".into()
        },
        ctx.domain.is_git,
    ));
    // 各层探测（P6 渐进披露：给升级建议，不阻塞）
    let l1 = AdvisoryBackend.probe();
    let l2 = LandlockBackend.probe();
    let l3 = BpfLsmBackend.probe();
    let auto = ctx.cfg.enforcement == "auto" || ctx.cfg.enforcement.is_empty();
    checks.push((
        "当前层".into(),
        format!(
            "{} ({}{}){}",
            layer.id,
            layer.name,
            if layer.experimental {
                ", experimental"
            } else {
                ""
            },
            if ctx.cfg.enforcement == "off" {
                " —— enforcement=off（L0 badge，AC2.5）"
            } else {
                ""
            }
        ),
        layer.id != "L0",
    ));
    checks.push((l1.id.to_string(), format!("{} ✓ 可用", l1.name), true));
    checks.push((
        l2.id.clone(),
        match &l2.reason {
            None => format!("{} ✓ 可用（非 root，进程级强制）", l2.name),
            Some(r) => format!("{} 不可用——{r}", l2.name),
        },
        l2.available,
    ));
    checks.push((
        l3.id.clone(),
        match &l3.reason {
            None => format!("{} ✓ 可用（experimental）", l3.name),
            Some(r) => format!("{} 不可用——{r}", l3.name),
        },
        l3.available,
    ));
    // 升级建议（L3 尚无强制实现，不再给 root 启用建议）
    let mut advice = String::new();
    if auto && layer.id == "L1" && ctx.domain.is_git && l2.available {
        advice =
            "升级建议：用 `airlock run -- <命令>` 包装 agent 进程即可获得 L2 Landlock 真实拒绝。"
                .into();
    }
    if ctx.out.json {
        let v = serde_json::json!({
            "layer": layer,
            "landlock": l2,
            "bpf_lsm": l3,
            "daemon_reachable": daemon_ok,
            "is_git": ctx.domain.is_git,
            "advice": advice,
        });
        println!("{}", serde_json::to_string_pretty(&v)?);
        return Ok(0);
    }
    ctx.out
        .println_stdout(&format!("AIRLOCK DOCTOR —— {}", ctx.domain.root.display()));
    for (name, detail, ok) in &checks {
        let badge = if *ok {
            ctx.out.green("✓")
        } else {
            ctx.out.yellow("!")
        };
        ctx.out.println_stdout(&format!("{badge} {name}: {detail}"));
    }
    if !advice.is_empty() {
        ctx.out.println_stdout(&ctx.out.yellow(&advice));
    }
    // 首周留存引导（§2.3）：从未开过第二个 agent 时附一行引导
    let only_one_session = daemon_ok
        && ctx
            .client()
            .and_then(|mut c| c.call("status", &serde_json::json!({})))
            .map(|v| {
                v.get("sessions")
                    .and_then(|s| s.as_array())
                    .map(|a| a.len() < 2)
                    .unwrap_or(false)
            })
            .unwrap_or(false);
    if only_one_session {
        ctx.out.println_stdout(&ctx.out.grey(
            "提示：再开一个 agent 会话即可看到 Airlock 的拦截事件（第一次亲眼看到保护生效）。",
        ));
    }
    // doctor 恒为可用状态，退出码 0（AC2.3：探测报告不是错误）
    Ok(0)
}

// ---------- board ----------

pub fn board(ctx: &Ctx, cmd: &crate::BoardCmd) -> Result<i32> {
    let mut c = ctx.client()?;
    match cmd {
        crate::BoardCmd::Read { budget } => {
            let v = c.call(
                "board_read",
                &serde_json::json!({ "token_budget": budget.unwrap_or(ctx.cfg.board_token_budget) }),
            )?;
            if ctx.out.json {
                println!("{}", serde_json::to_string_pretty(&v)?);
                return Ok(0);
            }
            let entries = v
                .get("entries")
                .and_then(|e| e.as_array())
                .cloned()
                .unwrap_or_default();
            for e in &entries {
                let origin = e.get("origin").and_then(|o| o.as_str()).unwrap_or("agent");
                let body = e.get("body").and_then(|b| b.as_str()).unwrap_or("");
                let lease = e
                    .get("lease_id")
                    .and_then(|l| l.as_str())
                    .map(short_id)
                    .unwrap_or_else(|| "-".into());
                ctx.out
                    .println_stdout(&format!("  [{origin}] ({lease}) {body}"));
            }
            let archived = v
                .get("archived_summary")
                .and_then(|a| a.as_array())
                .cloned()
                .unwrap_or_default();
            for a in &archived {
                let s = a.as_str().unwrap_or("");
                ctx.out.println_stdout(&ctx.out.grey(&format!("  {s}")));
            }
            if let Some(t) = v.get("truncated").and_then(|t| t.as_u64()) {
                if t > 0 {
                    ctx.out
                        .println_stdout(&ctx.out.yellow(&format!("（因 token 预算截断 {t} 条）")));
                }
            }
            Ok(0)
        }
        crate::BoardCmd::Write { body, lease_id } => {
            let (agent, session) = ctx.session()?;
            let v = c.call(
                "board_write",
                &serde_json::json!({ "body": body, "lease_id": lease_id, "agent_id": agent, "session_id": session }),
            )?;
            ctx.out.either(&v, &ctx.out.green("✓ 已写入黑板"));
            Ok(0)
        }
    }
}

// ---------- daemon ----------

pub fn daemon(ctx: &Ctx, cmd: &crate::DaemonCmd) -> Result<i32> {
    match cmd {
        crate::DaemonCmd::Spawn => Ok(0), // 实际处理在 main.rs
        crate::DaemonCmd::Start { foreground } => {
            if ctx.client().is_ok() {
                ctx.out.either(
                    &serde_json::json!({"status":"already-running"}),
                    "daemon 已在运行",
                );
                return Ok(0);
            }
            if *foreground {
                // 前台模式：等价于直接运行 airlockd --foreground（当前进程内等待）
                return Ok(spawn_daemon_foreground(ctx));
            }
            let dir = ctx.exe.parent().unwrap_or(Path::new("."));
            let mut cmd0 = std::process::Command::new(dir.join("airlockd"));
            cmd0.arg("--root").arg(&ctx.domain.root);
            if let Some(cfg) = &ctx.config_path {
                cmd0.arg("--config").arg(cfg); // 配置与 CLI 同源，不漂移
            }
            let mut child = cmd0.spawn();
            // 兜底：经当前二进制派生（airlockd 与 airlock 不同目录时）
            if child.is_err() {
                let mut fallback = std::process::Command::new(&ctx.exe);
                fallback
                    .args(["daemon", "spawn"])
                    .arg("--root")
                    .arg(&ctx.domain.root);
                if let Some(cfg) = &ctx.config_path {
                    fallback.arg("--config").arg(cfg);
                }
                child = fallback.spawn();
            }
            match child {
                Ok(_) => {
                    // 等待 socket 就绪
                    for _ in 0..50 {
                        if ctx.client().is_ok() {
                            ctx.out.either(
                                &serde_json::json!({"status":"started"}),
                                &ctx.out.green("✓ daemon 已启动"),
                            );
                            return Ok(0);
                        }
                        std::thread::sleep(std::time::Duration::from_millis(100));
                    }
                    Err(Error::DaemonUnreachable(
                        "daemon 启动超时（查看 daemon.log）".into(),
                    ))
                }
                Err(e) => Err(Error::DaemonUnreachable(format!("无法拉起 daemon: {e}"))),
            }
        }
        crate::DaemonCmd::Stop => {
            let mut c = ctx.client()?;
            let v = c.call("stop", &serde_json::json!({}))?;
            ctx.out.either(&v, &ctx.out.green("✓ daemon 停止中"));
            Ok(0)
        }
    }
}

/// daemon start 的前台入口（`airlock daemon spawn` 不在帮助里）。
pub fn spawn_daemon_foreground(ctx: &Ctx) -> i32 {
    let dir = ctx.exe.parent().unwrap_or(Path::new("."));
    let mut c = std::process::Command::new(dir.join("airlockd"));
    c.arg("--root").arg(&ctx.domain.root).arg("--foreground");
    if let Some(cfg) = &ctx.config_path {
        c.arg("--config").arg(cfg);
    }
    match c.status() {
        Ok(s) => s.code().unwrap_or(1),
        Err(e) => {
            eprintln!("无法启动 airlockd: {e}");
            4
        }
    }
}

/// 供 tower 使用：拉取状态。
pub fn fetch_status(ctx: &Ctx) -> Result<StatusReport> {
    let mut c = ctx.client()?;
    let v = c.call("status", &serde_json::json!({}))?;
    Ok(serde_json::from_value(v)?)
}

/// 供 tower 使用：拉取黑板。
pub fn fetch_board(ctx: &Ctx) -> Result<airlock_core::proto::BoardRead> {
    let mut c = ctx.client()?;
    let v = c.call("board_read", &serde_json::json!({}))?;
    Ok(serde_json::from_value(v)?)
}

/// 供 tower 使用：拉取最近事件。
pub fn fetch_events(ctx: &Ctx, limit: i64) -> Result<Vec<airlock_core::proto::AuditEntry>> {
    let mut c = ctx.client()?;
    let v = c.call("log", &serde_json::json!({ "limit": limit }))?;
    Ok(serde_json::from_value(v)?)
}
