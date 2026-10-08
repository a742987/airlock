//! PreToolUse hook 处理器（F4 接入层，AC4.1）：
//! agent 第一次 Edit 前自动 claim；路径被他人持有则拒绝（可读原因）；
//! Bash 写命令中的路径同样检查（L1 层拦截 `sed -i` 类越权写入）。
//!
//! 架构（P5 单一事实源）：daemon 可达时全部走 daemon（`ensure_claim` 幂等语义）；
//! daemon 不可达时 fail-open 直连本地存储并显式警告（P2/P7）。

use airlock_core::config::Config;
use airlock_core::enforce::resolve_layer;
use airlock_core::error::{Error, Result};
use airlock_core::glob;
use airlock_core::lease::ClaimParams;
use airlock_core::messages;
use airlock_core::proto::{self, Actor, ClaimOk};
use airlock_core::store::{now, Store};

use crate::commands::Ctx;

/// hook stdin 载荷上限：1 MiB（与 daemon 请求行上限一致）。
const HOOK_INPUT_MAX: u64 = 1 << 20;

/// Claude Code hook 的 stdin 载荷。
#[derive(Debug, Default, serde::Deserialize)]
struct HookInput {
    #[serde(default)]
    tool_name: String,
    #[serde(default)]
    tool_input: serde_json::Value,
    /// Claude Code 会在 hook 输入里带上自身 session_id——未配置
    /// AIRLOCK_SESSION_ID 时用它派生会话（同一 CC 实例的全部 hook 一致）。
    #[serde(default)]
    session_id: Option<String>,
}

#[derive(Debug, serde::Serialize)]
struct HookDecision {
    hook_specific_output: HookSpecific,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct HookSpecific {
    hook_event_name: String,
    permission_decision: String, // allow / deny
    permission_decision_reason: String,
}

/// 事务通道：daemon 优先，本地存储兜底（fail-open）。
enum Tx {
    Daemon(Box<proto::Client>),
    Local(Store),
}

impl Tx {
    /// 打开通道；daemon 不可达且本地存储损坏时返回 None（纯 fail-open）。
    fn open(ctx: &Ctx) -> Option<Tx> {
        if let Ok(c) = ctx.client_or_heal() {
            return Some(Tx::Daemon(Box::new(c)));
        }
        Store::open(&ctx.domain.db_path()).ok().map(Tx::Local)
    }

    /// 幂等 claim：本会话已覆盖 → 返回现有租约；他人持有 → Conflict；无 → 自动 claim。
    fn ensure_claim(&mut self, cfg: &Config, p: &ClaimParams) -> Result<ClaimOk> {
        match self {
            Tx::Daemon(c) => {
                let mut params = serde_json::json!({
                    "agent_id": p.agent_id,
                    "session_id": p.session_id,
                    "glob": p.glob,
                    "ttl_s": p.ttl_s,
                });
                if let Some(i) = &p.intent {
                    params["intent"] = serde_json::json!(i);
                }
                let v = c.call("ensure_claim", &params)?;
                Ok(serde_json::from_value(v)?)
            }
            Tx::Local(store) => {
                let actives = store.active_leases(Some(&p.conflict_domain), now())?;
                if let Some(existing) = actives
                    .iter()
                    .find(|l| l.session_id == p.session_id && glob::overlaps(&p.glob, &l.glob))
                {
                    return Ok(ClaimOk {
                        lease: existing.clone(),
                        prediction: airlock_core::proto::Prediction {
                            risk: "none".into(),
                            with_leases: vec![],
                            involved_symbols: vec![],
                        },
                        credentials: None,
                    });
                }
                airlock_core::lease::claim(store, cfg, p)
            }
        }
    }
}

pub fn handle(ctx: &Ctx, event: &str) -> Result<i32> {
    if event != "pretooluse" {
        return Err(Error::Config(format!("未知 hook 事件 {event}")));
    }
    let mut input = String::new();
    use std::io::Read;
    // hook 输入限长 1 MiB：防失控的 agent 进程用超长载荷耗内存
    let _ = std::io::stdin()
        .lock()
        .take(HOOK_INPUT_MAX)
        .read_to_string(&mut input);
    let parsed: HookInput = match serde_json::from_str(&input) {
        Ok(p) => p,
        Err(_) if input.trim().is_empty() => HookInput::default(),
        // 载荷损坏不能静默当空输入放行——那会让防护悄悄失效（P7 显式可见）
        Err(e) => {
            eprintln!(
                "{}",
                ctx.out.yellow(&format!(
                    "⚠ airlock hook 输入解析失败（{e}），本次按无写入路径放行——防护未生效，请检查 agent 的 hook 配置。"
                ))
            );
            HookInput::default()
        }
    };

    let agent = std::env::var("AIRLOCK_AGENT_ID").unwrap_or_else(|_| "hook-agent".into());
    // 会话优先级（P1-1 会话统一）：init 注入的 AIRLOCK_SESSION_ID
    // > CC hook 输入的 session_id（同一 agent 实例内一致）> per-agent 兜底。
    // hook 与同一 agent 的 MCP 进程共享 init 注入的会话，才不会 deny 自己。
    let session = std::env::var("AIRLOCK_SESSION_ID")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| {
            parsed
                .session_id
                .as_deref()
                .filter(|s| !s.is_empty())
                .map(|s| format!("cc-{s}"))
        })
        .unwrap_or_else(|| format!("hook-{agent}"));

    let candidate_paths = extract_write_paths(&parsed);

    // 读用户真实配置（P1-2：enforcement=off / 自定义 TTL / heartbeat 对 hook 面生效）
    let cfg = Config::load(None, &ctx.domain.root).unwrap_or_else(|e| {
        eprintln!("⚠ airlock hook 配置加载失败（{e}），按默认配置继续");
        Config::default()
    });
    let layer = resolve_layer(&cfg.enforcement);
    let actor = Actor {
        agent: agent.clone(),
        session: session.clone(),
        pid_tree: vec![std::process::id()],
    };

    // L0（enforcement=off）时 hook 不拦截（AC2.5）
    if layer.id == "L0" {
        return allow("");
    }

    let Some(mut tx) = Tx::open(ctx) else {
        // daemon 与存储均不可用 → 纯 fail-open，但必须显式可见（P7）
        eprintln!("{}", ctx.out.yellow(messages::DEGRADED_WARNING));
        return allow(&parsed.tool_name);
    };

    // daemon 不可达（本地兜底）→ 降级警告 + degrade 审计（P2）
    let degraded = matches!(tx, Tx::Local(_));
    if degraded {
        eprintln!("{}", ctx.out.yellow(messages::DEGRADED_WARNING));
        if let Tx::Local(store) = &tx {
            let _ = store.audit("degrade", &actor, "<hook>", None, &layer.id, None);
        }
    }

    for path in &candidate_paths {
        let Some(rel) = to_rel(&ctx.domain.root, path) else {
            continue; // 仓库外路径不归我们管
        };
        if rel.is_empty() {
            continue;
        }
        let params = airlock_core::lease::ClaimParams {
            conflict_domain: ctx.domain.id.clone(),
            agent_id: agent.clone(),
            session_id: session.clone(),
            glob: rel.clone(),
            intent: None,
            ttl_s: Some(cfg.default_ttl_s),
            heartbeat_s: cfg.heartbeat_s,
            layer: layer.id.clone(),
            actor: actor.clone(),
            root: Some(ctx.domain.root.clone()),
        };
        match tx.ensure_claim(&cfg, &params) {
            Ok(ok) => {
                eprintln!("airlock hook: {rel} 受租约 {} 保护", short(&ok.lease.id));
            }
            Err(Error::Conflict(rej)) => {
                // deny 链路（P1-3）：结构化 JSON 走 stdout + exit 0（Claude Code
                // 只在 exit 0 时解析 stdout JSON），人类可读原因同时复制到
                // stderr 双保险——模型必须能看到「谁持有、还剩多久、下一步」。
                let deny = HookDecision {
                    hook_specific_output: HookSpecific {
                        hook_event_name: "PreToolUse".into(),
                        permission_decision: "deny".into(),
                        permission_decision_reason: format!(
                            "{}\n（模型可读：{}）",
                            rej.human,
                            serde_json::json!({
                                "error": rej.error,
                                "path": rej.path,
                                "holder": rej.holder,
                                "ttl_remaining_s": rej.ttl_remaining_s,
                                "free_alternatives": rej.free_alternatives,
                                "suggested_action": rej.suggested_action,
                            })
                        ),
                    },
                };
                eprintln!("{}", ctx.out.yellow(&rej.human));
                println!("{}", serde_json::to_string(&deny)?);
                return Ok(0);
            }
            Err(e) => {
                // 存储错误 → fail-open 放行但显式可见（P7：失败安全但不失败可用）
                eprintln!("⚠ airlock hook 存储错误（{e}），本次操作无保护放行");
            }
        }
    }
    allow(&parsed.tool_name)
}

fn short(id: &str) -> String {
    id.chars().take(8).collect()
}

fn allow(reason: &str) -> Result<i32> {
    let d = HookDecision {
        hook_specific_output: HookSpecific {
            hook_event_name: "PreToolUse".into(),
            permission_decision: "allow".into(),
            permission_decision_reason: reason.to_string(),
        },
    };
    println!("{}", serde_json::to_string(&d)?);
    Ok(0)
}

/// 把绝对/相对路径归一化为仓库根相对路径；仓库外返回 None。
fn to_rel(root: &std::path::Path, p: &str) -> Option<String> {
    let path = std::path::Path::new(p);
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().ok()?.join(path)
    };
    let abs = airlock_core::paths::domain_key(&abs);
    let root_key = airlock_core::paths::domain_key(root);
    let rel = abs
        .strip_prefix(&root_key)?
        .trim_start_matches('/')
        .to_string();
    if rel.is_empty() {
        None
    } else {
        Some(rel)
    }
}

/// 从 hook 输入提取候选写入路径。
fn extract_write_paths(input: &HookInput) -> Vec<String> {
    let mut out = Vec::new();
    let ti = &input.tool_input;
    match input.tool_name.as_str() {
        "Edit" | "Write" | "NotebookEdit" => {
            if let Some(p) = ti
                .get("file_path")
                .or_else(|| ti.get("notebook_path"))
                .and_then(|v| v.as_str())
            {
                out.push(p.to_string());
            }
        }
        "MultiEdit" => {
            if let Some(p) = ti.get("file_path").and_then(|v| v.as_str()) {
                out.push(p.to_string());
            }
        }
        "Bash" => {
            if let Some(cmd) = ti.get("command").and_then(|v| v.as_str()) {
                out.extend(bash_write_paths(cmd));
            }
        }
        _ => {}
    }
    out.sort();
    out.dedup();
    out
}

/// 极简 Bash 写路径提取：重定向 / sed -i / rm / mv / cp / tee / touch / truncate / dd。
/// 先按 `&&` / `||` / `;` / `|` 分段（引号内不切），每段独立提取——
/// `sed -i a.ts && sed -i b.ts` 不再漏检前半段。
fn bash_write_paths(cmd: &str) -> Vec<String> {
    let mut out = Vec::new();
    for seg in split_shell_segments(cmd) {
        out.extend(segment_write_paths(&seg));
    }
    out.sort();
    out.dedup();
    out
}

/// 按命令分隔符切分（单引号/双引号内不切）。
fn split_shell_segments(cmd: &str) -> Vec<String> {
    let mut segs = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    let chars: Vec<char> = cmd.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        match quote {
            Some(q) => {
                cur.push(c);
                if c == q {
                    quote = None;
                }
            }
            None => {
                if c == '\'' || c == '"' {
                    quote = Some(c);
                    cur.push(c);
                } else if c == ';' {
                    segs.push(std::mem::take(&mut cur));
                } else if c == '&'
                    && chars.get(i + 1) == Some(&'>')
                    && chars
                        .get(i + 2)
                        .map(|c| c.is_ascii_digit())
                        .unwrap_or(false)
                    && cur
                        .chars()
                        .last()
                        .map(|c| c.is_ascii_digit())
                        .unwrap_or(false)
                {
                    // `2>&1`：fd 重定向被保守切分后会伪装成写文件 "1"——
                    // 把完整表达式单独成段，由 segment 层识别后跳过
                    let fd = cur.pop().unwrap();
                    segs.push(std::mem::take(&mut cur));
                    segs.push(format!("{fd}>&{}", chars[i + 2]));
                    i += 2; // 消费 '>' 与目标 fd（外层再 +1 消费 '&'）
                } else if c == '&' || c == '|' {
                    // && 与 || 是分隔符；单个 & / | 也按分隔符处理（保守多切不漏检）
                    if chars.get(i + 1) == Some(&c) {
                        i += 1;
                    }
                    segs.push(std::mem::take(&mut cur));
                } else {
                    cur.push(c);
                }
            }
        }
        i += 1;
    }
    segs.push(cur);
    segs.into_iter().filter(|s| !s.trim().is_empty()).collect()
}

/// 单段命令的写路径提取。
fn segment_write_paths(seg: &str) -> Vec<String> {
    let mut out = Vec::new();
    let tokens: Vec<String> = seg
        .split_whitespace()
        .map(|t| t.trim_matches(|c| c == '"' || c == '\'').to_string())
        .filter(|t| !t.is_empty())
        .collect();
    if tokens.is_empty() {
        return out;
    }
    let head = tokens[0].rsplit('/').next().unwrap_or(&tokens[0]);
    // 写命令 → 目标 = 最后一个非 flag 词；sed 需确认带 -i（任意位置）
    let is_write_op = match head {
        "sed" => tokens[1..].iter().any(|t| t == "-i" || t == "--in-place"),
        "rm" | "mv" | "cp" | "tee" | "touch" | "truncate" => true,
        "dd" => tokens.iter().any(|t| t.starts_with("of=")),
        _ => false,
    };
    if is_write_op {
        if head == "dd" {
            // dd 的目标在 of=<path>
            if let Some(t) = tokens.iter().find(|t| t.starts_with("of=")) {
                let p = t.trim_start_matches("of=");
                if !p.is_empty() && !p.starts_with('-') {
                    out.push(p.to_string());
                }
            }
        } else if let Some(last) = tokens
            .iter()
            .rev()
            .find(|t| !t.starts_with('-') && !is_fd_redirect(t))
        {
            // 多目标命令（如 sed -i a b c）只取最后一个词——已知局限，
            // 语义宁可漏检不可误拦（误拦会打断 agent 正常工作）
            out.push(last.clone());
        }
    }
    // 重定向：>file / >>file / 1>file / 2>file / &>file / > file
    for (i, t) in tokens.iter().enumerate() {
        let after = t.trim_start_matches(['0', '1', '2', '&']).to_string();
        if after.starts_with(">>") || (after.starts_with('>') && !t.starts_with("of=")) {
            let p = after.trim_start_matches('>');
            let p = if p.is_empty() {
                tokens.get(i + 1).map(|s| s.as_str()).unwrap_or("")
            } else {
                p
            };
            let p = p.trim_matches(|c| c == '"' || c == '\'');
            if p.is_empty() || p.starts_with('-') {
                continue;
            }
            // `2>&1` / `>&2` 类重定向到 fd：目标是文件描述符不是文件，跳过
            // （漏检名为 "1" 的文件远好于对纯 fd 重定向产生假租约请求）
            if p.chars().all(|c| c.is_ascii_digit()) && (t.contains(">&") || is_fd_redirect(t)) {
                continue;
            }
            out.push(p.to_string());
        }
    }
    out
}

/// 形如 `2>&1` 的 fd 重定向（tokenizer 把它单独成段）。
fn is_fd_redirect(t: &str) -> bool {
    let b = t.as_bytes();
    b.len() == 4 && b[1] == b'>' && b[2] == b'&' && b[0].is_ascii_digit() && b[3].is_ascii_digit()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bash_paths_extraction() {
        let ps = bash_write_paths("sed -i 's/a/b/' src/auth/login.ts");
        assert_eq!(ps, vec!["src/auth/login.ts"]);
        // 重定向到文件描述符不是写文件：`2>&1` 不得产出目标 "1"
        assert_eq!(
            bash_write_paths("cargo test 2>&1 | head"),
            Vec::<String>::new()
        );
        assert_eq!(bash_write_paths("make 2>&1"), Vec::<String>::new());
        // 真正的 stderr 重定向到文件仍要检出
        assert_eq!(bash_write_paths("make 2>build.log"), vec!["build.log"]);
        let ps = bash_write_paths("echo hi > /tmp/x.txt");
        assert_eq!(ps, vec!["/tmp/x.txt"]);
        let ps = bash_write_paths("rm src/api/old.ts");
        assert_eq!(ps, vec!["src/api/old.ts"]);
        // && 链：两段都要提取（P2-11）
        let ps = bash_write_paths("sed -i 's/a/b/' a.ts && sed -i 's/c/d/' b.ts");
        assert_eq!(ps, vec!["a.ts", "b.ts"]);
        // -i 不在第二位
        let ps = bash_write_paths("sed 's/a/b/' -i src/x.ts");
        assert_eq!(ps, vec!["src/x.ts"]);
        // 不带 -i 的 sed 是读操作
        let ps = bash_write_paths("sed 's/a/b/' src/x.ts");
        assert!(ps.is_empty());
        // dd of=
        let ps = bash_write_paths("dd if=/dev/zero of=relay.img bs=1M count=10");
        assert_eq!(ps, vec!["relay.img"]);
        // 无写操作
        let ps = bash_write_paths("cat src/x.ts | grep foo");
        assert!(ps.is_empty());
    }

    #[test]
    fn to_rel_normalizes() {
        let root = std::env::temp_dir();
        let abs = root.join("src/x.ts");
        let rel = to_rel(&root, &abs.to_string_lossy());
        assert_eq!(rel, Some("src/x.ts".into()));
    }
}
