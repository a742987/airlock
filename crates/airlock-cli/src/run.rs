//! `airlock run` —— 在租约保护下运行命令（L2 Landlock 进程级强制，FR2.1/FR2.2）。
//!
//! 工作方式：
//! 1. 会话注册（或复用 AIRLOCK_SESSION_ID），按需 claim `--claim` 指定的路径；
//! 2. 收集允许写入的路径：租约 glob 的字面量前缀目录 + 必要豁免（.git / 数据目录 / /tmp）；
//! 3. 应用 Landlock ruleset（读全放行，写仅限白名单）后派生子进程——
//!    规则随本进程树存在，进程退出即消失，daemon 崩溃零残留（AC2.4 构造保证）；
//! 4. 运行期间后台心跳线程续约；退出时释放租约（--keep-leases 保留）。
//!
//! daemon 不可达时：直接以本地 SQLite 运行（fail-open），打印黄色警告（P2/P7）。

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::Arc;

use airlock_core::enforce::resolve_layer;
use airlock_core::error::{Error, Result};
use airlock_core::landlock;
use airlock_core::proto::{self, Actor, ClaimOk, SessionInfo};
use airlock_core::resources;
use airlock_core::store::Store;
use airlock_core::{lease, messages};

use crate::commands::Ctx;

/// SIGINT/SIGTERM 到达标志：转发给子进程并触发退出后清理（P1-4：Ctrl+C
/// 不再把租约泄漏 30 分钟）。
static RUN_INTERRUPTED: AtomicBool = AtomicBool::new(false);
static CHILD_PID: AtomicI32 = AtomicI32::new(0);

extern "C" fn run_on_signal(sig: libc::c_int) {
    RUN_INTERRUPTED.store(true, Ordering::SeqCst);
    let pid = CHILD_PID.load(Ordering::SeqCst);
    if pid > 0 {
        unsafe { libc::kill(pid, sig) };
    }
}

/// 租约操作通道（P5 单一事实源）：daemon 可达时一律走 daemon；
/// 不可达时直连本地存储（fail-open），心跳/清理同库生效。
enum Tx {
    Daemon(Box<proto::Client>, std::path::PathBuf),
    Local(Store),
}

impl Tx {
    fn open(ctx: &Ctx) -> (Tx, bool) {
        match ctx.client_or_heal() {
            Ok(c) => (Tx::Daemon(Box::new(c), ctx.domain.socket_path()), false),
            Err(_) => match Store::open(&ctx.domain.db_path()) {
                Ok(s) => (Tx::Local(s), true),
                Err(_) => (
                    Tx::Daemon(
                        Box::new(proto::Client::degraded()),
                        ctx.domain.socket_path(),
                    ),
                    true,
                ),
            },
        }
    }

    fn register(&mut self, agent: &str, port_base: u16) -> Result<SessionInfo> {
        match self {
            Tx::Daemon(c, sock) => {
                let v =
                    c.call_with_retry(sock, "register", &serde_json::json!({ "agent_id": agent }))?;
                Ok(serde_json::from_value(v)?)
            }
            Tx::Local(store) => resources::register_session(store, agent, port_base),
        }
    }

    fn claim(
        &mut self,
        cfg: &airlock_core::config::Config,
        p: &lease::ClaimParams,
    ) -> Result<ClaimOk> {
        match self {
            Tx::Daemon(c, sock) => {
                let mut params = serde_json::json!({
                    "agent_id": p.agent_id,
                    "session_id": p.session_id,
                    "glob": p.glob,
                    "ttl_s": p.ttl_s,
                });
                if let Some(i) = &p.intent {
                    params["intent"] = serde_json::json!(i);
                }
                let v = c.call_with_retry(sock, "claim", &params)?;
                Ok(serde_json::from_value(v)?)
            }
            Tx::Local(store) => lease::claim(store, cfg, p),
        }
    }

    fn alloc_port(&mut self, session: &SessionInfo) -> Result<u16> {
        match self {
            Tx::Daemon(c, sock) => {
                let v = c.call_with_retry(
                    sock,
                    "alloc_port",
                    &serde_json::json!({ "session_id": session.session_id, "purpose": "dev" }),
                )?;
                Ok(v.get("port").and_then(|x| x.as_u64()).unwrap_or_default() as u16)
            }
            Tx::Local(store) => {
                let info = resources::allocate_port(store, session, "dev")?;
                Ok(info.port)
            }
        }
    }

    /// Landlock 应用失败等降级事件的审计（daemon 不可达时写本地库）。
    fn heartbeat_degrade(&mut self, actor: &Actor, reason: &str) -> Result<()> {
        match self {
            Tx::Daemon(c, sock) => {
                c.call_with_retry(
                    sock,
                    "degrade",
                    &serde_json::json!({
                        "agent_id": actor.agent, "session_id": actor.session,
                        "path": "<landlock-failed>", "reason": reason
                    }),
                )?;
            }
            Tx::Local(store) => {
                store.audit(
                    "degrade",
                    actor,
                    "<landlock-failed>",
                    None,
                    "L1",
                    Some(&serde_json::json!({ "reason": reason })),
                )?;
            }
        }
        Ok(())
    }

    fn cleanup(&mut self, lease_ids: &[String], session_id: &str, agent: &str) -> Result<()> {
        match self {
            Tx::Daemon(c, sock) => {
                for id in lease_ids {
                    let _ = c.call_with_retry(
                        sock,
                        "release",
                        &serde_json::json!({ "lease_id": id, "agent_id": agent, "session_id": session_id }),
                    );
                }
                let _ = c.call_with_retry(
                    sock,
                    "session_end",
                    &serde_json::json!({ "session_id": session_id }),
                );
            }
            Tx::Local(store) => {
                for id in lease_ids {
                    let _ = lease::release(
                        store,
                        id,
                        &Actor {
                            agent: agent.into(),
                            session: session_id.into(),
                            pid_tree: vec![],
                        },
                        "L1",
                        Some(session_id),
                        None,
                    );
                }
                let _ = resources::end_session_ports(store, session_id);
            }
        }
        Ok(())
    }
}

struct RunArgs {
    claims: Vec<String>,
    intents: Vec<String>,
    keep_leases: bool,
    port: bool,
    ttl: Option<i64>,
    allow_write: Vec<String>,
    dry_run: bool,
    cmd: Vec<String>,
}

fn parse_args(args: &[String]) -> Result<RunArgs> {
    let mut out = RunArgs {
        claims: vec![],
        intents: vec![],
        keep_leases: false,
        port: false,
        ttl: None,
        allow_write: vec![],
        dry_run: false,
        cmd: vec![],
    };
    let mut i = 0;
    let mut in_cmd = false;
    while i < args.len() {
        let a = &args[i];
        if in_cmd {
            out.cmd.push(a.clone());
        } else if a == "--" {
            in_cmd = true;
        } else if let Some(v) = a.strip_prefix("--claim=") {
            out.claims.push(v.to_string());
        } else if a == "--claim" {
            i += 1;
            out.claims.push(
                args.get(i)
                    .ok_or_else(|| Error::Config("--claim 需要值".into()))?
                    .clone(),
            );
        } else if let Some(v) = a.strip_prefix("--intent=") {
            out.intents.push(v.to_string());
        } else if a == "--intent" {
            i += 1;
            out.intents.push(
                args.get(i)
                    .ok_or_else(|| Error::Config("--intent 需要值".into()))?
                    .clone(),
            );
        } else if a == "--keep-leases" {
            out.keep_leases = true;
        } else if a == "--port" {
            out.port = true;
        } else if let Some(v) = a.strip_prefix("--ttl=") {
            out.ttl = parse_ttl(v);
            if out.ttl.is_none() {
                return Err(Error::Config(format!(
                    "--ttl 无法解析：{v}（如 30m / 1h / 1800）"
                )));
            }
        } else if a == "--ttl" {
            i += 1;
            let v = args
                .get(i)
                .ok_or_else(|| Error::Config("--ttl 需要值（如 30m / 1h / 1800）".into()))?;
            out.ttl = parse_ttl(v);
            if out.ttl.is_none() {
                return Err(Error::Config(format!(
                    "--ttl 无法解析：{v}（如 30m / 1h / 1800）"
                )));
            }
        } else if let Some(v) = a.strip_prefix("--allow-write=") {
            out.allow_write.push(v.to_string());
        } else if a == "--allow-write" {
            i += 1;
            out.allow_write.push(
                args.get(i)
                    .ok_or_else(|| Error::Config("--allow-write 需要值".into()))?
                    .clone(),
            );
        } else if a == "--dry-run" {
            out.dry_run = true;
        } else if a == "--help" || a == "-h" {
            print_run_help();
            std::process::exit(0);
        } else {
            out.cmd = args[i..].to_vec();
            break;
        }
        i += 1;
    }
    if out.cmd.is_empty() && !out.dry_run {
        return Err(Error::Config("airlock run 需要 `-- <命令>`".into()));
    }
    Ok(out)
}

fn print_run_help() {
    println!(
        "用法: airlock run [--claim <glob>] [--intent <文本>] [--port] [--ttl <时长>] \
         [--allow-write <路径>] [--keep-leases] [--dry-run] -- <命令> [参数...]\n\
         在 L2 Landlock 租约保护下运行命令：写操作仅允许租约路径与豁免目录。\n\
         时长格式支持 1800 / 30m / 1h / 1h30m。"
    );
}

/// 时长解析：纯数字 = 秒；支持 s/m/h 组合（如 30m、1h、90s、1h30m）。
pub fn parse_ttl(s: &str) -> Option<i64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    if let Ok(n) = s.parse::<i64>() {
        return Some(n);
    }
    let mut total: i64 = 0;
    let mut num = String::new();
    let mut matched = false;
    for c in s.chars() {
        if c.is_ascii_digit() {
            num.push(c);
        } else {
            let n: i64 = num.parse().ok()?;
            num.clear();
            let mult = match c {
                's' => 1,
                'm' => 60,
                'h' => 3600,
                _ => return None,
            };
            total = total.checked_add(n.checked_mul(mult)?)?;
            matched = true;
        }
    }
    if !num.is_empty() {
        return None; // 尾部残留数字（如 "30m30"）视为非法
    }
    if matched {
        Some(total)
    } else {
        None
    }
}

pub fn run_wrapped(ctx: &Ctx, args: &[String]) -> Result<i32> {
    let run = parse_args(args)?;
    let cfg = ctx.cfg.clone();

    // 信号处理：SIGINT/SIGTERM 转发给子进程并标记中断（退出后统一清理租约）
    unsafe {
        libc::signal(
            libc::SIGINT,
            run_on_signal as *const () as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGTERM,
            run_on_signal as *const () as libc::sighandler_t,
        );
    }

    // daemon 可达性：不可达 → fail-open 本地模式（P2：显式警告）
    let (mut tx, degraded) = Tx::open(ctx);
    if degraded {
        ctx.out
            .println_stderr(&ctx.out.yellow(messages::DEGRADED_WARNING));
    }

    let layer = resolve_layer(&cfg.enforcement);
    let actor = Actor {
        agent: std::env::var("AIRLOCK_AGENT_ID").unwrap_or_else(|_| "run".into()),
        session: String::new(),
        pid_tree: vec![std::process::id()],
    };

    // 会话：env 复用或新建
    let session: SessionInfo = match std::env::var("AIRLOCK_SESSION_ID") {
        Ok(sid) if !sid.is_empty() => SessionInfo {
            session_id: sid,
            agent_id: actor.agent.clone(),
            seq: -1,
            port_base: 0,
            env: Default::default(),
        },
        _ => tx.register(&actor.agent, cfg.port_base)?,
    };
    let mut actor = actor;
    actor.session = session.session_id.clone();

    // 统一清理：任何提前退出路径都释放已获租约（P1-5：部分失败不泄漏）
    let cleanup = |tx: &mut Tx, lease_ids: &[String]| {
        if !lease_ids.is_empty() && !run.keep_leases {
            let _ = tx.cleanup(lease_ids, &session.session_id, &actor.agent);
        }
    };

    // claim 指定路径
    let mut lease_ids: Vec<String> = Vec::new();
    // 子进程环境：会话 env 起底，claim 凭据（F13）与端口（F3）陆续并入
    let mut port_env = session.env.clone();
    for (idx, g) in run.claims.iter().enumerate() {
        let intent = run.intents.get(idx).or(run.intents.first()).cloned();
        let params = lease::ClaimParams {
            conflict_domain: ctx.domain.id.clone(),
            agent_id: actor.agent.clone(),
            session_id: session.session_id.clone(),
            glob: g.clone(),
            intent,
            ttl_s: run.ttl,
            heartbeat_s: cfg.heartbeat_s,
            layer: layer.id.clone(),
            actor: actor.clone(),
            root: Some(ctx.domain.root.clone()),
        };
        match tx.claim(&cfg, &params) {
            Ok(ok) => {
                let id8 = ok.lease.id.chars().take(8).collect::<String>();
                lease_ids.push(ok.lease.id);
                // F13：随租约发放的凭据注入子进程环境
                if let Some(creds) = &ok.credentials {
                    for (k, v) in creds {
                        port_env.insert(k.clone(), v.clone());
                    }
                    if !ctx.out.quiet {
                        ctx.out.println_stderr(&format!(
                            "✓ 凭据 {} 项已随租约发放（释放即吊销）",
                            creds.len()
                        ));
                    }
                }
                if !ctx.out.quiet {
                    ctx.out.println_stderr(&format!(
                        "✓ 已 claim {}（租约 {id8}）预测: {}",
                        g, ok.prediction.risk
                    ));
                }
            }
            Err(Error::Conflict(rej)) => {
                ctx.out.println_stderr(&rej.human);
                cleanup(&mut tx, &lease_ids);
                return Ok(2);
            }
            Err(e) => {
                cleanup(&mut tx, &lease_ids);
                return Err(e);
            }
        }
    }
    if RUN_INTERRUPTED.load(Ordering::SeqCst) {
        cleanup(&mut tx, &lease_ids);
        return Ok(130);
    }

    // 端口分配（F3）：分配并注入 PORT/VITE_PORT/NEXT_PORT
    if run.port {
        match tx.alloc_port(&session) {
            Ok(port) => {
                port_env = resources::inject_env(port);
                port_env.insert("AIRLOCK_ALLOCATED_PORT".into(), port.to_string());
                if !ctx.out.quiet {
                    ctx.out.println_stderr(&format!("✓ 端口 {port}"));
                }
            }
            Err(e) => {
                cleanup(&mut tx, &lease_ids);
                return Err(e);
            }
        }
    }

    // 允许写入路径 = 租约字面量前缀 + 豁免。
    // 租约前缀先 canonicalize 并校验落在仓库根内（P0：符号链接 / `..` 逃逸
    // 在 claim 层已拒绝，这里对真实文件系统再验一次；目录不存在则显式报错——
    // 静默跳过会让 L2 白名单缺一条规则而无人知晓）。
    let root_canon = ctx
        .domain
        .root
        .canonicalize()
        .unwrap_or_else(|_| ctx.domain.root.clone());
    let mut allowed: Vec<PathBuf> = Vec::new();
    for g in &run.claims {
        if let Some(dir) = airlock_core::glob::literal_prefix_dir(g) {
            let raw = ctx.domain.root.join(&dir);
            let canon = raw.canonicalize().map_err(|e| {
                cleanup(&mut tx, &lease_ids);
                Error::Config(format!(
                    "租约路径 `{}` 不存在或无法解析（{e}）——L2 拒绝不完整白名单",
                    dir.display()
                ))
            })?;
            if !canon.starts_with(&root_canon) {
                cleanup(&mut tx, &lease_ids);
                return Err(Error::Config(format!(
                    "租约路径 `{}` 解析后逃逸出仓库根（符号链接？）",
                    dir.display()
                )));
            }
            allowed.push(canon);
        }
    }
    for a in &run.allow_write {
        // --allow-write 是用户的显式选择：不限制在仓库内，但同样解析符号链接
        if let Ok(c) = ctx.domain.root.join(a).canonicalize() {
            allowed.push(c);
        }
    }
    allowed.push(ctx.domain.common_dir.join("airlock")); // 数据目录
    allowed.push(ctx.domain.common_dir.clone()); // .git
                                                 // /dev 整树授权：字符设备（/dev/null、/dev/pts）无法单独下发 PATH_BENEATH 规则，
                                                 // 而写 /dev/null 是 agent 的常规操作；设备节点写入仍受文件属主权限约束（agent 非特权）。
    allowed.push(PathBuf::from("/dev"));
    // 会话临时目录（窄豁免：绝不豁免整个 /tmp，否则 /tmp 下的仓库全放行）
    if let Ok(tmp) = std::env::var("TMPDIR") {
        if !tmp.is_empty() {
            allowed.push(PathBuf::from(tmp).join(format!("airlock-{}", session.session_id)));
        }
    }
    allowed.push(PathBuf::from("/tmp").join(format!("airlock-{}", session.session_id)));
    allowed.sort();
    allowed.dedup();

    // F12 政策即代码：deny 规则解析为具体目录，从 Landlock 允许集减去——
    // 被拒路径在本进程树内得到内核 EPERM（政策驱动内核拒绝的第二层）。
    // 政策文件非法 → Error::Config（fail-closed；claim 层同样会拦）。
    let denied: Vec<PathBuf> = match airlock_core::policy::Policy::load(&ctx.domain.root) {
        Ok(Some(pol)) => pol
            .denied_write_dirs(&ctx.domain.root)
            .iter()
            .filter_map(|p| p.canonicalize().ok())
            .collect(),
        Ok(None) => Vec::new(),
        Err(e) => {
            cleanup(&mut tx, &lease_ids);
            return Err(e);
        }
    };

    if run.dry_run {
        if ctx.out.json {
            let plan = serde_json::json!({
                "session": session.session_id,
                "leases": lease_ids,
                "allowed_write": allowed,
                "policy_denied_write": denied,
                "cmd": run.cmd,
                "env": port_env,
            });
            println!("{}", serde_json::to_string_pretty(&plan)?);
        } else {
            ctx.out.println_stdout(&format!(
                "dry-run：会话 {}，租约 {} 条",
                session.session_id,
                lease_ids.len()
            ));
            for l in &lease_ids {
                ctx.out.println_stdout(&format!("  lease {l}"));
            }
            ctx.out.println_stdout("允许写入：");
            for a in &allowed {
                ctx.out.println_stdout(&format!("  {}", a.display()));
            }
            if !denied.is_empty() {
                ctx.out
                    .println_stdout(&ctx.out.yellow("政策拒绝写入（内核排除）："));
                for a in &denied {
                    ctx.out.println_stdout(&format!("  {}", a.display()));
                }
            }
            ctx.out
                .println_stdout(&format!("命令：{}", run.cmd.join(" ")));
        }
        cleanup(&mut tx, &lease_ids);
        return Ok(0);
    }

    // L2 落地：应用 Landlock（layer=L2 且可用时；仅 Linux——L2 只在 Linux 可用，
    // 其他平台 resolve_layer 不会返回可用的 L2）。警告分支保持平台无关。
    let mut enforced = false;
    #[cfg(target_os = "linux")]
    if layer.id == "L2" && layer.available {
        match landlock::restrict_write_except(&allowed, &denied) {
            Ok(()) => enforced = true,
            Err(e) => {
                // P2：绝不静默降级
                ctx.out.println_stderr(&ctx.out.yellow(&format!(
                    "⚠ Landlock 应用失败（{e}），本次运行为 L1 advisory"
                )));
                let _ = tx.heartbeat_degrade(&actor, &e.to_string());
            }
        }
    }
    if enforced {
        if !ctx.out.quiet {
            let msg = ctx.out.green("🔒 Landlock 已启用：写操作仅限租约路径");
            ctx.out.println_stderr(&msg);
        }
    } else if layer.id == "L1" {
        if !ctx.out.quiet {
            ctx.out.println_stderr(
                &ctx.out
                    .yellow("⚠ 当前为 L1 advisory：内核强制不可用，仅 MCP/CLI 层拒绝越权 claim"),
            );
        }
    } else {
        // L0 / L3 / 显式指定但不可用的层：显式可见，绝不静默（P2；L3 目前无强制实现）
        let reason = layer.reason.clone().unwrap_or_default();
        ctx.out.println_stderr(&ctx.out.yellow(&format!(
            "⚠ 强制层 {}（{}）不提供内核写拦截：{}仅 MCP/CLI 层拒绝越权 claim",
            layer.id, layer.name, reason
        )));
        let _ = tx.heartbeat_degrade(&actor, &format!("layer {} no kernel enforcement", layer.id));
    }

    // 心跳线程（经由同一通道续约）
    let stop_flag = Arc::new(AtomicBool::new(false));
    if !lease_ids.is_empty() {
        // Tx 不可跨线程共享（rusqlite/UnixStream），心跳线程独立开通道
        let sock = ctx.domain.socket_path();
        let db = ctx.domain.db_path();
        let use_daemon = matches!(tx, Tx::Daemon(..));
        let ids = lease_ids.clone();
        let agent_hb = actor.agent.clone();
        let session_hb = session.session_id.clone();
        let hb_period = cfg.heartbeat_s.max(1) as u64;
        let flag = Arc::clone(&stop_flag);
        std::thread::spawn(move || loop {
            for _ in 0..hb_period * 10 {
                if flag.load(Ordering::SeqCst) {
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            for id in &ids {
                let _ = if use_daemon {
                    proto::Client::connect(&sock).and_then(|mut c| {
                        c.call(
                            "heartbeat",
                            &serde_json::json!({
                                "lease_id": id, "agent_id": agent_hb, "session_id": session_hb
                            }),
                        )
                    })
                } else {
                    Store::open(&db)
                        .and_then(|store| {
                            lease::heartbeat(
                                &store,
                                id,
                                &Actor {
                                    agent: agent_hb.clone(),
                                    session: session_hb.clone(),
                                    pid_tree: vec![],
                                },
                                "L1",
                                Some(&session_hb),
                            )
                        })
                        .map(|_| serde_json::Value::Null)
                };
            }
        });
    }

    // 派生子进程
    if run.cmd.is_empty() {
        cleanup(&mut tx, &lease_ids);
        return Ok(0);
    }
    let mut cmd = std::process::Command::new(&run.cmd[0]);
    cmd.args(&run.cmd[1..]);
    cmd.current_dir(&ctx.domain.root); // agent 的工作目录 = 仓库根
    if !ctx.out.quiet && ctx.domain.root != std::env::current_dir().unwrap_or_default() {
        ctx.out.println_stderr(&format!(
            "ℹ 子进程工作目录已切换到仓库根 {}（相对路径按根解析）",
            ctx.domain.root.display()
        ));
    }
    for (k, v) in &port_env {
        cmd.env(k, v);
    }
    cmd.env("AIRLOCK_SESSION_ID", &session.session_id);
    cmd.env("AIRLOCK_AGENT_ID", &actor.agent);
    let child = cmd.spawn();
    let status = match child {
        Ok(mut c) => {
            CHILD_PID.store(c.id() as i32, Ordering::SeqCst);
            let st = c.wait();
            CHILD_PID.store(0, Ordering::SeqCst);
            st
        }
        Err(e) => Err(e),
    };
    stop_flag.store(true, Ordering::SeqCst);

    // 退出清理：释放租约 + 结束会话（端口冷却）——信号中断路径同样到达
    cleanup(&mut tx, &lease_ids);

    match status {
        Ok(s) if s.success() => Ok(0),
        Ok(s) => {
            use std::os::unix::process::ExitStatusExt;
            // 信号终止 → 惯例 128+sig（SIGINT = 130，与中断语义衔接）
            if let Some(sig) = s.signal() {
                Ok(128 + sig)
            } else {
                Ok(s.code().unwrap_or(1))
            }
        }
        Err(e) => Err(Error::Other(format!("无法执行 {:?}: {e}", run.cmd[0]))),
    }
}
