//! airlockd —— Airlock 常驻守护进程。
//!
//! 职责（PRD §5 架构图）：租约引擎唯一权威事实源（P5）、hash-chained 审计、
//! 资源分配、黑板维护、过期清扫、保护空窗追踪（AC2.4）。
//! SQLite 损坏时拒绝启动（§8.4：宁可不可用，不可假保护）。

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::os::fd::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use airlock_core::config::Config;
use airlock_core::enforce::resolve_layer;
use airlock_core::error::{Error, Result};
use airlock_core::paths::Domain;
use airlock_core::proto::{self, Actor, ClaimOk, PortInfo, SessionInfo, StatusReport};
use airlock_core::resources;
use airlock_core::store::{now, Store};
use airlock_core::{lease, messages, Error as AirlockError};

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_sig: libc::c_int) {
    SHUTDOWN.store(true, Ordering::SeqCst);
}

/// Mutex 中毒恢复：一个请求线程 panic 不应砖掉整个 daemon（P2-3）。
fn lock_store(store: &Mutex<Store>) -> std::sync::MutexGuard<'_, Store> {
    store.lock().unwrap_or_else(|p| p.into_inner())
}

struct Daemon {
    store: Arc<Mutex<Store>>,
    domain: Domain,
    cfg: Config,
    layer: airlock_core::proto::LayerState,
    protection_gap_s: Option<i64>,
    started_at: i64,
}

fn main() {
    let mut args = std::env::args().skip(1);
    let mut root: Option<PathBuf> = None;
    let mut foreground = false;
    let mut listen_addr: Option<String> = None;
    let mut config_path: Option<PathBuf> = None;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--root" => match args.next() {
                Some(v) => root = Some(PathBuf::from(v)),
                None => {
                    eprintln!("--root 需要值；用法: airlockd [--root <dir>] [--foreground] [--config <file>]");
                    std::process::exit(5);
                }
            },
            "--foreground" => foreground = true,
            "--listen" => match args.next() {
                Some(v) => listen_addr = Some(v),
                None => {
                    eprintln!("--listen 需要值；用法: airlockd [--listen <addr>]");
                    std::process::exit(5);
                }
            },
            "--config" => match args.next() {
                Some(v) => config_path = Some(PathBuf::from(v)),
                None => {
                    eprintln!("--config 需要值；用法: airlockd [--root <dir>] [--foreground] [--config <file>]");
                    std::process::exit(5);
                }
            },
            "--version" => {
                println!("airlockd {}", env!("CARGO_PKG_VERSION"));
                return;
            }
            other => {
                eprintln!("未知参数 {other}；用法: airlockd [--root <dir>] [--foreground] [--config <file>]");
                std::process::exit(5);
            }
        }
    }

    // 信号处理器尽早注册：启动窗口内的 SIGTERM 也要走清理路径
    unsafe {
        libc::signal(libc::SIGTERM, on_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGINT, on_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }

    let domain = match Domain::discover(root.as_deref()) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("无法解析冲突域: {e}");
            std::process::exit(5);
        }
    };
    let mut cfg = match Config::load(config_path.as_deref(), &domain.root) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(5);
        }
    };
    if listen_addr.is_some() {
        cfg.listen_addr = listen_addr;
    }

    // SQLite 损坏 → 拒绝启动（§8.4），错误信息含修复指引（messages::SQLITE_CORRUPT）
    let store = match Store::open(&domain.db_path()) {
        Ok(s) => Arc::new(Mutex::new(s)),
        Err(Error::Integrity(m)) => {
            eprintln!("{m}");
            std::process::exit(5);
        }
        Err(e) => {
            eprintln!("存储打开失败: {e}");
            std::process::exit(5);
        }
    };

    let layer = resolve_layer(&cfg.enforcement);
    let boot_ts = now();
    let protection_gap_s = {
        let s = lock_store(&store);
        s.take_protection_gap(airlock_core::store::now_millis())
            .ok()
            .flatten()
    };

    let daemon = Daemon {
        store,
        domain,
        cfg,
        layer,
        protection_gap_s,
        started_at: boot_ts,
    };

    // 单实例保护（P2-1）：socket 可连接 = 已有 daemon 在跑（幂等成功）；
    // 连不上 = 陈旧残留，稍后清理再绑定。检查必须在 daemonize 之前，
    // 避免第二个实例先 fork 再退出、重复写 boot 审计。
    let sock = daemon.domain.socket_path();
    if sock.exists() && UnixStream::connect(&sock).is_ok() {
        println!("airlockd 已在运行（{}）", sock.display());
        return;
    }

    // TCP 复用完整的特权协议，只允许绑定回环地址。跨机监听没有认证层，
    // 因此必须在 daemonize 和 Unix socket 创建前拒绝非本机暴露。
    let tcp_listener = match daemon.cfg.listen_addr.as_deref() {
        Some(addr) => match bind_local_tcp_listener(addr) {
            Ok(listener) => {
                eprintln!("airlockd TCP protocol listening on {addr} (loopback only)");
                Some(listener)
            }
            Err(e) => {
                eprintln!("拒绝 TCP 监听 {addr}: {e}");
                std::process::exit(5);
            }
        },
        None => None,
    };

    if !foreground {
        daemonize(&daemon.domain);
    }

    // AC1.3：重启后从 SQLite 完整恢复租约状态（活跃租约保持在案，由 expires_at 决定存续）
    {
        let s = lock_store(&daemon.store);
        let _ = s.meta_set("boot_ts", &daemon.started_at.to_string());
        let recovered = lease::sweep_all(
            &s,
            &daemon.layer.id,
            &daemon.domain.dir.join("sessions"),
            Some(&daemon.domain.root),
        )
        .map(|v| v.len())
        .unwrap_or(0);
        let active = s
            .active_leases(Some(&daemon.domain.id), now())
            .map(|v| v.len())
            .unwrap_or(0);
        s.audit(
            "degrade",
            &Actor::default(),
            &daemon.domain.root.to_string_lossy(),
            None,
            &daemon.layer.id,
            Some(&serde_json::json!({
                "event_detail": "daemon_boot",
                "recovered_expired": recovered,
                "active_leases": active,
                "protection_gap_s": daemon.protection_gap_s,
            })),
        )
        .ok();
        println!(
            "airlockd 已启动：domain={} layer={} ({}{}) 活跃租约 {active}",
            daemon.domain.id,
            daemon.layer.id,
            daemon.layer.name,
            if daemon.layer.experimental {
                ", experimental"
            } else {
                ""
            }
        );
        if let Some(gap) = daemon.protection_gap_s {
            println!("{}", messages::protection_gap(gap));
        }
        let _ = recovered;
    }

    unsafe {
        libc::signal(libc::SIGTERM, on_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGINT, on_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }

    // 过期清扫线程：1s 周期（FR1.3 / FR3.3 / AC3.3）。
    // 退出统一由主循环驱动（SHUTDOWN → 清理 → 进程退出），清扫线程不 exit。
    {
        let store = Arc::clone(&daemon.store);
        let layer_id = daemon.layer.id.clone();
        let session_root = daemon.domain.dir.join("sessions");
        let domain_root = daemon.domain.root.clone();
        std::thread::spawn(move || loop {
            // try_lock：WouldBlock（本周期跳过）与中毒（恢复继续清扫）分开处理
            let guard = match store.try_lock() {
                Ok(g) => Some(g),
                Err(std::sync::TryLockError::Poisoned(p)) => Some(p.into_inner()),
                Err(std::sync::TryLockError::WouldBlock) => None,
            };
            if let Some(s) = guard {
                let _ = lease::sweep_all(&s, &layer_id, &session_root, Some(&domain_root));
                let _ = resources::sweep_cooldowns(&s);
            }
            std::thread::sleep(Duration::from_secs(1));
        });
    }

    let sock = daemon.domain.socket_path();
    let _ = std::fs::remove_file(&sock); // 清理陈旧残留（活 daemon 已在上方排除）
    let listener = match UnixListener::bind(&sock) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("绑定 {} 失败: {e}", sock.display());
            std::process::exit(5);
        }
    };
    // Optional local TCP transport. The wire format is the same versioned
    // NDJSON protocol as the Unix socket; bind_local_tcp_listener enforces
    // loopback-only access because this protocol has no authentication layer.
    if let Some(tcp) = tcp_listener {
        let _ = tcp.set_nonblocking(true);
        let d = Daemon {
            store: Arc::clone(&daemon.store),
            domain: daemon.domain.clone(),
            cfg: daemon.cfg.clone(),
            layer: daemon.layer.clone(),
            protection_gap_s: daemon.protection_gap_s,
            started_at: daemon.started_at,
        };
        std::thread::spawn(move || {
            while !SHUTDOWN.load(Ordering::SeqCst) {
                match tcp.accept() {
                    Ok((s, _)) => {
                        let _ = s.set_read_timeout(Some(Duration::from_secs(60)));
                        let _ = s.set_write_timeout(Some(Duration::from_secs(30)));
                        let d = Daemon {
                            store: Arc::clone(&d.store),
                            domain: d.domain.clone(),
                            cfg: d.cfg.clone(),
                            layer: d.layer.clone(),
                            protection_gap_s: d.protection_gap_s,
                            started_at: d.started_at,
                        };
                        std::thread::spawn(move || {
                            let _ = handle_conn(s, &d);
                        });
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(50));
                    }
                    Err(_) => break,
                }
            }
        });
    }
    // 写 pid 文件
    if let Err(e) = std::fs::write(daemon.domain.pid_path(), std::process::id().to_string()) {
        eprintln!(
            "⚠ pid 文件写入失败（{}）: {e}",
            daemon.domain.pid_path().display()
        );
    }

    // 非阻塞 accept + poll(SHUTDOWN 轮询)：poll 在连接到达时立即唤醒
    // （无轮询延迟），信号到达后最多 200ms 内走干净停机路径——
    // 而不是被 SA_RESTART 卡到下一条连接。
    let _ = listener.set_nonblocking(true);
    let listen_fd = listener.as_raw_fd();
    while !SHUTDOWN.load(Ordering::SeqCst) {
        let mut pfd = libc::pollfd {
            fd: listen_fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let rc = unsafe { libc::poll(&mut pfd, 1, 200) };
        if rc <= 0 {
            continue; // 超时或被信号中断 → 回到循环头检查 SHUTDOWN
        }
        match listener.accept() {
            Ok((s, _)) => {
                let _ = s.set_nonblocking(false);
                let _ = s.set_read_timeout(Some(Duration::from_secs(60)));
                let _ = s.set_write_timeout(Some(Duration::from_secs(30)));
                let d = Daemon {
                    store: Arc::clone(&daemon.store),
                    domain: daemon.domain.clone(),
                    cfg: daemon.cfg.clone(),
                    layer: daemon.layer.clone(),
                    protection_gap_s: daemon.protection_gap_s,
                    started_at: daemon.started_at,
                };
                std::thread::spawn(move || {
                    let _ = handle_conn(s, &d);
                });
            }
            Err(_) => continue,
        }
    }

    // 干净停机：清 socket/pid + 记录正常退出（不构成保护空窗）
    let _ = std::fs::remove_file(&sock);
    let _ = std::fs::remove_file(daemon.domain.pid_path());
    let s = lock_store(&daemon.store);
    let _ = s.mark_clean_shutdown();
}

fn bind_local_tcp_listener(addr: &str) -> io::Result<TcpListener> {
    let listener = TcpListener::bind(addr)?;
    let bound = listener.local_addr()?;
    validate_local_tcp_addr(bound)?;
    Ok(listener)
}

fn validate_local_tcp_addr(bound: SocketAddr) -> io::Result<()> {
    if bound.ip().is_loopback() {
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("监听地址必须是回环地址（实际绑定为 {bound}）"),
    ))
}

fn daemonize(domain: &Domain) {
    let log = std::fs::File::create(domain.dir.join("daemon.log")).ok();
    unsafe {
        let pid = libc::fork();
        if pid > 0 {
            std::process::exit(0); // 父进程退出
        }
        if pid < 0 {
            eprintln!("fork 失败，改为前台运行");
            return;
        }
        libc::setsid();
        // 输出重定向到 daemon.log
        if let Some(f) = log {
            libc::dup2(f.as_raw_fd(), libc::STDOUT_FILENO);
            libc::dup2(f.as_raw_fd(), libc::STDERR_FILENO);
        }
        let devnull = std::ffi::CString::new("/dev/null").unwrap();
        let fd = libc::open(devnull.as_ptr(), libc::O_RDONLY);
        if fd >= 0 {
            libc::dup2(fd, libc::STDIN_FILENO);
        }
    }
}

trait ProtocolStream: Read + Write {
    fn clone_stream(&self) -> std::io::Result<Self>
    where
        Self: Sized;
}

impl ProtocolStream for UnixStream {
    fn clone_stream(&self) -> std::io::Result<Self> {
        self.try_clone()
    }
}

impl ProtocolStream for std::net::TcpStream {
    fn clone_stream(&self) -> std::io::Result<Self> {
        self.try_clone()
    }
}

fn handle_conn<S: ProtocolStream>(stream: S, d: &Daemon) -> Result<()> {
    let mut reader = BufReader::new(stream.clone_stream()?);
    let mut w = stream;
    // 循环服务直到客户端 EOF——客户端在同一连接上发多个请求是合法用法
    // （P2-4：以前「一连接一请求」让复用方的第二次 write 撞 EPIPE）
    loop {
        // 按行限长（1 MiB/请求）：超长行直接断连，不给本机客户端耗内存的机会
        let mut limited = (&mut reader).take(MAX_REQUEST_BYTES);
        let mut line = String::new();
        let n = limited.read_line(&mut line)?;
        if n == 0 {
            return Ok(()); // 客户端关闭
        }
        if !line.ends_with('\n') {
            return Ok(()); // 超过单行上限被截断 → 断开（ Take 已复位，残行不再读）
        }
        // 单请求 panic 只丢这一连接（返回 internal 错误），不影响其他连接
        let resp = match serde_json::from_str::<proto::Request>(line.trim()) {
            Ok(req) => std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| dispatch(&req, d)))
                .unwrap_or_else(|_| {
                    proto::Response::err(&proto::simple_error("internal", "请求处理内部错误"))
                }),
            Err(e) => proto::Response::err(&proto::simple_error("config", &format!("坏请求: {e}"))),
        };
        let mut out = serde_json::to_string(&resp)?;
        out.push('\n');
        w.write_all(out.as_bytes())?;
        w.flush()?;
    }
}

/// 单请求行上限：1 MiB（本机客户端也不允许投超长行耗内存）。
const MAX_REQUEST_BYTES: u64 = 1 << 20;

fn dispatch(req: &proto::Request, d: &Daemon) -> proto::Response {
    let p = &req.params;
    let result: Result<serde_json::Value> = (|| {
        let store = d
            .store
            .lock()
            .map_err(|_| Error::Other("存储锁中毒".into()))?;
        match req.method.as_str() {
            "ping" => Ok(serde_json::json!({
                "version": env!("CARGO_PKG_VERSION"),
                "layer": d.layer,
                "protection_gap_s": d.protection_gap_s,
                "pid": std::process::id(),
                "uptime_s": now() - d.started_at,
            })),
            "register" => {
                let agent_id = str_or(p, "agent_id", "unknown-agent");
                let s: SessionInfo =
                    resources::register_session(&store, &agent_id, d.cfg.port_base)?;
                store.audit(
                    "claim",
                    &Actor { agent: agent_id, session: s.session_id.clone(), pid_tree: vec![] },
                    "<session-register>",
                    None,
                    &d.layer.id,
                    Some(&serde_json::json!({ "event_detail": "session_register", "port_base": s.port_base })),
                )?;
                Ok(serde_json::to_value(&s)?)
            }
            "claim" => {
                let agent_id = str_or(p, "agent_id", "unknown-agent");
                let session_id = str_or(p, "session_id", "");
                let glob = str_or(p, "glob", "");
                if glob.is_empty() {
                    return Err(Error::Config("claim 需要 glob 参数".into()));
                }
                let params = lease::ClaimParams {
                    conflict_domain: d.domain.id.clone(),
                    agent_id,
                    session_id,
                    glob,
                    intent: opt_str(p, "intent"),
                    ttl_s: p.get("ttl_s").and_then(|v| v.as_i64()),
                    heartbeat_s: p
                        .get("heartbeat_s")
                        .and_then(|v| v.as_i64())
                        .unwrap_or(d.cfg.heartbeat_s),
                    layer: d.layer.id.clone(),
                    actor: actor_from(p),
                    root: Some(d.domain.root.clone()),
                };
                let ok: ClaimOk = lease::claim(&store, &d.cfg, &params)?;
                Ok(serde_json::to_value(&ok)?)
            }
            "ensure_claim" => {
                // hook 自动 claim 的幂等语义：本会话已有覆盖该 glob 的活跃租约 →
                // 直接返回**并续约**（长会话不会在 30 分钟后失去保护）；否则走正常 claim。
                let agent_id = str_or(p, "agent_id", "unknown-agent");
                let session_id = str_or(p, "session_id", "");
                let glob = str_or(p, "glob", "");
                if glob.is_empty() {
                    return Err(Error::Config("ensure_claim 需要 glob 参数".into()));
                }
                let now_ts = now();
                let actives = store.active_leases(Some(&d.domain.id), now_ts)?;
                if let Some(existing) = actives.iter().find(|l| {
                    l.session_id == session_id && airlock_core::glob::overlaps(&glob, &l.glob)
                }) {
                    store.update_lease_heartbeat(&existing.id, now_ts, now_ts + existing.ttl_s)?;
                    let mut renewed = existing.clone();
                    renewed.last_heartbeat = now_ts;
                    renewed.expires_at = now_ts + existing.ttl_s;
                    let ok = ClaimOk {
                        lease: renewed,
                        prediction: airlock_core::proto::Prediction {
                            risk: "none".into(),
                            with_leases: vec![],
                            involved_symbols: vec![],
                        },
                    };
                    return Ok(serde_json::to_value(&ok)?);
                }
                let params = lease::ClaimParams {
                    conflict_domain: d.domain.id.clone(),
                    agent_id,
                    session_id,
                    glob,
                    intent: opt_str(p, "intent"),
                    ttl_s: p.get("ttl_s").and_then(|v| v.as_i64()),
                    heartbeat_s: p
                        .get("heartbeat_s")
                        .and_then(|v| v.as_i64())
                        .unwrap_or(d.cfg.heartbeat_s),
                    layer: d.layer.id.clone(),
                    actor: actor_from(p),
                    root: Some(d.domain.root.clone()),
                };
                let ok: ClaimOk = lease::claim(&store, &d.cfg, &params)?;
                Ok(serde_json::to_value(&ok)?)
            }
            "release" => {
                let actor = actor_from(p);
                let lease_id = str_or(p, "lease_id", "");
                if !lease_id.is_empty() {
                    // 单租约释放：必须携带与租约一致的 session_id（属主校验，P1-3）。
                    // lease_id 优先匹配——CLI 的 `release <id>` 同时带 session_id，
                    // 若先匹配 session 会误走 release_all，单租约语义失效。
                    let session = str_or(p, "session_id", "");
                    if session.is_empty() {
                        return Err(Error::Config("release 需要 session_id（属主校验）".into()));
                    }
                    let released = lease::release(
                        &store,
                        &lease_id,
                        &actor,
                        &d.layer.id,
                        Some(&session),
                        Some(&d.domain.root),
                    )?;
                    if !released {
                        return Err(Error::NotFound(format!("租约 {lease_id} 不存在或已释放")));
                    }
                    return Ok(serde_json::json!({ "released": 1 }));
                }
                if let Some(sid) = opt_str(p, "session_id") {
                    let n = lease::release_all(
                        &store,
                        &sid,
                        &actor,
                        &d.layer.id,
                        Some(&d.domain.root),
                    )?;
                    return Ok(serde_json::json!({ "released": n }));
                }
                Err(Error::Config("release 需要 lease_id 或 session_id".into()))
            }
            "heartbeat" => {
                let lease_id = str_or(p, "lease_id", "");
                let session = str_or(p, "session_id", "");
                if session.is_empty() {
                    return Err(Error::Config(
                        "heartbeat 需要 session_id（属主校验）".into(),
                    ));
                }
                let ok = lease::heartbeat(
                    &store,
                    &lease_id,
                    &actor_from(p),
                    &d.layer.id,
                    Some(&session),
                )?;
                if !ok {
                    return Err(Error::NotFound(format!("租约 {lease_id} 不存在或已过期")));
                }
                Ok(serde_json::json!({ "heartbeat": "ok" }))
            }
            "report_cost" => {
                let lease_id = str_or(p, "lease_id", "");
                let tokens = p.get("tokens").and_then(|v| v.as_u64()).unwrap_or(0);
                let cost_cents = p.get("cost_cents").and_then(|v| v.as_u64()).unwrap_or(0);
                if lease_id.is_empty() {
                    return Err(Error::Config("report_cost 需要 lease_id".into()));
                }
                store.update_lease_cost(&lease_id, tokens, cost_cents)?;
                Ok(serde_json::json!({ "report_cost": "ok" }))
            }
            "rollback" => {
                let lease_id = str_or(p, "lease_id", "");
                if lease_id.is_empty() {
                    return Err(Error::Config("rollback 需要 lease_id".into()));
                }
                let snap_dir = d.domain.root.join(".airlock").join("snapshots");
                let snapshot = airlock_core::snapshot::load_snapshot_from(&snap_dir, &lease_id)?;
                match snapshot {
                    Some(snap) => {
                        let restored =
                            airlock_core::snapshot::rollback_lease(&d.domain.root, &snap)?;
                        store.audit(
                            "rollback",
                            &actor_from(p),
                            &format!("lease:{lease_id}"),
                            Some(&lease_id),
                            &d.layer.id,
                            Some(&serde_json::json!({ "files_restored": restored })),
                        )?;
                        Ok(serde_json::json!({ "rollback": "ok", "files_restored": restored }))
                    }
                    None => Err(Error::NotFound(format!("租约 {lease_id} 的快照不存在"))),
                }
            }
            "snapshots" => {
                let snap_dir = d.domain.root.join(".airlock").join("snapshots");
                let snaps = airlock_core::snapshot::list_snapshots_from(&snap_dir)?;
                Ok(serde_json::to_value(&snaps)?)
            }
            "status" => {
                let active_only = p
                    .get("active_only")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let leases = if active_only {
                    store.active_leases(Some(&d.domain.id), now())?
                } else {
                    store.list_leases(Some(&d.domain.id), false)?
                };
                let sessions = store.list_sessions(false)?;
                let ports = store.list_ports()?;
                let report = StatusReport {
                    conflict_domain: d.domain.id.clone(),
                    repo_root: d.domain.root.to_string_lossy().into(),
                    is_git: d.domain.is_git,
                    layer: d.layer.clone(),
                    leases,
                    sessions,
                    ports,
                    protection_gap_s: d.protection_gap_s,
                };
                Ok(serde_json::to_value(&report)?)
            }
            "log" => {
                let since = p.get("since_ts").and_then(|v| v.as_i64());
                let limit = p.get("limit").and_then(|v| v.as_i64()).unwrap_or(500);
                Ok(serde_json::to_value(&store.audit_query(since, limit)?)?)
            }
            "verify" => {
                let broken = store.audit_verify()?;
                Ok(serde_json::json!({ "broken_seqs": broken, "intact": broken.is_empty() }))
            }
            "board_read" => {
                let budget =
                    p.get("token_budget")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(d.cfg.board_token_budget as u64) as usize;
                Ok(serde_json::to_value(&store.board_read(budget)?)?)
            }
            "board_write" => {
                let body = str_or(p, "body", "");
                if body.is_empty() {
                    return Err(Error::Config("board_write 需要 body".into()));
                }
                let entry = airlock_core::proto::BoardEntry {
                    id: uuid::Uuid::new_v4().to_string(),
                    lease_id: opt_str(p, "lease_id"),
                    origin: "agent".into(),
                    body,
                    status: "active".into(),
                    created_at: now(),
                    archived_at: None,
                };
                store.insert_board_entry(&entry)?;
                Ok(serde_json::to_value(&entry)?)
            }
            "alloc_port" => {
                let session_id = str_or(p, "session_id", "");
                let purpose = str_or(p, "purpose", "dev");
                let sessions = store.list_sessions(false)?;
                let session = sessions
                    .iter()
                    .find(|s| s.session_id == session_id)
                    .ok_or_else(|| Error::NotFound(format!("会话 {session_id} 未注册")))?
                    .clone();
                let info: PortInfo = resources::allocate_port(&store, &session, &purpose)?;
                Ok(serde_json::to_value(&info)?)
            }
            "session_end" => {
                let session_id = str_or(p, "session_id", "");
                let n = resources::end_session_ports(&store, &session_id)?;
                let actor = actor_from(p);
                lease::release_all(
                    &store,
                    &session_id,
                    &actor,
                    &d.layer.id,
                    Some(&d.domain.root),
                )?;
                for name in store.misc_locks_by_session(&session_id)? {
                    let _ = store.misc_lock_release(&name, &session_id);
                }
                Ok(serde_json::json!({ "ports_cooled": n }))
            }
            "misc_lock" => {
                let name = str_or(p, "name", "");
                let session_id = str_or(p, "session_id", "");
                match store.misc_lock_acquire(&name, &session_id)? {
                    None => Ok(serde_json::json!({ "acquired": true })),
                    Some(holder) => Ok(serde_json::json!({ "acquired": false, "holder": holder })),
                }
            }
            "misc_unlock" => {
                let name = str_or(p, "name", "");
                let session_id = str_or(p, "session_id", "");
                Ok(serde_json::json!({ "released": store.misc_lock_release(&name, &session_id)? }))
            }
            "branch_db" => {
                let path = PathBuf::from(str_or(p, "path", ""));
                let session_id = str_or(p, "session_id", "");
                let out = resources::branch_sqlite(&path, &d.domain.session_dir(&session_id))?;
                Ok(serde_json::json!({ "session_db": out.to_string_lossy() }))
            }
            "degrade" => {
                let actor = actor_from(p);
                store.audit(
                    "degrade",
                    &actor,
                    &str_or(p, "path", "<unknown>"),
                    None,
                    &d.layer.id,
                    Some(&serde_json::json!({ "reason": str_or(p, "reason", "") })),
                )?;
                Ok(serde_json::json!({ "logged": true }))
            }
            "stop" => {
                SHUTDOWN.store(true, Ordering::SeqCst);
                Ok(serde_json::json!({ "stopping": true }))
            }
            other => Err(Error::NotFound(format!("未知方法 {other}"))),
        }
    })();

    match result {
        Ok(data) => proto::Response {
            ok: true,
            data: Some(data),
            error: None,
        },
        Err(e) => match e {
            AirlockError::Conflict(r) => {
                proto::Response::err(&serde_json::to_value(*r).unwrap_or_default())
            }
            AirlockError::NotFound(m) => {
                proto::Response::err(&proto::simple_error("not_found", &m))
            }
            AirlockError::Config(m) => proto::Response::err(&proto::simple_error("config", &m)),
            AirlockError::Integrity(m) => {
                proto::Response::err(&proto::simple_error("integrity", &m))
            }
            other => proto::Response::err(&proto::simple_error("internal", &other.to_string())),
        },
    }
}

fn str_or(p: &serde_json::Value, key: &str, default: &str) -> String {
    p.get(key)
        .and_then(|v| v.as_str())
        .unwrap_or(default)
        .to_string()
}

fn opt_str(p: &serde_json::Value, key: &str) -> Option<String> {
    p.get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty())
}

fn actor_from(p: &serde_json::Value) -> Actor {
    Actor {
        agent: str_or(p, "agent_id", ""),
        session: str_or(p, "session_id", ""),
        pid_tree: p
            .get("pid_tree")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::validate_local_tcp_addr;

    #[test]
    fn tcp_listener_allows_loopback_only() {
        assert!(validate_local_tcp_addr("127.0.0.1:9418".parse::<SocketAddr>().unwrap()).is_ok());
        assert!(validate_local_tcp_addr("[::1]:9418".parse::<SocketAddr>().unwrap()).is_ok());
        assert!(validate_local_tcp_addr("0.0.0.0:9418".parse::<SocketAddr>().unwrap()).is_err());
        assert!(validate_local_tcp_addr("[::]:9418".parse::<SocketAddr>().unwrap()).is_err());
    }
}
