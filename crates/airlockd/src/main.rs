//! airlockd —— Airlock 常驻守护进程。
//!
//! 职责（PRD §5 架构图）：租约引擎唯一权威事实源（P5）、hash-chained 审计、
//! 资源分配、黑板维护、过期清扫、保护空窗追踪（AC2.4）。
//! SQLite 损坏时拒绝启动（§8.4：宁可不可用，不可假保护）。

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, ToSocketAddrs};
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
/// 活跃连接线程上限：超过后 accept 循环内联串行处理（背压），防连接洪泛耗尽内存。
const MAX_CONN_THREADS: usize = 64;
static ACTIVE_CONNS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

extern "C" fn on_signal(_sig: libc::c_int) {
    SHUTDOWN.store(true, Ordering::SeqCst);
}

/// Mutex 中毒恢复：一个请求线程 panic 不应砖掉整个 daemon（P2-3）。
fn lock_store(store: &Mutex<Store>) -> std::sync::MutexGuard<'_, Store> {
    store.lock().unwrap_or_else(|p| p.into_inner())
}

/// F13：为（新建或幂等命中的）租约挂上凭据。请求了 cred 资源时：
/// 幂等路径优先复用该租约现存 active 凭据的 env（不重复发放）；无则新发放。
/// 任何失败都先释放刚建立的租约再上抛（部分失败不泄漏，P1-5）。
fn attach_credentials(
    store: &Store,
    d: &Daemon,
    ok: &mut ClaimOk,
    cred_resource: Option<String>,
    agent_id: &str,
    session_id: &str,
) -> Result<()> {
    fn rollback_lease(store: &Store, d: &Daemon, lease_id: &str, actor: &Actor, session_id: &str) {
        let _ = lease::release(
            store,
            lease_id,
            actor,
            &d.layer.id,
            Some(session_id),
            Some(&d.domain.root),
        );
    }
    let Some(resource) = cred_resource else {
        return Ok(());
    };
    let actor = Actor {
        agent: agent_id.to_string(),
        session: session_id.to_string(),
        pid_tree: vec![],
    };
    let backend = match airlock_core::credentials::backend_from_config(&d.cfg, &d.domain.dir) {
        Ok(b) => b,
        Err(e) => {
            rollback_lease(store, d, &ok.lease.id, &actor, session_id);
            return Err(e);
        }
    };
    let Some(backend) = backend else {
        rollback_lease(store, d, &ok.lease.id, &actor, session_id);
        return Err(Error::Config(
            "请求了凭据（cred）但凭据代理未启用：airlock.toml 配置 credentials_backend = \"file\" 或 \"vault\""
                .into(),
        ));
    };
    // 幂等/重复 claim：复用该租约现存 active 凭据的 env；无则新发放
    let mut reused = std::collections::BTreeMap::new();
    if let Ok(rows) = store.list_credentials(Some(&ok.lease.id)) {
        for r in rows {
            if r.status != "active" || r.resource != resource {
                continue;
            }
            if let Some(env) = r.meta.as_ref().and_then(|m| m.get("env")) {
                if let Ok(map) = serde_json::from_value::<std::collections::BTreeMap<String, String>>(
                    env.clone(),
                ) {
                    reused.extend(map);
                }
            }
        }
    }
    if !reused.is_empty() {
        ok.credentials = Some(reused);
        return Ok(());
    }
    let scope = airlock_core::credentials::CredScope {
        lease_id: ok.lease.id.clone(),
        agent_id: agent_id.to_string(),
        resource,
        ttl_s: ok.lease.ttl_s,
    };
    match airlock_core::credentials::issue_for_lease(store, backend.as_ref(), &scope) {
        Ok(env) => {
            ok.credentials = Some(env);
            Ok(())
        }
        Err(e) => {
            rollback_lease(store, d, &ok.lease.id, &actor, session_id);
            Err(e)
        }
    }
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

    // 数据目录收紧为 0700：租约状态、审计链、F13 凭据源文件都在这里
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&domain.dir, std::fs::Permissions::from_mode(0o700));
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

    // 单实例保护（P2-1）：对 pid 文件持独占 flock——检查与持有是同一个原子
    // 操作，杜绝「检查时没跑、bind 前第二个实例也通过检查」的竞态窗口。
    // fd 在整个进程生命周期内保持打开（fork 继承，daemonize 后锁仍归子进程）。
    let _pid_guard = {
        let pid_path = daemon.domain.pid_path();
        let file = match std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&pid_path)
        {
            Ok(f) => f,
            Err(e) => {
                eprintln!("无法打开 pid 文件 {}: {e}", pid_path.display());
                std::process::exit(5);
            }
        };
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc != 0 {
            println!(
                "airlockd 已在运行（pid 文件 {} 被占用）",
                pid_path.display()
            );
            return;
        }
        file
    };

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
        // F12：审计当前生效政策（含 sha256；政策文件入库即可审计）。
        // 政策存在且非法 → 拒绝启动（fail-closed，与 claim 层口径一致）。
        match airlock_core::policy::Policy::load(&daemon.domain.root) {
            Ok(Some(_)) => {
                let policy_path = airlock_core::policy::Policy::path_for(&daemon.domain.root);
                let sha = airlock_core::policy::Policy::file_sha256(&daemon.domain.root);
                let _ = s.audit(
                    "policy_load",
                    &Actor::default(),
                    &policy_path.to_string_lossy(),
                    None,
                    &daemon.layer.id,
                    Some(&serde_json::json!({ "sha256": sha })),
                );
            }
            Ok(None) => {}
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(5);
            }
        }
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

    // 过期清扫线程：1s 周期（FR1.3 / FR3.3 / AC3.3 / F13 ≤60s 吊销）。
    // 退出统一由主循环驱动（SHUTDOWN → 清理 → 进程退出），清扫线程不 exit。
    {
        let store = Arc::clone(&daemon.store);
        let layer_id = daemon.layer.id.clone();
        let session_root = daemon.domain.dir.join("sessions");
        let domain_root = daemon.domain.root.clone();
        let cred_cfg = daemon.cfg.clone();
        let cred_dir = daemon.domain.dir.clone();
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
                // F13：租约已不活跃的凭据 → 后端吊销（1s 周期 ⇒ ≤60s 结构性保证）
                if let Ok(Some(_)) =
                    airlock_core::credentials::backend_from_config(&cred_cfg, &cred_dir)
                {
                    let _ = airlock_core::credentials::sweep_revocations(&s, &cred_cfg, &cred_dir);
                }
            }
            std::thread::sleep(Duration::from_secs(1));
        });
    }

    let sock = daemon.domain.socket_path();
    // 清理陈旧残留：flock 已确保本进程是唯一 daemon，此时才允许移除旧 socket
    let _ = std::fs::remove_file(&sock);
    let listener = match UnixListener::bind(&sock) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("绑定 {} 失败: {e}", sock.display());
            std::process::exit(5);
        }
    };
    // socket 收紧为 0600：协议唯一「认证」是客户端自报的 session_id，
    // 权限必须由文件模式保证（不能依赖 umask——某些发行版默认 000/002）
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o600));
    }
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
                        spawn_conn_handler(s, &d);
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
                spawn_conn_handler(s, &daemon);
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
    // 先解析并校验，再绑定：若先 bind 后校验，会存在短暂监听在
    // 全部接口上的窗口（外部连接可趁虚而入）
    let resolved: Vec<SocketAddr> = addr.to_socket_addrs()?.collect();
    let Some(target) = resolved.first() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("无法解析监听地址 {addr}"),
        ));
    };
    validate_local_tcp_addr(*target)?;
    let listener = TcpListener::bind(*target)?;
    // 双重校验：bind 可能改写端口（:0）或按系统解析回退到非回环地址
    validate_local_tcp_addr(listener.local_addr()?)?;
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
    // 追加而非截断：重启后仍保留上次崩溃前的日志（事后取证需要）
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(domain.dir.join("daemon.log"))
        .ok();
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

    fn configure(&self) {
        let _ = self.set_nonblocking_read(60);
        let _ = self.set_nonblocking_write(30);
    }

    fn set_nonblocking_read(&self, secs: u64) -> std::io::Result<()>;
    fn set_nonblocking_write(&self, secs: u64) -> std::io::Result<()>;
    fn disable_nonblocking(&self) -> std::io::Result<()>;
}

impl ProtocolStream for UnixStream {
    fn clone_stream(&self) -> std::io::Result<Self> {
        self.try_clone()
    }
    fn set_nonblocking_read(&self, secs: u64) -> std::io::Result<()> {
        self.set_read_timeout(Some(Duration::from_secs(secs)))
    }
    fn set_nonblocking_write(&self, secs: u64) -> std::io::Result<()> {
        self.set_write_timeout(Some(Duration::from_secs(secs)))
    }
    fn disable_nonblocking(&self) -> std::io::Result<()> {
        self.set_nonblocking(false)
    }
}

impl ProtocolStream for std::net::TcpStream {
    fn clone_stream(&self) -> std::io::Result<Self> {
        self.try_clone()
    }
    fn set_nonblocking_read(&self, secs: u64) -> std::io::Result<()> {
        self.set_read_timeout(Some(Duration::from_secs(secs)))
    }
    fn set_nonblocking_write(&self, secs: u64) -> std::io::Result<()> {
        self.set_write_timeout(Some(Duration::from_secs(secs)))
    }
    fn disable_nonblocking(&self) -> std::io::Result<()> {
        self.set_nonblocking(false)
    }
}

/// 连接处理：优先派线程；达到上限后在调用线程内联串行处理（背压）。
fn spawn_conn_handler<S: ProtocolStream + Send + 'static>(s: S, base: &Daemon) {
    let _ = s.disable_nonblocking();
    s.configure();
    let d = Daemon {
        store: Arc::clone(&base.store),
        domain: base.domain.clone(),
        cfg: base.cfg.clone(),
        layer: base.layer.clone(),
        protection_gap_s: base.protection_gap_s,
        started_at: base.started_at,
    };
    if ACTIVE_CONNS.load(Ordering::SeqCst) >= MAX_CONN_THREADS {
        // 上限已到：内联处理会阻塞 accept 循环——这正是背压，新连接排队等待
        let _ = handle_conn(s, &d);
        return;
    }
    ACTIVE_CONNS.fetch_add(1, Ordering::SeqCst);
    std::thread::spawn(move || {
        let _ = handle_conn(s, &d);
        ACTIVE_CONNS.fetch_sub(1, Ordering::SeqCst);
    });
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
        // 中毒恢复而非报错：一次 panic 后 catch_unwind 已兜住本连接，
        // 锁必须恢复可用，否则后续所有请求都会砖掉（P2-3）
        let store = lock_store(&d.store);
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
                // 空 session_id 会产生 owner 永远无法 release 的租约（release/heartbeat
                // 都要求非空 session_id），必须与它们一致地拒绝
                if session_id.is_empty() {
                    return Err(Error::Config("claim 需要 session_id".into()));
                }
                let params = lease::ClaimParams {
                    conflict_domain: d.domain.id.clone(),
                    agent_id: agent_id.clone(),
                    session_id: session_id.clone(),
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
                let mut ok: ClaimOk = lease::claim(&store, &d.cfg, &params)?;
                // F13：按需发放凭据（失败回滚租约，部分失败不泄漏）
                attach_credentials(
                    &store,
                    d,
                    &mut ok,
                    opt_str(p, "cred"),
                    &agent_id,
                    &session_id,
                )?;
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
                if session_id.is_empty() {
                    return Err(Error::Config("ensure_claim 需要 session_id".into()));
                }
                // 入口 glob 与 claim 同标准校验：快路径也不能绕过
                if let Err(m) = airlock_core::glob::validate_pattern(&glob) {
                    return Err(Error::Config(format!("非法 glob: {m}")));
                }
                let now_ts = now();
                let actives = store.active_leases(Some(&d.domain.id), now_ts)?;
                if let Some(existing) = actives.iter().find(|l| {
                    l.session_id == session_id && airlock_core::glob::overlaps(&glob, &l.glob)
                }) {
                    store.update_lease_heartbeat(&existing.id, now_ts, now_ts + existing.ttl_s)?;
                    // 续约计入审计链（与 lease::heartbeat 口径一致）
                    store.audit(
                        "heartbeat",
                        &actor_from(p),
                        &existing.glob,
                        Some(&existing.id),
                        &d.layer.id,
                        Some(&serde_json::json!({ "event_detail": "ensure_claim_renew" })),
                    )?;
                    let mut renewed = existing.clone();
                    renewed.last_heartbeat = now_ts;
                    renewed.expires_at = now_ts + existing.ttl_s;
                    let mut ok = ClaimOk {
                        lease: renewed,
                        prediction: airlock_core::proto::Prediction {
                            risk: "none".into(),
                            with_leases: vec![],
                            involved_symbols: vec![],
                        },
                        credentials: None,
                    };
                    // F13：幂等路径同样支持凭据请求（复用现存 active 凭据或补发）
                    attach_credentials(
                        &store,
                        d,
                        &mut ok,
                        opt_str(p, "cred"),
                        &agent_id,
                        &session_id,
                    )?;
                    return Ok(serde_json::to_value(&ok)?);
                }
                let params = lease::ClaimParams {
                    conflict_domain: d.domain.id.clone(),
                    agent_id: agent_id.clone(),
                    session_id: session_id.clone(),
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
                let mut ok: ClaimOk = lease::claim(&store, &d.cfg, &params)?;
                attach_credentials(
                    &store,
                    d,
                    &mut ok,
                    opt_str(p, "cred"),
                    &agent_id,
                    &session_id,
                )?;
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
                // 属主校验（与 release/heartbeat 同级）：凭 lease_id 不能改别人的账
                let session = str_or(p, "session_id", "");
                if session.is_empty() {
                    return Err(Error::Config(
                        "report_cost 需要 session_id（属主校验）".into(),
                    ));
                }
                let lease = store
                    .get_lease(&lease_id)?
                    .ok_or_else(|| Error::NotFound(format!("租约 {lease_id} 不存在")))?;
                if lease.session_id != session {
                    return Err(Error::Config(format!(
                        "租约 {lease_id} 不属于会话 {session}"
                    )));
                }
                store.update_lease_cost(&lease_id, tokens, cost_cents)?;
                Ok(serde_json::json!({ "report_cost": "ok" }))
            }
            "rollback" => {
                let lease_id = str_or(p, "lease_id", "");
                if lease_id.is_empty() {
                    return Err(Error::Config("rollback 需要 lease_id".into()));
                }
                // 属主校验：rollback 会 git restore 该租约的文件，凭 lease_id
                // （status 可枚举）不能回滚别的会话正在进行的工作
                let session = str_or(p, "session_id", "");
                if session.is_empty() {
                    return Err(Error::Config("rollback 需要 session_id（属主校验）".into()));
                }
                let lease = store
                    .get_lease(&lease_id)?
                    .ok_or_else(|| Error::NotFound(format!("租约 {lease_id} 不存在")))?;
                if lease.session_id != session {
                    return Err(Error::Config(format!(
                        "租约 {lease_id} 不属于会话 {session}"
                    )));
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
                Ok(serde_json::to_value(&store.board_read(budget, 7)?)?)
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
                // session_id 会拼进数据目录路径、path 会被读取复制：
                // 都是不可信输入。session_id 限定 daemon 自签的 UUID 字符集，
                // path 限定在仓库根之内。
                if !is_safe_session_id(&session_id) {
                    return Err(Error::Config("branch_db 需要合法的 session_id".into()));
                }
                let canon_path = path.canonicalize().map_err(|_| {
                    Error::Config(format!("branch_db 源库不存在: {}", path.display()))
                })?;
                if !canon_path.starts_with(&d.domain.root) {
                    return Err(Error::Config("branch_db 的 path 必须位于仓库内".into()));
                }
                let out =
                    resources::branch_sqlite(&canon_path, &d.domain.session_dir(&session_id))?;
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
            "creds_list" => {
                // F13：凭据清单（meta 脱敏：env 值替换为变量名清单）
                let lease_id = opt_str(p, "lease_id");
                let rows = store.list_credentials(lease_id.as_deref())?;
                let sanitized: Vec<airlock_core::proto::CredRow> = rows
                    .iter()
                    .map(airlock_core::credentials::sanitize_row)
                    .collect();
                Ok(serde_json::to_value(&sanitized)?)
            }
            "creds_revoke" => {
                // F13：立即吊销（管理员）；后端以凭据记录的 backend 为准
                let cred_id = str_or(p, "cred_id", "");
                if cred_id.is_empty() {
                    return Err(Error::Config("creds_revoke 需要 cred_id".into()));
                }
                let row = store
                    .get_credential(&cred_id)?
                    .ok_or_else(|| Error::NotFound(format!("凭据 {cred_id} 不存在")))?;
                let backend = airlock_core::credentials::backend_by_name(
                    &d.cfg,
                    &d.domain.dir,
                    &row.backend,
                )?
                .ok_or_else(|| Error::Config(format!("凭据后端 `{}` 不可用", row.backend)))?;
                let revoked =
                    airlock_core::credentials::revoke_one(&store, backend.as_ref(), &cred_id)?;
                Ok(serde_json::json!({ "revoked": revoked }))
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

/// session_id 用作路径组件（sessions/<sid>/…）时的白名单校验：
/// daemon 自签的是 UUID，只接受 `[A-Za-z0-9-]`，显式杜绝 `../` 类注入。
fn is_safe_session_id(sid: &str) -> bool {
    !sid.is_empty() && sid.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
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
