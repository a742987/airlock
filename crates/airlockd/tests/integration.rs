//! 集成测试：验收标准（AC）对照 PRD §4。
//! 测试自建临时 git 仓库 + 真实 airlockd 进程（CARGO_BIN_EXE 注入）。

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

/// macOS 的 `std::env::temp_dir()`（/var/folders/...）会让 unix socket 路径超过
/// `SUN_LEN`(104)，daemon.sock 无法绑定——macOS 上改用 /tmp（/private/tmp）。
#[cfg(target_os = "macos")]
fn short_tmp() -> PathBuf {
    PathBuf::from("/tmp")
}

#[cfg(not(target_os = "macos"))]
fn short_tmp() -> PathBuf {
    std::env::temp_dir()
}

struct Env {
    root: PathBuf,
    sock: PathBuf,
    daemon: Option<Child>,
}

impl Env {
    /// 启动 daemon 于临时 git 仓库。
    fn new(tag: &str) -> Env {
        let root = short_tmp().join(format!("airlock-it-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src/auth")).unwrap();
        std::fs::create_dir_all(root.join("src/api")).unwrap();
        std::fs::create_dir_all(root.join("docs")).unwrap();
        std::fs::write(root.join("src/auth/login.ts"), "orig").unwrap();
        let st = Command::new("git")
            .args(["init", "-q", "."])
            .current_dir(&root)
            .status()
            .unwrap();
        assert!(st.success(), "git init 失败——测试环境需要 git");

        let mut env = Env {
            root,
            sock: PathBuf::new(),
            daemon: None,
        };
        env.start_daemon();
        env
    }

    fn start_daemon(&mut self) {
        let exe = env!("CARGO_BIN_EXE_airlockd");
        let child = Command::new(exe)
            .arg("--root")
            .arg(&self.root)
            .arg("--foreground")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("启动 airlockd");
        self.daemon = Some(child);
        self.sock = self.root.join(".git/airlock/daemon.sock");
        for _ in 0..100 {
            if UnixStream::connect(&self.sock).is_ok() {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("daemon 启动超时");
    }

    fn call(&self, method: &str, params: Value) -> Result<Value, Value> {
        let mut stream = UnixStream::connect(&self.sock).expect("连接 daemon");
        stream
            .set_read_timeout(Some(Duration::from_secs(60)))
            .unwrap();
        let req = json!({ "v": 1, "method": method, "params": params });
        stream.write_all(format!("{req}\n").as_bytes()).unwrap();
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let resp: Value = serde_json::from_str(line.trim()).unwrap();
        if resp["ok"].as_bool().unwrap() {
            Ok(resp["data"].clone())
        } else {
            Err(resp["error"].clone())
        }
    }

    fn kill_daemon(&mut self) {
        if let Some(mut d) = self.daemon.take() {
            let _ = d.kill();
            let _ = d.wait();
        }
        let _ = std::fs::remove_file(&self.sock);
    }

    fn claim(&self, agent: &str, session: &str, glob: &str) -> Result<Value, Value> {
        self.call(
            "claim",
            json!({ "agent_id": agent, "session_id": session, "glob": glob }),
        )
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        self.kill_daemon();
        // WAL 文件可能仍被占用，容忍清理失败
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

// ---------- AC1.1 冲突拒绝载荷 ----------

#[test]
fn ac1_1_conflict_rejection_payload() {
    let env = Env::new("ac11");
    env.claim("agent-A", "sess-a", "src/auth/**").unwrap();
    let err = env
        .claim("agent-B", "sess-b", "src/auth/login.ts")
        .unwrap_err();

    assert_eq!(err["error"], "conflict");
    assert_eq!(err["holder"]["agent"], "agent-A");
    assert_eq!(err["holder"]["session"], "sess");
    assert!(err["ttl_remaining_s"].as_i64().unwrap() > 0);
    assert!(!err["suggested_action"].as_str().unwrap().is_empty());
    assert!(err["human"].as_str().unwrap().contains("agent-A"));
    // free_alternatives：同层无冲突目录
    let alts: Vec<String> = serde_json::from_value(err["free_alternatives"].clone()).unwrap();
    assert!(alts
        .iter()
        .any(|a| a.contains("docs") || a.contains("src/api")));
}

// ---------- AC1.2 心跳停止 → 自动过期 ----------

#[test]
fn ac1_2_heartbeat_stop_expires_lease() {
    let env = Env::new("ac12");
    let ok = env
        .call(
            "claim",
            json!({ "agent_id": "a", "session_id": "s", "glob": "src/auth/**", "ttl_s": 2, "heartbeat_s": 1 }),
        )
        .unwrap();
    let lease_id = ok["lease"]["id"].as_str().unwrap().to_string();

    // TTL(2s) + 2 个心跳周期内不续约 → 过期
    std::thread::sleep(Duration::from_secs(5));
    // 过期后同路径可 claim 成功
    let ok2 = env.claim("b", "s2", "src/auth/**");
    assert!(ok2.is_ok(), "过期后应可重新 claim：{ok2:?}");
    // 审计日志含 expire 事件
    let log = env.call("log", json!({})).unwrap();
    let events: Vec<&str> = log
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e["event"].as_str())
        .collect();
    assert!(
        events.contains(&"expire"),
        "审计日志应含 expire 事件：{events:?}"
    );
    assert!(events.contains(&"grant"));
    let _ = lease_id;
}

// ---------- AC1.3 daemon 重启恢复租约 ----------

#[test]
fn ac1_3_daemon_restart_recovers_leases() {
    let mut env = Env::new("ac13");
    env.claim("agent-A", "sess-a", "src/auth/**").unwrap();

    // 模拟崩溃（SIGKILL）
    env.kill_daemon();
    env.start_daemon();

    // 未过期租约继续有效：他人 claim 仍冲突
    let err = env.claim("agent-B", "sess-b", "src/auth/**").unwrap_err();
    assert_eq!(err["error"], "conflict");
    // 本会话租约可见
    let st = env.call("status", json!({})).unwrap();
    let leases = st["leases"].as_array().unwrap();
    assert!(leases
        .iter()
        .any(|l| l["state"] == "active" && l["glob"] == "src/auth/**"));
}

// ---------- AC1.4 审计日志防篡改 ----------

#[test]
fn ac1_4_audit_chain_tamper_detection() {
    let env = Env::new("ac14");
    env.claim("agent-A", "sess-a", "src/auth/**").unwrap();
    env.claim("agent-B", "sess-b", "src/api/**").unwrap();

    // 完整链
    let v = env.call("verify", json!({})).unwrap();
    assert_eq!(v["intact"], true);

    // 篡改一条审计记录的 event 字段
    let db = env.root.join(".git/airlock/airlock.db");
    {
        let conn = rusqlite::Connection::open(&db).unwrap();
        conn.execute("UPDATE audit_log SET event = 'tampered' WHERE seq = 2", [])
            .unwrap();
    }
    let v = env.call("verify", json!({})).unwrap();
    assert_eq!(v["intact"], false);
    let broken: Vec<i64> = serde_json::from_value(v["broken_seqs"].clone()).unwrap();
    assert!(broken.contains(&2), "应报告断链位置 seq=2：{broken:?}");
}

// ---------- AC1.5 1000 并发混沌 ----------

#[test]
fn ac1_5_thousand_concurrent_claims() {
    let env = Env::new("ac15");
    let sock = env.sock.clone();
    let n = 1000usize;
    let mut handles = Vec::new();
    for i in 0..n {
        let sock = sock.clone();
        handles.push(std::thread::spawn(move || -> (bool, String) {
            let stream = UnixStream::connect(&sock).expect("连接");
            stream.set_read_timeout(Some(Duration::from_secs(120))).unwrap();
            let mut s = stream;
            let glob = if i % 3 == 0 {
                // 三分之一撞同一路径（制造冲突）
                "src/shared/**".to_string()
            } else {
                format!("src/unique{i}/**")
            };
            let req = json!({
                "v": 1, "method": "claim",
                "params": { "agent_id": format!("a{i}"), "session_id": format!("s{i}"), "glob": glob }
            });
            s.write_all(format!("{req}\n").as_bytes()).unwrap();
            let mut reader = BufReader::new(s);
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let resp: Value = serde_json::from_str(line.trim()).unwrap();
            (
                resp["ok"].as_bool().unwrap(),
                resp["data"]["lease"]["id"]
                    .as_str()
                    .or(resp["error"]["error"].as_str())
                    .unwrap_or("malformed")
                    .to_string(),
            )
        }));
    }
    let mut granted = 0usize;
    let mut denied = 0usize;
    let mut malformed = 0usize;
    let mut lease_ids = std::collections::HashSet::new();
    for h in handles {
        let (ok, id) = h.join().expect("线程 panic——混沌失败");
        if ok {
            granted += 1;
            assert!(lease_ids.insert(id), "租约 ID 重复——状态错乱");
        } else if id == "conflict" {
            denied += 1;
        } else {
            malformed += 1;
        }
    }
    assert_eq!(malformed, 0, "存在格式异常响应——状态错乱");
    assert!(granted > 600, "应授予大多数无冲突 claim：granted={granted}");
    assert!(denied > 0, "共享路径应产生冲突拒绝");
    // 无死锁：daemon 仍可响应
    let st = env.call("status", json!({})).unwrap();
    assert_eq!(st["leases"].as_array().unwrap().len(), granted);
}

// ---------- AC2.5 enforcement=off → L0 badge ----------

#[test]
fn ac2_5_enforcement_off_l0_badge() {
    let root = short_tmp().join(format!("airlock-it-ac25-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    Command::new("git")
        .args(["init", "-q", "."])
        .current_dir(&root)
        .status()
        .unwrap();
    std::fs::write(root.join("airlock.toml"), "enforcement = \"off\"\n").unwrap();

    let exe = env!("CARGO_BIN_EXE_airlockd");
    let mut daemon = Command::new(exe)
        .arg("--root")
        .arg(&root)
        .arg("--foreground")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let sock = root.join(".git/airlock/daemon.sock");

    for _ in 0..100 {
        if UnixStream::connect(&sock).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let mut s = UnixStream::connect(&sock).unwrap();
    s.write_all(b"{\"v\":1,\"method\":\"status\",\"params\":{}}\n")
        .unwrap();
    let mut line = String::new();
    BufReader::new(s).read_line(&mut line).unwrap();
    let resp: Value = serde_json::from_str(line.trim()).unwrap();
    assert_eq!(resp["data"]["layer"]["id"], "L0");
    assert_eq!(resp["data"]["layer"]["name"], "disabled");
    let _ = daemon.kill();
    let _ = daemon.wait();
    let _ = std::fs::remove_dir_all(&root);
}

// ---------- AC3.1 端口段互不重叠 ----------

#[test]
fn ac3_1_port_segments_differ() {
    let env = Env::new("ac31");
    let s1 = env.call("register", json!({ "agent_id": "a" })).unwrap();
    let s2 = env.call("register", json!({ "agent_id": "b" })).unwrap();
    assert_ne!(s1["port_base"], s2["port_base"]);
    let p1 = env
        .call(
            "alloc_port",
            json!({ "session_id": s1["session_id"], "purpose": "vite" }),
        )
        .unwrap();
    let p2 = env
        .call(
            "alloc_port",
            json!({ "session_id": s2["session_id"], "purpose": "vite" }),
        )
        .unwrap();
    assert_ne!(p1["port"], p2["port"], "两个会话的 dev server 端口必须不同");
    assert_ne!(s1["env"]["PORT"], s2["env"]["PORT"]);
}

// ---------- AC4.3 反复被拒 → 升级引导 ----------

#[test]
fn ac4_3_escalation_after_repeated_denies() {
    let env = Env::new("ac43");
    env.claim("agent-A", "sess-a", "src/auth/**").unwrap();
    let mut last = None;
    for _ in 0..4 {
        last = Some(
            env.claim("agent-B", "sess-b", "src/auth/login.ts")
                .unwrap_err(),
        );
    }
    let err = last.unwrap();
    assert_eq!(err["suggested_action"], "escalate_switch_task");
    assert!(err["deny_count"].as_u64().unwrap() >= 3);
    assert!(
        err["human"].as_str().unwrap().contains("建议改做其他任务")
            || err["human"].as_str().unwrap().contains("多次")
    );
}

// ---------- AC5.1 黑板传递意图 ----------

#[test]
fn ac5_1_blackboard_carries_intent() {
    let env = Env::new("ac51");
    env.call(
        "claim",
        json!({ "agent_id": "agent-A", "session_id": "sa", "glob": "src/auth/**", "intent": "修复登录超时，重试逻辑抽到 retry.ts" }),
    )
    .unwrap();
    // 新会话（agent-B）读黑板
    let board = env.call("board_read", json!({})).unwrap();
    let bodies: Vec<String> = board["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e["body"].as_str().map(|s| s.to_string()))
        .collect();
    assert!(
        bodies.iter().any(|b| b.contains("登录超时")),
        "黑板应包含 A 的意图：{bodies:?}"
    );
}

// ---------- AC5.2 token 预算截断 ----------

#[test]
fn ac5_2_board_token_budget_truncation() {
    let env = Env::new("ac52");
    for i in 0..10 {
        env.call(
            "board_write",
            json!({ "body": format!("条目{i}：{}", "很长的说明文字。".repeat(50)) }),
        )
        .unwrap();
    }
    let board = env
        .call("board_read", json!({ "token_budget": 50 }))
        .unwrap();
    assert!(
        board["truncated"].as_u64().unwrap() > 0,
        "超预算应报告截断条数"
    );
    assert!(board["approx_tokens"].as_u64().unwrap() <= 60);
}

// ---------- 过期后黑板归档 + daemon 摘要（FR5.2/FR5.4） ----------

#[test]
fn board_archives_on_expire_with_daemon_summary() {
    let env = Env::new("board-arch");
    env.call(
        "claim",
        json!({ "agent_id": "a", "session_id": "s", "glob": "src/auth/**", "intent": "临时意图", "ttl_s": 2, "heartbeat_s": 1 }),
    )
    .unwrap();
    std::thread::sleep(Duration::from_secs(5));
    let board = env.call("board_read", json!({})).unwrap();
    // 归档摘要中应有 daemon 生成的不可抵赖条目
    let summary: Vec<String> = serde_json::from_value(board["archived_summary"].clone()).unwrap();
    assert!(
        summary
            .iter()
            .any(|s| s.contains("daemon") && s.contains("临时意图")),
        "过期后 daemon 应生成黑板摘要：{summary:?}"
    );
}

// ---------- 杂项锁（FR3.5 v0.2） ----------

#[test]
fn misc_lock_serializes() {
    let env = Env::new("misc-lock");
    let a = env
        .call(
            "misc_lock",
            json!({ "name": "index.lock", "session_id": "s1" }),
        )
        .unwrap();
    assert_eq!(a["acquired"], true);
    let b = env
        .call(
            "misc_lock",
            json!({ "name": "index.lock", "session_id": "s2" }),
        )
        .unwrap();
    assert_eq!(b["acquired"], false);
    assert_eq!(b["holder"], "s1");
    env.call(
        "misc_unlock",
        json!({ "name": "index.lock", "session_id": "s1" }),
    )
    .unwrap();
    let c = env
        .call(
            "misc_lock",
            json!({ "name": "index.lock", "session_id": "s2" }),
        )
        .unwrap();
    assert_eq!(c["acquired"], true);
}

// ---------- 性能预算（§8.1）：claim p50<5ms / p99<50ms（release 基准） ----------

#[test]
fn perf_claim_latency_budget() {
    let env = Env::new("perf");
    let iterations = 300;
    let mut samples = Vec::new();
    for i in 0..iterations {
        let t0 = Instant::now();
        let r = env.claim(
            "perf-agent",
            &format!("perf-{i}"),
            &format!("perf/dir{i}/**"),
        );
        let dt = t0.elapsed();
        assert!(r.is_ok());
        samples.push(dt);
    }
    samples.sort();
    let p50 = samples[iterations / 2];
    let p99 = samples[iterations * 99 / 100];
    // debug 构建放宽（CI 门禁以 --release 运行）
    let (p50_budget, p99_budget) = if cfg!(debug_assertions) {
        (Duration::from_millis(25), Duration::from_millis(120))
    } else {
        (Duration::from_millis(5), Duration::from_millis(50))
    };
    assert!(p50 < p50_budget, "claim p50={p50:?} 超预算");
    assert!(p99 < p99_budget, "claim p99={p99:?} 超预算");
}

// ---------- SQLite 损坏：宁可不可用（§8.4） ----------

#[test]
fn sqlite_corrupt_refuses_startup() {
    let root = short_tmp().join(format!("airlock-it-corrupt-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join(".git/airlock")).unwrap();
    std::fs::write(
        root.join(".git/airlock/airlock.db"),
        b"NOT A DATABASE AT ALL",
    )
    .unwrap();

    // 存储层直接打开应报 Integrity
    let r = airlock_core::store::Store::open(&root.join(".git/airlock/airlock.db"));
    match r {
        Err(airlock_core::Error::Integrity(m)) => {
            assert!(m.contains("损坏"), "错误信息应含修复指引：{m}");
        }
        Err(_) | Ok(_) => panic!("损坏库应拒绝打开（或报 Integrity 以外的错误）"),
    }
    let _ = std::fs::remove_dir_all(&root);
}

// ---------- 保护空窗检测（AC2.4 提示面） ----------

#[test]
fn protection_gap_reported_after_crash() {
    let mut env = Env::new("gap");
    env.claim("a", "s", "src/auth/**").unwrap();
    // 崩溃（不 mark_clean_shutdown）
    env.kill_daemon();
    env.start_daemon();
    let st = env.call("status", json!({})).unwrap();
    assert!(st["protection_gap_s"].is_i64(), "崩溃重启后应报告保护空窗");
}
