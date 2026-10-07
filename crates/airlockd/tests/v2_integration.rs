//! v2.0 集成测试（F12 政策即代码 + F13 凭据作用域代理）。
//!
//! 验收标准（路线图 §6.2 v2.0 行）：
//! - 「政策文件在 claim 时驱动内核拒绝」→ claim 层 409 载荷 + daemon 启动 fail-closed
//! - 「凭据随租约吊销（≤60s 失效）」→ file 后端发放 + release 后 sweeper 吊销
//!
//! 复用 integration.rs 的 Env 模式：临时 git 仓库 + 真实 airlockd 进程。

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
    /// 启动 daemon 于临时 git 仓库；可选写入 airlock.toml / 凭据源文件 / 政策文件。
    fn new(tag: &str) -> Env {
        Self::new_with_config(tag, None, None, None)
    }

    fn new_with_config(
        tag: &str,
        config: Option<&str>,
        credentials: Option<&str>,
        policy: Option<&str>,
    ) -> Env {
        let root = short_tmp().join(format!("airlock-v2-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::create_dir_all(root.join("vault")).unwrap();
        std::fs::write(root.join("src/main.rs"), "orig").unwrap();
        let st = Command::new("git")
            .args(["init", "-q", "."])
            .current_dir(&root)
            .status()
            .unwrap();
        assert!(st.success(), "git init 失败——测试环境需要 git");
        if let Some(c) = config {
            std::fs::write(root.join("airlock.toml"), c).unwrap();
        }
        if let Some(pol) = policy {
            std::fs::write(root.join("airlock.policy.toml"), pol).unwrap();
        }
        let mut env = Env {
            root,
            sock: PathBuf::new(),
            daemon: None,
        };
        if let Some(cred) = credentials {
            // 凭据源文件默认位于域目录（<git-common-dir>/airlock/credentials.toml）
            let dir = env.root.join(".git/airlock");
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("credentials.toml"), cred).unwrap();
        }
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

    fn claim(&self, agent: &str, session: &str, glob: &str) -> Result<Value, Value> {
        self.call(
            "claim",
            json!({ "agent_id": agent, "session_id": session, "glob": glob }),
        )
    }

    fn kill_daemon(&mut self) {
        if let Some(mut d) = self.daemon.take() {
            let _ = d.kill();
            let _ = d.wait();
        }
        let _ = std::fs::remove_file(&self.sock);
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        self.kill_daemon();
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

// ---------- F12：政策文件在 claim 时驱动拒绝 ----------

#[test]
fn f12_policy_rejects_claim_over_daemon() {
    let env = Env::new_with_config(
        "polrej",
        None,
        None,
        Some("[paths.deny]\n\"vault/**\" = \"密钥区\"\n"),
    );
    // 政策允许的路径正常
    env.claim("agent-A", "sess-a", "src/**").unwrap();
    // 政策拒绝：409 载荷 error=policy + policy 细节
    let err = env.claim("agent-B", "sess-b", "vault/key.pem").unwrap_err();
    assert_eq!(err["error"], "policy");
    assert_eq!(err["policy"]["kind"], "path_denied");
    assert_eq!(err["policy"]["rule"], "vault/**");
    assert!(
        err["human"].as_str().unwrap().contains("政策"),
        "人类可读文案应指明政策拒绝：{}",
        err["human"]
    );
    // 拒绝入审计（policy_deny 事件 + 政策 sha256）
    let log = env.call("log", json!({})).unwrap();
    let events: Vec<&str> = log
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e["event"].as_str())
        .collect();
    assert!(events.contains(&"policy_deny"));
    let deny_entry = log
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["event"] == "policy_deny")
        .unwrap();
    assert!(deny_entry["detail"]["policy_sha256"].is_string());
}

#[test]
fn f12_broken_policy_fails_daemon_boot() {
    let root = short_tmp().join(format!("airlock-v2-badpol-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    Command::new("git")
        .args(["init", "-q", "."])
        .current_dir(&root)
        .status()
        .unwrap()
        .success()
        .then_some(())
        .expect("git init");
    std::fs::write(root.join("airlock.policy.toml"), "[nope]\nx = \"1\"\n").unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_airlockd"))
        .arg("--root")
        .arg(&root)
        .arg("--foreground")
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(5),
        "坏政策必须让 daemon 拒绝启动（fail-closed，exit 5）"
    );
    let _ = std::fs::remove_dir_all(&root);
}

// ---------- F13：凭据随租约发放与吊销 ----------

const CRED_CONFIG: &str = "credentials_backend = \"file\"\n";
const CRED_FILE: &str = "[app-db]\nAIRLOCK_DB_URL = \"postgres://u:p@127.0.0.1:5432/app_test\"\n";

#[test]
fn f13_credentials_issued_with_claim_and_revoked_with_release() {
    let env = Env::new_with_config("credlife", Some(CRED_CONFIG), Some(CRED_FILE), None);

    // claim + cred → 凭据随响应发放
    let ok = env
        .call(
            "claim",
            json!({
                "agent_id": "agent-A", "session_id": "sess-a",
                "glob": "src/**", "cred": "app-db"
            }),
        )
        .unwrap();
    assert_eq!(
        ok["credentials"]["AIRLOCK_DB_URL"].as_str(),
        Some("postgres://u:p@127.0.0.1:5432/app_test"),
        "claim 响应应携带凭据 env"
    );
    let lease_id = ok["lease"]["id"].as_str().unwrap().to_string();

    // 发放入审计
    let log = env.call("log", json!({})).unwrap();
    assert!(log
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["event"] == "cred_issue"));

    // 凭据清单脱敏：只见变量名，不见值
    let rows = env.call("creds_list", json!({})).unwrap();
    let row = rows.as_array().unwrap().first().unwrap().clone();
    assert_eq!(row["status"], "active");
    assert!(row["meta"]["env"].is_null(), "env 值必须脱敏");
    assert_eq!(row["meta"]["env_keys"][0].as_str(), Some("AIRLOCK_DB_URL"));

    // release 租约 → sweeper（1s 周期）吊销凭据；验收 ≤60s
    let t0 = Instant::now();
    env.call(
        "release",
        json!({ "lease_id": lease_id, "agent_id": "agent-A", "session_id": "sess-a" }),
    )
    .unwrap();
    let mut revoked_at = None;
    while t0.elapsed() < Duration::from_secs(60) {
        let rows = env.call("creds_list", json!({})).unwrap();
        let status = rows.as_array().unwrap()[0]["status"]
            .as_str()
            .unwrap()
            .to_string();
        if status == "revoked" {
            revoked_at = Some(t0.elapsed());
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    let elapsed = revoked_at.expect("release 后凭据应在 ≤60s 内被吊销");
    assert!(
        elapsed < Duration::from_secs(60),
        "验收标准：吊销后 ≤60s 失效（实际 {elapsed:?}）"
    );

    // 审计链完整（cred_issue / cred_revoke 都在链上）
    let broken = env.call("verify", json!({})).unwrap();
    assert_eq!(broken["intact"], true);
}

#[test]
fn f13_creds_revoke_endpoint_and_missing_backend_errors() {
    let env = Env::new_with_config("credrev", Some(CRED_CONFIG), Some(CRED_FILE), None);
    // 立即吊销端点
    let ok = env
        .call(
            "claim",
            json!({
                "agent_id": "agent-A", "session_id": "sess-a",
                "glob": "src/**", "cred": "app-db"
            }),
        )
        .unwrap();
    let cred_id = env
        .call("creds_list", json!({}))
        .unwrap()
        .as_array()
        .unwrap()[0]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let v = env
        .call(
            "creds_revoke",
            json!({ "cred_id": cred_id, "agent_id": "agent-A" }),
        )
        .unwrap();
    assert_eq!(v["revoked"], true);
    let v = env
        .call(
            "creds_revoke",
            json!({ "cred_id": cred_id, "agent_id": "agent-A" }),
        )
        .unwrap();
    assert_eq!(v["revoked"], false, "重复吊销幂等返回 false");
    let _ = ok;

    // 未启用凭据代理时请求 cred → config 错误，且租约被回滚（不泄漏）
    let env2 = Env::new("nocred");
    let err = env2
        .call(
            "claim",
            json!({
                "agent_id": "agent-A", "session_id": "sess-a",
                "glob": "src/**", "cred": "app-db"
            }),
        )
        .unwrap_err();
    assert_eq!(err["kind"], "config");
    let status = env2.call("status", json!({})).unwrap();
    let active = status["leases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|l| l["state"] == "active")
        .count();
    assert_eq!(active, 0, "发放失败的租约必须回滚，不得泄漏");
}
