//! 回归测试（v2.0.1 审查修复）：
//! - rollback / report_cost 属主校验（凭 lease_id 不能动别人的租约）
//! - claim 空 session_id 拒绝
//! - 幂等 claim 不得把更宽的申请映射回更窄的既有租约
//! - daemon 单实例 flock；socket 文件 0600

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

use serde_json::{json, Value};

use harness::Env;

#[test]
fn rollback_requires_ownership() {
    let env = Env::new("rb-owner");
    let ok = env
        .claim("agent-a", "sess-a", "src/auth/**")
        .expect("claim 失败");
    let lease_id = ok["lease"]["id"].as_str().unwrap().to_string();

    // 他人会话：拒绝（属主校验）
    let err = env
        .call(
            "rollback",
            json!({ "lease_id": lease_id, "session_id": "sess-b" }),
        )
        .unwrap_err();
    assert_eq!(err["kind"].as_str().unwrap_or(""), "config", "{err}");

    // 属主会话：成功
    let v = env
        .call(
            "rollback",
            json!({ "lease_id": lease_id, "session_id": "sess-a" }),
        )
        .expect("属主 rollback 失败");
    assert_eq!(v["rollback"], "ok");
}

#[test]
fn rollback_rejects_traversal_lease_id() {
    let env = Env::new("rb-trav");
    let err = env
        .call(
            "rollback",
            json!({ "lease_id": "../../victim", "session_id": "sess-a" }),
        )
        .unwrap_err();
    // 不存在的租约 → not_found，绝不落到按路径读任意 json
    assert_eq!(err["kind"].as_str().unwrap_or(""), "not_found", "{err}");
}

#[test]
fn report_cost_requires_ownership() {
    let env = Env::new("cost-owner");
    let ok = env
        .claim("agent-a", "sess-a", "src/auth/**")
        .expect("claim 失败");
    let lease_id = ok["lease"]["id"].as_str().unwrap().to_string();

    let err = env
        .call(
            "report_cost",
            json!({ "lease_id": lease_id, "tokens": 1, "session_id": "sess-b" }),
        )
        .unwrap_err();
    assert_eq!(err["kind"].as_str().unwrap_or(""), "config", "{err}");

    env.call(
        "report_cost",
        json!({ "lease_id": lease_id, "tokens": 1, "session_id": "sess-a" }),
    )
    .expect("属主 report_cost 失败");
}

#[test]
fn claim_rejects_empty_session() {
    let env = Env::new("claim-empty-sid");
    let err = env
        .call(
            "claim",
            json!({ "agent_id": "a", "session_id": "", "glob": "src/**" }),
        )
        .unwrap_err();
    assert_eq!(err["kind"].as_str().unwrap_or(""), "config", "{err}");
}

#[test]
fn idempotent_claim_does_not_return_narrower_lease() {
    let env = Env::new("claim-widen");
    env.claim("agent-a", "sess-a", "src/auth/**")
        .expect("首次 claim");
    // 同会话申请更宽的 glob：不能复用窄租约（否则 agent 误以为全 src/ 受保护）
    let err = env.claim("agent-a", "sess-a", "src/**").unwrap_err();
    // Conflict 载荷是 Rejection 序列化：error = "conflict"
    assert_eq!(err["error"].as_str().unwrap_or(""), "conflict", "{err}");
    // 同 glob 幂等仍成立
    let again = env
        .claim("agent-a", "sess-a", "src/auth/**")
        .expect("幂等 claim");
    assert_eq!(again["prediction"]["risk"], "none");
}

#[test]
fn second_daemon_exits_via_flock() {
    let mut env = Env::new("singleton");
    env.stop_daemon_sigterm();
    // flock 已随第一个 daemon 释放；重新启动一个占住锁，第二个必须退出
    env.start_daemon();
    let exe = env!("CARGO_BIN_EXE_airlockd");
    let mut second = Command::new(exe)
        .arg("--root")
        .arg(&env.root)
        .arg("--foreground")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("启动第二个 daemon");
    let status = second.wait().expect("等待第二个 daemon");
    assert!(status.success(), "第二个实例应幂等退出（exit 0）");
    // 原 daemon 仍然可用
    env.call("ping", json!({})).expect("原 daemon 不应受影响");
}

#[test]
fn socket_file_is_0600() {
    let env = Env::new("sock-perm");
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(&env.sock).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600, "socket 权限应为 0600，实际 {mode:o}");
}

// ---- 独立的轻量 harness（避免与 integration.rs 的 Env 重复改动互相影响） ----
mod harness {
    use super::*;

    pub struct Env {
        pub root: PathBuf,
        pub sock: PathBuf,
        daemon: Option<std::process::Child>,
    }

    impl Env {
        pub fn new(tag: &str) -> Env {
            let root =
                std::env::temp_dir().join(format!("airlock-reg-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(root.join("src/auth")).unwrap();
            std::fs::write(root.join("src/auth/login.ts"), "orig").unwrap();
            let st = Command::new("git")
                .args(["init", "-q", "."])
                .current_dir(&root)
                .status()
                .unwrap();
            assert!(st.success(), "git init 失败——测试环境需要 git");
            // 快照锚点需要 git HEAD：先做一次初始提交
            for args in [
                vec!["config", "user.email", "t@t"],
                vec!["config", "user.name", "t"],
                vec!["add", "."],
                vec!["commit", "-qm", "init"],
            ] {
                let st = Command::new("git")
                    .args(&args)
                    .current_dir(&root)
                    .status()
                    .unwrap();
                assert!(st.success(), "git {args:?} 失败");
            }
            let mut env = Env {
                root,
                sock: PathBuf::new(),
                daemon: None,
            };
            env.start_daemon();
            env
        }

        pub fn start_daemon(&mut self) {
            let exe = env!("CARGO_BIN_EXE_airlockd");
            let child = Command::new(exe)
                .arg("--root")
                .arg(&self.root)
                .arg("--foreground")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
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

        pub fn stop_daemon_sigterm(&mut self) {
            if let Some(mut d) = self.daemon.take() {
                unsafe {
                    libc::kill(d.id() as i32, libc::SIGTERM);
                }
                let _ = d.wait();
                // 干净停机会移除 socket
                for _ in 0..40 {
                    if !self.sock.exists() {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
        }

        pub fn call(&self, method: &str, params: Value) -> Result<Value, Value> {
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

        pub fn claim(&self, agent: &str, session: &str, glob: &str) -> Result<Value, Value> {
            self.call(
                "claim",
                json!({ "agent_id": agent, "session_id": session, "glob": glob }),
            )
        }
    }

    impl Drop for Env {
        fn drop(&mut self) {
            if let Some(mut d) = self.daemon.take() {
                let _ = d.kill();
                let _ = d.wait();
            }
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }
}
