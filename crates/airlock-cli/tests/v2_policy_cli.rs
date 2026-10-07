//! v2.0 CLI 集成测试：`airlock policy check`（F12，本地校验 + 干跑决策）。

use std::path::PathBuf;
use std::process::Command;

fn temp_repo(tag: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("airlock-v2cli-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    Command::new("git")
        .args(["init", "-q", "."])
        .current_dir(&root)
        .status()
        .unwrap();
    root
}

fn airlock(root: &PathBuf) -> Command {
    let exe = env!("CARGO_BIN_EXE_airlock");
    let mut c = Command::new(exe);
    c.arg("--root").arg(root);
    c
}

#[test]
fn policy_check_reports_missing_file_as_zero_config() {
    let root = temp_repo("nopol");
    let out = airlock(&root).args(["policy", "check"]).output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("未配置政策"), "实际输出：{stdout}");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn policy_check_validates_and_dry_runs() {
    let root = temp_repo("polok");
    std::fs::write(
        root.join("airlock.policy.toml"),
        "[paths.deny]\n\"vault/**\" = \"密钥区\"\n[paths.allow]\n\"src/**\" = \"*\"\n",
    )
    .unwrap();
    // 摘要模式
    let out = airlock(&root).args(["policy", "check"]).output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("AIRLOCK POLICY"));
    assert!(stdout.contains("sha256"));
    assert!(stdout.contains("deny"));
    // 干跑命中 deny → 退出码 2（冲突/拒绝），人类可读
    let out = airlock(&root)
        .args(["policy", "check", "--glob", "vault/key.pem"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("拒绝"));
    assert!(stdout.contains("vault/**"));
    // 干跑命中 allow → 退出码 0
    let out = airlock(&root)
        .args(["policy", "check", "--glob", "src/main.rs"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn policy_check_json_mode() {
    let root = temp_repo("poljson");
    std::fs::write(
        root.join("airlock.policy.toml"),
        "[defaults]\nmax_ttl_s = 600\n",
    )
    .unwrap();
    let out = airlock(&root)
        .args([
            "--json", "policy", "check", "--glob", "src/**", "--ttl", "7200",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let v: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).expect("JSON 输出可解析");
    assert!(v["sha256"].is_string());
    assert_eq!(v["verdict"]["allowed"], true);
    assert_eq!(v["verdict"]["ttl_cap"], 600);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn policy_check_invalid_file_exits_5() {
    let root = temp_repo("polbad");
    std::fs::write(root.join("airlock.policy.toml"), "[nope]\nx = \"1\"\n").unwrap();
    let out = airlock(&root).args(["policy", "check"]).output().unwrap();
    assert_eq!(out.status.code(), Some(5), "坏政策 → config 错误退出码");
    let _ = std::fs::remove_dir_all(&root);
}
