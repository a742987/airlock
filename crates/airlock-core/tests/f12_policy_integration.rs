//! F12 政策即代码集成测试（v2.0）：政策在 claim 层的拒绝 / TTL 钳制 / fail-closed。
//! 验收标准：「政策文件在 claim 时驱动内核拒绝」（本文件覆盖 claim 层；
//! 内核层见 tests/landlock_policy_integration.rs）。

use std::path::{Path, PathBuf};

use airlock_core::config::Config;
use airlock_core::error::Error;
use airlock_core::lease::{self, ClaimParams};
use airlock_core::proto::Actor;
use airlock_core::store::Store;

fn temp_repo(tag: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("airlock-f12-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::create_dir_all(root.join("vault")).unwrap();
    std::fs::write(root.join("src/main.rs"), "fn main() {}").unwrap();
    let st = std::process::Command::new("git")
        .args(["init", "-q", "."])
        .current_dir(&root)
        .status()
        .unwrap();
    assert!(st.success());
    root
}

fn claim_params(root: &Path, agent: &str, glob: &str, ttl: Option<i64>) -> ClaimParams {
    ClaimParams {
        conflict_domain: "test-domain".into(),
        agent_id: agent.into(),
        session_id: format!("sess-{agent}"),
        glob: glob.into(),
        intent: None,
        ttl_s: ttl,
        heartbeat_s: 60,
        layer: "L1".into(),
        actor: Actor {
            agent: agent.into(),
            session: "sess".into(),
            pid_tree: vec![],
        },
        root: Some(root.to_path_buf()),
    }
}

#[test]
fn policy_deny_rejects_claim_with_policy_payload() {
    let root = temp_repo("deny");
    std::fs::write(
        root.join("airlock.policy.toml"),
        "[paths.deny]\n\"vault/**\" = \"密钥区禁止 agent 触碰\"\n",
    )
    .unwrap();
    let store = Store::open_in_memory().unwrap();
    let cfg = Config::default();

    // 允许路径正常授予
    let ok = lease::claim(&store, &cfg, &claim_params(&root, "codex", "src/**", None)).unwrap();
    assert_eq!(ok.lease.glob, "src/**");
    assert!(ok.credentials.is_none());

    // 政策拒绝：409 型 Conflict，载荷带 policy 细节
    let err = lease::claim(
        &store,
        &cfg,
        &claim_params(&root, "codex", "vault/key.pem", None),
    )
    .unwrap_err();
    match err {
        Error::Conflict(r) => {
            assert_eq!(r.error, "policy");
            let pol = r.policy.expect("policy 拒绝必须携带 policy 字段");
            assert_eq!(pol.kind, "path_denied");
            assert_eq!(pol.rule, "vault/**");
            assert!(r.human.contains("政策"), "人类可读文案应说明是政策拒绝");
            assert_eq!(
                r.suggested_action,
                airlock_core::messages::suggested_action::POLICY_DENIED_ADJUST_SCOPE
            );
        }
        other => panic!("期望 Conflict，实际 {other:?}"),
    }
    // 拒绝入审计（可追溯）
    let events: Vec<String> = store
        .audit_query(None, 100)
        .unwrap()
        .into_iter()
        .map(|e| e.event)
        .collect();
    assert!(events.contains(&"policy_deny".to_string()));

    // 审计链完好
    assert!(store.audit_verify().unwrap().is_empty());
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn policy_agent_allowlist_blocks_other_agents() {
    let root = temp_repo("agents");
    std::fs::write(
        root.join("airlock.policy.toml"),
        "[agents]\nallow = \"codex\"\n",
    )
    .unwrap();
    let store = Store::open_in_memory().unwrap();
    let err = lease::claim(
        &store,
        &Config::default(),
        &claim_params(&root, "gemini", "src/**", None),
    )
    .unwrap_err();
    match err {
        Error::Conflict(r) => {
            let pol = r.policy.unwrap();
            assert_eq!(pol.kind, "agent_not_allowed");
            assert_eq!(pol.rule, "<agents.allow>");
        }
        other => panic!("期望 Conflict，实际 {other:?}"),
    }
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn policy_clamps_ttl_and_audits() {
    let root = temp_repo("ttl");
    std::fs::write(
        root.join("airlock.policy.toml"),
        "[defaults]\nmax_ttl_s = 120\n",
    )
    .unwrap();
    let store = Store::open_in_memory().unwrap();
    let ok = lease::claim(
        &store,
        &Config::default(),
        &claim_params(&root, "codex", "src/**", Some(7200)),
    )
    .unwrap();
    assert_eq!(
        ok.lease.ttl_s, 120,
        "政策 TTL 上限应钳制申请值（clamp 而非拒绝）"
    );
    let events: Vec<String> = store
        .audit_query(None, 100)
        .unwrap()
        .into_iter()
        .map(|e| e.event)
        .collect();
    assert!(events.contains(&"policy_clamp".to_string()));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn broken_policy_fails_closed() {
    let root = temp_repo("broken");
    std::fs::write(
        root.join("airlock.policy.toml"),
        "[unknown-section]\nbad_key = \"1\"\n",
    )
    .unwrap();
    let store = Store::open_in_memory().unwrap();
    let err = lease::claim(
        &store,
        &Config::default(),
        &claim_params(&root, "codex", "src/**", None),
    )
    .unwrap_err();
    assert!(
        matches!(err, Error::Config(_)),
        "坏政策必须 fail-closed（Config 错误），实际 {err:?}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn allowlist_mode_requires_matching_allow_rule() {
    let root = temp_repo("allowlist");
    std::fs::write(
        root.join("airlock.policy.toml"),
        "[paths.allow]\n\"src/**\" = \"*\"\n",
    )
    .unwrap();
    let store = Store::open_in_memory().unwrap();
    let cfg = Config::default();
    assert!(lease::claim(&store, &cfg, &claim_params(&root, "codex", "src/**", None)).is_ok());
    let err = lease::claim(
        &store,
        &cfg,
        &claim_params(&root, "codex", "docs/x.md", None),
    )
    .unwrap_err();
    match err {
        Error::Conflict(r) => assert_eq!(r.policy.unwrap().kind, "allowlist_miss"),
        other => panic!("期望 Conflict，实际 {other:?}"),
    }
    let _ = std::fs::remove_dir_all(&root);
}
