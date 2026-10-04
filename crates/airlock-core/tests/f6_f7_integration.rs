//! F6 成本归因与 F7 隔离回滚的集成测试

use airlock_core::config::Config;
use airlock_core::lease::{self, ClaimParams};
use airlock_core::proto::Actor;
use airlock_core::snapshot;
use airlock_core::store::Store;
use std::fs;
use std::process::Command;
use tempfile::TempDir;

/// 创建测试用的 ClaimParams
fn make_test_claim(session_id: &str, glob: &str) -> ClaimParams {
    ClaimParams {
        conflict_domain: "test-domain".to_string(),
        agent_id: "test-agent".to_string(),
        session_id: session_id.to_string(),
        glob: glob.to_string(),
        intent: Some(format!("测试: {}", glob)),
        ttl_s: Some(300),
        heartbeat_s: 60,
        layer: "L1".to_string(),
        actor: Actor {
            agent: "test-agent".to_string(),
            session: session_id.to_string(),
            pid_tree: vec![std::process::id()],
        },
        root: None,
    }
}

#[test]
fn test_f6_cost_accumulation() {
    let store = Store::open_in_memory().unwrap();
    let cfg = Config::default();

    // 创建租约
    let params = make_test_claim("sess-1", "src/test.rs");
    let claim_ok = lease::claim(&store, &cfg, &params).unwrap();
    let lease_id = claim_ok.lease.id;

    // 第一次上报成本
    store.update_lease_cost(&lease_id, 1000, 50).unwrap();
    let lease = store.get_lease(&lease_id).unwrap().unwrap();
    assert_eq!(lease.tokens_used, 1000);
    assert_eq!(lease.cost_cents, 50);

    // 第二次上报成本（累加）
    store.update_lease_cost(&lease_id, 500, 25).unwrap();
    let lease = store.get_lease(&lease_id).unwrap().unwrap();
    assert_eq!(lease.tokens_used, 1500, "tokens 应该累加");
    assert_eq!(lease.cost_cents, 75, "cost 应该累加");

    // 第三次上报
    store.update_lease_cost(&lease_id, 2500, 125).unwrap();
    let lease = store.get_lease(&lease_id).unwrap().unwrap();
    assert_eq!(lease.tokens_used, 4000);
    assert_eq!(lease.cost_cents, 200);
}

#[test]
fn test_f6_cost_multiple_leases() {
    let store = Store::open_in_memory().unwrap();
    let cfg = Config::default();

    // 创建两个租约
    let params1 = make_test_claim("sess-1", "src/a.rs");
    let claim1 = lease::claim(&store, &cfg, &params1).unwrap();
    let lease_id1 = claim1.lease.id;

    let params2 = make_test_claim("sess-2", "src/b.rs");
    let claim2 = lease::claim(&store, &cfg, &params2).unwrap();
    let lease_id2 = claim2.lease.id;

    // 分别上报成本
    store.update_lease_cost(&lease_id1, 1000, 50).unwrap();
    store.update_lease_cost(&lease_id2, 2000, 100).unwrap();

    // 验证各自独立
    let lease1 = store.get_lease(&lease_id1).unwrap().unwrap();
    let lease2 = store.get_lease(&lease_id2).unwrap().unwrap();
    assert_eq!(lease1.tokens_used, 1000);
    assert_eq!(lease1.cost_cents, 50);
    assert_eq!(lease2.tokens_used, 2000);
    assert_eq!(lease2.cost_cents, 100);
}

#[test]
fn test_f6_cost_zero_values() {
    let store = Store::open_in_memory().unwrap();
    let cfg = Config::default();

    let params = make_test_claim("sess-1", "src/test.rs");
    let claim_ok = lease::claim(&store, &cfg, &params).unwrap();
    let lease_id = claim_ok.lease.id;

    // 上报零值
    store.update_lease_cost(&lease_id, 0, 0).unwrap();
    let lease = store.get_lease(&lease_id).unwrap().unwrap();
    assert_eq!(lease.tokens_used, 0);
    assert_eq!(lease.cost_cents, 0);

    // 再上报非零值
    store.update_lease_cost(&lease_id, 100, 5).unwrap();
    let lease = store.get_lease(&lease_id).unwrap().unwrap();
    assert_eq!(lease.tokens_used, 100);
    assert_eq!(lease.cost_cents, 5);
}

#[test]
fn test_f7_snapshot_lifecycle() {
    let temp = TempDir::new().unwrap();
    let repo = temp.path();

    // 初始化 git 仓库
    Command::new("git").args(["init"]).current_dir(repo).output().unwrap();
    Command::new("git").args(["config", "user.name", "test"]).current_dir(repo).output().unwrap();
    Command::new("git").args(["config", "user.email", "test@test.com"]).current_dir(repo).output().unwrap();

    // 创建初始文件并提交
    fs::write(repo.join("file1.txt"), "initial content").unwrap();
    fs::write(repo.join("file2.txt"), "another file").unwrap();
    Command::new("git").args(["add", "."]).current_dir(repo).output().unwrap();
    Command::new("git").args(["commit", "-m", "init"]).current_dir(repo).output().unwrap();

    // 创建快照
    let lease_id = "test-lease-123";
    let snap = snapshot::create_snapshot(repo, lease_id).unwrap();
    let snap_dir = repo.join(".airlock").join("snapshots");
    fs::create_dir_all(&snap_dir).unwrap();
    snapshot::save_snapshot_to(&snap_dir, &snap).unwrap();

    // 修改文件
    fs::write(repo.join("file1.txt"), "modified content").unwrap();
    fs::write(repo.join("file3.txt"), "new file").unwrap();
    fs::remove_file(repo.join("file2.txt")).unwrap();

    // 完成快照（记录变更）
    let mut snap = snapshot::load_snapshot_from(&snap_dir, lease_id).unwrap().unwrap();
    snapshot::finalize_snapshot(repo, &mut snap).unwrap();
    snapshot::save_snapshot_to(&snap_dir, &snap).unwrap();

    // 验证变更文件列表
    assert!(snap.changed_files.contains(&"file1.txt".to_string()), "应该记录 file1.txt");
    assert!(snap.changed_files.contains(&"file2.txt".to_string()), "应该记录 file2.txt");
    assert!(snap.changed_files.contains(&"file3.txt".to_string()), "应该记录 file3.txt");

    // 回滚
    let n = snapshot::rollback_lease(repo, &snap).unwrap();
    assert_eq!(n, snap.changed_files.len(), "回滚文件数应匹配");

    // 验证文件已恢复
    assert_eq!(fs::read_to_string(repo.join("file1.txt")).unwrap(), "initial content");
    assert!(repo.join("file2.txt").exists(), "file2.txt 应该恢复");
    assert!(!repo.join("file3.txt").exists(), "file3.txt 应该被删除");
}

#[test]
fn test_f7_snapshot_no_changes() {
    let temp = TempDir::new().unwrap();
    let repo = temp.path();

    // 初始化 git 仓库
    Command::new("git").args(["init"]).current_dir(repo).output().unwrap();
    Command::new("git").args(["config", "user.name", "test"]).current_dir(repo).output().unwrap();
    Command::new("git").args(["config", "user.email", "test@test.com"]).current_dir(repo).output().unwrap();

    fs::write(repo.join("file.txt"), "content").unwrap();
    Command::new("git").args(["add", "."]).current_dir(repo).output().unwrap();
    Command::new("git").args(["commit", "-m", "init"]).current_dir(repo).output().unwrap();

    // 创建快照
    let lease_id = "test-lease-456";
    let snap = snapshot::create_snapshot(repo, lease_id).unwrap();
    let snap_dir = repo.join(".airlock").join("snapshots");
    fs::create_dir_all(&snap_dir).unwrap();
    snapshot::save_snapshot_to(&snap_dir, &snap).unwrap();

    // 不做任何修改，直接完成快照
    let mut snap = snapshot::load_snapshot_from(&snap_dir, lease_id).unwrap().unwrap();
    snapshot::finalize_snapshot(repo, &mut snap).unwrap();

    // 验证没有变更
    assert!(snap.changed_files.is_empty(), "没有修改时应该为空");

    // 回滚应该不做任何事
    let n = snapshot::rollback_lease(repo, &snap).unwrap();
    assert_eq!(n, 0);
}

#[test]
fn test_f7_snapshot_multiple_leases() {
    let temp = TempDir::new().unwrap();
    let repo = temp.path();

    // 初始化 git 仓库
    Command::new("git").args(["init"]).current_dir(repo).output().unwrap();
    Command::new("git").args(["config", "user.name", "test"]).current_dir(repo).output().unwrap();
    Command::new("git").args(["config", "user.email", "test@test.com"]).current_dir(repo).output().unwrap();

    fs::write(repo.join("shared.txt"), "initial").unwrap();
    Command::new("git").args(["add", "."]).current_dir(repo).output().unwrap();
    Command::new("git").args(["commit", "-m", "init"]).current_dir(repo).output().unwrap();

    let snap_dir = repo.join(".airlock").join("snapshots");
    fs::create_dir_all(&snap_dir).unwrap();

    // 租约 A 的快照
    let lease_a = "lease-a";
    let snap_a = snapshot::create_snapshot(repo, lease_a).unwrap();
    snapshot::save_snapshot_to(&snap_dir, &snap_a).unwrap();

    // 租约 A 修改文件
    fs::write(repo.join("shared.txt"), "modified by A").unwrap();
    Command::new("git").args(["add", "."]).current_dir(repo).output().unwrap();
    Command::new("git").args(["commit", "-m", "A changes"]).current_dir(repo).output().unwrap();

    let mut snap_a = snapshot::load_snapshot_from(&snap_dir, lease_a).unwrap().unwrap();
    snapshot::finalize_snapshot(repo, &mut snap_a).unwrap();
    snapshot::save_snapshot_to(&snap_dir, &snap_a).unwrap();

    // 租约 B 的快照（在 A 修改后）
    let lease_b = "lease-b";
    let snap_b = snapshot::create_snapshot(repo, lease_b).unwrap();
    snapshot::save_snapshot_to(&snap_dir, &snap_b).unwrap();

    // 租约 B 修改文件
    fs::write(repo.join("shared.txt"), "modified by B").unwrap();
    Command::new("git").args(["add", "."]).current_dir(repo).output().unwrap();
    Command::new("git").args(["commit", "-m", "B changes"]).current_dir(repo).output().unwrap();

    let mut snap_b = snapshot::load_snapshot_from(&snap_dir, lease_b).unwrap().unwrap();
    snapshot::finalize_snapshot(repo, &mut snap_b).unwrap();
    snapshot::save_snapshot_to(&snap_dir, &snap_b).unwrap();

    // 回滚租约 B（应该恢复到 "modified by A"）
    snapshot::rollback_lease(repo, &snap_b).unwrap();
    assert_eq!(fs::read_to_string(repo.join("shared.txt")).unwrap(), "modified by A");

    // 回滚租约 A（应该恢复到 "initial"）
    snapshot::rollback_lease(repo, &snap_a).unwrap();
    assert_eq!(fs::read_to_string(repo.join("shared.txt")).unwrap(), "initial");
}

#[test]
fn test_f7_snapshots_list() {
    let temp = TempDir::new().unwrap();
    let snap_dir = temp.path();

    // 创建多个快照
    for i in 0..5 {
        let snap = snapshot::LeaseSnapshot {
            lease_id: format!("lease-{}", i),
            commit_hash: format!("abc{}", i),
            branch: "main".to_string(),
            created_at: 1000 + i,
            changed_files: vec![format!("file-{}.txt", i)],
        };
        snapshot::save_snapshot_to(snap_dir, &snap).unwrap();
    }

    // 列出所有快照
    let snaps = snapshot::list_snapshots_from(snap_dir).unwrap();
    assert_eq!(snaps.len(), 5);

    // 验证可以按 lease_id 加载
    for i in 0..5 {
        let snap = snapshot::load_snapshot_from(snap_dir, &format!("lease-{}", i))
            .unwrap()
            .unwrap();
        assert_eq!(snap.commit_hash, format!("abc{}", i));
    }

    // 删除一个快照
    snapshot::delete_snapshot(snap_dir, "lease-2").unwrap();
    let snaps = snapshot::list_snapshots_from(snap_dir).unwrap();
    assert_eq!(snaps.len(), 4);
}
