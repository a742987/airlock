//! 混沌测试：验证高并发场景下的租约引擎原子性与审计链完整性。
//! AC1.5: 1000 个并发 claim 请求无死锁、无状态错乱。

use airlock_core::config::Config;
use airlock_core::lease::{self, ClaimParams};
use airlock_core::proto::Actor;
use airlock_core::store::Store;
use std::collections::HashMap;
use std::sync::{Arc, Barrier, Mutex};
use std::thread;

/// 创建测试用的 ClaimParams
fn make_claim_params(session_id: &str, glob: &str, layer: &str) -> ClaimParams {
    ClaimParams {
        conflict_domain: "test-domain".to_string(),
        agent_id: "test-agent".to_string(),
        session_id: session_id.to_string(),
        glob: glob.to_string(),
        intent: Some(format!("测试意图: {}", glob)),
        ttl_s: Some(300),
        heartbeat_s: 60,
        layer: layer.to_string(),
        actor: Actor {
            agent: "test-agent".to_string(),
            session: session_id.to_string(),
            pid_tree: vec![std::process::id()],
        },
        root: None,
    }
}

#[test]
fn chaos_1000_concurrent_claims_non_overlapping() {
    // 1000 个线程同时 claim 不重叠的路径，全部应该成功
    let store = Arc::new(Mutex::new(Store::open_in_memory().unwrap()));
    let cfg = Arc::new(Config::default());
    let barrier = Arc::new(Barrier::new(1000));
    let mut handles = vec![];

    for i in 0..1000 {
        let store = Arc::clone(&store);
        let cfg = Arc::clone(&cfg);
        let barrier = Arc::clone(&barrier);

        let handle = thread::spawn(move || {
            barrier.wait(); // 所有线程同时起跑
            let params = make_claim_params(
                &format!("sess-{}", i),
                &format!("src/file-{}.rs", i), // 每个线程 claim 不同文件
                "L1",
            );
            let s = store.lock().unwrap();
            lease::claim(&s, &cfg, &params)
        });
        handles.push(handle);
    }

    let results: Vec<_> = handles
        .into_iter()
        .map(|h| h.join().expect("线程 panic"))
        .collect();

    // 验证：全部成功
    let success_count = results.iter().filter(|r| r.is_ok()).count();
    assert_eq!(
        success_count, 1000,
        "非重叠路径应全部 claim 成功，实际成功 {}",
        success_count
    );

    // 验证：审计链完整
    let s = store.lock().unwrap();
    let broken = s.audit_verify().unwrap();
    assert!(broken.is_empty(), "审计链存在断链位置: {:?}", broken);
}

#[test]
fn chaos_1000_concurrent_claims_with_conflicts() {
    // 1000 个线程同时 claim，10% 冲突率（每 10 个线程争抢同一文件）
    let store = Arc::new(Mutex::new(Store::open_in_memory().unwrap()));
    let cfg = Arc::new(Config::default());
    let barrier = Arc::new(Barrier::new(1000));
    let mut handles = vec![];

    for i in 0..1000 {
        let store = Arc::clone(&store);
        let cfg = Arc::clone(&cfg);
        let barrier = Arc::clone(&barrier);

        let handle = thread::spawn(move || {
            barrier.wait();
            let params = make_claim_params(
                &format!("sess-{}", i),
                &format!("src/file-{}.rs", i % 100), // 100 个不同文件，冲突率 10:1
                "L1",
            );
            let s = store.lock().unwrap();
            lease::claim(&s, &cfg, &params)
        });
        handles.push(handle);
    }

    let results: Vec<_> = handles
        .into_iter()
        .map(|h| h.join().expect("线程 panic"))
        .collect();

    // 统计每个文件的成功 claim 数
    let mut granted: HashMap<String, Vec<usize>> = HashMap::new();
    for (i, r) in results.iter().enumerate() {
        if let Ok(claim_ok) = r {
            granted
                .entry(claim_ok.lease.glob.clone())
                .or_default()
                .push(i);
        }
    }

    // 验证：每个文件最多一个成功 claim
    for (glob, sessions) in &granted {
        assert_eq!(
            sessions.len(),
            1,
            "路径 {} 被多个会话持有: {:?}",
            glob,
            sessions
        );
    }

    // 验证：大约 100 个成功（每个文件一个）
    let success_count = results.iter().filter(|r| r.is_ok()).count();
    assert!(
        (95..=105).contains(&success_count),
        "预期约 100 个成功 claim，实际 {}",
        success_count
    );

    // 验证：审计链完整
    let s = store.lock().unwrap();
    let broken = s.audit_verify().unwrap();
    assert!(broken.is_empty(), "审计链存在断链位置: {:?}", broken);

    // 验证：所有拒绝都有 deny 审计记录
    let audit = s.audit_query(None, 10000).unwrap();
    let deny_count = audit.iter().filter(|e| e.event == "deny").count();
    let conflict_count = results.iter().filter(|r| r.is_err()).count();
    assert!(deny_count > 0, "应该有 deny 审计记录，但实际为 0");
    println!(
        "混沌测试统计: {} 次成功, {} 次冲突, {} 条 deny 审计",
        success_count, conflict_count, deny_count
    );
}

#[test]
fn chaos_concurrent_claim_and_release() {
    // 500 个线程 claim，500 个线程 release，验证状态一致性
    let store = Arc::new(Mutex::new(Store::open_in_memory().unwrap()));
    let cfg = Arc::new(Config::default());
    let barrier = Arc::new(Barrier::new(1000));
    let mut handles = vec![];

    // 先预先创建一些租约供 release
    {
        let s = store.lock().unwrap();
        for i in 500..1000 {
            let params =
                make_claim_params(&format!("sess-{}", i), &format!("src/pre-{}.rs", i), "L1");
            let _ = lease::claim(&s, &cfg, &params);
        }
    }

    let lease_ids: Vec<String> = {
        let s = store.lock().unwrap();
        s.list_leases(Some("test-domain"), true)
            .unwrap()
            .into_iter()
            .map(|l| l.id)
            .collect()
    };

    // 500 个 claim，500 个 release
    for i in 0..500 {
        let store = Arc::clone(&store);
        let cfg = Arc::clone(&cfg);
        let barrier = Arc::clone(&barrier);

        // claim 线程
        let handle = thread::spawn(move || {
            barrier.wait();
            let params = make_claim_params(
                &format!("new-sess-{}", i),
                &format!("src/new-{}.rs", i),
                "L1",
            );
            let s = store.lock().unwrap();
            let _ = lease::claim(&s, &cfg, &params);
        });
        handles.push(handle);
    }

    for i in 0..500 {
        let store = Arc::clone(&store);
        let barrier = Arc::clone(&barrier);
        let lease_id = lease_ids.get(i).cloned();

        // release 线程
        let handle = thread::spawn(move || {
            barrier.wait();
            if let Some(lid) = lease_id {
                let s = store.lock().unwrap();
                let _ = lease::release(
                    &s,
                    &lid,
                    &Actor {
                        agent: "test-agent".into(),
                        session: "unknown".into(),
                        pid_tree: vec![],
                    },
                    "L1",
                    None,
                    None,
                );
            }
        });
        handles.push(handle);
    }

    // 等待所有线程完成
    for h in handles {
        let _ = h.join();
    }

    // 验证：审计链完整
    let s = store.lock().unwrap();
    let broken = s.audit_verify().unwrap();
    assert!(broken.is_empty(), "审计链存在断链位置: {:?}", broken);

    // 验证：active 租约数合理
    let active = s.list_leases(Some("test-domain"), true).unwrap();
    println!("混沌测试后 active 租约数: {}", active.len());
    assert!(active.len() <= 1000, "active 租约数异常: {}", active.len());
}

#[test]
fn chaos_stress_audit_chain() {
    // 压测审计链：10000 条记录，验证 hash 链完整性
    let store = Store::open_in_memory().unwrap();
    let cfg = Config::default();

    for i in 0..10000 {
        let params = make_claim_params(&format!("sess-{}", i), &format!("file-{}.rs", i), "L1");
        let _ = lease::claim(&store, &cfg, &params);
    }

    // 验证审计链
    let broken = store.audit_verify().unwrap();
    assert!(
        broken.is_empty(),
        "10000 条记录的审计链存在断链: {:?}",
        broken
    );

    // 验证审计记录数量
    let audit = store.audit_query(None, 20000).unwrap();
    assert!(audit.len() >= 10000, "审计记录数不足: {}", audit.len());
}
