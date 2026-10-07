//! F12 内核层行为测试（独立集成测试二进制）：政策 deny 子树在 Landlock 下的
//! 真实 EPERM。验收标准「政策文件在 claim 时驱动内核拒绝」的内核侧证明。
//!
//! restrict_self 进程级且不可逆——必须独立于 lib 测试进程（同
//! landlock_integration.rs 的隔离纪律），本文件内只保留一个测试。

#![cfg(target_os = "linux")]

use airlock_core::landlock::restrict_write_except;

#[test]
fn policy_denied_subtree_gets_kernel_eperm() {
    if airlock_core::landlock::abi_version() < 1 {
        eprintln!("内核不支持 Landlock，跳过");
        return;
    }
    let tmp = std::env::temp_dir().join(format!("airlock-ll-pol-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let src = tmp.join("src");
    let vault = src.join("vault");
    std::fs::create_dir_all(&vault).unwrap();
    std::fs::write(src.join("main.rs"), b"orig").unwrap();

    // claim src/**（允许 src 整树）+ 政策 deny src/vault/**：
    // restrict_write_except 应把 src 展开为「main.rs 文件规则 + vault 被排除」
    restrict_write_except(std::slice::from_ref(&src), std::slice::from_ref(&vault))
        .expect("restrict with policy deny");

    // 展开后的散文件（main.rs）仍可写——文件级规则精确授权
    std::fs::write(src.join("main.rs"), b"new").expect("展开后的散文件应可写");
    // 被拒子树（新建文件同样）→ 内核 EPERM（政策的内核层拒绝）
    let r = std::fs::write(vault.join("secret.pem"), b"x");
    assert!(r.is_err(), "政策 deny 子树应被内核拒绝（-EPERM）");

    // 允许集之外仍然拒绝（原有语义不回归）
    let r = std::fs::write(tmp.join("outside.txt"), b"x");
    assert!(r.is_err(), "允许集之外的路径应被拒");

    let _ = std::fs::remove_dir_all(&tmp);
}
