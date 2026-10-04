//! Landlock 行为测试（独立集成测试二进制）。
//!
//! restrict_self 是**进程级且不可逆**的：必须与 lib 单元测试隔离
//! （lib 测试二进制内并行测试写 /tmp，任何一次 restrict 都会污染它们）。
//! 本文件内只保留**一个**测试——同一进程只能应用一层规则。

#![cfg(target_os = "linux")]

use airlock_core::landlock::restrict_write_except;
use std::path::Path;

#[test]
fn restrict_grants_listed_and_denies_others() {
    if airlock_core::landlock::abi_version() < 1 {
        eprintln!("内核不支持 Landlock，跳过");
        return; // 老内核跳过
    }
    let tmp = std::env::temp_dir().join(format!("airlock-ll-it-{}", std::process::id()));
    let allowed = tmp.join("allowed");
    let denied = tmp.join("denied");
    std::fs::create_dir_all(&allowed).unwrap();
    std::fs::create_dir_all(&denied).unwrap();
    // 独立的文件规则目录：文件授权落地为其父目录（目录粒度），不能与
    // denied 断言同根，否则父目录被连带授权
    let file_root = std::env::temp_dir().join(format!("airlock-ll-it-f-{}", std::process::id()));
    std::fs::create_dir_all(&file_root).unwrap();
    let reg = file_root.join("existing.txt");
    std::fs::write(&reg, b"orig").unwrap();

    // 目录 + /dev 整树（/dev/null 是字符设备，只能经由父目录授权）+ 普通文件
    restrict_write_except(&[
        allowed.clone(),
        reg.clone(),
        Path::new("/dev").to_path_buf(),
    ])
    .expect("restrict with mixed rules");

    // 放行路径可写
    std::fs::write(allowed.join("ok.txt"), b"hi").expect("write allowed dir");
    // /dev/null（字符设备，经 /dev 目录规则）应可写
    std::fs::write("/dev/null", b"x").expect("write /dev/null via /dev rule");
    // 普通文件经父目录规则可写（目录粒度：file_root 整树被授权）
    std::fs::write(&reg, b"new").expect("write regular file via parent-dir rule");
    std::fs::write(file_root.join("sibling.txt"), b"x")
        .expect("sibling writable (dir granularity)");

    // 非放行路径必须被拒（-EPERM）
    let r = std::fs::write(denied.join("nope.txt"), b"hi");
    assert!(r.is_err(), "写非租约路径应被 Landlock 拒绝（-EPERM）");
    let r = std::fs::write("/tmp/airlock-ll-it-probe", b"x");
    assert!(r.is_err(), "写 /tmp 其他位置应被拒");

    let _ = std::fs::remove_dir_all(&tmp);
    let _ = std::fs::remove_dir_all(&file_root);
}
