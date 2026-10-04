//! Landlock 原始 syscall 封装（L2，Linux ≥5.13，非 root 可用）。
//!
//! 设计要点（对应 PRD FR2.4 / AC2.4）：`airlock run` 在**自身进程**上应用
//! restrict_self，规则随进程树生命周期存在——agent 退出即消失，daemon 崩溃
//! 不残留任何内核规则（进程作用域 ruleset 由构造保证无残留）。
//! 仅 Linux 编译（§8.2 兼容矩阵）；其他平台由 enforce 层报告"内核强制不可用"。

#![cfg(target_os = "linux")]

use std::path::Path;

use crate::error::{Error, Result};

//Landlock 能力位（linux/landlock.h，按 ABI 版本递增）
pub const LL_FS_EXECUTE: u64 = 1 << 0;
pub const LL_FS_WRITE_FILE: u64 = 1 << 1;
pub const LL_FS_READ_FILE: u64 = 1 << 2;
pub const LL_FS_READ_DIR: u64 = 1 << 3;
pub const LL_FS_REMOVE_DIR: u64 = 1 << 4;
pub const LL_FS_REMOVE_FILE: u64 = 1 << 5;
pub const LL_FS_MAKE_CHAR: u64 = 1 << 6;
pub const LL_FS_MAKE_DIR: u64 = 1 << 7;
pub const LL_FS_MAKE_FIFO: u64 = 1 << 8;
pub const LL_FS_MAKE_SOCK: u64 = 1 << 9;
pub const LL_FS_MAKE_SYM: u64 = 1 << 10;
pub const LL_FS_REFER: u64 = 1 << 11; // ABI 2
pub const LL_FS_TRUNCATE: u64 = 1 << 12; // ABI 3

const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1 << 0;
const LANDLOCK_RULE_PATH_BENEATH: u8 = 1;
const PR_SET_NO_NEW_PRIVS: i32 = 38;

// x86_64 / aarch64 通用编号（libc 较旧版本缺失时的兜底）
const SYS_LL_CREATE_RULESET: libc::c_long = 444;
const SYS_LL_ADD_RULE: libc::c_long = 445;
const SYS_LL_RESTRICT_SELF: libc::c_long = 446;

#[repr(C)]
struct LandlockRulesetAttr {
    handled_access_fs: u64,
}

#[repr(C)]
struct LandlockPathBeneathAttr {
    allowed_access: u64,
    parent_fd: i64,
}

/// 探测内核 Landlock ABI 版本；0 = 不可用（AC2.2 探测依据）。
pub fn abi_version() -> u32 {
    let rc = unsafe {
        libc::syscall(
            SYS_LL_CREATE_RULESET,
            std::ptr::null::<LandlockRulesetAttr>(),
            0 as libc::size_t,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if rc >= 1 {
        rc as u32
    } else {
        0
    }
}

/// 当前 ABI 支持的「写类」访问位（我们只处理写；读始终放行）。
fn handled_write_bits(abi: u32) -> u64 {
    let mut bits = LL_FS_WRITE_FILE
        | LL_FS_REMOVE_DIR
        | LL_FS_REMOVE_FILE
        | LL_FS_MAKE_CHAR
        | LL_FS_MAKE_DIR
        | LL_FS_MAKE_FIFO
        | LL_FS_MAKE_SOCK
        | LL_FS_MAKE_SYM;
    if abi >= 2 {
        bits |= LL_FS_REFER;
    }
    if abi >= 3 {
        bits |= LL_FS_TRUNCATE;
    }
    bits
}

const READ_BITS: u64 = LL_FS_READ_FILE | LL_FS_READ_DIR;

#[derive(Debug)]
pub struct LandlockError {
    pub op: &'static str,
    pub detail: String,
}

impl std::fmt::Display for LandlockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Landlock {} 失败: {}", self.op, self.detail)
    }
}

fn errno_str(op: &'static str) -> LandlockError {
    let e = std::io::Error::last_os_error();
    LandlockError {
        op,
        detail: e.to_string(),
    }
}

/// 在当前进程（及未来子进程）上应用 Landlock：
/// 读全放行；写仅允许 `allowed_write` 列出的路径树下（已存在的目录/文件）。
/// 成功后本进程无法再放宽——调用方须先完成全部准备再 restrict。
///
/// 安全设计（P0）：每条路径先 `canonicalize()` 解析全部符号链接再打开，
/// 且 open 一律加 `O_NOFOLLOW`——仓库内 `ln -s / out` 后 claim `out/**`
/// 不能再把规则挂到 `/` 上。canonicalize 失败（不存在/悬空链接）的路径跳过，
/// 符号链接本体不再被跟随。
pub fn restrict_write_except(
    allowed_write: &[std::path::PathBuf],
) -> std::result::Result<(), LandlockError> {
    let abi = abi_version();
    if abi < 1 {
        return Err(LandlockError {
            op: "probe",
            detail: "内核不支持 Landlock".into(),
        });
    }
    let handled = handled_write_bits(abi);
    let attr = LandlockRulesetAttr {
        handled_access_fs: handled,
    };
    let ruleset_fd = unsafe {
        libc::syscall(
            SYS_LL_CREATE_RULESET,
            &attr as *const LandlockRulesetAttr,
            std::mem::size_of::<LandlockRulesetAttr>(),
            0u32,
        )
    };
    if ruleset_fd < 0 {
        return Err(errno_str("create_ruleset"));
    }
    let ruleset_fd = ruleset_fd as i32;

    let add_path = |parent: &Path, allowed: u64| -> std::result::Result<(), LandlockError> {
        // O_PATH：只取路径引用，不触发权限检查；O_NOFOLLOW：绝不跟随符号链接
        let cpath = std::os::unix::ffi::OsStrExt::as_bytes(parent.as_os_str());
        let cstring = std::ffi::CString::new(cpath).map_err(|_| LandlockError {
            op: "open",
            detail: "路径含 NUL".into(),
        })?;
        let fd = unsafe {
            libc::open(
                cstring.as_ptr(),
                libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY,
            )
        };
        if fd < 0 {
            return Err(errno_str("open"));
        }
        let rule = LandlockPathBeneathAttr {
            allowed_access: allowed & (READ_BITS | handled),
            parent_fd: fd as i64,
        };
        let rc = unsafe {
            libc::syscall(
                SYS_LL_ADD_RULE,
                ruleset_fd,
                LANDLOCK_RULE_PATH_BENEATH as libc::c_ulong,
                &rule as *const LandlockPathBeneathAttr,
                0u32,
            )
        };
        unsafe { libc::close(fd) };
        if rc != 0 {
            return Err(errno_str("add_rule"));
        }
        Ok(())
    };

    let apply = || -> std::result::Result<(), LandlockError> {
        let mut seen = std::collections::HashSet::new();
        for p in allowed_write {
            // 先解析全部符号链接；不存在的路径跳过（与旧行为一致）
            let Ok(canon) = p.canonicalize() else {
                continue;
            };
            // 内核约束：PATH_BENEATH 规则只能挂在**目录**上（allowed ⊆ handled，
            // 多余位 → EINVAL）。普通文件授权落地到其父目录——即 L2 强制粒度是目录级
            // （文档明示：文件级冲突仍在 L1/MCP/hook 层拒绝）。字符设备无法授权，
            // 调用方应改授其父目录（如 /dev 覆盖 /dev/null、/dev/pts）。
            let meta = std::fs::symlink_metadata(&canon).map_err(|e| LandlockError {
                op: "stat",
                detail: e.to_string(),
            })?;
            let target: std::path::PathBuf = if meta.is_dir() {
                canon.clone()
            } else if meta.is_file() {
                match canon.parent() {
                    Some(parent) if parent != canon => parent.to_path_buf(),
                    _ => continue,
                }
            } else {
                continue; // 特殊文件：跳过
            };
            if seen.insert(target.clone()) {
                add_path(&target, handled)?;
            }
        }
        Ok(())
    };
    if let Err(e) = apply() {
        // 失败路径必须关闭 ruleset_fd，不泄漏
        unsafe { libc::close(ruleset_fd) };
        return Err(e);
    }

    // 子进程不再获得特权（Landlock 应用前置条件）
    if unsafe { libc::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        unsafe { libc::close(ruleset_fd) };
        return Err(errno_str("prctl(NO_NEW_PRIVS)"));
    }
    let rc = unsafe { libc::syscall(SYS_LL_RESTRICT_SELF, ruleset_fd, 0u32) };
    unsafe { libc::close(ruleset_fd) };
    if rc != 0 {
        return Err(errno_str("restrict_self"));
    }
    Ok(())
}

/// L2 可用性检查，供 doctor / run 使用。
pub fn check_available() -> Result<()> {
    if abi_version() < 1 {
        Err(Error::Other(
            "内核 Landlock 不可用（需要 Linux ≥ 5.13 且 LSM 启用 landlock）".into(),
        ))
    } else {
        Ok(())
    }
}

// 注意：restrict_self 是进程级且不可逆的行为测试已移至
// tests/landlock_integration.rs——lib 单元测试与它共用同一测试进程时，
// 任何一次 restrict 都会污染其他并行测试的 /tmp 写入。
