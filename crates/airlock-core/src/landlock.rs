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
/// 读全放行；写仅允许 `allowed_write` 列出的路径树下（已存在的目录/文件），
/// 但**减去 `denied_write` 列出的子树**（F12 政策即代码：deny 规则在内核层拒绝）。
/// 成功后本进程无法再放宽——调用方须先完成全部准备再 restrict。
///
/// 安全设计（P0）：每条路径先 `canonicalize()` 解析全部符号链接再打开，
/// 且 open 一律加 `O_NOFOLLOW`——仓库内 `ln -s / out` 后 claim `out/**`
/// 不能再把规则挂到 `/` 上。canonicalize 失败（不存在/悬空链接）的路径跳过，
/// 符号链接本体不再被跟随。
pub fn restrict_write_except(
    allowed_write: &[std::path::PathBuf],
    denied_write: &[std::path::PathBuf],
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

    let open_no_follow = |path: &Path, dir_only: bool| -> std::result::Result<i32, LandlockError> {
        // O_PATH：只取路径引用，不触发权限检查；O_NOFOLLOW：绝不跟随符号链接
        let cpath = std::os::unix::ffi::OsStrExt::as_bytes(path.as_os_str());
        let cstring = std::ffi::CString::new(cpath).map_err(|_| LandlockError {
            op: "open",
            detail: "路径含 NUL".into(),
        })?;
        let mut flags = libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW;
        if dir_only {
            flags |= libc::O_DIRECTORY;
        }
        let fd = unsafe { libc::open(cstring.as_ptr(), flags) };
        if fd < 0 {
            Err(errno_str("open"))
        } else {
            Ok(fd)
        }
    };

    let add_rule = |fd: i32, allowed: u64| -> std::result::Result<(), LandlockError> {
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
        if rc != 0 {
            return Err(errno_str("add_rule"));
        }
        Ok(())
    };

    let add_dir = |parent: &Path| -> std::result::Result<(), LandlockError> {
        let fd = open_no_follow(parent, true)?;
        let rc = add_rule(fd, handled);
        unsafe { libc::close(fd) };
        rc
    };

    // F12：文件级规则（被政策拒绝子树的同级散文件兜底）。
    // 内核对**文件 FD** 的 allowed_access 校验极严：实测（ABI 8）混入
    // REMOVE_FILE/TRUNCATE/REFER 一律 EINVAL，只接受纯 WRITE_FILE。
    // 策略：先尝试 WRITE_FILE|TRUNCATE（宽松内核可覆盖 O_TRUNC 写），
    // EINVAL 再退回纯 WRITE_FILE；仍失败则该文件不可写（fail-closed），
    // 绝不让单个文件规则失败放大成整体失败。
    let add_file = |path: &Path| -> std::result::Result<(), LandlockError> {
        let fd = open_no_follow(path, false)?;
        let mut bits = LL_FS_WRITE_FILE;
        if abi >= 3 {
            bits |= LL_FS_TRUNCATE;
        }
        if add_rule(fd, bits).is_err() {
            let _ = add_rule(fd, LL_FS_WRITE_FILE);
        }
        unsafe { libc::close(fd) };
        Ok(())
    };

    let apply = || -> std::result::Result<(), LandlockError> {
        // 先统一 canonicalize（老行为：不存在的路径跳过），再做政策减法——
        // starts_with 比较必须在同一规范化坐标系上进行
        let canon = |list: &[std::path::PathBuf]| -> Vec<std::path::PathBuf> {
            list.iter().filter_map(|p| p.canonicalize().ok()).collect()
        };
        let allowed = canon(allowed_write);
        let denied = canon(denied_write);
        let (dirs, files) = subtract_denied(&allowed, &denied)?;
        let mut seen = std::collections::HashSet::new();
        for d in &dirs {
            if seen.insert(d.clone()) {
                add_dir(d)?;
            }
        }
        for f in &files {
            let _ = add_file(f);
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

/// F12 政策减法的最大展开深度：超过即放弃该分支（fail-closed——被拒子树
/// 可能藏得更深，宁可收紧也不放行整个父目录）。
const MAX_EXPAND_DEPTH: usize = 16;

/// 从允许写集合中减去被政策拒绝的子树（F12：Landlock 只有允许规则，无 deny）。
///
/// 「父目录被允许、子目录被拒」时必须把父目录展开到子级、跳过被拒分支，
/// 递归直到无冲突；展开产生的**散文件**用文件级规则精确授权。展开失败
/// （read_dir 不可读）向上传播 → 调用方整体降级 L1（绝不静默放宽）。
/// 返回 (目录规则, 文件规则)；`denied` 为空时目录=全部允许目录、文件=允许文件。
fn subtract_denied(
    allowed: &[std::path::PathBuf],
    denied: &[std::path::PathBuf],
) -> std::result::Result<(Vec<std::path::PathBuf>, Vec<std::path::PathBuf>), LandlockError> {
    let mut dirs = Vec::new();
    let mut files = Vec::new();
    for a in allowed {
        expand_path(a, denied, 0, &mut dirs, &mut files)?;
    }
    dirs.sort();
    dirs.dedup();
    files.sort();
    files.dedup();
    Ok((dirs, files))
}

fn expand_path(
    path: &std::path::Path,
    denied: &[std::path::PathBuf],
    depth: usize,
    dirs: &mut Vec<std::path::PathBuf>,
    files: &mut Vec<std::path::PathBuf>,
) -> std::result::Result<(), LandlockError> {
    // 位于被拒子树内（含恰好相等）→ deny 永远赢
    if denied.iter().any(|d| path.starts_with(d)) {
        return Ok(());
    }
    // path 之下的被拒子树
    let has_conflict = denied.iter().any(|d| d.starts_with(path));
    if !has_conflict {
        let meta = std::fs::symlink_metadata(path).map_err(|e| LandlockError {
            op: "stat",
            detail: format!("{}: {e}", path.display()),
        })?;
        if meta.is_dir() {
            dirs.push(path.to_path_buf());
        } else if meta.is_file() {
            if depth == 0 {
                // 旧语义：显式授权的普通文件落地为父目录整树——但父目录含
                // 被拒子树时退化为文件级规则（政策不被父目录授权穿透）
                let parent_conflict = path
                    .parent()
                    .map(|p| denied.iter().any(|d| d.starts_with(p)))
                    .unwrap_or(false);
                match (path.parent(), parent_conflict) {
                    (Some(parent), false) if parent != path => dirs.push(parent.to_path_buf()),
                    _ => files.push(path.to_path_buf()),
                }
            } else {
                files.push(path.to_path_buf());
            }
        } // 特殊文件（设备/套接字等）：跳过，与旧行为一致
        return Ok(());
    }
    // path 下有被拒子树 → 必须展开细分；非目录不可能包含子树（防御性返回）
    if depth >= MAX_EXPAND_DEPTH
        || !std::fs::symlink_metadata(path)
            .map(|m| m.is_dir())
            .unwrap_or(false)
    {
        return Ok(()); // 深度耗尽：fail-closed，不放行
    }
    let entries = std::fs::read_dir(path).map_err(|e| LandlockError {
        op: "policy_expand",
        detail: format!("{}: {e}", path.display()),
    })?;
    for entry in entries {
        let entry = entry.map_err(|e| LandlockError {
            op: "policy_expand",
            detail: format!("{}: {e}", path.display()),
        })?;
        let ft = entry.file_type().map_err(|e| LandlockError {
            op: "policy_expand",
            detail: format!("{}: {e}", path.display()),
        })?; // 不跟随符号链接
        let child = entry.path();
        if ft.is_symlink() {
            // P0：展开中的符号链接一律跳过——跟随可能把规则挂到仓库外
            continue;
        }
        expand_path(&child, denied, depth + 1, dirs, files)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 政策减法是纯路径逻辑（无 syscall 副作用），在临时目录上直接验证。
    #[test]
    fn subtract_denied_splits_allowed_tree() {
        let tmp = std::env::temp_dir().join(format!("airlock-ll-sub-{}", std::process::id()));
        let src = tmp.join("src");
        let gen = src.join("generated");
        std::fs::create_dir_all(&gen).unwrap();
        std::fs::write(src.join("main.rs"), b"x").unwrap();
        std::fs::write(src.join("lib.rs"), b"x").unwrap();

        // 允许整个 src，拒绝 src/generated：应展开为 src 下的散文件规则 + 无 src 目录规则
        let (dirs, files) =
            subtract_denied(std::slice::from_ref(&src), std::slice::from_ref(&gen)).unwrap();
        assert!(dirs.is_empty(), "父目录不得整体放行：{dirs:?}");
        assert!(files.contains(&src.join("main.rs")));
        assert!(files.contains(&src.join("lib.rs")));

        // 无冲突时保持整目录授权（老路径行为不变）
        let (dirs, files) = subtract_denied(std::slice::from_ref(&src), &[]).unwrap();
        assert_eq!(dirs, vec![src.clone()]);
        assert!(files.is_empty());

        // deny 恰好等于允许目录 → 整体拒绝
        let (dirs, files) =
            subtract_denied(std::slice::from_ref(&gen), std::slice::from_ref(&gen)).unwrap();
        assert!(dirs.is_empty() && files.is_empty());

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn subtract_denied_drops_allowed_inside_denied() {
        let tmp = std::env::temp_dir().join(format!("airlock-ll-sub2-{}", std::process::id()));
        let vault = tmp.join("vault");
        let inner = vault.join("inner");
        std::fs::create_dir_all(&inner).unwrap();
        let (dirs, files) = subtract_denied(&[vault.clone(), inner.clone()], &[vault]).unwrap();
        assert!(dirs.is_empty() && files.is_empty());
        std::fs::remove_dir_all(&tmp).ok();
    }
}
