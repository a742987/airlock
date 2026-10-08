//! 冲突域与 Airlock 数据目录布局（§7 / §8.3）。
//!
//! - git 仓库：冲突域 = git common dir 规范路径的 SHA-256 前缀；数据存 `<git-common-dir>/airlock/`
//! - 非 git 目录：仅 L1 advisory 可用（§8.2 兼容矩阵），数据存 `<cwd>/.airlock/`

use std::path::{Path, PathBuf};
use std::process::Command;

#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;

use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
pub struct Domain {
    /// 冲突域 ID（git common dir 哈希 / 非 git 时 cwd 哈希）
    pub id: String,
    /// 仓库工作树根（git 仓库）或当前目录（非 git）
    pub root: PathBuf,
    /// git common dir（如 `<root>/.git`）；非 git 时等于 root
    pub common_dir: PathBuf,
    /// Airlock 数据目录：daemon.sock、airlock.db、sessions/
    pub dir: PathBuf,
    /// 是否为 git 仓库
    pub is_git: bool,
}

/// 冲突域键：Windows 语义默认大小写不敏感（PRD AC2.9，策略可配），Linux 区分大小写。
pub fn domain_key(p: &Path) -> String {
    #[cfg(target_os = "windows")]
    {
        p.to_string_lossy().to_lowercase()
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = p;
        p.to_string_lossy().to_string()
    }
}

fn sha16_bytes(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    let d = h.finalize();
    d.iter().map(|b| format!("{b:02x}")).collect::<String>()[..16].to_string()
}

impl Domain {
    /// 从工作目录解析冲突域。`start` 为空时取当前目录。
    pub fn discover(start: Option<&Path>) -> std::io::Result<Domain> {
        let cwd = match start {
            Some(p) => p.to_path_buf(),
            None => std::env::current_dir()?,
        };
        let cwd = cwd.canonicalize().unwrap_or(cwd);
        let common_dir = git_common_dir(&cwd);
        let is_git = common_dir.is_some();
        let common_dir = common_dir.unwrap_or_else(|| cwd.clone());
        let root = if is_git {
            // 冲突域 ID 以 common dir 为准（同一 common dir = 同一租约空间），
            // 但 root 必须是**当前 worktree**：linked worktree 的 common dir
            // 在主仓库下，取 parent 会把政策/快照/Landlock 全作用到主仓库树
            git_worktree_root(&cwd).unwrap_or_else(|| {
                common_dir
                    .parent()
                    .map(|p| p.to_path_buf())
                    .unwrap_or_else(|| common_dir.clone())
            })
        } else {
            cwd.clone()
        };
        let dir = if is_git {
            common_dir.join("airlock")
        } else {
            cwd.join(".airlock")
        };
        std::fs::create_dir_all(&dir)?;
        std::fs::create_dir_all(dir.join("sessions"))?;
        // 以原始字节哈希（to_string_lossy 的 U+FFFD 替换可造成域 ID 碰撞）
        #[cfg(unix)]
        let id = sha16_bytes(common_dir.as_os_str().as_bytes());
        #[cfg(not(unix))]
        let id = sha16_bytes(common_dir.to_string_lossy().as_bytes());
        Ok(Domain {
            id,
            root,
            common_dir,
            dir,
            is_git,
        })
    }

    pub fn socket_path(&self) -> PathBuf {
        self.dir.join("daemon.sock")
    }

    pub fn db_path(&self) -> PathBuf {
        self.dir.join("airlock.db")
    }

    pub fn pid_path(&self) -> PathBuf {
        self.dir.join("daemon.pid")
    }

    pub fn manifest_path(&self) -> PathBuf {
        self.dir.join("init-manifest.json")
    }

    pub fn session_dir(&self, session_id: &str) -> PathBuf {
        self.dir.join("sessions").join(session_id)
    }
}

/// 当前 worktree 根（`git rev-parse --show-toplevel`）。
/// linked worktree 下与 common dir 的 parent 不同——root 必须用它。
fn git_worktree_root(cwd: &Path) -> Option<PathBuf> {
    let out = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .current_dir(cwd)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() {
        return None;
    }
    let p = PathBuf::from(&s);
    let abs = if p.is_absolute() { p } else { cwd.join(p) };
    abs.canonicalize().ok().or(Some(abs))
}

fn git_common_dir(cwd: &Path) -> Option<PathBuf> {
    let out = Command::new("git")
        .args(["rev-parse", "--git-common-dir"])
        .current_dir(cwd)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() {
        return None;
    }
    let p = PathBuf::from(&s);
    let abs = if p.is_absolute() { p } else { cwd.join(p) };
    abs.canonicalize().ok().or(Some(abs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_git_domain_uses_cwd_airlock() {
        let tmp = std::env::temp_dir().join(format!("airlock-dom-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).unwrap();
        let d = Domain::discover(Some(&tmp)).unwrap();
        assert!(!d.is_git);
        assert_eq!(d.dir, tmp.join(".airlock"));
        assert_eq!(d.id.len(), 16);
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn domain_id_is_stable() {
        let tmp = std::env::temp_dir().join(format!("airlock-dom-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).unwrap();
        let d1 = Domain::discover(Some(&tmp)).unwrap();
        let d2 = Domain::discover(Some(&tmp)).unwrap();
        assert_eq!(d1.id, d2.id);
        std::fs::remove_dir_all(&tmp).ok();
    }
}
