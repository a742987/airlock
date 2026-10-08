//! F7 租约时间线快照与隔离回滚（v0.5）：
//! - 租约 claim 时记录 git HEAD 作为快照锚点
//! - 租约 release/expire 时记录变更文件列表
//! - rollback 时恢复到该租约的快照锚点，仅回滚该租约变更的文件

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;

/// 租约快照：记录租约开始时的 git 状态。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaseSnapshot {
    pub lease_id: String,
    pub commit_hash: String,
    pub branch: String,
    pub created_at: i64,
    /// 租约结束时记录的文件变更列表
    pub changed_files: Vec<String>,
}

/// 获取当前 git HEAD 的 commit hash。
pub fn git_head_commit(repo_root: &Path) -> Result<String> {
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(repo_root)
        .output()
        .map_err(Error::Io)?;
    if !output.status.success() {
        return Err(Error::Other(format!(
            "git rev-parse HEAD 失败: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// 获取当前 git 分支名。
pub fn git_current_branch(repo_root: &Path) -> Result<String> {
    let output = Command::new("git")
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .current_dir(repo_root)
        .output()
        .map_err(Error::Io)?;
    if !output.status.success() {
        return Err(Error::Other(format!(
            "git rev-parse --abbrev-ref HEAD 失败: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// 获取自某个 commit 以来变更的文件列表。
pub fn git_changed_files_since(repo_root: &Path, since_commit: &str) -> Result<Vec<String>> {
    let output = Command::new("git")
        .args(["diff", "--name-only", since_commit, "HEAD"])
        .current_dir(repo_root)
        .output()
        .map_err(Error::Io)?;
    if !output.status.success() {
        // 如果 HEAD 不存在（例如没有新提交），尝试对比工作区
        let output = Command::new("git")
            .args(["diff", "--name-only", since_commit])
            .current_dir(repo_root)
            .output()
            .map_err(Error::Io)?;
        if !output.status.success() {
            return Err(Error::Other(format!(
                "git diff 失败: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }
    }
    let files: Vec<String> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|l| !l.is_empty() && *l != ".airlock" && !l.starts_with(".airlock/"))
        .map(|l| l.to_string())
        .collect();
    Ok(files)
}

/// 获取工作区中变更的文件（包括未提交的）。
pub fn git_working_dir_changes(repo_root: &Path) -> Result<Vec<String>> {
    let output = Command::new("git")
        .args(["status", "--porcelain"])
        .current_dir(repo_root)
        .output()
        .map_err(Error::Io)?;
    if !output.status.success() {
        return Err(Error::Other(format!(
            "git status 失败: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    let files: Vec<String> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            // Porcelain format is two status bytes followed by a space and path.
            if line.len() >= 4 {
                let path = line[3..].trim();
                // Snapshot metadata is Airlock's bookkeeping and must not be
                // treated as an agent workspace change.
                if path == ".airlock" || path.starts_with(".airlock/") {
                    None
                } else {
                    Some(path.to_string())
                }
            } else {
                None
            }
        })
        .collect();
    Ok(files)
}

/// 将快照中的相对路径归一化并校验仍位于仓库内。
///
/// 快照 JSON 可能被仓库内任意进程写入，`changed_files` 属于不可信输入：
/// 绝对路径、`..`、空路径一律拒绝（`Path::starts_with` 不归一化 `..`，
/// 单独使用会被 `/repo/../../x` 绕过，因此必须先做组件归一化）。
fn safe_repo_path(repo_root: &Path, f: &str) -> Option<PathBuf> {
    let rel = Path::new(f);
    if f.is_empty() || rel.is_absolute() {
        return None;
    }
    let mut normalized = PathBuf::new();
    for comp in rel.components() {
        match comp {
            std::path::Component::Normal(c) => normalized.push(c),
            std::path::Component::CurDir => {}
            // ParentDir / RootDir / Prefix 一律拒绝
            _ => return None,
        }
    }
    if normalized.as_os_str().is_empty() {
        return None;
    }
    let full = repo_root.join(normalized);
    if full.starts_with(repo_root) {
        Some(full)
    } else {
        None
    }
}

/// 校验 lease_id 可安全用作文件名（拒绝路径分隔符与 `..`）。
fn safe_lease_id(lease_id: &str) -> bool {
    !lease_id.is_empty()
        && lease_id != "."
        && lease_id != ".."
        && !lease_id.contains('/')
        && !lease_id.contains('\\')
        && !lease_id.contains("..")
        && !lease_id.contains('\0')
}

/// 恢复指定文件到某个 commit 的状态。
pub fn git_restore_files_to_commit(
    repo_root: &Path,
    files: &[String],
    commit_hash: &str,
) -> Result<()> {
    if files.is_empty() {
        return Ok(());
    }
    for f in files {
        // 不可信输入：不在仓库内的路径（含遍历构造）直接跳过
        let path = match safe_repo_path(repo_root, f) {
            Some(p) => p,
            None => continue,
        };
        let exists = Command::new("git")
            .args(["cat-file", "-e", &format!("{commit_hash}:{f}")])
            .current_dir(repo_root)
            .status()
            .map_err(Error::Io)?
            .success();
        if exists {
            let output = Command::new("git")
                .args(["checkout", commit_hash, "--", f])
                .current_dir(repo_root)
                .output()
                .map_err(Error::Io)?;
            if !output.status.success() {
                return Err(Error::Other(format!(
                    "git checkout 失败: {}",
                    String::from_utf8_lossy(&output.stderr)
                )));
            }
        } else if path.exists() {
            if path.is_dir() {
                std::fs::remove_dir_all(path)?;
            } else {
                std::fs::remove_file(path)?;
            }
        }
    }
    Ok(())
}

/// 创建租约快照。
pub fn create_snapshot(repo_root: &Path, lease_id: &str) -> Result<LeaseSnapshot> {
    let commit_hash = git_head_commit(repo_root)?;
    let branch = git_current_branch(repo_root)?;
    Ok(LeaseSnapshot {
        lease_id: lease_id.to_string(),
        commit_hash,
        branch,
        created_at: crate::store::now(),
        changed_files: Vec::new(),
    })
}

/// 完成租约快照（记录变更文件）。
pub fn finalize_snapshot(repo_root: &Path, snapshot: &mut LeaseSnapshot) -> Result<()> {
    // 获取自快照创建以来的变更文件
    let changed = git_changed_files_since(repo_root, &snapshot.commit_hash)?;
    // 也包含工作区未提交的变更
    let working_changes = git_working_dir_changes(repo_root)?;
    let mut all_changed: Vec<String> = changed.into_iter().chain(working_changes).collect();
    all_changed.sort();
    all_changed.dedup();
    snapshot.changed_files = all_changed;
    Ok(())
}

/// 回滚租约：恢复该租约变更的文件到快照锚点。
pub fn rollback_lease(repo_root: &Path, snapshot: &LeaseSnapshot) -> Result<usize> {
    if snapshot.changed_files.is_empty() {
        return Ok(0);
    }
    git_restore_files_to_commit(repo_root, &snapshot.changed_files, &snapshot.commit_hash)?;
    Ok(snapshot.changed_files.len())
}

/// 快照存储路径。
pub fn snapshot_dir(domain_root: &Path) -> PathBuf {
    domain_root.join("snapshots")
}

/// 保存快照到磁盘。
pub fn save_snapshot(domain_root: &Path, snapshot: &LeaseSnapshot) -> Result<()> {
    let dir = snapshot_dir(domain_root);
    save_snapshot_to(&dir, snapshot)
}

/// 保存快照到指定目录。
pub fn save_snapshot_to(dir: &Path, snapshot: &LeaseSnapshot) -> Result<()> {
    if !safe_lease_id(&snapshot.lease_id) {
        return Err(Error::Other(format!(
            "非法 lease_id: {:?}",
            snapshot.lease_id
        )));
    }
    std::fs::create_dir_all(dir)?;
    let path = dir.join(format!("{}.json", snapshot.lease_id));
    let json = serde_json::to_string_pretty(snapshot)?;
    std::fs::write(path, json)?;
    Ok(())
}

/// 从磁盘加载快照。
pub fn load_snapshot(domain_root: &Path, lease_id: &str) -> Result<Option<LeaseSnapshot>> {
    let path = snapshot_dir(domain_root).join(format!("{}.json", lease_id));
    load_snapshot_from(path.parent().unwrap_or(Path::new(".")), lease_id)
}

/// 从指定目录加载快照。
pub fn load_snapshot_from(dir: &Path, lease_id: &str) -> Result<Option<LeaseSnapshot>> {
    if !safe_lease_id(lease_id) {
        return Err(Error::Other(format!("非法 lease_id: {lease_id:?}")));
    }
    let path = dir.join(format!("{}.json", lease_id));
    if !path.exists() {
        return Ok(None);
    }
    let json = std::fs::read_to_string(path)?;
    let snapshot: LeaseSnapshot = serde_json::from_str(&json)?;
    Ok(Some(snapshot))
}

/// 列出所有快照。
pub fn list_snapshots(domain_root: &Path) -> Result<Vec<LeaseSnapshot>> {
    let dir = snapshot_dir(domain_root);
    list_snapshots_from(&dir)
}

/// 从指定目录列出所有快照。
pub fn list_snapshots_from(dir: &Path) -> Result<Vec<LeaseSnapshot>> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut snapshots = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("json") {
            if let Ok(json) = std::fs::read_to_string(&path) {
                if let Ok(snap) = serde_json::from_str::<LeaseSnapshot>(&json) {
                    snapshots.push(snap);
                }
            }
        }
    }
    Ok(snapshots)
}

/// 删除快照。
pub fn delete_snapshot(domain_root: &Path, lease_id: &str) -> Result<()> {
    if !safe_lease_id(lease_id) {
        return Err(Error::Other(format!("非法 lease_id: {lease_id:?}")));
    }
    let direct = domain_root.join(format!("{}.json", lease_id));
    let dir = if direct.exists()
        || domain_root.file_name().and_then(|n| n.to_str()) == Some("snapshots")
    {
        domain_root.to_path_buf()
    } else {
        snapshot_dir(domain_root)
    };
    let path = dir.join(format!("{}.json", lease_id));
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn snapshot_serialization() {
        let snap = LeaseSnapshot {
            lease_id: "test-lease".into(),
            commit_hash: "abc123".into(),
            branch: "main".into(),
            created_at: 1234567890,
            changed_files: vec!["src/a.rs".into(), "src/b.rs".into()],
        };
        let json = serde_json::to_string(&snap).unwrap();
        let loaded: LeaseSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.lease_id, "test-lease");
        assert_eq!(loaded.changed_files.len(), 2);
    }

    #[test]
    fn save_and_load_snapshot() {
        let tmp = std::env::temp_dir().join("airlock_test_snapshots");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();

        let snap = LeaseSnapshot {
            lease_id: "test-lease-123".into(),
            commit_hash: "def456".into(),
            branch: "main".into(),
            created_at: 1234567890,
            changed_files: vec!["file.rs".into()],
        };

        save_snapshot(&tmp, &snap).unwrap();
        let loaded = load_snapshot(&tmp, "test-lease-123").unwrap().unwrap();
        assert_eq!(loaded.commit_hash, "def456");

        let list = list_snapshots(&tmp).unwrap();
        assert_eq!(list.len(), 1);

        delete_snapshot(&tmp, "test-lease-123").unwrap();
        let loaded = load_snapshot(&tmp, "test-lease-123").unwrap();
        assert!(loaded.is_none());

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn rollback_rejects_path_traversal() {
        // 回滚文件列表来自可被任意进程写入的快照 JSON：`..` 构造不得
        // 删除仓库外文件（审查 P1：starts_with 不归一化 `..`）
        let repo = std::env::temp_dir().join(format!("airlock-snap-repo-{}", uuid::Uuid::new_v4()));
        let outside =
            std::env::temp_dir().join(format!("airlock-snap-out-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&repo).unwrap();
        fs::write(&outside, b"victim").unwrap();

        // 文件不存在于 commit → 走文件删除分支；遍历路径必须被拒绝
        git_restore_files_to_commit(
            &repo,
            &[
                format!("../{}", outside.file_name().unwrap().to_string_lossy()),
                "../../etc/passwd".into(),
                "/etc/passwd".into(),
            ],
            "deadbeef",
        )
        .unwrap();
        assert!(outside.exists(), "仓库外文件不得被删除");

        // lease_id 用作文件名：路径分隔符与 `..` 一律拒绝
        let dir = std::env::temp_dir().join(format!("airlock-snap-dir-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        assert!(load_snapshot_from(&dir, "../../x").is_err());
        assert!(load_snapshot_from(&dir, "a/b").is_err());
        assert!(load_snapshot_from(&dir, "").is_err());
        // 合法 id 不受影响
        assert!(
            load_snapshot_from(&dir, "550e8400-e29b-41d4-a716-446655440000")
                .unwrap()
                .is_none()
        );

        fs::remove_dir_all(&repo).ok();
        fs::remove_file(&outside).ok();
        fs::remove_dir_all(&dir).ok();
    }
}
