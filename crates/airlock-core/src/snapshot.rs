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
        .map_err(|e| Error::Io(e))?;
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
        .map_err(|e| Error::Io(e))?;
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
        .map_err(|e| Error::Io(e))?;
    if !output.status.success() {
        // 如果 HEAD 不存在（例如没有新提交），尝试对比工作区
        let output = Command::new("git")
            .args(["diff", "--name-only", since_commit])
            .current_dir(repo_root)
            .output()
            .map_err(|e| Error::Io(e))?;
        if !output.status.success() {
            return Err(Error::Other(format!(
                "git diff 失败: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }
    }
    let files: Vec<String> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|l| !l.is_empty())
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
        .map_err(|e| Error::Io(e))?;
    if !output.status.success() {
        return Err(Error::Other(format!(
            "git status 失败: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    let files: Vec<String> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            // porcelain 格式: XY filename
            let parts: Vec<&str> = line.splitn(2, ' ').collect();
            if parts.len() == 2 {
                Some(parts[1].trim().to_string())
            } else {
                None
            }
        })
        .collect();
    Ok(files)
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
    // 使用 git checkout 恢复文件到指定 commit 的状态
    let mut cmd = Command::new("git");
    cmd.args(["checkout", commit_hash, "--"]);
    for f in files {
        cmd.arg(f);
    }
    let output = cmd.current_dir(repo_root).output().map_err(|e| Error::Io(e))?;
    if !output.status.success() {
        return Err(Error::Other(format!(
            "git checkout 失败: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
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
pub fn finalize_snapshot(
    repo_root: &Path,
    snapshot: &mut LeaseSnapshot,
) -> Result<()> {
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
    std::fs::create_dir_all(dir)?;
    let path = dir.join(format!("{}.json", snapshot.lease_id));
    let json = serde_json::to_string_pretty(snapshot)?;
    std::fs::write(path, json)?;
    Ok(())
}

/// 从磁盘加载快照。
pub fn load_snapshot(domain_root: &Path, lease_id: &str) -> Result<Option<LeaseSnapshot>> {
    let path = snapshot_dir(domain_root).join(format!("{}.json", lease_id));
    load_snapshot_from(&path.parent().unwrap_or(Path::new(".")), lease_id)
}

/// 从指定目录加载快照。
pub fn load_snapshot_from(dir: &Path, lease_id: &str) -> Result<Option<LeaseSnapshot>> {
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
    let path = snapshot_dir(domain_root).join(format!("{}.json", lease_id));
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
}
