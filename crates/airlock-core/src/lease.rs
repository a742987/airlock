//! F1 租约引擎：claim / release / heartbeat / 自动过期 + F11 黑板联动。

use std::path::Path;

use crate::config::Config;
use crate::error::{Error, Result};
use crate::glob;
use crate::messages;
use crate::proto::{Actor, AuditEntry, ClaimOk, Holder, LeaseInfo, Rejection};
use crate::store::{now, Store, LEASE_ACTIVE, LEASE_EXPIRED, LEASE_RELEASED};

/// 默认心跳周期（秒）——文档 FR1.1：心跳续约默认 60s。
pub const DEFAULT_HEARTBEAT_S: i64 = 60;
/// 默认 TTL（秒）——FR1.1：默认 30min。
pub const DEFAULT_TTL_S: i64 = 1800;
/// TTL 上限（协议入参钳制，防整数溢出/永久租约）：一周。
pub const MAX_TTL_S: i64 = 7 * 24 * 3600;
/// 心跳周期上限（钳制）：1 小时。
pub const MAX_HEARTBEAT_S: i64 = 3600;

pub struct ClaimParams {
    pub conflict_domain: String,
    pub agent_id: String,
    pub session_id: String,
    pub glob: String,
    pub intent: Option<String>,
    pub ttl_s: Option<i64>,
    pub heartbeat_s: i64,
    pub layer: String,
    pub actor: Actor,
    /// 仓库根（用于枚举无冲突备选路径）；None 时不枚举
    pub root: Option<std::path::PathBuf>,
}

/// 申请租约（FR1.1/FR1.2）。冲突 → Error::Conflict（409 型载荷）。
///
/// 原子性：冲突检查与 insert 在同一 `BEGIN IMMEDIATE` 事务内完成（多进程
/// 直开数据库也不会双授予）；冲突路径的 deny 审计随事务一并提交。
pub fn claim(store: &Store, cfg: &Config, p: &ClaimParams) -> Result<ClaimOk> {
    glob::validate_pattern(&p.glob).map_err(Error::Config)?;
    let now_ts = now();
    // 协议入参钳制：ttl ∈ [2, MAX_TTL_S]、heartbeat ∈ [1, MAX_HEARTBEAT_S]，
    // 防止溢出把 expires_at 回绕成负值（租约将永不参与冲突检测——静默零保护）
    let raw_ttl = p.ttl_s.unwrap_or(cfg.default_ttl_s).clamp(2, MAX_TTL_S);
    let heartbeat_s = if p.heartbeat_s > 0 {
        p.heartbeat_s
    } else {
        cfg.heartbeat_s
    }
    .clamp(1, MAX_HEARTBEAT_S);
    // TTL 下限 = 2 个心跳周期（FR1.3：心跳停止 2 个周期后过期）
    let ttl = raw_ttl.max(2 * heartbeat_s).min(MAX_TTL_S);

    store.begin_immediate()?;
    let result = claim_locked(store, p, now_ts, ttl);
    match result {
        // 冲突路径的 deny 审计已写入，随事务提交保留
        Ok(_) | Err(Error::Conflict(_)) => {
            store.commit()?;
            result
        }
        Err(e) => {
            let _ = store.rollback();
            Err(e)
        }
    }
}

fn claim_locked(store: &Store, p: &ClaimParams, now_ts: i64, ttl: i64) -> Result<ClaimOk> {
    store.audit("claim", &p.actor, &p.glob, None, &p.layer, None)?;

    // 同会话对重叠路径的重复 claim → 幂等返回既有租约（不误伤自己的 deny_count）
    let actives = store.active_leases(Some(&p.conflict_domain), now_ts)?;
    if let Some(existing) = actives
        .iter()
        .find(|l| l.session_id == p.session_id && glob::overlaps(&p.glob, &l.glob))
    {
        return Ok(ClaimOk {
            lease: existing.clone(),
            prediction: crate::proto::Prediction {
                risk: "none".into(),
                with_leases: vec![],
                involved_symbols: vec![],
            },
        });
    }

    // 冲突检测：与同冲突域内任一 active 租约的 glob 重叠
    if let Some(other) = actives.iter().find(|l| glob::overlaps(&p.glob, &l.glob)) {
        let ttl_remaining = (other.expires_at - now_ts).max(0);
        let deny_count = store.bump_deny_count(&p.session_id, &p.glob)?;
        let action = if deny_count >= 3 {
            messages::suggested_action::ESCALATE_SWITCH_TASK
        } else {
            messages::suggested_action::CLAIM_FREE_ALTERNATIVE_OR_WAIT
        };
        let rejection = build_rejection(
            store,
            &p.glob,
            other,
            ttl_remaining,
            action,
            deny_count,
            p.root.as_deref(),
        );
        store.audit(
            "deny",
            &p.actor,
            &p.glob,
            Some(&other.id),
            &p.layer,
            Some(&serde_json::json!({
                "holder": rejection.holder,
                "ttl_remaining_s": ttl_remaining,
                "deny_count": deny_count,
            })),
        )?;
        return Err(Error::Conflict(Box::new(rejection)));
    }

    let expires_at = now_ts
        .checked_add(ttl)
        .ok_or_else(|| Error::Config(format!("TTL 越界（expires_at 溢出）：ttl={ttl}")))?;
    let lease = LeaseInfo {
        id: uuid::Uuid::new_v4().to_string(),
        conflict_domain: p.conflict_domain.clone(),
        agent_id: p.agent_id.clone(),
        session_id: p.session_id.clone(),
        glob: p.glob.clone(),
        intent: p.intent.clone(),
        state: LEASE_ACTIVE.into(),
        issued_at: now_ts,
        ttl_s: ttl,
        last_heartbeat: now_ts,
        expires_at,
        enforcement_layer: p.layer.clone(),
        tokens_used: 0,
        cost_cents: 0,
    };
    store.insert_lease(&lease)?;

    // FR5.1：intent 写入黑板并与租约绑定
    if let Some(intent) = &p.intent {
        store.insert_board_entry(&crate::proto::BoardEntry {
            id: uuid::Uuid::new_v4().to_string(),
            lease_id: Some(lease.id.clone()),
            origin: "agent".into(),
            body: intent.clone(),
            status: "active".into(),
            created_at: now_ts,
            archived_at: None,
        })?;
    }

    store.audit("grant", &p.actor, &p.glob, Some(&lease.id), &p.layer, None)?;

    // F5：符号级冲突预测（当有 repo root 时启用 tree-sitter 分析）
    let prediction = match p.root.as_deref() {
        Some(root_path) => {
            let overlapping_files = find_overlapping_files(&actives, &p.glob, root_path);
            let reader = |path: &std::path::Path| -> Option<String> {
                let full = root_path.join(path);
                std::fs::read_to_string(full).ok()
            };
            // F7：创建租约快照（保存在 repo root 的 .airlock/snapshots 下）
            if let Ok(snap) = crate::snapshot::create_snapshot(root_path, &lease.id) {
                let snap_dir = root_path.join(".airlock").join("snapshots");
                let _ = std::fs::create_dir_all(&snap_dir);
                let _ = crate::snapshot::save_snapshot_to(&snap_dir, &snap);
            }
            crate::predict::predict(&actives, &p.glob, &overlapping_files, Some(reader))
        }
        None => crate::predict::predict_simple(&actives, &p.glob),
    };
    Ok(ClaimOk { lease, prediction })
}

fn build_rejection(
    store: &Store,
    path: &str,
    other: &LeaseInfo,
    ttl_remaining: i64,
    action: &str,
    deny_count: u32,
    root: Option<&Path>,
) -> Rejection {
    let holder = Holder {
        agent: other.agent_id.clone(),
        session: short_session(&other.session_id),
        layer: other.enforcement_layer.clone(),
    };
    let human =
        messages::rejection_human(path, &holder.agent, &holder.session, ttl_remaining, action);
    let free_alternatives = match root {
        Some(r) => {
            free_alternatives(store, r, other.conflict_domain.as_str(), path).unwrap_or_default()
        }
        None => Vec::new(),
    };
    Rejection {
        error: "conflict".into(),
        path: path.to_string(),
        holder: Some(holder),
        ttl_remaining_s: ttl_remaining,
        free_alternatives,
        suggested_action: action.to_string(),
        degraded: false,
        human,
        deny_count,
    }
}

fn short_session(session_id: &str) -> String {
    session_id.chars().take(4).collect()
}

/// 无冲突备选路径（§6.2 free_alternatives）：枚举仓库根一级目录，
/// 返回与所有 active 租约及待申请路径都不重叠的目录 glob（至多 5 条）。
pub fn free_alternatives(
    store: &Store,
    root: &Path,
    domain: &str,
    want: &str,
) -> Result<Vec<String>> {
    let now_ts = now();
    let actives = store.active_leases(Some(domain), now_ts)?;
    let mut out = Vec::new();
    let Ok(read_dir) = std::fs::read_dir(root) else {
        return Ok(out);
    };
    let mut dirs: Vec<String> = read_dir
        .flatten()
        .filter(|e| e.path().is_dir())
        .filter(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            !name.starts_with('.') && name != "node_modules" && name != "target" && name != "dist"
        })
        .map(|e| format!("{}/**", e.file_name().to_string_lossy()))
        .collect();
    dirs.sort();
    for cand in dirs {
        if cand == want || glob::overlaps(&cand, want) {
            continue;
        }
        if actives.iter().any(|l| glob::overlaps(&cand, &l.glob)) {
            continue;
        }
        out.push(cand);
        if out.len() >= 5 {
            break;
        }
    }
    Ok(out)
}

/// 主动释放（FR1.4）。返回是否确有租约被释放。
///
/// 属主校验：`expected_session` 为 Some 时必须与租约 session 一致，
/// 否则返回 409 型拒绝（error=forbidden）——任何拿到 lease_id 的第三方
/// 不能释放他人的租约（P1）。
pub fn release(
    store: &Store,
    lease_id: &str,
    actor: &Actor,
    layer: &str,
    expected_session: Option<&str>,
    root: Option<&Path>,
) -> Result<bool> {
    let Some(lease) = store.get_lease(lease_id)? else {
        return Ok(false);
    };
    if lease.state != LEASE_ACTIVE {
        return Ok(false);
    }
    check_ownership(&lease, expected_session)?;

    // F7：完成快照（记录变更文件）
    if let Some(root_path) = root {
        let snap_dir = root_path.join(".airlock").join("snapshots");
        if let Ok(Some(mut snap)) = crate::snapshot::load_snapshot_from(&snap_dir, lease_id) {
            let _ = crate::snapshot::finalize_snapshot(root_path, &mut snap);
            let _ = crate::snapshot::save_snapshot_to(&snap_dir, &snap);
        }
    }

    store.update_lease_state(lease_id, LEASE_RELEASED)?;
    store.archive_board_by_lease(lease_id)?;
    store.audit(
        "release",
        actor,
        &lease.glob,
        Some(lease_id),
        layer,
        Some(&serde_json::json!({ "session": lease.session_id })),
    )?;
    Ok(true)
}

/// 心跳续约（FR1.1）。返回 false = 租约不存在或已失效。
/// 属主校验同 [`release`]。
pub fn heartbeat(
    store: &Store,
    lease_id: &str,
    actor: &Actor,
    layer: &str,
    expected_session: Option<&str>,
) -> Result<bool> {
    let Some(lease) = store.get_lease(lease_id)? else {
        return Ok(false);
    };
    if lease.state != LEASE_ACTIVE || lease.expires_at <= now() {
        return Ok(false);
    }
    check_ownership(&lease, expected_session)?;
    let now_ts = now();
    store.update_lease_heartbeat(lease_id, now_ts, now_ts + lease.ttl_s)?;
    store.audit("heartbeat", actor, &lease.glob, Some(lease_id), layer, None)?;
    Ok(true)
}

/// 属主校验：期望会话与租约不一致 → 409 型 forbidden 拒绝（fail-closed）。
fn check_ownership(lease: &LeaseInfo, expected_session: Option<&str>) -> Result<()> {
    let Some(want) = expected_session else {
        return Ok(());
    };
    if want != lease.session_id {
        return Err(Error::Conflict(Box::new(Rejection {
            error: "forbidden".into(),
            path: lease.glob.clone(),
            holder: Some(Holder {
                agent: lease.agent_id.clone(),
                session: short_session(&lease.session_id),
                layer: lease.enforcement_layer.clone(),
            }),
            ttl_remaining_s: (lease.expires_at - now()).max(0),
            free_alternatives: vec![],
            suggested_action: messages::suggested_action::LEASE_NOT_OWNED_BY_SESSION.into(),
            degraded: false,
            human: format!(
                "✗ 操作被拒绝：租约 {}（{}）属于会话 {}，不属于会话 {}。",
                short_session(&lease.id),
                lease.glob,
                short_session(&lease.session_id),
                short_session(want)
            ),
            deny_count: 0,
        })));
    }
    Ok(())
}

/// 过期清扫（FR1.3）：心跳停止 2 个周期（expires_at = last_heartbeat + ttl，TTL ≥ 2 周期）后
/// 自动过期释放；黑板条目归档；daemon 依据审计日志生成不可抵赖的黑板摘要（FR5.4）。
pub fn sweep(store: &Store, layer: &str, root: Option<&Path>) -> Result<Vec<LeaseInfo>> {
    let now_ts = now();
    let to_expire = store.leases_to_expire(now_ts)?;
    let mut expired = Vec::new();
    for lease in to_expire {
        // F7：完成快照（记录变更文件）- 在状态变更前
        if let Some(root_path) = root {
            let snap_dir = root_path.join(".airlock").join("snapshots");
            if let Ok(Some(mut snap)) = crate::snapshot::load_snapshot_from(&snap_dir, &lease.id) {
                let _ = crate::snapshot::finalize_snapshot(root_path, &mut snap);
                let _ = crate::snapshot::save_snapshot_to(&snap_dir, &snap);
            }
        }

        store.update_lease_state(&lease.id, LEASE_EXPIRED)?;
        store.archive_board_by_lease(&lease.id)?;
        store.audit(
            "expire",
            &Actor {
                agent: lease.agent_id.clone(),
                session: lease.session_id.clone(),
                pid_tree: vec![],
            },
            &lease.glob,
            Some(&lease.id),
            layer,
            None,
        )?;
        // FR5.4：daemon 依据审计日志生成的黑板条目（来源标注 daemon，不可抵赖）
        if let Some(intent) = &lease.intent {
            store.insert_board_entry(&crate::proto::BoardEntry {
                id: uuid::Uuid::new_v4().to_string(),
                lease_id: Some(lease.id.clone()),
                origin: "daemon".into(),
                body: format!(
                    "租约 {}（{}）已于 {} 过期。声明的意图：{intent}。涉及路径：{}。",
                    short_session(&lease.session_id),
                    lease.agent_id,
                    ts_display(lease.expires_at),
                    lease.glob
                ),
                status: "archived".into(),
                created_at: now_ts,
                archived_at: Some(now_ts),
            })?;
        }
        expired.push(lease);
    }
    Ok(expired)
}

fn ts_display(ts: i64) -> String {
    format!("<ts:{ts}>")
}

/// 守护进程周期任务：过期清扫 + 黑板 7 天归档保留 + 已结束会话资源清理。
pub fn sweep_all(
    store: &Store,
    layer: &str,
    session_root: &Path,
    root: Option<&Path>,
) -> Result<Vec<LeaseInfo>> {
    let expired = sweep(store, layer, root)?;
    store.board_purge(7)?;
    // AC3.3：会话结束 60s 内销毁临时资源
    let cutoff = now() - 60;
    for sid in store.session_artifacts_to_clean(cutoff)? {
        let dir = session_root.join(&sid);
        if dir.exists() {
            let removed = std::fs::remove_dir_all(&dir);
            store.audit(
                if removed.is_ok() { "expire" } else { "degrade" },
                &Actor::default(),
                &dir.to_string_lossy(),
                None,
                layer,
                Some(&serde_json::json!({
                    "session_cleanup": sid,
                    "removed": removed.is_ok(),
                    "error": removed.as_ref().err().map(|e| e.to_string()),
                })),
            )?;
        }
        store.delete_session_row(&sid)?;
    }
    Ok(expired)
}

/// 把「已释放/已过期」状态映射为可读（tower 灰显用）。
pub fn state_is_graceful(state: &str) -> bool {
    matches!(state, LEASE_RELEASED | LEASE_EXPIRED)
}

/// 审计日志最近事件（tower 用）。
pub fn recent_events(store: &Store, limit: usize) -> Result<Vec<AuditEntry>> {
    let all = store.audit_query(None, limit as i64)?;
    Ok(all)
}

/// L1 advisory 的 release_all。
pub fn release_all(
    store: &Store,
    session_id: &str,
    actor: &Actor,
    layer: &str,
    root: Option<&Path>,
) -> Result<usize> {
    let now_ts = now();
    let actives = store.active_leases(None, now_ts)?;
    let mut n = 0;
    for l in actives.iter().filter(|l| l.session_id == session_id) {
        // release_all 本身按 session 过滤，无需二次属主校验
        if release(store, &l.id, actor, layer, None, root)? {
            n += 1;
        }
    }
    Ok(n)
}

/// F5：找出在多个 active 租约重叠区域内的文件（用于符号级冲突预测）。
fn find_overlapping_files(
    actives: &[crate::proto::LeaseInfo],
    want: &str,
    root: &std::path::Path,
) -> Vec<String> {
    let mut result = Vec::new();
    // 遍历仓库文件，找出同时匹配 want 和至少一个 active 租约的文件
    let walker = walkdir_simple(root, 4); // 限制深度避免性能问题
    for entry in walker {
        let rel = match entry.strip_prefix(root) {
            Ok(r) => r.to_string_lossy().to_string(),
            Err(_) => continue,
        };
        if crate::glob::matches(want, &rel) {
            // 检查是否也在某个 active 租约范围内
            for active in actives {
                if crate::glob::matches(&active.glob, &rel) {
                    result.push(rel);
                    break;
                }
            }
        }
    }
    result
}

/// 简单的目录遍历（不跟随符号链接，限制深度）。
fn walkdir_simple(root: &std::path::Path, max_depth: usize) -> Vec<std::path::PathBuf> {
    let mut result = Vec::new();
    let mut stack = vec![(root.to_path_buf(), 0usize)];
    while let Some((dir, depth)) = stack.pop() {
        if depth > max_depth {
            continue;
        }
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                // 跳过隐藏目录和常见大目录
                let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if name.starts_with('.') || name == "node_modules" || name == "target" {
                    continue;
                }
                stack.push((path, depth + 1));
            } else {
                result.push(path);
            }
        }
    }
    result
}
