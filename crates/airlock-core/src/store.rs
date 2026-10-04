//! SQLite 存储层（§7 数据设计）：leases / audit_log(hash-chained) / board_entries /
//! sessions / ports / misc_locks / deny_counts / meta。WAL 模式；损坏时宁可不可用（§8.4）。

use std::path::Path;
use std::time::{Duration, SystemTime};

use rusqlite::{params, Connection, OptionalExtension, Row};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::proto::{Actor, AuditEntry, BoardEntry, LeaseInfo, PortInfo, SessionInfo};

pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs() as i64
}

pub fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis() as i64
}

pub struct Store {
    conn: Connection,
    /// 审计链尾部锚点文件（`<dir>/airlock.head`）；内存库为 None。
    /// 每次追加审计后写入最后一条 hash——即使整条链被删除重建，
    /// 与锚点比对也能发现尾部截断（AC1.4 补强）。
    anchor_path: Option<std::path::PathBuf>,
}

pub const LEASE_ACTIVE: &str = "active";
pub const LEASE_EXPIRED: &str = "expired";
pub const LEASE_RELEASED: &str = "released";
pub const LEASE_REVOKED: &str = "revoked";

/// 审计事件词表（v1.0 冻结，新增走 RFC）。
pub const AUDIT_EVENTS: &[&str] = &[
    "claim",
    "grant",
    "deny",
    "heartbeat",
    "expire",
    "release",
    "enforce_deny",
    "enforce_expire",
    "degrade",
    "rollback",
];

impl Store {
    /// 打开（不存在则建表）。SQLite 损坏 → Integrity（daemon 拒绝启动，§8.4）。
    pub fn open(path: &Path) -> Result<Store> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| Error::Integrity(format!("WAL 设置失败：{e}（疑似数据库损坏）")))?;
        conn.pragma_update(None, "synchronous", "NORMAL").ok();
        conn.pragma_update(None, "busy_timeout", 5000).ok();
        let anchor_path = Some(path.with_file_name("airlock.head"));
        Self::init_schema(conn, anchor_path)
    }

    /// 内存库（测试用）。
    pub fn open_in_memory() -> Result<Store> {
        let conn = Connection::open_in_memory()?;
        Self::init_schema(conn, None)
    }

    fn init_schema(conn: Connection, anchor_path: Option<std::path::PathBuf>) -> Result<Store> {
        // 快速完整性预检：损坏的库在第一条语句即暴露
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS leases (
                id TEXT PRIMARY KEY,
                conflict_domain TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                glob TEXT NOT NULL,
                intent TEXT,
                state TEXT NOT NULL DEFAULT 'active',
                issued_at INTEGER NOT NULL,
                ttl_s INTEGER NOT NULL,
                last_heartbeat INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                enforcement_layer TEXT NOT NULL DEFAULT 'L1',
                tokens_used INTEGER NOT NULL DEFAULT 0,
                cost_cents INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_leases_state ON leases(state);
            CREATE INDEX IF NOT EXISTS idx_leases_domain ON leases(conflict_domain);
            CREATE TABLE IF NOT EXISTS audit_log (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                prev_hash TEXT NOT NULL,
                hash TEXT NOT NULL,
                ts INTEGER NOT NULL,
                event TEXT NOT NULL,
                actor TEXT NOT NULL,
                path TEXT NOT NULL DEFAULT '',
                lease_id TEXT,
                layer TEXT NOT NULL DEFAULT 'L1',
                detail TEXT
            );
            CREATE TABLE IF NOT EXISTS board_entries (
                id TEXT PRIMARY KEY,
                lease_id TEXT,
                origin TEXT NOT NULL DEFAULT 'agent',
                body TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                created_at INTEGER NOT NULL,
                archived_at INTEGER
            );
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                agent_id TEXT NOT NULL,
                seq INTEGER NOT NULL,
                port_base INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                ended_at INTEGER
            );
            CREATE TABLE IF NOT EXISTS ports (
                session_id TEXT NOT NULL,
                port INTEGER NOT NULL,
                purpose TEXT NOT NULL,
                state TEXT NOT NULL DEFAULT 'active',
                cooldown_until INTEGER,
                PRIMARY KEY (session_id, port)
            );
            CREATE TABLE IF NOT EXISTS misc_locks (
                name TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                acquired_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS deny_counts (
                session_id TEXT NOT NULL,
                path TEXT NOT NULL,
                count INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (session_id, path)
            );
            "#,
        )?;
        Ok(Store { conn, anchor_path })
    }

    // ---------- 事务（P2：claim 的「检查 → 插入」需要原子性） ----------
    //
    // 调用方（daemon）以全局 Mutex 串行化访问；这里提供显式事务以便
    // 多进程直开数据库时也不会出现双授予。仅支持单层事务（当前无嵌套场景）。

    pub fn begin_immediate(&self) -> Result<()> {
        self.conn.execute_batch("BEGIN IMMEDIATE")?;
        Ok(())
    }

    pub fn commit(&self) -> Result<()> {
        self.conn.execute_batch("COMMIT")?;
        Ok(())
    }

    pub fn rollback(&self) -> Result<()> {
        self.conn.execute_batch("ROLLBACK")?;
        Ok(())
    }

    /// 用 SQLite backup API 产生一致快照到 `dst`（branch_sqlite 用，替代逐文件复制）。
    pub fn backup_to(&self, dst: &Path) -> Result<()> {
        use rusqlite::backup::Backup;
        let mut dst_conn = Connection::open(dst)?;
        Backup::new(&self.conn, &mut dst_conn)?.run_to_completion(
            64,
            Duration::from_millis(5),
            None,
        )?;
        Ok(())
    }

    // ---------- meta ----------

    pub fn meta_get(&self, key: &str) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row("SELECT value FROM meta WHERE key = ?1", params![key], |r| {
                r.get::<_, String>(0)
            })
            .optional()?)
    }

    pub fn meta_set(&self, key: &str, value: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO meta(key, value) VALUES(?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = ?2",
            params![key, value],
        )?;
        Ok(())
    }

    // ---------- 审计日志（append-only，hash-chained） ----------

    /// 写入一条审计事件：hash = sha256(seq ‖ prev_hash ‖ ts ‖ event ‖ actor ‖ path ‖ lease_id ‖ layer ‖ detail)。
    pub fn audit(
        &self,
        event: &str,
        actor: &Actor,
        path: &str,
        lease_id: Option<&str>,
        layer: &str,
        detail: Option<&serde_json::Value>,
    ) -> Result<AuditEntry> {
        if !AUDIT_EVENTS.contains(&event) {
            return Err(Error::Other(format!(
                "未知的审计事件 `{event}`；词表 v1.0 冻结：{AUDIT_EVENTS:?}"
            )));
        }
        let ts = now();
        let prev_hash: String = self
            .conn
            .query_row(
                "SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .optional()?
            .unwrap_or_else(|| "0".repeat(64));
        let actor_json = serde_json::to_string(actor)?;
        let detail_json = detail.map(|d| d.to_string()).unwrap_or_default();
        let lease_field = lease_id.unwrap_or("");
        // seq 由 AUTOINCREMENT 决定；先以 next seq 参与哈希再回填，保证链可复算
        let next_seq: i64 =
            self.conn
                .query_row("SELECT COALESCE(MAX(seq), 0) + 1 FROM audit_log", [], |r| {
                    r.get(0)
                })?;
        let hash = audit_hash(
            next_seq,
            &prev_hash,
            ts,
            event,
            &actor_json,
            path,
            lease_field,
            layer,
            &detail_json,
        );
        self.conn.execute(
            "INSERT INTO audit_log(seq, prev_hash, hash, ts, event, actor, path, lease_id, layer, detail)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                next_seq,
                prev_hash,
                hash,
                ts,
                event,
                actor_json,
                path,
                lease_id,
                layer,
                if detail_json.is_empty() {
                    None
                } else {
                    Some(detail_json)
                }
            ],
        )?;
        // 尾部锚点：写盘失败仅降级（链校验仍覆盖中间篡改）
        if let Some(anchor) = &self.anchor_path {
            let _ = std::fs::write(anchor, &hash);
        }
        Ok(AuditEntry {
            seq: next_seq,
            prev_hash,
            hash,
            ts,
            event: event.to_string(),
            actor: actor.clone(),
            path: path.to_string(),
            lease_id: lease_id.map(|s| s.to_string()),
            layer: layer.to_string(),
            detail: detail.cloned(),
        })
    }

    pub fn audit_query(&self, since_ts: Option<i64>, limit: i64) -> Result<Vec<AuditEntry>> {
        let mut sql = "SELECT seq, prev_hash, hash, ts, event, actor, path, lease_id, layer, detail FROM audit_log".to_string();
        if since_ts.is_some() {
            sql.push_str(" WHERE ts >= ?1");
        }
        sql.push_str(" ORDER BY seq ASC LIMIT ");
        sql.push_str(&limit.to_string());
        let mut stmt = self.conn.prepare(&sql)?;
        let map = |r: &Row| -> rusqlite::Result<AuditEntry> {
            let actor_json: String = r.get(5)?;
            Ok(AuditEntry {
                seq: r.get(0)?,
                prev_hash: r.get(1)?,
                hash: r.get(2)?,
                ts: r.get(3)?,
                event: r.get(4)?,
                actor: serde_json::from_str(&actor_json).unwrap_or_default(),
                path: r.get::<_, Option<String>>(6)?.unwrap_or_default(),
                lease_id: r.get(7)?,
                layer: r.get(8)?,
                detail: r
                    .get::<_, Option<String>>(9)?
                    .and_then(|d| serde_json::from_str(&d).ok()),
            })
        };
        let rows = if let Some(since) = since_ts {
            stmt.query_map(params![since], map)?
                .collect::<rusqlite::Result<Vec<_>>>()?
        } else {
            stmt.query_map([], map)?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        Ok(rows)
    }

    /// 校验 hash 链完整性，返回断链位置（seq 列表）。空 = 完整（AC1.4）。
    /// `-1` 表示尾部锚点不匹配——链自洽但末尾记录可能被整体删除重建（防截断）。
    pub fn audit_verify(&self) -> Result<Vec<i64>> {
        let mut stmt = self.conn.prepare(
            "SELECT seq, prev_hash, hash, ts, event, actor, path, lease_id, layer, detail
             FROM audit_log ORDER BY seq ASC",
        )?;
        type AuditRow = (
            i64,
            String,
            String,
            i64,
            String,
            String,
            String,
            Option<String>,
            String,
            Option<String>,
        );
        let rows: Vec<AuditRow> = stmt
            .query_map([], |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                    r.get(8)?,
                    r.get(9)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut broken = Vec::new();
        let mut expect_prev = "0".repeat(64);
        let row_count = rows.len();
        for (seq, prev_hash, hash, ts, event, actor_json, path, lease_id, layer, detail) in rows {
            let mut seq_broken = false;
            if prev_hash != expect_prev {
                seq_broken = true;
            }
            let recomputed = audit_hash(
                seq,
                &prev_hash,
                ts,
                &event,
                &actor_json,
                &path,
                lease_id.as_deref().unwrap_or(""),
                &layer,
                detail.as_deref().unwrap_or(""),
            );
            if recomputed != hash {
                seq_broken = true;
            }
            if seq_broken {
                broken.push(seq);
            }
            expect_prev = hash;
        }
        // 尾部锚点比对：链自洽但最后一行被删除重建时，只有锚点能发现
        if let Some(anchor) = &self.anchor_path {
            if let Ok(anchor_hash) = std::fs::read_to_string(anchor) {
                if row_count > 0 && anchor_hash.trim() != expect_prev {
                    broken.push(-1);
                }
            }
        }
        Ok(broken)
    }

    // ---------- 租约 ----------

    pub fn insert_lease(&self, l: &LeaseInfo) -> Result<()> {
        self.conn.execute(
            "INSERT INTO leases(id, conflict_domain, agent_id, session_id, glob, intent, state, issued_at, ttl_s, last_heartbeat, expires_at, enforcement_layer, tokens_used, cost_cents)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
            params![
                l.id,
                l.conflict_domain,
                l.agent_id,
                l.session_id,
                l.glob,
                l.intent,
                l.state,
                l.issued_at,
                l.ttl_s,
                l.last_heartbeat,
                l.expires_at,
                l.enforcement_layer,
                l.tokens_used,
                l.cost_cents
            ],
        )?;
        Ok(())
    }

    pub fn update_lease_state(&self, id: &str, state: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE leases SET state = ?2 WHERE id = ?1",
            params![id, state],
        )?;
        Ok(())
    }

    pub fn update_lease_heartbeat(
        &self,
        id: &str,
        last_heartbeat: i64,
        expires_at: i64,
    ) -> Result<()> {
        self.conn.execute(
            "UPDATE leases SET last_heartbeat = ?2, expires_at = ?3 WHERE id = ?1",
            params![id, last_heartbeat, expires_at],
        )?;
        Ok(())
    }

    /// F6：更新租约的 token 消耗和成本。使用饱和加法防止溢出。
    pub fn update_lease_cost(
        &self,
        id: &str,
        tokens_delta: u64,
        cost_cents_delta: u64,
    ) -> Result<()> {
        // 先读取当前值
        let current: (u64, u64) = self
            .conn
            .query_row(
                "SELECT tokens_used, cost_cents FROM leases WHERE id = ?1",
                params![id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?
            .unwrap_or((0, 0));

        // 饱和加法：防止溢出回绕
        let new_tokens = current.0.saturating_add(tokens_delta);
        let new_cost = current.1.saturating_add(cost_cents_delta);

        self.conn.execute(
            "UPDATE leases SET tokens_used = ?2, cost_cents = ?3 WHERE id = ?1",
            params![id, new_tokens, new_cost],
        )?;
        Ok(())
    }

    pub fn get_lease(&self, id: &str) -> Result<Option<LeaseInfo>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, conflict_domain, agent_id, session_id, glob, intent, state, issued_at, ttl_s, last_heartbeat, expires_at, enforcement_layer
             FROM leases WHERE id = ?1",
        )?;
        let v = lease_from_row_query(&mut stmt, params![id])?;
        Ok(v.into_iter().next())
    }

    /// 列出租约（domain 过滤可选；state 过滤可选；expired/release 的历史也可见）。
    pub fn list_leases(&self, domain: Option<&str>, active_only: bool) -> Result<Vec<LeaseInfo>> {
        let mut sql = "SELECT id, conflict_domain, agent_id, session_id, glob, intent, state, issued_at, ttl_s, last_heartbeat, expires_at, enforcement_layer, tokens_used, cost_cents FROM leases".to_string();
        let mut conds = Vec::new();
        if domain.is_some() {
            conds.push("conflict_domain = ?1".to_string());
        }
        if active_only {
            conds.push(format!("state = '{LEASE_ACTIVE}'"));
        }
        if !conds.is_empty() {
            sql.push_str(" WHERE ");
            sql.push_str(&conds.join(" AND "));
        }
        sql.push_str(" ORDER BY issued_at DESC");
        let mut stmt = self.conn.prepare(&sql)?;
        let v = match domain {
            Some(d) => lease_from_row_query(&mut stmt, params![d])?,
            None => lease_from_row_query(&mut stmt, params![])?,
        };
        Ok(v)
    }

    /// 所有 active 且未过期的租约（调用方负责先 sweep 或以 expires_at 过滤）。
    pub fn active_leases(&self, domain: Option<&str>, now_ts: i64) -> Result<Vec<LeaseInfo>> {
        let mut sql = "SELECT id, conflict_domain, agent_id, session_id, glob, intent, state, issued_at, ttl_s, last_heartbeat, expires_at, enforcement_layer, tokens_used, cost_cents
                       FROM leases WHERE state = 'active' AND expires_at > ?1".to_string();
        if domain.is_some() {
            sql.push_str(" AND conflict_domain = ?2");
        }
        sql.push_str(" ORDER BY issued_at ASC");
        let mut stmt = self.conn.prepare(&sql)?;
        let v = match domain {
            Some(d) => lease_from_row_query(&mut stmt, params![now_ts, d])?,
            None => lease_from_row_query(&mut stmt, params![now_ts])?,
        };
        Ok(v)
    }

    /// 到期未释放的租约（sweeper 用）。
    pub fn leases_to_expire(&self, now_ts: i64) -> Result<Vec<LeaseInfo>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, conflict_domain, agent_id, session_id, glob, intent, state, issued_at, ttl_s, last_heartbeat, expires_at, enforcement_layer
             FROM leases WHERE state = 'active' AND expires_at <= ?1",
        )?;
        lease_from_row_query(&mut stmt, params![now_ts])
    }

    // ---------- 黑板 ----------

    pub fn insert_board_entry(&self, e: &BoardEntry) -> Result<()> {
        self.conn.execute(
            "INSERT INTO board_entries(id, lease_id, origin, body, status, created_at, archived_at)
             VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![
                e.id,
                e.lease_id,
                e.origin,
                e.body,
                e.status,
                e.created_at,
                e.archived_at
            ],
        )?;
        Ok(())
    }

    pub fn archive_board_by_lease(&self, lease_id: &str) -> Result<usize> {
        self.conn
            .execute(
                "UPDATE board_entries SET status = 'archived', archived_at = ?2
             WHERE lease_id = ?1 AND status = 'active'",
                params![lease_id, now()],
            )
            .map_err(Error::from)
    }

    /// 黑板读取：活动条目 + 7 天内归档摘要，按活跃度+时间排序，token 预算截断（FR5.3 / AC5.2）。
    pub fn board_read(&self, token_budget: usize) -> Result<crate::proto::BoardRead> {
        let mut stmt = self.conn.prepare(
            "SELECT id, lease_id, origin, body, status, created_at, archived_at
             FROM board_entries
             WHERE status = 'active'
                OR (status = 'archived' AND archived_at >= ?1 - 7*86400)
             ORDER BY status ASC, created_at DESC", // active 排前（'active' < 'archived'）
        )?;
        let entries: Vec<BoardEntry> = stmt
            .query_map(params![now()], |r| {
                Ok(BoardEntry {
                    id: r.get(0)?,
                    lease_id: r.get(1)?,
                    origin: r.get(2)?,
                    body: r.get(3)?,
                    status: r.get(4)?,
                    created_at: r.get(5)?,
                    archived_at: r.get(6)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        let budget_chars = token_budget.saturating_mul(4); // 近似 4 字符/token
        let mut used = 0usize;
        let mut kept = Vec::new();
        let mut archived_summary = Vec::new();
        let mut truncated = 0usize;
        for e in entries {
            let cost = e.body.chars().count() + 8;
            if used + cost > budget_chars {
                truncated += 1;
                continue;
            }
            used += cost;
            if e.status == "active" {
                kept.push(e);
            } else {
                let ts = ts_humane(e.archived_at.unwrap_or(e.created_at));
                archived_summary.push(format!(
                    "[{ts}] {origin}: {body}",
                    origin = e.origin,
                    body = e.body
                ));
            }
        }
        Ok(crate::proto::BoardRead {
            approx_tokens: used.div_ceil(4),
            entries: kept,
            archived_summary,
            truncated,
        })
    }

    /// 归档保留期清理（默认 7 天，可配）。
    pub fn board_purge(&self, retain_days: i64) -> Result<usize> {
        self.conn.execute(
            "DELETE FROM board_entries WHERE status = 'archived' AND archived_at < ?1 - ?2*86400",
            params![now(), retain_days],
        )
        .map_err(Error::from)
    }

    // ---------- 会话 / 端口 ----------

    pub fn insert_session(&self, s: &SessionInfo) -> Result<()> {
        self.conn.execute(
            "INSERT INTO sessions(session_id, agent_id, seq, port_base, created_at) VALUES(?1,?2,?3,?4,?5)",
            params![s.session_id, s.agent_id, s.seq, s.port_base as i64, now()],
        )?;
        Ok(())
    }

    pub fn list_sessions(&self, active_only: bool) -> Result<Vec<SessionInfo>> {
        let sql = if active_only {
            "SELECT session_id, agent_id, seq, port_base FROM sessions WHERE ended_at IS NULL ORDER BY seq"
        } else {
            "SELECT session_id, agent_id, seq, port_base FROM sessions ORDER BY seq"
        };
        let mut stmt = self.conn.prepare(sql)?;
        let rows = stmt
            .query_map([], |r| {
                Ok(SessionInfo {
                    session_id: r.get(0)?,
                    agent_id: r.get(1)?,
                    seq: r.get(2)?,
                    port_base: r.get::<_, i64>(3)? as u16,
                    env: Default::default(),
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn end_session(&self, session_id: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE sessions SET ended_at = ?2 WHERE session_id = ?1 AND ended_at IS NULL",
            params![session_id, now()],
        )?;
        Ok(())
    }

    pub fn upsert_port(&self, p: &PortInfo) -> Result<()> {
        self.conn.execute(
            "INSERT INTO ports(session_id, port, purpose, state, cooldown_until) VALUES(?1,?2,?3,?4,?5)
             ON CONFLICT(session_id, port) DO UPDATE SET purpose=?3, state=?4, cooldown_until=?5",
            params![p.session_id, p.port as i64, p.purpose, p.state, p.cooldown_until],
        )?;
        Ok(())
    }

    pub fn list_ports(&self) -> Result<Vec<PortInfo>> {
        let mut stmt = self.conn.prepare(
            "SELECT session_id, port, purpose, state, cooldown_until FROM ports ORDER BY port",
        )?;
        let rows = stmt
            .query_map([], |r| {
                Ok(PortInfo {
                    session_id: r.get(0)?,
                    port: r.get::<_, i64>(1)? as u16,
                    purpose: r.get(2)?,
                    state: r.get(3)?,
                    cooldown_until: r.get(4)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// 端口段是否与任何 active/cooldown 端口重叠（分配会话段时防撞）。
    /// 参数用 i64 以避免调用方 u16 运算回绕。
    pub fn port_range_busy(&self, base: i64, count: i64) -> Result<bool> {
        let busy: bool = self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM ports WHERE port >= ?1 AND port < ?2 AND state IN ('active','cooldown'))",
            params![base, base + count],
            |r| r.get(0),
        )?;
        Ok(busy)
    }

    // ---------- 杂项锁（v0.2 FR3.5） ----------

    /// 返回 Ok(None) = 获得锁；Ok(Some(holder)) = 锁被 holder 持有（排队重试）。
    pub fn misc_lock_acquire(&self, name: &str, session_id: &str) -> Result<Option<String>> {
        self.conn.execute(
            "INSERT INTO misc_locks(name, session_id, acquired_at) VALUES(?1, ?2, ?3)
             ON CONFLICT(name) DO NOTHING",
            params![name, session_id, now()],
        )?;
        let holder: Option<String> = self
            .conn
            .query_row(
                "SELECT session_id FROM misc_locks WHERE name = ?1",
                params![name],
                |r| r.get(0),
            )
            .optional()?;
        Ok(holder.filter(|h| h != session_id))
    }

    pub fn misc_lock_release(&self, name: &str, session_id: &str) -> Result<bool> {
        let n = self.conn.execute(
            "DELETE FROM misc_locks WHERE name = ?1 AND session_id = ?2",
            params![name, session_id],
        )?;
        Ok(n > 0)
    }

    pub fn misc_locks_by_session(&self, session_id: &str) -> Result<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT name FROM misc_locks WHERE session_id = ?1")?;
        let rows = stmt
            .query_map(params![session_id], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    // ---------- 拒绝计数（AC4.3） ----------

    pub fn bump_deny_count(&self, session_id: &str, path: &str) -> Result<u32> {
        self.conn.execute(
            "INSERT INTO deny_counts(session_id, path, count) VALUES(?1, ?2, 1)
             ON CONFLICT(session_id, path) DO UPDATE SET count = count + 1",
            params![session_id, path],
        )?;
        let c: u32 = self.conn.query_row(
            "SELECT count FROM deny_counts WHERE session_id = ?1 AND path = ?2",
            params![session_id, path],
            |r| r.get(0),
        )?;
        Ok(c)
    }

    // ---------- 保护空窗（AC2.4） ----------

    /// daemon 启动时读取上次会话结束方式，计算保护空窗（毫秒时间戳，转秒返回）。
    pub fn take_protection_gap(&self, boot_ts_ms: i64) -> Result<Option<i64>> {
        let last_boot: Option<i64> = self.meta_get("last_boot_ts")?.and_then(|v| v.parse().ok());
        let last_clean: bool = self
            .meta_get("last_boot_clean")?
            .map(|v| v == "1")
            .unwrap_or(true);
        // 记录本次启动
        self.meta_set("last_boot_ts", &boot_ts_ms.to_string())?;
        self.meta_set("last_boot_clean", "0")?; // 运行中；正常停机时改回 1
        match (last_boot, last_clean) {
            (Some(prev), false) if boot_ts_ms > prev => Ok(Some((boot_ts_ms - prev + 999) / 1000)),
            _ => Ok(None),
        }
    }

    /// 正常停机（SIGTERM）时调用：不构成空窗。
    pub fn mark_clean_shutdown(&self) -> Result<()> {
        self.meta_set("last_boot_clean", "1")
    }

    // ---------- 会话资源清理（AC3.3） ----------

    pub fn session_artifacts_to_clean(&self, cutoff: i64) -> Result<Vec<String>> {
        let mut stmt = self.conn.prepare(
            "SELECT session_id FROM sessions WHERE ended_at IS NOT NULL AND ended_at <= ?1",
        )?;
        let rows = stmt
            .query_map(params![cutoff], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn delete_session_row(&self, session_id: &str) -> Result<()> {
        self.conn.execute(
            "DELETE FROM sessions WHERE session_id = ?1",
            params![session_id],
        )?;
        self.conn.execute(
            "DELETE FROM ports WHERE session_id = ?1",
            params![session_id],
        )?;
        self.conn.execute(
            "DELETE FROM misc_locks WHERE session_id = ?1",
            params![session_id],
        )?;
        // deny_counts 一并清理，防止表无限增长
        self.conn.execute(
            "DELETE FROM deny_counts WHERE session_id = ?1",
            params![session_id],
        )?;
        Ok(())
    }
}

fn lease_from_row_query(
    stmt: &mut rusqlite::Statement,
    p: impl rusqlite::Params,
) -> Result<Vec<LeaseInfo>> {
    let rows = stmt
        .query_map(p, |r| {
            Ok(LeaseInfo {
                id: r.get(0)?,
                conflict_domain: r.get(1)?,
                agent_id: r.get(2)?,
                session_id: r.get(3)?,
                glob: r.get(4)?,
                intent: r.get(5)?,
                state: r.get(6)?,
                issued_at: r.get(7)?,
                ttl_s: r.get(8)?,
                last_heartbeat: r.get(9)?,
                expires_at: r.get(10)?,
                enforcement_layer: r.get(11)?,
                tokens_used: r.get::<_, u64>(12).unwrap_or(0),
                cost_cents: r.get::<_, u64>(13).unwrap_or(0),
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

#[allow(clippy::too_many_arguments)]
fn audit_hash(
    seq: i64,
    prev_hash: &str,
    ts: i64,
    event: &str,
    actor_json: &str,
    path: &str,
    lease_id: &str,
    layer: &str,
    detail_json: &str,
) -> String {
    let mut h = Sha256::new();
    h.update(seq.to_le_bytes());
    h.update(prev_hash.as_bytes());
    h.update(ts.to_le_bytes());
    h.update(event.as_bytes());
    h.update(actor_json.as_bytes());
    h.update(path.as_bytes());
    h.update(lease_id.as_bytes());
    h.update(layer.as_bytes());
    h.update(detail_json.as_bytes());
    let d = h.finalize();
    d.iter().map(|b| format!("{b:02x}")).collect()
}

/// UTC "YYYY-MM-DD HH:MM:SS"（避免引入 chrono）；CLI 日志渲染共用。
pub fn ts_humane(ts: i64) -> String {
    let days = ts / 86400;
    let secs = ts % 86400;
    let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    // 以 1970-01-01 起算的年月日（民用算法）
    let (y, mo, d) = civil_from_days(days);
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{m:02}:{s:02}")
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}
