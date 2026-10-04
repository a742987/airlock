//! 面向用户的字符串集中地（§6.4：i18n 架构准备）。
//!
//! 人类可读模板遵循 §6.2 拒绝消息模板（P1：拒绝必须可解释——谁持有、为什么、
//! 何时释放、下一步该做什么）。模型可读字段见 [`crate::proto::Rejection`]。

/// `suggested_action` 受控词表（v1.0 冻结，新增走 RFC）。
pub mod suggested_action {
    /// 存在无冲突路径：claim 备选或等待
    pub const CLAIM_FREE_ALTERNATIVE_OR_WAIT: &str = "claim_free_alternative_or_wait";
    /// 无备选路径：等待后重试
    pub const WAIT_THEN_RETRY: &str = "wait_then_retry";
    /// 同一路径反复被拒 ≥3 次：建议换任务或找用户仲裁（AC4.3 防模型死循环蛮干）
    pub const ESCALATE_SWITCH_TASK: &str = "escalate_switch_task";
    /// daemon 不可达，降级运行：先恢复连接
    pub const RETRY_AFTER_RECONNECT: &str = "retry_after_degraded_reconnect";
    /// 操作对象（租约）不属于本会话——v0.x 扩展词（v1.0 前纳入冻结表）
    pub const LEASE_NOT_OWNED_BY_SESSION: &str = "lease_not_owned_by_session";
}

pub const SQLITE_CORRUPT: &str = "SQLite 数据库损坏，airlockd 拒绝启动（宁可不可用，不可假保护）。\
修复指引：备份后删除 <git-common-dir>/airlock/airlock.db 并重启 daemon；\
租约状态会清空，审计日志如已备份可离线校验。";

/// §6.2 人类可读拒绝模板。
pub fn rejection_human(
    path: &str,
    agent: &str,
    session: &str,
    ttl_remaining_s: i64,
    action: &str,
) -> String {
    let mins = ttl_remaining_s / 60;
    let when = if mins >= 1 {
        format!("约 {mins} 分钟后释放")
    } else {
        format!("约 {ttl_remaining_s} 秒后释放")
    };
    let advice = match action {
        suggested_action::CLAIM_FREE_ALTERNATIVE_OR_WAIT => {
            "先做无冲突路径的工作（清单见 airlock status --free），或等待后重试"
        }
        suggested_action::WAIT_THEN_RETRY => "无现成备选路径，等待该租约释放后重试",
        suggested_action::ESCALATE_SWITCH_TASK => {
            "你已多次尝试同一路径——建议改做其他任务，或向用户说明并等待人工协调"
        }
        suggested_action::RETRY_AFTER_RECONNECT => {
            "airlockd 不可达，本次运行处于无保护降级状态；请提示用户重启 daemon"
        }
        suggested_action::LEASE_NOT_OWNED_BY_SESSION => {
            "请使用持有该租约的会话操作，或先由持有方 release"
        }
        _ => "查看 airlock status 了解当前租约",
    };
    format!(
        "✗ 无法 claim {path} —— 该路径由 {agent}（会话 {session}）持有，{when}。\n  建议：{advice}。"
    )
}

/// daemon 不可达时 CLI 的黄色警告（P2/P7：fail-open 必须显式可见）。
pub const DEGRADED_WARNING: &str =
    "⚠ airlockd 不可达——本次操作将在无租约保护下继续（fail-open）。请运行 `airlock doctor` 检查。";

/// 保护空窗提示（AC2.4：daemon 恢复后提示空窗时长）。
pub fn protection_gap(gap_s: i64) -> String {
    format!("⚠ 检测到保护空窗 {gap_s} 秒（上次 daemon 会话异常退出）。此间内核规则已随 TTL 失效，历史拦截请核查审计日志。")
}
