//! IPC / MCP 共享协议类型（P4：机器可读与人类可读同权）。
//!
//! unix socket 请求为单行 JSON：`{"v":1,"method":"...","params":{...}}`，
//! 响应 `{"ok":true,"data":...}` 或 `{"ok":false,"error":{...}}`。

use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: i64 = 1;

// ---------- 拒绝载荷（§6.2 / §7.3 模板，★设计标准） ----------

/// 409 型结构化拒绝。三要素：holder / ttl_remaining_s / suggested_action。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Rejection {
    pub error: String, // "conflict" | "degraded" | "policy" | ...
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub holder: Option<Holder>,
    pub ttl_remaining_s: i64,
    pub free_alternatives: Vec<String>,
    pub suggested_action: String,
    pub degraded: bool,
    /// 人类可读渲染（P1 / P4 双形态）
    pub human: String,
    /// AC4.3：同路径被拒次数（≥3 时 suggested_action 升级）
    #[serde(default)]
    pub deny_count: u32,
    /// F12：政策拒绝细节（协议 v2 additive；error = "policy" 时存在）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<PolicyViolation>,
}

/// F12 政策违规细节（协议 v2）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PolicyViolation {
    /// 命中的政策规则（glob）；agent/默认拒绝时为 `<agents.allow>` 等说明性占位
    pub rule: String,
    /// agent_not_allowed | path_denied | allowlist_miss | default_deny
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Holder {
    pub agent: String,
    pub session: String,
    pub layer: String,
}

// ---------- 租约 ----------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LeaseInfo {
    pub id: String,
    pub conflict_domain: String,
    pub agent_id: String,
    pub session_id: String,
    pub glob: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intent: Option<String>,
    /// active / expired / released / revoked
    pub state: String,
    pub issued_at: i64,
    pub ttl_s: i64,
    pub last_heartbeat: i64,
    pub expires_at: i64,
    /// 下发时的层（L1/L2/L3），用于空窗审计
    pub enforcement_layer: String,
    /// F6：累计 token 消耗（由 agent 通过 heartbeat 或 report_cost 上报）
    #[serde(default)]
    pub tokens_used: u64,
    /// F6：累计成本（美分，由 tokens_used × 单价估算）
    #[serde(default)]
    pub cost_cents: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Prediction {
    /// none / overlap / semantic-suspect（F5：建议不是拒绝）
    pub risk: String,
    pub with_leases: Vec<String>,
    /// 符号级延后（v0.3 Could）；文件/目录级预测恒为空数组
    pub involved_symbols: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimOk {
    pub lease: LeaseInfo,
    pub prediction: Prediction,
    /// F13：随租约发放的凭据（env 变量名 → 值）；未请求凭据时为 None（协议 v2 additive）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials: Option<std::collections::BTreeMap<String, String>>,
}

// ---------- 会话与资源 ----------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    pub session_id: String,
    pub agent_id: String,
    pub seq: i64,
    pub port_base: u16,
    /// 注入环境变量：PORT / VITE_PORT / NEXT_PORT 等
    pub env: std::collections::BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortInfo {
    pub session_id: String,
    pub port: u16,
    pub purpose: String,
    /// active / cooldown / released
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cooldown_until: Option<i64>,
}

// ---------- F13 凭据（协议 v2） ----------

/// 凭据发放记录。`meta` 内含后端句柄（如 vault lease_id）与发放时的 env——
/// 数据库位于 `<git-common-dir>/airlock/`（本机信任域，与凭据源文件同级）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredRow {
    pub id: String,
    pub lease_id: String,
    /// file / vault（后端名，与 Config.credentials_backend 对应）
    pub backend: String,
    /// 资源名（如测试库 app-db）
    pub resource: String,
    /// active / revoked
    pub status: String,
    pub issued_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<serde_json::Value>,
}

// ---------- 审计日志（§7.2） ----------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub seq: i64,
    pub prev_hash: String,
    pub hash: String,
    pub ts: i64,
    /// claim/grant/deny/heartbeat/expire/release/enforce_deny/enforce_expire/degrade/rollback
    pub event: String,
    pub actor: Actor,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease_id: Option<String>,
    pub layer: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Actor {
    #[serde(default)]
    pub agent: String,
    #[serde(default)]
    pub session: String,
    /// 进程树（pid 自根向下）
    #[serde(default)]
    pub pid_tree: Vec<u32>,
}

// ---------- 黑板（§7.3） ----------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoardEntry {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease_id: Option<String>,
    /// agent（声明，可谎报）| daemon（依审计日志生成，不可抵赖）
    pub origin: String,
    pub body: String,
    /// active / archived
    pub status: String,
    pub created_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub archived_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoardRead {
    pub entries: Vec<BoardEntry>,
    pub archived_summary: Vec<String>,
    /// 因 token 预算被截断的条数（AC5.2）
    pub truncated: usize,
    pub approx_tokens: usize,
}

// ---------- 状态汇总 ----------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayerState {
    /// L0 (disabled) / L1 / L2 / L3
    pub id: String,
    pub name: String,
    pub available: bool,
    pub experimental: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusReport {
    pub conflict_domain: String,
    pub repo_root: String,
    pub is_git: bool,
    pub layer: LayerState,
    pub leases: Vec<LeaseInfo>,
    pub sessions: Vec<SessionInfo>,
    pub ports: Vec<PortInfo>,
    /// daemon 上次异常退出造成的保护空窗（秒）；None = 无空窗
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protection_gap_s: Option<i64>,
}

// ---------- daemon 协议 ----------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub v: i64,
    pub method: String,
    #[serde(default = "serde_json::Value::default")]
    pub params: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<serde_json::Value>,
}

impl Response {
    pub fn ok<T: Serialize>(data: &T) -> Response {
        Response {
            ok: true,
            data: Some(serde_json::to_value(data).unwrap_or(serde_json::Value::Null)),
            error: None,
        }
    }

    pub fn err<T: Serialize>(err: &T) -> Response {
        Response {
            ok: false,
            data: None,
            error: Some(serde_json::to_value(err).unwrap_or_else(
                |_| serde_json::json!({ "kind": "internal", "message": "error 序列化失败" }),
            )),
        }
    }

    pub fn from_json(v: serde_json::Value) -> Response {
        match serde_json::from_value::<Response>(v.clone()) {
            Ok(r) => r,
            Err(_) => Response {
                ok: false,
                data: None,
                error: Some(v),
            },
        }
    }
}

/// 客户端调用 daemon 的轻量封装。
pub struct Client {
    inner: ClientInner,
}

enum ClientInner {
    Socket(std::os::unix::net::UnixStream),
    /// daemon 与本地存储均不可用时的空操作（调用恒失败，fail-open 语义由调用方实现）
    Dead,
}

impl Client {
    pub fn connect(sock: &std::path::Path) -> crate::error::Result<Client> {
        let stream = std::os::unix::net::UnixStream::connect(sock).map_err(|e| {
            crate::error::Error::DaemonUnreachable(format!("{}: {e}", sock.display()))
        })?;
        stream.set_read_timeout(Some(std::time::Duration::from_secs(30)))?;
        Ok(Client {
            inner: ClientInner::Socket(stream),
        })
    }

    /// 全降级占位客户端。
    pub fn degraded() -> Client {
        Client {
            inner: ClientInner::Dead,
        }
    }

    /// 带重试的调用：仅在**连接建立失败**时重连一次（自愈竞态：daemon 刚被
    /// 拉起/重启）。读超时/读失败不重试——请求可能已被处理，重发非幂等的
    /// claim/release 会造成二次授予或误释放。
    pub fn call_with_retry(
        &mut self,
        sock: &std::path::Path,
        method: &str,
        params: &serde_json::Value,
    ) -> crate::error::Result<serde_json::Value> {
        match self.call(method, params) {
            Err(crate::error::Error::DaemonUnreachable(_)) => {
                let c = Client::connect(sock)?;
                *self = c;
                self.call(method, params)
            }
            other => other,
        }
    }

    pub fn call(
        &mut self,
        method: &str,
        params: &serde_json::Value,
    ) -> crate::error::Result<serde_json::Value> {
        let ClientInner::Socket(stream) = &mut self.inner else {
            return Err(crate::error::Error::DaemonUnreachable(
                "daemon 与本地存储均不可用".into(),
            ));
        };
        let req = Request {
            v: PROTOCOL_VERSION,
            method: method.to_string(),
            params: params.clone(),
        };
        let mut line = serde_json::to_string(&req)?;
        line.push('\n');
        use std::io::{BufRead, Read, Write};
        stream.write_all(line.as_bytes())?;
        // 响应行设上限（1 MiB）：对端异常输出超长行时快速失败，不耗尽内存
        let mut reader = std::io::BufReader::new(stream.take(MAX_RESPONSE_BYTES));
        let mut buf = String::new();
        match reader.read_line(&mut buf) {
            Ok(0) => {
                // daemon 关闭连接：视为不可达（call_with_retry 可安全重连）
                return Err(crate::error::Error::DaemonUnreachable("空响应".into()));
            }
            Ok(_) => {}
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                // 读超时：请求可能已被处理，绝不重试——上层按 Io 错误直接失败
                return Err(crate::error::Error::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "daemon 响应超时（30s）",
                )));
            }
            Err(e) => return Err(e.into()),
        }
        if buf.trim().is_empty() {
            return Err(crate::error::Error::DaemonUnreachable("空响应".into()));
        }
        let resp: Response = serde_json::from_str(buf.trim())?;
        if resp.ok {
            Ok(resp.data.unwrap_or(serde_json::Value::Null))
        } else {
            Err(daemon_error(resp.error.unwrap_or(serde_json::json!({}))))
        }
    }
}

/// 响应行上限：16 MiB。`status` 返回全部租约、`log` 最多 500 条全量 JSON，
/// 忙碌共享仓库的合法响应可能超过 1 MiB（上限过低会让 CLI/MCP 的 status
/// 在 daemon 完全健康时持续报错）；16 MiB 仍足以挡住失控对端的内存耗尽。
const MAX_RESPONSE_BYTES: u64 = 16 << 20;

/// 将 daemon 错误载荷还原为 Error（保持 409 型拒绝的退出码语义）。
pub fn daemon_error(v: serde_json::Value) -> crate::error::Error {
    if let Ok(kind) = serde_json::from_value::<Rejection>(v.clone()) {
        if matches!(kind.error.as_str(), "conflict" | "degraded" | "forbidden") {
            return crate::error::Error::Conflict(Box::new(kind));
        }
    }
    if let Some(msg) = v.get("message").and_then(|m| m.as_str()) {
        match v.get("kind").and_then(|k| k.as_str()) {
            Some("not_found") => crate::error::Error::NotFound(msg.to_string()),
            Some("config") => crate::error::Error::Config(msg.to_string()),
            Some("integrity") => crate::error::Error::Integrity(msg.to_string()),
            _ => crate::error::Error::Other(msg.to_string()),
        }
    } else {
        crate::error::Error::Other(v.to_string())
    }
}

/// 可在 daemon 错误载荷中使用的简单错误。
pub fn simple_error(kind: &str, message: &str) -> serde_json::Value {
    serde_json::json!({ "kind": kind, "message": message })
}
