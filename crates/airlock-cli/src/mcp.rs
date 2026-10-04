//! MCP stdio server（F4，FR4.1/FR4.3）：JSON-RPC 2.0 over stdio。
//! 工具集：claim / release / status / log / heartbeat / blackboard_read / blackboard_write。
//! 拒绝消息双形态：content（人类可读）+ structuredContent（模型可读 JSON，P4）。
//! 会话注册后自动后台心跳（FR1.1 默认 60s 续约）。

use std::io::{BufRead, Write};
use std::sync::Arc;

use airlock_core::error::{Error, Result};
use airlock_core::proto::{self, ClaimOk, StatusReport};

use crate::commands::Ctx;

/// 本实现支持的 MCP 协议版本（initialize 无法协商时使用）。
const MCP_PROTOCOL_VERSION: &str = "2025-06-18";

pub fn serve(ctx: &Ctx) -> Result<i32> {
    let session: Arc<tokio_like::OnceCell<String>> = Arc::new(tokio_like::OnceCell::new());
    let stdin = std::io::stdin();
    let mut reader = stdin.lock();
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Ok(v) = serde_json::from_str::<serde_json::Value>(trimmed) else {
            // 非法 JSON 必须回 parse error——客户端在等响应，静默忽略会挂起（JSON-RPC 规范）
            let resp = serde_json::json!({
                "jsonrpc": "2.0",
                "id": serde_json::Value::Null,
                "error": { "code": -32700, "message": "Parse error" }
            });
            let mut out = std::io::stdout().lock();
            writeln!(out, "{resp}")?;
            out.flush()?;
            continue;
        };
        let id = v.get("id").cloned();
        let method = v
            .get("method")
            .and_then(|m| m.as_str())
            .unwrap_or("")
            .to_string();
        let params = v.get("params").cloned().unwrap_or(serde_json::json!({}));

        // notification：无 id，不回复
        if id.is_none() {
            continue;
        }

        let result: std::result::Result<serde_json::Value, (i64, String)> = match method.as_str() {
            "initialize" => {
                // 回显客户端请求的版本（协议协商），未提供时用本实现支持的版本
                let version = params
                    .get("protocolVersion")
                    .and_then(|p| p.as_str())
                    .filter(|s| !s.is_empty())
                    .unwrap_or(MCP_PROTOCOL_VERSION)
                    .to_string();
                Ok(serde_json::json!({
                    "protocolVersion": version,
                    "capabilities": { "tools": {} },
                    "serverInfo": { "name": "airlock", "version": env!("CARGO_PKG_VERSION") }
                }))
            }
            "ping" => Ok(serde_json::json!({})),
            "tools/list" => Ok(tools_list()),
            "tools/call" => match tool_call(ctx, &params, &session) {
                Ok(v) => Ok(v),
                Err(Error::Conflict(rej)) => Ok(serde_json::json!({
                    "content": [{ "type": "text", "text": rej.human }],
                    "structuredContent": serde_json::to_value(&*rej).unwrap_or_default(),
                    "isError": true
                })),
                Err(Error::NotFound(m)) => Err((-32602, m)),
                Err(e) => Err((-32603, e.to_string())),
            },
            other => Err((-32601, format!("未知方法 {other}"))),
        };

        let resp = match result {
            Ok(r) => serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": r }),
            Err((code, message)) => serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": { "code": code, "message": message }
            }),
        };
        let mut out = std::io::stdout().lock();
        writeln!(out, "{resp}")?;
        out.flush()?;
    }
    Ok(0)
}

/// 简化版 OnceCell（避免引入 tokio）。
mod tokio_like {
    use std::sync::Mutex;

    pub struct OnceCell<T>(Mutex<Option<T>>);

    impl<T> OnceCell<T> {
        pub fn new() -> Self {
            OnceCell(Mutex::new(None))
        }
        pub fn set(&self, v: T) -> Result<(), T> {
            let mut g = self.0.lock().unwrap();
            if g.is_some() {
                return Err(v);
            }
            *g = Some(v);
            Ok(())
        }
        pub fn get(&self) -> Option<T>
        where
            T: Clone,
        {
            self.0.lock().unwrap().clone()
        }
    }
}

fn tools_list() -> serde_json::Value {
    let tool = |name: &str, desc: &str, schema: serde_json::Value| serde_json::json!({ "name": name, "description": desc, "inputSchema": schema });
    let obj = |props: serde_json::Value, required: &[&str]| {
        let mut o = serde_json::json!({ "type": "object", "properties": props });
        if !required.is_empty() {
            o["required"] = serde_json::json!(required);
        }
        o
    };
    serde_json::json!({
        "tools": [
            tool("claim", "申请独占文件租约（glob 模式，带 TTL 与心跳）。冲突时返回结构化拒绝（holder/ttl_remaining/suggested_action）。",
                 obj(serde_json::json!({
                     "glob": { "type": "string", "description": "路径模式，如 src/auth/**" },
                     "intent": { "type": "string", "description": "本次工作意图（写入黑板，帮助其他 agent）" },
                     "ttl_s": { "type": "integer", "description": "TTL 秒数，默认 1800" }
                 }), &["glob"])),
            tool("release", "释放租约", obj(serde_json::json!({
                "lease_id": { "type": "string" }, "all": { "type": "boolean" }
            }), &[])),
            tool("heartbeat", "租约心跳续约", obj(serde_json::json!({
                "lease_id": { "type": "string" }
            }), &["lease_id"])),
            tool("report_cost", "上报租约的 token 消耗和成本（F6 成本归因）", obj(serde_json::json!({
                "lease_id": { "type": "string" },
                "tokens": { "type": "integer" },
                "cost_cents": { "type": "integer" }
            }), &["lease_id"])),
            tool("status", "查看租约表、资源分配与当前强制层", obj(serde_json::json!({}), &[])),
            tool("log", "审计日志（可选校验 hash 链）", obj(serde_json::json!({
                "verify": { "type": "boolean" }, "limit": { "type": "integer" }
            }), &[])),
            tool("blackboard_read", "读冲突域黑板：其他 agent 在做什么、仓库有什么坑（token 预算受控）",
                 obj(serde_json::json!({ "token_budget": { "type": "integer" } }), &[])),
            tool("blackboard_write", "写黑板条目（经验/坑/交接说明）", obj(serde_json::json!({
                "body": { "type": "string" }, "lease_id": { "type": "string" }
            }), &["body"])),
        ]
    })
}

fn ensure_session(ctx: &Ctx, session_cell: &Arc<tokio_like::OnceCell<String>>) -> Result<String> {
    if let Some(s) = session_cell.get() {
        return Ok(s);
    }
    let agent = std::env::var("AIRLOCK_AGENT_ID").unwrap_or_else(|_| "mcp-agent".into());
    if let Ok(sid) = std::env::var("AIRLOCK_SESSION_ID") {
        if !sid.is_empty() {
            let _ = session_cell.set(sid.clone());
            return Ok(sid);
        }
    }
    let mut c = ctx.client_or_heal()?;
    let v = c.call("register", &serde_json::json!({ "agent_id": agent }))?;
    let sid = v
        .get("session_id")
        .and_then(|s| s.as_str())
        .ok_or_else(|| Error::Other("daemon 未返回 session_id".into()))?
        .to_string();
    let _ = session_cell.set(sid.clone());
    // 后台心跳线程：为本会话全部 active 租约续约
    let sock = ctx.domain.socket_path();
    let heartbeat_s = ctx.cfg.heartbeat_s.max(5) as u64;
    let sid_for_hb = sid.clone();
    let agent_for_hb = agent.clone();
    std::thread::spawn(move || {
        let sid = sid_for_hb;
        loop {
            std::thread::sleep(std::time::Duration::from_secs(heartbeat_s));
            let Ok(mut client) = proto::Client::connect(&sock) else {
                continue;
            };
            let Ok(v) = client.call("status", &serde_json::json!({})) else {
                continue;
            };
            let Ok(report) = serde_json::from_value::<StatusReport>(v) else {
                continue;
            };
            for l in &report.leases {
                if l.session_id == sid && l.state == "active" {
                    let _ = client.call(
                    "heartbeat",
                    &serde_json::json!({ "lease_id": l.id, "agent_id": agent_for_hb, "session_id": sid }),
                );
                }
            }
        }
    });
    Ok(sid)
}

fn tool_call(
    ctx: &Ctx,
    params: &serde_json::Value,
    session_cell: &Arc<tokio_like::OnceCell<String>>,
) -> Result<serde_json::Value> {
    let name = params
        .get("name")
        .and_then(|n| n.as_str())
        .ok_or_else(|| Error::Config("tools/call 需要 name".into()))?
        .to_string();
    let args = params
        .get("arguments")
        .cloned()
        .unwrap_or(serde_json::json!({}));
    let mut c = ctx.client_or_heal()?;

    let structured: serde_json::Value = match name.as_str() {
        "claim" => {
            let sid = ensure_session(ctx, session_cell)?;
            let glob_pattern = args
                .get("glob")
                .and_then(|g| g.as_str())
                .ok_or_else(|| Error::Config("claim 需要 glob".into()))?;
            let mut p = serde_json::json!({
                "agent_id": std::env::var("AIRLOCK_AGENT_ID").unwrap_or_else(|_| "mcp-agent".into()),
                "session_id": sid,
                "glob": glob_pattern,
            });
            if let Some(i) = args.get("intent").and_then(|i| i.as_str()) {
                p["intent"] = serde_json::json!(i);
            }
            if let Some(t) = args.get("ttl_s").and_then(|t| t.as_i64()) {
                p["ttl_s"] = serde_json::json!(t);
            }
            let v = c.call("claim", &p)?;
            let ok: ClaimOk = serde_json::from_value(v)?;
            serde_json::to_value(&ok)?
        }
        "release" => {
            let sid = ensure_session(ctx, session_cell)?;
            let p = if args.get("all").and_then(|a| a.as_bool()).unwrap_or(false) {
                serde_json::json!({ "session_id": sid })
            } else {
                let id = args
                    .get("lease_id")
                    .and_then(|i| i.as_str())
                    .ok_or_else(|| Error::Config("release 需要 lease_id 或 all=true".into()))?;
                serde_json::json!({ "lease_id": id, "session_id": sid })
            };
            c.call("release", &p)?
        }
        "heartbeat" => {
            let sid = ensure_session(ctx, session_cell)?;
            let id = args
                .get("lease_id")
                .and_then(|i| i.as_str())
                .ok_or_else(|| Error::Config("heartbeat 需要 lease_id".into()))?;
            c.call(
                "heartbeat",
                &serde_json::json!({ "lease_id": id, "session_id": sid }),
            )?
        }
        "report_cost" => {
            let id = args
                .get("lease_id")
                .and_then(|i| i.as_str())
                .ok_or_else(|| Error::Config("report_cost 需要 lease_id".into()))?;
            let tokens = args.get("tokens").and_then(|v| v.as_u64()).unwrap_or(0);
            let cost_cents = args.get("cost_cents").and_then(|v| v.as_u64()).unwrap_or(0);
            c.call(
                "report_cost",
                &serde_json::json!({ "lease_id": id, "tokens": tokens, "cost_cents": cost_cents }),
            )?
        }
        "status" => {
            let _ = ensure_session(ctx, session_cell);
            c.call("status", &serde_json::json!({}))?
        }
        "log" => {
            let verify = args
                .get("verify")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if verify {
                c.call("verify", &serde_json::json!({}))?
            } else {
                let limit = args.get("limit").and_then(|l| l.as_i64()).unwrap_or(200);
                c.call("log", &serde_json::json!({ "limit": limit }))?
            }
        }
        "blackboard_read" => {
            let budget = args
                .get("token_budget")
                .and_then(|b| b.as_u64())
                .unwrap_or(500);
            c.call("board_read", &serde_json::json!({ "token_budget": budget }))?
        }
        "blackboard_write" => {
            let sid = ensure_session(ctx, session_cell)?;
            let body = args
                .get("body")
                .and_then(|b| b.as_str())
                .ok_or_else(|| Error::Config("blackboard_write 需要 body".into()))?;
            c.call(
                "board_write",
                &serde_json::json!({ "body": body, "lease_id": args.get("lease_id"), "session_id": sid }),
            )?
        }
        other => return Err(Error::NotFound(format!("未知工具 {other}"))),
    };

    // P4 双形态：人类可读文本 + 模型可读结构化
    let human = humanize(&name, &structured);
    Ok(serde_json::json!({
        "content": [{ "type": "text", "text": human }],
        "structuredContent": structured,
        "isError": false
    }))
}

fn humanize(tool: &str, v: &serde_json::Value) -> String {
    match tool {
        "claim" => {
            let id = v
                .pointer("/lease/id")
                .and_then(|x| x.as_str())
                .unwrap_or("?");
            let glob_pattern = v
                .pointer("/lease/glob")
                .and_then(|x| x.as_str())
                .unwrap_or("?");
            let risk = v
                .pointer("/prediction/risk")
                .and_then(|x| x.as_str())
                .unwrap_or("none");
            format!("✓ 租约 {id} 已建立（{glob_pattern}），冲突预测: {risk}")
        }
        "status" => {
            let n = v
                .pointer("/leases")
                .and_then(|x| x.as_array())
                .map(|a| a.len())
                .unwrap_or(0);
            let layer = v
                .pointer("/layer/id")
                .and_then(|x| x.as_str())
                .unwrap_or("?");
            format!("当前 {n} 条租约，强制层 {layer}")
        }
        "blackboard_read" => {
            let n = v
                .pointer("/entries")
                .and_then(|x| x.as_array())
                .map(|a| a.len())
                .unwrap_or(0);
            let t = v.get("truncated").and_then(|x| x.as_u64()).unwrap_or(0);
            let mut s = format!("黑板：{n} 条活动条目");
            if t > 0 {
                s.push_str(&format!("（截断 {t} 条）"));
            }
            s
        }
        other => format!("{other} 完成"),
    }
}
