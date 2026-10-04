//! `airlock init`（FR4.2 / AC4.2 / AC4.3 前置）：
//! 写入 agent 的 MCP 配置 + PreToolUse hook；已有配置时展示 diff 并要求确认，
//! 绝不静默覆盖；全部改动记录 manifest，`--undo` 一键回滚。

use std::path::PathBuf;

use airlock_core::error::{Error, Result};

use crate::commands::Ctx;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct ManifestFile {
    path: String,
    /// None = 原文件不存在（undo 时删除）
    original: Option<String>,
}

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
struct Manifest {
    agent: String,
    /// init 生成并注入 MCP/hook 配置的会话 ID（重复 init 复用，保持幂等）
    #[serde(default)]
    session_id: String,
    files: Vec<ManifestFile>,
}

struct Planned {
    path: PathBuf,
    /// 计划写入的新内容
    content: String,
    /// 原内容（None = 新建）
    original: Option<String>,
}

pub fn run(ctx: &Ctx, agent: Option<&str>, undo: bool, yes: bool) -> Result<i32> {
    if undo {
        return undo_init(ctx);
    }
    let agent = agent.unwrap_or("claude-code");
    let exe = ctx.exe.canonicalize().unwrap_or_else(|_| ctx.exe.clone());
    let home = std::env::var("HOME").unwrap_or_default();
    if home.is_empty() {
        // HOME 缺失时静默落相对路径曾把配置写到 CWD 下（P2-9）
        return Err(Error::Config(
            "环境变量 HOME 未设置，无法定位 agent 配置目录（codex 需要 $HOME/.codex）".into(),
        ));
    }
    let home = PathBuf::from(home);
    let root = &ctx.domain.root;
    let exe_s = exe.to_string_lossy().to_string();

    // 会话身份统一（P1-1）：同一 agent 的 MCP 进程与 hook 进程共享同一
    // session_id（init 时生成，manifest 里复用），hook 不会 deny 同一 agent
    // 的 MCP claim。hook 经 `env` 命令注入，MCP 经配置的 env 字段注入。
    let session_id = match load_manifest(ctx).map(|m| m.session_id) {
        Some(sid) if !sid.is_empty() => sid,
        _ => uuid::Uuid::new_v4().to_string(),
    };

    let mut mcp_entry = serde_json::json!({
        "command": exe_s,
        "args": ["mcp"]
    });
    mcp_entry["env"] = serde_json::json!({
        "AIRLOCK_SESSION_ID": session_id,
        "AIRLOCK_AGENT_ID": agent,
    });
    let hook_cmd = format!(
        "env AIRLOCK_SESSION_ID={session_id} AIRLOCK_AGENT_ID={agent} {exe_s} hook pretooluse"
    );
    let hook_entry = serde_json::json!({
        "matcher": "Edit|Write|MultiEdit|NotebookEdit|Bash",
        "hooks": [{ "type": "command", "command": hook_cmd }]
    });

    let plans: Vec<Planned> = match agent {
        "claude-code" => vec![
            json_plan(
                root.join(".mcp.json"),
                merge_json_key,
                "mcpServers",
                "airlock",
                &mcp_entry,
            )?,
            json_plan(
                root.join(".claude/settings.json"),
                merge_hook,
                "hooks",
                "PreToolUse",
                &hook_entry,
            )?,
        ],
        "gemini" => vec![json_plan(
            root.join(".gemini/settings.json"),
            merge_json_key,
            "mcpServers",
            "airlock",
            &mcp_entry,
        )?],
        "cursor" => vec![json_plan(
            root.join(".cursor/mcp.json"),
            merge_json_key,
            "mcpServers",
            "airlock",
            &mcp_entry,
        )?],
        "opencode" => vec![json_plan(
            root.join("opencode.json"),
            merge_opencode,
            "mcp",
            "airlock",
            &serde_json::json!({ "type": "local", "command": [exe_s, "mcp"], "env": { "AIRLOCK_SESSION_ID": session_id, "AIRLOCK_AGENT_ID": agent } }),
        )?],
        "codex" => vec![toml_plan(
            home.join(".codex/config.toml"),
            &format!(
                "\n[mcp_servers.airlock]\ncommand = {}\nargs = [\"mcp\"]\n",
                toml_quote(&exe_s)
            ),
            "[mcp_servers.airlock]",
        )?],
        other => {
            return Err(Error::Config(format!(
                "不支持的 agent `{other}`；支持：claude-code / codex / gemini / cursor / opencode"
            )))
        }
    };

    // AC4.2：只有「已存在文件的改动」需要确认（新建文件无需确认——绝不静默**覆盖**）
    let changing: Vec<&Planned> = plans
        .iter()
        .filter(|p| matches!(&p.original, Some(o) if o != &p.content))
        .collect();
    let creating: Vec<&Planned> = plans.iter().filter(|p| p.original.is_none()).collect();
    if changing.is_empty() && creating.is_empty() {
        ctx.out.either(
            &serde_json::json!({ "status": "unchanged", "agent": agent }),
            "配置已是最新，无需改动。",
        );
        return Ok(0);
    }
    if !changing.is_empty() && !yes {
        let interactive = std::io::IsTerminal::is_terminal(&std::io::stdin());
        println!("即将修改以下已有文件：");
        for p in &changing {
            println!("  ~ {}（已存在）", p.path.display());
        }
        println!("变更摘要：新增/更新 airlock 的 MCP 配置与 PreToolUse hook（不覆盖其他键）。");
        if !interactive {
            return Err(Error::Config(
                "检测到已有配置需要确认。非交互环境请加 --yes（或 --dry-run 预览）。绝不静默覆盖。"
                    .into(),
            ));
        }
        print!("确认写入？[y/N] ");
        use std::io::Write;
        std::io::stdout().flush().ok();
        let mut ans = String::new();
        std::io::stdin().read_line(&mut ans).ok();
        if !ans.trim().eq_ignore_ascii_case("y") {
            println!("已取消，未做任何改动。");
            return Ok(0); // 主动取消不是「用户中断」（原 130 语义牵强）
        }
    }

    // 写入 + manifest
    let mut manifest = load_manifest(ctx).unwrap_or(Manifest {
        agent: agent.into(),
        session_id: session_id.clone(),
        files: vec![],
    });
    manifest.agent = agent.into();
    manifest.session_id = session_id.clone();
    for p in &plans {
        if let Some(parent) = p.path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let original = p
            .original
            .as_ref()
            .map(|_| std::fs::read_to_string(&p.path).unwrap_or_default());
        // manifest 记录的是本次 init 前的状态（首次记录为准）
        if !manifest
            .files
            .iter()
            .any(|f| f.path == p.path.to_string_lossy())
        {
            manifest.files.push(ManifestFile {
                path: p.path.to_string_lossy().into(),
                original: original.clone().or(p.original.clone()),
            });
        }
        std::fs::write(&p.path, &p.content)?;
        ctx.out
            .println_stdout(&format!("✓ 已写入 {}", p.path.display()));
    }
    std::fs::write(
        ctx.domain.manifest_path(),
        serde_json::to_string_pretty(&manifest)?,
    )?;
    ctx.out.println_stdout(&format!(
        "\n✓ airlock init 完成（{agent}）。\n  回滚：airlock init --undo\n  检查：airlock doctor"
    ));
    Ok(0)
}

fn undo_init(ctx: &Ctx) -> Result<i32> {
    let path = ctx.domain.manifest_path();
    let text = std::fs::read_to_string(&path)
        .map_err(|_| Error::NotFound("没有 init manifest——无需回滚".into()))?;
    let manifest: Manifest = serde_json::from_str(&text)?;
    let mut n = 0;
    for f in &manifest.files {
        let p = PathBuf::from(&f.path);
        // original = None → 文件由 init 新建，直接删除；
        // original = Some → 只摘除 airlock 自己写入的部分，保留用户
        // init 之后的手工修改（JSON 按 key 删除）；识别不了才整体还原快照
        let undo_one = match &f.original {
            None => std::fs::remove_file(&p).map_err(|e| format!("删除 {} 失败: {e}", p.display())),
            Some(orig) => {
                let is_json = p.extension().map(|e| e == "json").unwrap_or(false);
                let stripped = if is_json {
                    std::fs::read_to_string(&p)
                        .ok()
                        .and_then(|cur| strip_airlock_json(&cur))
                } else {
                    None
                };
                match stripped {
                    Some(stripped) => std::fs::write(&p, stripped)
                        .map_err(|e| format!("写入 {} 失败: {e}", p.display())),
                    None => std::fs::write(&p, orig)
                        .map_err(|e| format!("写入 {} 失败: {e}", p.display())),
                }
            }
        };
        match undo_one {
            Ok(()) => println!("↩ 已还原 {}", p.display()),
            Err(e) => {
                return Err(Error::Io(std::io::Error::other(e)));
            }
        }
        n += 1;
    }
    let _ = std::fs::remove_file(&path);
    println!("✓ 回滚完成（{n} 个文件）。");
    Ok(0)
}

/// 从 JSON 配置中移除 airlock 写入的键；返回 None 表示结构里找不到 airlock 痕迹
/// （交给快照还原兜底）。
fn strip_airlock_json(text: &str) -> Option<String> {
    let mut doc: serde_json::Value = serde_json::from_str(text).ok()?;
    let obj = doc.as_object_mut()?;
    let mut touched = false;
    if let Some(mcp) = obj.get_mut("mcpServers").and_then(|m| m.as_object_mut()) {
        touched |= mcp.remove("airlock").is_some();
    }
    if let Some(hooks) = obj.get_mut("hooks").and_then(|h| h.as_object_mut()) {
        if let Some(list) = hooks.get_mut("PreToolUse").and_then(|l| l.as_array_mut()) {
            let before = list.len();
            list.retain(|e| {
                !e.pointer("/hooks/0/command")
                    .and_then(|c| c.as_str())
                    .map(|c| c.contains("airlock"))
                    .unwrap_or(false)
            });
            touched |= list.len() != before;
            if list.is_empty() {
                hooks.remove("PreToolUse");
            }
        }
    }
    if !touched {
        return None;
    }
    Some(format!("{}\n", serde_json::to_string_pretty(&doc).ok()?))
}

/// TOML 值引号：优先 literal string（单引号，不允许转义）；路径含 `'` 时
/// 退回 basic string（双引号 + 转义）——shell_quote 的 `'\''` 在 TOML 里非法。
fn toml_quote(s: &str) -> String {
    if !s.contains('\'') {
        format!("'{s}'")
    } else {
        format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
    }
}

fn load_manifest(ctx: &Ctx) -> Option<Manifest> {
    serde_json::from_str(&std::fs::read_to_string(ctx.domain.manifest_path()).ok()?).ok()
}

// ---------- 计划构造 ----------

fn json_plan(
    path: PathBuf,
    merge: fn(&mut serde_json::Value, &str, &str, &serde_json::Value),
    key: &'static str,
    subkey: &'static str,
    entry: &serde_json::Value,
) -> Result<Planned> {
    let original = std::fs::read_to_string(&path).ok();
    let mut doc = match &original {
        Some(text) => serde_json::from_str::<serde_json::Value>(text).map_err(|e| {
            Error::Config(format!(
                "{} 不是合法 JSON（{e}）；请手工修复后重试",
                path.display()
            ))
        })?,
        None => serde_json::json!({}),
    };
    merge(&mut doc, key, subkey, entry);
    Ok(Planned {
        path,
        content: format!("{}\n", serde_json::to_string_pretty(&doc)?),
        original,
    })
}

fn merge_json_key(doc: &mut serde_json::Value, key: &str, subkey: &str, entry: &serde_json::Value) {
    if !doc.is_object() {
        *doc = serde_json::json!({});
    }
    let obj = doc.as_object_mut().unwrap();
    let inner = obj.entry(key).or_insert_with(|| serde_json::json!({}));
    if !inner.is_object() {
        *inner = serde_json::json!({});
    }
    inner
        .as_object_mut()
        .unwrap()
        .insert(subkey.to_string(), entry.clone());
}

fn merge_hook(doc: &mut serde_json::Value, key: &str, subkey: &str, entry: &serde_json::Value) {
    if !doc.is_object() {
        *doc = serde_json::json!({});
    }
    let obj = doc.as_object_mut().unwrap();
    let hooks = obj.entry(key).or_insert_with(|| serde_json::json!({}));
    if !hooks.is_object() {
        *hooks = serde_json::json!({});
    }
    let list = hooks
        .as_object_mut()
        .unwrap()
        .entry(subkey)
        .or_insert_with(|| serde_json::json!([]));
    if !list.is_array() {
        *list = serde_json::json!([]);
    }
    let arr = list.as_array_mut().unwrap();
    // 已有 airlock hook 则替换（幂等）；否则追加
    let cmd_text = entry
        .pointer("/hooks/0/command")
        .and_then(|c| c.as_str())
        .unwrap_or("airlock hook");
    arr.retain(|e| {
        e.pointer("/hooks/0/command")
            .and_then(|c| c.as_str())
            .map(|c| !c.contains("airlock"))
            .unwrap_or(true)
    });
    let _ = cmd_text;
    arr.push(entry.clone());
}

fn merge_opencode(doc: &mut serde_json::Value, key: &str, subkey: &str, entry: &serde_json::Value) {
    merge_json_key(doc, key, subkey, entry);
}

fn toml_plan(path: PathBuf, section_text: &str, marker: &str) -> Result<Planned> {
    let original = std::fs::read_to_string(&path).ok();
    let content = match &original {
        Some(text) => {
            if text.contains(marker) {
                text.clone() // 已配置，幂等
            } else {
                format!("{text}{section_text}")
            }
        }
        None => format!("{}\n", section_text.trim_start_matches('\n')),
    };
    Ok(Planned {
        path,
        content,
        original,
    })
}
