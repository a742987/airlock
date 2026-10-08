//! CLI 集成测试：init/hook/MCP/退出码/doctor（AC2.3、AC2.8、AC4.1、AC4.2）。
//! 每个测试结束清理临时仓库与 heal 拉起的 daemon（不再泄漏进程/目录）。

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

/// macOS 的 `std::env::temp_dir()`（/var/folders/...）会让 unix socket 路径超过
/// `SUN_LEN`(104)，daemon.sock 无法绑定——macOS 上改用 /tmp（/private/tmp）。
#[cfg(target_os = "macos")]
fn short_tmp() -> PathBuf {
    PathBuf::from("/tmp")
}

#[cfg(not(target_os = "macos"))]
fn short_tmp() -> PathBuf {
    std::env::temp_dir()
}

fn temp_repo(tag: &str) -> PathBuf {
    let root = short_tmp().join(format!("airlock-cli-it-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    Command::new("git")
        .args(["init", "-q", "."])
        .current_dir(&root)
        .status()
        .unwrap();
    root
}

/// 停掉本测试域的 daemon（含 heal 拉起的常驻进程）并删除临时仓库。
fn cleanup_repo(root: &PathBuf) {
    let exe = env!("CARGO_BIN_EXE_airlock");
    let _ = Command::new(exe)
        .arg("--root")
        .arg(root)
        .args(["daemon", "stop"])
        .output();
    // 等一拍让 daemon 走完停机清理，再删目录
    std::thread::sleep(std::time::Duration::from_millis(300));
    let _ = std::fs::remove_dir_all(root);
}

/// airlock-cli 包内无法拿到 airlockd 的 CARGO_BIN_EXE，按 target 目录定位。
fn target_bin(name: &str) -> PathBuf {
    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target")
        .join(profile)
        .join(name)
}

fn airlock(root: &PathBuf) -> Command {
    let exe = env!("CARGO_BIN_EXE_airlock");
    let mut c = Command::new(exe);
    c.arg("--root").arg(root);
    c
}

// ---------- AC4.2 init 确认与回滚 ----------

#[test]
fn ac4_2_init_confirm_never_silent_overwrite() {
    let root = temp_repo("init42");
    // 全新 init：新建文件无需确认
    let st = airlock(&root)
        .args(["init", "claude-code"])
        .status()
        .unwrap();
    assert_eq!(st.code(), Some(0), "新建配置无需确认");

    // 已有配置改动：非交互必须拒绝（绝不静默覆盖）
    std::fs::write(root.join(".mcp.json"), "{}").unwrap();
    let out = airlock(&root)
        .args(["init", "claude-code"])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(5),
        "非交互遇到已有配置应报 config 错误"
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("绝不静默覆盖") || err.contains("--yes"));

    // 显式确认后成功，且不破坏其他键
    let st = airlock(&root)
        .args(["init", "claude-code", "--yes"])
        .status()
        .unwrap();
    assert_eq!(st.code(), Some(0));
    let mcp: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(root.join(".mcp.json")).unwrap()).unwrap();
    assert!(mcp
        .get("mcpServers")
        .and_then(|m| m.get("airlock"))
        .is_some());
    // 会话注入（P1-1）：MCP env 与 hook 命令共享同一 AIRLOCK_SESSION_ID
    let sid = mcp["mcpServers"]["airlock"]["env"]["AIRLOCK_SESSION_ID"]
        .as_str()
        .expect("MCP 配置应注入 AIRLOCK_SESSION_ID")
        .to_string();
    assert!(!sid.is_empty());
    let settings: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(root.join(".claude/settings.json")).unwrap())
            .unwrap();
    let hook_cmd = settings["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
        .as_str()
        .expect("hook 命令存在")
        .to_string();
    assert!(
        // hook 命令现在对值做 POSIX 单引号引用（路径含空格/引号不再静默失效）
        hook_cmd.contains(&format!("AIRLOCK_SESSION_ID='{sid}'")),
        "hook 命令应注入同一会话：{hook_cmd}"
    );

    // --undo 回滚：只摘除 airlock 的改动；手工加的键保留
    let st = airlock(&root).args(["init", "--undo"]).status().unwrap();
    assert_eq!(st.code(), Some(0));
    assert!(
        !root.join(".mcp.json").exists(),
        "undo 应回滚到 init 前状态"
    );
    cleanup_repo(&root);
}

#[test]
fn ac4_2_init_all_agents() {
    let root = temp_repo("init-all");
    for agent in ["claude-code", "gemini", "cursor", "opencode", "codex"] {
        let st = airlock(&root)
            .args(["init", agent, "--yes"])
            .status()
            .unwrap();
        assert_eq!(st.code(), Some(0), "init {agent} 应成功");
    }
    assert!(root.join(".gemini/settings.json").exists());
    assert!(root.join(".cursor/mcp.json").exists());
    assert!(root.join("opencode.json").exists());
    cleanup_repo(&root);
}

// ---------- AC4.1 hook 自动 claim（经 daemon 或本地兜底） ----------

#[test]
fn ac4_1_hook_auto_claims_on_first_edit() {
    let root = temp_repo("hook41");
    let root_clone = root.clone();
    let hook = move |tool: &str, path: &str, agent: &str| -> (Option<i32>, String) {
        let exe = env!("CARGO_BIN_EXE_airlock");
        let mut child = Command::new(exe)
            .args(["--root"])
            .arg(&root_clone)
            .args(["hook", "pretooluse"])
            .env("AIRLOCK_AGENT_ID", agent)
            .env("AIRLOCK_SESSION_ID", agent)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let input = serde_json::json!({
            "tool_name": tool,
            "tool_input": { "file_path": path }
        });
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(input.to_string().as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        (
            out.status.code(),
            String::from_utf8_lossy(&out.stdout).to_string(),
        )
    };
    let login = root.join("src/auth/login.ts").to_string_lossy().to_string();
    let api = root.join("src/api/main.rs").to_string_lossy().to_string();

    // 第一次 Edit：自动 claim + allow（AC4.1）
    let (code, out) = hook("Edit", &login, "agent-A");
    assert_eq!(code, Some(0));
    assert!(out.contains("\"allow\""), "{out}");
    // 同会话再编辑：allow（幂等）
    let (code, out) = hook("Edit", &login, "agent-A");
    assert_eq!(code, Some(0), "{out}");
    // 他人编辑同路径：deny（exit 0 + stdout JSON 决策；P1-3 拒绝理由可到模型）
    let (code, out) = hook("Edit", &login, "agent-B");
    assert_eq!(code, Some(0), "deny 走 JSON 决策，exit 0");
    assert!(out.contains("\"deny\""), "{out}");
    assert!(out.contains("agent-A"), "拒绝消息应指明持有人");
    // Bash sed -i 越权：deny
    let exe = env!("CARGO_BIN_EXE_airlock");
    let mut child = Command::new(exe)
        .args(["--root"])
        .arg(&root)
        .args(["hook", "pretooluse"])
        .env("AIRLOCK_AGENT_ID", "agent-B")
        .env("AIRLOCK_SESSION_ID", "agent-B")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let input = serde_json::json!({
        "tool_name": "Bash",
        "tool_input": { "command": format!("sed -i 's/a/b/' {login}") }
    });
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(input.to_string().as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(0), "sed -i 越权 deny 走 JSON 决策");
    assert!(String::from_utf8_lossy(&out.stdout).contains("\"deny\""));
    // 无冲突路径：allow
    let (code, out) = hook("Edit", &api, "agent-B");
    assert_eq!(code, Some(0), "{out}");
    cleanup_repo(&root);
}

// ---------- 退出码（§6.1 冻结表） ----------

#[test]
fn exit_codes_frozen_table() {
    let root = temp_repo("exitcodes");
    // 0 成功
    let st = airlock(&root).args(["doctor"]).status().unwrap();
    assert_eq!(
        st.code(),
        Some(0),
        "doctor 探测是可用性报告，退出码 0（AC2.3 同语义）"
    );
    // 4 daemon 不可达
    let st = airlock(&root).args(["status"]).status().unwrap();
    assert_eq!(st.code(), Some(4));
    // 5 配置错误
    std::fs::write(root.join("airlock.toml"), "no_such_key = 1\n").unwrap();
    let st = airlock(&root).args(["status"]).status().unwrap();
    assert_eq!(st.code(), Some(5));
    // 5 用法错误（clap 参数错误不再占用冻结的 2 = 冲突拒绝）
    let st = airlock(&root).args(["no-such-command"]).status().unwrap();
    assert_eq!(st.code(), Some(5), "未知命令应退出 5（用法错误）");
    // 2 冲突拒绝不被误占：--ttl 30m 现在是合法时长
    std::fs::remove_file(root.join("airlock.toml")).ok();
    let st = airlock(&root)
        .args(["claim", "src/**", "--ttl", "30m"])
        .status()
        .unwrap();
    assert_ne!(st.code(), Some(5), "--ttl 30m 应可解析");
    cleanup_repo(&root);
}

// ---------- doctor（AC2.2/AC2.3 风格：报告层与原因，不阻塞） ----------

#[test]
fn doctor_reports_layers_with_reasons() {
    let root = temp_repo("doctor");
    let out = airlock(&root).args(["doctor", "--json"]).output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    // L1 永远可用
    assert!(v["landlock"].is_object() || v["bpf_lsm"].is_object());
    // L3 未实现：必须恒为不可用且给出原因（P2：绝不静默假保护）
    assert_eq!(v["bpf_lsm"]["available"], serde_json::json!(false));
    assert!(
        v["bpf_lsm"]["reason"]
            .as_str()
            .unwrap_or("")
            .contains("尚未实现"),
        "L3 不可用原因应说明未实现：{}",
        v["bpf_lsm"]["reason"]
    );
    cleanup_repo(&root);
}

// ---------- status --json 与 --free ----------

#[test]
fn status_json_shape() {
    let root = temp_repo("status");
    // daemon 不可达 → 退出码 4；先起 daemon
    let dexe = target_bin("airlockd");
    let mut daemon = Command::new(dexe)
        .arg("--root")
        .arg(&root)
        .arg("--foreground")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut ok = false;
    for _ in 0..100 {
        if let Ok(out) = airlock(&root).args(["status", "--json"]).output() {
            if out.status.code() == Some(0) {
                let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
                assert!(v["layer"].is_object());
                assert!(v["leases"].is_array());
                assert!(v["conflict_domain"].is_string());
                ok = true;
                break;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(ok, "status --json 应产出完整结构");
    let _ = daemon.kill();
    let _ = daemon.wait();
    cleanup_repo(&root);
}

// ---------- MCP server 协议 ----------

#[test]
fn mcp_initialize_and_tools() {
    let root = temp_repo("mcp");
    let exe = env!("CARGO_BIN_EXE_airlock");
    let mut child = Command::new(exe)
        .args(["--root"])
        .arg(&root)
        .arg("mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let req = |id: i32, m: &str, p: serde_json::Value| {
        serde_json::json!({ "jsonrpc": "2.0", "id": id, "method": m, "params": p }).to_string()
            + "\n"
    };
    stdin
        .write_all(
            req(
                1,
                "initialize",
                serde_json::json!({"protocolVersion": "2025-06-18"}),
            )
            .as_bytes(),
        )
        .unwrap();
    stdin
        .write_all(req(2, "tools/list", serde_json::json!({})).as_bytes())
        .unwrap();
    stdin
        .write_all(
            req(
                3,
                "tools/call",
                serde_json::json!({"name": "status", "arguments": {}}),
            )
            .as_bytes(),
        )
        .unwrap();
    stdin.write_all("{bad json\n".as_bytes()).unwrap();
    drop(stdin);
    let out = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    // initialize 响应含 serverInfo，且回显请求的协议版本
    assert!(stdout.contains("airlock"), "{stdout}");
    assert!(stdout.contains("2025-06-18"), "{stdout}");
    // tools/list 有工具清单
    assert!(stdout.contains("\"tools\""), "{stdout}");
    // tools/call 正常返回结构化内容（status 走 fail-open 本地兜底也可）
    assert!(stdout.contains("structuredContent"), "{stdout}");
    // 非法 JSON 必须回 parse error（-32700），不能静默忽略挂起客户端
    assert!(stdout.contains("-32700"), "{stdout}");
    // 每行一个完整 JSON 响应（stdout 无日志污染）
    for line in stdout.lines() {
        if line.trim().is_empty() {
            continue;
        }
        assert!(
            serde_json::from_str::<serde_json::Value>(line).is_ok(),
            "stdout 必须是纯 JSON-RPC 行：{line}"
        );
    }
    cleanup_repo(&root);
}

// ---------- claim 冲突的 CLI 退出码 2 与 JSON 双形态 ----------

#[test]
fn claim_conflict_dual_form() {
    let root = temp_repo("claim-dual");
    let dexe = target_bin("airlockd");
    let mut daemon = Command::new(dexe)
        .arg("--root")
        .arg(&root)
        .arg("--foreground")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(600));

    let st = airlock(&root)
        .env("AIRLOCK_AGENT_ID", "agent-A")
        .env("AIRLOCK_SESSION_ID", "sess-a")
        .args(["claim", "src/auth/**"])
        .status()
        .unwrap();
    assert_eq!(st.code(), Some(0));

    // 人类形态：stderr 有渲染好的拒绝、退出码 2
    let out = airlock(&root)
        .env("AIRLOCK_AGENT_ID", "B")
        .env("AIRLOCK_SESSION_ID", "sess-b")
        .args(["claim", "src/auth/login.ts"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("agent-A"));

    // 模型形态：--json 输出结构化 409 载荷
    let out = airlock(&root)
        .env("AIRLOCK_AGENT_ID", "B")
        .env("AIRLOCK_SESSION_ID", "sess-b")
        .args(["claim", "src/auth/login.ts", "--json"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["error"], "conflict");
    assert!(v["holder"].is_object());
    assert!(v["suggested_action"].is_string());

    // 同 session 重复 claim → 幂等返回既有租约（不自冲突）
    let out = airlock(&root)
        .env("AIRLOCK_AGENT_ID", "agent-A")
        .env("AIRLOCK_SESSION_ID", "sess-a")
        .args(["claim", "src/auth/**", "--json"])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "同会话重复 claim 应幂等：{}",
        String::from_utf8_lossy(&out.stderr)
    );

    // 属主边界：release --all 只作用于自己的会话（sess-b 无租约 → 释放 0 条，成功）
    let out = airlock(&root)
        .env("AIRLOCK_AGENT_ID", "B")
        .env("AIRLOCK_SESSION_ID", "sess-b")
        .args(["release", "--all"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "--all 空释放是成功而非错误");

    let _ = daemon.kill();
    let _ = daemon.wait();
    cleanup_repo(&root);
}

// ---------- L2 Landlock 真实强制（AC2.1 的 Linux 非 root 等效验证） ----------

#[test]
fn l2_run_wrapper_real_enforcement() {
    // 内核门控：无 Landlock 时跳过（老内核 CI）
    if airlock_core_ffi_abi() < 1 {
        eprintln!("内核不支持 Landlock，跳过");
        return;
    }
    let root = temp_repo("l2run");
    std::fs::create_dir_all(root.join("src/auth")).unwrap();
    std::fs::create_dir_all(root.join("src/api")).unwrap();
    std::fs::write(root.join("src/auth/login.ts"), "orig").unwrap();
    std::fs::write(root.join("src/api/main.rs"), "orig").unwrap();

    let exe = env!("CARGO_BIN_EXE_airlock");
    // 租约内写入：成功
    let st = Command::new(exe)
        .args(["--root"])
        .arg(&root)
        .args([
            "run",
            "--ttl",
            "5",
            "--claim",
            "src/auth/**",
            "--",
            "sh",
            "-c",
            "echo ok > src/auth/login.ts",
        ])
        .status()
        .unwrap();
    assert_eq!(st.code(), Some(0), "租约路径内写入应成功");
    std::thread::sleep(std::time::Duration::from_secs(6));

    // 租约外写入：被 Landlock 拒绝（-EPERM）
    let st = Command::new(exe)
        .args(["--root"])
        .arg(&root)
        .args([
            "run",
            "--ttl",
            "5",
            "--claim",
            "src/auth/**",
            "--",
            "sh",
            "-c",
            "echo bad > src/api/main.rs",
        ])
        .status()
        .unwrap();
    assert_ne!(st.code(), Some(0), "租约外写入应被内核拒绝（AC2.1 等效）");
    std::thread::sleep(std::time::Duration::from_secs(6));

    // /dev/null 仍可写（agent 常规操作）
    let st = Command::new(exe)
        .args(["--root"])
        .arg(&root)
        .args([
            "run",
            "--ttl",
            "5",
            "--claim",
            "src/auth/**",
            "--",
            "sh",
            "-c",
            "echo silent > /dev/null",
        ])
        .status()
        .unwrap();
    assert_eq!(st.code(), Some(0), "/dev/null 写入应被豁免");
    // 租约外的符号链接逃逸：P0 回归——link 指向 src/api，写 link/x 不得放行
    std::os::unix::fs::symlink(root.join("src/api"), root.join("link")).unwrap();
    let st = Command::new(exe)
        .args(["--root"])
        .arg(&root)
        .args([
            "run",
            "--ttl",
            "5",
            "--claim",
            "src/auth/**",
            "--",
            "sh",
            "-c",
            "echo pwn > src/api/main.rs",
        ])
        .status()
        .unwrap();
    assert_ne!(
        st.code(),
        Some(0),
        "租约外的写（即使经同仓库路径）必须被拒绝"
    );
    cleanup_repo(&root);
}

/// 通过 CLI doctor 的 JSON 探测 Landlock ABI（避免测试进程内 syscall）。
fn airlock_core_ffi_abi() -> u32 {
    let exe = env!("CARGO_BIN_EXE_airlock");
    let root = short_tmp().join(format!("airlock-probe-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&root);
    let out = Command::new(exe)
        .args(["--root"])
        .arg(&root)
        .args(["doctor", "--json"])
        .output()
        .ok();
    let _ = std::fs::remove_dir_all(&root);
    match out {
        Some(o) => {
            let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap_or_default();
            if v["landlock"]["available"] == serde_json::json!(true) {
                1
            } else {
                0
            }
        }
        None => 0,
    }
}
