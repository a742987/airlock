//! `airlock` CLI 入口（§5.1 命令空间 v0.1 全量）。
//!
//! 全局行为（§6.1）：`--json` / `--no-color` / `--quiet` / `--config` 全命令支持；
//! 退出码 0/2/3/4/5/130 冻结（v1.0 起是 API 的一部分）。

mod commands;
mod hook;
mod init;
mod mcp;
mod output;
mod run;
mod tower;

use clap::{Parser, Subcommand};

use airlock_core::error::Error;

#[derive(Parser)]
#[command(
    name = "airlock",
    version,
    about = "One repo. Many agents. Zero collisions.",
    long_about = "Airlock —— 多 AI 编程代理共享工作区的协调运行时：文件租约由内核强制执行，\
                  共享资源自动分配，协作状态随租约生命周期自动维护。"
)]
struct Cli {
    /// 输出 JSON（P4：机器可读与人类可读同权）
    #[arg(long, global = true)]
    json: bool,
    /// 禁用彩色输出（非 TTY 自动禁用）
    #[arg(long, global = true)]
    no_color: bool,
    /// 安静模式（CI 友好：只输出结果本体）
    #[arg(long, global = true)]
    quiet: bool,
    /// 指定配置文件（默认 <root>/airlock.toml）
    #[arg(long, global = true)]
    config: Option<std::path::PathBuf>,
    /// 指定工作目录（默认当前目录）
    #[arg(long, global = true)]
    root: Option<std::path::PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// 配置 agent 的 hooks + MCP 接入（交互确认，绝不静默覆盖）
    Init {
        /// agent：claude-code / codex / gemini / cursor / opencode
        agent: Option<String>,
        /// 回滚 init 的全部改动（AC：回滚方案就绪）
        #[arg(long)]
        undo: bool,
        /// 跳过确认（CI / 自动化）
        #[arg(long)]
        yes: bool,
    },
    /// 按 glob 申请独占租约（带 TTL 与心跳续约；纯 CLI 不自动续约）
    Claim {
        /// 路径模式，如 src/auth/**
        glob: String,
        /// 黑板意图（做什么/为什么，FR5.1）
        #[arg(long)]
        intent: Option<String>,
        /// TTL：秒数或时长（1800 / 30m / 1h），默认 30 分钟
        #[arg(long)]
        ttl: Option<String>,
        /// F13：随租约发放凭据的资源名（如测试库 app-db），释放即吊销
        #[arg(long)]
        cred: Option<String>,
    },
    /// 释放租约
    Release {
        /// 租约 ID；省略时用 --all
        lease_id: Option<String>,
        /// 释放当前会话全部租约
        #[arg(long)]
        all: bool,
    },
    /// 租约心跳续约
    Heartbeat { lease_id: String },
    /// 上报租约的 token 消耗和成本（F6 成本归因）
    ReportCost {
        /// 租约 ID
        lease_id: String,
        /// 本次消耗的 token 数
        #[arg(long, default_value = "0")]
        tokens: u64,
        /// 本次消耗的成本（美分）
        #[arg(long, default_value = "0")]
        cost_cents: u64,
    },
    /// 回滚租约：恢复该租约变更的文件到租约开始时的状态（F7 隔离回滚）
    Rollback {
        /// 租约 ID
        lease_id: String,
    },
    /// 列出所有租约快照（F7）
    Snapshots,
    /// 列出租约 + 资源分配 + 当前强制层
    Status {
        /// 只显示无冲突的一级目录（rejection 建议 refer 的清单）
        #[arg(long)]
        free: bool,
    },
    /// 审计日志（hash-chained）
    Log {
        /// 校验 hash 链完整性（AC1.4）
        #[arg(long)]
        verify: bool,
        /// 起始时间，如 1h / 30m / 3600（秒）
        #[arg(long)]
        since: Option<String>,
    },
    /// 强制层探测 + 健康检查 + 升级建议（不阻塞）
    Doctor,
    /// F12 政策即代码：校验 airlock.policy.toml 并干跑决策
    #[command(subcommand)]
    Policy(PolicyCmd),
    /// F13 凭据代理：查看与吊销随租约发放的凭据
    #[command(subcommand)]
    Creds(CredsCmd),
    /// 冲突域黑板（v0.2 F11）
    #[command(subcommand)]
    Board(BoardCmd),
    /// daemon 生命周期
    #[command(subcommand)]
    Daemon(DaemonCmd),
    /// TUI 仪表盘（v0.3 F6）
    Tower,
    /// 在租约保护下运行命令（L2 Landlock 进程级强制）
    #[command(disable_help_flag = true)]
    Run {
        /// 包装器参数
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// 内部：agent hook 处理器（由 init 写入 agent 配置）
    #[command(hide = true)]
    Hook {
        #[arg(default_value = "pretooluse")]
        event: String,
    },
    /// 内部：MCP stdio server（由 agent 以 MCP 方式拉起）
    #[command(hide = true)]
    Mcp,
}

#[derive(Subcommand)]
pub enum PolicyCmd {
    /// 校验政策文件并干跑决策（--glob 指定申请路径；无 --glob 时打印政策摘要）
    Check {
        /// 干跑的申请路径模式（如 src/auth/**）
        #[arg(long)]
        glob: Option<String>,
        /// 干跑的 agent（默认 cli）
        #[arg(long)]
        agent: Option<String>,
        /// 干跑的 TTL（秒）
        #[arg(long)]
        ttl: Option<i64>,
    },
}

#[derive(Subcommand)]
pub enum CredsCmd {
    /// 列出凭据发放记录（env 值脱敏为变量名清单；--lease 过滤）
    List {
        #[arg(long)]
        lease: Option<String>,
    },
    /// 立即吊销凭据（管理员；租约释放后 sweeper 也会在 ≤60s 内自动吊销）
    Revoke { cred_id: String },
}

#[derive(Subcommand)]
enum BoardCmd {
    /// 读取黑板（活动条目 + 7 天归档摘要，token 预算受控）
    Read {
        /// token 预算（默认 500）
        #[arg(long)]
        budget: Option<usize>,
    },
    /// 写入黑板条目
    Write {
        body: String,
        #[arg(long)]
        lease_id: Option<String>,
    },
}

#[derive(Subcommand)]
enum DaemonCmd {
    /// 启动 daemon（默认后台；安装器通常托管）
    Start {
        #[arg(long)]
        foreground: bool,
    },
    /// 停止 daemon
    Stop,
    /// 内部：前台拉起 airlockd（start 派生用）
    #[command(hide = true)]
    Spawn,
}

fn main() {
    // 用法错误退出码 5（冻结表：2 = 冲突拒绝，clap 默认的 2 会让脚本
    // 把「命令写错了」误当「冲突应重试」）；--help/--version 仍是 0
    let cli = match Cli::try_parse() {
        Ok(c) => c,
        Err(e) => {
            if e.use_stderr() {
                eprint!("{e}");
                std::process::exit(5);
            } else {
                // help/version：输出到 stdout
                let _ = e.print();
                std::process::exit(0);
            }
        }
    };
    let code = real_main(&cli);
    std::process::exit(code);
}

fn real_main(cli: &Cli) -> i32 {
    let out = output::Output::new(cli.json, cli.no_color, cli.quiet);
    let ctx = match commands::Ctx::new(cli.root.as_deref(), cli.config.as_deref(), out.clone()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            return e.exit_code();
        }
    };
    let r = match &cli.command {
        Command::Init { agent, undo, yes } => init::run(&ctx, agent.as_deref(), *undo, *yes),
        Command::Claim {
            glob,
            intent,
            ttl,
            cred,
        } => commands::claim(
            &ctx,
            glob,
            intent.as_deref(),
            ttl.as_deref(),
            cred.as_deref(),
        ),
        Command::Release { lease_id, all } => commands::release(&ctx, lease_id.as_deref(), *all),
        Command::Heartbeat { lease_id } => commands::heartbeat(&ctx, lease_id),
        Command::ReportCost {
            lease_id,
            tokens,
            cost_cents,
        } => commands::report_cost(&ctx, lease_id, *tokens, *cost_cents),
        Command::Rollback { lease_id } => commands::rollback(&ctx, lease_id),
        Command::Snapshots => commands::list_snapshots(&ctx),
        Command::Status { free } => commands::status(&ctx, *free),
        Command::Log { verify, since } => commands::log(&ctx, *verify, since.as_deref()),
        Command::Doctor => commands::doctor(&ctx),
        Command::Policy(PolicyCmd::Check { glob, agent, ttl }) => {
            commands::policy_check(&ctx, glob.as_deref(), agent.as_deref(), *ttl)
        }
        Command::Creds(cmd) => commands::creds(&ctx, cmd),
        Command::Board(cmd) => commands::board(&ctx, cmd),
        Command::Daemon(DaemonCmd::Spawn) => Ok(commands::spawn_daemon_foreground(&ctx)),
        Command::Daemon(cmd) => commands::daemon(&ctx, cmd),
        Command::Tower => tower::run(&ctx),
        Command::Run { args } => run::run_wrapped(&ctx, args),
        Command::Hook { event } => hook::handle(&ctx, event),
        Command::Mcp => mcp::serve(&ctx),
    };
    match r {
        Ok(code) => code,
        Err(e) => {
            match &e {
                Error::Conflict(rej) if !cli.json => {
                    // P1：人类可读拒绝已渲染在载荷里
                    out.println_stderr(&rej.human);
                }
                other if !cli.json => {
                    out.println_stderr(&format!("✗ {other}"));
                }
                _ => {}
            }
            if cli.json {
                let payload = match &e {
                    Error::Conflict(rej) => serde_json::to_value(&**rej).unwrap_or_default(),
                    other => serde_json::json!({ "error": other.to_string() }),
                };
                out.println_stdout(&serde_json::to_string_pretty(&payload).unwrap_or_default());
            }
            e.exit_code()
        }
    }
}
