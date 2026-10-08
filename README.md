# Airlock v2.0.0 — One repo. Many agents. Zero collisions.

> v2.0.0 新增：**F12 政策即代码**（`airlock.policy.toml` 在 claim 时驱动内核拒绝）
> 与 **F13 凭据作用域代理**（凭据随租约发放，释放 ≤60s 内吊销）。见 [政策 cookbook](docs/policy-cookbook.md)。

## 一键安装

```bash
curl -fsSL https://raw.githubusercontent.com/a742987/airlock/main/scripts/install.sh | sh
```

需要 Rust 1.80+（脚本会自动检查并给出 rustup 链接）；Windows 请在 WSL2 中执行。
装完即打印下一步命令，或直接看[快速开始](#快速开始60-秒linuxmacoswsl2只演示-l1)。

> 注：install.sh 固定安装最新发布 tag（当前 `v2.0.0`，按仓库内 Cargo.lock 复现构建），
> 每次发版后脚本内的 `TAG` 变量会随之更新。

> 两个 agent 单测全绿、合并互毁——《Passes Alone, Fails Together》(UMD, SPLASH/ISSTA 2026) 实测现象，
> 也是你开两个 Claude Code 的日常。Airlock 用内核级文件租约让它**物理上不可能**发生。

**Airlock 是多 AI 编程代理共享工作区的协调运行时**：文件租约由内核强制执行、共享资源自动分配、
协作状态随租约生命周期自动维护。不是建议 agent 别碰，是让它碰不了。

- 📋 产品设计规范（PRD）：[Airlock-产品设计规范.md](Airlock-产品设计规范.md)
- 🗺️ 项目发展规划（战略与路线图 v10.0.0）：[Airlock-项目发展规划.md](Airlock-项目发展规划.md)
- 📡 租约协议规范：[docs/protocol.md](docs/protocol.md)

## 快速开始（60 秒，Linux/macOS/WSL2）——只演示 L1

```bash
# 构建（Rust 1.80+）
cargo build --release
export PATH="$PWD/target/release:$PATH"

cd your-repo
airlock daemon start      # 常驻守护进程（租约唯一权威事实源）
airlock doctor            # 三行看懂：当前层、内核能力、一条建议
airlock init claude-code  # 自动写入 MCP 配置 + PreToolUse hook（可 --undo 回滚）
```

然后正常开你的 agent。第一次 `Edit` 前自动 claim，无需任何手工配置：

```bash
$ airlock claim 'src/auth/**' --intent '修复登录超时'
✓ 租约已建立 94a80dee-c506-4cc8-af87-ab726854c050 (src/auth/**)

$ airlock claim 'src/auth/login.ts'   # ← 第二个 agent
✗ 无法 claim src/auth/login.ts —— 该路径由 agent-A（会话 sess）持有，约 29 分钟后释放。
  建议：先做无冲突路径的工作（清单见 airlock status --free），或等待后重试。
```

## 为什么不是 worktree / 容器隔离？

| | worktree / 容器隔离 | Airlock |
|---|---|---|
| 冲突处理 | **推迟**到 merge（workmux README 自认"worktree 不防止 merge conflict"） | **claim 时拒绝**，冲突在发生前消失 |
| 工作流 | 每个 agent 一份 checkout，心智负担重 | 同一目录、同一分支，agent 直接协作 |
| 资源 | 各自起 dev server / 数据库 | 端口段自动分配、会话级数据库分支 |
| 交接 | 无 | 冲突域黑板：后来者先读到"别人在做什么" |

## 它怎么拦得住 `sed -i`？——三层强制

agent 绕过 MCP 直接跑 `sed -i`？advisory 派到此为止，Airlock 还有内核：

| 层 | 平台 | 环境 | 体验 |
|---|---|---|---|
| **L1 Advisory** | 全平台 | 零依赖 | MCP/CLI/hook 层拒绝越权 claim |
| **L2 Landlock** | Linux ≥5.13（含 WSL2） | 非 root | `airlock run` 包装器：写操作仅限租约路径，真实 `-EPERM` |
| **L3 BPF-LSM** | Linux | root | **规划中，尚未实现**：v0.x 仅探测内核能力（root + LSM 启用 bpf + BTF），`available()` 恒为 false，`doctor` 明示"未实现"原因；auto 模式只会选 L2/L1 |

```bash
$ airlock run --claim 'src/auth/**' -- sh -c 'echo x > src/api/main.rs'
🔒 Landlock 已启用：写操作仅限租约路径
sh: 1: cannot create src/api/main.rs: Permission denied   # ← 内核拒绝

$ airlock run --claim 'src/auth/**' -- sh -c "sed -i 's/x/y/' src/api/other.ts"
sed: cannot rename ...: Permission denied                  # ← sed -i 也拦得住
```

L2 规则是**进程作用域**的：agent 退出即消失，daemon 崩溃零残留（`airlock doctor` 可验证）。
失败模式全部显式可见（P2：绝不静默降级）——daemon 不可达时 CLI/hook 打印黄色警告并 fail-open。

## 让编队像团队一样交接

```bash
airlock claim 'src/api/**' --intent '订单分页'   # 意图写入黑板
airlock board read                               # 后来者先读：别人在做什么、有什么坑
airlock tower                                    # TUI：租约/资源/事件/黑板 一屏
airlock log --verify                             # hash-chained 审计日志防篡改校验
```

审计日志是不可抵赖的事实源：冲突预测读租约表，黑板归档摘要由审计日志驱动；内核写的记录不可抵赖。

## 政策即代码：规则写进仓库，内核来执行（F12）

把治理规则写成 `airlock.policy.toml` 入库提交，claim 时由政策引擎求值——
deny 的路径在 claim 层被 409 拒绝，在 L2 下更会被**内核**拒绝（真实 `-EPERM`）：

```toml
# airlock.policy.toml
[paths.deny]
"vault/**" = "密钥区，agent 一律禁触"

[paths.allow]
"src/**"   = "*"
"tests/**" = "e2e-bot, ci-bot"
```

```bash
$ airlock policy check --glob 'vault/key.pem'
  ✗ 干跑 vault/key.pem（agent=cli）：拒绝（path_denied，规则 vault/**）

$ airlock run --claim 'src/**' -- sh -c 'echo x > vault/key.pem'
sh: 1: cannot create vault/key.pem: Permission denied   # ← 内核拒绝
```

政策不存在 = 零配置全放行（进阶而非门槛，P3）；存在且非法 → claim 拒绝、daemon
拒绝启动（fail-closed）。政策加载/拒绝入审计（含 sha256），入库提交即可追溯。
完整配方见[政策 cookbook](docs/policy-cookbook.md)。

## 凭据随租约发放与吊销（F13）

agent 需要测试库凭据？claim 时按资源名发放，**租约释放 ≤60s 内吊销**（sweeper
1 秒周期）——后端可插拔：本地凭据源文件或 HashiCorp Vault 动态密钥：

```bash
$ airlock claim 'src/**' --cred app-db
✓ 租约已建立 94a80dee (src/**)
✓ 凭据 1 项已随租约发放（AIRLOCK_DB_URL）：释放即吊销

$ airlock creds list     # env 值脱敏，只见变量名
$ airlock creds revoke <cred-id>   # 管理员立即吊销
```

边界（安全设计）：只代理**测试资源凭据**；提交密钥与仓库凭据（git push token /
SSH key）永不经过 Airlock 进程。

## 命令空间

```
airlock init [agent]        # claude-code / codex / gemini / cursor / opencode（--undo 回滚；
                            #  MCP 与 hook 注入同一 AIRLOCK_SESSION_ID，会话身份统一）
airlock claim <glob> [--intent] [--ttl 30m] [--cred <资源>]
airlock release <lease-id | --all>
airlock heartbeat <lease-id>  # 手动续约：纯 CLI claim 不自动续约（30 分钟 TTL 后过期），
                              # run / MCP / hook 路径由其内置心跳线程自动续约
airlock report-cost <lease-id> --tokens 1000 --cost-cents 50   # F6 成本归因
airlock rollback <lease-id>   # F7 隔离回滚：恢复该租约变更的文件
airlock snapshots             # F7 快照列表
airlock policy check [--glob <glob>] [--agent <a>] [--ttl <s>]   # F12 政策校验 + 干跑
airlock creds list [--lease <id>] | creds revoke <cred-id>       # F13 凭据
airlock status [--json] [--free]
airlock log [--verify] [--since 1h] [--json]
airlock doctor              # 层探测 + 健康检查 + 升级建议（退出码恒 0）
airlock tower               # TUI 仪表盘
airlock board read|write    # 冲突域黑板
airlock run -- <cmd>        # L2 Landlock 包装器（含政策 deny 的内核排除）
airlock daemon start|stop
```

退出码（v1.0 起冻结）：`0` 成功 · `1` 内部错误（I/O、存储等） · `2` 冲突 / 未授权拒绝（含政策拒绝） · `3` 未找到 · `4` daemon 不可达 · `5` 配置或用法错误（含命令行参数错误） · `130` 中断。

每个命令支持 `--json`（模型/脚本）、`--no-color`、`--quiet`（CI）、`--config`（P4：机器可读与人类可读同权）。

**API 稳定性承诺（v1.0 起）**：MCP 工具名/参数、CLI 退出码、租约协议版本化（semver）；
破坏性变更走 RFC + 一个大版本的弃用期。租约协议规范见 [docs/protocol.md](docs/protocol.md)（现为 v2，v1.0 冻结面全部兼容，v2.0 变更均为 additive）。

## 架构

```
┌───────────────────────────────────────────────────────────┐
│  客户端进程（agent / 用户拉起，各自独立）                    │
│  ┌───────────────────────┐  ┌─────────────────────────┐   │
│  │ MCP Server            │  │ CLI / tower TUI         │   │
│  │ `airlock mcp`——agent  │  │ `airlock …`——经 unix    │   │
│  │ 以 stdio 拉起的       │  │ socket 访问 daemon      │   │
│  │ 独立进程，非 daemon 内 │  │                         │   │
│  │ 部件                  │  │                         │   │
│  └───────────────────────┘  └─────────────────────────┘   │
└──────────────┬────────────────────────────────────────────┘
               │ unix socket（JSON 行协议）
┌──────────────▼────────────────────────────────────────────┐
│                     airlockd (Rust daemon)                  │
│  ┌─────────┐ ┌──────────┐ ┌──────────┐ ┌────────────────┐ │
│  │ Lease   │ │ Resource │ │ Black-   │ │ Audit Log      │ │
│  │ Engine  │ │ Allocator│ │ board    │ │ (hash-chained, │ │
│  │ (SQLite)│ │ ports/DB │ │          │ │ + .head 锚点)  │ │
│  └─────────┘ └──────────┘ └──────────┘ └────────────────┘ │
│  ┌─────────────────────┐ ┌──────────────────────────────┐ │
│  │ Policy Engine (F12) │ │ Credential Broker (F13)      │ │
│  │ airlock.policy.toml │ │ file / Vault 后端，随租约     │ │
│  │ claim 时驱动内核拒绝 │ │ 发放与吊销（≤60s）             │ │
│  └─────────────────────┘ └──────────────────────────────┘ │
└──────────────┬────────────────────────────────────────────┘
               │
┌──────────────▼────────────────────────────────────────────┐
│ Enforcement backends（同一探测 trait，可插拔）               │
│  L1 advisory ← 全平台兜底                                  │
│  L2 Landlock ← Linux 非 root（`airlock run` 包装器落地）    │
│  L3 BPF-LSM ← Linux root（规划中：v0.x 仅内核能力探测，     │
│  available() 恒 false，auto 恒选 L2/L1）                    │
└───────────────────────────────────────────────────────────┘
```

## 数据安全

- git 仓库内，审计日志存 `<git-common-dir>/airlock/`；非 git 目录存 `<cwd>/.airlock/`——**永不离开本机**；
- daemon 最小权限运行；L2 走内核 Landlock，无需 root；
- 提交密钥与仓库凭据不经过 Airlock 进程（F13 只代理测试资源凭据，边界见协议规范 §3.2）；
- 零遥测（默认关闭，且 v0.x 未实现采集）。

**信任模型**：Airlock 假定单用户开发机信任模型：daemon 的 Unix socket 与 SQLite 数据目录按 0600/0700 权限保护，多用户共享机器上的其他本地用户不在信任边界内。

## 许可

MIT OR Apache-2.0（个人与团队自用**永不收费**；Team 商业许可见路线图 v5.0）。

## Contributing

见 [CONTRIBUTING.md](CONTRIBUTING.md)；安全问题走 [SECURITY.md](SECURITY.md) 私密披露通道。
