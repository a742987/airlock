# Airlock —— 多 AI 编程代理共享工作区的内核强制协调运行时

> 规划文档 v10.0.0（2026-10-03 定稿，远期蓝图版）
>
> **配套文档**：《Airlock-产品设计规范.md》（PRD v1.0）——本档的战略与路线图在 PRD 中展开为标准产品设计：用户故事、Given/When/Then 验收标准、CLI/TUI/MCP 接口规范、数据模型、性能预算、失效模式表、发布门禁与 HEART 度量体系。两档功能编号（F1–F15）、真空点编号（V1–V11）、版本锚点保持一致。
>
> 文档版本说明：文档版本 = 蓝图完整度，与产品版本相互独立。v10.0.0 代表"五年完整产品蓝图"——包含 11 个经复核的技术真空点、完整的产品形态/发行版/运营设计、以及 v0.1→v10.0.0 的产品路线图。
>
> 版本沿革：v1.0 初稿 → v2.0 六周执行手册+三层体验+发布打法 → v2.1 第四轮检索+产品闭环 → **v10.0.0 第五、六轮增量检索（凭据代理/策略即代码/成本计量/提交溯源/时间机器/原子事务），真空点扩至 11 个并逐条标注复核状态；升级为完整产品设计（形态矩阵、发行版、运营治理）；路线图延伸至 v10.0.0。**

---

## 0. 一页摘要（TL;DR）

| 项 | 内容 |
|---|---|
| 一句话 | 一个自托管运行时，让多个 AI 编程代理安全地在**同一目录、同一分支**并行工作并像团队一样交接——租约由内核强制执行，冲突在 claim 时预测、在 merge 时兜底，一切协作状态围绕租约生命周期自动维护 |
| 核心口号 | "One repo. Many agents. Zero collisions." / "不是建议 agent 别碰，是让它碰不了。" |
| 真空区 | 11 个经六轮检索复核的技术真空点（§2.3），核心护城河 = 动态租约驱动的内核强制；战略壁垒 = 所有功能共享同一份不可抵赖的审计数据源（§4.5 数据闭环） |
| 体验策略 | advisory（L1）是第一入口；Linux 由 Landlock（L2）/BPF-LSM（L3）进阶，Windows 由 ACL Guard（L2W，v2.5）承接真实拒绝，Minifilter（L3W）v4.0 评估——三大平台各有可用层级 |
| 执行纪律 | 协调派生态（file_reservation_paths、port-keeper-mcp）正在逼近，**窗口期 = 六周**，一切资源向 v0.1 发布倾斜 |
| 产品形态 | CLI + daemon + MCP server + TUI + SDK/插件 + IDE 集成，六种形态一个事实源；Community 开源 + Team 自托管商业许可（双轨，§4.4） |
| Star 锚点 | v1.0 时 3k★，v3.0 时 7k★，v5.0 时 10k★，v10.0 品类爆发情景 15k+★（§6.2 各版本锚点） |
| 止损线 | 第 4 周 M0 未过 → 砍端口分配；第 8 周未发布 → 重评窗口；发布 3 个月安装转化 <10% → 冻结功能专攻体验；6 个月 <500★ 且活跃趋零 → 维护模式 |

---

## 1. 产品定位

### 1.1 一句话定义

**Airlock 是多 agent 共享工作区的"协调内核"**：编排工具（Gas Town 等）决定 agent 干什么活，Airlock 保证它们干活时不打架、并且像团队一样交接工作。

- 对隔离派：**互补层**——"编排工具决定分工，Airlock 保证执行不冲突"。禁止竞争性措辞，编排工具是分发渠道。
- 对 advisory 派：**同一问题的更强保证**——"agent 守规矩时我们一样好用；它不守规矩（直接跑 sed）时，只有我们拦得住"。
- 对 Murmell（商业 SaaS）：**开源 + 自托管 + 数据不出机器**。

### 1.2 "完整产品"的定义（v10.0.0 新增）

一个完整的产品 = 用户从听到、装上、用深、依赖、付费的全旅程都有承接：

1. **听到**：官网单页 + 演示视频 + 论文背书（§8）；
2. **装上**：`curl | sh` / brew，60 秒出效果，`airlock doctor` 告诉你处在哪一层；
3. **用深**：MCP 接入 agent → TUI 观察 → 黑板协作 → 语义预警 → 快照回滚；
4. **依赖**：政策即代码进版本库、提交溯源进 CI、API 稳定性承诺（v1.0 起）；
5. **付费**：Team 自托管许可（团队模式/政策引擎/审计导出），个人永远免费。

### 1.3 技术路线一句话

agent-lock 的内核强制（eBPF-LSM）× asynkor 的多 agent 租约 × worktree-compose 的资源分配 × AgenticFlict 式基准驱动的语义预测，合成一个自托管运行时；黑板、意图合并、凭据作用域、政策即代码、隔离回滚、跨租约事务、提交溯源全部长在同一个租约数据源上。

---

## 2. 市场与查重

### 2.1 问题

2026 年"并行跑多个 coding agent"已是主流工作方式，但多 agent 共享一个工作副本时会：

- 互相覆盖对方正在编辑的文件（一个 agent 写、另一个 agent 同时读）；
- 抢占同一个 dev server 端口、争抢 `index.lock`、踩坏共享依赖；
- 冲突只在 git merge 时才爆发，且是**语义冲突**（git 文本合并发现不了）；
- agent 之间没有工作交接机制：后加入的 agent 盲目探索、重复踩坑；
- 出事后无法只撤销"某一个 agent"的改动而不伤及他人。

### 2.2 现有生态的边界（2026-10-03，六轮检索合计）

| 流派 | 代表项目 | 局限 |
|---|---|---|
| **隔离派**（市场默认） | Gas Town / claude-squad / workmux / Conductor / container-use / Cursor worktrees | 每个 agent 一个 worktree/容器；workmux README 自认"worktree 不防止 merge conflict"；冲突推迟到 merge |
| **协调派**（advisory 为主） | Foremerge / Weave / asynkor / mcp_agent_mail / gptme / Hivemind / kairo-mcp | 租约全是"建议式"；agent 绕过 MCP 直接 `sed` 就失效 |
| **强制执行**（唯一） | Murmell（商业 SaaS）/ agent-lock（开源） | Murmell 云端闭源收费；agent-lock 只支持单 agent 目录监禁 |
| **单 checkout 多 agent（新出现）** | Deskhand / Terraphim "AI Dark Factory" / port-keeper-mcp | Deskhand 垂直 Laravel 且全 advisory；Terraphim 用 file_reservation_paths（advisory 预留）；port-keeper-mcp 只管端口，与租约/审计无关 |

> **对查重结论的诚实修正**：协调派生态正在快速逼近——端口分配与文件预留的 advisory 版本均已存在。真空不在"有没有人做协调"，而在"**通用 × 内核强制 × 租约数据闭环**"（§2.3 十一点）。这既是需求成立的最好证据，也是窗口收紧的警报。

### 2.3 十一个技术真空点（经复核，附状态）

| # | 真空点 | 状态 | 一句话差异 |
|---|---|---|---|
| V1 | **动态租约驱动的内核强制** | ✅ 真空 | 现有 eBPF-for-agents 是观察、现有强制是静态沙箱；无人把租约表实时接到 LSM 钩子按会话进程树动态授权 |
| V2 | **共享目录下的资源自动分配** | ⚠️ 收窄 | port-keeper-mcp 占住裸端口分配；真空 = 与租约/审计/生命周期打通 + 配置改写 + 数据库分支 |
| V3 | **带 OS 强制的跨机协同租约** | ✅ 真空 | asynkor 跨机纯 advisory；Gas Town 联邦基于 worktree |
| V4 | **租约感知的冲突域黑板** | ✅ 真空 | Memtrace/MCP Memory Service 是通用记忆层；与租约同生命周期、由 daemon 依审计日志维护的黑板无人做 |
| V5 | **意图感知语义合并** | ✅ 真空 | AST 阵营（Mergiraf/Weave）与 LLM 阵营（MergeBERT）都只吃代码文本；意图元数据作合并先验无人做 |
| V6 | **claim 时语义冲突预测** | ◐ 半真空 | AgenticFlict 数据集已有但只有数据没有工具；tree-sitter 预测无人做 |
| V7 | **租约作用域的凭据代理** | ⚠️ 收窄 | Infisical agent-vault 等通用 broker 已有；凭据发放与租约绑定（租约释放即吊销、仅对被分配的测试库有效）未见 |
| V8 | **声明式租约政策即代码** | ⚠️ 收窄 | 通用 guardrail 框架与 agent 权限模式已有；repo 级政策文件（`airlock.policy.toml`）在 claim 时驱动内核执行未见 |
| V9 | **共享工作区的多 agent 隔离回滚** | ◐ 半真空 | Claude /rewind、Gemini /restore 已把"单 agent 按提示回滚"做成标配；共享工作区按租约时间线隔离回滚（撤 A 不伤 B）未见 |
| V10 | **跨租约原子事务** | ✅ 真空 | 检索确认无分布式事务式编辑锁协议；当前实践是"整仓重构交给一个 agent" |
| V11 | **提交级 agent 溯源** | ◐ 半真空 | CIRIS 等通用签名认证协议已有、DevSecOps 岗位已要求 provenance；coding-agent 提交溯源工具（哪个会话、哪份租约）未见 |

> 复核方法与逐条证据见附录 A。状态含义：✅ 检索未发现任何近似实现；◐ 有数据/协议/单 agent 版本，但产品化缺口明确；⚠️ 通用层已有玩家，真空仅在"与租约数据闭环打通"的集成层。

### 2.4 需求证据

- arXiv《Passes Alone, Fails Together》（马里兰大学，SPLASH/ISSTA 2026）：agent 各自补丁单测通过、合并后互毁——**README 第一屏证据**。
- OpenReview《Multi-Agent Systems Should Prioritize Concurrency Control》：函数级锁定优于文件级。
- AgenticFlict（OpenReview）：大规模 AI agent PR 合并冲突数据集——需求证据 + F5 现成基准。
- Stanford "Agent-Native Git" 研究：把 agent 执行当软件工程管理（快照/回滚/受控恢复）——方向被学术界背书。
- Ask HN / r/ClaudeAI 多个"两个 Claude Code 打架"帖；Neon、Dolt 把"database branch for agents"当产品卖点。
- Deskhand、Terraphim、port-keeper-mcp 的出现证明问题被独立重复发现——需求成立，窗口收紧。

### 2.5 诚实的市场约束

1. **macOS 与 Windows 原生占用户群大头**，内核满血强制只在 Linux → advisory 模式必须本身可用、可感知；Windows 增加 L2W ACL Guard 中间层（v2.5），不装驱动也能获得真实拒绝体验，"内核强制"是进阶而非"入场券"。
2. **市场默认是 worktree/容器隔离**，本项目要求用户改变工作流 → 用"隔离派自认的缺陷"（workmux README 原话）作说服素材。
3. **窗口期短**：advisory 预留与端口分配已被占位 → 速度是唯一护城河，与六周发布无关的功能全部推迟。
4. **单 agent 回滚已成标配**（v10.0.0 检索新确认）→ F7 必须以"多 agent 隔离回滚"为卖点，单 agent 回滚不构成差异。

---

## 3. 用户与场景

| 用户群 | 使用场景 | 价值 | 触达渠道 |
|---|---|---|---|
| 职业程序员 | 同一仓库并行跑 Claude Code + Codex（修 bug + 写 feature） | 不维护一堆 worktree，merge 不再惊喜 | HN、技术博客 |
| VibeCoding 爱好者 | agent 编队持续迭代个人项目 | 装上就能跑，agent 不互相拆台还会交接 | r/ClaudeAI、r/vibecoding、X |
| Agent 工具开发者 | 给 agent 框架加协调能力 | MCP server / 租约协议 / SDK 直接接入 | GitHub、MCP 目录 |
| 团队/企业（v2.0+） | 多人多 agent、合规审计、政策管控 | 自托管 + 政策即代码 + 审计导出 | Team 许可、DevSecOps 社区 |

**首要画像**：Linux/WSL2 上用 2–3 个 agent 会话并行改同一仓库的个人开发者。第一年不为企业买家做任何设计（但架构上为 v2.0 的政策/审计留钩子）。

---

## 4. 产品设计（完整产品）

### 4.1 三层体验（Star 增长的核心产品决策）

| 层 | 平台 | 环境 | 体验 | 作用 |
|---|---|---|---|---|
| L1 Advisory | 全平台 | 零依赖 | MCP 工具层拒绝越权 claim；`airlock status` 可视化 | 所有平台的兜底完整体验；快速开始只演示这层 |
| L2 Landlock | Linux | 非 root | 路径级真实拒绝（5.13+，WSL2 可用） | 演示"真的拦得住" |
| L3 BPF-LSM | Linux | root | 全路径拦截（子进程/编译器/`sed -i`） | 护城河与传播素材；`airlock doctor` 自动引导 |
| L2W ACL Guard | Windows 原生 | 用户态，无驱动 | daemon 对租约路径动态下发 NTFS deny-write ACE，release/TTL 过期即撤销（v2.5） | Windows 用户的真实拒绝体验，无需驱动与内核签名 |
| L3W Minifilter | Windows 原生 | 内核驱动 | 文件系统过滤驱动强制（仅评估，v4.0 决策点） | 对标 L3 的 Windows 满血形态；签名/维护成本高，由 L2W 采用率验证后再立项 |

叙事："L1 让你有秩序，L2/L3/L2W 让你不可能越界。"——**三大平台各有至少一层真实拒绝**：Linux（L2/L3）、Windows（L2W）、macOS（L1，EndpointSecurity v4.0 评估）。

### 4.2 功能总览（真空点 → 功能映射）

| 功能 | 名称 | 对应真空 | 版本 |
|---|---|---|---|
| F1 | 租约服务（SQLite + TTL + 心跳 + hash-chained 审计） | V1/V10 地基 | v0.1 |
| F2 | 多层强制（Linux: BPF-LSM→Landlock→advisory；Windows: ACL Guard v2.5→advisory，Minifilter v4.0 评估） | V1 | v0.1 / v2.5 |
| F3 | 资源分配（端口注入/配置改写；DB 分支；杂项锁） | V2 | v0.1/v0.2 |
| F4 | 接入层（MCP server、CLI、hooks、可读拒绝原因） | 全部入口 | v0.1 |
| F5 | 语义冲突预测（tree-sitter，claim 时预警） | V6 | v0.3 |
| F6 | TUI 仪表盘 `airlock tower`（含租约维度成本归因展示） | 观测 | v0.3 |
| F7 | 租约时间线快照与**多 agent 隔离回滚** | V9 | v0.5 |
| F8 | 跨机租约（gRPC） | V3 | v1.0 |
| F9 | 意图感知语义合并 | V5 | v1.x→v2.x |
| F10 | 团队模式（多人混合并行、RBAC、审计导出） | 商业化 | v5.0 |
| F11 | 冲突域黑板（随租约生命周期自动维护） | V4 | v0.2 |
| F12 | 政策即代码 `airlock.policy.toml`（claim 时驱动内核执行） | V8 | v2.0 |
| F13 | 凭据作用域代理（与 agent-vault/Vault 集成，凭据随租约发放与吊销） | V7 | v2.0 |
| F14 | 跨租约事务（two-phase claim，跨模块原子重构） | V10 | v3.0（实验）/v4.0（转正） |
| F15 | 提交溯源与签名（Sigstore/gitsign 集成，提交附带租约证明） | V11 | v4.0 |

> 明确不做的功能决策：**成本/预算计量不设独立功能**——该赛道已有多个专用工具（ai-cost-tracking、各网关），Airlock 只在 `tower` 里做"每个租约花了多少 token"的归因展示，作为观测维度而非产品线。

### 4.3 产品形态矩阵（六种界面，一个事实源）

| 形态 | 载体 | 用户 | 版本 |
|---|---|---|---|
| CLI | `airlock`（claim/status/release/log/doctor/init） | 人 + 脚本 | v0.1 |
| Daemon | `airlockd` 常驻 | 系统 | v0.1 |
| MCP Server | rmcp，适配 5+ 主流 agent | agent | v0.1 |
| TUI | `airlock tower`（ratatui） | 人 | v0.3 |
| SDK/插件 | Rust crate + 租约协议规范文档 | 工具开发者 | v1.0 |
| IDE 集成 | VS Code / JetBrains 插件（tower 面板内嵌） | 人 | v3.0 |

### 4.4 发行版与开源策略（决策点已在表中标注）

| 发行版 | 许可 | 内容 | 版本 |
|---|---|---|---|
| **Community** | Apache-2.0 | 全部个人开发者功能（F1–F9、F11） | v0.1 起 |
| **Team**（自托管商业许可） | 商业许可 | F10 团队模式、F12 政策引擎企业规则、审计导出/合规报告、优先支持 | v5.0 起（**决策点：v1.0 发布后根据社区构成再定**，个人永不收费的承诺写进 README） |
| 托管服务 | — | **明确不做**（数据面不出机器是与 Murmell 的根本差异） | — |

### 4.5 产品闭环：所有真空点连成一个产品

十一个真空点不是功能堆叠，而是**共享同一个事实源（租约表 + hash-chained 审计日志）的一条流水线**：

```
Claim ──→ Allocate ──→ Authorize ──→ Notify ──→ Predict ──→ Commit ──→ Merge ──→ Rollback
F1/F2      F3           F12/F13       F11         F5          F15          F9         F7
谁在改什么  后勤保障      政策+凭据     广播意图     冲突预警     签名溯源     兜底合并    隔离回滚
（骨架）                 （v2.0）     （神经）     （预警）     （v4.0）                （保险）
```

- 审计日志**同时是五处消费的数据源**：黑板内容（F11）、预测器输入（F5）、合并先验（F9）、凭据吊销依据（F13）、提交溯源证明（F15）——一份记录驱动整条流水线。
- 新 agent 加入冲突域时自动注入黑板摘要，模型不用盲目探索。
- **advisory 派无法复制这条流水线**：他们的意图记录靠模型自觉上报、可以撒谎；Airlock 的记录是内核写的、不可抵赖。差异化从"单点技术"升级为"数据闭环"。
- 对外主线："Airlock 不只让 agent 不打架，它让 agent 编队像一个团队一样交接工作。"

### 4.6 非目标（明确不做）

- 不做 agent 编排/任务分派（Gas Town、vibe-kanban 的领域）；
- 不做云端 SaaS（自托管是与 Murmell 的根本差异）；
- 不做沙箱执行环境（E2B/Daytona 的领域）；
- 不做独立成本计量产品（赛道拥挤，仅做租约维度归因展示）；
- 不做通用 agent 记忆系统（黑板只服务冲突域，不越界）；
- 不承诺解决"两个 agent 想做同一件事"的任务重叠——只保证文件/资源层不冲突（F14 解决的是"分工明确但改动跨域"的情况）。

---

## 5. 技术架构

```
┌───────────────────────────────────────────────────────────┐
│                     airlockd (Rust daemon)                  │
│  ┌─────────┐ ┌──────────┐ ┌───────────┐ ┌───────────────┐ │
│  │ Lease   │ │ Resource │ │ Policy    │ │ Audit Log     │ │
│  │ Engine  │ │ Allocator│ │ Engine    │ │ (hash-chained)│ │
│  │ (SQLite)│ │ ports/DB │ │ (v2.0)    │ │ ← 事实源       │ │
│  └─────────┘ └──────────┘ └───────────┘ └───────────────┘ │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────┐ │
│  │ MCP      │ │ CLI/TUI  │ │ Black-   │ │ Snapshot     │ │
│  │ Server   │ │          │ │ board    │ │ Store (v0.5) │ │
│  └──────────┘ └──────────┘ └──────────┘ └──────────────┘ │
└──────────────┬────────────────────────────────────────────┘
               │ unix socket / gRPC (v1.0 跨机)
┌──────────────▼────────────────────────────────────────────┐
│ Enforcement backends（同一探测 trait，可插拔）               │
│  1. BPF-LSM (aya)   ← Linux root（规划中，L3 未实现，        │
│     v0.x 仅内核能力探测）      3. MCP deny ← 兜底            │
│  2. Landlock        ← Linux 非 root（run 包装器落地）        │
│  4. Windows ACL Guard (v2.5) ← NTFS deny-ACE 动态下发      │
│  5. Windows Minifilter / macOS EndpointSecurity (评估)     │
└───────────────────────────────────────────────────────────┘
```

**技术选型**：Rust（单二进制）；aya（eBPF，**规划中——L3 BPF-LSM 未实现，v0.x 仅探测内核能力，`available()` 恒 false，auto 恒选 L2/L1**）；rmcp（MCP）；rusqlite/SQLite WAL；tree-sitter（v0.3 起）；ratatui（TUI）；IPC 抽象（unix socket / Windows named pipe 同一 trait）；Windows 服务化（windows-service crate）+ winget/MSI 分发（代码签名证书列入 v2.5 预算）；凭据代理集成 Infisical agent-vault / HashiCorp Vault 动态密钥（F13，不自造 vault）；提交签名集成 Sigstore/gitsign（F15，不自造 CA）。

**工程实践约束**：

- M0–M1 不加新依赖（除非替换已有依赖）；所有 enforcement backend 实现同一 trait，advisory 第 1 周完成并设为默认；
- 混沌测试第 2 周开始写（同时是演示素材生成器）；CI 第一天起 `clippy --deny warnings` + Linux 内核矩阵（ubuntu-22.04 ≈5.15 / ubuntu-24.04 ≈6.8，含 Landlock 可测）+ windows-latest（WSL2 job，等效 Linux 矩阵；原生 L2W 自 v2.5 起）+ macOS（L1）；
- **API 稳定性承诺（v1.0 起）**：MCP 工具名/参数、CLI 退出码、租约协议版本化（semver），破坏性变更走 RFC + 一个大版本的弃用期——这是"完整产品"可信度的一部分；
- 插件机制（v3.0）：enforcement backend、policy 规则源、黑板消费者三个扩展点，其余不开放插件以保安全边界。

**安装体验**：`curl -fsSL https://raw.githubusercontent.com/airlock-dev/airlock/main/scripts/install.sh | sh` / `brew install airlock` → `airlock init`（配置 hooks+MCP，运行 doctor 报告当前层）。L2 需 Linux ≥5.13 内核（含 WSL2），安装脚本优雅降级并明说"你当前在 L1/L2"；L3 尚未实现，doctor 会明示"规划中"——绝无静默失效。

---

## 6. 产品路线图 v0.1 → v10.0.0

### 6.1 节奏总览（主题年）

| 年度 | 版本段 | 主题 | Star 锚点（区间末） |
|---|---|---|---|
| 2026 Q4 | v0.1–v0.2 | 立住真空：内核强制 + 资源分配 + 黑板 | 1k |
| 2027 | v0.3–v1.0 | 语义层 + 生态 + 跨机 → **生产可用 1.0** | 3k |
| 2028 | v2.0–v3.0 | 企业地基：政策即代码、凭据作用域、跨租约事务、插件 | 7k |
| 2029 | v4.0–v5.0 | 溯源 + 团队版 GA + 语义 VCS 实验 | 10k |
| 2030–2031 | v6.0–v10.0.0 | 平台化与标准化 | 15k+（爆发情景） |

### 6.2 逐版本路线图

| 版本 | 时间 | 交付物（对应功能） | 验收标准 | Star 锚点 |
|---|---|---|---|---|
| **v0.1** | 2026-11（第 6 周） | F1+F2 降级链+F3 端口+F4；README+60s 视频 | Show HN 首页；`airlock init` 5 分钟跑通 | 发布月 400–800 |
| **v0.2** | 2026-12 | F3 数据库分支+杂项锁；F11 黑板 v1 | 100 会话压测零冲突；黑板跨会话正确传递意图 | 1k |
| **v0.3** | 2027-02 | F5 冲突预测；F6 TUI（含成本归因展示） | 预测在《Passes Alone》+ AgenticFlict 样例生效 | 1.5k |
| **v0.5** | 2027-04 | F7 租约时间线快照+隔离回滚；brew/crates 分发；集成文档正式版 | 撤销 agent-A 的改动不触碰 agent-B 的文件；被一个编排工具文档引用 | 2k |
| **v1.0** | 2027-06 | F8 跨机 gRPC；API 稳定性承诺；安全审计；SDK/协议规范 | 两机 8 agent 无冲突；协议 v1 冻结 | **3k** |
| **v2.0** | 2027-12 | F12 政策即代码；F13 凭据作用域代理；Team 版 alpha | 政策文件在 claim 时驱动内核拒绝；凭据随租约吊销 | 4.5k |
| **v2.5** | 2028-03 | **Windows 原生**：L2W ACL Guard beta（NTFS deny-ACE 动态下发/撤销）、winget/MSI 安装 + 代码签名、Windows 服务化 | Windows 11 干净机：agent 子进程写被真实拒绝；安装→演示 ≤5min；daemon 崩溃后无残留 ACL | 5.5k |
| **v3.0** | 2028-06 | F14 跨租约事务（two-phase claim）转正；插件系统 v1；IDE 插件 | 跨 3 个 claim 域的重构原子提交或整体回滚 | 7k |
| **v4.0** | 2028-12 | F15 提交溯源（Sigstore 集成）；agent merge queue；**Windows Minifilter 与 macOS EndpointSecurity 评估决策** | CI 可验证"该提交出自持租约会话"；两份评估报告给出 go/no-go | 8.5k |
| **v5.0** | 2029-06 | F10 团队版 GA（RBAC/审计导出/合规报告）；语义 VCS 实验立项 | 首批付费 Team 用户留存 ≥ 60% | **10k** |
| **v6.0** | 2029-12 | 冲突域联邦（跨仓库依赖感知）；性能规模化 | 千仓库实例压测 | 12k |
| **v7.0** | 2030-06 | 语义合并 GA（F9 全量）；租约协议提交 MCP 官方扩展提案 | 协议被第二个独立实现 | 13k |
| **v8.0–v9.0** | 2030-12→2031-06 | 生态市场（插件/policy 模板）；国际化；LTS 计划 | 社区贡献占比 > 30% | 14k |
| **v10.0.0** | 2031 | "Agent-Native 开发平台"完整形态：租约协议成为行业默认、语义合并默认开启、六形态全覆盖、Team 版自养 | 品类默认答案 | 15k+（爆发情景） |

> 诚实标注：v6.0 之后进入"品类假设"区间——若"共享目录多 agent"工作流没有成为主流，v6+ 的部分交付物应转投语义 VCS 等相邻方向；每年 6 月/12 月做一次路线图滚动修订。

### 6.3 近期六周执行手册（M0→M1，不变的部分）

第 1 周：骨架 + L1 全链路（两 agent claim 冲突演示录屏）→ 第 2 周：Landlock + hook + 混沌测试 v0 → 第 3 周：BPF-LSM + 端口分配 + 内核矩阵 → 第 4 周：**M0 验收门 + 60s 视频定稿 + 集成 PR 发出（Gas Town/workmux/mcp_agent_mail）** → 第 5 周：安装打磨 + 内测（Ubuntu/WSL2/Arch 干净机跑通）→ 第 6 周：发布（§8.1 清单）。周末自查，连续两周未达标触发止损。

---

## 7. 风险与对策

| 风险 | 等级 | 触发信号 | 对策 |
|---|---|---|---|
| 先例项目（agent-lock / asynkor）填掉核心真空 | 高 | 每周一 scan 其 commit/release | 六周内出声量；README 首日划界；被填则 pivot 为"强制层之上的语义预测+数据闭环"（advisory 派无法复制审计数据源） |
| 协调派生态的 advisory 预留稀释差异化（file_reservation_paths、port-keeper-mcp 已占位） | 高 | 增量检索发现新编排工具采用 advisory 预留 | 演示对比"advisory vs 内核拒绝"；数据闭环壁垒（§4.5）；集成 PR 优先于一切 |
| 强制层被视作过度工程 | 中 | HN 高赞质疑集中于此 | 三层体验；论文数据正面回应；"绕过 MCP 被 sed 拦截"视频镜头用事实说话 |
| macOS 用户劝退 | 高（对增长） | 内测 5 分钟放弃率 > 30% | L1 是完整产品而非残缺版；快速开始只演示 L1 |
| eBPF 内核版本碎片化 | 中 | 第 3 周矩阵失败率 > 20% | 降级链兜底；L3 标注 experimental 不阻塞发布 |
| 单 agent 回滚标配化（/rewind 等）让 F7 显得多余 | 中 | 主流 agent 全面内置 checkpoint | F7 卖点锁定"多 agent 隔离回滚"（撤 A 不伤 B 是单 agent checkpoint 做不到的） |
| Windows 原生强制的签名与维护成本（Minifilter 需微软签名、Windows 版本碎片化、ACL 变更竞态） | 中 | v2.5 L2W 采用率与误拦反馈 | 分层策略：L2W 纯用户态先拿到真实拒绝体验（无驱动无签名门槛）；Minifilter 仅在 L2W 采用率验证后按"评估报告→go/no-go"两步走；NTFS 之外的卷（FAT32/WSL 挂载）明确降级 L1 并在 doctor 明示 |
| 凭据/签名集成选错生态伙伴 | 低 | F13/F15 设计评审 | 集成而非自造（agent-vault、Sigstore），保持后端可替换 |
| 路线图 v6+ 建立在品类爆发假设上 | 中 | 年度滚动修订时 star 落后锚点 50%+ | 每半年滚动修订；偏离即转投相邻方向（语义 VCS / 编排集成层） |
| 六周节奏崩盘 | 中 | 连续两周未达标 | 止损线（§0）：砍范围而非延期 |

---

## 8. 发布与增长计划

### 8.1 发布周清单

**发布前 1 周**：仓库门面（README/CONTRIBUTING/LICENSE MIT+Apache/issue 模板/good first issues）；cargo + brew 就绪；视频上传 + GIF 嵌入；airlock.dev 单页；预写 HN 首评（动机/致谢/取舍/限制）。

**发布日（周二–四，美东 8:00–10:00）**：Show HN（`Show HN: Airlock – Kernel-enforced file leases for parallel AI coding agents`）+ r/ClaudeAI、r/vibecoding 同日 + X 视频 thread + 逐条回复历史"agent 打架"帖（附视频，不刷屏）。

**发布后**：48 小时回复全部评论；dev log 双周更（题材库：内核拦截实战/压测数据/黑板设计/意图合并）；每月复查真空点与品类星数。

### 8.2 演示视频脚本（60 秒，最高优先级资产）

0–10s 分屏两 agent 同改 `src/auth/` → 10–25s **agent-B 直接 `sed -i` 被内核红色 `-EPERM` 拒绝 + tower 高亮** → 25–40s agent-B 读到可读原因自动改 claim 其他路径 → 40–52s 两个 dev server 各用各的端口 → 52–60s 安装命令 + slogan。纪律：真实录屏不用 mock；配英文硬字幕。

### 8.3 README 骨架（第一屏决定生死）

```
# Airlock — One repo. Many agents. Zero collisions.
[演示 GIF] [一行安装] [当前强制层 badge]
> 两个 agent 单测全绿、合并互毁——《Passes Alone, Fails Together》实测现象，
> 也是你开两个 Claude Code 的日常。Airlock 用内核级文件租约让它物理上不可能发生。
## 快速开始（60 秒，任何平台）——只演示 L1
## 为什么不是 worktree / 容器隔离？——三列对比表 + workmux 自认缺陷原话
## 它怎么拦得住 sed -i？——三层强制架构图
## 让编队像团队一样交接——黑板 / 预警 / 隔离回滚 一段一图
```

### 8.4 Star 漏斗与止损/加码线

| 指标 | 健康值 | 含义 |
|---|---|---|
| HN 首帖得分 | ≥ 100 | 叙事成立 |
| README → 安装转化 | ≥ 25% | 安装体验合格 |
| 安装 → init 完成 | ≥ 60% | 5 分钟上手达标 |
| 周新增 issue/PR/discussion | 连续 4 周非零 | 真实使用 |

情景：悲观（发布月 150–300 / 6 个月 400–700）→ 转 advisory+预测叙事重发；基准（400–800 / 1.5k–2.5k）→ 按路线图推进；乐观（1.5k–2k / 4k–6k）→ 立刻投入 F8 跨机承接外溢。止损线见 §0。

---

## 9. 产品化运营（完整产品的持续部分）

- **文档站**：docs.airlock.dev——Getting Started / 协议规范 / 政策 cookbook / 故障排查（doctor 输出对照表）；SEO 主攻"claude code merge conflict""multiple agents same repo""agent file locking"等搜索词——这些词目前只有博客文章在竞争，无工具文档占位。
- **支持**：GitHub Discussions（社区）+ issue 分级（bug/security/feature）+ SECURITY.md 私密披露通道；v5.0 起 Team 许可含 SLA 支持。
- **治理**：v1.0 起公开 ROADMAP 与 RFC 流程；租约协议规范独立成 doc 供第三方实现（v7.0 提交 MCP 扩展提案）；v8.0 成立 steering 组（3–5 人，含外部维护者）。
- **资金**：GitHub Sponsors 起步 → Team 许可（v5.0）→ 可选 NLnet/OSPF 等 open-source 基金资助内核强制与安全审计工作。
- **遥测**：默认零遥测；opt-in 匿名安装/层数统计（doctor 打点），数字公开在官网——"X 千台机器上跑着 L3"本身就是信任资产。
- **维护节奏**：每周一 scan 先例仓库；每两周 dev log；每半年路线图滚动修订；每年复查真空点全表（附录 A）。

---

## 10. 术语表

- **租约（Lease）**：agent 对一组路径的限时独占编辑权，带 TTL 与心跳。
- **强制执行（Enforcement）**：内核/OS 拒绝越权写入，区别于 advisory。
- **降级链 / 三层体验**：L1 advisory（全平台）→ L2 Landlock → L3 BPF-LSM，每层独立可用、独立可演示。
- **冲突域**：共享同一租约空间的 agent 集合（通常 = 一个仓库）。
- **数据闭环**：租约审计日志同时驱动黑板、预测、合并、凭据吊销、提交溯源五处消费的结构性壁垒。
- **租约时间线**：一个冲突域内按租约生命周期排列的变更历史，F7 隔离回滚与 F15 提交溯源的时间轴基础。
- **跨租约事务（F14）**：two-phase claim——先在多个冲突域预占（prepare），全部成功后统一转正（commit），任一失败整体释放。

---

## 附录 A：真空区复核记录（2026-10-03，六轮检索）

| # | 检索轮次与关键词方向 | 最接近的现有实现 | 为何仍是真空/收窄 | 下次复查 |
|---|---|---|---|---|
| V1 | 首轮+第三轮：eBPF LSM agent enforcement / Landlock 比较 | eBPF agent 监控（观察向）、静态 Landlock ruleset、sandbox-per-agent | 动态租约表驱动 + 会话进程树追踪未见 | 每月 |
| V2 | 第四轮：dev server port allocation agents / Neon branching | port-keeper-mcp（裸端口 MCP）、per-worktree Docker Postgres、Neon 分支 | 裸端口已占位 → 收窄；租约打通+配置改写+DB 分支（共享目录）未见 | 每月 |
| V3 | 首轮：cross-machine lease protocol | asynkor（跨机 advisory）、Gas Town 联邦（worktree） | OS 强制未见 | 每月 |
| V4 | 第四轮：blackboard / shared memory MCP / agent mail | Memtrace、MCP Memory Service、Coordination Memory MCP、Network-AI blackboard file | 全是通用记忆层，无租约绑定/审计驱动 | 每月 |
| V5 | 第二/四轮：semantic merge AST LLM | Mergiraf、Weave entity merge、MergeBERT、arXiv 2026-05 LLM 解冲突 | 两阵营都只吃代码文本，意图先验未见 | 每月 |
| V6 | 第五轮：conflict prediction benchmark | AgenticFlict（纯数据集）、《Passes Alone》（纯基准） | 有数据无工具 → 半真空 | 每月 |
| V7 | 第六轮：agent secrets broker / short-lived credentials | Infisical agent-vault、动态密钥模式文章、broker 模式系列 | 通用 broker 已有 → 收窄；凭据作用域与租约绑定（释放即吊销）未见 | 每月 |
| V8 | 第六轮：policy as code agent guardrails | Codex CLI 权限模式、"Policy as Prompt"研究、通用治理框架 | 通用层有玩家 → 收窄；repo 级政策文件驱动内核 claim 执行未见 | 每月 |
| V9 | 第六轮：agent undo / time travel / rollback | Claude /rewind、Gemini /restore、VS Code checkpoints、Stanford Agent-Native Git、Tigriden | 单 agent 按提示回滚已成标配 → 半真空；共享工作区按租约时间线隔离回滚未见 | 每月 |
| V10 | 第六轮：atomic cross-module refactor agents | 实践均为"整仓重构交给一个 agent"、分阶段验证 | 检索确认无事务式锁协议 | 每季 |
| V11 | 第六轮：commit provenance / signed agent identity | CIRIS 签名认证协议（通用）、DevSecOps provenance 岗位要求 | 通用协议有 → 半真空；coding-agent 提交级溯源工具（会话/租约级联）未见 | 每季 |

> 复核纪律：✅/◐/⚠️ 状态变更必须在 dev log 中记录；任何一条从 ✅ 变为 ◐/⚠️ 都触发对应功能的差异化重审（对照 §7 风险表）。

---

*本文档基于 2026-10-03 的六轮联网查重（三轮全量：GitHub / Show HN / PyPI / crates.io / MCP 目录 / arXiv；三轮增量：语义合并与冲突基准 / 共享记忆黑板 / 端口分配 / eBPF 强制 / 凭据代理 / 政策即代码 / 成本计量 / 提交溯源 / 时间机器回滚 / 原子事务）。竞品与机制以当日核实为准。例行维护：每周一 scan 先例仓库（agent-lock / asynkor / Gas Town / port-keeper-mcp / Deskhand / Terraphim / Infisical agent-vault），每月复查 §2.3 十一个真空点与 §8.4 漏斗指标，每半年滚动修订路线图，每年全表复核附录 A。*
