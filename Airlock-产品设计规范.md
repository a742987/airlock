# Airlock 产品设计规范（PRD）

> 文档版本 v1.0（2026-10-03）｜ 伴随文档：《Airlock-项目发展规划.md》v10.0.0（战略与路线图）
>
> 本文档遵循标准 PRD 结构：产品概述 → 用户研究 → 需求范围 → 功能需求（用户故事 + 验收标准）→ 信息架构 → UX/UI 规范 → 数据设计 → API 规范 → 非功能需求 → 商业设计 → 发布标准 → 度量体系。
>
> 深度原则：v0.1–v0.3 范围写到可开发的颗粒度；v0.5 及以后的功能只写产品需求，技术细节留待各版本 PRD 补充。

---

## 1. 产品概述

### 1.1 产品定义

Airlock 是一个自托管的本地守护进程（`airlockd`），让多个 AI 编程代理在同一目录、同一分支并行工作：文件租约由内核强制执行、共享资源自动分配、协作状态随租约生命周期自动维护。

### 1.2 愿景与北极星指标

- **愿景**：让"多 agent 共享工作区"成为一种默认安全的工作方式。
- **北极星指标**：每周"零写冲突的多 agent 会话数"（同一冲突域内 ≥2 个 agent 会话、全程无拦截事故、正常完成提交的会话组数）。
- **辅助护栏指标**：误拦率（合法写入被拒绝的比例）< 0.1%；拦截响应延迟 p99 < 10ms（L3）。

### 1.3 设计原则（所有功能评审的裁决标准）

| # | 原则 | 含义 | 反例（禁止出现） |
|---|---|---|---|
| P1 | **拒绝必须可解释** | 每条拒绝都含：谁持有、为什么、何时释放、下一步该做什么 | 裸 `-EPERM`、裸 "conflict" |
| P2 | **绝不静默降级** | 强制层降级必须被 doctor、TUI、拒绝信息三处同时可见 | daemon 挂了但 agent 以为有保护 |
| P3 | **零配置可用，深度可调** | 装完不写任何配置即可用；`airlock.policy.toml` 是进阶而非门槛 | 强迫先学政策语法 |
| P4 | **机器可读与人类可读同权** | 每个输出同时服务模型（结构化）与人（渲染），`--json` 全覆盖 | 只给人看的报错贴给模型 |
| P5 | **一个事实源** | CLI/TUI/MCP/日志渲染同一份租约表+审计日志，任何界面不得本地缓存权威状态 | TUI 显示与实际租约不一致 |
| P6 | **渐进披露** | L1→L3、advisory→强制、零配置→政策文件，每一步都是可选升级 | 首屏堆砌全部概念 |
| P7 | **失败安全但不失败可用** | daemon 崩溃时按 §8.4 明确定义的失效模式运行，且必须显式提示 | 崩溃后既不拦截也不告知 |

### 1.4 目标与非目标

见主文档 §4.6。本 PRD 不重复，仅强调与设计直接相关的一条：**不解决任务重叠**——两个 agent 要做同一件事时，Airlock 只保证文件/资源层不冲突，用户教育文案不得暗示更多。

---

## 2. 用户研究

### 2.1 Persona

**P1 · 并行派职业程序员（首要）** — 李工，32 岁，Linux 桌面 + WSL2，工作流：一个 Claude Code 修 bug、一个 Codex 写 feature。痛点：merge 时发现语义冲突；维护 4 个 worktree 的心智负担。技术程度：能接受 root 和内核概念，但拒绝"调内核参数半小时"。

**P2 · VibeCoder 爱好者** — Alex，25 岁，macOS，同时开 3 个 Claude Code 会话迭代副业项目。痛点：agent 互相拆台但不知道为什么；没有耐心读任何超过 3 屏的文档。要求：5 分钟内见效、报错能直接复制给模型看。

**P3 · 工具开发者** — 早苗，29 岁，维护一个小型 agent 编排框架。需求：稳定的租约协议、可编程接口、语义化版本承诺。

**P4 · 团队 Tech Lead / DevSecOps（v2.0+）** — 需求：政策即代码、审计导出、不为团队单独维护隔离环境。

### 2.2 Jobs-to-be-Done

| JTBD | 现状方案 | Airlock 对应能力 |
|---|---|---|
| "当我要让两个 agent 同时干活时，我想要它们不互相破坏，以便我不用在 merge 时收拾残局" | worktree 隔离（冲突推迟） | F1/F2 |
| "当 agent 卡在冲突上时，我想要它自动排队或改道，以便我不需要人工仲裁" | 人工看报错 | F4 可读拒绝 |
| "当多个 agent 跑 dev server 和测试时，我想要端口/数据库自动分开，以便不踩坏彼此的环境" | 手工改配置 | F3 |
| "当我中途加入/重启一个 agent 时，我想要它知道别人正在做什么，以便不盲目探索" | 无（重新读代码库） | F11 黑板 |
| "当某个 agent 改坏了东西时，我想要只撤销它的改动，以便不伤及其他工作" | git 整体回滚 | F7 隔离回滚 |

### 2.3 关键用户旅程（首次体验，P2 视角）

| 时刻 | 动作 | 设计要求 | 失败点防护 |
|---|---|---|---|
| T+0 | 看到 GIF/推文，复制安装命令 | 安装命令永远一行、永远可复制 | — |
| T+40s | `curl \| sh` 完成 | 脚本结尾打印下一步命令，不要求读文档 | 非 Linux：明说"你将运行在 L1 advisory"，不报错退出 |
| T+1min | `airlock doctor` | 三行输出：当前层、内核能力、一条建议 | 内核过旧：给出升级建议但**不阻塞** |
| T+3min | `airlock init` | 自动改 agent 配置，打印改了哪些文件（可回滚清单） | 已有 hook：询问而非覆盖 |
| T+5min | 开两个 agent，第二个 claim 被拒 | 拒绝信息让 agent 自己改道，用户全程无感 | agent 不理解拒绝：拒绝体含"可直接粘贴给模型的下一步指令" |
| T+1 天 | `airlock tower` | 一屏看懂：谁持有什么、资源分配、拦截事件 | — |

**首周留存的关键时刻**：第一次"亲眼看到"拦截事件（TUI 或审计日志）。产品目标：让这一时刻在安装后 24 小时内自然发生——若用户从未开过第二个 agent，doctor 输出附一行引导。

---

## 3. 需求范围（v0.1–v0.3，MoSCoW）

| 优先级 | 内容 | 理由 |
|---|---|---|
| **Must**（v0.1） | F1 租约引擎、F2 三层强制、F4 接入层（MCP+CLI+hook）、F3 端口注入（仅 PORT + vite/next/webpack） | 立住真空的最小闭环 |
| **Should**（v0.2） | F11 黑板 v1、F3 数据库分支（Postgres/SQLite）、杂项锁 | 数据闭环起步 |
| **Should**（v0.3） | F5 冲突预测（文件级→目录级，符号级延后）、F6 TUI（只读视图） | 预警与可视化 |
| **Could**（v0.3 若进度富余） | 符号级租约（tree-sitter）、`--json` 全覆盖收尾 | — |
| **Won't**（本阶段） | 符号级预测、快照回滚（v0.5）、跨机（v1.0）、政策引擎（v2.0） | 见主文档路线图 |

---

## 4. 功能需求（用户故事 + 验收标准）

> 验收标准统一使用 Given/When/Then；带 ★ 的条目为发布门禁（Release Gate，不通过不得发布该版本）。

### 4.1 F1 租约引擎（v0.1）

**用户故事**：作为一个并行跑多个 agent 的开发者，我想让 agent 在编辑前获得路径租约且冲突申请被明确拒绝，以便两个 agent 永不同时写同一文件。

**功能需求**：
- FR1.1 `claim`：按 glob 申请独占租约，带 TTL（默认 30min）与心跳续约（默认 60s）。自动心跳续约适用于 run / MCP / hook 路径；**纯 CLI claim 为一次性租约（TTL 到期自动过期），可用 `airlock heartbeat` 手动续约**；
- FR1.2 冲突申请返回 409 型结构化拒绝（见 §7.3 消息模板）；**同一 session 对重叠路径重复 claim 幂等返回既有租约（不自冲突）；`ensure_claim` 命中既有租约时顺带续约**；
- FR1.3 心跳停止 2 个周期后租约自动过期释放，事件写审计日志；
- FR1.4 `release`：主动释放；`status`：列出冲突域内全部租约；
- FR1.5 租约状态存 SQLite（WAL），审计日志 hash-chained（每条含前条 hash）。

**验收标准（节选）**：
- ★ AC1.1 Given agent-A 持有 `src/auth/**` 租约，When agent-B claim `src/auth/login.ts`，Then 返回拒绝，载荷含持锁者 ID、预计释放时间、建议动作。
- AC1.2 Given agent-A 进程被 kill，When TTL+2 心跳周期届满，Then 租约自动释放且后续 claim 成功，审计日志含 `expired` 事件。
- ★ AC1.3 Given daemon 重启，When 重启完成，Then 从 SQLite 完整恢复租约状态，未过期租约继续有效。
- AC1.4 Given 审计日志任意一条被篡改，When `airlock log --verify`，Then 报告断链位置。
- AC1.5 When 1000 个并发 claim 请求打到同一 daemon，Then 无死锁、无状态错乱（混沌测试断言）。

### 4.2 F2 三层强制（v0.1）

**用户故事**：作为一个怀疑 agent 会绕过 MCP 的开发者，我想让内核直接拒绝越权写入，以便不依赖模型自觉。

**功能需求**：
- FR2.1 三个 backend 实现同一**探测** trait（`id/name/available/unavailable_reason/probe`）：报告各层可用性与原因。L1 拒绝由 MCP/CLI/hook 层落地；L2 Landlock 强制在 `airlock run` 包装器中落地（对包装进程应用 ruleset）；**L3 BPF-LSM 为规划中——v0.x 仅做内核能力探测，`available()` 恒为 false，强制实现不存在**；`--enforcement=L3` 显式配置时，`doctor`/`run` 给出"尚未实现"的原因（P2 绝不静默）；
- FR2.2 `airlock doctor` 探测并报告当前层，给出升级建议（不阻塞）；
- FR2.3 每次拦截写审计日志（进程、路径、租约上下文）；
- FR2.4 失效模式（★ 设计决策，见 §8.4）：L1 拒绝由 MCP 层执行，daemon 不可达时 **fail-open + 显式警告**（P2/P7）；**L2 Landlock 规则是进程作用域的**——应用在 `airlock run` 包装进程自身上，随进程树存在、退出即消失，daemon 崩溃零残留（与 protocol.md §8、README 同口径）；daemon 不可达时等效 fail-open，但 doctor 与下次连接时必须展示"曾出现过保护空窗"；
- FR2.5（v2.5）Windows L2W "ACL Guard"：daemon 对租约路径动态下发 NTFS deny-write ACE（作用域限定 agent 进程令牌所属 SID），release/expire/daemon 退出时撤销；仅 NTFS 卷生效，FAT32/exFAT/WSL 挂载卷在 doctor 中明示降级 L1（P2 绝不静默）；路径匹配默认大小写不敏感（Windows 语义），策略可配；
- FR2.6（v4.0 决策点）Windows L3W Minifilter 驱动评估：仅在 L2W 采用率与误拦率达标后立项；评估报告须覆盖微软签名路径（attestation → WHQL）、Windows 版本矩阵、卸载残留风险；macOS EndpointSecurity 同节奏评估。

**验收标准（节选）**：
- ★ AC2.1（v0.x 口径：**L3 未实现，本条由 L2 等效验收 + L3 探测报告替代**）Given L2 Landlock 激活且 agent-B（含其子进程）`sed -i` 一个未持租约文件，Then 写入返回 -EPERM；Given doctor 在具备 root + bpf LSM + BTF 的机器上运行，Then L3 报告为"规划中，尚未实现"并说明原因，`auto` 模式恒选 L2/L1。
- AC2.2 Given 无 root 的 Linux 5.15+，When doctor 运行，Then 报告 L2 可用并给出启用命令。
- AC2.3 Given macOS，When doctor 运行，Then 报告 L1 并明示"内核强制不可用"及原因，退出码 0（可用，非错误）。
- ★ AC2.4 Given daemon 被 kill，When 60 秒后，Then L2/L3 已无任何残留拦截规则（`airlock doctor` 可验证），且下次 daemon 启动时提示"保护空窗 X 秒"。
- AC2.5 Given 用户 `--enforcement=off` 显式关闭，When 任意操作，Then 所有界面显示 `L0 (disabled)` badge（P2：绝不静默）。
- ★ AC2.6 Given Windows 11 + L2W 激活，When agent-B（含其子进程）写一个未持租约的 NTFS 路径，Then 返回 Access Denied，审计日志记录该进程树。
- AC2.7 Given L2W 激活且 daemon 崩溃，When Windows 服务恢复机制 + TTL 兜底清理运行，Then ≤TTL 内全部 deny-ACE 被撤销（无残留 ACL），doctor 报告空窗时长。
- AC2.8 Given 项目位于 exFAT 卷，When doctor 运行，Then 报告"该卷不支持 ACL Guard，已运行于 L1"，退出码 0（可用，非错误）。
- AC2.9 Given 大小写不同的两条路径（`SRC/auth` 与 `src/auth`），When 分别 claim，Then 在 Windows 上判定为同一路径（默认），在 Linux 上判定为不同路径。

### 4.3 F3 资源分配（v0.1 端口 / v0.2 数据库）

**用户故事**：作为开三个 agent 的用户，我想让每个 agent 的 dev server 和测试数据库自动隔离，以便不出现 EADDRINUSE 和数据互踩。

**功能需求**：
- FR3.1 会话注册时分配端口段（默认起 30000+会话序号×10），注入 `PORT`/`VITE_PORT`/`NEXT_PORT`；
- FR3.2 对 vite/next/webpack 项目改写对应配置文件（改写前列出将修改的文件，可 `--dry-run`）。**v0.x 现状：配置改写尚未接线到任何命令，v0.1 以 `--port` 环境变量注入（PORT/VITE_PORT/NEXT_PORT）为主路径**；
- FR3.3 端口回收带 5 分钟冷却期（防 agent 仍在收尾）；
- FR3.4（v0.2）Postgres：按 template database 克隆 `airlock_<session>` 库，会话结束 DROP；SQLite：复制副本到会话目录。
- FR3.5（v0.2）`index.lock` 等杂项锁排队（同一冲突域内 git 写操作串行化）。

**验收标准（节选）**：
- ★ AC3.1 Given 两个 agent 会话各自启动 vite，Then 两个 server 监听不同端口且互不报错。
- AC3.2 Given 配置文件已被用户手工指定端口，When 会话分配，Then 不覆盖显式配置、改用注入环境变量并在 status 中注明。
- AC3.3（v0.2）Given agent 会话结束（TTL 过期或 release），Then 其临时数据库在 60s 内被销毁，审计日志记录。

### 4.4 F4 接入层（v0.1）

**用户故事**：作为一个不想改工作流的用户，我想一条 `airlock init` 让我的 agent 自动遵守租约，以便零学习成本。

**功能需求**：
- FR4.1 MCP server 暴露工具：`claim` / `release` / `heartbeat` / `status` / `log` / `blackboard_read`（v0.2）/ `blackboard_write`（v0.2）；
- FR4.2 `airlock init claude-code`：写入 PreToolUse hook + MCP 配置，**并在两处注入同一 `AIRLOCK_SESSION_ID`（MCP 会话与 hook 会话身份统一）**；支持 codex/gemini/cursor/opencode。hook 的 deny 决策以 **exit 0 + stdout JSON**（`permissionDecision=deny`，含结构化拒绝原因）返回，同时在 stderr 输出人类可读原因（双保险，兼容不同 agent 的 hook 消费方式）；
- FR4.3 拒绝消息双形态：人类可读段落 + 模型可读 JSON（P4）；
- FR4.4 CLI 全命令支持 `--json`、`--no-color`、`--config`。

**验收标准（节选）**：
- ★ AC4.1 Given 全新 Claude Code 环境，When `airlock init claude-code && agent 启动`，Then agent 第一次 Edit 前自动 claim，无需任何手工配置。
- AC4.2 Given 检测到已存在的 hook 配置，When init，Then 展示 diff 并要求确认，绝不静默覆盖。
- AC4.3 Given agent 反复 claim 同一冲突路径 ≥3 次，Then 拒绝消息升级为"建议改做 X"级别的引导（防模型死循环蛮干）。

### 4.5 F11 冲突域黑板（v0.2）

**用户故事**：作为中途加入的 agent，我想先读到"别人正在做什么、这个仓库有什么坑"，以便不盲目探索、不重复踩坑。

**功能需求**：
- FR5.1 claim 时可选携带 `intent`（做什么/为什么），写入黑板并与租约绑定；
- FR5.2 release/TTL 过期时，黑板条目自动归档（保留 7 天）；
- FR5.3 `blackboard_read` 返回活动条目 + 最近归档摘要（token 预算受控，默认 ≤500 token）；
- FR5.4 条目来源分两级：agent 声明（advisory，可谎报）与 daemon 依据审计日志生成（强制层下不可抵赖），字段标明来源。

**验收标准（节选）**：
- ★ AC5.1 Given agent-A 带 intent claim 并完成提交，When agent-B 新会话首次读取黑板，Then 输出包含 A 的意图与改动路径摘要。
- AC5.2 Given 黑板内容超过 token 预算，Then 按活跃度+时间排序截断，并在输出末尾注明被截断条数。

### 4.6 F5 冲突预测 / F6 TUI（v0.3，产品需求级）

- FR6.1（F5）claim 时对已 claim 区域做重叠分析，返回风险等级（none/overlap/semantic-suspect）与涉及符号；预测输入含黑板意图（跨文件语义预警）；
- FR6.2（F5）预测是**建议不是拒绝**（不阻塞 claim，避免误拦率失控）；
- FR6.3（F6）`airlock tower` 一屏：租约列表（持有人/路径/剩余 TTL/意图）、资源分配、拦截事件流、黑板活动；刷新 ≤1s；鼠标不可用时可完全键盘操作。

### 4.7 v0.5+ 功能（产品需求级，技术 PRD 后补）

| 功能 | 核心产品需求 | 关键验收方向 |
|---|---|---|
| F7 隔离回滚（v0.5） | 按租约时间线快照；`airlock rollback <lease-id>` 只撤销该租约的改动，不触碰他人在重叠路径上的后续改动 | 撤 A 不伤 B；回滚前自动打安全点 |
| F8 跨机（v1.0） | 冲突域可跨机器，gRPC 同步租约，网络分区时本机继续强制、恢复时合并 | 分区 30s 恢复后状态一致 |
| F9 意图合并（v1.x） | merge 冲突时以双方租约意图作为先验产出建议 | 建议附带置信度，永不静默自动合并 |
| F12 政策即代码（v2.0） | `airlock.policy.toml` 入版本库：路径规则、agent 白名单、TTL 上限；claim 时由政策引擎求值并驱动内核 | 政策变更需 commit，可审计 |
| F13 凭据作用域（v2.0） | 凭据随租约发放（只可访问被分配的测试库）、租约释放即吊销；后端可接 agent-vault/Vault | 吊销后旧凭据 ≤60s 失效 |
| F14 跨租约事务（v3.0） | `airlock tx begin/commit/abort`：多域预占→统一转正，任一失败整体释放 | 3 域原子性；prepare 超时自动 abort |
| F15 提交溯源（v4.0） | 提交时产出租约证明（哪个会话/租约/强制层），可接 Sigstore 签名 | CI 可独立验证证明 |

---

## 5. 信息架构与用户流程

### 5.1 命令空间（v0.1 全量）

```
airlock
├── init [agent]        # 配置 hooks + MCP（交互确认，绝不静默覆盖）
├── claim <glob> [--intent "..."] [--ttl 30m]   # --ttl 支持时长格式（30m/1h/90s/1h30m）与纯秒数
├── release <lease-id | --all>
├── heartbeat <lease-id> # 手动续约（纯 CLI claim 不自动续约；run/MCP/hook 自动续约）
├── status [--json] [--free]   # 租约 + 资源分配 + 当前强制层；--free 列无冲突一级目录
├── log [--verify] [--since 1h] [--json]
├── doctor              # 强制层探测 + 健康检查 + 升级建议
├── tower               # TUI（v0.3）
├── board read|write    # 黑板（v0.2）
└── daemon start|stop   # 通常由安装器托管
```

### 5.2 核心流程图（claim 冲突路径）

```
agent 调用 claim(glob)
  → daemon 求值政策（v2.0）/ 冲突检测
     ├─ 无冲突 → 创建租约 → (L2/L3) 下发内核规则 → 返回 lease-id
     ├─ 冲突   → 409 载荷{holder, ttl_remaining, suggestion}
     │            → agent 排队 / 改道 / 用户介入
     └─ daemon 不可达 → fail-open + 警告载荷{degraded:true}（§8.4）
```

---

## 6. UX/UI 设计标准

### 6.1 CLI 输出规范

- 退出码：`0` 成功；`1` 内部错误（I/O、存储等）；`2` 冲突 / 未授权拒绝（conflict / forbidden）；`3` 无租约/未找到；`4` daemon 不可达；`5` 配置或用法错误（含命令行参数错误）；`130` 用户中断。**退出码是 API 的一部分（v1.0 起冻结）**；
- 输出三档：`--json`（模型/脚本）、默认（人类，彩色）、`--quiet`（CI）；
- 颜色语义全局统一：绿=正常、黄=降级/警告、红=拒绝/拦截、灰=过期/归档；`--no-color` 与非 TTY 环境自动禁用。

### 6.2 拒绝消息模板（P1 的落地，★设计标准）

```
人类可读：
✗ 无法 claim src/auth/** —— 该路径由 agent-B（会话 7f3a）持有，约 4 分钟后释放。
  建议：先做 X（无冲突路径清单见 airlock status --free），或等待后重试。

模型可读（--json / MCP 载荷）：
{ "error": "conflict", "path": "src/auth/**",
  "holder": {"agent": "agent-B", "session": "7f3a", "layer": "L3"},
  "ttl_remaining_s": 240, "free_alternatives": ["src/api/**"],
  "suggested_action": "claim_free_alternative_or_wait",
  "degraded": false }
```

规则：每条拒绝必须含 holder / ttl_remaining / suggested_action 三要素；`suggested_action` 的取值是受控词表（v1.0 冻结），保证模型行为可预期。

### 6.3 TUI（tower）布局

```
┌ AIRLOCK TOWER ─ repo: ~/shop ─ L3 (BPF-LSM) ──────────────┐
│ LEASES                                                     │
│ agent-A  src/auth/**      12:34 剩余   intent: 修复登录超时 │
│ agent-B  src/api/**       04:10 剩余   intent: 订单分页     │
│ RESOURCES       agent-A :30010 vite  agent-B :30020 vite   │
│ EVENTS          12:31 ✗ agent-C sed → src/auth/login.ts    │
│ BOARD           agent-A: "重试逻辑抽到 retry.ts"            │
└────────────────────────────────────────────────────────────┘
```

标准：首屏必须回答三个问题——谁持有什么、是否在保护中（层 badge）、最近发生了什么；键盘可达性 100%；宽度 <80 列不破版。

### 6.4 文案语气规范

- 对人：陈述事实 + 给下一步，不指责 agent（"agent-C 的写入被拦下"而非"agent-C 违规！"）；
- 对模型：命令式、可执行（"claim_free_alternative_or_wait"），避免含糊修辞；
- 全部面向用户的字符串集中在 i18n 资源文件（v8.0 国际化前先做架构准备）。

---

## 7. 数据设计

### 7.1 租约表（leases）

| 字段 | 类型 | 说明 |
|---|---|---|
| id | UUID | 租约 ID |
| conflict_domain | TEXT（git common dir 哈希） | 冲突域 |
| agent_id / session_id | TEXT | 持有者 |
| glob | TEXT | 声明的路径模式 |
| intent | TEXT? | 黑板意图（可空） |
| state | ENUM | active / expired / released / revoked |
| issued_at / ttl_s / last_heartbeat | 整数 | 生命周期 |
| enforcement_layer | ENUM | L1/L2/L3（下发时的层，用于空窗审计） |

### 7.2 审计日志（audit_log，append-only）

`{seq, prev_hash, hash, ts, event, actor{agent, session, pid_tree}, path, lease_id?, layer, detail}` — event 词表：`claim/grant/deny/heartbeat/expire/release/enforce_deny/enforce_expire/degrade/rollback`（v1.0 冻结，新增走 RFC）。另维护**尾部锚点文件** `<dir>/airlock/airlock.head`（记录末条 seq 与 hash）：日志尾部被截断时 `verify` 与锚点比对即报缺口，防"砍尾"式篡改。

### 7.3 黑板（board_entries）

`{id, lease_id, origin: agent|daemon, body, status: active|archived, created_at, archived_at}` — 归档保留 7 天（可配）。

---

## 8. 非功能需求（NFR）

### 8.1 性能预算（★发布门禁）

| 指标 | 预算 | 测法 |
|---|---|---|
| claim 延迟 | p50 < 5ms / p99 < 50ms | 基准测试套件 |
| L3 拦截引入的写入延迟（规划中，当前仅探测） | < 1ms（BPF map 查找） | fio 对比 |
| daemon 常驻内存 | < 50MB（1000 租约规模） | 压测 |
| audit 写入 | < 5ms（同步链式写） | 基准 |
| tower 刷新 | ≤ 1s | 手测 |
| L2W ACL 传播 | 租约变更 → deny-ACE 生效 p99 < 500ms；撤销 p99 < 2s | Windows 集成测试 |

### 8.2 兼容性矩阵（v0.1 支持承诺）

| 维度 | 支持 |
|---|---|
| Linux | glibc 2.31+；内核：L1 全部 / L2 ≥5.13 / L3 规划中（目标 ≥5.15 且 BPF-LSM 启用；v0.x 仅内核能力探测，不拦截） |
| macOS | L1（14+，brew 分发）；L2/L3 明示不可用 |
| Windows | v0.1 起：WSL2（等效 Linux 矩阵）；v2.5 起原生：L1 全版本（Windows 10 1809+）/ L2W ACL Guard（NTFS 卷）/ L3W Minifilter 仅评估（v4.0 决策）；winget + MSI 分发，安装包须代码签名 |
| Agent | Claude Code / Codex CLI / Gemini CLI / Cursor / OpenCode（各配集成测试） |
| 仓库 | git 仓库（依赖 common dir）；非 git 目录仅 L1 advisory 可用 |

### 8.3 安全与隐私

- daemon 以最小权限运行：L2/L3 规则下发后立即丢弃特权（setuid 帮助进程模型），常态零 root 进程；
- 审计日志默认存 `<git-common-dir>/airlock/`，永不离开本机；opt-in 遥测只含版本/层/计数（§9.4，主文档）；
- 提交密钥与仓库凭据**永不**经过 Airlock 进程（F13 边界：只代理测试资源凭据）。

### 8.4 失效模式表（★设计决策，P2/P7 的落地）

| 场景 | 行为 | 用户可见性 |
|---|---|---|
| daemon 崩溃（L1） | MCP 调用失败 → agent 无租约保护地运行 | 拒绝载荷 `degraded:true` + CLI 黄色警告 + doctor 红色 |
| daemon 崩溃（L2） | `airlock run` 包装进程不受影响，其内核规则随包装进程退出消失（零残留）；daemon 重启后提示"保护空窗 X 秒" | 恢复后提示"保护空窗 X 秒" |
| SQLite 损坏 | daemon 拒绝启动（宁可不可用不可假保护） | 启动错误 + 修复指引 |
| 心跳丢失 | 2 周期后释放租约 | 审计 `expire` 事件 + tower 灰显 |
| daemon 崩溃（L2W / Windows） | 服务恢复机制自动重启 + TTL 兜底清理任务撤销全部 deny-ACE | doctor 报告空窗时长；AC2.7 验收 |

---

## 9. 商业设计（对应主文档 §4.4）

- **Community（Apache-2.0）**：本 PRD §4 全部 v0.x 功能永久免费；README 明示"个人与团队自用永不收费"；
- **Team（v5.0，商业许可）**：F10（RBAC/多人）、政策引擎企业规则源、审计导出（SIEM 格式）、SLA 支持。定价原则：按**冲突域/实例**年订阅，不定按座（agent 数不可控）；上限价锚定"一个中级工程师一天工资/年"；
- 转化钩子设计在产品内：`doctor` 对多仓库用户提示"团队模式可集中管理冲突域"（一次性、可关闭）。

---

## 10. 发布标准（Definition of Done）

| 门禁 | v0.1 | v0.3 | v1.0 |
|---|---|---|---|
| Must 验收 AC 全过（含 ★） | ✅ | ✅ | ✅ |
| 性能预算达标（§8.1） | ✅ | ✅ | ✅ |
| 混沌测试：100 会话零写冲突 | — | ✅ | ✅ |
| 兼容矩阵全绿（CI） | ✅ | ✅ | ✅ |
| 安全审计 | — | 自查 | 第三方 |
| 安装→首个拦截演示 ≤5min（干净机实测） | ✅ | ✅ | ✅ |
| API/退出码/事件词表冻结 | — | 草案 | ✅ |

Beta（公开预览）门槛：★ 全过 + 已知问题清单公开 + 回滚方案（`airlock init --undo`）就绪。

平台附加门禁：v0.1 起 CI 含 windows-latest（L1）；v2.5 起发布门禁加入 Windows 11 干净机实测（L1 + L2W 安装→演示 ≤5min、AC2.6/2.7 通过）；L2W 上线前必须通过"崩溃残留 ACL"专项混沌测试（等价 AC2.7 的自动化版本）。

---

## 11. 度量体系（HEART 映射）

| 维度 | 指标 | 采集方式 | 健康线 |
|---|---|---|---|
| Happiness | 首帖/评论情感、NPS（内测问卷） | 人工 | — |
| Engagement | 周活跃冲突域数、周黑板读写数 | 本地计数 + opt-in 遥测 | 环比不降 |
| Adoption | 安装→init→首次 claim→首次双 agent 转化漏斗 | opt-in 匿名 | §8.4 主文档漏斗线 |
| Retention | 4 周后仍在用的安装占比 | opt-in | ≥ 40% |
| Task success | 误拦率 <0.1%、拦截后 agent 自行改道率 ≥80% | 审计日志本地统计 | 见左 |

> 遥测纪律：所有指标默认关闭；`init` 时一次性询问；拒绝则零采集；聚合计数公开在官网。

---

*变更记录：v1.0（2026-10-03）——按标准 PRD 结构成稿，覆盖 v0.1–v0.3 开发级颗粒度与 v0.5+ 产品级需求；与主文档 v10.0.0 的功能编号（F1–F15）、真空点编号（V1–V11）、版本锚点保持一致。维护纪律：主文档路线图滚动修订时，同步更新本档 §3/§4/§10。
v1.0.1（2026-10-04）——与实现对齐修订：L3 标注"规划中，仅探测"（FR2.1/AC2.1/§8.1/§8.2）；L2 失效模型改为进程作用域（FR2.4/§8.4）；FR3.2 注明配置改写未接线；FR4.1 补 heartbeat；§5.1 补 --free 与时长格式；§6.1 退出码补 1 并并入用法错误；FR1.1/FR1.2 补 CLI 不自动续约与同会话幂等语义。**实现进度部分领先于分期：F5 冲突预测、F6 tower TUI、F11 黑板已在 v0.1 代码中实现。***
