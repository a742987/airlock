# Airlock 政策 Cookbook（F12 政策即代码）

> 对应运营规划「政策 cookbook」；技术规范见 [protocol.md](protocol.md) §3.1。

`airlock.policy.toml` 放在仓库根、**随代码入库提交**——政策变更走 PR review，
审计日志记录每次加载的文件 sha256，可追溯"当时生效的是哪一版政策"。

## 最小可用示例

```toml
# airlock.policy.toml
[paths.deny]
"vault/**" = "密钥与凭据，agent 一律禁触"
"infrastructure/**" = "生产基建只允许人工修改"

[paths.allow]
"src/**"    = "*"
"tests/**"  = "e2e-bot, ci-bot"
"docs/**"   = "*"
```

语义：deny 命中即拒绝（与声明顺序无关）；存在非空 `[paths.allow]` 时进入
白名单模式——只允许命中规则（且 agent 名单匹配，`*` = 全部）的路径。

## 全部键位

| 段 | 键 | 说明 |
|---|---|---|
| `[defaults]` | `action = "allow" \| "deny"` | allow 段为空时的默认动作（默认 `allow`） |
| `[defaults]` | `max_ttl_s = <整数>` | TTL 上限：claim 申请更长时间会被**钳制**（不拒绝） |
| `[agents]` | `allow = "a, b"` | agent 白名单；缺省 = 不限制 |
| `[paths.deny]` | `"glob" = "原因"` | 拒绝规则；值是人类可读原因（进 409 载荷与审计） |
| `[paths.allow]` | `"glob" = "agent 列表或 *"` | 白名单规则 |

规则 glob 支持与租约相同的语义（`**` / `*` / `?`）。未知键、绝对路径、含 `..`
的模式一律**报错**（fail-closed），不会静默忽略。

## 逐场景配方

### 1. 密钥区绝对隔离

```toml
[paths.deny]
".env*" = "环境变量文件"
"secrets/**" = "凭据目录"
"**/*.pem" = "私钥文件"
```

claim 层：daemon 拒绝 claim（409，`error="policy"`）；
内核层（L2）：`airlock run` 下这些路径真实 `-EPERM`——即使 agent 绕过 claim
直接 `cat > secrets/x` 也写不进去。

### 2. 只让测试机器人跑 tests

```toml
[paths.allow]
"src/**" = "*"
"tests/**" = "e2e-bot, ci-bot"
```

### 3. 限制租约时长（防止"占着不走"）

```toml
[defaults]
max_ttl_s = 1800   # 所有 claim 的 TTL 被钳到 30min
```

### 4. 白名单 agent

```toml
[agents]
allow = "claude-code, codex"
```

未列出的 agent claim 任何路径都会被拒（`agent_not_allowed`）。

### 5. 全库默认只读（默认 deny + 白名单）

```toml
[defaults]
action = "deny"

[paths.allow]
"src/auth/**" = "claude-code"
```

## 校验与干跑

```bash
airlock policy check                     # 校验 + 摘要（含 sha256、未提交改动警告）
airlock policy check --glob 'vault/**'   # 干跑一次决策（显示命中规则；被拒 exit 2）
airlock policy check --glob 'src/**' --agent codex --ttl 7200
airlock --json policy check --glob 'src/**'   # 机器可读（含 ttl_cap / deny_kind）
```

## 与内核强制的交互（重要粒度说明）

政策 deny 通过从 Landlock 允许集**减去**被拒子树实现内核拒绝。Landlock 只有
允许规则（无 deny），因此当"允许目录包含被拒子树"时，Airlock 会把允许目录
**展开到子级**：被拒分支跳过、其余子目录照常授权、目录下的**已有散文件**用
文件级规则精确授权。由此带来的收紧：展开过的目录里**新建**文件可能被内核拒绝
（L1/MCP 层不受影响）。建议把 deny 目标设计为一级目录，避免与 claim 范围嵌套。

## 边界与纪律

- **政策是门槛不是建议**：文件不存在 = 全放行（P3 零配置）；存在且非法 →
  claim 拒绝 + daemon 拒绝启动。
- **变更需 commit**：`airlock policy check` 检测到未提交改动会告警——
  入库才能 PR review + 审计追溯。
- **Team 商业线说明**：政策引擎的"企业规则源"（远程规则、SIEM 集成等）按
  路线图属 Team 版商业许可范围（v5.0 决策点），社区版不包含。
