# Airlock 租约协议规范 v2

> 状态：v2.0（Airlock v2.0.0）。v1.0 冻结的字段、方法和退出码全部保持兼容；
> v2.0 变更均为 **additive**（新增方法 / 新增可选字段 / 新增词表项），旧客户端与
> 旧 daemon 互操作不受影响。变更记录见 §9。
> 本文档供第三方实现（SDK / 编排框架接入）。变更走 RFC。
>
> v1.0 新增：`report_cost`（F6 成本归因）、`rollback`（F7 隔离回滚）、`snapshots`（F7 快照列表）。
> v2.0 新增：`creds_list` / `creds_revoke`（F13 凭据代理）、claim/ensure_claim 的
> `cred` 参数与响应 `credentials` 字段（F13）、409 载荷 `policy` 字段（F12 政策即代码）、
> 新审计事件 5 项、新 `suggested_action` 2 项。

## 1. 概念

- **冲突域（conflict domain）**：共享同一租约空间的 agent 集合。git 仓库 = git common dir；
  非 git 目录 = 该目录（此时仅 L1 advisory）。
- **租约（lease）**：agent 对一个 glob 路径模式的限时独占编辑权，带 TTL 与心跳。
- **强制层（layer）**：`L0 (disabled)` / `L1 advisory` / `L2 Landlock` / `L3 BPF-LSM`。

## 2. 传输

daemon `airlockd` 在 `<git-common-dir>/airlock/daemon.sock` 监听 **unix socket**，
协议为**单行 JSON**（NDJSON）：

```json
→ {"v":1,"method":"claim","params":{"agent_id":"agent-A","session_id":"…","glob":"src/auth/**"}}
← {"ok":true,"data":{…}}
← {"ok":false,"error":{…}}
```

`v` 是协议版本（当前 1）。未知方法返回 `not_found` 错误。

如需本机 TCP 客户端，可在 `airlock.toml` 设置 `listen_addr = "127.0.0.1:9418"`，
或启动 `airlockd --listen <addr>`。TCP 监听复用同一 NDJSON 协议和 `v=1` 版本字段；
daemon 默认关闭 TCP，并拒绝绑定非回环地址。协议没有认证或传输加密层，不能用于跨机暴露。

## 3. 方法

| 方法 | 参数 | 返回 / 错误 |
|---|---|---|
| `ping` | – | 版本、当前层、保护空窗、pid |
| `register` | `agent_id` | `SessionInfo{session_id, agent_id, seq, port_base, env}`（env 含 PORT/VITE_PORT/NEXT_PORT） |
| `claim` | `agent_id, session_id, glob, intent?, ttl_s?, heartbeat_s?, cred?` | `ClaimOk{lease, prediction, credentials?}`；他人持有冲突 → 409 载荷；**政策拒绝 → 409 载荷 `error="policy"`**（F12）；**同一 session 对重叠路径重复 claim → 幂等返回既有租约（不自冲突）**。入口校验：空 glob、绝对路径、含 `..` 的模式一律拒绝（`config` 错误）；`ttl_s` 钳制 [2, 604800] 且受政策 `max_ttl_s` 钳制，`heartbeat_s` 钳制 [1, 3600]。`cred` = F13 凭据资源名：授予后发放凭据，env 随 `credentials` 字段返回；发放失败 → 租约回滚（不泄漏） |
| `ensure_claim` | 同 claim | 幂等语义：本会话已有覆盖性租约 → 直接返回既有租约**并顺带续约**（`expires_at` 延长为 `now + ttl_s`）；请求 `cred` 时复用该租约现存 active 凭据或补发；供 hook 自动 claim |
| `release` | `lease_id` 或 `session_id`（释放全部）；须携带与租约一致的 `session_id` | `{released: n}`；属主校验失败 → 409 型载荷 `error="forbidden"` |
| `heartbeat` | `lease_id` + `session_id`（须与租约属主一致） | `{heartbeat:"ok"}`；未找到 → `not_found`；属主校验失败 → `error="forbidden"` |
| `status` | – | `StatusReport{conflict_domain, layer, leases[], sessions[], ports[], protection_gap_s?}` |
| `log` | `since_ts?, limit?` | 审计条目数组 |
| `verify` | – | `{intact, broken_seqs[]}`（hash 链校验） |
| `board_read` | `token_budget?` | `{entries[], archived_summary[], truncated, approx_tokens}` |
| `board_write` | `body, lease_id?` | 写入条目（origin=agent） |
| `alloc_port` | `session_id, purpose` | `PortInfo`（端口回收带 5 分钟冷却） |
| `session_end` | `session_id` | 释放全部租约 + 端口冷却 + 杂项锁清理 |
| `misc_lock` / `misc_unlock` | `name, session_id` | git `index.lock` 类串行化 |
| `branch_db` | `path, session_id` | SQLite 会话副本路径 |
| `degrade` | `path, reason` | 写入降级审计事件 |
| `report_cost` | `lease_id, tokens?, cost_cents?` | `{report_cost:"ok"}`；上报租约的 token 消耗和成本（F6） |
| `rollback` | `lease_id` | `{rollback:"ok", files_restored: n}`；恢复该租约变更的文件到快照锚点（F7） |
| `snapshots` | – | 快照数组（F7） |
| `creds_list` | `lease_id?` | 凭据发放记录数组（F13）：`{id, lease_id, backend, resource, status, issued_at, expires_at?, revoked_at?, meta{env_keys[], backend}}`——**meta 中不含 env 值**（脱敏） |
| `creds_revoke` | `cred_id` | `{revoked: bool}`；立即吊销（管理员）；后端以凭据记录的 `backend` 为准 |
| `stop` | – | 干净停机 |

## 3.1 F12 政策即代码（v2.0）

仓库根的 `airlock.policy.toml`（入库提交）在 claim 时求值，优先于冲突检测：

- **agent 白名单**（`[agents] allow`）、**路径规则**（`[paths.deny]` / `[paths.allow]`，
  deny 永远赢）、**TTL 上限**（`[defaults] max_ttl_s`，clamp 而非拒绝）；
- 政策文件不存在 = 全放行（P3 零配置）；**存在且非法 = `config` 错误**
  （claim 拒绝 + daemon 拒绝启动，fail-closed）；
- **内核驱动**：deny 规则解析为具体目录后从 Landlock 允许写集合减去——
  `airlock run` 下被拒路径得到内核 `-EPERM`（展开粒度注意：deny 子树所在的
  允许目录会展开到现有文件级规则，目录内**新建**文件可能被收紧，见政策 cookbook）；
- 政策加载（`policy_load`，含 sha256）与拒绝（`policy_deny`）入审计——
  政策文件入库提交即可比对审计中的 sha256 追溯版本。

## 3.2 F13 凭据作用域代理（v2.0）

凭据随租约发放（claim 参数 `cred=<资源名>`）、租约释放/过期即吊销
（daemon sweeper 1s 周期 ⇒ **≤60s 失效**为结构性保证）：

- 后端可插拔：`file`（本地凭据源文件，域目录内、不入库）/ `vault`
  （HashiCorp Vault 动态密钥 `database/creds/<role>`，`POST /v1/sys/leases/revoke` 吊销）；
- **边界**：只代理**测试资源凭据**；提交密钥与仓库凭据（git push token / SSH key）
  永不经过 Airlock 进程；
- `file` 后端的吊销是记账性的（值已注入 env 无法强制收回）；严格 ≤60s 失效
  语义由 `vault` 动态凭据提供；
- 未启用凭据代理（默认 `off`）时请求 `cred` → `config` 错误，且已建租约回滚。

## 4. 409 拒绝载荷（v1.0 冻结）

```json
{
  "error": "conflict",
  "path": "src/auth/**",
  "holder": {"agent": "agent-B", "session": "7f3a", "layer": "L3"},
  "ttl_remaining_s": 240,
  "free_alternatives": ["src/api/**"],
  "suggested_action": "claim_free_alternative_or_wait",
  "degraded": false,
  "human": "✗ 无法 claim …（人类可读渲染）",
  "deny_count": 1
}
```

`suggested_action` 受控词表（新增走 RFC）：
- `claim_free_alternative_or_wait` — 存在无冲突路径
- `wait_then_retry` — 无备选
- `escalate_switch_task` — 同路径被拒 ≥3 次（防模型死循环）
- `retry_after_degraded_reconnect` — daemon 不可达
- `lease_not_owned_by_session` — release/heartbeat 携带的 `session_id` 与租约属主不一致（**v0.x 扩展，未冻结**）
- `policy_denied_adjust_scope` — **v2.0**：路径被 `airlock.policy.toml` 拒绝（F12）
- `credential_unavailable` — **v2.0**：凭据资源不存在或后端不可用（F13）

属主校验失败（release/heartbeat 携带的 `session_id` 与租约不一致）返回与 409 同构的拒绝载荷，
`error = "forbidden"`，CLI 退出码 2；载荷含 `suggested_action: "lease_not_owned_by_session"`。

**F12 政策拒绝载荷（v2.0）**：与 409 同构，`error = "policy"`，附加可选字段：

```json
{
  "error": "policy",
  "path": "vault/key.pem",
  "suggested_action": "policy_denied_adjust_scope",
  "policy": {"rule": "vault/**", "kind": "path_denied"},
  "human": "✗ 无法 claim …（被政策拒绝）"
}
```

`policy.kind` 受控词表：`agent_not_allowed` / `path_denied` / `allowlist_miss` / `default_deny`。
旧客户端忽略未知字段（additive 兼容）。

## 5. 租约生命周期

- 默认 TTL 30min，心跳周期 60s；TTL 下限 = 2 个心跳周期；
- 心跳续约：`expires_at = last_heartbeat + ttl_s`；
- 心跳停止 → 到期自动 `expired`，事件写审计日志，黑板条目归档（保留 7 天）；
- 状态机：`active → released | expired | revoked`（`revoked` 为**保留状态**，v0.x 无触发路径）。

## 6. 审计事件词表（v1.0 冻结；v2.0 新增走 §9 RFC）

`claim / grant / deny / heartbeat / expire / release / enforce_deny / enforce_expire / degrade / rollback`
+ **v2.0**：`policy_load / policy_deny / policy_clamp`（F12）· `cred_issue / cred_revoke`（F13）

每条记录：`{seq, prev_hash, hash, ts, event, actor{agent,session,pid_tree}, path, lease_id?, layer, detail?}`，
`hash = SHA-256(seq ‖ prev_hash ‖ ts ‖ event ‖ actor ‖ path ‖ lease_id ‖ layer ‖ detail)`，
首条 `prev_hash` 为 **64 个 `'0'` 字符**。任意篡改可由 `verify` 定位断链 seq。

审计日志另维护**尾部锚点文件** `<dir>/airlock/airlock.head`（记录最后一条的 seq 与 hash）：
即使日志文件尾部被截断，`verify` 也会与锚点比对并报告缺口，防"砍尾"式篡改。

## 7. CLI 退出码（v1.0 冻结）

`0` 成功 · `1` 内部错误（I/O、存储等） · `2` 冲突 / 未授权拒绝（conflict / forbidden） · `3` 未找到 · `4` daemon 不可达 · `5` 配置或用法错误（含命令行参数错误） · `130` 用户中断。

## 8. 失效模式（P2/P7）

| 场景 | 行为 | 用户可见性 |
|---|---|---|
| daemon 崩溃（L1） | 客户端 fail-open 继续运行 | 黄色警告 + 拒绝载荷 `degraded:true` + doctor 红色 |
| daemon 崩溃（L2） | 规则随进程退出消失（零残留） | 恢复后提示"保护空窗 X 秒" |
| SQLite 损坏 | daemon 拒绝启动（宁可不可用不可假保护） | 启动错误 + 修复指引 |
| 心跳丢失 | 2 周期后释放租约 | 审计 `expire` + tower 灰显 |
| 政策文件非法 | claim 拒绝 + daemon 拒绝启动（fail-closed） | `config` 错误（exit 5）+ `airlock policy check` |
| 凭据发放失败 | 租约回滚，错误上抛（不泄漏半途租约） | `config`/后端错误 + `cred_issue` 不入审计 |
| 凭据吊销失败 | sweeper 下轮重试（自愈），期间凭据仍 active | `degrade` 审计事件 |

## 9. RFC 变更记录

- **RFC-2026-v2.0（Airlock v2.0.0）**：引入 F12/F13 协议面。全部变更 additive：
  1. 新方法 `creds_list` / `creds_revoke`（§3.2）；
  2. `claim`/`ensure_claim` 新可选参数 `cred`，`ClaimOk` 新可选字段 `credentials`（§3.1/§3.2）；
  3. 409 拒绝载荷新可选字段 `policy`，`error = "policy"` 拒绝类型（§4）；
  4. `suggested_action` 词表新增 `policy_denied_adjust_scope` / `credential_unavailable`（§4）；
  5. 审计事件词表新增 `policy_load` / `policy_deny` / `policy_clamp` / `cred_issue` / `cred_revoke`（§6）；
  6. 存储层新增 `credentials` 表，`meta.schema_version = 2`（只升不降）。
  线上 `v` 字段保持 `1`（wire 格式未变，向后兼容）；本文档版本号升级为 **v2** 表示
  规范范围的扩展。v1.0 遗留说明：F8 跨机 gRPC 未随 v2.0 交付，跨机暴露仍然不可用
  （协议无认证层，仅 unix socket / 回环 TCP）。
