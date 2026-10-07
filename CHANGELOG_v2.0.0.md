# Airlock v2.0.0

## 主要新增功能

### F12: 政策即代码
仓库根的 `airlock.policy.toml`（入库提交）在 claim 时由政策引擎求值并**驱动内核拒绝**。

```toml
[paths.deny]
"vault/**" = "密钥区，agent 一律禁触"

[paths.allow]
"src/**" = "*"
```

```bash
airlock policy check --glob 'vault/key.pem'   # 校验 + 干跑决策
```

- 政策三要素：**路径规则**（deny 永远赢）、**agent 白名单**、**TTL 上限**（clamp 而非拒绝）；
- 双层执行：claim 层 409（`error="policy"` 载荷含命中规则）+ L2 内核层
  （deny 子树从 Landlock 允许集减去，真实 `-EPERM`）；
- 政策不存在 = 零配置全放行（P3）；存在且非法 → claim 拒绝 + daemon 拒绝启动（fail-closed）；
- 可审计：`policy_load` / `policy_deny` / `policy_clamp` 审计事件（含文件 sha256），
  入库提交即可追溯政策版本；未提交改动由 `airlock policy check` 告警。

### F13: 凭据作用域代理
凭据随租约发放、租约释放/过期即吊销（sweeper 1s 周期 ⇒ **≤60s 失效**为结构性保证）。

```bash
airlock claim 'src/**' --cred app-db   # env 随 claim 响应注入
airlock creds list                     # env 值脱敏
airlock creds revoke <cred-id>         # 管理员立即吊销
```

- 后端可插拔（`CredBackend` trait）：`file`（本地凭据源文件，域目录内不入库）
  / `vault`（HashiCorp Vault 动态密钥 `database/creds/<role>` + lease 吊销）；
- 发放失败 → 租约自动回滚（不泄漏半途租约）；吊销失败 → sweeper 下轮重试（自愈）；
- **安全边界**：只代理测试资源凭据；提交密钥与仓库凭据永不经过 Airlock 进程；
- 默认 `off`（零配置原则），`airlock.toml` 显式启用。

## 协议 v2（additive）

- 新方法 `creds_list` / `creds_revoke`；claim/ensure_claim 新参数 `cred`、
  响应新字段 `credentials`；409 载荷新字段 `policy`；
- 新 `suggested_action`：`policy_denied_adjust_scope` / `credential_unavailable`；
- 新审计事件：`policy_load` / `policy_deny` / `policy_clamp` / `cred_issue` / `cred_revoke`；
- 存储 `schema_version = 2`（新增 `credentials` 表）；
- v1.0 冻结的方法、字段、退出码全部保持兼容，旧客户端不受影响（见 docs/protocol.md §9）。

## 质量与工程

- 新增集成测试 14 项：政策拒绝/TTL 钳制/fail-closed（core + daemon + CLI）、
  内核级政策 EPERM（独立 Landlock 测试）、凭据全生命周期与 ≤60s 吊销验收（mock-free file 后端）、
  凭据发放失败回滚；
- `cargo test --workspace` / `clippy -D warnings` / `fmt --check` 全绿；
- 版本号说明：v1.0.0 为协议冻结占位（F8 跨机 gRPC 未交付）；v2.0.0 是首个
  同时落实路线图 v2.0 验收标准（政策驱动内核拒绝 + 凭据随租约吊销）的发布，
  并补齐 git tag。Team 版（企业规则源/审计导出）按路线图口径延后至商业决策点。

## 升级与兼容

- 从 v0.5/v1.0 升级：无需数据迁移（`credentials` 表按需创建）；协议 additive，旧客户端可用；
- 新增依赖：`ureq`（F13 Vault 集成，阻塞式 HTTP，rustls TLS）；
- 政策与凭据均为**可选**功能：不写 `airlock.policy.toml`、不启用 `credentials_backend`
  时行为与 v0.x 完全一致。

## 验收对照（路线图 §6.2 v2.0）

| 验收标准 | 落实 |
|---|---|
| 政策文件在 claim 时驱动内核拒绝 | claim 层 409 + Landlock 内核 EPERM（集成测试覆盖两层） |
| 凭据随租约吊销（PRD：≤60s 失效） | sweeper 1s 周期吊销，集成测试断言 <60s |

Team 版 alpha 未随本版交付（路线图自身标记该决策点为"v1.0 发布后根据社区构成再定"，
且无功能定义与验收标准）；详见[项目发展规划 §4.4](Airlock-项目发展规划.md)。

## 文档

- [RELEASE_NOTES.md](RELEASE_NOTES.md)
- [政策 cookbook](docs/policy-cookbook.md)
- [租约协议规范 v2](docs/protocol.md)
- [产品设计规范（PRD）](Airlock-产品设计规范.md)
