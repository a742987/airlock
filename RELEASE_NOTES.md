# Airlock v2.0.0 Release Notes

> **状态**: Production Ready（v2.0 验收标准全部落地）  
> **发布日期**: 2026-10-07  
> **里程碑**: 政策即代码 + 凭据作用域代理——Authorize 阶段上线

---

## 🎉 主要新增功能

### F12: 政策即代码（`airlock.policy.toml`）

把治理规则写进仓库、随 PR 审查，claim 时由政策引擎求值并**驱动两层拒绝**：
claim 层 409（`error="policy"`，载荷含命中规则与建议动作）+ L2 内核层
（deny 子树从 Landlock 允许集**减去**，`airlock run` 下真实 `-EPERM`）。

**新增命令**:

```bash
airlock policy check                       # 校验 + 摘要（sha256、未提交改动警告）
airlock policy check --glob 'vault/**' --agent codex   # 干跑一次决策
airlock --json policy check --glob 'src/**' --ttl 7200 # 机器可读（deny_kind / ttl_cap）
```

**特性**:

- ✅ 路径规则（deny 永远赢，顺序无关）/ agent 白名单 / TTL 上限（clamp）
- ✅ 文件不存在 = 零配置全放行（P3）；存在且非法 = fail-closed（claim 拒绝 + daemon 拒绝启动）
- ✅ 政策加载与拒绝入审计（含 sha256），入库提交即可追溯
- ✅ 政策 deny 解析为具体目录（字面量前缀 + 通配规则文件遍历，上限 256 条）

### F13: 凭据作用域代理

凭据随租约发放（`claim --cred <资源>`，env 随响应注入）、租约释放/过期即吊销——
sweeper 1 秒周期，**≤60s 失效为结构性保证**（集成测试断言）。

**新增命令**:

```bash
airlock claim 'src/**' --cred app-db
airlock creds list [--lease <id>]     # env 值脱敏为变量名清单
airlock creds revoke <cred-id>        # 立即吊销（管理员）
```

**特性**:

- ✅ 后端可插拔 trait：`file`（零外部依赖）/ `vault`（HashiCorp Vault 动态密钥）
- ✅ 发放失败 → 租约回滚（P1-5：部分失败不泄漏）；吊销失败 → sweeper 自愈重试
- ✅ 幂等 claim 复用现存 active 凭据（不重复发放）
- ✅ 安全边界：只代理测试资源凭据，提交密钥与仓库凭据永不经过 Airlock 进程

---

## 📡 协议 v2（全 additive，向后兼容）

- 方法：`creds_list` / `creds_revoke`；
- claim/ensure_claim：新参数 `cred`，响应新字段 `credentials`；
- 409 载荷：新字段 `policy {rule, kind}`；`suggested_action` 词表 +2；
- 审计事件词表 +5：`policy_load / policy_deny / policy_clamp / cred_issue / cred_revoke`；
- 存储：`credentials` 表 + `meta.schema_version = 2`（只升不降）。

v1.0 冻结面（方法/字段/退出码）无一变更；详见 [docs/protocol.md §9](docs/protocol.md)。

---

## 🧪 测试与质量

- 新增集成测试 14 项（core / airlockd / CLI / 独立 Landlock 内核测试）：
  - 政策拒绝 409 载荷 + `policy_deny` 审计 + sha256 记录；
  - TTL 钳制（clamp + `policy_clamp` 审计）；
  - 坏政策 fail-closed：claim 拒绝 + **daemon 拒绝启动（exit 5）**；
  - **内核级政策 EPERM**：deny 子树被拒、同级散文件仍可写（文件级 Landlock 规则）；
  - 凭据全生命周期：发放 → 脱敏清单 → release → sweeper 吊销（断言 <60s）；
  - 凭据发放失败回滚（status 确认无泄漏租约）；
- 全仓 `cargo test --workspace`（含 1000 并发 chaos 套件）、`clippy -D warnings`、`fmt --check` 全绿；
- 内核兼容性实测：文件级 Landlock 规则在严格内核（ABI 8，文件 FD 仅接受纯
  `WRITE_FILE` 位）下自动降级尝试，兼容老内核。

---

## 📦 升级与兼容

- 从 v0.5.x / 1.0.0 升级：无数据迁移（新表按需创建），协议 additive，旧客户端可用；
- 新增可选依赖 `ureq`（F13 Vault 集成）；
- 两项新功能默认关闭/不存在即不生效——不写政策文件、不配 `credentials_backend`
  时行为与 v0.x 完全一致；
- 版本号历史说明：1.0.0 为协议冻结占位（F8 未交付）；v2.0.0 首次落实路线图
  v2.0 验收标准并补打 git tag `v2.0.0`；
- Team 版（企业规则源/审计导出）按路线图 §4.4 口径延后至商业决策点（v5.0 GA）。

---

## 🗺️ 后续规划

- v2.5：Windows 原生（NTFS deny-ACE Guard、winget/MSI + 代码签名）
- v3.0：跨租约事务（two-phase claim）转正、插件系统 v1
- F8 跨机 gRPC（v1.0 遗留）：独立推进，不阻塞 v2.x 功能线

## 相关文档

- [CHANGELOG_v2.0.0.md](./CHANGELOG_v2.0.0.md)
- [政策 cookbook](./docs/policy-cookbook.md)
- [租约协议规范 v2](./docs/protocol.md)
- [产品设计规范（PRD）](./Airlock-产品设计规范.md)

---

**感谢使用 Airlock v2.0.0！**

如有问题或建议，请提交 GitHub Issue 或联系维护团队。
