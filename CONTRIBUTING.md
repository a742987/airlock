# Contributing to Airlock

感谢参与！Airlock 的设计原则（PRD §1.3）是所有评审的裁决标准——提交前请自查：

| # | 原则 | 反例（会被打回） |
|---|---|---|
| P1 | 拒绝必须可解释（holder / ttl_remaining / suggested_action 三要素） | 裸 `-EPERM`、裸 "conflict" |
| P2 | 绝不静默降级 | daemon 挂了但 agent 以为有保护 |
| P3 | 零配置可用，深度可调 | 强迫先学政策语法 |
| P4 | 机器可读与人类可读同权 | 只给人看的报错贴给模型 |
| P5 | 一个事实源 | 任何界面本地缓存权威状态 |
| P6 | 渐进披露 | 首屏堆砌全部概念 |
| P7 | 失败安全但不失败可用 | 崩溃后既不拦截也不告知 |

## 工程约束（§5 主文档）

- CI 第一天起 `cargo clippy --workspace --all-targets -- -D warnings`；
- 所有 enforcement backend 实现同一 trait（`airlock_core::enforce::EnforcementBackend`）；
- **API 稳定性承诺**：MCP 工具名/参数、CLI 退出码、审计事件词表（v1.0 起冻结）——破坏性变更走 RFC + 一个大版本的弃用期；
- 新增审计事件：`AUDIT_EVENTS` 词表是冻结的，新增必须先开 RFC issue；
- 面向用户的字符串集中在 `airlock-core/src/messages.rs`（i18n 架构准备）；
- `suggested_action` 取值是受控词表，新增同样走 RFC。

## 开发流程

```bash
cargo build --workspace
cargo test --workspace           # 含 1000 并发混沌测试与性能预算
cargo clippy --workspace --all-targets -- -D warnings
cargo test --release -p airlockd perf_claim_latency_budget   # 严格性能门禁
```

## 提交规范

Conventional Commits（`feat: / fix: / docs: / test: / chore:`）。
重大功能先开 issue 讨论；安全漏洞走 SECURITY.md 私密通道，不要公开 issue。
