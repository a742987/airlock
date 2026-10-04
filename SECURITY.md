# 安全政策

## 报告漏洞

**不要**为安全漏洞创建公开 issue。请使用 GitHub Security Advisories（"Report a vulnerability"）
私密披露。我们承诺 72 小时内确认、7 天内给出评估。

## 受支持版本

| 版本 | 状态 |
|---|---|
| 0.1.x | ✅ 受支持（接收安全修复） |
| 更早版本（< 0.1） | ❌ 不受支持，请升级到 0.1.x |

## 威胁模型边界（v0.x）

**在保护范围内**：
- agent 绕过 MCP/hook 直接写文件（L2 Landlock 进程级拦截）；
- 两个 agent 同时写同一文件（租约冲突拒绝）；
- 审计日志事后篡改（hash 链校验，`airlock log --verify`）。

**不在保护范围内（诚实声明）**：
- root 用户或内核层攻击者；
- agent 进程在 `airlock run` 之外自行脱离 Landlock（Landlock 无提权路径，但进程若被注入另论）；
- 两个 agent 想做**同一件事**的任务重叠（Airlock 只保证文件/资源层不冲突）；
- macOS（当前仅 L1 advisory）。

## 数据边界

- 审计日志、租约、黑板全部存 `<git-common-dir>/airlock/`，永不离开本机；
- 提交密钥与仓库凭据不经过任何 Airlock 进程；
- 零遥测。
