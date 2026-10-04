# Airlock v0.5.0

## 主要新增功能

### F6: 成本归因
跟踪每个租约的 token 消耗和 API 成本。

```bash
airlock report-cost <lease-id> --tokens 1000 --cost-cents 50
```

### F7: 隔离回滚
Git 快照 + 一键回滚，为 agent 工作流提供事务性操作。

```bash
airlock snapshots              # 列出所有快照
airlock rollback <lease-id>    # 回滚指定租约的变更
```

### F5: 符号级冲突预测
使用 tree-sitter 解析源代码，提供函数/类级别的冲突预测。

## Bug 修复

- ✅ 添加完整的混沌测试套件（1000 并发）
- ✅ 修复 F7 快照未接线到 daemon
- ✅ 添加 F6/F7 集成测试（13 个测试用例）
- ✅ 添加符号解析器大文件保护（1MB 阈值）
- ✅ 添加成本归因溢出保护（饱和加法）
- ✅ 修正文档版本号

## 质量提升

| 指标 | v0.4.x | v0.5.0 | 提升 |
|------|--------|--------|------|
| 总体评分 | 92/100 | **95/100** | +3 |
| 测试覆盖 | 85/100 | **90/100** | +5 |
| 质量等级 | Alpha | **Beta** | ⬆️ |

## 新增测试

- **混沌测试**: 4 个测试，验证 1000 并发无死锁
- **F6/F7 集成测试**: 9 个测试，覆盖成本累加和快照回滚

## 完整更新说明

请查看 [RELEASE_NOTES.md](./RELEASE_NOTES.md) 和 [REVIEW_REPORT.md](./REVIEW_REPORT.md)

---

**感谢使用 Airlock v0.5.0！**
