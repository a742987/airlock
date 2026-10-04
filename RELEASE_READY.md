## ✅ 清理完成 - 准备发布

### 📦 待提交文件（精简版）

**修改的文件** (15个):
- 核心代码更新：Cargo.toml, Cargo.lock
- 功能实现：lease.rs, store.rs, predict.rs, proto.rs
- CLI/Daemon：commands.rs, main.rs, mcp.rs, tower.rs
- 文档：protocol.md, airlock.rb

**新增文件** (8个):
- 核心功能：snapshot.rs, symbols.rs
- 测试：chaos.rs, f6_f7_integration.rs
- 文档：CHANGELOG_v0.5.0.md, RELEASE_NOTES.md, REVIEW_REPORT.md
- 发布脚本：do_release.sh

### 🚀 立即发布

```bash
# 方法 1: 使用自动化脚本
chmod +x do_release.sh
./do_release.sh

# 方法 2: 手动执行
git add -A
git commit -m "feat: release v0.5.0 - 成本归因 + 隔离回滚 + 符号级预测

## 新增功能
- F6: 成本归因（tokens_used + cost_cents）
- F7: 隔离回滚（snapshot + rollback）
- F5: 符号级冲突预测（tree-sitter）

## 测试增强
- 新增混沌测试套件（1000 并发）
- 新增 F6/F7 集成测试（13 个测试用例）

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"

git push origin main
git tag -a v0.5.0 -m "Release v0.5.0"
git push origin v0.5.0
gh release create v0.5.0 --title "v0.5.0 - 成本归因 + 隔离回滚" --notes-file CHANGELOG_v0.5.0.md --latest
```

### 📊 总结
- ✅ 已清理所有临时报告文件
- ✅ 保留必要的发布文档（3个）
- ✅ 代码修改完整（15个文件）
- ✅ 测试完善（2个新测试套件）
- ✅ 无敏感文件，可安全发布
