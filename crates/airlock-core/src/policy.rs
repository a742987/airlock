//! F12 政策即代码：`airlock.policy.toml`（v2.0）。
//!
//! 政策文件入库（commit）即可审计（PRD §4.7「政策变更需 commit，可审计」）；
//! claim 时由本引擎求值并驱动两层拒绝：
//! 1. **claim 层**：冲突检测之前求值，拒绝返回 409 型载荷（`Rejection.policy` 字段）；
//! 2. **内核层**：deny 规则解析为具体目录后，从 Landlock 允许写集合中**减去**
//!    （[`crate::landlock::restrict_write_except`]）——被拒路径在 `airlock run`
//!    下得到内核 EPERM，对应验收标准「政策文件在 claim 时驱动内核拒绝」。
//!
//! 求值语义（声明顺序无关，**deny 永远赢**）：
//! 1. `[agents] allow` 非空 → agent 白名单，不在名单内直接拒绝；
//! 2. `[paths.deny]` 任一规则与申请 glob 重叠 → 拒绝；
//! 3. `[paths.allow]` 非空 → 白名单模式：必须命中某条 allow 规则（且 agent
//!    在该规则的名单内，`*` = 全部）；
//! 4. allow 段为空时按 `[defaults] action`（allow/deny）；
//! 5. `[defaults] max_ttl_s` 把申请 TTL 钳制到上限（clamp 而非拒绝）。
//!
//! P3 纪律：政策文件是进阶而非门槛——文件不存在 = 全放行；但**存在且非法**
//! 时 claim 报配置错误（fail-closed，绝不带着坏政策静默放行）。

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::glob;

/// 政策文件名（仓库根，入库提交）。
pub const POLICY_FILE: &str = "airlock.policy.toml";

/// deny 目录解析上限：防恶意政策把 daemon/run 拖入巨型遍历。
const MAX_DENIED_DIRS: usize = 256;

#[derive(Debug, Clone, PartialEq)]
pub struct PathRule {
    /// 仓库相对 glob（已过 `glob::validate_pattern` 校验）
    pub glob: String,
    /// deny 规则：人类可读拒绝原因；allow 规则：允许的 agent 列表（逗号分隔，`*` = 全部）
    pub value: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Policy {
    /// allow 段为空时的默认动作："allow" | "deny"
    pub default_action: String,
    /// agent 白名单（空 = 不限制）
    pub agents_allow: Vec<String>,
    pub deny_rules: Vec<PathRule>,
    pub allow_rules: Vec<PathRule>,
    /// TTL 上限（秒）；None = 不钳制
    pub max_ttl_s: Option<i64>,
}

/// 拒绝原因。`kind()` 是协议 v2 受控词表（`Rejection.policy.kind`）。
#[derive(Debug, Clone, PartialEq)]
pub enum PolicyDeny {
    /// agent 不在 `[agents] allow` 白名单内
    AgentNotAllowed,
    /// 命中 `[paths.deny]` 规则
    PathDenied { rule: String, reason: String },
    /// `[paths.allow]` 白名单模式下未命中任何规则
    AllowlistMiss,
    /// allow 段为空且 `[defaults] action = "deny"`
    DefaultDeny,
}

impl PolicyDeny {
    pub fn kind(&self) -> &'static str {
        match self {
            PolicyDeny::AgentNotAllowed => "agent_not_allowed",
            PolicyDeny::PathDenied { .. } => "path_denied",
            PolicyDeny::AllowlistMiss => "allowlist_miss",
            PolicyDeny::DefaultDeny => "default_deny",
        }
    }

    /// 命中的规则（glob）；无具体规则的拒绝返回说明性占位。
    pub fn rule(&self) -> &str {
        match self {
            PolicyDeny::AgentNotAllowed => "<agents.allow>",
            PolicyDeny::PathDenied { rule, .. } => rule,
            PolicyDeny::AllowlistMiss => "<paths.allow>",
            PolicyDeny::DefaultDeny => "<defaults.action>",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Verdict {
    pub allowed: bool,
    pub deny: Option<PolicyDeny>,
    /// TTL 钳制上限（None = 不钳制）
    pub ttl_cap: Option<i64>,
}

impl Policy {
    pub fn path_for(root: &Path) -> PathBuf {
        root.join(POLICY_FILE)
    }

    /// 加载政策；文件不存在 → `Ok(None)`（P3：零配置全放行）。
    /// 存在但非法 → `Err(Config)`（fail-closed）。
    pub fn load(root: &Path) -> Result<Option<Policy>> {
        let path = Self::path_for(root);
        let text = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(Error::Config(format!("无法读取 {}: {e}", path.display()))),
        };
        Ok(Some(Self::parse(&text, &path)?))
    }

    fn parse(text: &str, from: &Path) -> Result<Policy> {
        let kv = crate::config::parse_toml_lite(text);
        let mut p = Policy {
            default_action: "allow".into(),
            agents_allow: vec![],
            deny_rules: vec![],
            allow_rules: vec![],
            max_ttl_s: None,
        };
        for (k, v) in &kv {
            let v = v.trim();
            if k == "defaults.action" {
                match v {
                    "allow" | "deny" => p.default_action = v.to_string(),
                    other => return Err(perr(from, k, other, "allow 或 deny")),
                }
                continue;
            }
            if k == "defaults.max_ttl_s" {
                let n: i64 = v.parse().map_err(|_| perr(from, k, v, "整数（秒）"))?;
                if n < 2 {
                    return Err(Error::Config(format!(
                        "defaults.max_ttl_s 必须 ≥ 2（来自 {}）",
                        from.display()
                    )));
                }
                p.max_ttl_s = Some(n);
                continue;
            }
            if k == "agents.allow" {
                p.agents_allow = split_agents(v);
                continue;
            }
            if let Some(g) = k.strip_prefix("paths.deny.") {
                glob::validate_pattern(g).map_err(|e| {
                    Error::Config(format!(
                        "政策 deny 规则 `{g}` 非法（来自 {}）：{e}",
                        from.display()
                    ))
                })?;
                p.deny_rules.push(PathRule {
                    glob: g.to_string(),
                    value: v.to_string(),
                });
                continue;
            }
            if let Some(g) = k.strip_prefix("paths.allow.") {
                glob::validate_pattern(g).map_err(|e| {
                    Error::Config(format!(
                        "政策 allow 规则 `{g}` 非法（来自 {}）：{e}",
                        from.display()
                    ))
                })?;
                p.allow_rules.push(PathRule {
                    glob: g.to_string(),
                    value: v.to_string(),
                });
                continue;
            }
            return Err(Error::Config(format!(
                "未知政策键 `{k}`（来自 {}）；合法段：defaults / agents / paths.deny / paths.allow",
                from.display()
            )));
        }
        Ok(p)
    }

    /// claim 时求值（PRD §5.2：政策在冲突检测之前，是门槛不是建议）。
    pub fn evaluate(&self, agent_id: &str, claim_glob: &str, ttl_s: i64) -> Verdict {
        let ttl_cap = self.max_ttl_s.filter(|&cap| cap < ttl_s);
        if !self.agents_allow.is_empty() && !self.agents_allow.iter().any(|a| a == agent_id) {
            return Verdict {
                allowed: false,
                deny: Some(PolicyDeny::AgentNotAllowed),
                ttl_cap,
            };
        }
        // deny 永远赢（与声明顺序无关）
        for r in &self.deny_rules {
            if glob::overlaps(&r.glob, claim_glob) {
                return Verdict {
                    allowed: false,
                    deny: Some(PolicyDeny::PathDenied {
                        rule: r.glob.clone(),
                        reason: r.value.clone(),
                    }),
                    ttl_cap,
                };
            }
        }
        if !self.allow_rules.is_empty() {
            let hit = self
                .allow_rules
                .iter()
                .find(|r| glob::overlaps(&r.glob, claim_glob) && agents_match(&r.value, agent_id));
            if hit.is_none() {
                return Verdict {
                    allowed: false,
                    deny: Some(PolicyDeny::AllowlistMiss),
                    ttl_cap,
                };
            }
        } else if self.default_action == "deny" {
            return Verdict {
                allowed: false,
                deny: Some(PolicyDeny::DefaultDeny),
                ttl_cap,
            };
        }
        Verdict {
            allowed: true,
            deny: None,
            ttl_cap,
        }
    }

    /// F12 内核驱动：deny 规则解析为具体目录（交给 Landlock 允许集减法）。
    /// 字面量前缀直接落地；首段即通配的规则（如 `**/*.key`）遍历仓库匹配
    /// 文件并取其父目录。上限 [`MAX_DENIED_DIRS`] 条。
    pub fn denied_write_dirs(&self, root: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        for r in &self.deny_rules {
            if let Some(dir) = glob::literal_prefix_dir(&r.glob) {
                out.push(root.join(dir));
                continue;
            }
            for f in crate::lease::walkdir_simple(root, 6) {
                let Ok(rel) = f.strip_prefix(root) else {
                    continue;
                };
                if glob::matches(&r.glob, &rel.to_string_lossy()) {
                    if let Some(parent) = f.parent() {
                        out.push(parent.to_path_buf());
                    }
                }
                if out.len() >= MAX_DENIED_DIRS {
                    return dedupe(out);
                }
            }
            if out.len() >= MAX_DENIED_DIRS {
                break;
            }
        }
        dedupe(out)
    }

    /// 政策文件 sha256（审计 policy_load / policy_deny 附带，可比对政策版本）。
    pub fn file_sha256(root: &Path) -> Option<String> {
        let data = std::fs::read(Self::path_for(root)).ok()?;
        let mut h = Sha256::new();
        h.update(&data);
        Some(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
    }

    /// 政策文件是否有未提交改动（「政策变更需 commit，可审计」）。
    /// 非 git 域 / git 不可用 → `None`（无 commit 语义，不告警）。
    pub fn uncommitted_changes(root: &Path) -> Option<bool> {
        let out = std::process::Command::new("git")
            .args(["status", "--porcelain", "--", POLICY_FILE])
            .current_dir(root)
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        Some(!out.stdout.is_empty())
    }
}

/// 逗号分隔的 agent 名单（`*` 原样保留）。
fn split_agents(v: &str) -> Vec<String> {
    v.split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn agents_match(value: &str, agent: &str) -> bool {
    value == "*" || split_agents(value).iter().any(|a| a == agent)
}

fn dedupe(mut v: Vec<PathBuf>) -> Vec<PathBuf> {
    v.sort();
    v.dedup();
    v
}

fn perr(from: &Path, k: &str, v: &str, want: &str) -> Error {
    Error::Config(format!(
        "政策键 `{k}` 值 `{v}` 非法（来自 {}）；应为 {want}",
        from.display()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(text: &str) -> Policy {
        Policy::parse(text, Path::new("test.policy.toml")).unwrap()
    }

    #[test]
    fn missing_file_is_none() {
        let tmp = std::env::temp_dir().join(format!("airlock-pol-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).unwrap();
        assert!(Policy::load(&tmp).unwrap().is_none());
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn full_schema_roundtrip() {
        let p = policy(
            r#"
            [defaults]
            action = "deny"
            max_ttl_s = 600
            [agents]
            allow = "codex, claude-code"
            [paths.deny]
            "vault/**" = "密钥区"
            [paths.allow]
            "src/**" = "*"
            "tests/**" = "e2e-bot, ci-bot"
            "#,
        );
        assert_eq!(p.default_action, "deny");
        assert_eq!(p.max_ttl_s, Some(600));
        assert_eq!(p.agents_allow, vec!["codex", "claude-code"]);
        assert_eq!(p.deny_rules.len(), 1);
        assert_eq!(p.allow_rules.len(), 2);
    }

    #[test]
    fn deny_wins_regardless_of_allow() {
        let p = policy("[paths.deny]\n\"vault/**\" = \"x\"\n[paths.allow]\n\"vault/**\" = \"*\"\n");
        let v = p.evaluate("codex", "vault/key.pem", 1800);
        assert!(!v.allowed);
        assert_eq!(v.deny.unwrap().kind(), "path_denied");
    }

    #[test]
    fn allowlist_mode_and_agent_filter() {
        let p = policy("[paths.allow]\n\"tests/**\" = \"e2e-bot\"\n");
        // e2e-bot 命中
        assert!(p.evaluate("e2e-bot", "tests/a.rs", 1800).allowed);
        // codex 未命中任何 allow 规则的 agent 名单
        let v = p.evaluate("codex", "tests/a.rs", 1800);
        assert!(!v.allowed);
        assert_eq!(v.deny.unwrap().kind(), "allowlist_miss");
        // 完全不在 allow 段内的路径
        let v = p.evaluate("e2e-bot", "src/main.rs", 1800);
        assert!(!v.allowed);
        assert_eq!(v.deny.unwrap().kind(), "allowlist_miss");
    }

    #[test]
    fn agent_allowlist_blocks_everything_else() {
        let p = policy("[agents]\nallow = \"codex\"\n[paths.allow]\n\"src/**\" = \"*\"\n");
        let v = p.evaluate("gemini", "src/x.rs", 1800);
        assert!(!v.allowed);
        assert_eq!(v.deny.unwrap().kind(), "agent_not_allowed");
        assert!(p.evaluate("codex", "src/x.rs", 1800).allowed);
    }

    #[test]
    fn default_deny_when_no_allow_section() {
        let p = policy("[defaults]\naction = \"deny\"\n");
        assert!(!p.evaluate("codex", "anything", 1800).allowed);
        let p2 = policy("");
        assert!(p2.evaluate("codex", "anything", 1800).allowed);
    }

    #[test]
    fn ttl_is_clamped_not_rejected() {
        let p = policy("[defaults]\nmax_ttl_s = 600\n");
        let v = p.evaluate("codex", "src/**", 1800);
        assert!(v.allowed);
        assert_eq!(v.ttl_cap, Some(600));
        // 低于上限不钳制
        assert_eq!(p.evaluate("codex", "src/**", 300).ttl_cap, None);
    }

    #[test]
    fn unknown_key_and_bad_glob_are_errors() {
        let e = Policy::parse("[unknown]\nx = \"1\"\n", Path::new("t")).unwrap_err();
        assert!(e.to_string().contains("未知政策键"));
        let e = Policy::parse("[paths.deny]\n\"/abs/**\" = \"x\"\n", Path::new("t")).unwrap_err();
        assert!(e.to_string().contains("非法"));
        let e = Policy::parse("[paths.deny]\n\"../x/**\" = \"y\"\n", Path::new("t")).unwrap_err();
        assert!(e.to_string().contains("非法"));
    }

    #[test]
    fn denied_write_dirs_resolves_literal_prefixes() {
        let tmp = std::env::temp_dir().join(format!("airlock-pol-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(tmp.join("vault/deep")).unwrap();
        std::fs::create_dir_all(tmp.join("src")).unwrap();
        std::fs::write(tmp.join("src/main.rs"), b"fn main() {}").unwrap();
        let p = policy("[paths.deny]\n\"vault/**\" = \"x\"\n");
        let dirs = p.denied_write_dirs(&tmp);
        assert_eq!(dirs, vec![tmp.join("vault")]);
        // 首段通配：遍历文件取父目录
        let p2 = policy("[paths.deny]\n\"**/main.rs\" = \"x\"\n");
        assert_eq!(p2.denied_write_dirs(&tmp), vec![tmp.join("src")]);
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn quoted_keys_are_unquoted_by_parser() {
        // 解析器扩展（带引号的键）是政策文件的前提
        let kv = crate::config::parse_toml_lite("[paths.deny]\n\"vault/**\" = \"x\"\n");
        assert_eq!(kv.get("paths.deny.vault/**").map(String::as_str), Some("x"));
    }
}
