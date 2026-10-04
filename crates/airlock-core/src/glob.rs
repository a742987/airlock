//! glob 匹配与重叠判定（F1 冲突检测的基础）。
//!
//! 支持语义：`**` 跨段匹配（含零段）、`*` 单段内任意字符、`?` 单字符、字面量。
//! `overlaps` 判定两个模式是否存在共同匹配的具体路径——用于租约冲突检测。
//!
//! 安全设计：
//! - 所有比较前先做**段归一化**（去空段/`.`、解析 `..`）：`src/../etc/passwd`
//!   与 `src/**` 不匹配，逃逸仓库根的路径不会匹配任何仓库内模式；
//! - 匹配与重叠均为 O(段数²) 的 DP，无指数回溯——单条恶意 glob 不会挂死 daemon。

/// 段数上限（防御异常输入；超过视为不可匹配）。
const MAX_SEGMENTS: usize = 512;

/// 把路径/模式拆为归一化段：去空段与 `.`；`..` 弹出上一段；
/// 从空栈弹出（逃逸仓库根）或超长时返回 None。
fn normalize_segments(s: &str) -> Option<Vec<&str>> {
    let mut out: Vec<&str> = Vec::new();
    for seg in s.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                out.pop()?;
            }
            _ => {
                if out.len() >= MAX_SEGMENTS {
                    return None;
                }
                out.push(seg);
            }
        }
    }
    Some(out)
}

/// claim 入口的模式校验：必须是非空仓库相对路径、不含 `..`、长度有界。
pub fn validate_pattern(pattern: &str) -> Result<(), String> {
    if pattern.trim().is_empty() {
        return Err("glob 不能为空".into());
    }
    if pattern.len() > 4096 {
        return Err("glob 过长（>4096 字符）".into());
    }
    if pattern.starts_with('/') {
        return Err("glob 必须是仓库相对路径（不得以 / 开头）".into());
    }
    for seg in pattern.split('/') {
        if seg == ".." {
            return Err("glob 不得包含 `..`（会逃逸仓库根）".into());
        }
    }
    match normalize_segments(pattern) {
        None => Err("glob 段数超限".into()),
        Some(segs) if segs.is_empty() => Err("glob 不能为空".into()),
        Some(_) => Ok(()),
    }
}

/// 路径模式是否匹配具体路径。
pub fn matches(pattern: &str, path: &str) -> bool {
    let (Some(p), Some(s)) = (normalize_segments(pattern), normalize_segments(path)) else {
        return false;
    };
    seg_match(&p, &s)
}

/// DP[i][j] = p[i..] 是否匹配 s[j..]；O(|p|·|s|)。
fn seg_match(p: &[&str], s: &[&str]) -> bool {
    let (pi, si) = (p.len(), s.len());
    let mut dp = vec![vec![false; si + 1]; pi + 1];
    dp[pi][si] = true;
    for i in (0..pi).rev() {
        for j in (0..=si).rev() {
            dp[i][j] = if p[i] == "**" {
                dp[i + 1][j] || (j < si && dp[i][j + 1])
            } else {
                j < si && seg_overlap(p[i], s[j]) && dp[i + 1][j + 1]
            };
        }
    }
    dp[0][0]
}

/// 两个模式是否可能匹配同一条具体路径。
pub fn overlaps(a: &str, b: &str) -> bool {
    let (Some(pa), Some(pb)) = (normalize_segments(a), normalize_segments(b)) else {
        return false;
    };
    ov(&pa, &pb)
}

/// DP[i][j] = a[i..] 与 b[j..] 是否存在共同匹配；O(|a|·|b|)。
fn ov(a: &[&str], b: &[&str]) -> bool {
    let (ai, bi) = (a.len(), b.len());
    let mut dp = vec![vec![false; bi + 1]; ai + 1];
    dp[ai][bi] = true;
    for i in (0..=ai).rev() {
        for j in (0..=bi).rev() {
            if i == ai && j == bi {
                continue;
            }
            dp[i][j] = match (a.get(i), b.get(j)) {
                (Some(&"**"), _) => dp[i + 1][j] || (j < bi && dp[i][j + 1]),
                (_, Some(&"**")) => dp[i][j + 1] || (i < ai && dp[i + 1][j]),
                (Some(sa), Some(sb)) => seg_overlap(sa, sb) && dp[i + 1][j + 1],
                _ => false,
            };
        }
    }
    dp[0][0]
}

/// 单段级模式兼容性：是否存在字符串同时匹配 sa 与 sb（段内仅 `*` `?` 与字面量）。
pub fn seg_overlap(sa: &str, sb: &str) -> bool {
    let a: Vec<char> = sa.chars().collect();
    let b: Vec<char> = sb.chars().collect();
    // DP：state = (a 位置, b 位置)
    let mut seen = vec![vec![false; b.len() + 1]; a.len() + 1];
    let mut stack = vec![(0usize, 0usize)];
    while let Some((i, j)) = stack.pop() {
        if seen[i][j] {
            continue;
        }
        seen[i][j] = true;
        if i == a.len() && j == b.len() {
            return true;
        }
        let ca = a.get(i).copied();
        let cb = b.get(j).copied();
        match (ca, cb) {
            (Some('*'), _) => {
                stack.push((i + 1, j)); // * 吞零字符
                if j < b.len() {
                    stack.push((i, j + 1)); // * 吞一个字符
                }
            }
            (_, Some('*')) => {
                stack.push((i, j + 1));
                if i < a.len() {
                    stack.push((i + 1, j));
                }
            }
            (Some('?'), _) => {
                if j < b.len() {
                    stack.push((i + 1, j + 1));
                }
            }
            (_, Some('?')) => {
                if i < a.len() {
                    stack.push((i + 1, j + 1));
                }
            }
            (Some(ca), Some(cb)) if ca == cb => {
                stack.push((i + 1, j + 1));
            }
            _ => {}
        }
    }
    false
}

/// 返回模式的首个非通配段（F5 目录级预测用）。`src/auth/**` → `src`；`**` → None。
pub fn first_literal_segment(pattern: &str) -> Option<String> {
    pattern
        .split('/')
        .filter(|s| !s.is_empty() && *s != "." && *s != "..")
        .find(|s| !s.contains('*') && !s.contains('?'))
        .map(|s| s.to_string())
}

/// 返回模式的字面量前缀目录（Landlock 规则落地用）：`src/auth/**` → `src/auth`；
/// `src/a?c/x.ts` → `src`。模式为绝对路径、含 `..`/`.` 之外的安全形态缺失
/// （首段即通配、空模式）时返回 None——调用方不得对含 `..` 或绝对路径的
/// 模式落地内核规则。
pub fn literal_prefix_dir(pattern: &str) -> Option<std::path::PathBuf> {
    if pattern.starts_with('/') {
        return None;
    }
    let mut out = std::path::PathBuf::new();
    for seg in pattern.split('/') {
        match seg {
            "" | "." => continue,
            ".." => return None,
            s if s.contains('*') || s.contains('?') => break,
            s => out.push(s),
        }
    }
    if out.as_os_str().is_empty() {
        None
    } else {
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_matching() {
        assert!(matches("src/auth/**", "src/auth/login.ts"));
        assert!(matches("src/auth/**", "src/auth/deep/nested/x.rs"));
        assert!(!matches("src/auth/**", "src/api/main.rs"));
        assert!(matches("src/*/main.rs", "src/api/main.rs"));
        assert!(!matches("src/*/main.rs", "src/api/v2/main.rs"));
        assert!(matches("**/*.ts", "a/b/c.ts"));
        assert!(matches("exact.ts", "exact.ts"));
        assert!(!matches("exact.ts", "other.ts"));
        assert!(matches("a?c/x.ts", "abc/x.ts"));
    }

    #[test]
    fn overlap_detection() {
        assert!(overlaps("src/auth/**", "src/auth/login.ts"));
        assert!(overlaps("src/auth/login.ts", "src/auth/**"));
        assert!(overlaps("src/**", "src/api/**"));
        assert!(!overlaps("src/auth/**", "src/api/**"));
        assert!(overlaps("**", "anything/here.ts"));
        assert!(overlaps("src/*/a.ts", "src/auth/a.ts"));
        assert!(!overlaps("src/auth/**", "docs/readme.md"));
        assert!(overlaps("a.ts", "a.ts"));
        assert!(!overlaps("a.ts", "b.ts"));
        // 相互为 `**` 时必然重叠
        assert!(overlaps("**/x.ts", "a/**"));
    }

    #[test]
    fn normalization_blocks_escape() {
        // 未规范化路径不得匹配租约（P0：`..` 逃逸）
        assert!(!matches("src/**", "src/../etc/passwd"));
        assert!(!matches("src/auth/**", "src/auth/../api/x"));
        assert!(!overlaps("src/**", "src/../etc/**"));
        // 归一化后相等的路径仍应匹配
        assert!(matches("src/auth/**", "src/auth/./login.ts"));
        assert!(matches("src/auth/**", "src/x/../auth/login.ts"));
        // 绝对/相对混同不再成立：两侧都归一化为相对段后才比较
        assert!(matches("/etc/**", "etc/passwd"));
        assert!(matches("/etc/**", "/etc/passwd"));
    }

    #[test]
    fn literal_prefix_dir_is_safe() {
        assert_eq!(
            literal_prefix_dir("src/auth/**"),
            Some(std::path::PathBuf::from("src/auth"))
        );
        assert_eq!(literal_prefix_dir("src/a?c/x.ts"), Some("src".into()));
        // 绝对路径与 `..` 一律拒绝落地（P0）
        assert_eq!(literal_prefix_dir("/etc/**"), None);
        assert_eq!(literal_prefix_dir("../victim/**"), None);
        assert_eq!(literal_prefix_dir("src/../../etc/**"), None);
        assert_eq!(literal_prefix_dir("**"), None);
        assert_eq!(literal_prefix_dir(""), None);
    }

    #[test]
    fn pattern_validation() {
        assert!(validate_pattern("src/auth/**").is_ok());
        assert!(validate_pattern("**").is_ok());
        assert!(validate_pattern("").is_err());
        assert!(validate_pattern("/etc/**").is_err());
        assert!(validate_pattern("../victim/**").is_err());
        assert!(validate_pattern("src/../../etc/**").is_err());
        assert!(validate_pattern("   ").is_err());
    }

    #[test]
    fn overlap_is_polynomial_not_exponential() {
        // 16 个 `**` 的互配在 DP 下应瞬间完成（旧实现指数回溯跑不完）。
        // a 要求 b..p 依序出现且首段为 a；b 要求 z..l 依序出现且首段为 z——无共同路径。
        let a = "a/**/b/**/c/**/d/**/e/**/f/**/g/**/h/**/i/**/j/**/k/**/l/**/m/**/n/**/o/**/p/**";
        let b = "z/**/y/**/x/**/w/**/v/**/u/**/t/**/s/**/r/**/q/**/p/**/o/**/n/**/m/**/l/**";
        let t0 = std::time::Instant::now();
        assert!(!overlaps(a, b));
        assert!(overlaps(a, "a/1/2/3/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/end"));
        assert!(
            t0.elapsed() < std::time::Duration::from_secs(2),
            "重叠判定不应指数回溯"
        );
    }
}
