//! F5 冲突预测（v0.3）：claim 时对已 claim 区域做 file → directory 级重叠分析，
//! 并用 tree-sitter 做符号级（函数/类/方法）语义冲突预测。
//! 预测是**建议不是拒绝**（FR6.2：不阻塞 claim，避免误拦率失控）。

use crate::glob;
use crate::proto::{LeaseInfo, Prediction};
use crate::symbols;
use std::path::Path;

pub const RISK_NONE: &str = "none";
pub const RISK_OVERLAP: &str = "overlap";
pub const RISK_SEMANTIC_SUSPECT: &str = "semantic-suspect";
pub const RISK_SYMBOL_CONFLICT: &str = "symbol-conflict";

/// 最大文件大小（1MB）：超过此大小的文件跳过符号级解析，防止内存耗尽
const MAX_FILE_SIZE_FOR_SYMBOLS: usize = 1024 * 1024;

/// 对候选 glob 与现有 active 租约做风险分级：
/// - `symbol-conflict`：与某租约在同一文件修改同一符号（函数/类/方法）；
/// - `overlap`：存在可能共同匹配的具体路径（glob 重叠）；
/// - `semantic-suspect`：glob 不重叠，但与某租约共享同一一级目录；
/// - `none`。
///
/// `overlapping_files` 是已知在重叠区域内的文件路径列表（由调用方枚举）。
/// `file_reader` 用于读取文件内容以做符号解析；若为 None 则跳过符号级分析。
pub fn predict<F>(
    actives: &[LeaseInfo],
    want: &str,
    overlapping_files: &[String],
    file_reader: Option<F>,
) -> Prediction
where
    F: Fn(&Path) -> Option<String>,
{
    let mut with_leases_overlap = Vec::new();
    let mut with_leases_suspect = Vec::new();
    let mut all_involved_symbols = Vec::new();

    for l in actives {
        if glob::overlaps(want, &l.glob) {
            with_leases_overlap.push(l.id.clone());
        } else if same_top_dir(want, &l.glob) {
            with_leases_suspect.push(l.id.clone());
        }
    }

    // 符号级分析：当有文件读取器且存在重叠时，尝试解析符号冲突
    if let Some(reader) = file_reader {
        if !with_leases_overlap.is_empty() && !overlapping_files.is_empty() {
            for file_path in overlapping_files {
                let Some(source) = reader(Path::new(file_path)) else {
                    continue;
                };

                // F5 大文件保护：跳过超过 1MB 的文件，防止内存耗尽
                if source.len() > MAX_FILE_SIZE_FOR_SYMBOLS {
                    eprintln!(
                        "⚠ 跳过符号解析（文件过大）: {} ({} bytes)",
                        file_path,
                        source.len()
                    );
                    continue;
                }

                let candidate_syms = symbols::extract_symbols(Path::new(file_path), &source);
                if candidate_syms.is_empty() {
                    continue;
                }
                // 检查该文件是否也在其他 active 租约范围内
                for active in actives {
                    if !with_leases_overlap.contains(&active.id) {
                        continue;
                    }
                    if !glob::matches(&active.glob, file_path) {
                        continue;
                    }
                    // 同一文件被多个租约覆盖——符号级冲突
                    for sym in &candidate_syms {
                        all_involved_symbols.push(format!(
                            "{}:{}({})",
                            file_path,
                            sym.name,
                            sym.kind.as_str()
                        ));
                    }
                }
            }
        }
    }

    if !all_involved_symbols.is_empty() {
        all_involved_symbols.sort();
        all_involved_symbols.dedup();
        Prediction {
            risk: RISK_SYMBOL_CONFLICT.into(),
            with_leases: with_leases_overlap,
            involved_symbols: all_involved_symbols,
        }
    } else if !with_leases_overlap.is_empty() {
        Prediction {
            risk: RISK_OVERLAP.into(),
            with_leases: with_leases_overlap,
            involved_symbols: vec![],
        }
    } else if !with_leases_suspect.is_empty() {
        Prediction {
            risk: RISK_SEMANTIC_SUSPECT.into(),
            with_leases: with_leases_suspect,
            involved_symbols: vec![],
        }
    } else {
        Prediction {
            risk: RISK_NONE.into(),
            with_leases: vec![],
            involved_symbols: vec![],
        }
    }
}

/// 简化版 predict（无文件读取器，退化为文件/目录级）。
pub fn predict_simple(actives: &[LeaseInfo], want: &str) -> Prediction {
    let mut with_leases_overlap = Vec::new();
    let mut with_leases_suspect = Vec::new();
    for l in actives {
        if glob::overlaps(want, &l.glob) {
            with_leases_overlap.push(l.id.clone());
        } else if same_top_dir(want, &l.glob) {
            with_leases_suspect.push(l.id.clone());
        }
    }
    if !with_leases_overlap.is_empty() {
        Prediction {
            risk: RISK_OVERLAP.into(),
            with_leases: with_leases_overlap,
            involved_symbols: vec![],
        }
    } else if !with_leases_suspect.is_empty() {
        Prediction {
            risk: RISK_SEMANTIC_SUSPECT.into(),
            with_leases: with_leases_suspect,
            involved_symbols: vec![],
        }
    } else {
        Prediction {
            risk: RISK_NONE.into(),
            with_leases: vec![],
            involved_symbols: vec![],
        }
    }
}

fn same_top_dir(a: &str, b: &str) -> bool {
    match (
        glob::first_literal_segment(a),
        glob::first_literal_segment(b),
    ) {
        (Some(x), Some(y)) => x == y,
        // 通配首段（如 `**`）过于宽泛，不判 suspect（避免误报）
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn lease(id: &str, glob: &str) -> LeaseInfo {
        LeaseInfo {
            id: id.into(),
            conflict_domain: "d".into(),
            agent_id: "a".into(),
            session_id: "s".into(),
            glob: glob.into(),
            intent: None,
            state: "active".into(),
            issued_at: 0,
            ttl_s: 60,
            last_heartbeat: 0,
            expires_at: 9999,
            enforcement_layer: "L1".into(),
            tokens_used: 0,
            cost_cents: 0,
        }
    }

    #[test]
    fn overlap_risk() {
        let actives = vec![lease("l1", "src/auth/**")];
        let p = predict_simple(&actives, "src/auth/login.ts");
        assert_eq!(p.risk, RISK_OVERLAP);
        assert_eq!(p.with_leases, vec!["l1"]);
    }

    #[test]
    fn semantic_suspect_risk() {
        let actives = vec![lease("l1", "src/auth/**")];
        let p = predict_simple(&actives, "src/api/orders.ts");
        assert_eq!(p.risk, RISK_SEMANTIC_SUSPECT);
    }

    #[test]
    fn none_risk() {
        let actives = vec![lease("l1", "src/auth/**")];
        let p = predict_simple(&actives, "docs/readme.md");
        assert_eq!(p.risk, RISK_NONE);
    }

    #[test]
    fn symbol_conflict_with_file_reader() {
        let actives = vec![lease("l1", "src/**")];
        let files: HashMap<&str, &str> = [("src/auth.rs", "pub fn login() {}\npub fn logout() {}")]
            .into_iter()
            .collect();
        let reader = |p: &Path| files.get(p.to_str()?).copied().map(String::from);
        let overlapping = vec!["src/auth.rs".to_string()];
        let p = predict(&actives, "src/auth.rs", &overlapping, Some(reader));
        assert_eq!(p.risk, RISK_SYMBOL_CONFLICT);
        assert!(!p.involved_symbols.is_empty());
    }

    #[test]
    fn no_symbol_conflict_without_reader() {
        let actives = vec![lease("l1", "src/**")];
        let overlapping = vec!["src/auth.rs".to_string()];
        let p = predict::<fn(&Path) -> Option<String>>(&actives, "src/auth.rs", &overlapping, None);
        assert_eq!(p.risk, RISK_OVERLAP);
        assert!(p.involved_symbols.is_empty());
    }
}
