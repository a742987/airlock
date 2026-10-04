//! F5 冲突预测（v0.3）：claim 时对已 claim 区域做 file → directory 级重叠分析。
//! 预测是**建议不是拒绝**（FR6.2：不阻塞 claim，避免误拦率失控）。
//! 符号级（tree-sitter）为 v0.3 Could，延后——`involved_symbols` 恒为空。

use crate::glob;
use crate::proto::{LeaseInfo, Prediction};

pub const RISK_NONE: &str = "none";
pub const RISK_OVERLAP: &str = "overlap";
pub const RISK_SEMANTIC_SUSPECT: &str = "semantic-suspect";

/// 对候选 glob 与现有 active 租约做风险分级：
/// - `overlap`：存在可能共同匹配的具体路径（glob 重叠）；
/// - `semantic-suspect`：glob 不重叠，但与某租约共享同一一级目录
///   （语义冲突高发区——《Passes Alone, Fails Together》现象）；
/// - `none`。
pub fn predict(actives: &[LeaseInfo], want: &str) -> Prediction {
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
        }
    }

    #[test]
    fn overlap_risk() {
        let actives = vec![lease("l1", "src/auth/**")];
        let p = predict(&actives, "src/auth/login.ts");
        assert_eq!(p.risk, RISK_OVERLAP);
        assert_eq!(p.with_leases, vec!["l1"]);
    }

    #[test]
    fn semantic_suspect_risk() {
        let actives = vec![lease("l1", "src/auth/**")];
        let p = predict(&actives, "src/api/orders.ts");
        assert_eq!(p.risk, RISK_SEMANTIC_SUSPECT);
    }

    #[test]
    fn none_risk() {
        let actives = vec![lease("l1", "src/auth/**")];
        let p = predict(&actives, "docs/readme.md");
        assert_eq!(p.risk, RISK_NONE);
    }
}
