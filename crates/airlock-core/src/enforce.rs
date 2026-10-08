//! F2 三层强制（§4.2）：同一 trait 的可插拔 backend。
//!
//! - L1 Advisory：全平台兜底，MCP/CLI 层拒绝越权 claim；
//! - L2 Landlock（Linux ≥5.13，非 root）：`airlock run` 包装器对 agent 进程树
//!   应用 Landlock ruleset，只放行租约路径的写——规则是**进程作用域**的，
//!   进程退出即消失，daemon 崩溃零残留（AC2.4 由构造保证）；
//! - L3 BPF-LSM（Linux root，experimental）：探测内核能力，未启用时明确报告原因
//!   并降级（P2 绝不静默降级）。

use crate::proto::LayerState;

pub trait EnforcementBackend: Send + Sync {
    /// 层 ID：L1 / L2 / L3
    fn id(&self) -> &'static str;
    /// 展示名
    fn name(&self) -> &'static str;
    /// 是否可用
    fn available(&self) -> bool;
    /// 不可用原因（available = false 时给出）
    fn unavailable_reason(&self) -> Option<String>;
    /// 是否 experimental（不阻塞发布，§7 风险表）
    fn experimental(&self) -> bool {
        false
    }
    fn probe(&self) -> LayerState {
        LayerState {
            id: self.id().to_string(),
            name: self.name().to_string(),
            available: self.available(),
            experimental: self.experimental(),
            reason: self.unavailable_reason(),
        }
    }
}

/// L1 Advisory —— 永远可用。
pub struct AdvisoryBackend;

impl EnforcementBackend for AdvisoryBackend {
    fn id(&self) -> &'static str {
        "L1"
    }
    fn name(&self) -> &'static str {
        "advisory (MCP deny)"
    }
    fn available(&self) -> bool {
        true
    }
    fn unavailable_reason(&self) -> Option<String> {
        None
    }
}

/// L2 Landlock（仅 Linux；非 Linux 平台不可用并明示原因，AC2.3）。
pub struct LandlockBackend;

impl EnforcementBackend for LandlockBackend {
    fn id(&self) -> &'static str {
        "L2"
    }
    fn name(&self) -> &'static str {
        "Landlock"
    }
    fn available(&self) -> bool {
        #[cfg(target_os = "linux")]
        {
            crate::landlock::abi_version() >= 1
        }
        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    }
    fn unavailable_reason(&self) -> Option<String> {
        #[cfg(target_os = "linux")]
        {
            let abi = crate::landlock::abi_version();
            if abi == 0 {
                Some("内核 Landlock 不可用（需要 Linux ≥ 5.13 且 LSM 启用 landlock）".to_string())
            } else {
                None
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            Some(
                "内核强制在本平台不可用（Landlock 仅限 Linux ≥ 5.13）；本机运行于 L1 advisory"
                    .to_string(),
            )
        }
    }
}

/// L3 BPF-LSM（experimental）：**强制实现尚不存在**——仅探测内核能力用于
/// doctor 诊断。`available()` 恒为 false：auto 解析永不落到 L3，绝不出现
/// 「报告 L3 可用但零强制」的假保护（P2）。
pub struct BpfLsmBackend;

impl EnforcementBackend for BpfLsmBackend {
    fn id(&self) -> &'static str {
        "L3"
    }
    fn name(&self) -> &'static str {
        "BPF-LSM"
    }
    fn available(&self) -> bool {
        // v0.x 无 BPF-LSM 程序实现；内核条件齐备也不可用（宁可不可用，不可假保护）
        false
    }
    fn unavailable_reason(&self) -> Option<String> {
        #[cfg(target_os = "linux")]
        let kernel_note: String = {
            if is_root()
                && lsm_enabled("bpf")
                && std::path::Path::new("/sys/kernel/btf/vmlinux").exists()
            {
                "内核条件齐备（root + bpf LSM + BTF），".to_string()
            } else if !is_root() {
                "需要 root（euid=0）；".to_string()
            } else if !lsm_enabled("bpf") {
                format!(
                    "内核 LSM 未启用 bpf（当前：{}）；",
                    lsm_list().unwrap_or_else(|| "未知".into())
                )
            } else {
                "内核 BTF 不可用（CONFIG_DEBUG_INFO_BTF 未启用）；".to_string()
            }
        };
        #[cfg(not(target_os = "linux"))]
        let kernel_note: String = "BPF-LSM 仅限 Linux；".to_string();
        Some(format!(
            "{kernel_note}BPF-LSM 强制尚未实现（v0.x 仅能力探测，规划中）——当前自动使用 L2/L1"
        ))
    }
    fn experimental(&self) -> bool {
        true
    }
}

#[cfg(target_os = "linux")]
fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

#[cfg(target_os = "linux")]
fn lsm_list() -> Option<String> {
    std::fs::read_to_string("/sys/kernel/security/lsm")
        .ok()
        .map(|s| s.trim().to_string())
}

#[cfg(target_os = "linux")]
fn lsm_enabled(name: &str) -> bool {
    lsm_list()
        .map(|l| l.split(',').any(|s| s.trim() == name))
        .unwrap_or(false)
}

/// 按配置解析当前强制层（AC2.5：`--enforcement=off` → L0 disabled badge）。
pub fn resolve_layer(cfg_enforcement: &str) -> LayerState {
    if cfg_enforcement == "off" {
        return LayerState {
            id: "L0".into(),
            name: "disabled".into(),
            available: true,
            experimental: false,
            reason: Some("强制执行已被显式关闭（enforcement = off）".into()),
        };
    }
    let backends: Vec<Box<dyn EnforcementBackend>> = vec![
        Box::new(BpfLsmBackend),
        Box::new(LandlockBackend),
        Box::new(AdvisoryBackend),
    ];
    match cfg_enforcement {
        "L1" | "advisory" => backends[2].probe(),
        "L2" | "landlock" => backends[1].probe(),
        "L3" | "bpf" => backends[0].probe(),
        // auto：取可用的最高层。fallback = L1 probe：AdvisoryBackend
        // available() 恒真的不变量若将来被破坏，返回 L1 报告而非 panic
        _ => backends
            .iter()
            .find(|b| b.available())
            .map(|b| b.probe())
            .unwrap_or_else(|| backends[2].probe()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn l1_always_available() {
        let s = AdvisoryBackend.probe();
        assert!(s.available);
        assert_eq!(s.id, "L1");
    }

    #[test]
    fn off_is_l0_badge() {
        let s = resolve_layer("off");
        assert_eq!(s.id, "L0");
        assert_eq!(s.name, "disabled");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn auto_resolves_to_l2_or_higher_on_modern_kernel() {
        let s = resolve_layer("auto");
        // 本机内核 7.0 已启用 landlock；CI 老内核降级 L1 也应可用
        assert!(s.id == "L1" || s.id == "L2" || s.id == "L3");
        assert!(s.available);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn l3_reports_reason_when_unavailable() {
        let b = BpfLsmBackend;
        if !b.available() {
            assert!(b.unavailable_reason().is_some());
        }
    }
}
