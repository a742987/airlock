//! 零配置可用的最小配置层（P3：零配置可用，深度可调）。
//!
//! v0.1 配置文件是可选的 TOML 子集（key = "value" / [section]，不含数组与多行）；
//! v2.0 起支持**带引号的键**（F12 政策规则键是 glob，如 `"vault/**" = "deny"`）
//! 与 F13 凭据代理键。`airlock.policy.toml` 的解析见 [`crate::policy`]。

use std::collections::BTreeMap;
use std::path::Path;

use crate::error::{Error, Result};

#[derive(Debug, Clone, PartialEq)]
pub struct Config {
    /// "auto"（默认，探测最优层）| "off"（L0 disabled badge，AC2.5）| "L1" | "L2" | "L3"
    pub enforcement: String,
    /// 心跳周期（秒），默认 60
    pub heartbeat_s: i64,
    /// 租约默认 TTL（秒），默认 30min
    pub default_ttl_s: i64,
    /// 端口段起始，默认 30000
    pub port_base: u16,
    /// 黑板 token 预算，默认 500
    pub board_token_budget: usize,
    /// 遥测：默认 false（遥测纪律：默认零采集）
    pub telemetry: bool,
    /// Optional loopback-only TCP listener for local protocol clients. Disabled by default.
    pub listen_addr: Option<String>,
    /// F13 凭据代理后端：off（默认，零配置）/ file（本地凭据源文件）/ vault（HashiCorp Vault 动态密钥）
    pub credentials_backend: String,
    /// file 后端的凭据源文件路径；空 = `<domain.dir>/credentials.toml`（运行时按域目录解析）
    pub credentials_file: String,
    /// vault 后端地址（如 `http://127.0.0.1:8200`）；仅 backend = vault 时必需
    pub vault_addr: String,
    /// vault 动态密钥角色（database/creds/<role>）；仅 backend = vault 时必需
    pub vault_role: String,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            enforcement: "auto".into(),
            heartbeat_s: 60,
            default_ttl_s: 1800,
            port_base: 30000,
            board_token_budget: 500,
            telemetry: false,
            listen_addr: None,
            credentials_backend: "off".into(),
            credentials_file: String::new(),
            vault_addr: String::new(),
            vault_role: String::new(),
        }
    }
}

/// 合法的凭据后端取值（F13；off = 凭据代理整体关闭）。
const CREDENTIALS_BACKENDS: &[&str] = &["off", "file", "vault"];

/// 合法的 enforcement 取值（resolve_layer 接受的全集）。
const ENFORCEMENT_VALUES: &[&str] = &[
    "auto", "off", "L1", "L2", "L3", "advisory", "landlock", "bpf",
];

/// 解析极简 TOML 子集：`[section]` 与 `key = value`（字符串/整数/布尔）。
/// v2.0 起键支持一层成对引号（F12 政策规则键是 glob，如 `"vault/**"`）。
pub fn parse_toml_lite(text: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut section = String::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            section = line[1..line.len() - 1].trim().to_string();
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let key_body = unquote(k.trim());
            let key = if section.is_empty() {
                key_body
            } else {
                format!("{}.{}", section, key_body)
            };
            out.insert(key, unquote(strip_inline_comment(v.trim())));
        }
    }
    out
}

/// 剥掉行内注释：值含 ` #`（引号外）时截断到注释前。
/// `telemetry = true # off for now` 此前会把整串当值，
/// 布尔解析静默落 false、deny reason 混入注释文本。
fn strip_inline_comment(v: &str) -> &str {
    let mut in_quote: Option<char> = None;
    let bytes = v.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i] as char;
        match (in_quote, c) {
            (Some(q), c2) if c2 == q => in_quote = None,
            (None, q @ ('"' | '\'')) => in_quote = Some(q),
            // TOML 行内注释以 # 开头；截断点之前的尾部空白一并去掉
            (None, '#') => return v[..i].trim_end(),
            _ => {}
        }
        i += 1;
    }
    v
}

/// 去掉一层成对引号（只剥一对，避免 `""x""` 之类被静默剥光）。
fn unquote(v: &str) -> String {
    for q in ['"', '\''] {
        if v.len() >= 2 && v.starts_with(q) && v.ends_with(q) {
            return v[1..v.len() - 1].to_string();
        }
    }
    v.to_string()
}

impl Config {
    /// 加载顺序：默认 → `--config` 指定文件 → `<root>/airlock.toml`（存在时）。
    pub fn load(explicit: Option<&Path>, root: &Path) -> Result<Config> {
        let mut cfg = Config::default();
        let candidates: Vec<std::path::PathBuf> = match explicit {
            Some(p) => vec![p.to_path_buf()],
            None => {
                let auto = root.join("airlock.toml");
                if auto.exists() {
                    vec![auto]
                } else {
                    vec![]
                }
            }
        };
        for p in &candidates {
            let text = std::fs::read_to_string(p)
                .map_err(|e| Error::Config(format!("无法读取配置 {}: {e}", p.display())))?;
            let kv = parse_toml_lite(&text);
            cfg.apply_kv(&kv, &p.display().to_string())?;
        }
        // F13 交叉校验：vault 后端必须有地址与角色（fail-fast，不发到 issue 时才发现）
        if cfg.credentials_backend == "vault" {
            if cfg.vault_addr.is_empty() {
                return Err(Error::Config(format!(
                    "credentials_backend = \"vault\" 需要同时配置 vault_addr（来自 {}）",
                    candidates
                        .last()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "默认值".into())
                )));
            }
            if cfg.vault_role.is_empty() {
                return Err(Error::Config(
                    "credentials_backend = \"vault\" 需要同时配置 vault_role".into(),
                ));
            }
        }
        Ok(cfg)
    }

    fn apply_kv(&mut self, kv: &BTreeMap<String, String>, from: &str) -> Result<()> {
        for (k, v) in kv {
            match k.as_str() {
                "enforcement" => {
                    if !ENFORCEMENT_VALUES.contains(&v.as_str()) {
                        return Err(Error::Config(format!(
                            "enforcement 值 `{v}` 非法（来自 {from}）；合法值：{}",
                            ENFORCEMENT_VALUES.join("/")
                        )));
                    }
                    self.enforcement = v.clone();
                }
                "heartbeat_s" => {
                    self.heartbeat_s = v.parse().map_err(|_| err(k, v, from))?;
                    if self.heartbeat_s < 1 {
                        return Err(Error::Config(format!("heartbeat_s 必须 ≥ 1（来自 {from}）")));
                    }
                }
                "default_ttl_s" => {
                    self.default_ttl_s = v.parse().map_err(|_| err(k, v, from))?;
                    if self.default_ttl_s < 2 {
                        return Err(Error::Config(format!("default_ttl_s 必须 ≥ 2（来自 {from}）")));
                    }
                }
                "port_base" => {
                    self.port_base = v.parse().map_err(|_| err(k, v, from))?;
                }
                "board_token_budget" => {
                    self.board_token_budget = v.parse().map_err(|_| err(k, v, from))?;
                }
                "telemetry" => {
                    self.telemetry = matches!(v.as_str(), "true" | "1" | "yes");
                }
                "listen_addr" => {
                    let addr = v.trim();
                    if addr.is_empty() {
                        return Err(Error::Config(format!("listen_addr 不能为空（来自 {from}）")));
                    }
                    self.listen_addr = Some(addr.to_string());
                }
                "credentials_backend" => {
                    if !CREDENTIALS_BACKENDS.contains(&v.as_str()) {
                        return Err(Error::Config(format!(
                            "credentials_backend 值 `{v}` 非法（来自 {from}）；合法值：{}",
                            CREDENTIALS_BACKENDS.join("/")
                        )));
                    }
                    self.credentials_backend = v.clone();
                }
                "credentials_file" => {
                    self.credentials_file = v.trim().to_string();
                }
                "vault_addr" => {
                    self.vault_addr = v.trim().to_string();
                }
                "vault_role" => {
                    self.vault_role = v.trim().to_string();
                }
                other => {
                    return Err(Error::Config(format!(
                        "未知配置键 `{other}`（来自 {from}）；合法键：enforcement/heartbeat_s/default_ttl_s/port_base/board_token_budget/telemetry/listen_addr/credentials_backend/credentials_file/vault_addr/vault_role"
                    )))
                }
            }
        }
        Ok(())
    }
}

fn err(k: &str, v: &str, from: &str) -> Error {
    Error::Config(format!("配置键 `{k}` 值 `{v}` 无法解析（来自 {from}）"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_toml_subset() {
        let kv = parse_toml_lite(
            "# comment\n[airlock]\nenforcement = \"off\"\nheartbeat_s = 5\ntelemetry = true\n",
        );
        assert_eq!(kv.get("airlock.enforcement").unwrap(), "off");
        assert_eq!(kv.get("airlock.heartbeat_s").unwrap(), "5");
        assert_eq!(kv.get("airlock.telemetry").unwrap(), "true");
    }

    #[test]
    fn inline_comments_are_stripped() {
        let kv = parse_toml_lite(
            "telemetry = true # off for now\nname = \"a # b\" # keep hash in quotes\nreason = 'x y' # note\nnum = 5#tight\n",
        );
        assert_eq!(kv.get("telemetry").unwrap(), "true");
        assert_eq!(kv.get("name").unwrap(), "a # b");
        assert_eq!(kv.get("reason").unwrap(), "x y");
        assert_eq!(kv.get("num").unwrap(), "5");
    }

    #[test]
    fn unknown_key_is_config_error() {
        let mut cfg = Config::default();
        let mut kv = BTreeMap::new();
        kv.insert("nope".to_string(), "1".to_string());
        assert!(cfg.apply_kv(&kv, "test").is_err());
    }

    #[test]
    fn enforcement_value_is_validated() {
        let mut cfg = Config::default();
        let mut kv = BTreeMap::new();
        kv.insert("enforcement".to_string(), "of".to_string()); // 拼写错误必须报错
        assert!(cfg.apply_kv(&kv, "test").is_err());
        let mut ok = BTreeMap::new();
        ok.insert("enforcement".to_string(), "landlock".to_string());
        cfg.apply_kv(&ok, "test").unwrap();
        assert_eq!(cfg.enforcement, "landlock");
    }
}
