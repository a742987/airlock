//! F13 凭据作用域代理（v2.0）：凭据随租约发放与吊销。
//!
//! **安全边界（PRD §8.3）**：只代理**测试资源凭据**（如分支测试库的连接串）；
//! 提交密钥与仓库凭据（git push token / SSH key）**永不**经过 Airlock 进程。
//!
//! **设计约束（路线图 §7 风险表）**：集成而非自造 vault，后端可替换——
//! [`CredBackend`] trait 的两个内置实现：
//! - [`FileBackend`]：本地凭据源文件（零外部依赖，完全可测）。吊销是记账性
//!   的：值已随 env 注入子进程，无法强制收回——文档明示，严格 ≤60s 失效
//!   语义只有动态后端（vault）提供。
//! - [`VaultBackend`]：HashiCorp Vault 动态密钥（`database/creds/<role>`），
//!   租约释放后由 daemon sweeper 吊销 vault lease（≤60s 验收）。
//!
//! 发放：claim 成功后由 daemon 调 [`issue_for_lease`]，env 随 claim 响应返回；
//! 吊销：租约 release/expire 后凭据仍 active → [`sweep_revocations`]（1s 周期）
//! 调后端吊销并落审计（结构性保证 ≤60s）。

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use crate::config::Config;
use crate::error::{Error, Result};
use crate::messages;
use crate::proto::{Actor, CredRow};
use crate::store::{now, Store};

/// 凭据申请的作用域：绑定到租约与资源名。
#[derive(Debug, Clone)]
pub struct CredScope {
    pub lease_id: String,
    pub agent_id: String,
    /// 资源名（如测试库 `app-db`）；不得含 `.`（凭据源文件按段名解析）
    pub resource: String,
    pub ttl_s: i64,
}

/// 后端发放结果：注入子进程的 env + 后端内部句柄（写 meta 供吊销）。
#[derive(Debug, Clone)]
pub struct IssuedCred {
    pub env: BTreeMap<String, String>,
    /// 后端句柄（如 vault lease_id）；与 env 一并存入 CredRow.meta
    pub backend_meta: serde_json::Value,
    /// 凭据失效时间（后端给出时）；None = 跟随租约生命周期
    pub expires_at: Option<i64>,
}

/// 可替换的凭据后端（路线图 §7：集成而非自造，保持后端可替换）。
pub trait CredBackend: Send + Sync {
    fn name(&self) -> &'static str;
    fn issue(&self, scope: &CredScope) -> Result<IssuedCred>;
    /// 吊销一个已发放的凭据（入参为发放时写入 meta 的后端句柄）。
    fn revoke(&self, backend_meta: &serde_json::Value) -> Result<()>;
}

// ---------- FileBackend ----------

/// 本地凭据源文件后端。文件位于域目录（git 仓库内时在 .git/airlock/ 下，
/// 天然不入库）：
///
/// ```toml
/// [app-db]
/// AIRLOCK_DB_URL = "postgres://user:pass@127.0.0.1:5432/app_test"
/// ```
///
/// 段名 = 资源名；键 = 注入子进程的 env 变量名。
pub struct FileBackend {
    pub path: PathBuf,
}

impl CredBackend for FileBackend {
    fn name(&self) -> &'static str {
        "file"
    }

    fn issue(&self, scope: &CredScope) -> Result<IssuedCred> {
        if scope.resource.contains('.') {
            let resource = scope.resource.clone();
            return Err(Error::Config(format!(
                "凭据资源名不得含 `.`：{resource}（凭据源文件按段名解析）"
            )));
        }
        let text = std::fs::read_to_string(&self.path).map_err(|e| {
            Error::NotFound(format!(
                "凭据源文件 {} 不可读（{e}）；{}",
                self.path.display(),
                messages::suggested_action::CREDENTIAL_UNAVAILABLE
            ))
        })?;
        let kv = crate::config::parse_toml_lite(&text);
        let prefix = format!("{}.", scope.resource);
        let mut env = BTreeMap::new();
        for (k, v) in &kv {
            if let Some(env_key) = k.strip_prefix(&prefix) {
                if !env_key.is_empty() && env_key.to_uppercase() == env_key {
                    env.insert(env_key.to_string(), v.clone());
                }
            }
        }
        if env.is_empty() {
            return Err(Error::NotFound(format!(
                "凭据源文件 {} 中不存在资源 `{}`；{}",
                self.path.display(),
                scope.resource,
                messages::suggested_action::CREDENTIAL_UNAVAILABLE
            )));
        }
        Ok(IssuedCred {
            env,
            backend_meta: serde_json::json!({ "file": self.path.to_string_lossy() }),
            expires_at: None,
        })
    }

    /// file 后端的吊销是记账性的：值已随 env 注入，无法强制收回（模块文档明示）。
    /// 记账仍有意义：审计链记录吊销事实，`creds list` 不再返回该凭据。
    fn revoke(&self, _backend_meta: &serde_json::Value) -> Result<()> {
        Ok(())
    }
}

// ---------- VaultBackend ----------

/// HashiCorp Vault 动态密钥后端（`POST /v1/database/creds/<role>`）。
/// Vault 令牌从环境变量 `VAULT_TOKEN` 读取（缺省时匿名请求，适配免认证的
/// 测试/开发端点）。data 中的字符串字段逐个映射为 `AIRLOCK_<KEY>` 环境变量。
pub struct VaultBackend {
    pub addr: String,
    pub role: String,
    pub token: Option<String>,
}

impl CredBackend for VaultBackend {
    fn name(&self) -> &'static str {
        "vault"
    }

    fn issue(&self, _scope: &CredScope) -> Result<IssuedCred> {
        let url = format!(
            "{}/v1/database/creds/{}",
            self.addr.trim_end_matches('/'),
            self.role
        );
        let (_status, body) = vault_post(&url, self.token.as_deref(), &serde_json::json!({}))?;
        let v: serde_json::Value = serde_json::from_str(&body)
            .map_err(|e| Error::Other(format!("Vault 响应不是合法 JSON：{e}")))?;
        let data = v
            .get("data")
            .and_then(|d| d.as_object())
            .ok_or_else(|| Error::Other("Vault 响应缺少 data 对象".into()))?;
        let mut env = BTreeMap::new();
        for (k, val) in data {
            if let Some(s) = val.as_str() {
                env.insert(format!("AIRLOCK_{}", k.to_uppercase()), s.to_string());
            }
        }
        if env.is_empty() {
            return Err(Error::Other("Vault 动态密钥未返回任何字符串字段".into()));
        }
        let lease_duration = v
            .get("lease_duration")
            .and_then(|d| d.as_i64())
            .unwrap_or(0);
        let expires_at = (lease_duration > 0).then(|| now() + lease_duration);
        Ok(IssuedCred {
            env,
            backend_meta: serde_json::json!({
                "vault_lease_id": v.get("lease_id").and_then(|l| l.as_str()).unwrap_or(""),
                "vault_addr": self.addr,
            }),
            expires_at,
        })
    }

    fn revoke(&self, backend_meta: &serde_json::Value) -> Result<()> {
        let lease_id = backend_meta
            .get("vault_lease_id")
            .and_then(|l| l.as_str())
            .unwrap_or("");
        if lease_id.is_empty() {
            return Err(Error::Other(
                "凭据 meta 缺少 vault_lease_id，无法吊销".into(),
            ));
        }
        let addr = backend_meta
            .get("vault_addr")
            .and_then(|a| a.as_str())
            .unwrap_or(&self.addr);
        let url = format!("{}/v1/sys/leases/revoke", addr.trim_end_matches('/'));
        vault_post(
            &url,
            self.token.as_deref(),
            &serde_json::json!({ "lease_id": lease_id }),
        )?;
        Ok(())
    }
}

/// Vault HTTP POST（JSON 进 / JSON 或 204 出）。非 2xx → 带响应体的错误。
fn vault_post(url: &str, token: Option<&str>, body: &serde_json::Value) -> Result<(u16, String)> {
    let mut req = ureq::post(url).timeout(Duration::from_secs(10));
    if let Some(t) = token {
        if !t.is_empty() {
            req = req.set("X-Vault-Token", t);
        }
    }
    let payload = body.to_string();
    let req = req.set("Content-Type", "application/json");
    match req.send_string(&payload) {
        Ok(resp) => {
            let status = resp.status();
            let text = resp.into_string().unwrap_or_default();
            Ok((status, text))
        }
        Err(ureq::Error::Status(status, resp)) => {
            let text = resp.into_string().unwrap_or_default();
            Err(Error::Other(format!(
                "Vault 请求失败（HTTP {status}）：{}",
                text.chars().take(200).collect::<String>()
            )))
        }
        Err(e) => Err(Error::Other(format!(
            "Vault 不可达（{url}）：{e}；{}",
            messages::suggested_action::CREDENTIAL_UNAVAILABLE
        ))),
    }
}

// ---------- 组装与生命周期 ----------

/// 按配置构造后端；`credentials_backend = "off"` → None。
pub fn backend_from_config(
    cfg: &Config,
    domain_dir: &std::path::Path,
) -> Result<Option<Box<dyn CredBackend>>> {
    match cfg.credentials_backend.as_str() {
        "off" => Ok(None),
        other => backend_by_name(cfg, domain_dir, other),
    }
}

/// 按名称构造后端。吊销路径以**凭据记录的 backend** 为准（配置可能事后改动），
/// 不受当前 `credentials_backend` 影响。
pub fn backend_by_name(
    cfg: &Config,
    domain_dir: &std::path::Path,
    name: &str,
) -> Result<Option<Box<dyn CredBackend>>> {
    match name {
        "file" => {
            let path = if cfg.credentials_file.is_empty() {
                domain_dir.join("credentials.toml")
            } else {
                let p = PathBuf::from(&cfg.credentials_file);
                if p.is_absolute() {
                    p
                } else {
                    domain_dir.join(p)
                }
            };
            // 凭据源文件收紧为 0600（通常由本用户创建，失败仅忽略——
            // 域目录本身已是 0700）
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
            }
            Ok(Some(Box::new(FileBackend { path })))
        }
        "vault" => {
            if cfg.vault_addr.is_empty() || cfg.vault_role.is_empty() {
                return Err(Error::Config(
                    "凭据记录引用 vault 后端，但 airlock.toml 未配置 vault_addr/vault_role".into(),
                ));
            }
            // http:// 明文传输 X-Vault-Token：仅回环地址可接受，否则显式警告
            let addr = cfg.vault_addr.clone();
            if addr.starts_with("http://") && !is_loopback_http_addr(&addr) {
                eprintln!(
                    "⚠ vault_addr 使用明文 http://（{}）：VAULT_TOKEN 将以明文传输，仅建议在受信任的本机/隔离网络使用",
                    addr
                );
            }
            Ok(Some(Box::new(VaultBackend {
                addr,
                role: cfg.vault_role.clone(),
                token: std::env::var("VAULT_TOKEN").ok().filter(|t| !t.is_empty()),
            })))
        }
        other => Err(Error::Config(format!(
            "未知凭据后端 `{other}`（合法值：file/vault）"
        ))),
    }
}

/// http:// 地址是否指向回环（127.0.0.1 / localhost / [::1]）。
fn is_loopback_http_addr(addr: &str) -> bool {
    let host = addr
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or("");
    let host = host.rsplit_once(':').map(|(h, _)| h).unwrap_or(host);
    let host = host.trim_start_matches('[').trim_end_matches(']');
    matches!(host, "127.0.0.1" | "localhost" | "::1" | "[::1]")
}

/// 发放凭据并落库 + 审计（claim 成功后由 daemon 调用）。
/// 返回注入子进程的 env 映射。
pub fn issue_for_lease(
    store: &Store,
    backend: &dyn CredBackend,
    scope: &CredScope,
) -> Result<BTreeMap<String, String>> {
    let issued = backend.issue(scope)?;
    let id = uuid::Uuid::new_v4().to_string();
    let row = CredRow {
        id: id.clone(),
        lease_id: scope.lease_id.clone(),
        backend: backend.name().to_string(),
        resource: scope.resource.clone(),
        status: "active".into(),
        issued_at: now(),
        expires_at: issued.expires_at,
        revoked_at: None,
        meta: Some(serde_json::json!({
            "env": issued.env,
            "backend": issued.backend_meta,
        })),
    };
    store.insert_credential(&row)?;
    store.audit(
        "cred_issue",
        &Actor {
            agent: scope.agent_id.clone(),
            session: String::new(),
            pid_tree: vec![],
        },
        &scope.resource,
        Some(&scope.lease_id),
        "L1",
        Some(&serde_json::json!({ "cred_id": id, "backend": backend.name() })),
    )?;
    Ok(issued.env)
}

/// 立即吊销单个凭据（管理员 `airlock creds revoke` / sweeper 共用）。
/// 后端吊销成功才落 revoked 状态（失败留待下轮 sweep 重试，自愈）。
pub fn revoke_one(store: &Store, backend: &dyn CredBackend, cred_id: &str) -> Result<bool> {
    let Some(row) = store.get_credential(cred_id)? else {
        return Err(Error::NotFound(format!("凭据 {cred_id} 不存在")));
    };
    if row.status != "active" {
        return Ok(false);
    }
    let meta = row.meta.clone().unwrap_or(serde_json::json!({}));
    backend.revoke(&meta)?;
    store.mark_credential_revoked(cred_id)?;
    // 凭据值不得在吊销后长期躺在数据库里（L2 只限写不限读，任何 agent
    // 都能直读 .git/airlock/airlock.db）：吊销即清除 meta 中的 env 原文。
    // 后端句柄保留，供审计与重试。
    store.purge_credential_env(cred_id)?;
    store.audit(
        "cred_revoke",
        &Actor::default(),
        &row.resource,
        Some(&row.lease_id),
        "L1",
        Some(&serde_json::json!({ "cred_id": cred_id, "backend": row.backend })),
    )?;
    Ok(true)
}

/// sweeper 钩子：吊销所有「所属租约已不活跃」的凭据（≤60s 验收的执行点）。
/// 后端按凭据记录的 backend 逐一构造；单条失败不阻塞其余（下轮 1s sweep
/// 重试，自愈）；返回成功吊销数。
pub fn sweep_revocations(
    store: &Store,
    cfg: &Config,
    domain_dir: &std::path::Path,
) -> Result<usize> {
    let mut n = 0;
    for row in store.credentials_to_revoke()? {
        let backend = match backend_by_name(cfg, domain_dir, &row.backend) {
            Ok(b) => b,
            Err(e) => {
                let _ = store.audit(
                    "degrade",
                    &Actor::default(),
                    &row.resource,
                    Some(&row.lease_id),
                    "L1",
                    Some(&serde_json::json!({
                        "event_detail": "cred_revoke_backend_error",
                        "cred_id": row.id,
                        "error": e.to_string(),
                    })),
                );
                continue;
            }
        };
        let Some(backend) = backend else {
            continue;
        };
        match revoke_one(store, backend.as_ref(), &row.id) {
            Ok(true) => n += 1,
            Ok(false) => {}
            Err(e) => {
                let _ = store.audit(
                    "degrade",
                    &Actor::default(),
                    &row.resource,
                    Some(&row.lease_id),
                    "L1",
                    Some(&serde_json::json!({
                        "event_detail": "cred_revoke_retry",
                        "cred_id": row.id,
                        "error": e.to_string(),
                    })),
                );
            }
        }
    }
    Ok(n)
}

/// `creds list` 输出前的脱敏：meta 中的 env 值替换为变量名清单。
pub fn sanitize_row(row: &CredRow) -> CredRow {
    let mut row = row.clone();
    if let Some(meta) = &row.meta {
        let env_keys: Vec<String> = meta
            .get("env")
            .and_then(|e| e.as_object())
            .map(|o| o.keys().cloned().collect())
            .unwrap_or_default();
        let mut sanitized = meta.clone();
        sanitized["env_keys"] = serde_json::json!(env_keys);
        if let Some(obj) = sanitized.as_object_mut() {
            obj.remove("env");
        }
        row.meta = Some(sanitized);
    }
    row
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope(resource: &str) -> CredScope {
        CredScope {
            lease_id: "lease-1".into(),
            agent_id: "codex".into(),
            resource: resource.into(),
            ttl_s: 1800,
        }
    }

    #[test]
    fn file_backend_issues_and_scopes() {
        let tmp = std::env::temp_dir().join(format!("airlock-cred-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).unwrap();
        let path = tmp.join("credentials.toml");
        std::fs::write(
            &path,
            "[app-db]\nAIRLOCK_DB_URL = \"postgres://u:p@127.0.0.1:5432/app_test\"\n\n[other-db]\nAIRLOCK_DB_URL = \"x\"\n",
        )
        .unwrap();
        let b = FileBackend { path };
        let issued = b.issue(&scope("app-db")).unwrap();
        assert_eq!(
            issued.env.get("AIRLOCK_DB_URL").map(String::as_str),
            Some("postgres://u:p@127.0.0.1:5432/app_test")
        );
        // 其他资源的凭据不得泄漏进本租约的 env（作用域隔离）
        assert_eq!(issued.env.len(), 1);
        // 不存在的资源 → NotFound
        assert!(b.issue(&scope("nope")).is_err());
        // 含点的资源名 → Config
        assert!(b.issue(&scope("a.b")).is_err());
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn sanitize_strips_env_values() {
        let row = CredRow {
            id: "c1".into(),
            lease_id: "l1".into(),
            backend: "file".into(),
            resource: "app-db".into(),
            status: "active".into(),
            issued_at: 0,
            expires_at: None,
            revoked_at: None,
            meta: Some(serde_json::json!({
                "env": { "AIRLOCK_DB_URL": "postgres://u:p@x" },
                "backend": { "file": "/tmp/x" }
            })),
        };
        let s = sanitize_row(&row);
        let meta = s.meta.unwrap();
        assert!(meta.get("env").is_none());
        assert_eq!(
            meta.get("env_keys").unwrap(),
            &serde_json::json!(["AIRLOCK_DB_URL"])
        );
        assert!(meta.get("backend").is_some());
    }

    #[test]
    fn lifecycle_with_store() {
        let store = Store::open_in_memory().unwrap();
        let tmp = std::env::temp_dir().join(format!("airlock-cred-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(
            tmp.join("credentials.toml"),
            "[app-db]\nAIRLOCK_DB_URL = \"x://y\"\n",
        )
        .unwrap();
        let b = FileBackend {
            path: tmp.join("credentials.toml"),
        };
        let env = issue_for_lease(&store, &b, &scope("app-db")).unwrap();
        assert_eq!(env.len(), 1);
        let listed = store.list_credentials(None).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].status, "active");
        // 租约不再 active → credentials_to_revoke 命中 → 吊销成功
        store.update_lease_state("lease-1", "released").ok(); // 不存在也无所谓：JOIN 无行
                                                              // 真实路径：插入对应租约行
        store
            .insert_lease(&crate::proto::LeaseInfo {
                id: "lease-1".into(),
                conflict_domain: "d".into(),
                agent_id: "codex".into(),
                session_id: "s".into(),
                glob: "src/**".into(),
                intent: None,
                state: "active".into(),
                issued_at: 0,
                ttl_s: 1800,
                last_heartbeat: 0,
                expires_at: 1800,
                enforcement_layer: "L1".into(),
                tokens_used: 0,
                cost_cents: 0,
            })
            .unwrap();
        assert!(store.credentials_to_revoke().unwrap().is_empty());
        store.update_lease_state("lease-1", "released").unwrap();
        let to_revoke = store.credentials_to_revoke().unwrap();
        assert_eq!(to_revoke.len(), 1);
        let cfg = Config {
            credentials_backend: "file".into(),
            credentials_file: tmp.join("credentials.toml").to_string_lossy().to_string(),
            ..Default::default()
        };
        assert_eq!(sweep_revocations(&store, &cfg, &tmp).unwrap(), 1);
        let after = store.get_credential(&listed[0].id).unwrap().unwrap();
        assert_eq!(after.status, "revoked");
        // 吊销后 meta 中的凭据明文已清除（L2 不限读，DB 文件任何 agent 可读）
        assert!(
            after.meta.as_ref().unwrap().get("env").is_none(),
            "吊销后 meta.env 必须被清除：{:?}",
            after.meta
        );
        // 吊销后 sweep 不再命中
        assert_eq!(sweep_revocations(&store, &cfg, &tmp).unwrap(), 0);
        std::fs::remove_dir_all(&tmp).ok();
    }
}
