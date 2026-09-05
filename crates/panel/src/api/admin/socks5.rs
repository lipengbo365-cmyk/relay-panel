use super::err;
use crate::api::middleware::AdminOnly;
use crate::api::AppState;
use crate::db::error::DbError;
use crate::db::repo::ResourceScope;
use crate::service::credentials::CredentialCipher;
use crate::service::socks5::{validate_endpoint, Socks5ResourcePublic, Socks5RulePublic};
use axum::{
    extract::{Path, State},
    Json,
};
use relay_shared::protocol::ApiResponse;
use serde::Deserialize;

const RESOURCE_PASSWORD_PURPOSE: &str = "socks5-resource-password";
const RELAY_PASSWORD_PURPOSE: &str = "socks5-relay-password";

#[derive(Deserialize)]
pub struct CreateSocks5ResourceRequest {
    pub name: String,
    pub host: String,
    pub port: i32,
    pub username: Option<String>,
    pub password: Option<String>,
    #[serde(default)]
    pub country: String,
    #[serde(default)]
    pub country_code: String,
    #[serde(default)]
    pub region: String,
    #[serde(default)]
    pub city: String,
    #[serde(default)]
    pub isp: String,
    #[serde(default)]
    pub remark: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

#[derive(Deserialize, Default)]
pub struct UpdateSocks5ResourceRequest {
    pub name: Option<String>,
    pub host: Option<String>,
    pub port: Option<i32>,
    /// Omitted keeps the username, null clears it, and a string replaces it.
    pub username: Option<Option<String>>,
    /// Omitted or empty keeps the encrypted password.
    pub password: Option<String>,
    #[serde(default)]
    pub clear_password: bool,
    pub country: Option<String>,
    pub country_code: Option<String>,
    pub region: Option<String>,
    pub city: Option<String>,
    pub isp: Option<String>,
    pub remark: Option<String>,
    pub enabled: Option<bool>,
}

#[derive(Deserialize)]
pub struct CreateSocks5RuleRequest {
    pub name: String,
    pub device_group_in: i64,
    pub listen_port: Option<i32>,
    pub socks5_resource_id: i64,
    pub relay_username: Option<String>,
    pub relay_password: Option<String>,
    #[serde(default)]
    pub allow_no_auth: bool,
    #[serde(default = "default_true")]
    pub remote_dns: bool,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

#[derive(Deserialize)]
pub struct UpdateSocks5RuleRequest {
    pub name: String,
    pub device_group_in: i64,
    pub listen_port: i32,
    pub socks5_resource_id: i64,
    #[serde(default = "default_true")]
    pub remote_dns: bool,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

#[derive(Deserialize)]
pub struct ResetSocks5RuleCredentialRequest {
    pub username: String,
    pub password: String,
}

fn default_true() -> bool {
    true
}

fn normalize_optional(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let value = value.trim().to_owned();
        (!value.is_empty()).then_some(value)
    })
}

fn credential_cipher(state: &AppState) -> Result<CredentialCipher, Json<ApiResponse<()>>> {
    CredentialCipher::from_config(state.config.socks5_credential_key.as_deref()).map_err(|e| {
        tracing::error!("SOCKS5 credential encryption is unavailable: {e:?}");
        Json(err(503, "SOCKS5 凭据加密密钥未配置或无效"))
    })
}

fn validate_credential_pair(
    username: Option<&str>,
    has_password: bool,
) -> Result<(), &'static str> {
    if username.is_some() != has_password {
        return Err("用户名和密码必须同时设置或同时留空");
    }
    Ok(())
}

async fn broadcast_config_changed(state: &AppState) {
    state
        .node_connections
        .broadcast_all(r#"{"type":"config_changed"}"#)
        .await;
}

pub async fn list_socks5_resources(
    _admin: AdminOnly,
    State(state): State<AppState>,
) -> Json<ApiResponse<Vec<Socks5ResourcePublic>>> {
    match state.db.list_socks5_resources().await {
        Ok(rows) => Json(ApiResponse::success(
            rows.into_iter().map(Into::into).collect(),
        )),
        Err(e) => {
            tracing::error!("list_socks5_resources: {e}");
            Json(err(500, "数据库错误"))
        }
    }
}

pub async fn create_socks5_resource(
    _admin: AdminOnly,
    State(state): State<AppState>,
    Json(req): Json<CreateSocks5ResourceRequest>,
) -> Json<ApiResponse<Socks5ResourcePublic>> {
    if let Err(message) = validate_endpoint(&req.name, &req.host, req.port) {
        return Json(err(400, message));
    }
    let username = normalize_optional(req.username);
    let password = normalize_optional(req.password);
    if let Err(message) = validate_credential_pair(username.as_deref(), password.is_some()) {
        return Json(err(400, message));
    }
    let (ciphertext, nonce, key_version) = match password.as_deref() {
        Some(password) => {
            let cipher = match credential_cipher(&state) {
                Ok(cipher) => cipher,
                Err(response) => return response.map_data(),
            };
            match cipher.encrypt(password, RESOURCE_PASSWORD_PURPOSE) {
                Ok((ciphertext, nonce, version)) => (Some(ciphertext), Some(nonce), version),
                Err(e) => {
                    tracing::error!("encrypt SOCKS5 resource credential: {e:?}");
                    return Json(err(500, "凭据加密失败"));
                }
            }
        }
        None => (None, None, 1),
    };

    let id = match state
        .db
        .insert_socks5_resource(
            req.name.trim(),
            req.host.trim(),
            req.port,
            username.as_deref(),
            ciphertext.as_deref(),
            nonce.as_deref(),
            key_version,
            req.country.trim(),
            req.country_code.trim(),
            req.region.trim(),
            req.city.trim(),
            req.isp.trim(),
            req.remark.trim(),
            req.enabled,
        )
        .await
    {
        Ok(id) => id,
        Err(DbError::UniqueViolation) => {
            return Json(err(409, "相同地址和用户名的 SOCKS5 资源已存在"));
        }
        Err(e) => {
            tracing::error!("create_socks5_resource: {e}");
            return Json(err(500, "数据库错误"));
        }
    };

    match state.db.find_socks5_resource(id).await {
        Ok(Some(row)) => Json(ApiResponse::success(row.into())),
        Ok(None) => Json(err(500, "创建后读取 SOCKS5 资源失败")),
        Err(e) => {
            tracing::error!("read created SOCKS5 resource {id}: {e}");
            Json(err(500, "数据库错误"))
        }
    }
}

pub async fn get_socks5_resource(
    _admin: AdminOnly,
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Json<ApiResponse<Socks5ResourcePublic>> {
    match state.db.find_socks5_resource(id).await {
        Ok(Some(row)) => Json(ApiResponse::success(row.into())),
        Ok(None) => Json(err(404, "SOCKS5 资源不存在")),
        Err(e) => {
            tracing::error!("get_socks5_resource {id}: {e}");
            Json(err(500, "数据库错误"))
        }
    }
}

pub async fn update_socks5_resource(
    _admin: AdminOnly,
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(req): Json<UpdateSocks5ResourceRequest>,
) -> Json<ApiResponse<Socks5ResourcePublic>> {
    let current = match state.db.find_socks5_resource(id).await {
        Ok(Some(row)) => row,
        Ok(None) => return Json(err(404, "SOCKS5 资源不存在")),
        Err(e) => {
            tracing::error!("update_socks5_resource lookup {id}: {e}");
            return Json(err(500, "数据库错误"));
        }
    };

    let name = req.name.unwrap_or(current.name);
    let host = req.host.unwrap_or(current.host);
    let port = req.port.unwrap_or(current.port);
    if let Err(message) = validate_endpoint(&name, &host, port) {
        return Json(err(400, message));
    }
    let username = match req.username {
        Some(value) => normalize_optional(value),
        None => current.username,
    };
    let supplied_password = normalize_optional(req.password);
    let (ciphertext, nonce, key_version) = if req.clear_password {
        (None, None, 1)
    } else if let Some(password) = supplied_password.as_deref() {
        let cipher = match credential_cipher(&state) {
            Ok(cipher) => cipher,
            Err(response) => return response.map_data(),
        };
        match cipher.encrypt(password, RESOURCE_PASSWORD_PURPOSE) {
            Ok((ciphertext, nonce, version)) => (Some(ciphertext), Some(nonce), version),
            Err(e) => {
                tracing::error!("encrypt SOCKS5 resource credential: {e:?}");
                return Json(err(500, "凭据加密失败"));
            }
        }
    } else {
        (
            current.password_ciphertext,
            current.password_nonce,
            current.password_key_version,
        )
    };
    if let Err(message) = validate_credential_pair(username.as_deref(), ciphertext.is_some()) {
        return Json(err(400, message));
    }

    let result = state
        .db
        .update_socks5_resource_full(
            id,
            name.trim(),
            host.trim(),
            port,
            username.as_deref(),
            ciphertext.as_deref(),
            nonce.as_deref(),
            key_version,
            req.country.as_deref().unwrap_or(&current.country).trim(),
            req.country_code
                .as_deref()
                .unwrap_or(&current.country_code)
                .trim(),
            req.region.as_deref().unwrap_or(&current.region).trim(),
            req.city.as_deref().unwrap_or(&current.city).trim(),
            req.isp.as_deref().unwrap_or(&current.isp).trim(),
            req.remark.as_deref().unwrap_or(&current.remark).trim(),
            req.enabled.unwrap_or(current.enabled),
        )
        .await;
    match result {
        Ok(0) => return Json(err(404, "SOCKS5 资源不存在")),
        Ok(_) => {}
        Err(DbError::UniqueViolation) => {
            return Json(err(409, "相同地址和用户名的 SOCKS5 资源已存在"));
        }
        Err(e) => {
            tracing::error!("update_socks5_resource {id}: {e}");
            return Json(err(500, "数据库错误"));
        }
    }
    broadcast_config_changed(&state).await;
    get_socks5_resource(_admin, State(state), Path(id)).await
}

pub async fn set_socks5_resource_enabled(
    _admin: AdminOnly,
    State(state): State<AppState>,
    Path((id, enabled)): Path<(i64, bool)>,
) -> Json<ApiResponse<()>> {
    match state.db.set_socks5_resource_enabled(id, enabled).await {
        Ok(0) => Json(err(404, "SOCKS5 资源不存在")),
        Ok(_) => {
            broadcast_config_changed(&state).await;
            Json(ApiResponse::success(()))
        }
        Err(e) => {
            tracing::error!("set_socks5_resource_enabled {id}: {e}");
            Json(err(500, "数据库错误"))
        }
    }
}

pub async fn delete_socks5_resource(
    _admin: AdminOnly,
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Json<ApiResponse<()>> {
    match state.db.count_socks5_resource_bindings(id).await {
        Ok(count) if count > 0 => {
            return Json(err(409, format!("资源仍被 {count} 条规则使用")));
        }
        Ok(_) => {}
        Err(e) => {
            tracing::error!("count SOCKS5 resource bindings {id}: {e}");
            return Json(err(500, "数据库错误"));
        }
    }
    match state.db.delete_socks5_resource(id).await {
        Ok(0) => Json(err(404, "SOCKS5 资源不存在")),
        Ok(_) => Json(ApiResponse::success(())),
        Err(DbError::ForeignKeyViolation) => Json(err(409, "资源仍被规则使用")),
        Err(e) => {
            tracing::error!("delete_socks5_resource {id}: {e}");
            Json(err(500, "数据库错误"))
        }
    }
}

pub async fn list_socks5_rules(
    _admin: AdminOnly,
    State(state): State<AppState>,
) -> Json<ApiResponse<Vec<Socks5RulePublic>>> {
    match state.db.list_socks5_rule_views().await {
        Ok(rows) => Json(ApiResponse::success(
            rows.into_iter().map(Into::into).collect(),
        )),
        Err(e) => {
            tracing::error!("list_socks5_rules: {e}");
            Json(err(500, "数据库错误"))
        }
    }
}

pub async fn create_socks5_rule(
    admin: AdminOnly,
    State(state): State<AppState>,
    Json(req): Json<CreateSocks5RuleRequest>,
) -> Json<ApiResponse<Socks5RulePublic>> {
    if req.name.trim().is_empty() {
        return Json(err(400, "规则名称不能为空"));
    }
    let group = match crate::db::repo::GroupRepository::find_by_id(
        state.db.as_ref(),
        req.device_group_in,
        &ResourceScope::All,
    )
    .await
    {
        Ok(Some(group)) if group.group_type == "in" => group,
        Ok(Some(_)) => return Json(err(400, "SOCKS5 入口必须选择入口分组")),
        Ok(None) => return Json(err(404, "入口分组不存在")),
        Err(e) => {
            tracing::error!("create_socks5_rule group lookup: {e}");
            return Json(err(500, "数据库错误"));
        }
    };
    match state.db.find_socks5_resource(req.socks5_resource_id).await {
        Ok(Some(resource)) if resource.enabled => {}
        Ok(Some(_)) => return Json(err(400, "SOCKS5 资源已禁用")),
        Ok(None) => return Json(err(404, "SOCKS5 资源不存在")),
        Err(e) => {
            tracing::error!("create_socks5_rule resource lookup: {e}");
            return Json(err(500, "数据库错误"));
        }
    }

    let relay_username = normalize_optional(req.relay_username);
    let relay_password = normalize_optional(req.relay_password);
    if req.allow_no_auth
        && !std::env::var("ALLOW_NO_AUTH_SOCKS5")
            .ok()
            .is_some_and(|value| matches!(value.as_str(), "1" | "true" | "TRUE"))
    {
        return Json(err(
            400,
            "无认证入口仅允许开发/测试环境（需显式设置 ALLOW_NO_AUTH_SOCKS5=1）",
        ));
    }
    if req.allow_no_auth && (relay_username.is_some() || relay_password.is_some()) {
        return Json(err(400, "无认证入口不能同时保存入口用户名或密码"));
    }
    if !req.allow_no_auth {
        if let Err(message) =
            validate_credential_pair(relay_username.as_deref(), relay_password.is_some())
        {
            return Json(err(400, message));
        }
        if relay_username.is_none() {
            return Json(err(400, "生产规则必须设置入口 SOCKS5 用户名和密码"));
        }
    }
    let (relay_ciphertext, relay_nonce, relay_key_version) =
        if let Some(password) = relay_password.as_deref() {
            let cipher = match credential_cipher(&state) {
                Ok(cipher) => cipher,
                Err(response) => return response.map_data(),
            };
            match cipher.encrypt(password, RELAY_PASSWORD_PURPOSE) {
                Ok((ciphertext, nonce, version)) => (Some(ciphertext), Some(nonce), version),
                Err(e) => {
                    tracing::error!("encrypt relay credential: {e:?}");
                    return Json(err(500, "凭据加密失败"));
                }
            }
        } else {
            (None, None, 1)
        };

    let mut auto_port = req.listen_port.is_none();
    for _ in 0..32 {
        let listen_port = match req.listen_port {
            Some(port) if (1..=65535).contains(&port) => port,
            Some(_) => return Json(err(400, "监听端口必须在 1-65535 之间")),
            None => {
                match crate::service::rules::auto_assign_port(state.db.as_ref(), group.id, "tcp")
                    .await
                {
                    Ok(port) => i32::from(port),
                    Err(message) => return Json(err(409, message)),
                }
            }
        };
        match state
            .db
            .create_socks5_rule_full(
                req.name.trim(),
                admin.user_id,
                listen_port,
                group.id,
                req.socks5_resource_id,
                req.remote_dns,
                relay_username.as_deref(),
                relay_ciphertext.as_deref(),
                relay_nonce.as_deref(),
                relay_key_version,
                req.allow_no_auth,
                req.enabled,
            )
            .await
        {
            Ok(Some(rule_id)) => {
                broadcast_config_changed(&state).await;
                let rows = match state.db.list_socks5_rule_views().await {
                    Ok(rows) => rows,
                    Err(e) => {
                        tracing::error!("read created SOCKS5 rule {rule_id}: {e}");
                        return Json(err(500, "数据库错误"));
                    }
                };
                return match rows.into_iter().find(|row| row.rule_id == rule_id) {
                    Some(row) => Json(ApiResponse::success(row.into())),
                    None => Json(err(500, "创建后读取 SOCKS5 规则失败")),
                };
            }
            Ok(None) => return Json(err(409, "规则配额已满")),
            Err(DbError::PortConflict | DbError::UniqueViolation) if auto_port => {
                auto_port = true;
            }
            Err(DbError::PortConflict | DbError::UniqueViolation) => {
                return Json(err(409, "该入口分组上的监听端口已被占用"));
            }
            Err(DbError::NotFound | DbError::ForeignKeyViolation) => {
                return Json(err(404, "SOCKS5 资源或入口分组不存在"));
            }
            Err(e) => {
                tracing::error!("create_socks5_rule: {e}");
                return Json(err(500, "数据库错误"));
            }
        }
    }
    Json(err(409, "自动端口分配冲突，请重试"))
}

pub async fn update_socks5_rule(
    _admin: AdminOnly,
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(req): Json<UpdateSocks5RuleRequest>,
) -> Json<ApiResponse<Socks5RulePublic>> {
    if req.name.trim().is_empty() {
        return Json(err(400, "规则名称不能为空"));
    }
    if !(1..=65535).contains(&req.listen_port) {
        return Json(err(400, "监听端口必须在 1-65535 之间"));
    }
    match crate::db::repo::GroupRepository::find_by_id(
        state.db.as_ref(),
        req.device_group_in,
        &ResourceScope::All,
    )
    .await
    {
        Ok(Some(group)) if group.group_type == "in" => {}
        Ok(Some(_)) => return Json(err(400, "SOCKS5 入口必须选择入口分组")),
        Ok(None) => return Json(err(404, "入口分组不存在")),
        Err(e) => {
            tracing::error!("update_socks5_rule group lookup: {e}");
            return Json(err(500, "数据库错误"));
        }
    }
    match state.db.find_socks5_resource(req.socks5_resource_id).await {
        Ok(Some(resource)) if resource.enabled => {}
        Ok(Some(_)) => return Json(err(400, "SOCKS5 资源已禁用")),
        Ok(None) => return Json(err(404, "SOCKS5 资源不存在")),
        Err(e) => {
            tracing::error!("update_socks5_rule resource lookup: {e}");
            return Json(err(500, "数据库错误"));
        }
    }
    match state
        .db
        .update_socks5_rule_full(
            id,
            req.name.trim(),
            req.listen_port,
            req.device_group_in,
            req.socks5_resource_id,
            req.remote_dns,
            req.enabled,
        )
        .await
    {
        Ok(0) => return Json(err(404, "SOCKS5 规则不存在")),
        Ok(_) => {}
        Err(DbError::PortConflict | DbError::UniqueViolation) => {
            return Json(err(409, "该入口分组上的监听端口已被占用"));
        }
        Err(DbError::NotFound | DbError::ForeignKeyViolation) => {
            return Json(err(404, "SOCKS5 资源或入口分组不存在"));
        }
        Err(e) => {
            tracing::error!("update_socks5_rule {id}: {e}");
            return Json(err(500, "数据库错误"));
        }
    }
    broadcast_config_changed(&state).await;
    match state
        .db
        .list_socks5_rule_views()
        .await
        .map(|rows| rows.into_iter().find(|row| row.rule_id == id))
    {
        Ok(Some(row)) => Json(ApiResponse::success(row.into())),
        Ok(None) => Json(err(500, "更新后读取 SOCKS5 规则失败")),
        Err(e) => {
            tracing::error!("read updated SOCKS5 rule {id}: {e}");
            Json(err(500, "数据库错误"))
        }
    }
}

pub async fn set_socks5_rule_enabled(
    _admin: AdminOnly,
    State(state): State<AppState>,
    Path((id, enabled)): Path<(i64, bool)>,
) -> Json<ApiResponse<()>> {
    match state.db.find_socks5_rule_config(id).await {
        Ok(Some(_)) => {}
        Ok(None) => return Json(err(404, "SOCKS5 规则不存在")),
        Err(e) => {
            tracing::error!("find SOCKS5 rule before enabled update {id}: {e}");
            return Json(err(500, "数据库错误"));
        }
    }
    match state
        .db
        .update_rule_fields(
            id,
            &ResourceScope::All,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(!enabled),
        )
        .await
    {
        Ok(0) => Json(err(404, "SOCKS5 规则不存在")),
        Ok(_) => {
            broadcast_config_changed(&state).await;
            Json(ApiResponse::success(()))
        }
        Err(DbError::QuotaExceeded) => Json(err(409, "规则配额已满")),
        Err(e) => {
            tracing::error!("set_socks5_rule_enabled {id}: {e}");
            Json(err(500, "数据库错误"))
        }
    }
}

pub async fn delete_socks5_rule(
    _admin: AdminOnly,
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Json<ApiResponse<()>> {
    match state.db.find_socks5_rule_config(id).await {
        Ok(Some(_)) => {}
        Ok(None) => return Json(err(404, "SOCKS5 规则不存在")),
        Err(e) => {
            tracing::error!("find SOCKS5 rule before delete {id}: {e}");
            return Json(err(500, "数据库错误"));
        }
    }
    match crate::service::groups::delete_rule(state.db.as_ref(), id, &ResourceScope::All).await {
        Ok(true) => {
            broadcast_config_changed(&state).await;
            Json(ApiResponse::success(()))
        }
        Ok(false) => Json(err(404, "SOCKS5 规则不存在")),
        Err(e) => {
            tracing::error!("delete_socks5_rule {id}: {e}");
            Json(err(500, "数据库错误"))
        }
    }
}

pub async fn reset_socks5_rule_credential(
    _admin: AdminOnly,
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(req): Json<ResetSocks5RuleCredentialRequest>,
) -> Json<ApiResponse<()>> {
    let username = req.username.trim();
    if username.is_empty() || req.password.is_empty() {
        return Json(err(400, "用户名和密码不能为空"));
    }
    let cipher = match credential_cipher(&state) {
        Ok(cipher) => cipher,
        Err(response) => return response,
    };
    let (ciphertext, nonce, key_version) =
        match cipher.encrypt(&req.password, RELAY_PASSWORD_PURPOSE) {
            Ok(value) => value,
            Err(e) => {
                tracing::error!("encrypt reset relay credential: {e:?}");
                return Json(err(500, "凭据加密失败"));
            }
        };
    match state
        .db
        .reset_socks5_rule_credential(id, username, &ciphertext, &nonce, key_version)
        .await
    {
        Ok(0) => Json(err(404, "SOCKS5 规则不存在")),
        Ok(_) => {
            broadcast_config_changed(&state).await;
            Json(ApiResponse::success(()))
        }
        Err(e) => {
            tracing::error!("reset_socks5_rule_credential {id}: {e}");
            Json(err(500, "数据库错误"))
        }
    }
}

trait MapResponseData {
    fn map_data<T: serde::Serialize>(self) -> Json<ApiResponse<T>>;
}

impl MapResponseData for Json<ApiResponse<()>> {
    fn map_data<T: serde::Serialize>(self) -> Json<ApiResponse<T>> {
        Json(ApiResponse {
            code: self.0.code,
            message: self.0.message,
            data: None,
        })
    }
}
