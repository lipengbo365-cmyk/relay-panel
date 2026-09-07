//! Directed SOCKS5 checks: Panel registers a one-shot request, sends it to one
//! physical Relay Node over the existing WS channel, and accepts exactly one
//! authenticated, challenge-bound result from that node.

use crate::api::middleware::AdminOnly;
use crate::api::node::{extract_node_token, node_identity_hash};
use crate::api::AppState;
use crate::db::repo::{Socks5HealthRecord, Socks5ResourceQuery};
use crate::service::credentials::CredentialCipher;
use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::Json;
use relay_shared::protocol::{ApiResponse, SecretString, Socks5CheckRequest, Socks5CheckResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{oneshot, Mutex};

const RESOURCE_PASSWORD_PURPOSE: &str = "socks5-resource-password";
const RESULT_TIMEOUT: Duration = Duration::from_secs(35);
const MAX_BATCH_SIZE: usize = 10_000;

struct PendingCheck {
    challenge: String,
    session_id: String,
    resource_generation: i64,
    generation: i64,
    resource_id: i64,
    relay_node_id: i64,
    node_id: String,
    sender: oneshot::Sender<Socks5CheckResult>,
}

#[derive(Clone, Default)]
pub struct Socks5CheckRegistry {
    inner: Arc<Mutex<HashMap<String, PendingCheck>>>,
}

impl Socks5CheckRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    async fn start(
        &self,
        resource_id: i64,
        relay_node_id: i64,
        node_id: &str,
        session_id: &str,
        resource_generation: i64,
        generation: i64,
    ) -> (String, String, oneshot::Receiver<Socks5CheckResult>) {
        let request_id = uuid::Uuid::new_v4().to_string();
        let challenge = uuid::Uuid::new_v4().to_string();
        let (sender, receiver) = oneshot::channel();
        self.inner.lock().await.insert(
            request_id.clone(),
            PendingCheck {
                challenge: challenge.clone(),
                session_id: session_id.to_owned(),
                resource_generation,
                generation,
                resource_id,
                relay_node_id,
                node_id: node_id.to_owned(),
                sender,
            },
        );
        let registry = self.clone();
        let expiring_id = request_id.clone();
        tokio::spawn(async move {
            tokio::time::sleep(RESULT_TIMEOUT).await;
            registry.remove(&expiring_id).await;
        });
        (request_id, challenge, receiver)
    }

    async fn matches(&self, result: &Socks5CheckResult) -> bool {
        let pending = self.inner.lock().await;
        let Some(check) = pending.get(&result.request_id) else {
            return false;
        };
        !(check.challenge != result.challenge
            || check.session_id != result.session_id
            || check.resource_generation != result.resource_generation
            || check.generation != result.generation
            || check.resource_id != result.resource_id
            || check.relay_node_id != result.relay_node_id
            || check.node_id != result.node_id)
    }

    async fn complete_matching(
        &self,
        result: &Socks5CheckResult,
    ) -> Option<oneshot::Sender<Socks5CheckResult>> {
        let mut pending = self.inner.lock().await;
        let check = pending.get(&result.request_id)?;
        if check.challenge != result.challenge
            || check.session_id != result.session_id
            || check.resource_generation != result.resource_generation
            || check.generation != result.generation
            || check.resource_id != result.resource_id
            || check.relay_node_id != result.relay_node_id
            || check.node_id != result.node_id
        {
            return None;
        }
        pending.remove(&result.request_id).map(|entry| entry.sender)
    }

    async fn remove(&self, request_id: &str) {
        self.inner.lock().await.remove(request_id);
    }
}

#[derive(Debug, Deserialize)]
pub struct CheckRequest {
    pub relay_node_id: i64,
}

#[derive(Debug, Deserialize)]
pub struct BatchCheckRequest {
    pub relay_node_id: i64,
    pub resource_ids: Vec<i64>,
}

#[derive(Debug, Deserialize)]
pub struct CheckAllRequest {
    pub relay_node_id: i64,
    pub search: Option<String>,
    pub status: Option<String>,
    pub country: Option<String>,
    pub detected_country: Option<String>,
    pub tag: Option<String>,
    pub enabled: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct CheckResponse {
    pub resource_id: i64,
    pub relay_node_id: i64,
    /// COMPLETED, NODE_OFFLINE, NODE_BUSY, NODE_TIMEOUT, INVALID_RESOURCE,
    /// INVALID_NODE, or DISABLED.
    pub outcome: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Socks5CheckResultPublic>,
}

#[derive(Debug, Serialize)]
pub struct Socks5CheckResultPublic {
    pub status: relay_shared::protocol::Socks5HealthStatus,
    pub tcp_latency_ms: Option<u64>,
    pub handshake_latency_ms: Option<u64>,
    pub connect_latency_ms: Option<u64>,
    pub total_latency_ms: Option<u64>,
    pub exit_ip: Option<String>,
    pub detected_country: Option<String>,
    pub error_stage: Option<relay_shared::protocol::Socks5CheckStage>,
    pub error_code: Option<String>,
    pub safe_error_message: Option<String>,
    pub checked_at: String,
}

impl From<Socks5CheckResult> for Socks5CheckResultPublic {
    fn from(value: Socks5CheckResult) -> Self {
        Self {
            status: value.status,
            tcp_latency_ms: value.tcp_latency_ms,
            handshake_latency_ms: value.handshake_latency_ms,
            connect_latency_ms: value.connect_latency_ms,
            total_latency_ms: value.total_latency_ms,
            exit_ip: value.exit_ip,
            detected_country: value.detected_country,
            error_stage: value.error_stage,
            error_code: value.error_code,
            safe_error_message: value.safe_error_message,
            checked_at: value.checked_at,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct HistoryQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

fn api_error<T: Serialize>(code: i32, message: impl Into<String>) -> ApiResponse<T> {
    ApiResponse {
        code,
        message: message.into(),
        data: None,
    }
}

pub async fn check_resource(
    admin: AdminOnly,
    State(state): State<AppState>,
    Path(resource_id): Path<i64>,
    Json(request): Json<CheckRequest>,
) -> Json<ApiResponse<CheckResponse>> {
    let response = run_one(state.clone(), resource_id, request.relay_node_id).await;
    crate::service::audit::record(
        &state,
        Some(admin.user_id),
        "socks5_resource_check",
        "socks5_resource",
        resource_id,
        &format!(
            "relay_node_id={}; outcome={}",
            request.relay_node_id, response.outcome
        ),
    )
    .await;
    Json(ApiResponse::success(response))
}

pub async fn check_batch(
    admin: AdminOnly,
    State(state): State<AppState>,
    Json(request): Json<BatchCheckRequest>,
) -> Json<ApiResponse<Vec<CheckResponse>>> {
    let mut ids = request.resource_ids;
    ids.sort_unstable();
    ids.dedup();
    if ids.is_empty() || ids.len() > MAX_BATCH_SIZE {
        return Json(api_error(
            400,
            "resource_ids must contain 1..10000 unique IDs",
        ));
    }

    let relay_node_id = request.relay_node_id;
    let results = run_batch(state.clone(), ids, relay_node_id).await;

    record_batch_audit(&state, admin.user_id, relay_node_id, results.len()).await;
    Json(ApiResponse::success(results))
}

pub async fn check_all(
    admin: AdminOnly,
    State(state): State<AppState>,
    Json(request): Json<CheckAllRequest>,
) -> Json<ApiResponse<Vec<CheckResponse>>> {
    let query = Socks5ResourceQuery {
        search: normalize(request.search),
        status: normalize_upper(request.status),
        country: normalize_upper(request.country),
        detected_country: normalize_upper(request.detected_country),
        tag: normalize(request.tag),
        enabled: request.enabled,
        sort: "id".into(),
        descending: false,
        limit: MAX_BATCH_SIZE as i64,
        offset: 0,
    };
    let (resources, total) = match state.db.query_socks5_resources(&query).await {
        Ok(value) => value,
        Err(error) => {
            tracing::error!("query SOCKS5 resources for check-all: {error}");
            return Json(api_error(500, "database error"));
        }
    };
    if total > MAX_BATCH_SIZE as i64 {
        return Json(api_error(400, "filtered result exceeds 10000 resources"));
    }
    let ids = resources.into_iter().map(|resource| resource.id).collect();
    let results = run_batch(state.clone(), ids, request.relay_node_id).await;
    record_batch_audit(&state, admin.user_id, request.relay_node_id, results.len()).await;
    Json(ApiResponse::success(results))
}

async fn run_batch(state: AppState, ids: Vec<i64>, relay_node_id: i64) -> Vec<CheckResponse> {
    let concurrency = state.config.socks5_check_concurrency;
    map_bounded(ids, concurrency, |resource_id| {
        let state = state.clone();
        async move { run_one(state, resource_id, relay_node_id).await }
    })
    .await
}

async fn map_bounded<I, F, Fut, Output>(
    items: Vec<I>,
    concurrency: usize,
    operation: F,
) -> Vec<Output>
where
    F: Fn(I) -> Fut,
    Fut: std::future::Future<Output = Output>,
{
    use futures_util::StreamExt;
    futures_util::stream::iter(items.into_iter().map(operation))
        .buffer_unordered(concurrency)
        .collect::<Vec<_>>()
        .await
}

async fn record_batch_audit(state: &AppState, user_id: i64, relay_node_id: i64, count: usize) {
    crate::service::audit::record(
        state,
        Some(user_id),
        "socks5_resource_batch_check",
        "relay_node",
        relay_node_id,
        &format!("count={count}"),
    )
    .await;
}

fn normalize(value: Option<String>) -> Option<String> {
    value
        .map(|item| item.trim().to_owned())
        .filter(|item| !item.is_empty())
}

fn normalize_upper(value: Option<String>) -> Option<String> {
    normalize(value).map(|item| item.to_ascii_uppercase())
}

async fn run_one(state: AppState, resource_id: i64, relay_node_id: i64) -> CheckResponse {
    let base = |outcome: &str| CheckResponse {
        resource_id,
        relay_node_id,
        outcome: outcome.to_owned(),
        result: None,
    };
    let resource = match state.db.find_socks5_resource(resource_id).await {
        Ok(Some(resource)) => resource,
        _ => return base("INVALID_RESOURCE"),
    };
    if !resource.enabled {
        return base("DISABLED");
    }
    if !secure_control_channel_allowed(&state.config.public_panel_url) {
        return base("INSECURE_CONTROL_CHANNEL");
    }
    let relay = match state.db.find_relay_node(relay_node_id).await {
        Ok(Some(relay)) if relay.enabled => relay,
        _ => return base("INVALID_NODE"),
    };
    if !state
        .node_connections
        .online_node_ids(relay.device_group_id)
        .await
        .contains(&relay.node_key)
    {
        return base("NODE_OFFLINE");
    }
    if !node_supports_socks5_check(&state, relay.device_group_id, &relay.node_key).await {
        return base("NODE_UNSUPPORTED");
    }

    let Some(session_id) = state
        .node_connections
        .node_session(relay.device_group_id, &relay.node_key)
        .await
    else {
        return base("NODE_OFFLINE");
    };
    let (resource, generation) = match state
        .db
        .begin_socks5_health_check(resource_id, relay_node_id)
        .await
    {
        Ok(Some(value)) => value,
        Ok(None) => return base("INVALID_RESOURCE"),
        Err(error) => {
            tracing::error!("begin SOCKS5 health generation: {error}");
            return base("DISPATCH_FAILED");
        }
    };
    let resource_generation = resource.health_generation;

    let password = match decrypt_password(&state, &resource) {
        Ok(value) => value.map(SecretString::new),
        Err(()) => return base("CREDENTIAL_UNAVAILABLE"),
    };
    let (request_id, challenge, receiver) = state
        .socks5_checks
        .start(
            resource_id,
            relay_node_id,
            &relay.node_key,
            &session_id,
            resource_generation,
            generation,
        )
        .await;
    let command = Socks5CheckRequest {
        msg_type: "socks5_check".into(),
        request_id: request_id.clone(),
        challenge,
        session_id: session_id.clone(),
        resource_generation,
        generation,
        resource_id,
        relay_node_id,
        node_id: relay.node_key.clone(),
        host: resource.host,
        port: resource.port as u16,
        username: resource.username,
        password,
        check_urls: state.config.socks5_check_urls.clone(),
        relay_public_ip: (!relay.public_ip.is_empty()).then_some(relay.public_ip),
    };
    let payload = match serde_json::to_string(&command) {
        Ok(value) => value,
        Err(_) => {
            state.socks5_checks.remove(&request_id).await;
            return base("DISPATCH_FAILED");
        }
    };
    if state
        .node_connections
        .send_node_session(
            relay.device_group_id,
            &relay.node_key,
            &session_id,
            &payload,
        )
        .await
        == 0
    {
        state.socks5_checks.remove(&request_id).await;
        return base("NODE_OFFLINE");
    }

    match tokio::time::timeout(RESULT_TIMEOUT, receiver).await {
        Ok(Ok(result)) => CheckResponse {
            resource_id,
            relay_node_id,
            outcome: match result.error_code.as_deref() {
                Some("NODE_BUSY") => "NODE_BUSY".into(),
                Some("NODE_DISABLED") => "NODE_DISABLED".into(),
                Some("RESULT_SUPERSEDED") => "SUPERSEDED".into(),
                Some("PERSIST_FAILED") => "PERSIST_FAILED".into(),
                _ => "COMPLETED".into(),
            },
            result: Some(result.into()),
        },
        _ => {
            state.socks5_checks.remove(&request_id).await;
            base("NODE_TIMEOUT")
        }
    }
}

async fn node_supports_socks5_check(state: &AppState, group_id: i64, node_key: &str) -> bool {
    let key = format!("node_status:{group_id}:{node_key}");
    state
        .db
        .get(&key)
        .await
        .ok()
        .flatten()
        .and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw).ok())
        .is_some_and(|status| status.get("socks5_check_queue_depth").is_some())
}

fn secure_control_channel_allowed(public_panel_url: &str) -> bool {
    public_panel_url.trim_start().starts_with("https://")
        || std::env::var("ALLOW_INSECURE_SOCKS5_CONFIG")
            .ok()
            .is_some_and(|value| matches!(value.as_str(), "1" | "true" | "TRUE"))
}

fn decrypt_password(
    state: &AppState,
    resource: &crate::db::repo::Socks5ResourceRecord,
) -> Result<Option<String>, ()> {
    match (
        resource.password_ciphertext.as_deref(),
        resource.password_nonce.as_deref(),
    ) {
        (None, None) => Ok(None),
        (Some(ciphertext), Some(nonce)) => {
            CredentialCipher::from_config(state.config.socks5_credential_key.as_deref())
                .and_then(|cipher| {
                    cipher.decrypt(
                        ciphertext,
                        nonce,
                        resource.password_key_version,
                        RESOURCE_PASSWORD_PURPOSE,
                    )
                })
                .map(Some)
                .map_err(|error| {
                    tracing::error!("SOCKS5 check credential decrypt failed: {error:?}");
                })
        }
        _ => Err(()),
    }
}

pub async fn receive_result(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(mut result): Json<Socks5CheckResult>,
) -> Json<ApiResponse<()>> {
    let Some(token) = extract_node_token(&headers) else {
        return Json(api_error(401, "Invalid token"));
    };
    let group = match state.db.find_by_token(&token).await {
        Ok(Some(group)) => group,
        Ok(None) => return Json(api_error(401, "Invalid token")),
        Err(error) => {
            tracing::error!("socks5 check result token lookup: {error}");
            return Json(api_error(500, "database error"));
        }
    };
    let relay = match state.db.find_relay_node(result.relay_node_id).await {
        Ok(Some(relay)) => relay,
        Ok(None) => return Json(api_error(404, "Relay node not found")),
        Err(error) => {
            tracing::error!("socks5 check result relay lookup: {error}");
            return Json(api_error(500, "database error"));
        }
    };
    if relay.device_group_id != group.id || relay.node_key != result.node_id {
        return Json(api_error(403, "Result does not belong to this Relay Node"));
    }
    let header_node_id = headers
        .get("X-Node-ID")
        .and_then(|value| value.to_str().ok())
        .map(str::trim);
    if header_node_id != Some(result.node_id.as_str())
        || node_identity_hash(&headers).as_deref() != Some(relay.identity_secret_hash.as_str())
    {
        return Json(api_error(403, "Physical node identity does not match"));
    }
    if !state
        .node_connections
        .is_current_node_session(group.id, &result.node_id, &result.session_id)
        .await
    {
        return Json(api_error(409, "WebSocket session is no longer current"));
    }

    if validate_result(&result).is_err() || !state.socks5_checks.matches(&result).await {
        return Json(api_error(409, "Check task unknown, expired, or mismatched"));
    }
    let Some(sender) = state.socks5_checks.complete_matching(&result).await else {
        return Json(api_error(409, "Check task already completed or mismatched"));
    };
    result.checked_at = chrono::Utc::now()
        .format("%Y-%m-%d %H:%M:%S%.6f")
        .to_string();

    if !relay.enabled {
        result.status = relay_shared::protocol::Socks5HealthStatus::Unknown;
        result.error_stage = None;
        result.error_code = Some("NODE_DISABLED".into());
        result.safe_error_message = Some("Relay Node was disabled while check was running".into());
        let _ = sender.send(result);
        return Json(ApiResponse::success(()));
    }

    // NODE_BUSY means no SOCKS5 check occurred, so it must not mutate health.
    if result.error_code.as_deref() != Some("NODE_BUSY") {
        if let Some(exit_ip) = result.exit_ip.as_deref() {
            if exit_ip == relay.public_ip {
                result.status = relay_shared::protocol::Socks5HealthStatus::ConnectFailed;
                result.error_stage = Some(relay_shared::protocol::Socks5CheckStage::ExitIpParse);
                result.error_code = Some("EXIT_IP_MISMATCH".into());
                result.safe_error_message =
                    Some("SOCKS5 exit IP equals Relay Node public IP".into());
            } else if state.config.geoip_enabled {
                result.detected_country = crate::api::geoip::lookup(
                    state.db.as_ref(),
                    state.config.geoip_cache_ttl as i64,
                    &state.geoip_in_flight,
                    exit_ip,
                )
                .await
                .and_then(|entry| entry.country_code.or(entry.country_name));
            }
        }
        let health = health_from_result(&result);
        match state
            .db
            .record_socks5_health(&health, result.resource_generation, result.generation)
            .await
        {
            Ok(true) => {}
            Ok(false) => {
                result.status = relay_shared::protocol::Socks5HealthStatus::Unknown;
                result.error_stage = None;
                result.error_code = Some("RESULT_SUPERSEDED".into());
                result.safe_error_message = Some("Check result was superseded".into());
                let _ = sender.send(result);
                return Json(ApiResponse::success(()));
            }
            Err(error) => {
                tracing::error!("record SOCKS5 health: {error}");
                result.status = relay_shared::protocol::Socks5HealthStatus::Unknown;
                result.error_stage = None;
                result.error_code = Some("PERSIST_FAILED".into());
                result.safe_error_message = Some("Health result could not be persisted".into());
                let _ = sender.send(result);
                return Json(api_error(500, "database error"));
            }
        }
        let cutoff = (chrono::Utc::now()
            - chrono::Duration::days(state.config.socks5_check_retention_days))
        .format("%Y-%m-%d %H:%M:%S")
        .to_string();
        if let Err(error) = state.db.prune_socks5_check_history(&cutoff).await {
            tracing::warn!("prune SOCKS5 check history: {error}");
        }
    }
    let _ = sender.send(result);
    Json(ApiResponse::success(()))
}

fn validate_result(result: &Socks5CheckResult) -> Result<(), ()> {
    if result.msg_type != "socks5_check_result"
        || result.request_id.len() > 64
        || result.challenge.len() > 64
        || result.session_id.len() > 32
        || result.error_code.as_ref().is_some_and(|v| v.len() > 64)
        || result
            .safe_error_message
            .as_ref()
            .is_some_and(|v| v.len() > 512)
        || result
            .detected_country
            .as_ref()
            .is_some_and(|v| v.len() > 128)
        || [
            result.tcp_latency_ms,
            result.handshake_latency_ms,
            result.connect_latency_ms,
            result.total_latency_ms,
        ]
        .into_iter()
        .flatten()
        .any(|value| value > RESULT_TIMEOUT.as_millis() as u64)
    {
        return Err(());
    }
    let parsed_ip = result
        .exit_ip
        .as_deref()
        .map(str::parse::<std::net::IpAddr>)
        .transpose()
        .map_err(|_| ())?;
    if result.status == relay_shared::protocol::Socks5HealthStatus::Online {
        if parsed_ip.is_none() || result.error_code.is_some() || result.error_stage.is_some() {
            return Err(());
        }
    } else if result.error_code.as_deref() != Some("NODE_BUSY")
        && (result.error_code.is_none() || result.safe_error_message.is_none())
    {
        return Err(());
    }
    if result.error_code.as_deref() == Some("NODE_BUSY")
        && (result.status != relay_shared::protocol::Socks5HealthStatus::Unknown
            || result.exit_ip.is_some())
    {
        return Err(());
    }
    Ok(())
}

fn health_from_result(result: &Socks5CheckResult) -> Socks5HealthRecord {
    let millis = |value: Option<u64>| value.map(|v| v.min(i32::MAX as u64) as i32);
    Socks5HealthRecord {
        resource_id: result.resource_id,
        relay_node_id: result.relay_node_id,
        status: result.status.as_str().into(),
        tcp_latency_ms: millis(result.tcp_latency_ms),
        handshake_latency_ms: millis(result.handshake_latency_ms),
        connect_latency_ms: millis(result.connect_latency_ms),
        total_latency_ms: millis(result.total_latency_ms),
        exit_ip: result.exit_ip.clone(),
        country: result.detected_country.clone(),
        error_stage: result.error_stage.map(|stage| stage.as_str().to_owned()),
        error_code: result.error_code.clone(),
        safe_error_message: result.safe_error_message.clone(),
        consecutive_failures: 0,
        checked_at: result.checked_at.clone(),
        last_success_at: None,
    }
}

pub async fn list_health(
    _admin: AdminOnly,
    State(state): State<AppState>,
    Path(resource_id): Path<i64>,
) -> Json<ApiResponse<Vec<Socks5HealthRecord>>> {
    match state.db.list_socks5_health(resource_id).await {
        Ok(rows) => Json(ApiResponse::success(rows)),
        Err(error) => {
            tracing::error!("list SOCKS5 health: {error}");
            Json(api_error(500, "database error"))
        }
    }
}

pub async fn list_history(
    _admin: AdminOnly,
    State(state): State<AppState>,
    Path(resource_id): Path<i64>,
    Query(query): Query<HistoryQuery>,
) -> Json<ApiResponse<Vec<crate::db::repo::Socks5CheckHistoryRecord>>> {
    let limit = query.limit.unwrap_or(50).clamp(1, 500);
    let offset = query.offset.unwrap_or(0).max(0);
    match state
        .db
        .list_socks5_check_history(resource_id, limit, offset)
        .await
    {
        Ok(rows) => Json(ApiResponse::success(rows)),
        Err(error) => {
            tracing::error!("list SOCKS5 check history: {error}");
            Json(api_error(500, "database error"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use relay_shared::protocol::Socks5HealthStatus;

    fn result(request_id: &str, challenge: &str) -> Socks5CheckResult {
        Socks5CheckResult {
            msg_type: "socks5_check_result".into(),
            request_id: request_id.into(),
            challenge: challenge.into(),
            session_id: "session-1".into(),
            resource_generation: 1,
            generation: 1,
            resource_id: 7,
            relay_node_id: 9,
            node_id: "node-a".into(),
            status: Socks5HealthStatus::Online,
            tcp_latency_ms: Some(1),
            handshake_latency_ms: Some(2),
            connect_latency_ms: Some(3),
            total_latency_ms: Some(6),
            exit_ip: Some("203.0.113.5".into()),
            detected_country: None,
            error_stage: None,
            error_code: None,
            safe_error_message: None,
            checked_at: String::new(),
        }
    }

    #[tokio::test]
    async fn registry_rejects_wrong_challenge_without_consuming_task() {
        let registry = Socks5CheckRegistry::new();
        let (id, challenge, _receiver) = registry.start(7, 9, "node-a", "session-1", 1, 1).await;
        assert!(registry
            .complete_matching(&result(&id, "wrong"))
            .await
            .is_none());
        assert!(registry
            .complete_matching(&result(&id, &challenge))
            .await
            .is_some());
        assert!(
            registry
                .complete_matching(&result(&id, &challenge))
                .await
                .is_none(),
            "a challenge is one-shot even under retries"
        );
    }

    #[tokio::test]
    async fn registry_binds_session_generation_resource_and_node() {
        let registry = Socks5CheckRegistry::new();
        let (id, challenge, _receiver) = registry.start(7, 9, "node-a", "session-1", 2, 4).await;
        let mut candidate = result(&id, &challenge);
        for mutate in 0..5 {
            candidate.session_id = "session-1".into();
            candidate.resource_generation = 2;
            candidate.generation = 4;
            candidate.resource_id = 7;
            candidate.node_id = "node-a".into();
            match mutate {
                0 => candidate.session_id = "old-session".into(),
                1 => candidate.resource_generation = 1,
                2 => candidate.generation = 3,
                3 => candidate.resource_id = 8,
                _ => candidate.node_id = "node-b".into(),
            }
            assert!(registry.complete_matching(&candidate).await.is_none());
        }
        candidate.session_id = "session-1".into();
        candidate.resource_generation = 2;
        candidate.generation = 4;
        candidate.resource_id = 7;
        candidate.node_id = "node-a".into();
        assert!(registry.complete_matching(&candidate).await.is_some());
    }

    #[tokio::test]
    async fn challenge_is_consumed_exactly_once_under_one_hundred_replays() {
        let registry = Socks5CheckRegistry::new();
        let (id, challenge, _receiver) = registry.start(7, 9, "node-a", "session-1", 1, 1).await;
        let candidate = Arc::new(result(&id, &challenge));
        let accepted = futures_util::future::join_all((0..100).map(|_| {
            let registry = registry.clone();
            let candidate = candidate.clone();
            async move { registry.complete_matching(&candidate).await.is_some() }
        }))
        .await
        .into_iter()
        .filter(|accepted| *accepted)
        .count();
        assert_eq!(accepted, 1);
    }

    #[tokio::test]
    async fn batch_mapper_never_exceeds_configured_concurrency() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let output = map_bounded((0..1_000).collect(), 50, |item| {
            let active = active.clone();
            let peak = peak.clone();
            async move {
                let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(current, Ordering::SeqCst);
                tokio::task::yield_now().await;
                active.fetch_sub(1, Ordering::SeqCst);
                item
            }
        })
        .await;
        assert_eq!(output.len(), 1_000);
        assert!(peak.load(Ordering::SeqCst) <= 50);
    }

    #[test]
    fn result_validation_rejects_invalid_ip_and_inconsistent_status() {
        let mut value = result("request", "challenge");
        assert!(validate_result(&value).is_ok());
        value.exit_ip = Some("1.2.3.4 garbage".into());
        assert!(validate_result(&value).is_err());
        value.exit_ip = Some("1.2.3.4".into());
        value.error_code = Some("FORGED".into());
        assert!(validate_result(&value).is_err());
        value.error_code = None;
        value.total_latency_ms = Some(RESULT_TIMEOUT.as_millis() as u64 + 1);
        assert!(validate_result(&value).is_err());
    }
}
