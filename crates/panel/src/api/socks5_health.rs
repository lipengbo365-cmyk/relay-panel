//! Directed SOCKS5 checks: Panel registers a one-shot request, sends it to one
//! physical Relay Node over the existing WS channel, and accepts exactly one
//! authenticated, challenge-bound result from that node.

use crate::api::middleware::AdminOnly;
use crate::api::node::{extract_node_token, node_identity_hash};
use crate::api::AppState;
use crate::db::health_orchestration::HealthJobItemState;
use crate::db::repo::{Socks5HealthRecord, Socks5ResourceQuery};
use crate::service::credentials::CredentialCipher;
use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::Json;
use relay_shared::protocol::{ApiResponse, Socks5CheckResult};
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
    durable: Option<DurablePendingContext>,
}

#[derive(Debug, Clone)]
pub(crate) struct DurablePendingContext {
    pub job_id: String,
    pub item_id: i64,
    pub dispatch_attempt_id: String,
    pub item_fence_token: i64,
    pub pair_fence_token: i64,
    pub lease_owner: String,
}

pub(crate) struct PendingCompletion {
    pub sender: oneshot::Sender<Socks5CheckResult>,
    pub durable: Option<DurablePendingContext>,
}

#[derive(Clone, Default)]
pub struct Socks5CheckRegistry {
    inner: Arc<Mutex<HashMap<String, PendingCheck>>>,
}

impl Socks5CheckRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    #[cfg(test)]
    async fn start(
        &self,
        resource_id: i64,
        relay_node_id: i64,
        node_id: &str,
        session_id: &str,
        resource_generation: i64,
        generation: i64,
    ) -> (String, String, oneshot::Receiver<Socks5CheckResult>) {
        self.start_compatibility(
            resource_id,
            relay_node_id,
            node_id,
            session_id,
            resource_generation,
            generation,
        )
        .await
    }

    async fn start_compatibility(
        &self,
        resource_id: i64,
        relay_node_id: i64,
        node_id: &str,
        session_id: &str,
        resource_generation: i64,
        generation: i64,
    ) -> (String, String, oneshot::Receiver<Socks5CheckResult>) {
        self.start_with_context(
            resource_id,
            relay_node_id,
            node_id,
            session_id,
            resource_generation,
            generation,
            None,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn start_durable(
        &self,
        resource_id: i64,
        relay_node_id: i64,
        node_id: &str,
        session_id: &str,
        resource_generation: i64,
        generation: i64,
        durable: DurablePendingContext,
    ) -> (String, String, oneshot::Receiver<Socks5CheckResult>) {
        self.start_with_context(
            resource_id,
            relay_node_id,
            node_id,
            session_id,
            resource_generation,
            generation,
            Some(durable),
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn start_with_context(
        &self,
        resource_id: i64,
        relay_node_id: i64,
        node_id: &str,
        session_id: &str,
        resource_generation: i64,
        generation: i64,
        durable: Option<DurablePendingContext>,
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
                durable,
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

    async fn complete_matching(&self, result: &Socks5CheckResult) -> Option<PendingCompletion> {
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
        pending
            .remove(&result.request_id)
            .map(|entry| PendingCompletion {
                sender: entry.sender,
                durable: entry.durable,
            })
    }

    pub(crate) async fn remove(&self, request_id: &str) {
        self.inner.lock().await.remove(request_id);
    }
}

async fn durable_context_is_current(
    db: &dyn crate::db::repo::Repository,
    result: &Socks5CheckResult,
    context: &DurablePendingContext,
    now_ms: i64,
) -> bool {
    let item = match db.find_health_job_item(context.item_id).await {
        Ok(Some(item)) => item,
        Ok(None) => return false,
        Err(error) => {
            tracing::error!("validate durable health item fence: {error}");
            return false;
        }
    };
    let item_matches = item.job_id == context.job_id
        && item.state == HealthJobItemState::InFlight.as_str()
        && item.dispatch_attempt_id.as_deref() == Some(&context.dispatch_attempt_id)
        && item.request_id.as_deref() == Some(result.request_id.as_str())
        && item.item_fence_token == context.item_fence_token
        && item.pair_fence_token == Some(context.pair_fence_token)
        && item.lease_owner.as_deref() == Some(&context.lease_owner)
        && item
            .lease_expires_at_ms
            .is_some_and(|expires_at| expires_at > now_ms);
    if !item_matches {
        return false;
    }
    match db
        .find_health_pair_lease(result.resource_id, result.relay_node_id)
        .await
    {
        Ok(Some(pair)) => {
            pair.item_id == Some(context.item_id)
                && pair.lease_owner.as_deref() == Some(&context.lease_owner)
                && pair.pair_fence_token == context.pair_fence_token
                && pair
                    .lease_expires_at_ms
                    .is_some_and(|expires_at| expires_at > now_ms)
        }
        Ok(None) => false,
        Err(error) => {
            tracing::error!("validate durable health pair fence: {error}");
            false
        }
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
    let response = run_batch(
        state.clone(),
        vec![resource_id],
        request.relay_node_id,
        admin.user_id,
    )
    .await
    .pop()
    .unwrap_or(CheckResponse {
        resource_id,
        relay_node_id: request.relay_node_id,
        outcome: "DISPATCH_FAILED".into(),
        result: None,
    });
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
    let results = run_batch(state.clone(), ids, relay_node_id, admin.user_id).await;

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
    let results = run_batch(state.clone(), ids, request.relay_node_id, admin.user_id).await;
    record_batch_audit(&state, admin.user_id, request.relay_node_id, results.len()).await;
    Json(ApiResponse::success(results))
}

async fn run_batch(
    state: AppState,
    ids: Vec<i64>,
    relay_node_id: i64,
    _actor_id: i64,
) -> Vec<CheckResponse> {
    let base = |resource_id: i64, outcome: &str| CheckResponse {
        resource_id,
        relay_node_id,
        outcome: outcome.to_owned(),
        result: None,
    };
    if !secure_control_channel_allowed(&state.config.public_panel_url) {
        return ids
            .into_iter()
            .map(|id| base(id, "INSECURE_CONTROL_CHANNEL"))
            .collect();
    }
    let relay = match state.db.find_relay_node(relay_node_id).await {
        Ok(Some(relay)) if relay.enabled => relay,
        _ => return ids.into_iter().map(|id| base(id, "INVALID_NODE")).collect(),
    };
    if !state
        .node_connections
        .online_node_ids(relay.device_group_id)
        .await
        .contains(&relay.node_key)
    {
        return ids.into_iter().map(|id| base(id, "NODE_OFFLINE")).collect();
    }
    if !node_supports_socks5_check(&state, relay.device_group_id, &relay.node_key).await {
        return ids
            .into_iter()
            .map(|id| base(id, "NODE_UNSUPPORTED"))
            .collect();
    }

    let resources = match state.db.list_socks5_resources().await {
        Ok(resources) => resources
            .into_iter()
            .map(|resource| (resource.id, resource))
            .collect::<HashMap<_, _>>(),
        Err(error) => {
            tracing::error!("compatibility health resource lookup: {error}");
            return ids
                .into_iter()
                .map(|id| base(id, "DISPATCH_FAILED"))
                .collect();
        }
    };
    let mut responses = ids
        .iter()
        .map(|id| {
            let outcome = match resources.get(id) {
                None => "INVALID_RESOURCE",
                Some(resource) if !resource.enabled => "DISABLED",
                Some(_) => "QUEUED",
            };
            (*id, base(*id, outcome))
        })
        .collect::<HashMap<_, _>>();
    let valid_ids = ids
        .iter()
        .copied()
        .filter(|id| resources.get(id).is_some_and(|resource| resource.enabled))
        .collect::<Vec<_>>();
    if valid_ids.is_empty() {
        return ids
            .into_iter()
            .map(|id| responses.remove(&id).expect("response exists"))
            .collect();
    }
    let completed = map_bounded(valid_ids, 50, |resource_id| {
        let state = state.clone();
        let relay = relay.clone();
        let resource = resources.get(&resource_id).cloned();
        async move {
            match resource {
                Some(resource) => compatibility_check(state, resource, relay).await,
                None => CheckResponse {
                    resource_id,
                    relay_node_id,
                    outcome: "INVALID_RESOURCE".into(),
                    result: None,
                },
            }
        }
    })
    .await;
    for response in completed {
        responses.insert(response.resource_id, response);
    }
    ids.into_iter()
        .map(|id| responses.remove(&id).expect("response exists"))
        .collect()
}

async fn compatibility_check(
    state: AppState,
    resource: crate::db::repo::Socks5ResourceRecord,
    relay: crate::db::repo::RelayNodeRecord,
) -> CheckResponse {
    use crate::db::health_orchestration::{
        ConditionalWriteOutcome, HealthPairCoordinationRequest, PairLeaseAcquireOutcome,
    };
    use relay_shared::protocol::{SecretString, Socks5CheckRequest};
    let resource_id = resource.id;
    let relay_node_id = relay.id;
    let base = |outcome: &str| CheckResponse {
        resource_id,
        relay_node_id,
        outcome: outcome.into(),
        result: None,
    };
    let owner = format!("compat:{}", uuid::Uuid::new_v4());
    let now = chrono::Utc::now().timestamp_millis();
    let pair_fence = match state
        .db
        .acquire_health_pair_coordination(HealthPairCoordinationRequest {
            resource_id,
            relay_node_id,
            lease_owner: &owner,
            lease_expires_at_ms: now + 60_000,
            now_ms: now,
        })
        .await
    {
        Ok(PairLeaseAcquireOutcome::Acquired { pair_fence_token }) => pair_fence_token,
        Ok(PairLeaseAcquireOutcome::Busy) => return base("NODE_BUSY"),
        Err(error) => {
            tracing::error!("acquire compatibility health pair: {error}");
            return base("DISPATCH_FAILED");
        }
    };
    let response = async {
        let Some(session_id) = state
            .node_connections
            .node_session(relay.device_group_id, &relay.node_key)
            .await
        else {
            return base("NODE_OFFLINE");
        };
        let password = match decrypt_password(&state, &resource) {
            Ok(value) => value.map(SecretString::new),
            Err(()) => return base("CREDENTIAL_UNAVAILABLE"),
        };
        let Some((resource, generation)) = state
            .db
            .begin_socks5_health_check_if_resource_generation(
                resource_id,
                relay_node_id,
                resource.health_generation,
            )
            .await
            .ok()
            .flatten()
        else {
            return base("DISPATCH_FAILED");
        };
        let resource_generation = resource.health_generation;
        let (request_id, challenge, mut receiver) = state
            .socks5_checks
            .start_compatibility(
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
            relay_public_ip: (!relay.public_ip.is_empty()).then_some(relay.public_ip.clone()),
        };
        let Ok(payload) = serde_json::to_string(&command) else {
            state.socks5_checks.remove(&request_id).await;
            return base("DISPATCH_FAILED");
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
        let deadline = tokio::time::Instant::now() + RESULT_TIMEOUT;
        let exact = loop {
            tokio::select! {
                value = &mut receiver => break value.ok(),
                _ = tokio::time::sleep_until(deadline) => break None,
                _ = tokio::time::sleep(Duration::from_secs(15)) => {
                    let renew_now = chrono::Utc::now().timestamp_millis();
                    if !matches!(state.db.renew_health_pair_coordination(
                        HealthPairCoordinationRequest {
                            resource_id,
                            relay_node_id,
                            lease_owner: &owner,
                            lease_expires_at_ms: renew_now + 60_000,
                            now_ms: renew_now,
                        },
                        pair_fence,
                    ).await, Ok(ConditionalWriteOutcome::Applied)) {
                        state.socks5_checks.remove(&request_id).await;
                        break None;
                    }
                }
            }
        };
        let Some(result) = exact else {
            state.socks5_checks.remove(&request_id).await;
            return base("NODE_TIMEOUT");
        };
        if result.error_code.as_deref() == Some("NODE_BUSY") {
            return base("NODE_BUSY");
        }
        if result.error_code.as_deref() == Some("PERSIST_FAILED") {
            return base("PERSIST_FAILED");
        }
        if matches!(
            result.error_code.as_deref(),
            Some("RESULT_SUPERSEDED" | "NODE_DISABLED")
        ) {
            return base("DISPATCH_FAILED");
        }
        CheckResponse {
            resource_id,
            relay_node_id,
            outcome: "COMPLETED".into(),
            result: Some(result.into()),
        }
    }
    .await;
    let _ = state
        .db
        .release_health_pair_coordination(
            resource_id,
            relay_node_id,
            &owner,
            pair_fence,
            chrono::Utc::now().timestamp_millis(),
        )
        .await;
    response
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

pub(crate) async fn node_supports_socks5_check(
    state: &AppState,
    group_id: i64,
    node_key: &str,
) -> bool {
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

pub(crate) fn secure_control_channel_allowed(public_panel_url: &str) -> bool {
    public_panel_url.trim_start().starts_with("https://")
        || std::env::var("ALLOW_INSECURE_SOCKS5_CONFIG")
            .ok()
            .is_some_and(|value| matches!(value.as_str(), "1" | "true" | "TRUE"))
}

pub(crate) fn decrypt_password(
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
    let Some(completion) = state.socks5_checks.complete_matching(&result).await else {
        return Json(api_error(409, "Check task already completed or mismatched"));
    };
    if let Some(context) = &completion.durable {
        if !durable_context_is_current(
            state.db.as_ref(),
            &result,
            context,
            chrono::Utc::now().timestamp_millis(),
        )
        .await
        {
            result.status = relay_shared::protocol::Socks5HealthStatus::Unknown;
            result.error_stage = None;
            result.error_code = Some("RESULT_SUPERSEDED".into());
            result.safe_error_message = Some("Check result was superseded".into());
            let _ = completion.sender.send(result);
            return Json(api_error(409, "Check task ownership was superseded"));
        }
    }
    result.checked_at = chrono::Utc::now()
        .format("%Y-%m-%d %H:%M:%S%.6f")
        .to_string();

    if !relay.enabled {
        result.status = relay_shared::protocol::Socks5HealthStatus::Unknown;
        result.error_stage = None;
        result.error_code = Some("NODE_DISABLED".into());
        result.safe_error_message = Some("Relay Node was disabled while check was running".into());
        let _ = completion.sender.send(result);
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
                let _ = completion.sender.send(result);
                return Json(ApiResponse::success(()));
            }
            Err(error) => {
                tracing::error!("record SOCKS5 health: {error}");
                result.status = relay_shared::protocol::Socks5HealthStatus::Unknown;
                result.error_stage = None;
                result.error_code = Some("PERSIST_FAILED".into());
                result.safe_error_message = Some("Health result could not be persisted".into());
                let _ = completion.sender.send(result);
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
    let _ = completion.sender.send(result);
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
    use crate::db::health_orchestration::{
        snapshot_hash, ConditionalWriteOutcome, HealthItemClaimRequest, HealthItemDispatchRequest,
        HealthItemTransition, HealthJobItemState, HealthJobSource, NewHealthJob, NewHealthJobItem,
    };
    use crate::db::repo::HealthOrchestrationRepository;
    use crate::db::schema::{run_migrations, SCHEMA_SQL};
    use crate::db::sqlite_repo::SqliteRepository;
    use crate::{api::system::ReleaseCache, api::ws::NodeConnections, config::Config};
    use relay_shared::protocol::{Socks5CheckRequest, Socks5HealthStatus};
    use sqlx::sqlite::SqlitePoolOptions;
    use std::collections::HashSet;

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
    async fn durable_result_requires_current_item_and_pair_fences_before_health_persistence() {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query(SCHEMA_SQL).execute(&pool).await.unwrap();
        run_migrations(&pool).await.unwrap();
        sqlx::query("PRAGMA foreign_keys=ON")
            .execute(&pool)
            .await
            .unwrap();
        let group = sqlx::query(
            "INSERT INTO device_groups(name,group_type,token,uid) VALUES('result-fence','in','result-fence-token',1)",
        )
        .execute(&pool)
        .await
        .unwrap()
        .last_insert_rowid();
        let resource = sqlx::query(
            "INSERT INTO socks5_resources(name,host,port) VALUES('result-fence-r','127.0.0.1',1080)",
        )
        .execute(&pool)
        .await
        .unwrap()
        .last_insert_rowid();
        let node = sqlx::query("INSERT INTO relay_nodes(device_group_id,node_key,first_seen_at,last_seen_at) VALUES(?,'result-fence-n','2026-01-01','2026-01-01')")
            .bind(group)
            .execute(&pool)
            .await
            .unwrap()
            .last_insert_rowid();
        let db = SqliteRepository::new(pool);
        let job = NewHealthJob {
            id: "result-fence-job".into(),
            source: HealthJobSource::Manual,
            policy_id: None,
            parent_job_id: None,
            actor_id: None,
            request_fingerprint: "a".repeat(64),
            snapshot_hash: snapshot_hash(&[(resource, node)]),
            resource_selector_json: "{}".into(),
            node_selector_json: "{}".into(),
            scheduled_for_ms: None,
            created_at_ms: 1_000,
        };
        db.create_health_job(
            &job,
            &[NewHealthJobItem {
                resource_id: resource,
                relay_node_id: node,
                not_before_ms: 1_000,
                deadline_at_ms: Some(100_000),
            }],
        )
        .await
        .unwrap();
        let leased = db
            .claim_health_job_items(&HealthItemClaimRequest {
                lease_owner: "worker-a".into(),
                now_ms: 2_000,
                lease_expires_at_ms: 62_000,
                limit: 1,
                global_limit: 16,
                per_node_limit: 10,
                per_job_limit: 20,
            })
            .await
            .unwrap()
            .remove(0);
        let dispatching = db
            .begin_health_item_dispatch(&HealthItemDispatchRequest {
                item_id: leased.id,
                lease_owner: "worker-a".into(),
                expected_item_fence: leased.item_fence_token,
                expected_pair_fence: leased.pair_fence_token.unwrap(),
                dispatch_attempt_id: "attempt-a".into(),
                now_ms: 2_100,
            })
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            db.transition_health_job_item(&HealthItemTransition {
                item_id: dispatching.id,
                expected_state: HealthJobItemState::Dispatching,
                expected_fence: dispatching.item_fence_token,
                new_state: HealthJobItemState::InFlight,
                lease_owner: Some("worker-a".into()),
                lease_expires_at_ms: dispatching.lease_expires_at_ms,
                pair_fence_token: dispatching.pair_fence_token,
                dispatch_attempt_id: Some("attempt-a".into()),
                request_id: Some("request-a".into()),
                not_before_ms: None,
                health_status: None,
                safe_error_code: None,
                safe_error_message: None,
                completed_after_cancel: false,
                now_ms: 2_200,
            })
            .await
            .unwrap(),
            ConditionalWriteOutcome::Applied
        );
        let in_flight = db
            .find_health_job_item(dispatching.id)
            .await
            .unwrap()
            .unwrap();
        let context = DurablePendingContext {
            job_id: job.id,
            item_id: in_flight.id,
            dispatch_attempt_id: "attempt-a".into(),
            item_fence_token: in_flight.item_fence_token,
            pair_fence_token: in_flight.pair_fence_token.unwrap(),
            lease_owner: "worker-a".into(),
        };
        let mut candidate = result("request-a", "challenge-a");
        candidate.resource_id = resource;
        candidate.relay_node_id = node;
        assert!(durable_context_is_current(&db, &candidate, &context, 3_000).await);

        assert_eq!(
            db.release_health_pair_lease(
                resource,
                node,
                in_flight.id,
                "worker-a",
                context.pair_fence_token,
                3_100,
            )
            .await
            .unwrap(),
            ConditionalWriteOutcome::Applied
        );
        assert!(!durable_context_is_current(&db, &candidate, &context, 3_200).await);
    }

    #[tokio::test]
    async fn compatibility_single_batch_and_manual_jobs_share_one_pair_coordinator() {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query(SCHEMA_SQL).execute(&pool).await.unwrap();
        run_migrations(&pool).await.unwrap();
        sqlx::query("PRAGMA foreign_keys=ON")
            .execute(&pool)
            .await
            .unwrap();
        let group = sqlx::query(
            "INSERT INTO device_groups(name,group_type,token,uid) VALUES('compat-pair','in','compat-pair-token',1)",
        )
        .execute(&pool)
        .await
        .unwrap()
        .last_insert_rowid();
        let resource_a = sqlx::query(
            "INSERT INTO socks5_resources(name,host,port) VALUES('compat-a','127.0.0.1',1080)",
        )
        .execute(&pool)
        .await
        .unwrap()
        .last_insert_rowid();
        let resource_b = sqlx::query(
            "INSERT INTO socks5_resources(name,host,port) VALUES('compat-b','127.0.0.2',1081)",
        )
        .execute(&pool)
        .await
        .unwrap()
        .last_insert_rowid();
        let node = sqlx::query("INSERT INTO relay_nodes(device_group_id,node_key,first_seen_at,last_seen_at) VALUES(?,'compat-pair-node','2026-01-01','2026-01-01')")
            .bind(group)
            .execute(&pool)
            .await
            .unwrap()
            .last_insert_rowid();
        let state = AppState {
            db: Arc::new(SqliteRepository::new(pool.clone())),
            config: Config {
                database_path: "sqlite::memory:".into(),
                listen: "127.0.0.1:0".into(),
                key: "test-key".into(),
                jwt_secret: "compat-pair-secret".into(),
                public_dir: "public".into(),
                public_panel_url: "https://panel.test".into(),
                registration_enabled: false,
                cors_origins: vec![],
                geoip_enabled: false,
                geoip_cache_ttl: 604_800,
                socks5_credential_key: Some("11".repeat(32)),
                socks5_check_urls: vec!["https://api.ipify.org".into()],
                socks5_check_concurrency: 50,
                socks5_check_retention_days: 30,
                relay_recommend_health_ttl_seconds: 600,
                relay_recommend_max_cpu_percent: 95.0,
                relay_recommend_max_memory_percent: 95.0,
            },
            release_cache: ReleaseCache::new(),
            node_connections: NodeConnections::new(),
            diagnose: crate::api::diagnose::DiagnoseRegistry::new(),
            socks5_checks: Socks5CheckRegistry::new(),
            geoip_in_flight: Arc::new(Mutex::new(HashSet::new())),
        };
        let (_connection_id, mut node_receiver) = state
            .node_connections
            .register(group, Some("compat-pair-node".into()))
            .await;
        state
            .db
            .set(
                &format!("node_status:{group}:compat-pair-node"),
                r#"{"socks5_check_queue_depth":0}"#,
            )
            .await
            .unwrap();

        // `run_batch` is the execution path used by both legacy single and
        // batch handlers. Both acquire the same persistent Pair coordinator as
        // Manual Jobs, without creating hidden Jobs themselves.
        let batch = tokio::spawn(run_batch(
            state.clone(),
            vec![resource_a, resource_b],
            node,
            1,
        ));
        let first: Socks5CheckRequest = serde_json::from_str(
            &tokio::time::timeout(Duration::from_secs(2), node_receiver.recv())
                .await
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        let second: Socks5CheckRequest = serde_json::from_str(
            &tokio::time::timeout(Duration::from_secs(2), node_receiver.recv())
                .await
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        let single = tokio::spawn(run_batch(state.clone(), vec![resource_a], node, 1));
        let single_result = tokio::time::timeout(Duration::from_secs(2), single)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(single_result[0].outcome, "NODE_BUSY");

        let created_at_ms = chrono::Utc::now().timestamp_millis();
        let manual = NewHealthJob {
            id: "manual-shared-pair".into(),
            source: HealthJobSource::Manual,
            policy_id: None,
            parent_job_id: None,
            actor_id: Some(1),
            request_fingerprint: "a".repeat(64),
            snapshot_hash: snapshot_hash(&[(resource_a, node)]),
            resource_selector_json: "{}".into(),
            node_selector_json: "{}".into(),
            scheduled_for_ms: None,
            created_at_ms,
        };
        state
            .db
            .create_health_job(
                &manual,
                &[NewHealthJobItem {
                    resource_id: resource_a,
                    relay_node_id: node,
                    not_before_ms: created_at_ms,
                    deadline_at_ms: Some(created_at_ms + 900_000),
                }],
            )
            .await
            .unwrap();
        let claimed = state
            .db
            .claim_health_job_items(&HealthItemClaimRequest {
                lease_owner: "compat-shared-worker".into(),
                now_ms: created_at_ms + 1,
                lease_expires_at_ms: created_at_ms + 60_001,
                limit: 8,
                global_limit: 16,
                per_node_limit: 10,
                per_job_limit: 20,
            })
            .await
            .unwrap();
        assert!(
            claimed.is_empty(),
            "legacy batch must block the Manual Job Pair"
        );
        let hidden_jobs: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM socks5_check_jobs WHERE id<>'manual-shared-pair'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            hidden_jobs, 0,
            "compatibility APIs must not create hidden Jobs"
        );
        let (request_a, request_b) = if first.resource_id == resource_a {
            (first, second)
        } else {
            (second, first)
        };
        let latest = Socks5HealthRecord {
            resource_id: resource_a,
            relay_node_id: node,
            status: "ONLINE".into(),
            tcp_latency_ms: Some(99),
            handshake_latency_ms: Some(99),
            connect_latency_ms: Some(99),
            total_latency_ms: Some(297),
            exit_ip: Some("203.0.113.99".into()),
            country: Some("ZZ".into()),
            error_stage: None,
            error_code: None,
            safe_error_message: None,
            consecutive_failures: 0,
            checked_at: "2026-09-16 00:00:00".into(),
            last_success_at: None,
        };
        assert!(state
            .db
            .record_socks5_health(&latest, request_a.resource_generation, request_a.generation,)
            .await
            .unwrap());
        let exact = |request: &Socks5CheckRequest, exit_ip: &str| Socks5CheckResult {
            msg_type: "socks5_check_result".into(),
            request_id: request.request_id.clone(),
            challenge: request.challenge.clone(),
            session_id: request.session_id.clone(),
            resource_generation: request.resource_generation,
            generation: request.generation,
            resource_id: request.resource_id,
            relay_node_id: request.relay_node_id,
            node_id: request.node_id.clone(),
            status: Socks5HealthStatus::Online,
            tcp_latency_ms: Some(1),
            handshake_latency_ms: Some(2),
            connect_latency_ms: Some(3),
            total_latency_ms: Some(6),
            exit_ip: Some(exit_ip.into()),
            detected_country: Some("US".into()),
            error_stage: None,
            error_code: None,
            safe_error_message: None,
            checked_at: "2026-09-16 00:00:01".into(),
        };
        for result in [
            exact(&request_a, "198.51.100.1"),
            exact(&request_b, "198.51.100.2"),
        ] {
            let completion = state
                .socks5_checks
                .complete_matching(&result)
                .await
                .unwrap();
            completion.sender.send(result).unwrap();
        }
        let batch_result = tokio::time::timeout(Duration::from_secs(2), batch)
            .await
            .unwrap()
            .unwrap();
        let a = batch_result
            .iter()
            .find(|response| response.resource_id == resource_a)
            .unwrap();
        assert_eq!(a.outcome, "COMPLETED");
        assert_eq!(
            a.result
                .as_ref()
                .and_then(|result| result.exit_ip.as_deref()),
            Some("198.51.100.1"),
            "compatibility response must use its exact result, not the latest health cell"
        );
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

    #[tokio::test(start_paused = true)]
    async fn compatibility_batch_has_per_item_lifetimes_not_a_global_35_second_deadline() {
        let started = tokio::time::Instant::now();
        let output = map_bounded((0..21).collect(), 1, |item| async move {
            tokio::time::sleep(Duration::from_secs(2)).await;
            item
        })
        .await;
        assert_eq!(output.len(), 21);
        assert!(started.elapsed() >= Duration::from_secs(42));
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
