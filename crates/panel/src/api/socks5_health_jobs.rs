//! Stage 5.2 manual durable SOCKS5 health-job API.
//!
//! HTTP handlers only validate, resolve a deterministic snapshot and commit it.
//! Network execution belongs to the background worker.

use crate::api::middleware::AdminOnly;
use crate::api::AppState;
use crate::db::health_orchestration::{
    canonical_selector_json, request_fingerprint, snapshot_hash, HealthJobCreateOutcome,
    HealthJobFingerprintInput, HealthJobItemListQuery, HealthJobItemRecord, HealthJobListQuery,
    HealthJobRecord, HealthJobSource, HealthJobStatus, HealthMatrixMode, HealthTagMatch,
    NewHealthJob, NewHealthJobIdempotency, NewHealthJobItem, NodeSelector, ResourceSelector,
    IDEMPOTENCY_TTL_MS,
};
use crate::db::repo::{RelayNodeRecord, Socks5ResourceRecord};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};
use relay_shared::protocol::ApiResponse;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashSet;

const DEFAULT_MAX_ITEMS: i64 = 10_000;
const ABSOLUTE_MAX_ITEMS: i64 = 20_000;
const MAX_SELECTOR_IDS: usize = 20_000;
const MAX_SELECTOR_VALUES: usize = 256;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualJobRequest {
    #[serde(default)]
    pub resource_selector: ResourceSelector,
    #[serde(default)]
    pub node_selector: NodeSelector,
    pub matrix_mode: Option<HealthMatrixMode>,
    pub max_items: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct DryRunResponse {
    pub resource_count: i64,
    pub node_count: i64,
    pub item_count: i64,
    pub effective_limit: i64,
    pub within_limit: bool,
    pub snapshot_estimated_at: i64,
    pub matrix_mode: &'static str,
}

#[derive(Debug, Serialize)]
pub struct JobCreateResponse {
    pub job_id: String,
    pub status: String,
    pub total_items: i64,
    pub created_at: i64,
    pub replayed: bool,
}

#[derive(Debug, Serialize)]
pub struct JobResponse {
    pub id: String,
    pub source: String,
    pub parent_job_id: Option<String>,
    pub status: String,
    pub resource_selector: serde_json::Value,
    pub node_selector: serde_json::Value,
    pub snapshot_hash: String,
    pub matrix_mode: String,
    /// `CARTESIAN` for selector-derived Jobs and `EXACT_PAIRS` for a
    /// Retry-Failed child. The persisted selectors remain provenance only.
    pub snapshot_semantics: &'static str,
    pub selectors_reconstruct_snapshot: bool,
    pub retry_policy_version: String,
    pub cancel_requested: bool,
    pub total_items: i64,
    pub queued_count: i64,
    pub running_count: i64,
    pub succeeded_count: i64,
    pub failed_count: i64,
    pub cancelled_count: i64,
    pub failure_code: Option<String>,
    pub created_at: i64,
    pub started_at: Option<i64>,
    pub finished_at: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct JobItemResponse {
    pub id: i64,
    pub job_id: String,
    pub resource_id: Option<i64>,
    pub relay_node_id: Option<i64>,
    pub resource_id_snapshot: i64,
    pub relay_node_id_snapshot: i64,
    pub state: String,
    pub attempt_count: i64,
    pub retry_count: i64,
    pub not_before: i64,
    pub first_started_at: Option<i64>,
    pub last_started_at: Option<i64>,
    pub deadline_at: Option<i64>,
    pub health_status: Option<String>,
    pub safe_error_code: Option<String>,
    pub safe_error_message: Option<String>,
    pub completed_after_cancel: bool,
    pub created_at: i64,
    pub updated_at: i64,
    pub finished_at: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct Page<T: Serialize> {
    pub items: Vec<T>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct JobListParams {
    pub status: Option<String>,
    pub source: Option<String>,
    pub cursor: Option<String>,
    pub limit: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct ItemListParams {
    pub state: Option<String>,
    pub safe_error_code: Option<String>,
    pub cursor: Option<String>,
    pub limit: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize)]
struct JobCursor {
    created_at_ms: i64,
    id: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ItemCursor {
    id: i64,
}

struct ResolvedIntent {
    resources: Vec<i64>,
    nodes: Vec<i64>,
    pairs: Vec<(i64, i64)>,
    item_count: i64,
    resource_selector: ResourceSelector,
    node_selector: NodeSelector,
    max_items: i64,
}

#[derive(Debug, Clone, Copy)]
struct ApiFailure {
    status: StatusCode,
    code: &'static str,
}

impl ApiFailure {
    fn into_response(self) -> Response {
        error(self.status, self.code)
    }
}

fn failure(status: StatusCode, code: &'static str) -> ApiFailure {
    ApiFailure { status, code }
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

fn response<T: Serialize>(status: StatusCode, body: ApiResponse<T>) -> Response {
    (status, Json(body)).into_response()
}

fn success<T: Serialize>(status: StatusCode, data: T) -> Response {
    response(status, ApiResponse::success(data))
}

fn error(status: StatusCode, code: &'static str) -> Response {
    response(
        status,
        ApiResponse::<serde_json::Value> {
            code: status.as_u16().into(),
            message: code.into(),
            data: None,
        },
    )
}

pub async fn dry_run(
    _admin: AdminOnly,
    State(state): State<AppState>,
    Json(request): Json<ManualJobRequest>,
) -> Response {
    let estimated_at = now_ms();
    match resolve_intent(&state, request, false).await {
        Ok(intent) => success(
            StatusCode::OK,
            DryRunResponse {
                resource_count: intent.resources.len() as i64,
                node_count: intent.nodes.len() as i64,
                item_count: intent.item_count,
                effective_limit: intent.max_items,
                within_limit: intent.item_count <= intent.max_items
                    && intent.item_count <= ABSOLUTE_MAX_ITEMS,
                snapshot_estimated_at: estimated_at,
                matrix_mode: HealthMatrixMode::Cartesian.as_str(),
            },
        ),
        Err(failure) => failure.into_response(),
    }
}

pub async fn create(
    admin: AdminOnly,
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ManualJobRequest>,
) -> Response {
    let idempotency_key = match parse_idempotency_key(&headers) {
        Ok(value) => value,
        Err(failure) => return failure.into_response(),
    };
    let normalized = match normalize_manual_request(request) {
        Ok(value) => value,
        Err(failure) => return failure.into_response(),
    };
    let fingerprint = request_fingerprint(&HealthJobFingerprintInput {
        operation: "CREATE".into(),
        source: HealthJobSource::Manual,
        resource_selector: normalized.resource_selector.clone(),
        node_selector: normalized.node_selector.clone(),
        matrix_mode: HealthMatrixMode::Cartesian,
        max_items: normalized.max_items,
        parent_job_id: None,
        policy_id: None,
        policy_revision: None,
    });
    match state
        .db
        .lookup_health_job_idempotency(admin.user_id, &idempotency_key, &fingerprint, now_ms())
        .await
    {
        Ok(crate::db::health_orchestration::HealthJobIdempotencyOutcome::Replay { job_id }) => {
            let Some(existing) = state.db.find_health_job(&job_id).await.ok().flatten() else {
                return error(StatusCode::CONFLICT, "IDEMPOTENCY_LEDGER_ORPHANED");
            };
            crate::service::audit::record(
                &state,
                Some(admin.user_id),
                "JOB_REPLAYED",
                "socks5_health_job",
                &job_id,
                "same_fingerprint=true",
            )
            .await;
            return success(
                StatusCode::OK,
                JobCreateResponse {
                    job_id,
                    status: existing.status,
                    total_items: existing.total_items,
                    created_at: existing.created_at_ms,
                    replayed: true,
                },
            );
        }
        Ok(crate::db::health_orchestration::HealthJobIdempotencyOutcome::Conflict) => {
            return error(StatusCode::CONFLICT, "IDEMPOTENCY_KEY_REUSED");
        }
        Ok(crate::db::health_orchestration::HealthJobIdempotencyOutcome::Available) => {}
        Err(db_error) => {
            tracing::error!("lookup durable health job idempotency: {db_error}");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "DATABASE_ERROR");
        }
    }
    let intent = match resolve_normalized_intent(&state, normalized, true).await {
        Ok(value) => value,
        Err(failure) => {
            if failure.code == "MATRIX_TOO_LARGE" {
                crate::service::audit::record(
                    &state,
                    Some(admin.user_id),
                    "JOB_CARDINALITY_REJECTED",
                    "socks5_health_job",
                    "new",
                    "selector matrix exceeds effective limit",
                )
                .await;
            }
            return failure.into_response();
        }
    };
    create_from_pairs(
        &state,
        admin.user_id,
        idempotency_key,
        HealthJobSource::Manual,
        None,
        intent.resource_selector,
        intent.node_selector,
        intent.pairs,
        intent.max_items,
        "CREATE",
    )
    .await
    .response
}

pub async fn list(
    _admin: AdminOnly,
    State(state): State<AppState>,
    Query(params): Query<JobListParams>,
) -> Response {
    let status = match normalize_job_status(params.status) {
        Ok(value) => value,
        Err(()) => return error(StatusCode::BAD_REQUEST, "INVALID_STATUS"),
    };
    let source = match normalize_job_source(params.source) {
        Ok(value) => value,
        Err(()) => return error(StatusCode::BAD_REQUEST, "INVALID_SOURCE"),
    };
    let cursor = match params
        .cursor
        .as_deref()
        .map(|raw| decode_cursor::<JobCursor>(&state.config.jwt_secret, raw))
    {
        Some(Ok(value)) if value.created_at_ms >= 0 && !value.id.is_empty() => Some(value),
        Some(_) => return error(StatusCode::BAD_REQUEST, "INVALID_CURSOR"),
        None => None,
    };
    let limit = match params.limit.unwrap_or(50) {
        value @ 1..=200 => value,
        _ => return error(StatusCode::BAD_REQUEST, "INVALID_LIMIT"),
    };
    let query = HealthJobListQuery {
        status,
        source,
        before_created_at_ms: cursor.as_ref().map(|value| value.created_at_ms),
        before_id: cursor.map(|value| value.id),
        limit: limit + 1,
    };
    match state.db.list_health_jobs(&query).await {
        Ok(mut rows) => {
            let has_more = rows.len() > limit as usize;
            rows.truncate(limit as usize);
            let next_cursor = has_more.then(|| {
                let row = rows.last().expect("truncated page is non-empty");
                encode_cursor(
                    &state.config.jwt_secret,
                    &JobCursor {
                        created_at_ms: row.created_at_ms,
                        id: row.id.clone(),
                    },
                )
            });
            success(
                StatusCode::OK,
                Page {
                    items: rows.into_iter().map(job_response).collect(),
                    next_cursor,
                },
            )
        }
        Err(db_error) => {
            tracing::error!("list durable health jobs: {db_error}");
            error(StatusCode::INTERNAL_SERVER_ERROR, "DATABASE_ERROR")
        }
    }
}

pub async fn detail(
    _admin: AdminOnly,
    State(state): State<AppState>,
    Path(job_id): Path<String>,
) -> Response {
    if uuid::Uuid::parse_str(&job_id).is_err() {
        return error(StatusCode::NOT_FOUND, "JOB_NOT_FOUND");
    }
    match state.db.find_health_job(&job_id).await {
        Ok(Some(job)) => success(StatusCode::OK, job_response(job)),
        Ok(None) => error(StatusCode::NOT_FOUND, "JOB_NOT_FOUND"),
        Err(db_error) => {
            tracing::error!("find durable health job: {db_error}");
            error(StatusCode::INTERNAL_SERVER_ERROR, "DATABASE_ERROR")
        }
    }
}

pub async fn items(
    _admin: AdminOnly,
    State(state): State<AppState>,
    Path(job_id): Path<String>,
    Query(params): Query<ItemListParams>,
) -> Response {
    match state.db.find_health_job(&job_id).await {
        Ok(Some(_)) => {}
        Ok(None) => return error(StatusCode::NOT_FOUND, "JOB_NOT_FOUND"),
        Err(db_error) => {
            tracing::error!("find health job for item page: {db_error}");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "DATABASE_ERROR");
        }
    }
    let state_filter = match params.state {
        Some(value) => {
            let value = value.trim().to_ascii_uppercase();
            if crate::db::health_orchestration::HealthJobItemState::parse(&value).is_none() {
                return error(StatusCode::BAD_REQUEST, "INVALID_ITEM_STATE");
            }
            Some(value)
        }
        None => None,
    };
    let after_id = match params
        .cursor
        .as_deref()
        .map(|raw| decode_cursor::<ItemCursor>(&state.config.jwt_secret, raw))
    {
        Some(Ok(value)) if value.id > 0 => Some(value.id),
        Some(_) => return error(StatusCode::BAD_REQUEST, "INVALID_CURSOR"),
        None => None,
    };
    let limit = match params.limit.unwrap_or(100) {
        value @ 1..=500 => value,
        _ => return error(StatusCode::BAD_REQUEST, "INVALID_LIMIT"),
    };
    let query = HealthJobItemListQuery {
        job_id,
        state: state_filter,
        safe_error_code: params
            .safe_error_code
            .map(|value| value.trim().to_ascii_uppercase())
            .filter(|value| !value.is_empty()),
        after_id,
        limit: limit + 1,
    };
    match state.db.list_health_job_items_page(&query).await {
        Ok(mut rows) => {
            let has_more = rows.len() > limit as usize;
            rows.truncate(limit as usize);
            let next_cursor = has_more.then(|| {
                encode_cursor(
                    &state.config.jwt_secret,
                    &ItemCursor {
                        id: rows.last().expect("truncated page is non-empty").id,
                    },
                )
            });
            success(
                StatusCode::OK,
                Page {
                    items: rows.into_iter().map(item_response).collect(),
                    next_cursor,
                },
            )
        }
        Err(db_error) => {
            tracing::error!("list durable health job items: {db_error}");
            error(StatusCode::INTERNAL_SERVER_ERROR, "DATABASE_ERROR")
        }
    }
}

pub async fn cancel(
    admin: AdminOnly,
    State(state): State<AppState>,
    Path(job_id): Path<String>,
) -> Response {
    let before = match state.db.find_health_job(&job_id).await {
        Ok(Some(job)) => job,
        Ok(None) => return error(StatusCode::NOT_FOUND, "JOB_NOT_FOUND"),
        Err(db_error) => {
            tracing::error!("find durable health job before cancel: {db_error}");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "DATABASE_ERROR");
        }
    };
    let transition_ms = now_ms();
    match state.db.cancel_health_job(&job_id, transition_ms).await {
        Ok(true) => match state.db.find_health_job(&job_id).await {
            Ok(Some(job)) => {
                if !before.cancel_requested
                    && !HealthJobStatus::parse(&before.status)
                        .is_some_and(HealthJobStatus::is_terminal)
                {
                    crate::service::audit::record(
                        &state,
                        Some(admin.user_id),
                        "JOB_CANCEL_REQUESTED",
                        "socks5_health_job",
                        &job_id,
                        "cancel_requested=true",
                    )
                    .await;
                }
                success(StatusCode::OK, job_response(job))
            }
            _ => error(StatusCode::INTERNAL_SERVER_ERROR, "DATABASE_ERROR"),
        },
        Ok(false) => error(StatusCode::NOT_FOUND, "JOB_NOT_FOUND"),
        Err(db_error) => {
            tracing::error!("cancel durable health job: {db_error}");
            error(StatusCode::INTERNAL_SERVER_ERROR, "DATABASE_ERROR")
        }
    }
}

pub async fn retry_failed(
    admin: AdminOnly,
    State(state): State<AppState>,
    Path(parent_job_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let idempotency_key = match parse_idempotency_key(&headers) {
        Ok(value) => value,
        Err(failure) => return failure.into_response(),
    };
    let parent = match state.db.find_health_job(&parent_job_id).await {
        Ok(Some(job)) => job,
        Ok(None) => return error(StatusCode::NOT_FOUND, "JOB_NOT_FOUND"),
        Err(db_error) => {
            tracing::error!("find retry parent health job: {db_error}");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "DATABASE_ERROR");
        }
    };
    if !HealthJobStatus::parse(&parent.status).is_some_and(HealthJobStatus::is_terminal) {
        return error(StatusCode::CONFLICT, "JOB_NOT_TERMINAL");
    }
    let pairs = match state.db.retry_failed_health_pairs(&parent_job_id).await {
        Ok(pairs) if pairs.is_empty() => return error(StatusCode::CONFLICT, "NO_FAILED_ITEMS"),
        Ok(pairs) => pairs,
        Err(db_error) => {
            tracing::error!("resolve failed durable health pairs: {db_error}");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "DATABASE_ERROR");
        }
    };
    let resource_selector = ResourceSelector {
        ids: pairs.iter().map(|pair| pair.0).collect(),
        enabled: None,
        ..Default::default()
    }
    .canonicalized();
    let node_selector = NodeSelector {
        ids: pairs.iter().map(|pair| pair.1).collect(),
        enabled: None,
        ..Default::default()
    }
    .canonicalized();
    let result = create_from_pairs(
        &state,
        admin.user_id,
        idempotency_key,
        HealthJobSource::RetryFailed,
        Some(parent_job_id.clone()),
        resource_selector,
        node_selector,
        pairs,
        ABSOLUTE_MAX_ITEMS,
        "RETRY_FAILED",
    )
    .await;
    if result.response.status().is_success() {
        let replayed = result.replayed.unwrap_or(false);
        crate::service::audit::record(
            &state,
            Some(admin.user_id),
            "JOB_RETRY_FAILED",
            "socks5_health_job",
            &parent_job_id,
            &format!("child_job_created={}; replayed={replayed}", !replayed),
        )
        .await;
    }
    result.response
}

struct CreateFromPairsOutcome {
    response: Response,
    replayed: Option<bool>,
}

#[allow(clippy::too_many_arguments)]
async fn create_from_pairs(
    state: &AppState,
    actor_id: i64,
    idempotency_key: String,
    source: HealthJobSource,
    parent_job_id: Option<String>,
    resource_selector: ResourceSelector,
    node_selector: NodeSelector,
    mut pairs: Vec<(i64, i64)>,
    max_items: i64,
    operation: &str,
) -> CreateFromPairsOutcome {
    pairs.sort_unstable();
    pairs.dedup();
    if pairs.is_empty() {
        return CreateFromPairsOutcome {
            response: error(StatusCode::UNPROCESSABLE_ENTITY, "EMPTY_SELECTION"),
            replayed: None,
        };
    }
    if pairs.len() > ABSOLUTE_MAX_ITEMS as usize || pairs.len() as i64 > max_items {
        crate::service::audit::record(
            state,
            Some(actor_id),
            "JOB_CARDINALITY_REJECTED",
            "socks5_health_job",
            "new",
            &format!("item_count={}; effective_limit={max_items}", pairs.len()),
        )
        .await;
        return CreateFromPairsOutcome {
            response: error(StatusCode::UNPROCESSABLE_ENTITY, "MATRIX_TOO_LARGE"),
            replayed: None,
        };
    }
    let fingerprint = request_fingerprint(&HealthJobFingerprintInput {
        operation: operation.into(),
        source,
        resource_selector: resource_selector.clone(),
        node_selector: node_selector.clone(),
        matrix_mode: HealthMatrixMode::Cartesian,
        max_items,
        parent_job_id: parent_job_id.clone(),
        policy_id: None,
        policy_revision: None,
    });
    let created_at_ms = now_ms();
    let job_id = uuid::Uuid::new_v4().to_string();
    let job = NewHealthJob {
        id: job_id.clone(),
        source,
        policy_id: None,
        parent_job_id,
        actor_id: Some(actor_id),
        request_fingerprint: fingerprint.clone(),
        snapshot_hash: snapshot_hash(&pairs),
        resource_selector_json: canonical_selector_json(&resource_selector),
        node_selector_json: canonical_selector_json(&node_selector),
        scheduled_for_ms: None,
        created_at_ms,
    };
    let deadline = created_at_ms.checked_add(15 * 60 * 1_000);
    let items = pairs
        .into_iter()
        .map(|(resource_id, relay_node_id)| NewHealthJobItem {
            resource_id,
            relay_node_id,
            not_before_ms: created_at_ms,
            deadline_at_ms: deadline,
        })
        .collect::<Vec<_>>();
    let key = NewHealthJobIdempotency {
        actor_id,
        idempotency_key,
        request_fingerprint: fingerprint,
        created_at_ms,
        expires_at_ms: created_at_ms + IDEMPOTENCY_TTL_MS,
    };
    match state
        .db
        .create_health_job_idempotent(&job, &items, &key)
        .await
    {
        Ok(HealthJobCreateOutcome::Created { job_id }) => {
            crate::service::audit::record(
                state,
                Some(actor_id),
                "JOB_CREATED",
                "socks5_health_job",
                &job_id,
                &format!("source={}; total_items={}", source.as_str(), items.len()),
            )
            .await;
            CreateFromPairsOutcome {
                response: success(
                    StatusCode::ACCEPTED,
                    JobCreateResponse {
                        job_id,
                        status: "QUEUED".into(),
                        total_items: items.len() as i64,
                        created_at: created_at_ms,
                        replayed: false,
                    },
                ),
                replayed: Some(false),
            }
        }
        Ok(HealthJobCreateOutcome::Replay { job_id }) => {
            let Some(existing) = state.db.find_health_job(&job_id).await.ok().flatten() else {
                return CreateFromPairsOutcome {
                    response: error(StatusCode::CONFLICT, "IDEMPOTENCY_LEDGER_ORPHANED"),
                    replayed: None,
                };
            };
            crate::service::audit::record(
                state,
                Some(actor_id),
                "JOB_REPLAYED",
                "socks5_health_job",
                &job_id,
                "same_fingerprint=true",
            )
            .await;
            CreateFromPairsOutcome {
                response: success(
                    StatusCode::OK,
                    JobCreateResponse {
                        job_id,
                        status: existing.status,
                        total_items: existing.total_items,
                        created_at: existing.created_at_ms,
                        replayed: true,
                    },
                ),
                replayed: Some(true),
            }
        }
        Ok(HealthJobCreateOutcome::Conflict) => CreateFromPairsOutcome {
            response: error(StatusCode::CONFLICT, "IDEMPOTENCY_KEY_REUSED"),
            replayed: None,
        },
        Err(db_error) => {
            tracing::error!("create durable health job: {db_error}");
            CreateFromPairsOutcome {
                response: error(StatusCode::INTERNAL_SERVER_ERROR, "DATABASE_ERROR"),
                replayed: None,
            }
        }
    }
}

async fn resolve_intent(
    state: &AppState,
    request: ManualJobRequest,
    reject_over_limit: bool,
) -> Result<ResolvedIntent, ApiFailure> {
    let request = normalize_manual_request(request)?;
    resolve_normalized_intent(state, request, reject_over_limit).await
}

#[derive(Debug)]
struct NormalizedManualRequest {
    resource_selector: ResourceSelector,
    node_selector: NodeSelector,
    max_items: i64,
}

fn normalize_manual_request(
    request: ManualJobRequest,
) -> Result<NormalizedManualRequest, ApiFailure> {
    if !matches!(
        request.matrix_mode,
        None | Some(HealthMatrixMode::Cartesian)
    ) {
        return Err(failure(StatusCode::BAD_REQUEST, "INVALID_MATRIX_MODE"));
    }
    let max_items = request.max_items.unwrap_or(DEFAULT_MAX_ITEMS);
    if !(1..=ABSOLUTE_MAX_ITEMS).contains(&max_items) {
        return Err(failure(StatusCode::BAD_REQUEST, "INVALID_MAX_ITEMS"));
    }
    validate_selector_sizes(&request.resource_selector, &request.node_selector)?;
    let resource_selector = request.resource_selector.canonicalized();
    let node_selector = request.node_selector.canonicalized();
    validate_selector_values(&resource_selector, &node_selector)?;
    Ok(NormalizedManualRequest {
        resource_selector,
        node_selector,
        max_items,
    })
}

async fn resolve_normalized_intent(
    state: &AppState,
    request: NormalizedManualRequest,
    reject_over_limit: bool,
) -> Result<ResolvedIntent, ApiFailure> {
    let resource_selector = request.resource_selector;
    let node_selector = request.node_selector;
    let max_items = request.max_items;
    let resources = state.db.list_socks5_resources().await.map_err(|db_error| {
        tracing::error!("resolve durable health resources: {db_error}");
        failure(StatusCode::INTERNAL_SERVER_ERROR, "DATABASE_ERROR")
    })?;
    let nodes = state.db.list_relay_nodes().await.map_err(|db_error| {
        tracing::error!("resolve durable health relay nodes: {db_error}");
        failure(StatusCode::INTERNAL_SERVER_ERROR, "DATABASE_ERROR")
    })?;
    ensure_explicit_ids_exist(&resource_selector.ids, resources.iter().map(|row| row.id))?;
    ensure_explicit_ids_exist(&node_selector.ids, nodes.iter().map(|row| row.id))?;
    let mut resource_ids = resources
        .iter()
        .filter(|row| resource_matches(row, &resource_selector))
        .map(|row| row.id)
        .collect::<Vec<_>>();
    let mut node_ids = nodes
        .iter()
        .filter(|row| node_matches(row, &node_selector))
        .map(|row| row.id)
        .collect::<Vec<_>>();
    resource_ids.sort_unstable();
    node_ids.sort_unstable();
    if resource_ids.is_empty() || node_ids.is_empty() {
        return Err(failure(StatusCode::UNPROCESSABLE_ENTITY, "EMPTY_SELECTION"));
    }
    let item_count = resource_ids
        .len()
        .checked_mul(node_ids.len())
        .ok_or_else(|| failure(StatusCode::UNPROCESSABLE_ENTITY, "MATRIX_TOO_LARGE"))?;
    if reject_over_limit
        && (item_count > max_items as usize || item_count > ABSOLUTE_MAX_ITEMS as usize)
    {
        return Err(failure(
            StatusCode::UNPROCESSABLE_ENTITY,
            "MATRIX_TOO_LARGE",
        ));
    }
    let item_count_i64 = i64::try_from(item_count)
        .map_err(|_| failure(StatusCode::UNPROCESSABLE_ENTITY, "MATRIX_TOO_LARGE"))?;
    let pairs = if item_count <= ABSOLUTE_MAX_ITEMS as usize && item_count <= max_items as usize {
        resource_ids
            .iter()
            .flat_map(|resource_id| node_ids.iter().map(move |node_id| (*resource_id, *node_id)))
            .collect()
    } else {
        Vec::new()
    };
    Ok(ResolvedIntent {
        resources: resource_ids,
        nodes: node_ids,
        pairs,
        item_count: item_count_i64,
        resource_selector,
        node_selector,
        max_items,
    })
}

fn validate_selector_sizes(
    resources: &ResourceSelector,
    nodes: &NodeSelector,
) -> Result<(), ApiFailure> {
    if resources.ids.len() > MAX_SELECTOR_IDS
        || nodes.ids.len() > MAX_SELECTOR_IDS
        || resources.country_codes.len() > MAX_SELECTOR_VALUES
        || resources.statuses.len() > MAX_SELECTOR_VALUES
        || resources.tags.len() > MAX_SELECTOR_VALUES
        || nodes.country_codes.len() > MAX_SELECTOR_VALUES
        || nodes.tags.len() > MAX_SELECTOR_VALUES
    {
        return Err(failure(StatusCode::PAYLOAD_TOO_LARGE, "SELECTOR_TOO_LARGE"));
    }
    if resources.ids.iter().chain(&nodes.ids).any(|id| *id <= 0) {
        return Err(failure(StatusCode::BAD_REQUEST, "INVALID_SELECTOR_ID"));
    }
    Ok(())
}

fn validate_selector_values(
    resources: &ResourceSelector,
    nodes: &NodeSelector,
) -> Result<(), ApiFailure> {
    let strings = resources
        .country_codes
        .iter()
        .chain(&resources.statuses)
        .chain(&resources.tags)
        .chain(&nodes.country_codes)
        .chain(&nodes.tags);
    if strings.clone().any(|value| value.len() > 128) {
        return Err(failure(StatusCode::BAD_REQUEST, "INVALID_SELECTOR_VALUE"));
    }
    const STATUSES: [&str; 7] = [
        "ONLINE",
        "OFFLINE",
        "AUTH_FAILED",
        "TIMEOUT",
        "CONNECT_FAILED",
        "DISABLED",
        "UNKNOWN",
    ];
    if resources
        .statuses
        .iter()
        .any(|status| !STATUSES.contains(&status.as_str()))
    {
        return Err(failure(StatusCode::BAD_REQUEST, "INVALID_RESOURCE_STATUS"));
    }
    Ok(())
}

fn ensure_explicit_ids_exist(
    explicit: &[i64],
    available: impl Iterator<Item = i64>,
) -> Result<(), ApiFailure> {
    if explicit.is_empty() {
        return Ok(());
    }
    let available = available.collect::<HashSet<_>>();
    if explicit.iter().all(|id| available.contains(id)) {
        Ok(())
    } else {
        Err(failure(
            StatusCode::UNPROCESSABLE_ENTITY,
            "SELECTOR_REFERENCE_MISSING",
        ))
    }
}

fn resource_matches(row: &Socks5ResourceRecord, selector: &ResourceSelector) -> bool {
    (selector.ids.is_empty() || selector.ids.binary_search(&row.id).is_ok())
        && selector
            .enabled
            .is_none_or(|enabled| row.enabled == enabled)
        && (selector.country_codes.is_empty()
            || selector
                .country_codes
                .binary_search(&row.country_code.trim().to_ascii_uppercase())
                .is_ok())
        && (selector.statuses.is_empty()
            || selector
                .statuses
                .binary_search(&row.status.trim().to_ascii_uppercase())
                .is_ok())
        && tags_match(&row.tags, &selector.tags, selector.tag_match)
}

fn node_matches(row: &RelayNodeRecord, selector: &NodeSelector) -> bool {
    (selector.ids.is_empty() || selector.ids.binary_search(&row.id).is_ok())
        && selector
            .enabled
            .is_none_or(|enabled| row.enabled == enabled)
        && (selector.country_codes.is_empty()
            || selector
                .country_codes
                .binary_search(&row.country_code.trim().to_ascii_uppercase())
                .is_ok())
        && tags_match(&row.tags, &selector.tags, selector.tag_match)
}

fn tags_match(raw: &str, expected: &[String], mode: HealthTagMatch) -> bool {
    if expected.is_empty() {
        return true;
    }
    let actual = serde_json::from_str::<Vec<String>>(raw)
        .unwrap_or_default()
        .into_iter()
        .map(|tag| tag.trim().to_ascii_lowercase())
        .collect::<HashSet<_>>();
    match mode {
        HealthTagMatch::Any => expected.iter().any(|tag| actual.contains(tag)),
        HealthTagMatch::All => expected.iter().all(|tag| actual.contains(tag)),
    }
}

fn parse_idempotency_key(headers: &HeaderMap) -> Result<String, ApiFailure> {
    let Some(raw) = headers
        .get("Idempotency-Key")
        .and_then(|value| value.to_str().ok())
    else {
        return Err(failure(StatusCode::BAD_REQUEST, "INVALID_IDEMPOTENCY_KEY"));
    };
    let parsed = uuid::Uuid::parse_str(raw)
        .map_err(|_| failure(StatusCode::BAD_REQUEST, "INVALID_IDEMPOTENCY_KEY"))?;
    let canonical = parsed.hyphenated().to_string();
    if parsed.get_version() != Some(uuid::Version::Random) || raw != canonical {
        return Err(failure(StatusCode::BAD_REQUEST, "INVALID_IDEMPOTENCY_KEY"));
    }
    Ok(canonical)
}

fn normalize_job_status(value: Option<String>) -> Result<Option<String>, ()> {
    value
        .map(|value| {
            let value = value.trim().to_ascii_uppercase();
            HealthJobStatus::parse(&value).map(|_| value).ok_or(())
        })
        .transpose()
}

fn normalize_job_source(value: Option<String>) -> Result<Option<String>, ()> {
    value
        .map(|value| {
            let value = value.trim().to_ascii_uppercase();
            HealthJobSource::parse(&value).map(|_| value).ok_or(())
        })
        .transpose()
}

fn encode_cursor<T: Serialize>(secret: &str, value: &T) -> String {
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(value).expect("cursor serializes"));
    format!("{payload}.{}", cursor_signature(secret, &payload))
}

fn decode_cursor<T: for<'de> Deserialize<'de>>(secret: &str, raw: &str) -> Result<T, ()> {
    let (payload, signature) = raw.rsplit_once('.').ok_or(())?;
    if signature != cursor_signature(secret, payload) {
        return Err(());
    }
    let bytes = URL_SAFE_NO_PAD.decode(payload).map_err(|_| ())?;
    serde_json::from_slice(&bytes).map_err(|_| ())
}

fn cursor_signature(secret: &str, payload: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .expect("HMAC accepts keys of every length");
    mac.update(payload.as_bytes());
    mac.finalize()
        .into_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn parse_json(raw: &str) -> serde_json::Value {
    serde_json::from_str(raw).unwrap_or(serde_json::Value::Null)
}

fn job_response(row: HealthJobRecord) -> JobResponse {
    let exact_pairs = row.source == HealthJobSource::RetryFailed.as_str();
    JobResponse {
        id: row.id,
        source: row.source,
        parent_job_id: row.parent_job_id,
        status: row.status,
        resource_selector: parse_json(&row.resource_selector_json),
        node_selector: parse_json(&row.node_selector_json),
        snapshot_hash: row.snapshot_hash,
        matrix_mode: row.matrix_mode,
        snapshot_semantics: if exact_pairs {
            "EXACT_PAIRS"
        } else {
            "CARTESIAN"
        },
        selectors_reconstruct_snapshot: !exact_pairs,
        retry_policy_version: row.retry_policy_version,
        cancel_requested: row.cancel_requested,
        total_items: row.total_items,
        queued_count: row.queued_count,
        running_count: row.running_count,
        succeeded_count: row.succeeded_count,
        failed_count: row.failed_count,
        cancelled_count: row.cancelled_count,
        failure_code: row.failure_code,
        created_at: row.created_at_ms,
        started_at: row.started_at_ms,
        finished_at: row.finished_at_ms,
    }
}

fn item_response(row: HealthJobItemRecord) -> JobItemResponse {
    JobItemResponse {
        id: row.id,
        job_id: row.job_id,
        resource_id: row.resource_id,
        relay_node_id: row.relay_node_id,
        resource_id_snapshot: row.resource_id_snapshot,
        relay_node_id_snapshot: row.relay_node_id_snapshot,
        state: row.state,
        attempt_count: row.attempt_count,
        retry_count: row.retry_count,
        not_before: row.not_before_ms,
        first_started_at: row.first_started_at_ms,
        last_started_at: row.last_started_at_ms,
        deadline_at: row.deadline_at_ms,
        health_status: row.health_status,
        safe_error_code: row.safe_error_code,
        safe_error_message: row.safe_error_message,
        completed_after_cancel: row.completed_after_cancel,
        created_at: row.created_at_ms,
        updated_at: row.updated_at_ms,
        finished_at: row.finished_at_ms,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::middleware::Claims;
    use crate::api::system::ReleaseCache;
    use crate::api::ws::NodeConnections;
    use crate::config::Config;
    use crate::db::schema::SCHEMA_SQL;
    use crate::db::sqlite_repo::SqliteRepository;
    use axum::body::Body;
    use axum::http::{HeaderValue, Method, Request};
    use jsonwebtoken::{encode, EncodingKey, Header};
    use sqlx::sqlite::SqlitePoolOptions;
    use std::sync::Arc;
    use tower::ServiceExt;

    async fn http_test_state() -> (AppState, sqlx::SqlitePool) {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query(SCHEMA_SQL).execute(&pool).await.unwrap();
        crate::db::schema::run_migrations(&pool).await.unwrap();
        sqlx::query("UPDATE users SET token_version=0,must_change_password=0,banned=0 WHERE id=1")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO users (id,username,password,admin,all_device_groups,balance,max_rules,traffic_used,traffic_limit,banned) VALUES (2,'member','unused-test-hash',0,1,'0',5,0,0,0)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO socks5_resources(id,name,host,port) VALUES(11,'manual-resource','127.0.0.1',1080)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO device_groups(id,name,group_type,token,uid) VALUES(21,'manual-group','in','manual-group-token',1)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO relay_nodes(id,device_group_id,node_key,first_seen_at,last_seen_at) VALUES(31,21,'manual-node','2026-01-01','2026-01-01')")
            .execute(&pool)
            .await
            .unwrap();
        let state = AppState {
            db: Arc::new(SqliteRepository::new(pool.clone())),
            config: Config {
                database_path: "sqlite::memory:".into(),
                listen: "127.0.0.1:0".into(),
                key: "test-key".into(),
                jwt_secret: "health-jobs-test-secret".into(),
                public_dir: "public".into(),
                public_panel_url: String::new(),
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
            socks5_checks: crate::api::socks5_health::Socks5CheckRegistry::new(),
            geoip_in_flight: Arc::new(tokio::sync::Mutex::new(HashSet::new())),
        };
        (state, pool)
    }

    fn token(user_id: i64, admin: bool) -> String {
        encode(
            &Header::default(),
            &Claims {
                sub: user_id,
                admin,
                token_version: 0,
                exp: (chrono::Utc::now().timestamp() + 3_600) as usize,
            },
            &EncodingKey::from_secret(b"health-jobs-test-secret"),
        )
        .unwrap()
    }

    fn request(
        method: Method,
        uri: &str,
        token: Option<&str>,
        idempotency_key: Option<&str>,
        body: &str,
    ) -> Request<Body> {
        let mut builder = Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json");
        if let Some(token) = token {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        if let Some(key) = idempotency_key {
            builder = builder.header("idempotency-key", key);
        }
        builder.body(Body::from(body.to_owned())).unwrap()
    }

    #[test]
    fn cursor_round_trip_and_tamper_rejection() {
        let cursor = JobCursor {
            created_at_ms: 123,
            id: "job-a".into(),
        };
        let encoded = encode_cursor("secret", &cursor);
        let decoded: JobCursor = decode_cursor("secret", &encoded).unwrap();
        assert_eq!(decoded.created_at_ms, 123);
        assert_eq!(decoded.id, "job-a");
        assert!(decode_cursor::<JobCursor>("secret", "not!base64").is_err());
        assert!(decode_cursor::<JobCursor>("wrong", &encoded).is_err());
    }

    #[test]
    fn tags_obey_any_and_all() {
        let raw = r#"["US","residential"]"#;
        assert!(tags_match(raw, &["us".into()], HealthTagMatch::Any));
        assert!(tags_match(
            raw,
            &["us".into(), "residential".into()],
            HealthTagMatch::All
        ));
        assert!(!tags_match(
            raw,
            &["us".into(), "mobile".into()],
            HealthTagMatch::All
        ));
    }

    #[test]
    fn manual_request_normalizes_selectors_and_rejects_unknown_status() {
        let normalized = normalize_manual_request(ManualJobRequest {
            resource_selector: ResourceSelector {
                ids: vec![3, 1, 3],
                country_codes: vec![" us ".into(), "JP".into()],
                statuses: vec![" online ".into()],
                tags: vec![" Residential ".into()],
                ..Default::default()
            },
            node_selector: NodeSelector {
                ids: vec![9, 2, 9],
                ..Default::default()
            },
            matrix_mode: Some(HealthMatrixMode::Cartesian),
            max_items: None,
        })
        .unwrap();
        assert_eq!(normalized.resource_selector.ids, vec![1, 3]);
        assert_eq!(normalized.resource_selector.country_codes, vec!["JP", "US"]);
        assert_eq!(normalized.resource_selector.statuses, vec!["ONLINE"]);
        assert_eq!(normalized.resource_selector.tags, vec!["residential"]);
        assert_eq!(normalized.node_selector.ids, vec![2, 9]);
        assert_eq!(normalized.max_items, DEFAULT_MAX_ITEMS);

        let invalid = normalize_manual_request(ManualJobRequest {
            resource_selector: ResourceSelector {
                statuses: vec!["SECRET_RAW_ERROR".into()],
                ..Default::default()
            },
            node_selector: NodeSelector::default(),
            matrix_mode: None,
            max_items: None,
        })
        .unwrap_err();
        assert_eq!(invalid.code, "INVALID_RESOURCE_STATUS");
    }

    #[test]
    fn idempotency_key_requires_canonical_uuid_v4() {
        let key = uuid::Uuid::new_v4().to_string();
        let mut headers = HeaderMap::new();
        headers.insert("Idempotency-Key", HeaderValue::from_str(&key).unwrap());
        assert_eq!(parse_idempotency_key(&headers).unwrap(), key);

        headers.insert(
            "Idempotency-Key",
            HeaderValue::from_static("550e8400-e29b-11d4-a716-446655440000"),
        );
        assert_eq!(
            parse_idempotency_key(&headers).unwrap_err().code,
            "INVALID_IDEMPOTENCY_KEY"
        );
    }

    #[tokio::test]
    async fn manual_job_http_contract_enforces_auth_idempotency_and_pagination() {
        let (state, pool) = http_test_state().await;
        let app = crate::api::routes().with_state(state);
        let selector = r#"{"resource_selector":{"ids":[11]},"node_selector":{"ids":[31]}}"#;

        let unauthenticated = app
            .clone()
            .oneshot(request(
                Method::POST,
                "/admin/socks5-health/jobs/dry-run",
                None,
                None,
                selector,
            ))
            .await
            .unwrap();
        assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

        let member = token(2, false);
        let forbidden = app
            .clone()
            .oneshot(request(
                Method::POST,
                "/admin/socks5-health/jobs/dry-run",
                Some(&member),
                None,
                selector,
            ))
            .await
            .unwrap();
        assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);

        let admin = token(1, true);
        let dry_run = app
            .clone()
            .oneshot(request(
                Method::POST,
                "/admin/socks5-health/jobs/dry-run",
                Some(&admin),
                None,
                selector,
            ))
            .await
            .unwrap();
        assert_eq!(dry_run.status(), StatusCode::OK);
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM socks5_check_jobs")
                .fetch_one(&pool)
                .await
                .unwrap(),
            0
        );

        let missing_key = app
            .clone()
            .oneshot(request(
                Method::POST,
                "/admin/socks5-health/jobs",
                Some(&admin),
                None,
                selector,
            ))
            .await
            .unwrap();
        assert_eq!(missing_key.status(), StatusCode::BAD_REQUEST);

        let key = uuid::Uuid::new_v4().to_string();
        let created = app
            .clone()
            .oneshot(request(
                Method::POST,
                "/admin/socks5-health/jobs",
                Some(&admin),
                Some(&key),
                selector,
            ))
            .await
            .unwrap();
        assert_eq!(created.status(), StatusCode::ACCEPTED);
        let body = axum::body::to_bytes(created.into_body(), 65_536)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let job_id = body["data"]["job_id"].as_str().unwrap().to_owned();
        assert_eq!(body["data"]["replayed"], false);

        let replay = app
            .clone()
            .oneshot(request(
                Method::POST,
                "/admin/socks5-health/jobs",
                Some(&admin),
                Some(&key),
                selector,
            ))
            .await
            .unwrap();
        assert_eq!(replay.status(), StatusCode::OK);
        let replay_body = axum::body::to_bytes(replay.into_body(), 65_536)
            .await
            .unwrap();
        let replay_body: serde_json::Value = serde_json::from_slice(&replay_body).unwrap();
        assert_eq!(replay_body["data"]["job_id"], job_id);
        assert_eq!(replay_body["data"]["replayed"], true);

        let conflicting =
            r#"{"resource_selector":{"ids":[11]},"node_selector":{"ids":[31]},"max_items":2}"#;
        let conflict = app
            .clone()
            .oneshot(request(
                Method::POST,
                "/admin/socks5-health/jobs",
                Some(&admin),
                Some(&key),
                conflicting,
            ))
            .await
            .unwrap();
        assert_eq!(conflict.status(), StatusCode::CONFLICT);
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM socks5_check_jobs")
                .fetch_one(&pool)
                .await
                .unwrap(),
            1
        );

        let jobs = app
            .clone()
            .oneshot(request(
                Method::GET,
                "/admin/socks5-health/jobs?limit=1",
                Some(&admin),
                None,
                "",
            ))
            .await
            .unwrap();
        assert_eq!(jobs.status(), StatusCode::OK);
        let items = app
            .clone()
            .oneshot(request(
                Method::GET,
                &format!("/admin/socks5-health/jobs/{job_id}/items?limit=1"),
                Some(&admin),
                None,
                "",
            ))
            .await
            .unwrap();
        assert_eq!(items.status(), StatusCode::OK);
        let tampered_cursor = app
            .oneshot(request(
                Method::GET,
                "/admin/socks5-health/jobs?cursor=tampered&limit=1",
                Some(&admin),
                None,
                "",
            ))
            .await
            .unwrap();
        assert_eq!(tampered_cursor.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn retry_failed_reports_exact_pairs_and_audits_idempotency_replay_truthfully() {
        let (state, pool) = http_test_state().await;
        let parent = NewHealthJob {
            id: "retry-parent".into(),
            source: HealthJobSource::Manual,
            policy_id: None,
            parent_job_id: None,
            actor_id: Some(1),
            request_fingerprint: "a".repeat(64),
            snapshot_hash: snapshot_hash(&[(11, 31)]),
            resource_selector_json: r#"{"ids":[11]}"#.into(),
            node_selector_json: r#"{"ids":[31]}"#.into(),
            scheduled_for_ms: None,
            created_at_ms: 1_000,
        };
        state
            .db
            .create_health_job(
                &parent,
                &[NewHealthJobItem {
                    resource_id: 11,
                    relay_node_id: 31,
                    not_before_ms: 1_000,
                    deadline_at_ms: Some(10_000),
                }],
            )
            .await
            .unwrap();
        sqlx::query(
            "UPDATE socks5_check_job_items
             SET state='FAILED',safe_error_code='UPSTREAM_UNAVAILABLE',
                 safe_error_message='Upstream service unavailable',finished_at_ms=2000,updated_at_ms=2000
             WHERE job_id='retry-parent'",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "UPDATE socks5_check_jobs
             SET status='FAILED',queued_count=0,failed_count=1,finished_at_ms=2000
             WHERE id='retry-parent'",
        )
        .execute(&pool)
        .await
        .unwrap();

        let app = crate::api::routes().with_state(state);
        let admin = token(1, true);
        let key = uuid::Uuid::new_v4().to_string();
        let created = app
            .clone()
            .oneshot(request(
                Method::POST,
                "/admin/socks5-health/jobs/retry-parent/retry-failed",
                Some(&admin),
                Some(&key),
                "",
            ))
            .await
            .unwrap();
        assert_eq!(created.status(), StatusCode::ACCEPTED);
        let created_body = axum::body::to_bytes(created.into_body(), 65_536)
            .await
            .unwrap();
        let created_body: serde_json::Value = serde_json::from_slice(&created_body).unwrap();
        let child_id = created_body["data"]["job_id"].as_str().unwrap();
        assert_eq!(created_body["data"]["replayed"], false);

        let replay = app
            .clone()
            .oneshot(request(
                Method::POST,
                "/admin/socks5-health/jobs/retry-parent/retry-failed",
                Some(&admin),
                Some(&key),
                "",
            ))
            .await
            .unwrap();
        assert_eq!(replay.status(), StatusCode::OK);

        let detail = app
            .clone()
            .oneshot(request(
                Method::GET,
                &format!("/admin/socks5-health/jobs/{child_id}"),
                Some(&admin),
                None,
                "",
            ))
            .await
            .unwrap();
        assert_eq!(detail.status(), StatusCode::OK);
        let detail = axum::body::to_bytes(detail.into_body(), 65_536)
            .await
            .unwrap();
        let detail: serde_json::Value = serde_json::from_slice(&detail).unwrap();
        assert_eq!(detail["data"]["snapshot_semantics"], "EXACT_PAIRS");
        assert_eq!(detail["data"]["selectors_reconstruct_snapshot"], false);
        assert_eq!(detail["data"]["matrix_mode"], "CARTESIAN");

        let audit: Vec<String> = sqlx::query_scalar(
            "SELECT detail FROM audit_log WHERE action='JOB_RETRY_FAILED' ORDER BY id",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(
            audit,
            vec![
                "child_job_created=true; replayed=false".to_string(),
                "child_job_created=false; replayed=true".to_string(),
            ]
        );
    }
}
