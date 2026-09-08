use crate::api::middleware::AdminOnly;
use crate::api::AppState;
use crate::db::repo::{SmartRelayCreateInput, SmartRelayCreateOutcome};
use crate::service::credentials::CredentialCipher;
use crate::service::relay_recommendation::{self, RelayCandidate, RelayRecommendation};
use axum::extract::{Path, Query, State};
use axum::Json;
use relay_shared::protocol::{ApiResponse, CONFIG_PROTOCOL_VERSION};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const RELAY_PASSWORD_PURPOSE: &str = "socks5-relay-password";

#[derive(Debug, Deserialize)]
pub struct RecommendationQuery {
    #[serde(default = "default_limit")]
    limit: usize,
    #[serde(default)]
    include_unavailable: bool,
}

#[derive(Debug, Deserialize)]
pub struct SmartRelayPreviewRequest {
    pub resource_id: i64,
    pub relay_node_id: i64,
    pub port_mode: String,
    pub manual_port: Option<i32>,
}

#[derive(Debug, Serialize)]
pub struct SmartRelayPreviewResponse {
    pub eligible: bool,
    pub warnings: Vec<String>,
    pub candidate: RelayCandidate,
    pub port_mode: String,
    pub manual_port: Option<i32>,
    pub resource_revision: i64,
    pub health_generation: i64,
    pub health_checked_at: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SmartRelayCreateRequest {
    pub resource_id: i64,
    pub relay_node_id: i64,
    pub port_mode: String,
    pub manual_port: Option<i32>,
    pub rule_name: String,
    pub idempotency_key: String,
    pub expected_resource_revision: i64,
    pub expected_health_generation: i64,
    pub expected_health_checked_at: String,
}

#[derive(Debug, Serialize)]
pub struct SmartRelayCreateResponse {
    pub rule_id: i64,
    pub relay_node_id: i64,
    pub resource_id: i64,
    pub host: String,
    pub port: i32,
    pub relay_username: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relay_password: Option<String>,
    pub protocol: &'static str,
    pub exit_ip: String,
    pub exit_country: Option<String>,
    pub selection_mode: String,
    pub deployment_status: &'static str,
    pub replayed: bool,
    pub password_shown_once: bool,
}

fn default_limit() -> usize {
    10
}

fn error<T: Serialize>(code: i32, message: impl Into<String>) -> ApiResponse<T> {
    ApiResponse {
        code,
        message: message.into(),
        data: None,
    }
}

pub async fn recommendations(
    _admin: AdminOnly,
    State(state): State<AppState>,
    Path(resource_id): Path<i64>,
    Query(query): Query<RecommendationQuery>,
) -> Json<ApiResponse<RelayRecommendation>> {
    match relay_recommendation::recommend(state.db.as_ref(), &state.config, resource_id).await {
        Ok(Some(mut recommendation)) => {
            let limit = query.limit.clamp(1, 100);
            if !query.include_unavailable {
                recommendation
                    .candidates
                    .retain(|candidate| candidate.eligible);
            }
            recommendation.candidates.truncate(limit);
            Json(ApiResponse::success(recommendation))
        }
        Ok(None) => Json(error(404, "RESOURCE_NOT_FOUND")),
        Err(db_error) => {
            tracing::error!("relay recommendations for resource {resource_id}: {db_error}");
            Json(error(500, "DATABASE_ERROR"))
        }
    }
}

pub async fn preview(
    _admin: AdminOnly,
    State(state): State<AppState>,
    Json(request): Json<SmartRelayPreviewRequest>,
) -> Json<ApiResponse<SmartRelayPreviewResponse>> {
    let (port_mode, manual_port) = match normalize_port(&request.port_mode, request.manual_port) {
        Ok(value) => value,
        Err(code) => return Json(error(400, code)),
    };
    let recommendation = match relay_recommendation::recommend(
        state.db.as_ref(),
        &state.config,
        request.resource_id,
    )
    .await
    {
        Ok(Some(value)) => value,
        Ok(None) => return Json(error(404, "RESOURCE_NOT_FOUND")),
        Err(db_error) => {
            tracing::error!("smart relay preview: {db_error}");
            return Json(error(500, "DATABASE_ERROR"));
        }
    };
    let Some(mut candidate) = recommendation
        .candidates
        .into_iter()
        .find(|candidate| candidate.relay_node_id == request.relay_node_id)
    else {
        return Json(error(404, "NODE_NOT_FOUND"));
    };
    if let Some(port) = manual_port {
        let in_range = state
            .db
            .group_port_range(candidate.device_group_id)
            .await
            .ok()
            .flatten()
            .map(|range| crate::service::rules::resolve_auto_port_range(&range))
            .is_some_and(|(low, high)| port >= i32::from(low) && port <= i32::from(high));
        let available = state
            .db
            .list_group_port_protocols(candidate.device_group_id)
            .await
            .map(|ports| {
                !ports.into_iter().any(|(used, protocol)| {
                    used == port && matches!(protocol.as_str(), "tcp" | "tcp_udp")
                })
            })
            .unwrap_or(false);
        if !in_range {
            candidate.warnings.push("PORT_OUT_OF_RANGE".into());
            candidate.eligible = false;
        } else if !available {
            candidate.warnings.push("PORT_CONFLICT".into());
            candidate.eligible = false;
        }
    }
    let Some(health_generation) = candidate.health_generation else {
        return Json(error(409, "HEALTH_MISSING"));
    };
    let Some(health_checked_at) = candidate.health_checked_at.clone() else {
        return Json(error(409, "HEALTH_MISSING"));
    };
    Json(ApiResponse::success(SmartRelayPreviewResponse {
        eligible: candidate.eligible,
        warnings: candidate.warnings.clone(),
        candidate,
        port_mode,
        manual_port,
        resource_revision: recommendation.resource_revision,
        health_generation,
        health_checked_at,
    }))
}

pub async fn create(
    admin: AdminOnly,
    State(state): State<AppState>,
    Json(mut request): Json<SmartRelayCreateRequest>,
) -> Json<ApiResponse<SmartRelayCreateResponse>> {
    request.rule_name = request.rule_name.trim().to_owned();
    if request.rule_name.is_empty() || request.rule_name.len() > 128 {
        return Json(error(400, "INVALID_RULE_NAME"));
    }
    if uuid::Uuid::parse_str(request.idempotency_key.trim()).is_err() {
        return Json(error(400, "INVALID_IDEMPOTENCY_KEY"));
    }
    request.idempotency_key = request.idempotency_key.trim().to_ascii_lowercase();
    let (_, requested_port) = match normalize_port(&request.port_mode, request.manual_port) {
        Ok(value) => value,
        Err(code) => return Json(error(400, code)),
    };
    let request_fingerprint = request_fingerprint(&request);
    match state
        .db
        .find_smart_relay_receipt(admin.user_id, &request.idempotency_key)
        .await
    {
        Ok(Some(receipt)) if receipt.request_fingerprint == request_fingerprint => {
            return Json(ApiResponse::success(create_response(
                receipt.created(),
                None,
                true,
            )));
        }
        Ok(Some(_)) => return Json(error(409, "IDEMPOTENCY_KEY_REUSED")),
        Ok(None) => {}
        Err(db_error) => {
            tracing::error!("smart relay idempotency lookup: {db_error}");
            return Json(error(500, "DATABASE_ERROR"));
        }
    }

    let recommendation = match relay_recommendation::recommend(
        state.db.as_ref(),
        &state.config,
        request.resource_id,
    )
    .await
    {
        Ok(Some(value)) => value,
        Ok(None) => return Json(error(404, "RESOURCE_NOT_FOUND")),
        Err(db_error) => {
            tracing::error!("smart relay create prevalidation: {db_error}");
            return Json(error(500, "DATABASE_ERROR"));
        }
    };
    let Some(selected) = recommendation
        .candidates
        .iter()
        .find(|candidate| candidate.relay_node_id == request.relay_node_id)
    else {
        return Json(error(404, "NODE_NOT_FOUND"));
    };
    if !selected.eligible {
        return Json(error(
            409,
            selected
                .warnings
                .first()
                .cloned()
                .unwrap_or_else(|| "RECOMMENDATION_STALE".into()),
        ));
    }
    let selection_mode = if selected.recommended {
        "RECOMMENDED"
    } else {
        "MANUAL"
    };
    let selected_node_country = selected.country_code.clone();
    let selected_health_checked_at = request.expected_health_checked_at.clone();
    let (relay_username, relay_password) = crate::service::password::generate_relay_credentials();
    let cipher = match CredentialCipher::from_config(state.config.socks5_credential_key.as_deref())
    {
        Ok(cipher) => cipher,
        Err(cipher_error) => {
            tracing::error!("smart relay credential cipher unavailable: {cipher_error:?}");
            return Json(error(503, "CREDENTIAL_ENCRYPTION_UNAVAILABLE"));
        }
    };
    let (ciphertext, nonce, key_version) =
        match cipher.encrypt(&relay_password, RELAY_PASSWORD_PURPOSE) {
            Ok(value) => value,
            Err(cipher_error) => {
                tracing::error!("smart relay credential encryption failed: {cipher_error:?}");
                return Json(error(500, "CREDENTIAL_ENCRYPTION_FAILED"));
            }
        };
    let input = SmartRelayCreateInput {
        actor_id: admin.user_id,
        idempotency_key: request.idempotency_key,
        request_fingerprint,
        name: request.rule_name,
        resource_id: request.resource_id,
        relay_node_id: request.relay_node_id,
        requested_port,
        expected_resource_revision: request.expected_resource_revision,
        expected_health_generation: request.expected_health_generation,
        expected_health_checked_at: request.expected_health_checked_at,
        selection_mode: selection_mode.into(),
        relay_username,
        relay_password_ciphertext: ciphertext,
        relay_password_nonce: nonce,
        relay_password_key_version: key_version,
        health_ttl_seconds: state.config.relay_recommend_health_ttl_seconds,
        required_protocol_version: CONFIG_PROTOCOL_VERSION,
        max_cpu_percent: state.config.relay_recommend_max_cpu_percent,
        max_memory_percent: state.config.relay_recommend_max_memory_percent,
    };
    match state.db.create_smart_relay(&input).await {
        Ok(SmartRelayCreateOutcome::Created(created)) => {
            state
                .node_connections
                .broadcast_all(r#"{"type":"config_changed"}"#)
                .await;
            crate::service::audit::record(
                &state,
                Some(admin.user_id),
                "stage4_relay_create",
                "forward_rule",
                created.rule_id,
                &format!(
                    "resource_id={}; relay_node_id={}; listen_port={}; selection_mode={}; detected_country={}; node_country={}; health_checked_at={}",
                    created.resource_id,
                    created.relay_node_id,
                    created.listen_port,
                    created.selection_mode,
                    created.exit_country.as_deref().unwrap_or(""),
                    selected_node_country,
                    selected_health_checked_at
                ),
            )
            .await;
            Json(ApiResponse::success(create_response(
                created,
                Some(relay_password),
                false,
            )))
        }
        Ok(SmartRelayCreateOutcome::Replay(created)) => {
            Json(ApiResponse::success(create_response(created, None, true)))
        }
        Ok(SmartRelayCreateOutcome::Rejected(code)) => Json(error(409, code)),
        Ok(SmartRelayCreateOutcome::QuotaExceeded) => Json(error(409, "RULE_QUOTA_EXCEEDED")),
        Err(db_error) => {
            tracing::error!("smart relay create transaction: {db_error}");
            Json(error(500, "DATABASE_ERROR"))
        }
    }
}

fn create_response(
    created: crate::db::repo::SmartRelayCreatedRecord,
    relay_password: Option<String>,
    replayed: bool,
) -> SmartRelayCreateResponse {
    SmartRelayCreateResponse {
        rule_id: created.rule_id,
        relay_node_id: created.relay_node_id,
        resource_id: created.resource_id,
        host: created.endpoint_host,
        port: created.listen_port,
        relay_username: created.relay_username,
        relay_password,
        protocol: "SOCKS5",
        exit_ip: created.exit_ip,
        exit_country: created.exit_country,
        selection_mode: created.selection_mode,
        deployment_status: "CREATED",
        replayed,
        password_shown_once: !replayed,
    }
}

fn normalize_port(mode: &str, port: Option<i32>) -> Result<(String, Option<i32>), &'static str> {
    match mode.trim().to_ascii_uppercase().as_str() {
        "AUTO" if port.is_none() => Ok(("AUTO".into(), None)),
        "MANUAL" if port.is_some_and(|port| (1..=65535).contains(&port)) => {
            Ok(("MANUAL".into(), port))
        }
        "AUTO" => Err("AUTO_PORT_MUST_BE_EMPTY"),
        "MANUAL" => Err("INVALID_MANUAL_PORT"),
        _ => Err("INVALID_PORT_MODE"),
    }
}

fn request_fingerprint(request: &SmartRelayCreateRequest) -> String {
    let payload = serde_json::to_vec(request).unwrap_or_default();
    format!("{:x}", Sha256::digest(payload))
}
