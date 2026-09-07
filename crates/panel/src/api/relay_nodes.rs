//! Relational Relay Node metadata merged with the existing KVS live metrics.

use crate::api::middleware::AdminOnly;
use crate::api::AppState;
use crate::db::repo::RelayNodeRecord;
use axum::extract::{Path, State};
use axum::Json;
use relay_shared::protocol::ApiResponse;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Serialize)]
pub struct RelayNodePublic {
    pub id: i64,
    pub device_group_id: i64,
    pub node_key: String,
    pub name: String,
    pub country: String,
    pub country_code: String,
    pub region: String,
    pub city: String,
    pub provider: String,
    pub public_ip: String,
    pub bandwidth_mbps: i32,
    pub remark: String,
    pub tags: Vec<String>,
    pub enabled: bool,
    pub first_seen_at: String,
    pub last_seen_at: String,
    pub online: bool,
    pub cpu: Option<f64>,
    pub ram: Option<f64>,
    pub connections: Option<u64>,
    pub node_version: Option<String>,
    pub config_protocol_version: Option<u64>,
    pub socks5_check_queue: Option<u64>,
    pub supports_socks5_check: bool,
}

#[derive(Clone, Default)]
struct LiveMetrics {
    online: bool,
    cpu: Option<f64>,
    ram: Option<f64>,
    connections: Option<u64>,
    node_version: Option<String>,
    config_protocol_version: Option<u64>,
    socks5_check_queue: Option<u64>,
}

#[derive(Deserialize)]
pub struct UpdateRelayNodeRequest {
    pub name: String,
    #[serde(default)]
    pub country: String,
    #[serde(default)]
    pub country_code: String,
    #[serde(default)]
    pub region: String,
    #[serde(default)]
    pub city: String,
    #[serde(default)]
    pub provider: String,
    #[serde(default)]
    pub bandwidth_mbps: i32,
    #[serde(default)]
    pub remark: String,
    #[serde(default)]
    pub tags: Vec<String>,
    pub enabled: bool,
}

#[derive(Deserialize)]
pub struct ReplaceRelayNodeIdentityRequest {
    /// SHA-256 hex fingerprint of the replacement node's local instance key.
    /// The raw key must never be sent to the Panel.
    pub identity_hash: String,
}

fn error<T: Serialize>(code: i32, message: &str) -> ApiResponse<T> {
    ApiResponse {
        code,
        message: message.into(),
        data: None,
    }
}

pub async fn list(
    _admin: AdminOnly,
    State(state): State<AppState>,
) -> Json<ApiResponse<Vec<RelayNodePublic>>> {
    let nodes = match state.db.list_relay_nodes().await {
        Ok(nodes) => nodes,
        Err(db_error) => {
            tracing::error!("list relay nodes: {db_error}");
            return Json(error(500, "数据库错误"));
        }
    };
    let live = load_live_metrics(&state).await;
    let rows = nodes
        .into_iter()
        .map(|node| {
            let metrics = live
                .get(&(node.device_group_id, node.node_key.clone()))
                .cloned()
                .unwrap_or_default();
            let tags = serde_json::from_str(&node.tags).unwrap_or_default();
            RelayNodePublic {
                id: node.id,
                device_group_id: node.device_group_id,
                node_key: node.node_key,
                name: node.name,
                country: node.country,
                country_code: node.country_code,
                region: node.region,
                city: node.city,
                provider: node.provider,
                public_ip: node.public_ip,
                bandwidth_mbps: node.bandwidth_mbps,
                remark: node.remark,
                tags,
                enabled: node.enabled,
                first_seen_at: node.first_seen_at,
                last_seen_at: node.last_seen_at,
                online: metrics.online,
                cpu: metrics.cpu,
                ram: metrics.ram,
                connections: metrics.connections,
                node_version: metrics.node_version,
                config_protocol_version: metrics.config_protocol_version,
                socks5_check_queue: metrics.socks5_check_queue,
                supports_socks5_check: metrics.socks5_check_queue.is_some(),
            }
        })
        .collect();
    Json(ApiResponse::success(rows))
}

pub async fn update(
    admin: AdminOnly,
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(mut request): Json<UpdateRelayNodeRequest>,
) -> Json<ApiResponse<RelayNodeRecord>> {
    request.name = request.name.trim().to_owned();
    request.country_code = request.country_code.trim().to_ascii_uppercase();
    if request.name.is_empty() || request.name.len() > 128 {
        return Json(error(400, "节点名称不能为空且不得超过 128 字符"));
    }
    if !request.country_code.is_empty()
        && (request.country_code.len() != 2
            || !request
                .country_code
                .bytes()
                .all(|b| b.is_ascii_alphabetic()))
    {
        return Json(error(400, "Country Code 必须是两个字母"));
    }
    if request.bandwidth_mbps < 0 {
        return Json(error(400, "Bandwidth 不能为负数"));
    }
    request.tags = normalize_tags(request.tags);
    if request.tags.len() > 32 || request.tags.iter().any(|tag| tag.len() > 64) {
        return Json(error(400, "最多 32 个标签，每个标签不超过 64 字符"));
    }
    let tags = serde_json::to_string(&request.tags).unwrap_or_else(|_| "[]".into());
    let changed = state
        .db
        .update_relay_node(
            id,
            &request.name,
            request.country.trim(),
            &request.country_code,
            request.region.trim(),
            request.city.trim(),
            request.provider.trim(),
            request.bandwidth_mbps,
            request.remark.trim(),
            &tags,
            request.enabled,
        )
        .await;
    match changed {
        Ok(0) => Json(error(404, "Relay Node 不存在")),
        Err(db_error) => {
            tracing::error!("update relay node {id}: {db_error}");
            Json(error(500, "数据库错误"))
        }
        Ok(_) => {
            crate::service::audit::record(
                &state,
                Some(admin.user_id),
                "relay_node_update",
                "relay_node",
                id,
                "metadata updated",
            )
            .await;
            match state.db.find_relay_node(id).await {
                Ok(Some(node)) => Json(ApiResponse::success(node)),
                _ => Json(error(500, "更新后读取节点失败")),
            }
        }
    }
}

pub async fn replace_identity(
    admin: AdminOnly,
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(request): Json<ReplaceRelayNodeIdentityRequest>,
) -> Json<ApiResponse<()>> {
    let identity_hash = request.identity_hash.trim().to_ascii_lowercase();
    if identity_hash.len() != 64 || !identity_hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Json(error(400, "Identity fingerprint 必须是 64 位 SHA-256 hex"));
    }
    let node = match state.db.find_relay_node(id).await {
        Ok(Some(node)) => node,
        Ok(None) => return Json(error(404, "Relay Node 不存在")),
        Err(db_error) => {
            tracing::error!("find relay node before identity replacement {id}: {db_error}");
            return Json(error(500, "数据库错误"));
        }
    };

    // Close both sides of the DB update to cover a reconnect racing the
    // administrative rotation. Old callbacks also fail the fingerprint and
    // WebSocket-session checks.
    state
        .node_connections
        .close_node(node.device_group_id, &node.node_key)
        .await;
    match state
        .db
        .replace_relay_node_identity(id, &identity_hash)
        .await
    {
        Ok(1) => {}
        Ok(_) => return Json(error(404, "Relay Node 不存在")),
        Err(db_error) => {
            tracing::error!("replace relay node identity {id}: {db_error}");
            return Json(error(500, "数据库错误"));
        }
    }
    state
        .node_connections
        .close_node(node.device_group_id, &node.node_key)
        .await;
    crate::service::audit::record(
        &state,
        Some(admin.user_id),
        "relay_node_identity_replace",
        "relay_node",
        id,
        "physical identity fingerprint replaced",
    )
    .await;
    Json(ApiResponse::success(()))
}

async fn load_live_metrics(state: &AppState) -> HashMap<(i64, String), LiveMetrics> {
    let mut result = HashMap::new();
    let rows = match state.db.scan_prefix("node_status:").await {
        Ok(rows) => rows,
        Err(error) => {
            tracing::warn!("relay node KVS metrics unavailable: {error}");
            return result;
        }
    };
    let now = chrono::Utc::now();
    for (key, raw) in rows {
        let Some(rest) = key.strip_prefix("node_status:") else {
            continue;
        };
        let Some((group, node_key)) = rest.split_once(':') else {
            continue;
        };
        let Ok(group_id) = group.parse::<i64>() else {
            continue;
        };
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&raw) else {
            continue;
        };
        let online = value
            .get("last_seen")
            .and_then(|v| v.as_str())
            .and_then(|v| chrono::DateTime::parse_from_rfc3339(v).ok())
            .is_some_and(|seen| {
                now.signed_duration_since(seen.with_timezone(&chrono::Utc))
                    .num_seconds()
                    <= 120
            });
        result.insert(
            (group_id, node_key.to_owned()),
            LiveMetrics {
                online,
                cpu: value.get("cpu").and_then(|v| v.as_f64()),
                ram: value.get("mem").and_then(|v| v.as_f64()),
                connections: value.get("connections").and_then(|v| v.as_u64()),
                node_version: value
                    .get("node_version")
                    .and_then(|v| v.as_str())
                    .map(ToOwned::to_owned),
                config_protocol_version: value
                    .get("config_protocol_version")
                    .and_then(|v| v.as_u64()),
                socks5_check_queue: value
                    .get("socks5_check_queue_depth")
                    .and_then(|v| v.as_u64()),
            },
        );
    }
    result
}

fn normalize_tags(tags: Vec<String>) -> Vec<String> {
    let mut tags = tags
        .into_iter()
        .map(|tag| tag.trim().to_owned())
        .filter(|tag| !tag.is_empty())
        .collect::<Vec<_>>();
    tags.sort();
    tags.dedup();
    tags
}
