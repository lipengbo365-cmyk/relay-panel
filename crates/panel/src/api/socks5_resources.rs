//! Scalable resource-list and bulk-mutation endpoints. The legacy unpaged list
//! remains for compatibility; the Stage 3 UI uses this paged projection.

use crate::api::middleware::AdminOnly;
use crate::api::AppState;
use crate::db::repo::Socks5ResourceQuery;
use crate::service::socks5::Socks5ResourcePublic;
use axum::extract::{Query, State};
use axum::Json;
use relay_shared::protocol::ApiResponse;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Deserialize)]
pub struct PageQuery {
    pub page: Option<i64>,
    pub page_size: Option<i64>,
    pub search: Option<String>,
    pub status: Option<String>,
    pub country: Option<String>,
    pub detected_country: Option<String>,
    pub tag: Option<String>,
    pub enabled: Option<bool>,
    pub sort: Option<String>,
    pub order: Option<String>,
}

#[derive(Serialize)]
pub struct PageResponse {
    pub items: Vec<Socks5ResourcePublic>,
    pub total: i64,
    pub page: i64,
    pub page_size: i64,
}

#[derive(Debug, Deserialize)]
pub struct BulkActionRequest {
    pub ids: Vec<i64>,
    pub action: BulkAction,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BulkAction {
    Enable,
    Disable,
    Delete,
    SetTags,
}

#[derive(Debug, Serialize)]
pub struct DeleteBlocker {
    pub resource_id: i64,
    pub rule_id: i64,
    pub reason: String,
}

#[derive(Serialize)]
pub struct BulkActionResponse {
    pub affected: u64,
    pub blockers: Vec<DeleteBlocker>,
}

fn error<T: Serialize>(code: i32, message: &str) -> ApiResponse<T> {
    ApiResponse {
        code,
        message: message.into(),
        data: None,
    }
}

pub async fn list_page(
    _admin: AdminOnly,
    State(state): State<AppState>,
    Query(input): Query<PageQuery>,
) -> Json<ApiResponse<PageResponse>> {
    let page = input.page.unwrap_or(1).max(1);
    let page_size = input.page_size.unwrap_or(50).clamp(1, 500);
    let query = Socks5ResourceQuery {
        search: normalize(input.search),
        status: normalize_upper(input.status),
        country: normalize_upper(input.country),
        detected_country: normalize_upper(input.detected_country),
        tag: normalize(input.tag),
        enabled: input.enabled,
        sort: input.sort.unwrap_or_else(|| "id".into()),
        descending: input
            .order
            .as_deref()
            .is_none_or(|value| !value.eq_ignore_ascii_case("asc")),
        limit: page_size,
        offset: (page - 1).saturating_mul(page_size),
    };
    match state.db.query_socks5_resources(&query).await {
        Ok((rows, total)) => {
            let ids = rows.iter().map(|row| row.id).collect::<Vec<_>>();
            let latest = match state.db.list_latest_socks5_health_for_resources(&ids).await {
                Ok(rows) => rows
                    .into_iter()
                    .map(|row| (row.resource_id, row))
                    .collect::<HashMap<_, _>>(),
                Err(db_error) => {
                    tracing::error!("latest SOCKS5 health projection: {db_error}");
                    return Json(error(500, "数据库错误"));
                }
            };
            let items = rows
                .into_iter()
                .map(|row| {
                    let mut public: Socks5ResourcePublic = row.into();
                    if let Some(health) = latest.get(&public.id) {
                        public.status = health.status.clone();
                        public.last_check_at = Some(health.checked_at.clone());
                        public.last_relay_node_id = Some(health.relay_node_id);
                        public.last_relay_node_name = Some(health.relay_node_name.clone());
                    }
                    public
                })
                .collect();
            Json(ApiResponse::success(PageResponse {
                items,
                total,
                page,
                page_size,
            }))
        }
        Err(db_error) => {
            tracing::error!("paged SOCKS5 resource list: {db_error}");
            Json(error(500, "数据库错误"))
        }
    }
}

pub async fn bulk_action(
    admin: AdminOnly,
    State(state): State<AppState>,
    Json(mut request): Json<BulkActionRequest>,
) -> Json<ApiResponse<BulkActionResponse>> {
    request.ids.retain(|id| *id > 0);
    request.ids.sort_unstable();
    request.ids.dedup();
    if request.ids.is_empty() || request.ids.len() > 10_000 {
        return Json(error(400, "ids must contain 1..10000 unique IDs"));
    }

    let result = match request.action {
        BulkAction::Enable => state
            .db
            .bulk_set_socks5_resources_enabled(&request.ids, true)
            .await
            .map(|affected| (affected, Vec::new())),
        BulkAction::Disable => state
            .db
            .bulk_set_socks5_resources_enabled(&request.ids, false)
            .await
            .map(|affected| (affected, Vec::new())),
        BulkAction::SetTags => {
            let tags = match normalize_tags(request.tags) {
                Ok(tags) => tags,
                Err(message) => return Json(error(400, message)),
            };
            let json = serde_json::to_string(&tags).unwrap_or_else(|_| "[]".into());
            state
                .db
                .bulk_set_socks5_resource_tags(&request.ids, &json)
                .await
                .map(|affected| (affected, Vec::new()))
        }
        BulkAction::Delete => {
            state
                .db
                .bulk_delete_socks5_resources_guarded(&request.ids)
                .await
        }
    };
    let (affected, raw_blockers) = match result {
        Ok(value) => value,
        Err(db_error) => {
            tracing::error!("SOCKS5 resource bulk action: {db_error}");
            return Json(error(500, "数据库错误"));
        }
    };
    if matches!(request.action, BulkAction::Enable | BulkAction::Disable) && affected > 0 {
        state
            .node_connections
            .broadcast_all(r#"{"type":"config_changed"}"#)
            .await;
    }
    let blockers = raw_blockers
        .into_iter()
        .map(|(resource_id, rule_id)| DeleteBlocker {
            resource_id,
            rule_id,
            reason: "资源正被转发规则引用".into(),
        })
        .collect::<Vec<_>>();
    let action_name = format!("{:?}", request.action);
    crate::service::audit::record(
        &state,
        Some(admin.user_id),
        "socks5_resource_bulk_action",
        "socks5_resource",
        "bulk",
        &format!(
            "action={action_name}; requested={}; affected={}; blocked={}",
            request.ids.len(),
            affected,
            blockers.len()
        ),
    )
    .await;
    Json(ApiResponse::success(BulkActionResponse {
        affected,
        blockers,
    }))
}

fn normalize(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let value = value.trim().to_owned();
        (!value.is_empty()).then_some(value)
    })
}

fn normalize_upper(value: Option<String>) -> Option<String> {
    normalize(value).map(|value| value.to_ascii_uppercase())
}

fn normalize_tags(tags: Vec<String>) -> Result<Vec<String>, &'static str> {
    let mut result = tags
        .into_iter()
        .map(|tag| tag.trim().to_owned())
        .filter(|tag| !tag.is_empty())
        .collect::<Vec<_>>();
    result.sort();
    result.dedup();
    if result.len() > 32 || result.iter().any(|tag| tag.len() > 64) {
        return Err("最多 32 个标签，每个标签不超过 64 字符");
    }
    Ok(result)
}
