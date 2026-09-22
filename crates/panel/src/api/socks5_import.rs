//! Two-step bulk import. Preview and confirm both parse server-side; neither
//! response contains a parsed credential or echoes the submitted source text.

use crate::api::middleware::AdminOnly;
use crate::api::AppState;
use crate::db::repo::{BulkImportOutcome, BulkSocks5Resource};
use crate::service::credentials::CredentialCipher;
use crate::service::socks5_import::{parse_import, ImportLineError, ParsedImportLine};
use axum::extract::State;
use axum::Json;
use relay_shared::protocol::ApiResponse;
use serde::{Deserialize, Serialize};

const MAX_IMPORT_LINES: usize = 10_000;
const IMPORT_CHUNK_SIZE: usize = 500;
const RESOURCE_PASSWORD_PURPOSE: &str = "socks5-resource-password";

#[derive(Deserialize)]
pub struct ImportPreviewRequest {
    pub text: String,
}

#[derive(Serialize)]
pub struct ImportPreviewResponse {
    pub total: usize,
    pub valid: usize,
    pub invalid: usize,
    pub duplicate: usize,
    pub new: usize,
    pub invalid_lines: Vec<ImportLineError>,
}

#[derive(Deserialize)]
pub struct ImportConfirmRequest {
    pub text: String,
    pub strategy: ImportStrategy,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ImportStrategy {
    SkipDuplicate,
    UpdateCredential,
}

#[derive(Serialize)]
pub struct ImportConfirmResponse {
    pub created: usize,
    pub updated: usize,
    pub skipped: usize,
    pub failed: usize,
    pub failures: Vec<ImportLineError>,
}

struct EncryptedImportRow {
    line_number: usize,
    raw_masked: String,
    record: BulkSocks5Resource,
}

fn error<T: Serialize>(code: i32, message: &str) -> ApiResponse<T> {
    ApiResponse {
        code,
        message: message.into(),
        data: None,
    }
}

pub async fn preview(
    _admin: AdminOnly,
    State(state): State<AppState>,
    Json(request): Json<ImportPreviewRequest>,
) -> Json<ApiResponse<ImportPreviewResponse>> {
    let parsed = parse_import(&request.text, MAX_IMPORT_LINES);
    let keys = parsed
        .valid
        .iter()
        .map(|row| (row.host.clone(), row.port, row.username.clone()))
        .collect::<Vec<_>>();
    let existing = match state.db.find_socks5_resources_by_keys(&keys).await {
        Ok(rows) => rows.len(),
        Err(db_error) => {
            tracing::error!("SOCKS5 import preview dedupe lookup: {db_error}");
            return Json(error(500, "数据库错误"));
        }
    };
    let input_duplicates = parsed.duplicates.len();
    let unique_valid = parsed.valid.len();
    Json(ApiResponse::success(ImportPreviewResponse {
        total: parsed.total,
        valid: unique_valid + input_duplicates,
        invalid: parsed.invalid.len(),
        duplicate: existing + input_duplicates,
        new: unique_valid.saturating_sub(existing),
        invalid_lines: parsed.invalid,
    }))
}

pub async fn confirm(
    admin: AdminOnly,
    State(state): State<AppState>,
    Json(request): Json<ImportConfirmRequest>,
) -> Json<ApiResponse<ImportConfirmResponse>> {
    let parsed = parse_import(&request.text, MAX_IMPORT_LINES);
    if parsed.total > MAX_IMPORT_LINES {
        return Json(error(400, "单次导入最多允许 10000 条非空记录"));
    }
    let update_credentials = matches!(request.strategy, ImportStrategy::UpdateCredential);
    let has_password = parsed.valid.iter().any(|row| row.password.is_some());
    let cipher = if has_password {
        match CredentialCipher::from_config(state.config.socks5_credential_key.as_deref()) {
            Ok(cipher) => Some(cipher),
            Err(error_value) => {
                tracing::error!("SOCKS5 import credential cipher unavailable: {error_value:?}");
                return Json(error(503, "SOCKS5 凭据加密密钥未配置或无效"));
            }
        }
    } else {
        None
    };

    let mut encrypted = Vec::with_capacity(parsed.valid.len());
    let mut failures = parsed.invalid;
    for row in parsed.valid {
        let line_number = row.line_number;
        let raw_masked = format!("{}:{}", row.host, row.port);
        match encrypt_row(row, cipher.as_ref()) {
            Ok(record) => encrypted.push(EncryptedImportRow {
                line_number,
                raw_masked,
                record,
            }),
            Err(failure) => failures.push(failure),
        }
    }

    let mut outcome = BulkImportOutcome::default();
    for chunk in encrypted.chunks(IMPORT_CHUNK_SIZE) {
        let records = chunk
            .iter()
            .map(|row| row.record.clone())
            .collect::<Vec<_>>();
        match state
            .db
            .bulk_import_socks5_resources(&records, update_credentials)
            .await
        {
            Ok(part) => {
                outcome.created += part.created;
                outcome.updated += part.updated;
                outcome.skipped += part.skipped;
            }
            Err(db_error) => {
                tracing::error!("SOCKS5 bulk import chunk failed: {db_error}");
                failures.extend(chunk.iter().map(|row| ImportLineError {
                    line_number: row.line_number,
                    error_code: "DATABASE_TRANSACTION_FAILED",
                    raw_masked: row.raw_masked.clone(),
                    error_reason: "数据库事务失败，当前批次已回滚".into(),
                }));
            }
        }
    }
    outcome.skipped += parsed.duplicates.len();

    crate::service::audit::record(
        &state,
        Some(admin.user_id),
        "socks5_resource_bulk_import",
        "socks5_resource",
        "bulk",
        &format!(
            "strategy={:?}; created={}; updated={}; skipped={}; failed={}",
            request.strategy,
            outcome.created,
            outcome.updated,
            outcome.skipped,
            failures.len()
        ),
    )
    .await;

    Json(ApiResponse::success(ImportConfirmResponse {
        created: outcome.created,
        updated: outcome.updated,
        skipped: outcome.skipped,
        failed: failures.len(),
        failures,
    }))
}

fn encrypt_row(
    row: ParsedImportLine,
    cipher: Option<&CredentialCipher>,
) -> Result<BulkSocks5Resource, ImportLineError> {
    let encrypted = match row.password.as_deref() {
        Some(password) => cipher
            .ok_or(())
            .and_then(|cipher| {
                cipher
                    .encrypt(password, RESOURCE_PASSWORD_PURPOSE)
                    .map_err(|_| ())
            })
            .map(Some),
        None => Ok(None),
    };
    match encrypted {
        Ok(value) => {
            let (password_ciphertext, password_nonce, password_key_version) = value
                .map(|(ciphertext, nonce, version)| (Some(ciphertext), Some(nonce), version))
                .unwrap_or((None, None, 1));
            Ok(BulkSocks5Resource {
                name: row.generated_name(),
                host: row.host,
                port: row.port,
                username: row.username,
                password_ciphertext,
                password_nonce,
                password_key_version,
            })
        }
        Err(()) => Err(ImportLineError {
            line_number: row.line_number,
            error_code: "CREDENTIAL_ENCRYPTION_FAILED",
            raw_masked: format!("{}:{}", row.host, row.port),
            error_reason: "凭据加密失败".into(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::diagnose::DiagnoseRegistry;
    use crate::api::socks5_health::Socks5CheckRegistry;
    use crate::api::system::ReleaseCache;
    use crate::api::ws::NodeConnections;
    use crate::config::Config;
    use crate::db::schema::SCHEMA_SQL;
    use crate::db::sqlite_repo::SqliteRepository;
    use sqlx::sqlite::SqlitePoolOptions;
    use std::collections::HashSet;
    use std::sync::Arc;

    #[derive(Debug, PartialEq, Eq)]
    struct PreviewPersistenceSnapshot {
        resources: i64,
        bindings: i64,
        health: i64,
        history: i64,
        rules: i64,
        receipts: i64,
        idempotency_keys: i64,
    }

    async fn persistence_snapshot(pool: &sqlx::SqlitePool) -> PreviewPersistenceSnapshot {
        PreviewPersistenceSnapshot {
            resources: sqlx::query_scalar("SELECT COUNT(*) FROM socks5_resources")
                .fetch_one(pool)
                .await
                .unwrap(),
            bindings: sqlx::query_scalar("SELECT COUNT(*) FROM socks5_rule_bindings")
                .fetch_one(pool)
                .await
                .unwrap(),
            health: sqlx::query_scalar("SELECT COUNT(*) FROM socks5_resource_health")
                .fetch_one(pool)
                .await
                .unwrap(),
            history: sqlx::query_scalar("SELECT COUNT(*) FROM socks5_check_history")
                .fetch_one(pool)
                .await
                .unwrap(),
            rules: sqlx::query_scalar("SELECT COUNT(*) FROM forward_rules")
                .fetch_one(pool)
                .await
                .unwrap(),
            receipts: sqlx::query_scalar("SELECT COUNT(*) FROM relay_creation_receipts")
                .fetch_one(pool)
                .await
                .unwrap(),
            idempotency_keys: sqlx::query_scalar(
                "SELECT COUNT(*) FROM relay_creation_idempotency_keys",
            )
            .fetch_one(pool)
            .await
            .unwrap(),
        }
    }

    async fn state() -> (AppState, sqlx::SqlitePool) {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query(SCHEMA_SQL).execute(&pool).await.unwrap();
        let state = AppState {
            db: Arc::new(SqliteRepository::new(pool.clone())),
            config: Config {
                database_path: "sqlite::memory:".into(),
                listen: "127.0.0.1:0".into(),
                key: "test-key".into(),
                jwt_secret: "test-secret".into(),
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
            diagnose: DiagnoseRegistry::new(),
            socks5_checks: Socks5CheckRegistry::new(),
            geoip_in_flight: Arc::new(tokio::sync::Mutex::new(HashSet::new())),
        };
        (state, pool)
    }

    #[tokio::test]
    async fn preview_sizes_are_read_only() {
        let (state, pool) = state().await;
        let before = persistence_snapshot(&pool).await;
        for size in [1, 5, 100] {
            let text = (0..size)
                .map(|index| format!("preview-{size}-{index}.example:1080"))
                .collect::<Vec<_>>()
                .join("\n");
            let Json(response) = preview(
                AdminOnly { user_id: 1 },
                State(state.clone()),
                Json(ImportPreviewRequest { text }),
            )
            .await;
            let data = response.data.unwrap();
            assert_eq!((data.total, data.valid, data.new), (size, size, size));
            assert_eq!((data.invalid, data.duplicate), (0, 0));
        }
        assert_eq!(
            persistence_snapshot(&pool).await,
            before,
            "preview must not change persistent business state"
        );
    }

    #[tokio::test]
    async fn preview_reports_input_and_database_duplicates_without_leaking_credentials() {
        let (state, pool) = state().await;
        sqlx::query("INSERT INTO socks5_resources(name,host,port) VALUES('existing','existing.example',1080)")
            .execute(&pool)
            .await
            .unwrap();
        let secret = "never-return-this:密 码";
        let text = format!(
            "existing.example:1080\nexisting.example:1080\nno-auth.example:1081\nauth.example:1082:user:{secret}\nbad host:1080:user:{secret}\nbad-port.example:70000"
        );
        let before = persistence_snapshot(&pool).await;
        let Json(response) = preview(
            AdminOnly { user_id: 1 },
            State(state.clone()),
            Json(ImportPreviewRequest { text: text.clone() }),
        )
        .await;
        assert_eq!(response.code, 0);
        let serialized = serde_json::to_string(&response).unwrap();
        assert!(!serialized.contains(secret));
        assert!(!serialized.contains("never-return-this"));
        let data = response.data.unwrap();
        assert_eq!(data.total, 6);
        assert_eq!(data.valid, 4);
        assert_eq!(data.invalid, 2);
        assert_eq!(data.duplicate, 2);
        assert_eq!(data.new, 2);
        assert!(data
            .invalid_lines
            .iter()
            .all(|line| line.raw_masked == "***"));
        assert_eq!(
            persistence_snapshot(&pool).await,
            before,
            "preview must not change persistent business state"
        );

        let Json(confirm_response) = confirm(
            AdminOnly { user_id: 1 },
            State(state),
            Json(ImportConfirmRequest {
                text,
                strategy: ImportStrategy::SkipDuplicate,
            }),
        )
        .await;
        assert_eq!(confirm_response.code, 0);
        let serialized = serde_json::to_string(&confirm_response).unwrap();
        assert!(!serialized.contains(secret));
        assert!(!serialized.contains("never-return-this"));
        assert!(!serialized.contains("user:"));
        let data = confirm_response.data.unwrap();
        assert_eq!((data.created, data.updated), (2, 0));
        assert_eq!((data.skipped, data.failed), (2, 2));
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM socks5_resources")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(
            count, 3,
            "confirm must import exactly the previewed new rows"
        );
    }
}
