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
