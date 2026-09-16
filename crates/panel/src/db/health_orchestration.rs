//! Stage 5 durable health-orchestration persistence contract.
//!
//! This module is deliberately free of scheduling, WebSocket and network
//! behavior. It owns the closed enums, canonical selector representation and
//! deterministic hashes shared by both database backends.

#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const HEALTH_JOB_CONTRACT_VERSION: &str = "stage5-health-job-v1";
pub const HEALTH_RETRY_POLICY_VERSION: &str = "v1";
pub const IDEMPOTENCY_TTL_MS: i64 = 7 * 24 * 60 * 60 * 1_000;
pub const SAFE_ERROR_MESSAGE_MAX_CHARS: usize = 256;
pub const PAIR_LEASE_TOMBSTONE_UPDATED_AT_MS: i64 = i64::MAX;

const SAFE_ERROR_MESSAGES: [(&str, &str); 7] = [
    ("PROXY_CONNECT_TIMEOUT", "Proxy connection timed out"),
    ("NETWORK_DNS_FAILED", "DNS resolution failed"),
    ("PROXY_AUTH_FAILED", "Proxy authentication failed"),
    ("UPSTREAM_UNAVAILABLE", "Upstream service unavailable"),
    ("PAIR_LEASE_BUSY", "Relay pair is busy"),
    ("TRANSITION_CONFLICT", "State transition conflicted"),
    ("REQUEST_CANCELLED", "Health check was cancelled"),
];

macro_rules! string_enum {
    ($name:ident { $($variant:ident => $value:literal),+ $(,)? }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(rename_all = "SCREAMING_SNAKE_CASE")]
        pub enum $name { $($variant),+ }

        impl $name {
            pub const fn as_str(self) -> &'static str {
                match self { $(Self::$variant => $value),+ }
            }

            pub fn parse(value: &str) -> Option<Self> {
                match value { $($value => Some(Self::$variant),)+ _ => None }
            }
        }
    };
}

string_enum!(HealthJobSource {
    Manual => "MANUAL",
    Scheduled => "SCHEDULED",
    RetryFailed => "RETRY_FAILED",
    PolicyRunNow => "POLICY_RUN_NOW",
});

string_enum!(HealthJobStatus {
    Queued => "QUEUED",
    Running => "RUNNING",
    CancelRequested => "CANCEL_REQUESTED",
    Succeeded => "SUCCEEDED",
    Failed => "FAILED",
    Partial => "PARTIAL",
    Cancelled => "CANCELLED",
    PartialCancelled => "PARTIAL_CANCELLED",
});

impl HealthJobStatus {
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded
                | Self::Failed
                | Self::Partial
                | Self::Cancelled
                | Self::PartialCancelled
        )
    }
}

string_enum!(HealthJobItemState {
    Queued => "QUEUED",
    Leased => "LEASED",
    Dispatching => "DISPATCHING",
    InFlight => "IN_FLIGHT",
    RetryWait => "RETRY_WAIT",
    Succeeded => "SUCCEEDED",
    Failed => "FAILED",
    Cancelled => "CANCELLED",
});

impl HealthJobItemState {
    pub const fn counter_category(self) -> HealthCounterCategory {
        match self {
            Self::Queued | Self::RetryWait => HealthCounterCategory::Queued,
            Self::Leased | Self::Dispatching | Self::InFlight => HealthCounterCategory::Running,
            Self::Succeeded => HealthCounterCategory::Succeeded,
            Self::Failed => HealthCounterCategory::Failed,
            Self::Cancelled => HealthCounterCategory::Cancelled,
        }
    }

    pub const fn is_terminal(self) -> bool {
        matches!(
            Self::counter_category(self),
            HealthCounterCategory::Succeeded
                | HealthCounterCategory::Failed
                | HealthCounterCategory::Cancelled
        )
    }

    pub const fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Queued, Self::Leased | Self::Cancelled)
                | (
                    Self::Leased,
                    Self::Dispatching | Self::RetryWait | Self::Failed | Self::Cancelled
                )
                | (
                    Self::Dispatching,
                    Self::InFlight | Self::RetryWait | Self::Failed | Self::Cancelled
                )
                | (
                    Self::InFlight,
                    Self::Succeeded | Self::Failed | Self::RetryWait | Self::Cancelled
                )
                | (Self::RetryWait, Self::Leased | Self::Cancelled)
        )
    }
}

string_enum!(HealthMatrixMode { Cartesian => "CARTESIAN" });
string_enum!(HealthTagMatch { Any => "ANY", All => "ALL" });

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthCounterCategory {
    Queued,
    Running,
    Succeeded,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ResourceSelector {
    pub ids: Vec<i64>,
    pub enabled: Option<bool>,
    pub country_codes: Vec<String>,
    pub statuses: Vec<String>,
    pub tags: Vec<String>,
    pub tag_match: HealthTagMatch,
}

impl Default for ResourceSelector {
    fn default() -> Self {
        Self {
            ids: Vec::new(),
            enabled: Some(true),
            country_codes: Vec::new(),
            statuses: Vec::new(),
            tags: Vec::new(),
            tag_match: HealthTagMatch::All,
        }
    }
}

impl ResourceSelector {
    pub fn canonicalized(mut self) -> Self {
        normalize_ids(&mut self.ids);
        normalize_upper(&mut self.country_codes);
        normalize_upper(&mut self.statuses);
        normalize_tags(&mut self.tags);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NodeSelector {
    pub ids: Vec<i64>,
    pub enabled: Option<bool>,
    pub country_codes: Vec<String>,
    pub tags: Vec<String>,
    pub tag_match: HealthTagMatch,
}

impl Default for NodeSelector {
    fn default() -> Self {
        Self {
            ids: Vec::new(),
            enabled: Some(true),
            country_codes: Vec::new(),
            tags: Vec::new(),
            tag_match: HealthTagMatch::All,
        }
    }
}

impl NodeSelector {
    pub fn canonicalized(mut self) -> Self {
        normalize_ids(&mut self.ids);
        normalize_upper(&mut self.country_codes);
        normalize_tags(&mut self.tags);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthJobFingerprintInput {
    pub operation: String,
    pub source: HealthJobSource,
    pub resource_selector: ResourceSelector,
    pub node_selector: NodeSelector,
    pub matrix_mode: HealthMatrixMode,
    pub max_items: i64,
    pub parent_job_id: Option<String>,
    pub policy_id: Option<i64>,
    pub policy_revision: Option<i64>,
}

#[derive(Serialize)]
struct CanonicalFingerprint<'a> {
    contract_version: &'static str,
    operation: String,
    source: &'static str,
    resource_selector: ResourceSelector,
    node_selector: NodeSelector,
    matrix_mode: &'static str,
    max_items: i64,
    retry_policy_version: &'static str,
    parent_job_id: Option<&'a str>,
    policy_id: Option<i64>,
    policy_revision: Option<i64>,
}

pub fn request_fingerprint(input: &HealthJobFingerprintInput) -> String {
    let canonical = CanonicalFingerprint {
        contract_version: HEALTH_JOB_CONTRACT_VERSION,
        operation: input.operation.trim().to_ascii_uppercase(),
        source: input.source.as_str(),
        resource_selector: input.resource_selector.clone().canonicalized(),
        node_selector: input.node_selector.clone().canonicalized(),
        matrix_mode: input.matrix_mode.as_str(),
        max_items: input.max_items,
        retry_policy_version: HEALTH_RETRY_POLICY_VERSION,
        parent_job_id: input.parent_job_id.as_deref(),
        policy_id: input.policy_id,
        policy_revision: input.policy_revision,
    };
    sha256_hex(&canonical_json(&canonical))
}

pub fn snapshot_hash(pairs: &[(i64, i64)]) -> String {
    let mut pairs = pairs.to_vec();
    pairs.sort_unstable();
    pairs.dedup();
    let mut payload = String::new();
    for (resource_id, relay_node_id) in pairs {
        payload.push_str(&resource_id.to_string());
        payload.push(':');
        payload.push_str(&relay_node_id.to_string());
        payload.push('\n');
    }
    sha256_hex(payload.as_bytes())
}

pub fn canonical_selector_json<T: Serialize>(value: &T) -> String {
    String::from_utf8(canonical_json(value)).expect("JSON serialization is valid UTF-8")
}

fn canonical_json<T: Serialize>(value: &T) -> Vec<u8> {
    let value = serde_json::to_value(value).expect("canonical model serializes");
    serde_json::to_vec(&sort_json(value)).expect("canonical JSON serializes")
}

fn sort_json(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(values) => {
            let sorted = values
                .into_iter()
                .map(|(key, value)| (key, sort_json(value)))
                .collect::<BTreeMap<_, _>>();
            serde_json::Value::Object(sorted.into_iter().collect())
        }
        serde_json::Value::Array(values) => {
            serde_json::Value::Array(values.into_iter().map(sort_json).collect())
        }
        other => other,
    }
}

fn sha256_hex(payload: &[u8]) -> String {
    let digest = Sha256::digest(payload);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn normalize_ids(values: &mut Vec<i64>) {
    values.sort_unstable();
    values.dedup();
}

fn normalize_upper(values: &mut Vec<String>) {
    *values = values
        .drain(..)
        .map(|value| value.trim().to_ascii_uppercase())
        .filter(|value| !value.is_empty())
        .collect();
    values.sort();
    values.dedup();
}

fn normalize_tags(values: &mut Vec<String>) {
    *values = values
        .drain(..)
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
        .collect();
    values.sort();
    values.dedup();
}

#[derive(Debug, Clone)]
pub struct NewHealthPolicy {
    pub name: String,
    pub enabled: bool,
    pub resource_selector_json: String,
    pub node_selector_json: String,
    pub interval_seconds: i64,
    pub jitter_seconds: i64,
    pub max_items: i64,
    pub next_run_at_ms: i64,
    pub created_by: Option<i64>,
    pub now_ms: i64,
}

#[derive(Debug, Clone, Default)]
pub struct HealthPolicyPatch {
    pub name: Option<String>,
    pub enabled: Option<bool>,
    pub resource_selector_json: Option<String>,
    pub node_selector_json: Option<String>,
    pub interval_seconds: Option<i64>,
    pub jitter_seconds: Option<i64>,
    pub max_items: Option<i64>,
    pub next_run_at_ms: Option<i64>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct HealthPolicyRecord {
    pub id: i64,
    pub name: String,
    pub enabled: bool,
    pub revision: i64,
    pub resource_selector_json: String,
    pub node_selector_json: String,
    pub matrix_mode: String,
    pub interval_seconds: i64,
    pub jitter_seconds: i64,
    pub max_items: i64,
    pub next_run_at_ms: i64,
    pub last_scheduled_at_ms: Option<i64>,
    pub last_error_code: Option<String>,
    pub last_error_message: Option<String>,
    pub last_error_at_ms: Option<i64>,
    pub skipped_overlap_count: i64,
    pub created_by: Option<i64>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    pub deleted_at_ms: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct NewHealthJob {
    pub id: String,
    pub source: HealthJobSource,
    pub policy_id: Option<i64>,
    pub parent_job_id: Option<String>,
    pub actor_id: Option<i64>,
    pub request_fingerprint: String,
    pub snapshot_hash: String,
    pub resource_selector_json: String,
    pub node_selector_json: String,
    pub scheduled_for_ms: Option<i64>,
    pub created_at_ms: i64,
}

#[derive(Debug, Clone)]
pub struct NewHealthJobItem {
    pub resource_id: i64,
    pub relay_node_id: i64,
    pub not_before_ms: i64,
    pub deadline_at_ms: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct NewHealthJobIdempotency {
    pub actor_id: i64,
    pub idempotency_key: String,
    pub request_fingerprint: String,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HealthJobCreateOutcome {
    Created { job_id: String },
    Replay { job_id: String },
    Conflict,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct HealthJobRecord {
    pub id: String,
    pub source: String,
    pub policy_id: Option<i64>,
    pub parent_job_id: Option<String>,
    pub actor_id: Option<i64>,
    pub status: String,
    pub request_fingerprint: String,
    pub snapshot_hash: String,
    pub resource_selector_json: String,
    pub node_selector_json: String,
    pub matrix_mode: String,
    pub retry_policy_version: String,
    pub scheduled_for_ms: Option<i64>,
    pub cancel_requested: bool,
    pub total_items: i64,
    pub queued_count: i64,
    pub running_count: i64,
    pub succeeded_count: i64,
    pub failed_count: i64,
    pub cancelled_count: i64,
    pub failure_code: Option<String>,
    pub created_at_ms: i64,
    pub started_at_ms: Option<i64>,
    pub finished_at_ms: Option<i64>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct HealthJobItemRecord {
    pub id: i64,
    pub job_id: String,
    pub resource_id: Option<i64>,
    pub relay_node_id: Option<i64>,
    pub resource_id_snapshot: i64,
    pub relay_node_id_snapshot: i64,
    pub state: String,
    pub attempt_count: i64,
    pub item_fence_token: i64,
    pub pair_fence_token: Option<i64>,
    pub dispatch_attempt_id: Option<String>,
    pub request_id: Option<String>,
    pub not_before_ms: i64,
    pub lease_owner: Option<String>,
    pub lease_expires_at_ms: Option<i64>,
    pub first_started_at_ms: Option<i64>,
    pub last_started_at_ms: Option<i64>,
    pub deadline_at_ms: Option<i64>,
    pub health_status: Option<String>,
    pub safe_error_code: Option<String>,
    pub safe_error_message: Option<String>,
    pub completed_after_cancel: bool,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    pub finished_at_ms: Option<i64>,
}

#[derive(Debug, Clone, Default)]
pub struct HealthJobListQuery {
    pub status: Option<String>,
    pub source: Option<String>,
    pub before_created_at_ms: Option<i64>,
    pub before_id: Option<String>,
    pub limit: i64,
}

#[derive(Debug, Clone, Default)]
pub struct HealthJobItemListQuery {
    pub job_id: String,
    pub state: Option<String>,
    pub safe_error_code: Option<String>,
    pub after_id: Option<i64>,
    pub limit: i64,
}

#[derive(Debug, Clone)]
pub struct HealthItemClaimRequest {
    pub lease_owner: String,
    pub now_ms: i64,
    pub lease_expires_at_ms: i64,
    pub limit: i64,
    pub global_limit: i64,
    pub per_node_limit: i64,
    pub per_job_limit: i64,
}

#[derive(Debug, Clone)]
pub struct HealthItemDispatchRequest {
    pub item_id: i64,
    pub lease_owner: String,
    pub expected_item_fence: i64,
    pub expected_pair_fence: i64,
    pub dispatch_attempt_id: String,
    pub now_ms: i64,
}

#[derive(Debug, Clone)]
pub struct HealthLeaseRenewRequest {
    pub item_id: i64,
    pub lease_owner: String,
    pub expected_item_fence: i64,
    pub expected_pair_fence: i64,
    pub lease_expires_at_ms: i64,
    pub now_ms: i64,
}

#[derive(Debug, Clone)]
pub struct HealthItemTransition {
    pub item_id: i64,
    pub expected_state: HealthJobItemState,
    pub expected_fence: i64,
    pub new_state: HealthJobItemState,
    pub lease_owner: Option<String>,
    pub lease_expires_at_ms: Option<i64>,
    pub pair_fence_token: Option<i64>,
    pub dispatch_attempt_id: Option<String>,
    pub request_id: Option<String>,
    pub not_before_ms: Option<i64>,
    pub health_status: Option<String>,
    pub safe_error_code: Option<String>,
    pub safe_error_message: Option<String>,
    pub completed_after_cancel: bool,
    pub now_ms: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConditionalWriteOutcome {
    Applied,
    NotFound,
    ConditionFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HealthJobCounters {
    pub total: i64,
    pub queued: i64,
    pub running: i64,
    pub succeeded: i64,
    pub failed: i64,
    pub cancelled: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HealthJobIdempotencyOutcome {
    Available,
    Replay { job_id: String },
    Conflict,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct HealthPairLeaseRecord {
    pub resource_id: i64,
    pub relay_node_id: i64,
    pub item_id: Option<i64>,
    pub lease_owner: Option<String>,
    pub lease_expires_at_ms: Option<i64>,
    pub pair_fence_token: i64,
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairLeaseAcquireOutcome {
    Acquired { pair_fence_token: i64 },
    Busy,
}

#[derive(Debug, Clone, Copy)]
pub struct PairLeaseAcquireRequest<'a> {
    pub resource_id: i64,
    pub relay_node_id: i64,
    pub item_id: i64,
    pub lease_owner: &'a str,
    pub lease_expires_at_ms: i64,
    pub now_ms: i64,
}

pub fn validate_health_item_transition_fields(transition: &HealthItemTransition) -> bool {
    let has_lease = transition
        .lease_owner
        .as_deref()
        .is_some_and(|value| !value.is_empty())
        && transition
            .lease_expires_at_ms
            .is_some_and(|value| value > transition.now_ms)
        && transition.pair_fence_token.is_some_and(|value| value >= 0);
    let no_lease = transition.lease_owner.is_none()
        && transition.lease_expires_at_ms.is_none()
        && transition.pair_fence_token.is_none();
    let has_dispatch = transition
        .dispatch_attempt_id
        .as_deref()
        .is_some_and(|value| !value.is_empty());
    let has_request = transition
        .request_id
        .as_deref()
        .is_some_and(|value| !value.is_empty());

    let state_fields_valid = match transition.new_state {
        HealthJobItemState::Leased => has_lease && !has_dispatch && !has_request,
        HealthJobItemState::Dispatching => has_lease && has_dispatch && !has_request,
        HealthJobItemState::InFlight => has_lease && has_dispatch && has_request,
        HealthJobItemState::Queued
        | HealthJobItemState::RetryWait
        | HealthJobItemState::Succeeded
        | HealthJobItemState::Failed
        | HealthJobItemState::Cancelled => no_lease && !has_dispatch && !has_request,
    };
    let error_fields_valid = matches!(
        transition.new_state,
        HealthJobItemState::RetryWait | HealthJobItemState::Failed
    ) || (transition.safe_error_code.is_none()
        && transition.safe_error_message.is_none());
    state_fields_valid && error_fields_valid
}

pub fn safe_error_message(
    error_code: Option<&str>,
    requested_message: Option<&str>,
) -> Result<Option<String>, ()> {
    let Some(code) = error_code else {
        return if requested_message.is_none() {
            Ok(None)
        } else {
            Err(())
        };
    };
    let Some((_, canonical)) = SAFE_ERROR_MESSAGES
        .iter()
        .find(|(allowed_code, _)| *allowed_code == code)
    else {
        return Err(());
    };
    match requested_message {
        None => Ok(None),
        Some(message) if message == *canonical => Ok(Some(
            canonical
                .chars()
                .take(SAFE_ERROR_MESSAGE_MAX_CHARS)
                .collect(),
        )),
        Some(_) => Err(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn intent() -> HealthJobFingerprintInput {
        HealthJobFingerprintInput {
            operation: "create".into(),
            source: HealthJobSource::Manual,
            resource_selector: ResourceSelector {
                ids: vec![3, 1, 3],
                country_codes: vec![" us ".into(), "JP".into()],
                tags: vec![" Residential ".into(), "us".into()],
                ..Default::default()
            },
            node_selector: NodeSelector {
                ids: vec![9, 2, 9],
                country_codes: vec!["de".into()],
                ..Default::default()
            },
            matrix_mode: HealthMatrixMode::Cartesian,
            max_items: 10_000,
            parent_job_id: None,
            policy_id: None,
            policy_revision: None,
        }
    }

    #[test]
    fn fingerprint_canonicalization_is_order_independent() {
        let first = intent();
        let mut second = intent();
        second.resource_selector.ids.reverse();
        second.resource_selector.country_codes.reverse();
        second.resource_selector.tags.reverse();
        second.node_selector.ids.reverse();
        assert_eq!(request_fingerprint(&first), request_fingerprint(&second));
        assert_eq!(request_fingerprint(&first).len(), 64);
    }

    #[test]
    fn fingerprint_changes_with_business_intent() {
        let first = intent();
        let mut second = intent();
        second.max_items = 9_999;
        assert_ne!(request_fingerprint(&first), request_fingerprint(&second));
    }

    #[test]
    fn snapshot_hash_is_order_and_duplicate_independent() {
        let first = snapshot_hash(&[(2, 4), (1, 3), (2, 4)]);
        let second = snapshot_hash(&[(1, 3), (2, 4)]);
        assert_eq!(first, second);
        assert_ne!(first, snapshot_hash(&[(1, 3), (2, 5)]));
    }

    #[test]
    fn safe_error_contract_only_accepts_canonical_allowlisted_messages() {
        assert_eq!(
            safe_error_message(
                Some("PROXY_CONNECT_TIMEOUT"),
                Some("Proxy connection timed out")
            ),
            Ok(Some("Proxy connection timed out".into()))
        );
        assert_eq!(safe_error_message(None, None), Ok(None));
        for secret in [
            "socks5://user:password@host:1080",
            "password=hunter2",
            "passwd=secret",
            "Authorization: Bearer abc.def.ghi",
            "Cookie: session=secret",
            "token=secret",
            "混合文本 secret=秘密 🔐",
        ] {
            assert!(safe_error_message(Some("PROXY_CONNECT_TIMEOUT"), Some(secret)).is_err());
        }
        assert!(safe_error_message(Some("UNKNOWN"), None).is_err());
        assert!(safe_error_message(None, Some(&"🙂".repeat(300))).is_err());
        assert!(safe_error_message(
            Some("NETWORK_DNS_FAILED"),
            Some(&"a".repeat(SAFE_ERROR_MESSAGE_MAX_CHARS + 1))
        )
        .is_err());
    }
}
