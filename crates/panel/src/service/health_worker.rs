//! Stage 5.2 durable manual SOCKS5 health worker.

use crate::api::socks5_health::{
    decrypt_password, node_supports_socks5_check, secure_control_channel_allowed,
    DurablePendingContext,
};
use crate::api::AppState;
use crate::db::health_orchestration::{
    ConditionalWriteOutcome, HealthItemClaimRequest, HealthItemDispatchRequest,
    HealthItemTransition, HealthJobItemRecord, HealthJobItemState, HealthJobStatus,
    HealthLeaseRenewRequest,
};
use relay_shared::protocol::{SecretString, Socks5CheckRequest, Socks5CheckResult};
use std::time::Duration;

const ITEM_LEASE_MS: i64 = 60_000;
const LEASE_RENEW_MS: i64 = 15_000;
const RESULT_TIMEOUT_MS: i64 = 35_000;
const MAX_ATTEMPTS: i64 = 3;
const MAX_RETRY_AGE_MS: i64 = 15 * 60 * 1_000;

#[derive(Debug, Clone)]
pub struct HealthWorkerConfig {
    pub global_limit: i64,
    pub per_node_limit: i64,
    pub per_job_limit: i64,
    pub node_queue_soft_limit: i64,
    pub claim_batch: i64,
}

impl HealthWorkerConfig {
    pub fn load() -> Result<Self, String> {
        let config = Self {
            global_limit: parse_env("HEALTH_WORKER_GLOBAL_LIMIT", 50)?,
            per_node_limit: parse_env("HEALTH_WORKER_PER_NODE_LIMIT", 10)?,
            per_job_limit: parse_env("HEALTH_WORKER_PER_JOB_LIMIT", 20)?,
            node_queue_soft_limit: parse_env("HEALTH_WORKER_NODE_QUEUE_SOFT_LIMIT", 160)?,
            claim_batch: parse_env("HEALTH_WORKER_CLAIM_BATCH", 32)?,
        };
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), String> {
        if !(1..=50).contains(&self.global_limit) {
            return Err("HEALTH_WORKER_GLOBAL_LIMIT must be within 1..=50".into());
        }
        if !(1..=10).contains(&self.per_node_limit) || self.per_node_limit > self.global_limit {
            return Err(
                "HEALTH_WORKER_PER_NODE_LIMIT must be within 1..=10 and <= global limit".into(),
            );
        }
        if !(1..=20).contains(&self.per_job_limit) || self.per_job_limit > self.global_limit {
            return Err(
                "HEALTH_WORKER_PER_JOB_LIMIT must be within 1..=20 and <= global limit".into(),
            );
        }
        if !(1..=160).contains(&self.node_queue_soft_limit) {
            return Err("HEALTH_WORKER_NODE_QUEUE_SOFT_LIMIT must be within 1..=160".into());
        }
        if !(1..=32).contains(&self.claim_batch) {
            return Err("HEALTH_WORKER_CLAIM_BATCH must be within 1..=32".into());
        }
        Ok(())
    }
}

fn parse_env(name: &str, default: i64) -> Result<i64, String> {
    match std::env::var(name) {
        Ok(raw) => raw
            .parse::<i64>()
            .map_err(|_| format!("{name} must be an integer")),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(std::env::VarError::NotUnicode(_)) => Err(format!("{name} must be valid UTF-8")),
    }
}

pub fn spawn(state: AppState, config: HealthWorkerConfig) {
    let owner = format!("panel:{}", uuid::Uuid::new_v4());
    let sqlite = !crate::db::init::is_postgres_url(&state.config.database_path);
    let effective_global = if sqlite {
        config.global_limit.min(16)
    } else {
        config.global_limit
    };
    let effective_batch = if sqlite {
        config.claim_batch.min(8)
    } else {
        config.claim_batch.min(32)
    };
    if sqlite && (effective_global != config.global_limit || effective_batch != config.claim_batch)
    {
        tracing::warn!(
            configured_global = config.global_limit,
            effective_global,
            configured_claim_batch = config.claim_batch,
            effective_claim_batch = effective_batch,
            "SQLite durable health worker safety caps are active"
        );
    }
    let runtime = Runtime {
        state,
        owner,
        config,
        effective_global,
        effective_batch,
    };
    tokio::spawn(runtime.clone().worker_loop());
    tokio::spawn(runtime.recovery_loop());
}

#[derive(Clone)]
struct Runtime {
    state: AppState,
    owner: String,
    config: HealthWorkerConfig,
    effective_global: i64,
    effective_batch: i64,
}

impl Runtime {
    async fn worker_loop(self) {
        let mut interval = tokio::time::interval(Duration::from_millis(250));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            let now = now_ms();
            let request = HealthItemClaimRequest {
                lease_owner: self.owner.clone(),
                now_ms: now,
                lease_expires_at_ms: now + ITEM_LEASE_MS,
                limit: self.effective_batch,
                global_limit: self.effective_global,
                per_node_limit: self.config.per_node_limit,
                per_job_limit: self.config.per_job_limit,
            };
            match self.state.db.claim_health_job_items(&request).await {
                Ok(items) => {
                    for item in items {
                        let runtime = self.clone();
                        tokio::spawn(async move { runtime.execute(item).await });
                    }
                }
                Err(error) => tracing::warn!("durable health claim failed: {error}"),
            }
        }
    }

    async fn recovery_loop(self) {
        self.reconcile().await;
        let mut reaper = tokio::time::interval(Duration::from_secs(5));
        reaper.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut reconciliation = tokio::time::interval(Duration::from_secs(60));
        reconciliation.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = reaper.tick() => self.reap().await,
                _ = reconciliation.tick() => self.reconcile().await,
            }
        }
    }

    async fn execute(&self, leased: HealthJobItemRecord) {
        let Some(pair_fence) = leased.pair_fence_token else {
            return;
        };
        let job = match self.state.db.find_health_job(&leased.job_id).await {
            Ok(Some(job)) => job,
            _ => {
                self.release_pair(&leased, pair_fence).await;
                return;
            }
        };
        if job.cancel_requested {
            self.cancel_owned(&leased, pair_fence).await;
            return;
        }
        let resource = match self
            .state
            .db
            .find_socks5_resource(leased.resource_id_snapshot)
            .await
        {
            Ok(Some(resource)) if resource.enabled => resource,
            _ => {
                self.fail_owned(&leased, pair_fence, "UPSTREAM_UNAVAILABLE")
                    .await;
                return;
            }
        };
        let relay = match self
            .state
            .db
            .find_relay_node(leased.relay_node_id_snapshot)
            .await
        {
            Ok(Some(relay)) if relay.enabled => relay,
            _ => {
                self.fail_owned(&leased, pair_fence, "UPSTREAM_UNAVAILABLE")
                    .await;
                return;
            }
        };
        if !secure_control_channel_allowed(&self.state.config.public_panel_url) {
            self.fail_owned(&leased, pair_fence, "UPSTREAM_UNAVAILABLE")
                .await;
            return;
        }
        if !self
            .state
            .node_connections
            .online_node_ids(relay.device_group_id)
            .await
            .contains(&relay.node_key)
        {
            self.retry_owned(&leased, pair_fence, "UPSTREAM_UNAVAILABLE")
                .await;
            return;
        }
        if !node_supports_socks5_check(&self.state, relay.device_group_id, &relay.node_key).await {
            self.fail_owned(&leased, pair_fence, "UPSTREAM_UNAVAILABLE")
                .await;
            return;
        }
        if node_queue_depth(&self.state, relay.device_group_id, &relay.node_key)
            .await
            .is_some_and(|depth| depth >= self.config.node_queue_soft_limit)
        {
            self.retry_owned(&leased, pair_fence, "UPSTREAM_UNAVAILABLE")
                .await;
            return;
        }
        let Some(session_id) = self
            .state
            .node_connections
            .node_session(relay.device_group_id, &relay.node_key)
            .await
        else {
            self.retry_owned(&leased, pair_fence, "UPSTREAM_UNAVAILABLE")
                .await;
            return;
        };
        let password = match decrypt_password(&self.state, &resource) {
            Ok(value) => value.map(SecretString::new),
            Err(()) => {
                self.fail_owned(&leased, pair_fence, "PROXY_AUTH_FAILED")
                    .await;
                return;
            }
        };
        let dispatch_attempt_id = uuid::Uuid::new_v4().to_string();
        let dispatching = match self
            .state
            .db
            .begin_health_item_dispatch(&HealthItemDispatchRequest {
                item_id: leased.id,
                lease_owner: self.owner.clone(),
                expected_item_fence: leased.item_fence_token,
                expected_pair_fence: pair_fence,
                dispatch_attempt_id: dispatch_attempt_id.clone(),
                now_ms: now_ms(),
            })
            .await
        {
            Ok(Some(item)) => item,
            _ => {
                self.cancel_or_release(&leased, pair_fence).await;
                return;
            }
        };
        if self
            .state
            .db
            .find_health_job(&dispatching.job_id)
            .await
            .ok()
            .flatten()
            .is_none_or(|job| job.cancel_requested)
        {
            self.cancel_owned(&dispatching, pair_fence).await;
            return;
        }

        // Generation advances only after pair ownership, runtime revalidation,
        // credential availability and an actual dispatch attempt are established.
        let (resource, generation) = match self
            .state
            .db
            .begin_socks5_health_check_if_resource_generation(
                resource.id,
                relay.id,
                resource.health_generation,
            )
            .await
        {
            Ok(Some(value)) => value,
            _ => {
                self.retry_owned(&dispatching, pair_fence, "UPSTREAM_UNAVAILABLE")
                    .await;
                return;
            }
        };
        let resource_generation = resource.health_generation;
        let renew_now = now_ms();
        let renewed_until = renew_now + ITEM_LEASE_MS;
        if !matches!(
            self.state
                .db
                .renew_health_item_and_pair_lease(&HealthLeaseRenewRequest {
                    item_id: dispatching.id,
                    lease_owner: self.owner.clone(),
                    expected_item_fence: dispatching.item_fence_token,
                    expected_pair_fence: pair_fence,
                    lease_expires_at_ms: renewed_until,
                    now_ms: renew_now,
                })
                .await,
            Ok(ConditionalWriteOutcome::Applied)
        ) {
            return;
        }
        let expected_in_flight_fence = dispatching.item_fence_token + 1;
        let (request_id, challenge, receiver) = self
            .state
            .socks5_checks
            .start_durable(
                resource.id,
                relay.id,
                &relay.node_key,
                &session_id,
                resource_generation,
                generation,
                DurablePendingContext {
                    job_id: dispatching.job_id.clone(),
                    item_id: dispatching.id,
                    dispatch_attempt_id: dispatch_attempt_id.clone(),
                    item_fence_token: expected_in_flight_fence,
                    pair_fence_token: pair_fence,
                    lease_owner: self.owner.clone(),
                },
            )
            .await;
        let command = Socks5CheckRequest {
            msg_type: "socks5_check".into(),
            request_id: request_id.clone(),
            challenge,
            session_id: session_id.clone(),
            resource_generation,
            generation,
            resource_id: resource.id,
            relay_node_id: relay.id,
            node_id: relay.node_key.clone(),
            host: resource.host,
            port: resource.port as u16,
            username: resource.username,
            password,
            check_urls: self.state.config.socks5_check_urls.clone(),
            relay_public_ip: (!relay.public_ip.is_empty()).then_some(relay.public_ip),
        };
        let payload = match serde_json::to_string(&command) {
            Ok(payload) => payload,
            Err(_) => {
                self.state.socks5_checks.remove(&request_id).await;
                self.retry_owned(&dispatching, pair_fence, "UPSTREAM_UNAVAILABLE")
                    .await;
                return;
            }
        };
        let in_flight = HealthItemTransition {
            item_id: dispatching.id,
            expected_state: HealthJobItemState::Dispatching,
            expected_fence: dispatching.item_fence_token,
            new_state: HealthJobItemState::InFlight,
            lease_owner: Some(self.owner.clone()),
            lease_expires_at_ms: Some(renewed_until),
            pair_fence_token: Some(pair_fence),
            dispatch_attempt_id: Some(dispatch_attempt_id),
            request_id: Some(request_id.clone()),
            not_before_ms: None,
            health_status: None,
            safe_error_code: None,
            safe_error_message: None,
            completed_after_cancel: false,
            now_ms: now_ms(),
        };
        if !matches!(
            self.state.db.transition_health_job_item(&in_flight).await,
            Ok(ConditionalWriteOutcome::Applied)
        ) {
            self.state.socks5_checks.remove(&request_id).await;
            self.retry_owned(&dispatching, pair_fence, "TRANSITION_CONFLICT")
                .await;
            return;
        }
        let Some(current) = self
            .state
            .db
            .find_health_job_item(dispatching.id)
            .await
            .ok()
            .flatten()
        else {
            return;
        };
        if self
            .state
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
            self.state.socks5_checks.remove(&request_id).await;
            self.retry_owned(&current, pair_fence, "UPSTREAM_UNAVAILABLE")
                .await;
            return;
        }
        self.await_result(current, pair_fence, receiver).await;
    }

    async fn await_result(
        &self,
        mut item: HealthJobItemRecord,
        pair_fence: i64,
        receiver: tokio::sync::oneshot::Receiver<Socks5CheckResult>,
    ) {
        let request_id = item.request_id.clone().unwrap_or_default();
        let deadline =
            tokio::time::Instant::now() + Duration::from_millis(RESULT_TIMEOUT_MS as u64);
        tokio::pin!(receiver);
        let result = loop {
            tokio::select! {
                value = &mut receiver => break value.ok(),
                _ = tokio::time::sleep_until(deadline) => break None,
                _ = tokio::time::sleep(Duration::from_millis(LEASE_RENEW_MS as u64)) => {
                    let now = now_ms();
                    let renewed = self.state.db.renew_health_item_and_pair_lease(&HealthLeaseRenewRequest {
                        item_id: item.id,
                        lease_owner: self.owner.clone(),
                        expected_item_fence: item.item_fence_token,
                        expected_pair_fence: pair_fence,
                        lease_expires_at_ms: now + ITEM_LEASE_MS,
                        now_ms: now,
                    }).await;
                    if !matches!(renewed, Ok(ConditionalWriteOutcome::Applied)) {
                        self.state.socks5_checks.remove(&request_id).await;
                        return;
                    }
                    item.lease_expires_at_ms = Some(now + ITEM_LEASE_MS);
                }
            }
        };
        let Some(result) = result else {
            self.state.socks5_checks.remove(&request_id).await;
            self.retry_owned(&item, pair_fence, "PROXY_CONNECT_TIMEOUT")
                .await;
            return;
        };
        let renew_now = now_ms();
        let renewed_until = renew_now + ITEM_LEASE_MS;
        if !matches!(
            self.state
                .db
                .renew_health_item_and_pair_lease(&HealthLeaseRenewRequest {
                    item_id: item.id,
                    lease_owner: self.owner.clone(),
                    expected_item_fence: item.item_fence_token,
                    expected_pair_fence: pair_fence,
                    lease_expires_at_ms: renewed_until,
                    now_ms: renew_now,
                })
                .await,
            Ok(ConditionalWriteOutcome::Applied)
        ) {
            return;
        }
        item.lease_expires_at_ms = Some(renewed_until);
        if matches!(
            result.error_code.as_deref(),
            Some("NODE_BUSY" | "PERSIST_FAILED" | "RESULT_SUPERSEDED")
        ) {
            self.retry_owned(&item, pair_fence, "UPSTREAM_UNAVAILABLE")
                .await;
            return;
        }
        if result.error_code.as_deref() == Some("NODE_DISABLED") {
            self.fail_owned(&item, pair_fence, "UPSTREAM_UNAVAILABLE")
                .await;
            return;
        }
        let completed_after_cancel = self
            .state
            .db
            .find_health_job(&item.job_id)
            .await
            .ok()
            .flatten()
            .is_some_and(|job| job.cancel_requested);
        let transition = HealthItemTransition {
            item_id: item.id,
            expected_state: HealthJobItemState::InFlight,
            expected_fence: item.item_fence_token,
            new_state: HealthJobItemState::Succeeded,
            lease_owner: None,
            lease_expires_at_ms: None,
            pair_fence_token: None,
            dispatch_attempt_id: None,
            request_id: None,
            not_before_ms: None,
            health_status: Some(result.status.as_str().into()),
            safe_error_code: None,
            safe_error_message: None,
            completed_after_cancel,
            now_ms: now_ms(),
        };
        if matches!(
            self.state.db.transition_health_job_item(&transition).await,
            Ok(ConditionalWriteOutcome::Applied)
        ) {
            self.release_pair(&item, pair_fence).await;
            self.audit_if_final(&item.job_id, transition.now_ms).await;
        }
    }

    async fn retry_owned(&self, item: &HealthJobItemRecord, pair_fence: i64, code: &str) {
        let now = now_ms();
        let expired = item.deadline_at_ms.is_some_and(|deadline| deadline <= now)
            || now.saturating_sub(item.created_at_ms) >= MAX_RETRY_AGE_MS;
        if expired || item.attempt_count >= MAX_ATTEMPTS {
            self.fail_owned(item, pair_fence, code).await;
            return;
        }
        let delay = retry_delay_ms(item.attempt_count.max(1));
        let Some(expected_state) = HealthJobItemState::parse(&item.state) else {
            return;
        };
        let (safe_code, safe_message) = safe_failure(code);
        let transition = HealthItemTransition {
            item_id: item.id,
            expected_state,
            expected_fence: item.item_fence_token,
            new_state: HealthJobItemState::RetryWait,
            lease_owner: None,
            lease_expires_at_ms: None,
            pair_fence_token: None,
            dispatch_attempt_id: None,
            request_id: None,
            not_before_ms: Some(now + delay),
            health_status: None,
            safe_error_code: Some(safe_code.into()),
            safe_error_message: Some(safe_message.into()),
            completed_after_cancel: false,
            now_ms: now,
        };
        if matches!(
            self.state.db.transition_health_job_item(&transition).await,
            Ok(ConditionalWriteOutcome::Applied)
        ) {
            self.release_pair(item, pair_fence).await;
        }
    }

    async fn fail_owned(&self, item: &HealthJobItemRecord, pair_fence: i64, code: &str) {
        let Some(expected_state) = HealthJobItemState::parse(&item.state) else {
            return;
        };
        let (safe_code, safe_message) = safe_failure(code);
        let now = now_ms();
        let transition = HealthItemTransition {
            item_id: item.id,
            expected_state,
            expected_fence: item.item_fence_token,
            new_state: HealthJobItemState::Failed,
            lease_owner: None,
            lease_expires_at_ms: None,
            pair_fence_token: None,
            dispatch_attempt_id: None,
            request_id: None,
            not_before_ms: None,
            health_status: None,
            safe_error_code: Some(safe_code.into()),
            safe_error_message: Some(safe_message.into()),
            completed_after_cancel: false,
            now_ms: now,
        };
        if matches!(
            self.state.db.transition_health_job_item(&transition).await,
            Ok(ConditionalWriteOutcome::Applied)
        ) {
            self.release_pair(item, pair_fence).await;
            self.audit_if_final(&item.job_id, now).await;
        }
    }

    async fn cancel_owned(&self, item: &HealthJobItemRecord, pair_fence: i64) {
        let Some(expected_state) = HealthJobItemState::parse(&item.state) else {
            return;
        };
        if !expected_state.can_transition_to(HealthJobItemState::Cancelled) {
            return;
        }
        let now = now_ms();
        let transition = HealthItemTransition {
            item_id: item.id,
            expected_state,
            expected_fence: item.item_fence_token,
            new_state: HealthJobItemState::Cancelled,
            lease_owner: None,
            lease_expires_at_ms: None,
            pair_fence_token: None,
            dispatch_attempt_id: None,
            request_id: None,
            not_before_ms: None,
            health_status: None,
            safe_error_code: None,
            safe_error_message: None,
            completed_after_cancel: false,
            now_ms: now,
        };
        if matches!(
            self.state.db.transition_health_job_item(&transition).await,
            Ok(ConditionalWriteOutcome::Applied)
        ) {
            self.release_pair(item, pair_fence).await;
            self.audit_if_final(&item.job_id, now).await;
        }
    }

    async fn cancel_or_release(&self, item: &HealthJobItemRecord, pair_fence: i64) {
        let cancelled = self
            .state
            .db
            .find_health_job(&item.job_id)
            .await
            .ok()
            .flatten()
            .is_some_and(|job| job.cancel_requested);
        if cancelled {
            self.cancel_owned(item, pair_fence).await;
        } else {
            self.release_pair(item, pair_fence).await;
        }
    }

    async fn release_pair(&self, item: &HealthJobItemRecord, pair_fence: i64) {
        let _ = self
            .state
            .db
            .release_health_pair_lease(
                item.resource_id_snapshot,
                item.relay_node_id_snapshot,
                item.id,
                &self.owner,
                pair_fence,
                now_ms(),
            )
            .await;
    }

    async fn reap(&self) {
        let now = now_ms();
        if let Ok(items) = self.state.db.list_expired_health_job_items(now, 200).await {
            for item in items {
                let Some(pair_fence) = item.pair_fence_token else {
                    continue;
                };
                let cancelled = self
                    .state
                    .db
                    .find_health_job(&item.job_id)
                    .await
                    .ok()
                    .flatten()
                    .is_some_and(|job| job.cancel_requested);
                if cancelled {
                    self.cancel_owned(&item, pair_fence).await;
                } else {
                    self.retry_owned(&item, pair_fence, "UPSTREAM_UNAVAILABLE")
                        .await;
                }
            }
        }
        if let Ok(items) = self.state.db.list_overdue_health_job_items(now, 200).await {
            for item in items {
                let Some(expected_state) = HealthJobItemState::parse(&item.state) else {
                    continue;
                };
                let (code, message) = safe_failure("UPSTREAM_UNAVAILABLE");
                let transition = HealthItemTransition {
                    item_id: item.id,
                    expected_state,
                    expected_fence: item.item_fence_token,
                    new_state: HealthJobItemState::Failed,
                    lease_owner: None,
                    lease_expires_at_ms: None,
                    pair_fence_token: None,
                    dispatch_attempt_id: None,
                    request_id: None,
                    not_before_ms: None,
                    health_status: None,
                    safe_error_code: Some(code.into()),
                    safe_error_message: Some(message.into()),
                    completed_after_cancel: false,
                    now_ms: now,
                };
                let _ = self.state.db.transition_health_job_item(&transition).await;
                self.audit_if_final(&item.job_id, now).await;
            }
        }
    }

    async fn reconcile(&self) {
        match self
            .state
            .db
            .reconcile_health_job_counters(now_ms(), 500)
            .await
        {
            Ok(job_ids) => {
                for job_id in job_ids {
                    crate::service::audit::record(
                        &self.state,
                        None,
                        "JOB_COUNTER_RECONCILED",
                        "socks5_health_job",
                        &job_id,
                        "counters_rebuilt_from_items=true",
                    )
                    .await;
                }
            }
            Err(error) => tracing::warn!("durable health counter reconciliation failed: {error}"),
        }
    }

    async fn audit_if_final(&self, job_id: &str, transition_ms: i64) {
        let Ok(Some(job)) = self.state.db.find_health_job(job_id).await else {
            return;
        };
        if HealthJobStatus::parse(&job.status).is_some_and(HealthJobStatus::is_terminal)
            && job.finished_at_ms == Some(transition_ms)
        {
            crate::service::audit::record(
                &self.state,
                None,
                "JOB_FINALIZED",
                "socks5_health_job",
                job_id,
                &format!(
                    "status={}; succeeded={}; failed={}; cancelled={}",
                    job.status, job.succeeded_count, job.failed_count, job.cancelled_count
                ),
            )
            .await;
        }
    }
}

async fn node_queue_depth(state: &AppState, group_id: i64, node_key: &str) -> Option<i64> {
    let key = format!("node_status:{group_id}:{node_key}");
    state
        .db
        .get(&key)
        .await
        .ok()
        .flatten()
        .and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw).ok())
        .and_then(|status| status.get("socks5_check_queue_depth")?.as_i64())
}

fn retry_delay_ms(attempt: i64) -> i64 {
    let exponent = attempt.saturating_sub(1).min(10) as u32;
    let raw = 1_000_i64.saturating_mul(1_i64 << exponent).min(30_000);
    let jitter_cap = (raw / 5).min(5_000);
    let random = uuid::Uuid::new_v4().as_u128() as i64 & i64::MAX;
    raw + random % (jitter_cap + 1)
}

fn safe_failure(code: &str) -> (&'static str, &'static str) {
    match code {
        "PROXY_CONNECT_TIMEOUT" => ("PROXY_CONNECT_TIMEOUT", "Proxy connection timed out"),
        "PROXY_AUTH_FAILED" => ("PROXY_AUTH_FAILED", "Proxy authentication failed"),
        "TRANSITION_CONFLICT" => ("TRANSITION_CONFLICT", "State transition conflicted"),
        _ => ("UPSTREAM_UNAVAILABLE", "Upstream service unavailable"),
    }
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::system::ReleaseCache;
    use crate::api::ws::NodeConnections;
    use crate::config::Config;
    use crate::db::health_orchestration::{
        snapshot_hash, HealthJobSource, NewHealthJob, NewHealthJobItem,
    };
    use crate::db::schema::{run_migrations, SCHEMA_SQL};
    use crate::db::sqlite_repo::SqliteRepository;
    use axum::extract::State;
    use axum::http::{HeaderMap, HeaderValue};
    use axum::Json;
    use relay_shared::protocol::{Socks5CheckStage, Socks5HealthStatus};
    use sha2::{Digest, Sha256};
    use sqlx::sqlite::SqlitePoolOptions;
    use std::collections::HashSet;
    use std::sync::Arc;

    #[test]
    fn retry_backoff_is_bounded_and_non_decreasing_by_bucket() {
        for attempt in 1..=10 {
            let delay = retry_delay_ms(attempt);
            let raw = 1_000_i64
                .saturating_mul(1_i64 << (attempt - 1).min(10))
                .min(30_000);
            assert!(delay >= raw);
            assert!(delay <= raw + (raw / 5).min(5_000));
        }
    }

    #[test]
    fn runtime_limits_reject_out_of_contract_values() {
        let mut config = HealthWorkerConfig {
            global_limit: 50,
            per_node_limit: 10,
            per_job_limit: 20,
            node_queue_soft_limit: 160,
            claim_batch: 32,
        };
        assert!(config.validate().is_ok());
        config.global_limit = 51;
        assert!(config.validate().is_err());
        config.global_limit = 50;
        config.claim_batch = 33;
        assert!(config.validate().is_err());
    }

    #[tokio::test]
    async fn durable_worker_dispatches_validates_persists_and_finalizes_health_fact() {
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
            "INSERT INTO device_groups(name,group_type,token,uid) VALUES('worker-e2e','in','worker-e2e-token',1)",
        )
        .execute(&pool)
        .await
        .unwrap()
        .last_insert_rowid();
        let resource = sqlx::query(
            "INSERT INTO socks5_resources(name,host,port) VALUES('worker-e2e-r','127.0.0.1',1080)",
        )
        .execute(&pool)
        .await
        .unwrap()
        .last_insert_rowid();
        let identity_secret = "a".repeat(64);
        let identity_hash = format!("{:x}", Sha256::digest(identity_secret.as_bytes()));
        let node: i64 = sqlx::query_scalar("INSERT INTO relay_nodes(device_group_id,node_key,identity_secret_hash,first_seen_at,last_seen_at) VALUES(?,'worker-e2e-node',?,'2026-01-01','2026-01-01') RETURNING id")
            .bind(group)
            .bind(&identity_hash)
            .fetch_one(&pool)
            .await
            .unwrap();
        let state = AppState {
            db: Arc::new(SqliteRepository::new(pool.clone())),
            config: Config {
                database_path: "sqlite::memory:".into(),
                listen: "127.0.0.1:0".into(),
                key: "test-key".into(),
                jwt_secret: "worker-e2e-secret".into(),
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
            socks5_checks: crate::api::socks5_health::Socks5CheckRegistry::new(),
            geoip_in_flight: Arc::new(tokio::sync::Mutex::new(HashSet::new())),
        };
        let (_connection_id, mut node_receiver) = state
            .node_connections
            .register(group, Some("worker-e2e-node".into()))
            .await;
        state
            .db
            .set(
                &format!("node_status:{group}:worker-e2e-node"),
                r#"{"socks5_check_queue_depth":0}"#,
            )
            .await
            .unwrap();
        let created_at_ms = now_ms();
        let job = NewHealthJob {
            id: "worker-e2e-job".into(),
            source: HealthJobSource::Manual,
            policy_id: None,
            parent_job_id: None,
            actor_id: None,
            request_fingerprint: "a".repeat(64),
            snapshot_hash: snapshot_hash(&[(resource, node)]),
            resource_selector_json: "{}".into(),
            node_selector_json: "{}".into(),
            scheduled_for_ms: None,
            created_at_ms,
        };
        state
            .db
            .create_health_job(
                &job,
                &[NewHealthJobItem {
                    resource_id: resource,
                    relay_node_id: node,
                    not_before_ms: created_at_ms,
                    deadline_at_ms: Some(created_at_ms + MAX_RETRY_AGE_MS),
                }],
            )
            .await
            .unwrap();
        let runtime = Runtime {
            state: state.clone(),
            owner: "panel:test-worker".into(),
            config: HealthWorkerConfig {
                global_limit: 16,
                per_node_limit: 10,
                per_job_limit: 16,
                node_queue_soft_limit: 160,
                claim_batch: 8,
            },
            effective_global: 16,
            effective_batch: 8,
        };
        let leased = state
            .db
            .claim_health_job_items(&HealthItemClaimRequest {
                lease_owner: runtime.owner.clone(),
                now_ms: created_at_ms + 1,
                lease_expires_at_ms: created_at_ms + ITEM_LEASE_MS,
                limit: 1,
                global_limit: 16,
                per_node_limit: 10,
                per_job_limit: 16,
            })
            .await
            .unwrap()
            .remove(0);
        let worker = {
            let runtime = runtime.clone();
            tokio::spawn(async move { runtime.execute(leased).await })
        };
        let payload = tokio::time::timeout(Duration::from_secs(2), node_receiver.recv())
            .await
            .unwrap()
            .unwrap();
        let request: Socks5CheckRequest = serde_json::from_str(&payload).unwrap();
        let result = Socks5CheckResult {
            msg_type: "socks5_check_result".into(),
            request_id: request.request_id,
            challenge: request.challenge,
            session_id: request.session_id,
            resource_generation: request.resource_generation,
            generation: request.generation,
            resource_id: request.resource_id,
            relay_node_id: request.relay_node_id,
            node_id: request.node_id,
            status: Socks5HealthStatus::AuthFailed,
            tcp_latency_ms: Some(1),
            handshake_latency_ms: Some(2),
            connect_latency_ms: None,
            total_latency_ms: Some(3),
            exit_ip: None,
            detected_country: None,
            error_stage: Some(Socks5CheckStage::Authentication),
            error_code: Some("SOCKS5_AUTH_FAILED".into()),
            safe_error_message: Some("SOCKS5 authentication failed".into()),
            checked_at: String::new(),
        };
        let mut headers = HeaderMap::new();
        headers.insert(
            "Authorization",
            HeaderValue::from_static("Bearer worker-e2e-token"),
        );
        headers.insert("X-Node-ID", HeaderValue::from_static("worker-e2e-node"));
        headers.insert(
            "X-Node-Identity",
            HeaderValue::from_str(&identity_secret).unwrap(),
        );
        let response =
            crate::api::socks5_health::receive_result(State(state.clone()), headers, Json(result))
                .await;
        assert_eq!(response.0.code, 0);
        worker.await.unwrap();

        let item = state
            .db
            .list_health_job_items(&job.id)
            .await
            .unwrap()
            .remove(0);
        assert_eq!(item.state, "SUCCEEDED");
        assert_eq!(item.health_status.as_deref(), Some("AUTH_FAILED"));
        assert_eq!(item.attempt_count, 1);
        let stored_job = state.db.find_health_job(&job.id).await.unwrap().unwrap();
        assert_eq!(stored_job.status, "SUCCEEDED");
        assert_eq!(stored_job.succeeded_count, 1);
        let health = state.db.list_socks5_health(resource).await.unwrap();
        assert_eq!(health.len(), 1);
        assert_eq!(health[0].status, "AUTH_FAILED");
        assert_eq!(
            state
                .db
                .list_socks5_check_history(resource, 10, 0)
                .await
                .unwrap()
                .len(),
            1
        );

        // Recovery is DB-driven: an expired pre-dispatch lease returns to
        // RETRY_WAIT without consuming a network attempt and releases the Pair.
        let recovery_now = now_ms();
        let recovery_job = NewHealthJob {
            id: "worker-reaper-job".into(),
            source: HealthJobSource::Manual,
            policy_id: None,
            parent_job_id: None,
            actor_id: None,
            request_fingerprint: "b".repeat(64),
            snapshot_hash: snapshot_hash(&[(resource, node)]),
            resource_selector_json: "{}".into(),
            node_selector_json: "{}".into(),
            scheduled_for_ms: None,
            created_at_ms: recovery_now - 2_000,
        };
        state
            .db
            .create_health_job(
                &recovery_job,
                &[NewHealthJobItem {
                    resource_id: resource,
                    relay_node_id: node,
                    not_before_ms: recovery_now - 2_000,
                    deadline_at_ms: Some(recovery_now + MAX_RETRY_AGE_MS),
                }],
            )
            .await
            .unwrap();
        state
            .db
            .claim_health_job_items(&HealthItemClaimRequest {
                lease_owner: runtime.owner.clone(),
                now_ms: recovery_now - 1_000,
                lease_expires_at_ms: recovery_now - 1,
                limit: 1,
                global_limit: 16,
                per_node_limit: 10,
                per_job_limit: 16,
            })
            .await
            .unwrap();
        runtime.reap().await;
        let recovered = state
            .db
            .list_health_job_items(&recovery_job.id)
            .await
            .unwrap()
            .remove(0);
        assert_eq!(recovered.state, "RETRY_WAIT");
        assert_eq!(recovered.attempt_count, 0);
        assert_eq!(
            recovered.safe_error_code.as_deref(),
            Some("UPSTREAM_UNAVAILABLE")
        );
        let pair = state
            .db
            .find_health_pair_lease(resource, node)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(pair.lease_owner, None);
        assert_eq!(pair.item_id, None);
    }
}
