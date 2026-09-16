//! Stage 5.1 migration DDL. These statements intentionally omit
//! `IF NOT EXISTS`: migration versions, not permissive DDL, provide rerun
//! safety. Version/schema disagreement is validated and fails startup.

pub const HEALTH_TABLES: [&str; 5] = [
    "socks5_check_policies",
    "socks5_check_jobs",
    "socks5_check_job_items",
    "socks5_check_pair_leases",
    "socks5_health_job_idempotency",
];

pub const HEALTH_INDEXES: [&str; 10] = [
    "idx_socks5_check_jobs_status_created",
    "idx_socks5_check_jobs_policy_status",
    "uq_socks5_check_jobs_scheduled_slot",
    "idx_socks5_check_job_items_ready",
    "idx_socks5_check_job_items_job_state",
    "idx_socks5_check_job_items_pair_state",
    "idx_socks5_check_job_items_lease_expiry",
    "idx_socks5_check_pair_leases_expiry",
    "idx_socks5_check_pair_leases_updated",
    "idx_socks5_health_job_idempotency_expiry",
];

pub const POSTGRES_HEALTH_COLUMN_FINGERPRINT: &str =
    "8df0b1eed2ee0c77ed5aa563a065259d00126f05eec43bb92d75fcfa13a3b2d9";
pub const POSTGRES_HEALTH_CONSTRAINT_FINGERPRINT: &str =
    "88e0c261e38a6f0c8bfce52d956f3a01eca56db840b09fe8f394071d7c0bfbdd";
pub const POSTGRES_HEALTH_INDEX_FINGERPRINT: &str =
    "bfa8a654b1972ef608a1d8e050cfba04dca5d056bf8c49eb90d4f9fad01f054e";

pub fn normalize_schema_sql(sql: &str) -> String {
    sql.chars()
        .filter(|character| !character.is_whitespace())
        .flat_map(char::to_lowercase)
        .collect()
}

pub const SQLITE_MIGRATION_51: [&str; 15] = [
    r#"CREATE TABLE socks5_check_policies (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE CHECK(length(trim(name)) > 0),
        enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),
        revision INTEGER NOT NULL DEFAULT 1 CHECK(revision >= 1),
        resource_selector_json TEXT NOT NULL CHECK(json_valid(resource_selector_json)),
        node_selector_json TEXT NOT NULL CHECK(json_valid(node_selector_json)),
        matrix_mode TEXT NOT NULL DEFAULT 'CARTESIAN' CHECK(matrix_mode='CARTESIAN'),
        interval_seconds INTEGER NOT NULL CHECK(interval_seconds >= 60 AND interval_seconds <= 31536000),
        jitter_seconds INTEGER NOT NULL DEFAULT 0 CHECK(jitter_seconds >= 0 AND jitter_seconds < interval_seconds),
        max_items INTEGER NOT NULL CHECK(max_items > 0),
        next_run_at_ms INTEGER NOT NULL CHECK(next_run_at_ms >= 0),
        last_scheduled_at_ms INTEGER CHECK(last_scheduled_at_ms IS NULL OR last_scheduled_at_ms >= 0),
        last_error_code TEXT,
        last_error_message TEXT CHECK(last_error_message IS NULL OR length(last_error_message) <= 256),
        last_error_at_ms INTEGER CHECK(last_error_at_ms IS NULL OR last_error_at_ms >= 0),
        skipped_overlap_count INTEGER NOT NULL DEFAULT 0 CHECK(skipped_overlap_count >= 0),
        created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
        created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
        updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0),
        deleted_at_ms INTEGER CHECK(deleted_at_ms IS NULL OR deleted_at_ms >= 0),
        CHECK((last_error_code IS NULL AND last_error_message IS NULL) OR
              (last_error_code='PROXY_CONNECT_TIMEOUT' AND (last_error_message IS NULL OR last_error_message='Proxy connection timed out')) OR
              (last_error_code='NETWORK_DNS_FAILED' AND (last_error_message IS NULL OR last_error_message='DNS resolution failed')) OR
              (last_error_code='PROXY_AUTH_FAILED' AND (last_error_message IS NULL OR last_error_message='Proxy authentication failed')) OR
              (last_error_code='UPSTREAM_UNAVAILABLE' AND (last_error_message IS NULL OR last_error_message='Upstream service unavailable')) OR
              (last_error_code='PAIR_LEASE_BUSY' AND (last_error_message IS NULL OR last_error_message='Relay pair is busy')) OR
              (last_error_code='TRANSITION_CONFLICT' AND (last_error_message IS NULL OR last_error_message='State transition conflicted')) OR
              (last_error_code='REQUEST_CANCELLED' AND (last_error_message IS NULL OR last_error_message='Health check was cancelled')))
    )"#,
    r#"CREATE TABLE socks5_check_jobs (
        id TEXT PRIMARY KEY CHECK(length(id) > 0),
        source TEXT NOT NULL CHECK(source IN ('MANUAL','SCHEDULED','RETRY_FAILED','POLICY_RUN_NOW')),
        policy_id INTEGER REFERENCES socks5_check_policies(id) ON DELETE RESTRICT,
        parent_job_id TEXT REFERENCES socks5_check_jobs(id) ON DELETE RESTRICT,
        actor_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        status TEXT NOT NULL DEFAULT 'QUEUED' CHECK(status IN ('QUEUED','RUNNING','CANCEL_REQUESTED','SUCCEEDED','FAILED','PARTIAL','CANCELLED','PARTIAL_CANCELLED')),
        request_fingerprint TEXT NOT NULL CHECK(length(request_fingerprint)=64 AND request_fingerprint=lower(request_fingerprint)),
        snapshot_hash TEXT NOT NULL CHECK(length(snapshot_hash)=64 AND snapshot_hash=lower(snapshot_hash)),
        resource_selector_json TEXT NOT NULL CHECK(json_valid(resource_selector_json)),
        node_selector_json TEXT NOT NULL CHECK(json_valid(node_selector_json)),
        matrix_mode TEXT NOT NULL DEFAULT 'CARTESIAN' CHECK(matrix_mode='CARTESIAN'),
        retry_policy_version TEXT NOT NULL CHECK(length(retry_policy_version) > 0),
        scheduled_for_ms INTEGER CHECK(scheduled_for_ms IS NULL OR scheduled_for_ms >= 0),
        cancel_requested INTEGER NOT NULL DEFAULT 0 CHECK(cancel_requested IN (0,1)),
        total_items INTEGER NOT NULL CHECK(total_items > 0),
        queued_count INTEGER NOT NULL CHECK(queued_count >= 0),
        running_count INTEGER NOT NULL DEFAULT 0 CHECK(running_count >= 0),
        succeeded_count INTEGER NOT NULL DEFAULT 0 CHECK(succeeded_count >= 0),
        failed_count INTEGER NOT NULL DEFAULT 0 CHECK(failed_count >= 0),
        cancelled_count INTEGER NOT NULL DEFAULT 0 CHECK(cancelled_count >= 0),
        failure_code TEXT,
        created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
        started_at_ms INTEGER CHECK(started_at_ms IS NULL OR started_at_ms >= 0),
        finished_at_ms INTEGER CHECK(finished_at_ms IS NULL OR finished_at_ms >= 0),
        CHECK(queued_count+running_count+succeeded_count+failed_count+cancelled_count=total_items),
        CHECK((status IN ('SUCCEEDED','FAILED','PARTIAL','CANCELLED','PARTIAL_CANCELLED') AND finished_at_ms IS NOT NULL) OR (status IN ('QUEUED','RUNNING','CANCEL_REQUESTED') AND finished_at_ms IS NULL)),
        CHECK((source='SCHEDULED' AND policy_id IS NOT NULL AND parent_job_id IS NULL AND scheduled_for_ms IS NOT NULL) OR
              (source='MANUAL' AND policy_id IS NULL AND parent_job_id IS NULL AND scheduled_for_ms IS NULL) OR
              (source='RETRY_FAILED' AND parent_job_id IS NOT NULL AND scheduled_for_ms IS NULL) OR
              (source='POLICY_RUN_NOW' AND policy_id IS NOT NULL AND parent_job_id IS NULL AND scheduled_for_ms IS NULL))
    )"#,
    r#"CREATE TABLE socks5_check_job_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        job_id TEXT NOT NULL REFERENCES socks5_check_jobs(id) ON DELETE CASCADE,
        resource_id INTEGER REFERENCES socks5_resources(id) ON DELETE SET NULL,
        relay_node_id INTEGER REFERENCES relay_nodes(id) ON DELETE SET NULL,
        resource_id_snapshot INTEGER NOT NULL CHECK(resource_id_snapshot > 0),
        relay_node_id_snapshot INTEGER NOT NULL CHECK(relay_node_id_snapshot > 0),
        state TEXT NOT NULL DEFAULT 'QUEUED' CHECK(state IN ('QUEUED','LEASED','DISPATCHING','IN_FLIGHT','RETRY_WAIT','SUCCEEDED','FAILED','CANCELLED')),
        attempt_count INTEGER NOT NULL DEFAULT 0 CHECK(attempt_count >= 0),
        item_fence_token INTEGER NOT NULL DEFAULT 0 CHECK(item_fence_token >= 0),
        pair_fence_token INTEGER CHECK(pair_fence_token IS NULL OR pair_fence_token >= 0),
        dispatch_attempt_id TEXT,
        request_id TEXT,
        not_before_ms INTEGER NOT NULL CHECK(not_before_ms >= 0),
        lease_owner TEXT,
        lease_expires_at_ms INTEGER CHECK(lease_expires_at_ms IS NULL OR lease_expires_at_ms >= 0),
        first_started_at_ms INTEGER CHECK(first_started_at_ms IS NULL OR first_started_at_ms >= 0),
        last_started_at_ms INTEGER CHECK(last_started_at_ms IS NULL OR last_started_at_ms >= 0),
        deadline_at_ms INTEGER CHECK(deadline_at_ms IS NULL OR deadline_at_ms >= 0),
        health_status TEXT,
        safe_error_code TEXT,
        safe_error_message TEXT CHECK(safe_error_message IS NULL OR length(safe_error_message) <= 256),
        completed_after_cancel INTEGER NOT NULL DEFAULT 0 CHECK(completed_after_cancel IN (0,1)),
        created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
        updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0),
        finished_at_ms INTEGER CHECK(finished_at_ms IS NULL OR finished_at_ms >= 0),
        CHECK((lease_owner IS NULL AND lease_expires_at_ms IS NULL) OR (lease_owner IS NOT NULL AND lease_expires_at_ms IS NOT NULL)),
        CHECK((state='LEASED' AND lease_owner IS NOT NULL AND lease_expires_at_ms > updated_at_ms AND pair_fence_token IS NOT NULL AND dispatch_attempt_id IS NULL AND request_id IS NULL) OR
              (state='DISPATCHING' AND lease_owner IS NOT NULL AND lease_expires_at_ms > updated_at_ms AND pair_fence_token IS NOT NULL AND dispatch_attempt_id IS NOT NULL AND length(dispatch_attempt_id)>0 AND request_id IS NULL) OR
              (state='IN_FLIGHT' AND lease_owner IS NOT NULL AND lease_expires_at_ms > updated_at_ms AND pair_fence_token IS NOT NULL AND dispatch_attempt_id IS NOT NULL AND length(dispatch_attempt_id)>0 AND request_id IS NOT NULL AND length(request_id)>0) OR
              (state IN ('QUEUED','RETRY_WAIT','SUCCEEDED','FAILED','CANCELLED') AND lease_owner IS NULL AND lease_expires_at_ms IS NULL AND pair_fence_token IS NULL AND dispatch_attempt_id IS NULL AND request_id IS NULL)),
        CHECK((safe_error_code IS NULL AND safe_error_message IS NULL) OR
              (safe_error_code='PROXY_CONNECT_TIMEOUT' AND (safe_error_message IS NULL OR safe_error_message='Proxy connection timed out')) OR
              (safe_error_code='NETWORK_DNS_FAILED' AND (safe_error_message IS NULL OR safe_error_message='DNS resolution failed')) OR
              (safe_error_code='PROXY_AUTH_FAILED' AND (safe_error_message IS NULL OR safe_error_message='Proxy authentication failed')) OR
              (safe_error_code='UPSTREAM_UNAVAILABLE' AND (safe_error_message IS NULL OR safe_error_message='Upstream service unavailable')) OR
              (safe_error_code='PAIR_LEASE_BUSY' AND (safe_error_message IS NULL OR safe_error_message='Relay pair is busy')) OR
              (safe_error_code='TRANSITION_CONFLICT' AND (safe_error_message IS NULL OR safe_error_message='State transition conflicted')) OR
              (safe_error_code='REQUEST_CANCELLED' AND (safe_error_message IS NULL OR safe_error_message='Health check was cancelled'))),
        CHECK(state IN ('RETRY_WAIT','FAILED') OR (safe_error_code IS NULL AND safe_error_message IS NULL)),
        CHECK((state IN ('SUCCEEDED','FAILED','CANCELLED') AND finished_at_ms IS NOT NULL) OR (state IN ('QUEUED','LEASED','DISPATCHING','IN_FLIGHT','RETRY_WAIT') AND finished_at_ms IS NULL)),
        UNIQUE(job_id,resource_id_snapshot,relay_node_id_snapshot)
    )"#,
    r#"CREATE TABLE socks5_check_pair_leases (
        resource_id INTEGER NOT NULL REFERENCES socks5_resources(id) ON DELETE CASCADE,
        relay_node_id INTEGER NOT NULL REFERENCES relay_nodes(id) ON DELETE CASCADE,
        item_id INTEGER REFERENCES socks5_check_job_items(id) ON DELETE SET NULL,
        lease_owner TEXT,
        lease_expires_at_ms INTEGER CHECK(lease_expires_at_ms IS NULL OR lease_expires_at_ms >= 0),
        pair_fence_token INTEGER NOT NULL DEFAULT 0 CHECK(pair_fence_token >= 0),
        updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0),
        PRIMARY KEY(resource_id,relay_node_id),
        CHECK((lease_owner IS NULL AND lease_expires_at_ms IS NULL) OR (lease_owner IS NOT NULL AND lease_expires_at_ms > updated_at_ms))
    )"#,
    r#"CREATE TABLE socks5_health_job_idempotency (
        actor_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        idempotency_key TEXT NOT NULL CHECK(length(idempotency_key) > 0),
        request_fingerprint TEXT NOT NULL CHECK(length(request_fingerprint)=64 AND request_fingerprint=lower(request_fingerprint)),
        job_id TEXT REFERENCES socks5_check_jobs(id) ON DELETE SET NULL,
        created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
        expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms > created_at_ms),
        PRIMARY KEY(actor_id,idempotency_key)
    )"#,
    "CREATE INDEX idx_socks5_check_jobs_status_created ON socks5_check_jobs(status,created_at_ms)",
    "CREATE INDEX idx_socks5_check_jobs_policy_status ON socks5_check_jobs(policy_id,status)",
    "CREATE UNIQUE INDEX uq_socks5_check_jobs_scheduled_slot ON socks5_check_jobs(policy_id,scheduled_for_ms) WHERE source='SCHEDULED'",
    "CREATE INDEX idx_socks5_check_job_items_ready ON socks5_check_job_items(state,not_before_ms,id)",
    "CREATE INDEX idx_socks5_check_job_items_job_state ON socks5_check_job_items(job_id,state,id)",
    "CREATE INDEX idx_socks5_check_job_items_pair_state ON socks5_check_job_items(resource_id_snapshot,relay_node_id_snapshot,state)",
    "CREATE INDEX idx_socks5_check_job_items_lease_expiry ON socks5_check_job_items(lease_expires_at_ms)",
    "CREATE INDEX idx_socks5_check_pair_leases_expiry ON socks5_check_pair_leases(lease_expires_at_ms)",
    "CREATE INDEX idx_socks5_check_pair_leases_updated ON socks5_check_pair_leases(updated_at_ms)",
    "CREATE INDEX idx_socks5_health_job_idempotency_expiry ON socks5_health_job_idempotency(expires_at_ms)",
];

/// Stage 5.2 audit remediation. Historical migration 51 remains immutable;
/// retry scheduling gets its own durable counter in migration 52.
pub const SQLITE_MIGRATION_52: &str =
    "ALTER TABLE socks5_check_job_items ADD COLUMN retry_count INTEGER NOT NULL DEFAULT 0 CHECK(retry_count >= 0)";

pub const POSTGRES_MIGRATION_35: [&str; 15] = [
    r#"CREATE TABLE socks5_check_policies (
        id BIGSERIAL PRIMARY KEY, name TEXT NOT NULL UNIQUE CHECK(length(btrim(name)) > 0),
        enabled BOOLEAN NOT NULL, revision BIGINT NOT NULL DEFAULT 1 CHECK(revision >= 1),
        resource_selector_json TEXT NOT NULL CHECK(resource_selector_json::jsonb IS NOT NULL),
        node_selector_json TEXT NOT NULL CHECK(node_selector_json::jsonb IS NOT NULL),
        matrix_mode TEXT NOT NULL DEFAULT 'CARTESIAN' CHECK(matrix_mode='CARTESIAN'),
        interval_seconds BIGINT NOT NULL CHECK(interval_seconds BETWEEN 60 AND 31536000),
        jitter_seconds BIGINT NOT NULL DEFAULT 0 CHECK(jitter_seconds >= 0 AND jitter_seconds < interval_seconds),
        max_items BIGINT NOT NULL CHECK(max_items > 0), next_run_at_ms BIGINT NOT NULL CHECK(next_run_at_ms >= 0),
        last_scheduled_at_ms BIGINT CHECK(last_scheduled_at_ms IS NULL OR last_scheduled_at_ms >= 0),
        last_error_code TEXT, last_error_message TEXT CHECK(last_error_message IS NULL OR length(last_error_message) <= 256),
        last_error_at_ms BIGINT CHECK(last_error_at_ms IS NULL OR last_error_at_ms >= 0),
        skipped_overlap_count BIGINT NOT NULL DEFAULT 0 CHECK(skipped_overlap_count >= 0),
        created_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
        created_at_ms BIGINT NOT NULL CHECK(created_at_ms >= 0), updated_at_ms BIGINT NOT NULL CHECK(updated_at_ms >= 0),
        deleted_at_ms BIGINT CHECK(deleted_at_ms IS NULL OR deleted_at_ms >= 0),
        CHECK((last_error_code IS NULL AND last_error_message IS NULL) OR
              (last_error_code='PROXY_CONNECT_TIMEOUT' AND (last_error_message IS NULL OR last_error_message='Proxy connection timed out')) OR
              (last_error_code='NETWORK_DNS_FAILED' AND (last_error_message IS NULL OR last_error_message='DNS resolution failed')) OR
              (last_error_code='PROXY_AUTH_FAILED' AND (last_error_message IS NULL OR last_error_message='Proxy authentication failed')) OR
              (last_error_code='UPSTREAM_UNAVAILABLE' AND (last_error_message IS NULL OR last_error_message='Upstream service unavailable')) OR
              (last_error_code='PAIR_LEASE_BUSY' AND (last_error_message IS NULL OR last_error_message='Relay pair is busy')) OR
              (last_error_code='TRANSITION_CONFLICT' AND (last_error_message IS NULL OR last_error_message='State transition conflicted')) OR
              (last_error_code='REQUEST_CANCELLED' AND (last_error_message IS NULL OR last_error_message='Health check was cancelled')))
    )"#,
    r#"CREATE TABLE socks5_check_jobs (
        id TEXT PRIMARY KEY CHECK(length(id)>0), source TEXT NOT NULL CHECK(source IN ('MANUAL','SCHEDULED','RETRY_FAILED','POLICY_RUN_NOW')),
        policy_id BIGINT REFERENCES socks5_check_policies(id) ON DELETE RESTRICT,
        parent_job_id TEXT REFERENCES socks5_check_jobs(id) ON DELETE RESTRICT,
        actor_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
        status TEXT NOT NULL DEFAULT 'QUEUED' CHECK(status IN ('QUEUED','RUNNING','CANCEL_REQUESTED','SUCCEEDED','FAILED','PARTIAL','CANCELLED','PARTIAL_CANCELLED')),
        request_fingerprint TEXT NOT NULL CHECK(length(request_fingerprint)=64 AND request_fingerprint=lower(request_fingerprint)),
        snapshot_hash TEXT NOT NULL CHECK(length(snapshot_hash)=64 AND snapshot_hash=lower(snapshot_hash)),
        resource_selector_json TEXT NOT NULL CHECK(resource_selector_json::jsonb IS NOT NULL),
        node_selector_json TEXT NOT NULL CHECK(node_selector_json::jsonb IS NOT NULL),
        matrix_mode TEXT NOT NULL DEFAULT 'CARTESIAN' CHECK(matrix_mode='CARTESIAN'), retry_policy_version TEXT NOT NULL CHECK(length(retry_policy_version)>0),
        scheduled_for_ms BIGINT CHECK(scheduled_for_ms IS NULL OR scheduled_for_ms >= 0), cancel_requested BOOLEAN NOT NULL DEFAULT FALSE,
        total_items BIGINT NOT NULL CHECK(total_items>0), queued_count BIGINT NOT NULL CHECK(queued_count>=0), running_count BIGINT NOT NULL DEFAULT 0 CHECK(running_count>=0),
        succeeded_count BIGINT NOT NULL DEFAULT 0 CHECK(succeeded_count>=0), failed_count BIGINT NOT NULL DEFAULT 0 CHECK(failed_count>=0), cancelled_count BIGINT NOT NULL DEFAULT 0 CHECK(cancelled_count>=0),
        failure_code TEXT, created_at_ms BIGINT NOT NULL CHECK(created_at_ms>=0), started_at_ms BIGINT CHECK(started_at_ms IS NULL OR started_at_ms>=0), finished_at_ms BIGINT CHECK(finished_at_ms IS NULL OR finished_at_ms>=0),
        CHECK(queued_count+running_count+succeeded_count+failed_count+cancelled_count=total_items),
        CHECK((status IN ('SUCCEEDED','FAILED','PARTIAL','CANCELLED','PARTIAL_CANCELLED') AND finished_at_ms IS NOT NULL) OR (status IN ('QUEUED','RUNNING','CANCEL_REQUESTED') AND finished_at_ms IS NULL)),
        CHECK((source='SCHEDULED' AND policy_id IS NOT NULL AND parent_job_id IS NULL AND scheduled_for_ms IS NOT NULL) OR (source='MANUAL' AND policy_id IS NULL AND parent_job_id IS NULL AND scheduled_for_ms IS NULL) OR (source='RETRY_FAILED' AND parent_job_id IS NOT NULL AND scheduled_for_ms IS NULL) OR (source='POLICY_RUN_NOW' AND policy_id IS NOT NULL AND parent_job_id IS NULL AND scheduled_for_ms IS NULL))
    )"#,
    r#"CREATE TABLE socks5_check_job_items (
        id BIGSERIAL PRIMARY KEY, job_id TEXT NOT NULL REFERENCES socks5_check_jobs(id) ON DELETE CASCADE,
        resource_id BIGINT REFERENCES socks5_resources(id) ON DELETE SET NULL, relay_node_id BIGINT REFERENCES relay_nodes(id) ON DELETE SET NULL,
        resource_id_snapshot BIGINT NOT NULL CHECK(resource_id_snapshot>0), relay_node_id_snapshot BIGINT NOT NULL CHECK(relay_node_id_snapshot>0),
        state TEXT NOT NULL DEFAULT 'QUEUED' CHECK(state IN ('QUEUED','LEASED','DISPATCHING','IN_FLIGHT','RETRY_WAIT','SUCCEEDED','FAILED','CANCELLED')),
        attempt_count BIGINT NOT NULL DEFAULT 0 CHECK(attempt_count>=0), item_fence_token BIGINT NOT NULL DEFAULT 0 CHECK(item_fence_token>=0), pair_fence_token BIGINT CHECK(pair_fence_token IS NULL OR pair_fence_token>=0),
        dispatch_attempt_id TEXT, request_id TEXT, not_before_ms BIGINT NOT NULL CHECK(not_before_ms>=0), lease_owner TEXT,
        lease_expires_at_ms BIGINT CHECK(lease_expires_at_ms IS NULL OR lease_expires_at_ms>=0), first_started_at_ms BIGINT CHECK(first_started_at_ms IS NULL OR first_started_at_ms>=0),
        last_started_at_ms BIGINT CHECK(last_started_at_ms IS NULL OR last_started_at_ms>=0), deadline_at_ms BIGINT CHECK(deadline_at_ms IS NULL OR deadline_at_ms>=0),
        health_status TEXT, safe_error_code TEXT, safe_error_message TEXT CHECK(safe_error_message IS NULL OR length(safe_error_message)<=256), completed_after_cancel BOOLEAN NOT NULL DEFAULT FALSE,
        created_at_ms BIGINT NOT NULL CHECK(created_at_ms>=0), updated_at_ms BIGINT NOT NULL CHECK(updated_at_ms>=0), finished_at_ms BIGINT CHECK(finished_at_ms IS NULL OR finished_at_ms>=0),
        CHECK((lease_owner IS NULL AND lease_expires_at_ms IS NULL) OR (lease_owner IS NOT NULL AND lease_expires_at_ms IS NOT NULL)),
        CHECK((state='LEASED' AND lease_owner IS NOT NULL AND lease_expires_at_ms > updated_at_ms AND pair_fence_token IS NOT NULL AND dispatch_attempt_id IS NULL AND request_id IS NULL) OR
              (state='DISPATCHING' AND lease_owner IS NOT NULL AND lease_expires_at_ms > updated_at_ms AND pair_fence_token IS NOT NULL AND dispatch_attempt_id IS NOT NULL AND length(dispatch_attempt_id)>0 AND request_id IS NULL) OR
              (state='IN_FLIGHT' AND lease_owner IS NOT NULL AND lease_expires_at_ms > updated_at_ms AND pair_fence_token IS NOT NULL AND dispatch_attempt_id IS NOT NULL AND length(dispatch_attempt_id)>0 AND request_id IS NOT NULL AND length(request_id)>0) OR
              (state IN ('QUEUED','RETRY_WAIT','SUCCEEDED','FAILED','CANCELLED') AND lease_owner IS NULL AND lease_expires_at_ms IS NULL AND pair_fence_token IS NULL AND dispatch_attempt_id IS NULL AND request_id IS NULL)),
        CHECK((safe_error_code IS NULL AND safe_error_message IS NULL) OR
              (safe_error_code='PROXY_CONNECT_TIMEOUT' AND (safe_error_message IS NULL OR safe_error_message='Proxy connection timed out')) OR
              (safe_error_code='NETWORK_DNS_FAILED' AND (safe_error_message IS NULL OR safe_error_message='DNS resolution failed')) OR
              (safe_error_code='PROXY_AUTH_FAILED' AND (safe_error_message IS NULL OR safe_error_message='Proxy authentication failed')) OR
              (safe_error_code='UPSTREAM_UNAVAILABLE' AND (safe_error_message IS NULL OR safe_error_message='Upstream service unavailable')) OR
              (safe_error_code='PAIR_LEASE_BUSY' AND (safe_error_message IS NULL OR safe_error_message='Relay pair is busy')) OR
              (safe_error_code='TRANSITION_CONFLICT' AND (safe_error_message IS NULL OR safe_error_message='State transition conflicted')) OR
              (safe_error_code='REQUEST_CANCELLED' AND (safe_error_message IS NULL OR safe_error_message='Health check was cancelled'))),
        CHECK(state IN ('RETRY_WAIT','FAILED') OR (safe_error_code IS NULL AND safe_error_message IS NULL)),
        CHECK((state IN ('SUCCEEDED','FAILED','CANCELLED') AND finished_at_ms IS NOT NULL) OR (state IN ('QUEUED','LEASED','DISPATCHING','IN_FLIGHT','RETRY_WAIT') AND finished_at_ms IS NULL)),
        UNIQUE(job_id,resource_id_snapshot,relay_node_id_snapshot)
    )"#,
    r#"CREATE TABLE socks5_check_pair_leases (
        resource_id BIGINT NOT NULL REFERENCES socks5_resources(id) ON DELETE CASCADE, relay_node_id BIGINT NOT NULL REFERENCES relay_nodes(id) ON DELETE CASCADE,
        item_id BIGINT REFERENCES socks5_check_job_items(id) ON DELETE SET NULL, lease_owner TEXT, lease_expires_at_ms BIGINT CHECK(lease_expires_at_ms IS NULL OR lease_expires_at_ms>=0),
        pair_fence_token BIGINT NOT NULL DEFAULT 0 CHECK(pair_fence_token>=0), updated_at_ms BIGINT NOT NULL CHECK(updated_at_ms>=0), PRIMARY KEY(resource_id,relay_node_id),
        CHECK((lease_owner IS NULL AND lease_expires_at_ms IS NULL) OR (lease_owner IS NOT NULL AND lease_expires_at_ms > updated_at_ms))
    )"#,
    r#"CREATE TABLE socks5_health_job_idempotency (
        actor_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE, idempotency_key TEXT NOT NULL CHECK(length(idempotency_key)>0),
        request_fingerprint TEXT NOT NULL CHECK(length(request_fingerprint)=64 AND request_fingerprint=lower(request_fingerprint)),
        job_id TEXT REFERENCES socks5_check_jobs(id) ON DELETE SET NULL, created_at_ms BIGINT NOT NULL CHECK(created_at_ms>=0), expires_at_ms BIGINT NOT NULL CHECK(expires_at_ms>created_at_ms),
        PRIMARY KEY(actor_id,idempotency_key)
    )"#,
    "CREATE INDEX idx_socks5_check_jobs_status_created ON socks5_check_jobs(status,created_at_ms)",
    "CREATE INDEX idx_socks5_check_jobs_policy_status ON socks5_check_jobs(policy_id,status)",
    "CREATE UNIQUE INDEX uq_socks5_check_jobs_scheduled_slot ON socks5_check_jobs(policy_id,scheduled_for_ms) WHERE source='SCHEDULED'",
    "CREATE INDEX idx_socks5_check_job_items_ready ON socks5_check_job_items(state,not_before_ms,id)",
    "CREATE INDEX idx_socks5_check_job_items_job_state ON socks5_check_job_items(job_id,state,id)",
    "CREATE INDEX idx_socks5_check_job_items_pair_state ON socks5_check_job_items(resource_id_snapshot,relay_node_id_snapshot,state)",
    "CREATE INDEX idx_socks5_check_job_items_lease_expiry ON socks5_check_job_items(lease_expires_at_ms)",
    "CREATE INDEX idx_socks5_check_pair_leases_expiry ON socks5_check_pair_leases(lease_expires_at_ms)",
    "CREATE INDEX idx_socks5_check_pair_leases_updated ON socks5_check_pair_leases(updated_at_ms)",
    "CREATE INDEX idx_socks5_health_job_idempotency_expiry ON socks5_health_job_idempotency(expires_at_ms)",
];

/// Stage 5.2 audit remediation. Historical migration 35 remains immutable.
pub const POSTGRES_MIGRATION_36: &str =
    "ALTER TABLE socks5_check_job_items ADD COLUMN retry_count BIGINT NOT NULL DEFAULT 0 CHECK(retry_count >= 0)";
