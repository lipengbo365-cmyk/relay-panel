use super::PgRepository;
use crate::db::error::DbError;
use crate::db::health_orchestration::{
    safe_error_message, validate_health_item_transition_fields, ConditionalWriteOutcome,
    HealthCounterCategory, HealthItemTransition, HealthJobCreateOutcome,
    HealthJobIdempotencyOutcome, HealthJobItemRecord, HealthJobRecord, HealthPairLeaseRecord,
    HealthPolicyPatch, HealthPolicyRecord, NewHealthJob, NewHealthJobIdempotency, NewHealthJobItem,
    NewHealthPolicy, PairLeaseAcquireOutcome, PairLeaseAcquireRequest, HEALTH_RETRY_POLICY_VERSION,
    PAIR_LEASE_TOMBSTONE_UPDATED_AT_MS,
};
use crate::db::repo::HealthOrchestrationRepository;
use async_trait::async_trait;
use sqlx::{Postgres, Transaction};

pub(super) const HEALTH_IDEMPOTENCY_LOCK_CLASS: i32 = 0x4854_4944;
pub(super) const HEALTH_PAIR_LEASE_LOCK_CLASS: i32 = 0x4854_504C;

async fn insert_job(
    tx: &mut Transaction<'_, Postgres>,
    job: &NewHealthJob,
    items: &[NewHealthJobItem],
) -> Result<(), DbError> {
    if items.is_empty() {
        return Err(DbError::ConstraintViolation);
    }
    if let Some(policy_id) = job.policy_id {
        let active: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM socks5_check_policies WHERE id=$1 AND deleted_at_ms IS NULL)",
        )
        .bind(policy_id)
        .fetch_one(&mut **tx)
        .await?;
        if !active {
            return Err(DbError::NotFound);
        }
    }
    let total = i64::try_from(items.len()).map_err(|_| DbError::ConstraintViolation)?;
    sqlx::query(
        "INSERT INTO socks5_check_jobs
         (id,source,policy_id,parent_job_id,actor_id,status,request_fingerprint,snapshot_hash,
          resource_selector_json,node_selector_json,matrix_mode,retry_policy_version,scheduled_for_ms,
          cancel_requested,total_items,queued_count,running_count,succeeded_count,failed_count,
          cancelled_count,created_at_ms)
         VALUES($1,$2,$3,$4,$5,'QUEUED',$6,$7,$8,$9,'CARTESIAN',$10,$11,FALSE,$12,$12,0,0,0,0,$13)",
    )
    .bind(&job.id).bind(job.source.as_str()).bind(job.policy_id).bind(&job.parent_job_id)
    .bind(job.actor_id).bind(&job.request_fingerprint).bind(&job.snapshot_hash)
    .bind(&job.resource_selector_json).bind(&job.node_selector_json)
    .bind(HEALTH_RETRY_POLICY_VERSION).bind(job.scheduled_for_ms).bind(total)
    .bind(job.created_at_ms).execute(&mut **tx).await?;
    for item in items {
        sqlx::query(
            "INSERT INTO socks5_check_job_items
             (job_id,resource_id,relay_node_id,resource_id_snapshot,relay_node_id_snapshot,state,
              attempt_count,item_fence_token,not_before_ms,deadline_at_ms,completed_after_cancel,
              created_at_ms,updated_at_ms)
             VALUES($1,$2,$3,$2,$3,'QUEUED',0,0,$4,$5,FALSE,$6,$6)",
        )
        .bind(&job.id)
        .bind(item.resource_id)
        .bind(item.relay_node_id)
        .bind(item.not_before_ms)
        .bind(item.deadline_at_ms)
        .bind(job.created_at_ms)
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

fn counter_column(category: HealthCounterCategory) -> &'static str {
    match category {
        HealthCounterCategory::Queued => "queued_count",
        HealthCounterCategory::Running => "running_count",
        HealthCounterCategory::Succeeded => "succeeded_count",
        HealthCounterCategory::Failed => "failed_count",
        HealthCounterCategory::Cancelled => "cancelled_count",
    }
}

async fn aggregate_and_finalize(
    tx: &mut Transaction<'_, Postgres>,
    job_id: &str,
    now_ms: i64,
) -> Result<bool, DbError> {
    let cancel: Option<bool> =
        sqlx::query_scalar("SELECT cancel_requested FROM socks5_check_jobs WHERE id=$1 FOR UPDATE")
            .bind(job_id)
            .fetch_optional(&mut **tx)
            .await?;
    let Some(cancel) = cancel else {
        return Ok(false);
    };
    let _: Vec<i64> = sqlx::query_scalar(
        "SELECT id FROM socks5_check_job_items WHERE job_id=$1 ORDER BY id FOR UPDATE",
    )
    .bind(job_id)
    .fetch_all(&mut **tx)
    .await?;
    let counts: Option<(i64, i64, i64, i64, i64)> = sqlx::query_as(
        "SELECT COUNT(*) FILTER(WHERE state IN ('QUEUED','RETRY_WAIT')),
                COUNT(*) FILTER(WHERE state IN ('LEASED','DISPATCHING','IN_FLIGHT')),
                COUNT(*) FILTER(WHERE state='SUCCEEDED'),COUNT(*) FILTER(WHERE state='FAILED'),
                COUNT(*) FILTER(WHERE state='CANCELLED')
         FROM socks5_check_job_items WHERE job_id=$1 HAVING COUNT(*)>0",
    )
    .bind(job_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some((queued, running, succeeded, failed, cancelled)) = counts else {
        return Ok(false);
    };
    let total = queued + running + succeeded + failed + cancelled;
    let terminal = queued == 0 && running == 0;
    let status = if terminal {
        if cancelled == total {
            "CANCELLED"
        } else if cancelled > 0 {
            "PARTIAL_CANCELLED"
        } else if succeeded == total {
            "SUCCEEDED"
        } else if failed == total {
            "FAILED"
        } else {
            "PARTIAL"
        }
    } else {
        if cancel {
            "CANCEL_REQUESTED"
        } else {
            "RUNNING"
        }
    };
    let result=sqlx::query("UPDATE socks5_check_jobs SET status=$1,total_items=$2,queued_count=$3,running_count=$4,succeeded_count=$5,failed_count=$6,cancelled_count=$7,finished_at_ms=$8 WHERE id=$9")
        .bind(status).bind(total).bind(queued).bind(running).bind(succeeded).bind(failed).bind(cancelled).bind(terminal.then_some(now_ms)).bind(job_id).execute(&mut **tx).await?;
    Ok(result.rows_affected() == 1)
}

#[async_trait]
impl HealthOrchestrationRepository for PgRepository {
    async fn create_health_policy(&self, input: &NewHealthPolicy) -> Result<i64, DbError> {
        Ok(sqlx::query_scalar("INSERT INTO socks5_check_policies(name,enabled,revision,resource_selector_json,node_selector_json,matrix_mode,interval_seconds,jitter_seconds,max_items,next_run_at_ms,skipped_overlap_count,created_by,created_at_ms,updated_at_ms) VALUES($1,$2,1,$3,$4,'CARTESIAN',$5,$6,$7,$8,0,$9,$10,$10) RETURNING id")
            .bind(&input.name).bind(input.enabled).bind(&input.resource_selector_json).bind(&input.node_selector_json).bind(input.interval_seconds).bind(input.jitter_seconds).bind(input.max_items).bind(input.next_run_at_ms).bind(input.created_by).bind(input.now_ms).fetch_one(&self.pool).await?)
    }
    async fn find_health_policy(&self, id: i64) -> Result<Option<HealthPolicyRecord>, DbError> {
        Ok(sqlx::query_as(
            "SELECT * FROM socks5_check_policies WHERE id=$1 AND deleted_at_ms IS NULL",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?)
    }
    async fn update_health_policy(
        &self,
        id: i64,
        expected_revision: i64,
        patch: &HealthPolicyPatch,
        now_ms: i64,
    ) -> Result<HealthPolicyRecord, DbError> {
        let row=sqlx::query_as("UPDATE socks5_check_policies SET name=COALESCE($1,name),enabled=COALESCE($2,enabled),resource_selector_json=COALESCE($3,resource_selector_json),node_selector_json=COALESCE($4,node_selector_json),interval_seconds=COALESCE($5,interval_seconds),jitter_seconds=COALESCE($6,jitter_seconds),max_items=COALESCE($7,max_items),next_run_at_ms=COALESCE($8,next_run_at_ms),revision=revision+1,updated_at_ms=$9 WHERE id=$10 AND revision=$11 AND deleted_at_ms IS NULL RETURNING *")
            .bind(&patch.name).bind(patch.enabled).bind(&patch.resource_selector_json).bind(&patch.node_selector_json).bind(patch.interval_seconds).bind(patch.jitter_seconds).bind(patch.max_items).bind(patch.next_run_at_ms).bind(now_ms).bind(id).bind(expected_revision).fetch_optional(&self.pool).await?;
        if let Some(row) = row {
            return Ok(row);
        }
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM socks5_check_policies WHERE id=$1 AND deleted_at_ms IS NULL)")
                .bind(id)
                .fetch_one(&self.pool)
                .await?;
        Err(if exists {
            DbError::RevisionConflict
        } else {
            DbError::NotFound
        })
    }
    async fn create_health_job(
        &self,
        job: &NewHealthJob,
        items: &[NewHealthJobItem],
    ) -> Result<HealthJobCreateOutcome, DbError> {
        let mut tx = self.pool.begin().await?;
        insert_job(&mut tx, job, items).await?;
        tx.commit().await?;
        Ok(HealthJobCreateOutcome::Created {
            job_id: job.id.clone(),
        })
    }
    async fn create_health_job_idempotent(
        &self,
        job: &NewHealthJob,
        items: &[NewHealthJobItem],
        key: &NewHealthJobIdempotency,
    ) -> Result<HealthJobCreateOutcome, DbError> {
        if job.actor_id != Some(key.actor_id)
            || job.request_fingerprint != key.request_fingerprint
            || key.expires_at_ms <= key.created_at_ms
        {
            return Err(DbError::ConstraintViolation);
        }
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock($1,hashtext($2))")
            .bind(HEALTH_IDEMPOTENCY_LOCK_CLASS)
            .bind(format!("{}:{}", key.actor_id, key.idempotency_key))
            .execute(&mut *tx)
            .await?;
        let existing:Option<(String,Option<String>,i64)>=sqlx::query_as("SELECT request_fingerprint,job_id,expires_at_ms FROM socks5_health_job_idempotency WHERE actor_id=$1 AND idempotency_key=$2 FOR UPDATE").bind(key.actor_id).bind(&key.idempotency_key).fetch_optional(&mut *tx).await?;
        if let Some((fingerprint, existing_job, expires)) = existing {
            if expires > key.created_at_ms {
                tx.commit().await?;
                return Ok(if fingerprint == key.request_fingerprint {
                    existing_job
                        .map(|job_id| HealthJobCreateOutcome::Replay { job_id })
                        .unwrap_or(HealthJobCreateOutcome::Conflict)
                } else {
                    HealthJobCreateOutcome::Conflict
                });
            }
            sqlx::query("DELETE FROM socks5_health_job_idempotency WHERE actor_id=$1 AND idempotency_key=$2").bind(key.actor_id).bind(&key.idempotency_key).execute(&mut *tx).await?;
        }
        insert_job(&mut tx, job, items).await?;
        sqlx::query("INSERT INTO socks5_health_job_idempotency(actor_id,idempotency_key,request_fingerprint,job_id,created_at_ms,expires_at_ms) VALUES($1,$2,$3,$4,$5,$6)").bind(key.actor_id).bind(&key.idempotency_key).bind(&key.request_fingerprint).bind(&job.id).bind(key.created_at_ms).bind(key.expires_at_ms).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(HealthJobCreateOutcome::Created {
            job_id: job.id.clone(),
        })
    }
    async fn lookup_health_job_idempotency(
        &self,
        actor_id: i64,
        idempotency_key: &str,
        request_fingerprint: &str,
        now_ms: i64,
    ) -> Result<HealthJobIdempotencyOutcome, DbError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock($1,hashtext($2))")
            .bind(HEALTH_IDEMPOTENCY_LOCK_CLASS)
            .bind(format!("{actor_id}:{idempotency_key}"))
            .execute(&mut *tx)
            .await?;
        let row:Option<(String,Option<String>,i64)>=sqlx::query_as("SELECT request_fingerprint,job_id,expires_at_ms FROM socks5_health_job_idempotency WHERE actor_id=$1 AND idempotency_key=$2 FOR UPDATE").bind(actor_id).bind(idempotency_key).fetch_optional(&mut *tx).await?;
        let outcome = match row {
            None => HealthJobIdempotencyOutcome::Available,
            Some((_, _, expires)) if expires <= now_ms => {
                sqlx::query("DELETE FROM socks5_health_job_idempotency WHERE actor_id=$1 AND idempotency_key=$2").bind(actor_id).bind(idempotency_key).execute(&mut *tx).await?;
                HealthJobIdempotencyOutcome::Available
            }
            Some((fingerprint, Some(job_id), _)) if fingerprint == request_fingerprint => {
                HealthJobIdempotencyOutcome::Replay { job_id }
            }
            Some(_) => HealthJobIdempotencyOutcome::Conflict,
        };
        tx.commit().await?;
        Ok(outcome)
    }
    async fn find_health_job(&self, id: &str) -> Result<Option<HealthJobRecord>, DbError> {
        Ok(
            sqlx::query_as("SELECT * FROM socks5_check_jobs WHERE id=$1")
                .bind(id)
                .fetch_optional(&self.pool)
                .await?,
        )
    }
    async fn list_health_job_items(
        &self,
        job_id: &str,
    ) -> Result<Vec<HealthJobItemRecord>, DbError> {
        Ok(
            sqlx::query_as("SELECT * FROM socks5_check_job_items WHERE job_id=$1 ORDER BY id")
                .bind(job_id)
                .fetch_all(&self.pool)
                .await?,
        )
    }
    async fn transition_health_job_item(
        &self,
        t: &HealthItemTransition,
    ) -> Result<ConditionalWriteOutcome, DbError> {
        let message = safe_error_message(
            t.safe_error_code.as_deref(),
            t.safe_error_message.as_deref(),
        )
        .map_err(|()| DbError::ConstraintViolation)?;
        if !t.expected_state.can_transition_to(t.new_state)
            || !validate_health_item_transition_fields(t)
        {
            return Err(DbError::InvalidTransition);
        }
        let mut tx = self.pool.begin().await?;
        let job_id: Option<String> =
            sqlx::query_scalar("SELECT job_id FROM socks5_check_job_items WHERE id=$1")
                .bind(t.item_id)
                .fetch_optional(&mut *tx)
                .await?;
        let Some(expected_job_id) = job_id else {
            tx.rollback().await?;
            return Ok(ConditionalWriteOutcome::NotFound);
        };
        let job_status: Option<String> =
            sqlx::query_scalar("SELECT status FROM socks5_check_jobs WHERE id=$1 FOR UPDATE")
                .bind(&expected_job_id)
                .fetch_optional(&mut *tx)
                .await?;
        let Some(job_status) = job_status else {
            tx.rollback().await?;
            return Ok(ConditionalWriteOutcome::NotFound);
        };
        if matches!(
            job_status.as_str(),
            "SUCCEEDED" | "FAILED" | "PARTIAL" | "CANCELLED" | "PARTIAL_CANCELLED"
        ) {
            tx.rollback().await?;
            return Ok(ConditionalWriteOutcome::ConditionFailed);
        }
        let row:Option<(String,String,i64)>=sqlx::query_as("SELECT job_id,state,item_fence_token FROM socks5_check_job_items WHERE id=$1 FOR UPDATE").bind(t.item_id).fetch_optional(&mut *tx).await?;
        let Some((job_id, state, fence)) = row else {
            tx.rollback().await?;
            return Ok(ConditionalWriteOutcome::NotFound);
        };
        if job_id != expected_job_id
            || state != t.expected_state.as_str()
            || fence != t.expected_fence
        {
            tx.rollback().await?;
            return Ok(ConditionalWriteOutcome::ConditionFailed);
        }
        let old = t.expected_state.counter_category();
        let new = t.new_state.counter_category();
        let terminal = t.new_state.is_terminal();
        sqlx::query("UPDATE socks5_check_job_items SET state=$1,item_fence_token=item_fence_token+1,lease_owner=$2,lease_expires_at_ms=$3,pair_fence_token=$4,dispatch_attempt_id=$5,request_id=$6,not_before_ms=COALESCE($7,not_before_ms),first_started_at_ms=CASE WHEN $1='LEASED' THEN COALESCE(first_started_at_ms,$8) ELSE first_started_at_ms END,last_started_at_ms=CASE WHEN $1='LEASED' THEN $8 ELSE last_started_at_ms END,health_status=$9,safe_error_code=$10,safe_error_message=$11,completed_after_cancel=$12,updated_at_ms=$8,finished_at_ms=$13 WHERE id=$14 AND state=$15 AND item_fence_token=$16")
            .bind(t.new_state.as_str()).bind(&t.lease_owner).bind(t.lease_expires_at_ms).bind(t.pair_fence_token).bind(&t.dispatch_attempt_id).bind(&t.request_id).bind(t.not_before_ms).bind(t.now_ms).bind(&t.health_status).bind(&t.safe_error_code).bind(message).bind(t.completed_after_cancel).bind(terminal.then_some(t.now_ms)).bind(t.item_id).bind(t.expected_state.as_str()).bind(t.expected_fence).execute(&mut *tx).await?;
        if old != new {
            let sql=format!("UPDATE socks5_check_jobs SET {old}={old}-1,{new}={new}+1,status=CASE WHEN status='QUEUED' THEN 'RUNNING' ELSE status END,started_at_ms=COALESCE(started_at_ms,$1) WHERE id=$2",old=counter_column(old),new=counter_column(new));
            sqlx::query(&sql)
                .bind(t.now_ms)
                .bind(&job_id)
                .execute(&mut *tx)
                .await?;
        }
        if terminal {
            aggregate_and_finalize(&mut tx, &job_id, t.now_ms).await?;
        }
        tx.commit().await?;
        Ok(ConditionalWriteOutcome::Applied)
    }
    async fn cancel_health_job(&self, job_id: &str, now_ms: i64) -> Result<bool, DbError> {
        let mut tx = self.pool.begin().await?;
        let status: Option<String> =
            sqlx::query_scalar("SELECT status FROM socks5_check_jobs WHERE id=$1 FOR UPDATE")
                .bind(job_id)
                .fetch_optional(&mut *tx)
                .await?;
        let Some(status) = status else {
            tx.rollback().await?;
            return Ok(false);
        };
        if matches!(
            status.as_str(),
            "SUCCEEDED" | "FAILED" | "PARTIAL" | "CANCELLED" | "PARTIAL_CANCELLED"
        ) {
            tx.commit().await?;
            return Ok(true);
        }
        sqlx::query("UPDATE socks5_check_jobs SET cancel_requested=TRUE,status='CANCEL_REQUESTED' WHERE id=$1").bind(job_id).execute(&mut *tx).await?;
        sqlx::query("UPDATE socks5_check_job_items SET state='CANCELLED',lease_owner=NULL,lease_expires_at_ms=NULL,pair_fence_token=NULL,dispatch_attempt_id=NULL,request_id=NULL,finished_at_ms=$1,updated_at_ms=$1 WHERE job_id=$2 AND state IN ('QUEUED','RETRY_WAIT')").bind(now_ms).bind(job_id).execute(&mut *tx).await?;
        aggregate_and_finalize(&mut tx, job_id, now_ms).await?;
        tx.commit().await?;
        Ok(true)
    }
    async fn finalize_health_job(&self, job_id: &str, now_ms: i64) -> Result<bool, DbError> {
        let mut tx = self.pool.begin().await?;
        let value = aggregate_and_finalize(&mut tx, job_id, now_ms).await?;
        tx.commit().await?;
        Ok(value)
    }
    async fn retry_failed_health_pairs(
        &self,
        parent_job_id: &str,
    ) -> Result<Vec<(i64, i64)>, DbError> {
        let terminal:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM socks5_check_jobs WHERE id=$1 AND status IN ('SUCCEEDED','FAILED','PARTIAL','CANCELLED','PARTIAL_CANCELLED'))").bind(parent_job_id).fetch_one(&self.pool).await?;
        if !terminal {
            return Err(DbError::InvalidTransition);
        }
        Ok(sqlx::query_as("SELECT resource_id_snapshot,relay_node_id_snapshot FROM socks5_check_job_items WHERE job_id=$1 AND state='FAILED' ORDER BY resource_id_snapshot,relay_node_id_snapshot").bind(parent_job_id).fetch_all(&self.pool).await?)
    }
    async fn acquire_health_pair_lease(
        &self,
        r: PairLeaseAcquireRequest<'_>,
    ) -> Result<PairLeaseAcquireOutcome, DbError> {
        if r.resource_id <= 0
            || r.relay_node_id <= 0
            || r.item_id <= 0
            || r.lease_owner.is_empty()
            || r.lease_expires_at_ms <= r.now_ms
        {
            return Err(DbError::ConstraintViolation);
        }
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock($1,hashtext($2))")
            .bind(HEALTH_PAIR_LEASE_LOCK_CLASS)
            .bind(format!("{}:{}", r.resource_id, r.relay_node_id))
            .execute(&mut *tx)
            .await?;
        let item: Option<(i64, i64, String)> = sqlx::query_as(
            "SELECT resource_id_snapshot,relay_node_id_snapshot,state FROM socks5_check_job_items WHERE id=$1 FOR UPDATE",
        )
        .bind(r.item_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((resource_snapshot, node_snapshot, state)) = item else {
            tx.rollback().await?;
            return Err(DbError::NotFound);
        };
        if resource_snapshot != r.resource_id
            || node_snapshot != r.relay_node_id
            || !matches!(
                state.as_str(),
                "QUEUED" | "LEASED" | "DISPATCHING" | "IN_FLIGHT" | "RETRY_WAIT"
            )
        {
            tx.rollback().await?;
            return Err(DbError::InvalidTransition);
        }
        let row:Option<(Option<String>,Option<i64>,i64)>=sqlx::query_as("SELECT lease_owner,lease_expires_at_ms,pair_fence_token FROM socks5_check_pair_leases WHERE resource_id=$1 AND relay_node_id=$2 FOR UPDATE").bind(r.resource_id).bind(r.relay_node_id).fetch_optional(&mut *tx).await?;
        let token = match row {
            None => {
                sqlx::query("INSERT INTO socks5_check_pair_leases(resource_id,relay_node_id,item_id,lease_owner,lease_expires_at_ms,pair_fence_token,updated_at_ms) VALUES($1,$2,$3,$4,$5,1,$6)").bind(r.resource_id).bind(r.relay_node_id).bind(r.item_id).bind(r.lease_owner).bind(r.lease_expires_at_ms).bind(r.now_ms).execute(&mut *tx).await?;
                1
            }
            Some((owner, expires, token))
                if owner.is_none() || expires.is_some_and(|value| value <= r.now_ms) =>
            {
                let next = token.checked_add(1).ok_or(DbError::ConstraintViolation)?;
                sqlx::query("UPDATE socks5_check_pair_leases SET item_id=$1,lease_owner=$2,lease_expires_at_ms=$3,pair_fence_token=$4,updated_at_ms=$5 WHERE resource_id=$6 AND relay_node_id=$7").bind(r.item_id).bind(r.lease_owner).bind(r.lease_expires_at_ms).bind(next).bind(r.now_ms).bind(r.resource_id).bind(r.relay_node_id).execute(&mut *tx).await?;
                next
            }
            Some(_) => {
                tx.commit().await?;
                return Ok(PairLeaseAcquireOutcome::Busy);
            }
        };
        tx.commit().await?;
        Ok(PairLeaseAcquireOutcome::Acquired {
            pair_fence_token: token,
        })
    }
    async fn renew_health_pair_lease(
        &self,
        resource_id: i64,
        relay_node_id: i64,
        item_id: i64,
        lease_owner: &str,
        expected_pair_fence: i64,
        lease_expires_at_ms: i64,
        now_ms: i64,
    ) -> Result<ConditionalWriteOutcome, DbError> {
        if lease_owner.is_empty() || lease_expires_at_ms <= now_ms {
            return Err(DbError::ConstraintViolation);
        }
        let result=sqlx::query("UPDATE socks5_check_pair_leases SET lease_expires_at_ms=$1,updated_at_ms=$2 WHERE resource_id=$3 AND relay_node_id=$4 AND item_id=$5 AND lease_owner=$6 AND pair_fence_token=$7").bind(lease_expires_at_ms).bind(now_ms).bind(resource_id).bind(relay_node_id).bind(item_id).bind(lease_owner).bind(expected_pair_fence).execute(&self.pool).await?;
        Ok(if result.rows_affected() == 1 {
            ConditionalWriteOutcome::Applied
        } else {
            ConditionalWriteOutcome::ConditionFailed
        })
    }
    async fn release_health_pair_lease(
        &self,
        resource_id: i64,
        relay_node_id: i64,
        item_id: i64,
        lease_owner: &str,
        expected_pair_fence: i64,
        now_ms: i64,
    ) -> Result<ConditionalWriteOutcome, DbError> {
        let result=sqlx::query("UPDATE socks5_check_pair_leases SET item_id=NULL,lease_owner=NULL,lease_expires_at_ms=NULL,updated_at_ms=$1 WHERE resource_id=$2 AND relay_node_id=$3 AND item_id=$4 AND lease_owner=$5 AND pair_fence_token=$6").bind(now_ms).bind(resource_id).bind(relay_node_id).bind(item_id).bind(lease_owner).bind(expected_pair_fence).execute(&self.pool).await?;
        Ok(if result.rows_affected() == 1 {
            ConditionalWriteOutcome::Applied
        } else {
            ConditionalWriteOutcome::ConditionFailed
        })
    }
    async fn find_health_pair_lease(
        &self,
        resource_id: i64,
        relay_node_id: i64,
    ) -> Result<Option<HealthPairLeaseRecord>, DbError> {
        Ok(sqlx::query_as(
            "SELECT * FROM socks5_check_pair_leases WHERE resource_id=$1 AND relay_node_id=$2",
        )
        .bind(resource_id)
        .bind(relay_node_id)
        .fetch_optional(&self.pool)
        .await?)
    }

    async fn list_terminal_health_job_prune_candidates(
        &self,
        cutoff_ms: i64,
        limit: i64,
    ) -> Result<Vec<String>, DbError> {
        Ok(sqlx::query_scalar(
            "SELECT j.id FROM socks5_check_jobs j
             WHERE j.status IN ('SUCCEEDED','FAILED','PARTIAL','CANCELLED','PARTIAL_CANCELLED')
               AND j.finished_at_ms < $1
               AND NOT EXISTS (SELECT 1 FROM socks5_check_jobs child WHERE child.parent_job_id=j.id)
             ORDER BY j.finished_at_ms,j.id LIMIT $2",
        )
        .bind(cutoff_ms)
        .bind(limit.clamp(0, 1000))
        .fetch_all(&self.pool)
        .await?)
    }

    async fn prune_terminal_health_jobs(&self, cutoff_ms: i64, limit: i64) -> Result<u64, DbError> {
        let result=sqlx::query("DELETE FROM socks5_check_jobs WHERE id IN (SELECT j.id FROM socks5_check_jobs j WHERE j.status IN ('SUCCEEDED','FAILED','PARTIAL','CANCELLED','PARTIAL_CANCELLED') AND j.finished_at_ms < $1 AND NOT EXISTS (SELECT 1 FROM socks5_check_jobs child WHERE child.parent_job_id=j.id) ORDER BY j.finished_at_ms,j.id LIMIT $2)").bind(cutoff_ms).bind(limit.clamp(0,1000)).execute(&self.pool).await?;
        Ok(result.rows_affected())
    }

    async fn list_released_health_pair_lease_prune_candidates(
        &self,
        cutoff_ms: i64,
        limit: i64,
    ) -> Result<Vec<(i64, i64)>, DbError> {
        Ok(sqlx::query_as(
            "SELECT l.resource_id,l.relay_node_id FROM socks5_check_pair_leases l
             WHERE l.lease_owner IS NULL AND l.item_id IS NULL AND l.updated_at_ms < $1
               AND NOT EXISTS (SELECT 1 FROM socks5_check_job_items i
                   WHERE i.resource_id_snapshot=l.resource_id AND i.relay_node_id_snapshot=l.relay_node_id
                     AND i.state IN ('QUEUED','LEASED','DISPATCHING','IN_FLIGHT','RETRY_WAIT'))
             ORDER BY updated_at_ms,resource_id,relay_node_id LIMIT $2",
        )
        .bind(cutoff_ms)
        .bind(limit.clamp(0, 1000))
        .fetch_all(&self.pool)
        .await?)
    }

    async fn prune_released_health_pair_leases(
        &self,
        cutoff_ms: i64,
        limit: i64,
    ) -> Result<u64, DbError> {
        let result=sqlx::query("UPDATE socks5_check_pair_leases l SET updated_at_ms=$3 WHERE (l.resource_id,l.relay_node_id) IN (SELECT candidate.resource_id,candidate.relay_node_id FROM socks5_check_pair_leases candidate WHERE candidate.lease_owner IS NULL AND candidate.item_id IS NULL AND candidate.updated_at_ms < $1 AND NOT EXISTS (SELECT 1 FROM socks5_check_job_items i WHERE i.resource_id_snapshot=candidate.resource_id AND i.relay_node_id_snapshot=candidate.relay_node_id AND i.state IN ('QUEUED','LEASED','DISPATCHING','IN_FLIGHT','RETRY_WAIT')) ORDER BY candidate.updated_at_ms LIMIT $2) AND l.lease_owner IS NULL AND l.item_id IS NULL AND NOT EXISTS (SELECT 1 FROM socks5_check_job_items i WHERE i.resource_id_snapshot=l.resource_id AND i.relay_node_id_snapshot=l.relay_node_id AND i.state IN ('QUEUED','LEASED','DISPATCHING','IN_FLIGHT','RETRY_WAIT'))").bind(cutoff_ms).bind(limit.clamp(0,1000)).bind(PAIR_LEASE_TOMBSTONE_UPDATED_AT_MS).execute(&self.pool).await?;
        Ok(result.rows_affected())
    }
    async fn prune_expired_health_job_idempotency(
        &self,
        cutoff_ms: i64,
        limit: i64,
    ) -> Result<u64, DbError> {
        let result=sqlx::query("DELETE FROM socks5_health_job_idempotency WHERE (actor_id,idempotency_key) IN (SELECT actor_id,idempotency_key FROM socks5_health_job_idempotency WHERE expires_at_ms <= $1 ORDER BY expires_at_ms LIMIT $2)").bind(cutoff_ms).bind(limit.clamp(0,1000)).execute(&self.pool).await?;
        Ok(result.rows_affected())
    }
}
