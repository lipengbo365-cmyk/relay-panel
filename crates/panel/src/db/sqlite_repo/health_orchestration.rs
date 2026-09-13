use super::SqliteRepository;
use crate::db::error::DbError;
use crate::db::health_orchestration::{
    safe_error_message, ConditionalWriteOutcome, HealthCounterCategory, HealthItemTransition,
    HealthJobCreateOutcome, HealthJobIdempotencyOutcome, HealthJobItemRecord, HealthJobRecord,
    HealthPairLeaseRecord, HealthPolicyPatch, HealthPolicyRecord, NewHealthJob,
    NewHealthJobIdempotency, NewHealthJobItem, NewHealthPolicy, PairLeaseAcquireOutcome,
    PairLeaseAcquireRequest, HEALTH_RETRY_POLICY_VERSION,
};
use crate::db::repo::HealthOrchestrationRepository;
use async_trait::async_trait;
use sqlx::SqliteConnection;

async fn begin_immediate(
    pool: &sqlx::SqlitePool,
) -> Result<sqlx::pool::PoolConnection<sqlx::Sqlite>, DbError> {
    let mut conn = pool.acquire().await?;
    sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;
    Ok(conn)
}

async fn rollback(conn: &mut SqliteConnection) {
    let _ = sqlx::query("ROLLBACK").execute(conn).await;
}

async fn insert_job(
    conn: &mut SqliteConnection,
    job: &NewHealthJob,
    items: &[NewHealthJobItem],
) -> Result<(), DbError> {
    if items.is_empty() {
        return Err(DbError::ConstraintViolation);
    }
    let total = i64::try_from(items.len()).map_err(|_| DbError::ConstraintViolation)?;
    sqlx::query(
        "INSERT INTO socks5_check_jobs
         (id,source,policy_id,parent_job_id,actor_id,status,request_fingerprint,snapshot_hash,
          resource_selector_json,node_selector_json,matrix_mode,retry_policy_version,scheduled_for_ms,
          cancel_requested,total_items,queued_count,running_count,succeeded_count,failed_count,
          cancelled_count,created_at_ms)
         VALUES(?,?,?,?,?,'QUEUED',?,?,?,?,'CARTESIAN',?,?,0,?,?,0,0,0,0,?)",
    )
    .bind(&job.id)
    .bind(job.source.as_str())
    .bind(job.policy_id)
    .bind(&job.parent_job_id)
    .bind(job.actor_id)
    .bind(&job.request_fingerprint)
    .bind(&job.snapshot_hash)
    .bind(&job.resource_selector_json)
    .bind(&job.node_selector_json)
    .bind(HEALTH_RETRY_POLICY_VERSION)
    .bind(job.scheduled_for_ms)
    .bind(total)
    .bind(total)
    .bind(job.created_at_ms)
    .execute(&mut *conn)
    .await?;
    for item in items {
        sqlx::query(
            "INSERT INTO socks5_check_job_items
             (job_id,resource_id,relay_node_id,resource_id_snapshot,relay_node_id_snapshot,
              state,attempt_count,item_fence_token,not_before_ms,deadline_at_ms,
              completed_after_cancel,created_at_ms,updated_at_ms)
             VALUES(?,?,?,?,?,'QUEUED',0,0,?,?,0,?,?)",
        )
        .bind(&job.id)
        .bind(item.resource_id)
        .bind(item.relay_node_id)
        .bind(item.resource_id)
        .bind(item.relay_node_id)
        .bind(item.not_before_ms)
        .bind(item.deadline_at_ms)
        .bind(job.created_at_ms)
        .bind(job.created_at_ms)
        .execute(&mut *conn)
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
    conn: &mut SqliteConnection,
    job_id: &str,
    now_ms: i64,
) -> Result<bool, DbError> {
    let counts: Option<(i64, i64, i64, i64, i64)> = sqlx::query_as(
        "SELECT
           SUM(CASE WHEN state IN ('QUEUED','RETRY_WAIT') THEN 1 ELSE 0 END),
           SUM(CASE WHEN state IN ('LEASED','DISPATCHING','IN_FLIGHT') THEN 1 ELSE 0 END),
           SUM(CASE WHEN state='SUCCEEDED' THEN 1 ELSE 0 END),
           SUM(CASE WHEN state='FAILED' THEN 1 ELSE 0 END),
           SUM(CASE WHEN state='CANCELLED' THEN 1 ELSE 0 END)
         FROM socks5_check_job_items WHERE job_id=? HAVING COUNT(*)>0",
    )
    .bind(job_id)
    .fetch_optional(&mut *conn)
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
        let cancel_requested: bool =
            sqlx::query_scalar("SELECT cancel_requested FROM socks5_check_jobs WHERE id=?")
                .bind(job_id)
                .fetch_one(&mut *conn)
                .await?;
        if cancel_requested {
            "CANCEL_REQUESTED"
        } else {
            "RUNNING"
        }
    };
    let result = sqlx::query(
        "UPDATE socks5_check_jobs SET status=?,total_items=?,queued_count=?,running_count=?,
         succeeded_count=?,failed_count=?,cancelled_count=?,finished_at_ms=? WHERE id=?",
    )
    .bind(status)
    .bind(total)
    .bind(queued)
    .bind(running)
    .bind(succeeded)
    .bind(failed)
    .bind(cancelled)
    .bind(terminal.then_some(now_ms))
    .bind(job_id)
    .execute(&mut *conn)
    .await?;
    Ok(result.rows_affected() == 1)
}

#[async_trait]
impl HealthOrchestrationRepository for SqliteRepository {
    async fn create_health_policy(&self, input: &NewHealthPolicy) -> Result<i64, DbError> {
        let result = sqlx::query(
            "INSERT INTO socks5_check_policies
             (name,enabled,revision,resource_selector_json,node_selector_json,matrix_mode,
              interval_seconds,jitter_seconds,max_items,next_run_at_ms,skipped_overlap_count,
              created_by,created_at_ms,updated_at_ms)
             VALUES(?,?,1,?,?,'CARTESIAN',?,?,?,?,0,?,?,?)",
        )
        .bind(&input.name)
        .bind(input.enabled)
        .bind(&input.resource_selector_json)
        .bind(&input.node_selector_json)
        .bind(input.interval_seconds)
        .bind(input.jitter_seconds)
        .bind(input.max_items)
        .bind(input.next_run_at_ms)
        .bind(input.created_by)
        .bind(input.now_ms)
        .bind(input.now_ms)
        .execute(&self.pool)
        .await?;
        Ok(result.last_insert_rowid())
    }

    async fn find_health_policy(&self, id: i64) -> Result<Option<HealthPolicyRecord>, DbError> {
        Ok(
            sqlx::query_as("SELECT * FROM socks5_check_policies WHERE id=?")
                .bind(id)
                .fetch_optional(&self.pool)
                .await?,
        )
    }

    async fn update_health_policy(
        &self,
        id: i64,
        expected_revision: i64,
        patch: &HealthPolicyPatch,
        now_ms: i64,
    ) -> Result<HealthPolicyRecord, DbError> {
        let result = sqlx::query(
            "UPDATE socks5_check_policies SET name=COALESCE(?,name),enabled=COALESCE(?,enabled),
             resource_selector_json=COALESCE(?,resource_selector_json),node_selector_json=COALESCE(?,node_selector_json),
             interval_seconds=COALESCE(?,interval_seconds),jitter_seconds=COALESCE(?,jitter_seconds),
             max_items=COALESCE(?,max_items),next_run_at_ms=COALESCE(?,next_run_at_ms),
             revision=revision+1,updated_at_ms=? WHERE id=? AND revision=?"
        ).bind(&patch.name).bind(patch.enabled).bind(&patch.resource_selector_json)
        .bind(&patch.node_selector_json).bind(patch.interval_seconds).bind(patch.jitter_seconds)
        .bind(patch.max_items).bind(patch.next_run_at_ms).bind(now_ms).bind(id).bind(expected_revision)
        .execute(&self.pool).await?;
        if result.rows_affected() == 0 {
            let exists: bool =
                sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM socks5_check_policies WHERE id=?)")
                    .bind(id)
                    .fetch_one(&self.pool)
                    .await?;
            return Err(if exists {
                DbError::RevisionConflict
            } else {
                DbError::NotFound
            });
        }
        self.find_health_policy(id).await?.ok_or(DbError::NotFound)
    }

    async fn create_health_job(
        &self,
        job: &NewHealthJob,
        items: &[NewHealthJobItem],
    ) -> Result<HealthJobCreateOutcome, DbError> {
        let mut conn = begin_immediate(&self.pool).await?;
        if let Err(error) = insert_job(&mut conn, job, items).await {
            rollback(&mut conn).await;
            return Err(error);
        }
        sqlx::query("COMMIT").execute(&mut *conn).await?;
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
        let mut conn = begin_immediate(&self.pool).await?;
        let existing: Option<(String,Option<String>,i64)> = sqlx::query_as(
            "SELECT request_fingerprint,job_id,expires_at_ms FROM socks5_health_job_idempotency WHERE actor_id=? AND idempotency_key=?"
        ).bind(key.actor_id).bind(&key.idempotency_key).fetch_optional(&mut *conn).await?;
        if let Some((fingerprint, existing_job, expires)) = existing {
            if expires > key.created_at_ms {
                sqlx::query("COMMIT").execute(&mut *conn).await?;
                return Ok(if fingerprint == key.request_fingerprint {
                    existing_job
                        .map(|job_id| HealthJobCreateOutcome::Replay { job_id })
                        .unwrap_or(HealthJobCreateOutcome::Conflict)
                } else {
                    HealthJobCreateOutcome::Conflict
                });
            }
            sqlx::query(
                "DELETE FROM socks5_health_job_idempotency WHERE actor_id=? AND idempotency_key=?",
            )
            .bind(key.actor_id)
            .bind(&key.idempotency_key)
            .execute(&mut *conn)
            .await?;
        }
        if let Err(error) = insert_job(&mut conn, job, items).await {
            rollback(&mut conn).await;
            return Err(error);
        }
        if let Err(error)=sqlx::query(
            "INSERT INTO socks5_health_job_idempotency(actor_id,idempotency_key,request_fingerprint,job_id,created_at_ms,expires_at_ms) VALUES(?,?,?,?,?,?)"
        ).bind(key.actor_id).bind(&key.idempotency_key).bind(&key.request_fingerprint).bind(&job.id)
        .bind(key.created_at_ms).bind(key.expires_at_ms).execute(&mut *conn).await.map_err(DbError::from) {
            rollback(&mut conn).await; return Err(error);
        }
        sqlx::query("COMMIT").execute(&mut *conn).await?;
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
        let mut conn = begin_immediate(&self.pool).await?;
        let row:Option<(String,Option<String>,i64)>=sqlx::query_as("SELECT request_fingerprint,job_id,expires_at_ms FROM socks5_health_job_idempotency WHERE actor_id=? AND idempotency_key=?")
            .bind(actor_id).bind(idempotency_key).fetch_optional(&mut *conn).await?;
        let outcome = match row {
            None => HealthJobIdempotencyOutcome::Available,
            Some((_, _, expires)) if expires <= now_ms => {
                sqlx::query("DELETE FROM socks5_health_job_idempotency WHERE actor_id=? AND idempotency_key=?").bind(actor_id).bind(idempotency_key).execute(&mut *conn).await?;
                HealthJobIdempotencyOutcome::Available
            }
            Some((fingerprint, Some(job_id), _)) if fingerprint == request_fingerprint => {
                HealthJobIdempotencyOutcome::Replay { job_id }
            }
            Some(_) => HealthJobIdempotencyOutcome::Conflict,
        };
        sqlx::query("COMMIT").execute(&mut *conn).await?;
        Ok(outcome)
    }

    async fn find_health_job(&self, id: &str) -> Result<Option<HealthJobRecord>, DbError> {
        Ok(sqlx::query_as("SELECT * FROM socks5_check_jobs WHERE id=?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?)
    }
    async fn list_health_job_items(
        &self,
        job_id: &str,
    ) -> Result<Vec<HealthJobItemRecord>, DbError> {
        Ok(
            sqlx::query_as("SELECT * FROM socks5_check_job_items WHERE job_id=? ORDER BY id")
                .bind(job_id)
                .fetch_all(&self.pool)
                .await?,
        )
    }

    async fn transition_health_job_item(
        &self,
        t: &HealthItemTransition,
    ) -> Result<ConditionalWriteOutcome, DbError> {
        if !t.expected_state.can_transition_to(t.new_state) {
            return Err(DbError::InvalidTransition);
        }
        let mut conn = begin_immediate(&self.pool).await?;
        let row: Option<(String, String, i64)> = sqlx::query_as(
            "SELECT job_id,state,item_fence_token FROM socks5_check_job_items WHERE id=?",
        )
        .bind(t.item_id)
        .fetch_optional(&mut *conn)
        .await?;
        let Some((job_id, state, fence)) = row else {
            rollback(&mut conn).await;
            return Ok(ConditionalWriteOutcome::NotFound);
        };
        if state != t.expected_state.as_str() || fence != t.expected_fence {
            rollback(&mut conn).await;
            return Ok(ConditionalWriteOutcome::ConditionFailed);
        }
        let old = t.expected_state.counter_category();
        let new = t.new_state.counter_category();
        let message = safe_error_message(t.safe_error_message.as_deref());
        let terminal = t.new_state.is_terminal();
        sqlx::query("UPDATE socks5_check_job_items SET state=?,item_fence_token=item_fence_token+1,lease_owner=?,lease_expires_at_ms=?,pair_fence_token=?,dispatch_attempt_id=?,request_id=?,not_before_ms=COALESCE(?,not_before_ms),first_started_at_ms=CASE WHEN ?='LEASED' THEN COALESCE(first_started_at_ms,?) ELSE first_started_at_ms END,last_started_at_ms=CASE WHEN ?='LEASED' THEN ? ELSE last_started_at_ms END,health_status=?,safe_error_code=?,safe_error_message=?,completed_after_cancel=?,updated_at_ms=?,finished_at_ms=? WHERE id=? AND state=? AND item_fence_token=?")
            .bind(t.new_state.as_str()).bind(&t.lease_owner).bind(t.lease_expires_at_ms).bind(t.pair_fence_token).bind(&t.dispatch_attempt_id).bind(&t.request_id).bind(t.not_before_ms)
            .bind(t.new_state.as_str()).bind(t.now_ms).bind(t.new_state.as_str()).bind(t.now_ms).bind(&t.health_status).bind(&t.safe_error_code).bind(message).bind(t.completed_after_cancel).bind(t.now_ms).bind(terminal.then_some(t.now_ms)).bind(t.item_id).bind(t.expected_state.as_str()).bind(t.expected_fence)
            .execute(&mut *conn).await?;
        if old != new {
            let sql=format!("UPDATE socks5_check_jobs SET {old}={old}-1,{new}={new}+1,status=CASE WHEN status='QUEUED' THEN 'RUNNING' ELSE status END,started_at_ms=CASE WHEN started_at_ms IS NULL THEN ? ELSE started_at_ms END WHERE id=?",old=counter_column(old),new=counter_column(new));
            sqlx::query(&sql)
                .bind(t.now_ms)
                .bind(&job_id)
                .execute(&mut *conn)
                .await?;
        }
        sqlx::query("COMMIT").execute(&mut *conn).await?;
        Ok(ConditionalWriteOutcome::Applied)
    }

    async fn cancel_health_job(&self, job_id: &str, now_ms: i64) -> Result<bool, DbError> {
        let mut conn = begin_immediate(&self.pool).await?;
        let status: Option<String> =
            sqlx::query_scalar("SELECT status FROM socks5_check_jobs WHERE id=?")
                .bind(job_id)
                .fetch_optional(&mut *conn)
                .await?;
        let Some(status) = status else {
            rollback(&mut conn).await;
            return Ok(false);
        };
        if matches!(
            status.as_str(),
            "SUCCEEDED" | "FAILED" | "PARTIAL" | "CANCELLED" | "PARTIAL_CANCELLED"
        ) {
            sqlx::query("COMMIT").execute(&mut *conn).await?;
            return Ok(true);
        }
        sqlx::query(
            "UPDATE socks5_check_jobs SET cancel_requested=1,status='CANCEL_REQUESTED' WHERE id=?",
        )
        .bind(job_id)
        .execute(&mut *conn)
        .await?;
        sqlx::query("UPDATE socks5_check_job_items SET state='CANCELLED',lease_owner=NULL,lease_expires_at_ms=NULL,finished_at_ms=?,updated_at_ms=? WHERE job_id=? AND state IN ('QUEUED','RETRY_WAIT')")
            .bind(now_ms).bind(now_ms).bind(job_id).execute(&mut *conn).await?;
        aggregate_and_finalize(&mut conn, job_id, now_ms).await?;
        sqlx::query("COMMIT").execute(&mut *conn).await?;
        Ok(true)
    }

    async fn finalize_health_job(&self, job_id: &str, now_ms: i64) -> Result<bool, DbError> {
        let mut conn = begin_immediate(&self.pool).await?;
        let result = aggregate_and_finalize(&mut conn, job_id, now_ms).await;
        match result {
            Ok(value) => {
                sqlx::query("COMMIT").execute(&mut *conn).await?;
                Ok(value)
            }
            Err(error) => {
                rollback(&mut conn).await;
                Err(error)
            }
        }
    }

    async fn retry_failed_health_pairs(
        &self,
        parent_job_id: &str,
    ) -> Result<Vec<(i64, i64)>, DbError> {
        let terminal:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM socks5_check_jobs WHERE id=? AND status IN ('SUCCEEDED','FAILED','PARTIAL','CANCELLED','PARTIAL_CANCELLED'))").bind(parent_job_id).fetch_one(&self.pool).await?;
        if !terminal {
            return Err(DbError::InvalidTransition);
        }
        Ok(sqlx::query_as("SELECT resource_id_snapshot,relay_node_id_snapshot FROM socks5_check_job_items WHERE job_id=? AND state='FAILED' ORDER BY resource_id_snapshot,relay_node_id_snapshot").bind(parent_job_id).fetch_all(&self.pool).await?)
    }

    async fn acquire_health_pair_lease(
        &self,
        r: PairLeaseAcquireRequest<'_>,
    ) -> Result<PairLeaseAcquireOutcome, DbError> {
        let mut conn = begin_immediate(&self.pool).await?;
        let row:Option<(Option<String>,Option<i64>,i64)>=sqlx::query_as("SELECT lease_owner,lease_expires_at_ms,pair_fence_token FROM socks5_check_pair_leases WHERE resource_id=? AND relay_node_id=?").bind(r.resource_id).bind(r.relay_node_id).fetch_optional(&mut *conn).await?;
        let token = match row {
            None => {
                sqlx::query("INSERT INTO socks5_check_pair_leases(resource_id,relay_node_id,item_id,lease_owner,lease_expires_at_ms,pair_fence_token,updated_at_ms) VALUES(?,?,?,?,?,1,?)").bind(r.resource_id).bind(r.relay_node_id).bind(r.item_id).bind(r.lease_owner).bind(r.lease_expires_at_ms).bind(r.now_ms).execute(&mut *conn).await?;
                1
            }
            Some((owner, expires, token))
                if owner.is_none() || expires.is_some_and(|value| value <= r.now_ms) =>
            {
                let next = token.checked_add(1).ok_or(DbError::ConstraintViolation)?;
                sqlx::query("UPDATE socks5_check_pair_leases SET item_id=?,lease_owner=?,lease_expires_at_ms=?,pair_fence_token=?,updated_at_ms=? WHERE resource_id=? AND relay_node_id=?").bind(r.item_id).bind(r.lease_owner).bind(r.lease_expires_at_ms).bind(next).bind(r.now_ms).bind(r.resource_id).bind(r.relay_node_id).execute(&mut *conn).await?;
                next
            }
            Some(_) => {
                sqlx::query("COMMIT").execute(&mut *conn).await?;
                return Ok(PairLeaseAcquireOutcome::Busy);
            }
        };
        sqlx::query("COMMIT").execute(&mut *conn).await?;
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
        let result=sqlx::query("UPDATE socks5_check_pair_leases SET lease_expires_at_ms=?,updated_at_ms=? WHERE resource_id=? AND relay_node_id=? AND item_id=? AND lease_owner=? AND pair_fence_token=?").bind(lease_expires_at_ms).bind(now_ms).bind(resource_id).bind(relay_node_id).bind(item_id).bind(lease_owner).bind(expected_pair_fence).execute(&self.pool).await?;
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
        let result=sqlx::query("UPDATE socks5_check_pair_leases SET item_id=NULL,lease_owner=NULL,lease_expires_at_ms=NULL,updated_at_ms=? WHERE resource_id=? AND relay_node_id=? AND item_id=? AND lease_owner=? AND pair_fence_token=?").bind(now_ms).bind(resource_id).bind(relay_node_id).bind(item_id).bind(lease_owner).bind(expected_pair_fence).execute(&self.pool).await?;
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
            "SELECT * FROM socks5_check_pair_leases WHERE resource_id=? AND relay_node_id=?",
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
               AND j.finished_at_ms < ?
               AND NOT EXISTS (SELECT 1 FROM socks5_check_jobs child WHERE child.parent_job_id=j.id)
             ORDER BY j.finished_at_ms,j.id LIMIT ?",
        )
        .bind(cutoff_ms)
        .bind(limit.clamp(0, 1000))
        .fetch_all(&self.pool)
        .await?)
    }

    async fn prune_terminal_health_jobs(&self, cutoff_ms: i64, limit: i64) -> Result<u64, DbError> {
        let result=sqlx::query("DELETE FROM socks5_check_jobs WHERE id IN (SELECT j.id FROM socks5_check_jobs j WHERE j.status IN ('SUCCEEDED','FAILED','PARTIAL','CANCELLED','PARTIAL_CANCELLED') AND j.finished_at_ms < ? AND NOT EXISTS (SELECT 1 FROM socks5_check_jobs child WHERE child.parent_job_id=j.id) ORDER BY j.finished_at_ms,j.id LIMIT ?)").bind(cutoff_ms).bind(limit.clamp(0,1000)).execute(&self.pool).await?;
        Ok(result.rows_affected())
    }

    async fn list_released_health_pair_lease_prune_candidates(
        &self,
        cutoff_ms: i64,
        limit: i64,
    ) -> Result<Vec<(i64, i64)>, DbError> {
        Ok(sqlx::query_as(
            "SELECT resource_id,relay_node_id FROM socks5_check_pair_leases
             WHERE lease_owner IS NULL AND item_id IS NULL AND updated_at_ms < ?
             ORDER BY updated_at_ms,resource_id,relay_node_id LIMIT ?",
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
        let result=sqlx::query("DELETE FROM socks5_check_pair_leases WHERE rowid IN (SELECT rowid FROM socks5_check_pair_leases WHERE lease_owner IS NULL AND item_id IS NULL AND updated_at_ms < ? ORDER BY updated_at_ms LIMIT ?)").bind(cutoff_ms).bind(limit.clamp(0,1000)).execute(&self.pool).await?;
        Ok(result.rows_affected())
    }
    async fn prune_expired_health_job_idempotency(
        &self,
        cutoff_ms: i64,
        limit: i64,
    ) -> Result<u64, DbError> {
        let result=sqlx::query("DELETE FROM socks5_health_job_idempotency WHERE rowid IN (SELECT rowid FROM socks5_health_job_idempotency WHERE expires_at_ms <= ? ORDER BY expires_at_ms LIMIT ?)").bind(cutoff_ms).bind(limit.clamp(0,1000)).execute(&self.pool).await?;
        Ok(result.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::health_orchestration::{
        snapshot_hash, HealthJobItemState, HealthJobSource, HealthJobStatus, IDEMPOTENCY_TTL_MS,
    };
    use crate::db::schema::{run_migrations, SCHEMA_SQL};
    use sqlx::sqlite::SqlitePoolOptions;

    async fn fixture() -> (SqliteRepository, i64, i64) {
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
            "INSERT INTO device_groups(name,group_type,token,uid) VALUES('health','in','health-token',1)",
        )
        .execute(&pool)
        .await
        .unwrap()
        .last_insert_rowid();
        let resource = sqlx::query(
            "INSERT INTO socks5_resources(name,host,port) VALUES('r','127.0.0.1',1080)",
        )
        .execute(&pool)
        .await
        .unwrap()
        .last_insert_rowid();
        let node = sqlx::query("INSERT INTO relay_nodes(device_group_id,node_key,first_seen_at,last_seen_at) VALUES(?,'n','2026-01-01','2026-01-01')")
            .bind(group).execute(&pool).await.unwrap().last_insert_rowid();
        (SqliteRepository::new(pool), resource, node)
    }

    fn job(
        id: &str,
        resource: i64,
        node: i64,
        actor_id: Option<i64>,
    ) -> (NewHealthJob, Vec<NewHealthJobItem>) {
        (
            NewHealthJob {
                id: id.into(),
                source: HealthJobSource::Manual,
                policy_id: None,
                parent_job_id: None,
                actor_id,
                request_fingerprint: "a".repeat(64),
                snapshot_hash: snapshot_hash(&[(resource, node)]),
                resource_selector_json: "{}".into(),
                node_selector_json: "{}".into(),
                scheduled_for_ms: None,
                created_at_ms: 1_000,
            },
            vec![NewHealthJobItem {
                resource_id: resource,
                relay_node_id: node,
                not_before_ms: 1_000,
                deadline_at_ms: Some(10_000),
            }],
        )
    }

    fn transition(
        item_id: i64,
        from: HealthJobItemState,
        fence: i64,
        to: HealthJobItemState,
        now_ms: i64,
    ) -> HealthItemTransition {
        let running = matches!(
            to,
            HealthJobItemState::Leased
                | HealthJobItemState::Dispatching
                | HealthJobItemState::InFlight
        );
        HealthItemTransition {
            item_id,
            expected_state: from,
            expected_fence: fence,
            new_state: to,
            lease_owner: running.then(|| "worker-1".into()),
            lease_expires_at_ms: running.then_some(now_ms + 1_000),
            pair_fence_token: None,
            dispatch_attempt_id: None,
            request_id: None,
            not_before_ms: None,
            health_status: None,
            safe_error_code: None,
            safe_error_message: None,
            completed_after_cancel: false,
            now_ms,
        }
    }

    #[tokio::test]
    async fn health_policy_revision_and_constraints() {
        let (repo, _, _) = fixture().await;
        let id = repo
            .create_health_policy(&NewHealthPolicy {
                name: "daily".into(),
                enabled: true,
                resource_selector_json: "{}".into(),
                node_selector_json: "{}".into(),
                interval_seconds: 3600,
                jitter_seconds: 30,
                max_items: 100,
                next_run_at_ms: 10,
                created_by: Some(1),
                now_ms: 1,
            })
            .await
            .unwrap();
        let changed = repo
            .update_health_policy(
                id,
                1,
                &HealthPolicyPatch {
                    name: Some("daily-2".into()),
                    ..Default::default()
                },
                2,
            )
            .await
            .unwrap();
        assert_eq!(changed.revision, 2);
        assert!(matches!(
            repo.update_health_policy(id, 1, &HealthPolicyPatch::default(), 3)
                .await,
            Err(DbError::RevisionConflict)
        ));
        let invalid = repo
            .create_health_policy(&NewHealthPolicy {
                name: "bad".into(),
                enabled: true,
                resource_selector_json: "{}".into(),
                node_selector_json: "{}".into(),
                interval_seconds: 10,
                jitter_seconds: 0,
                max_items: 1,
                next_run_at_ms: 0,
                created_by: None,
                now_ms: 0,
            })
            .await;
        assert!(matches!(invalid, Err(DbError::ConstraintViolation)));
    }

    #[tokio::test]
    async fn health_job_transition_counter_fence_and_finalization_are_atomic() {
        let (repo, resource, node) = fixture().await;
        let (job, items) = job("job-transition", resource, node, None);
        repo.create_health_job(&job, &items).await.unwrap();
        let item = repo.list_health_job_items(&job.id).await.unwrap().remove(0);
        assert_eq!(
            repo.transition_health_job_item(&transition(
                item.id,
                HealthJobItemState::Queued,
                7,
                HealthJobItemState::Leased,
                2_000
            ))
            .await
            .unwrap(),
            ConditionalWriteOutcome::ConditionFailed
        );
        assert_eq!(
            repo.transition_health_job_item(&transition(
                item.id,
                HealthJobItemState::Queued,
                0,
                HealthJobItemState::Leased,
                2_000
            ))
            .await
            .unwrap(),
            ConditionalWriteOutcome::Applied
        );
        let active = repo.find_health_job(&job.id).await.unwrap().unwrap();
        assert_eq!((active.queued_count, active.running_count), (0, 1));
        assert_eq!(
            repo.transition_health_job_item(&transition(
                item.id,
                HealthJobItemState::Leased,
                1,
                HealthJobItemState::Dispatching,
                2_500
            ))
            .await
            .unwrap(),
            ConditionalWriteOutcome::Applied
        );
        assert_eq!(
            repo.transition_health_job_item(&transition(
                item.id,
                HealthJobItemState::Dispatching,
                2,
                HealthJobItemState::InFlight,
                2_750
            ))
            .await
            .unwrap(),
            ConditionalWriteOutcome::Applied
        );
        assert_eq!(
            repo.transition_health_job_item(&transition(
                item.id,
                HealthJobItemState::InFlight,
                3,
                HealthJobItemState::Succeeded,
                3_000
            ))
            .await
            .unwrap(),
            ConditionalWriteOutcome::Applied
        );
        assert!(repo.finalize_health_job(&job.id, 3_001).await.unwrap());
        let done = repo.find_health_job(&job.id).await.unwrap().unwrap();
        assert_eq!(done.status, HealthJobStatus::Succeeded.as_str());
        assert_eq!((done.running_count, done.succeeded_count), (0, 1));
        assert_eq!(done.finished_at_ms, Some(3_001));
    }

    #[tokio::test]
    async fn health_job_cancel_and_retry_failed_snapshot_are_persistent() {
        let (repo, resource, node) = fixture().await;
        let (mut parent, items) = job("job-parent", resource, node, None);
        parent.snapshot_hash = snapshot_hash(&[(resource, node)]);
        repo.create_health_job(&parent, &items).await.unwrap();
        let item = repo
            .list_health_job_items(&parent.id)
            .await
            .unwrap()
            .remove(0);
        repo.transition_health_job_item(&transition(
            item.id,
            HealthJobItemState::Queued,
            0,
            HealthJobItemState::Leased,
            2_000,
        ))
        .await
        .unwrap();
        repo.transition_health_job_item(&transition(
            item.id,
            HealthJobItemState::Leased,
            1,
            HealthJobItemState::Failed,
            3_000,
        ))
        .await
        .unwrap();
        repo.finalize_health_job(&parent.id, 3_001).await.unwrap();
        assert_eq!(
            repo.retry_failed_health_pairs(&parent.id).await.unwrap(),
            vec![(resource, node)]
        );

        let (cancel, mut cancel_items) = job("job-cancel", resource, node, None);
        let resource2 = sqlx::query(
            "INSERT INTO socks5_resources(name,host,port) VALUES('r2','127.0.0.2',1081)",
        )
        .execute(&repo.pool)
        .await
        .unwrap()
        .last_insert_rowid();
        cancel_items.push(NewHealthJobItem {
            resource_id: resource2,
            relay_node_id: node,
            not_before_ms: 1_000,
            deadline_at_ms: None,
        });
        let mut cancel = cancel;
        cancel.snapshot_hash = snapshot_hash(&[(resource, node), (resource2, node)]);
        repo.create_health_job(&cancel, &cancel_items)
            .await
            .unwrap();
        assert!(repo.cancel_health_job(&cancel.id, 4_000).await.unwrap());
        let cancelled = repo.find_health_job(&cancel.id).await.unwrap().unwrap();
        assert_eq!(cancelled.status, HealthJobStatus::Cancelled.as_str());
        assert_eq!(cancelled.cancelled_count, 2);
    }

    #[tokio::test]
    async fn health_pair_lease_wait_fencing_and_prune_contract() {
        let (repo, resource, node) = fixture().await;
        let (job, items) = job("job-lease", resource, node, None);
        repo.create_health_job(&job, &items).await.unwrap();
        let item = repo.list_health_job_items(&job.id).await.unwrap().remove(0);
        let acquired = repo
            .acquire_health_pair_lease(PairLeaseAcquireRequest {
                resource_id: resource,
                relay_node_id: node,
                item_id: item.id,
                lease_owner: "w1",
                lease_expires_at_ms: 2_000,
                now_ms: 1_000,
            })
            .await
            .unwrap();
        assert_eq!(
            acquired,
            PairLeaseAcquireOutcome::Acquired {
                pair_fence_token: 1
            }
        );
        assert_eq!(
            repo.acquire_health_pair_lease(PairLeaseAcquireRequest {
                resource_id: resource,
                relay_node_id: node,
                item_id: item.id,
                lease_owner: "w2",
                lease_expires_at_ms: 2_500,
                now_ms: 1_500
            })
            .await
            .unwrap(),
            PairLeaseAcquireOutcome::Busy
        );
        assert_eq!(
            repo.renew_health_pair_lease(resource, node, item.id, "w1", 9, 3_000, 1_600)
                .await
                .unwrap(),
            ConditionalWriteOutcome::ConditionFailed
        );
        assert_eq!(
            repo.release_health_pair_lease(resource, node, item.id, "w1", 1, 1_700)
                .await
                .unwrap(),
            ConditionalWriteOutcome::Applied
        );
        assert_eq!(
            repo.list_released_health_pair_lease_prune_candidates(1_800, 1000)
                .await
                .unwrap(),
            vec![(resource, node)]
        );
        assert_eq!(
            repo.prune_released_health_pair_leases(1_800, 1000)
                .await
                .unwrap(),
            1
        );
    }

    #[tokio::test]
    async fn health_job_idempotency_ttl_actor_isolation_and_backlog() {
        let (repo, resource, node) = fixture().await;
        let now = 1_000_000;
        let mut tx = repo.pool.begin().await.unwrap();
        for index in 0..=10_000_i64 {
            sqlx::query("INSERT INTO socks5_health_job_idempotency(actor_id,idempotency_key,request_fingerprint,job_id,created_at_ms,expires_at_ms) VALUES(1,?,?,NULL,0,?)")
                .bind(format!("expired-{index:05}")).bind("e".repeat(64)).bind(now-1).execute(&mut *tx).await.unwrap();
        }
        tx.commit().await.unwrap();
        assert_eq!(
            repo.lookup_health_job_idempotency(1, "expired-10000", &"e".repeat(64), now)
                .await
                .unwrap(),
            HealthJobIdempotencyOutcome::Available
        );
        let (job, items) = job("job-idem", resource, node, Some(1));
        let key = NewHealthJobIdempotency {
            actor_id: 1,
            idempotency_key: "expired-10000".into(),
            request_fingerprint: job.request_fingerprint.clone(),
            created_at_ms: now,
            expires_at_ms: now + IDEMPOTENCY_TTL_MS,
        };
        assert!(matches!(
            repo.create_health_job_idempotent(&job, &items, &key)
                .await
                .unwrap(),
            HealthJobCreateOutcome::Created { .. }
        ));
        assert_eq!(
            repo.create_health_job_idempotent(&job, &items, &key)
                .await
                .unwrap(),
            HealthJobCreateOutcome::Replay {
                job_id: job.id.clone()
            }
        );
        assert_eq!(
            repo.lookup_health_job_idempotency(1, &key.idempotency_key, &"b".repeat(64), now + 1)
                .await
                .unwrap(),
            HealthJobIdempotencyOutcome::Conflict
        );
        assert_eq!(
            repo.lookup_health_job_idempotency(
                2,
                &key.idempotency_key,
                &job.request_fingerprint,
                now + 1
            )
            .await
            .unwrap(),
            HealthJobIdempotencyOutcome::Available
        );
    }

    #[tokio::test]
    async fn health_retention_excludes_active_jobs_and_active_pair_leases() {
        let (repo, resource, node) = fixture().await;
        let (active, items) = job("active-retention", resource, node, None);
        repo.create_health_job(&active, &items).await.unwrap();
        assert_eq!(
            repo.list_terminal_health_job_prune_candidates(99_999, 1000)
                .await
                .unwrap(),
            Vec::<String>::new()
        );
        assert_eq!(
            repo.prune_terminal_health_jobs(99_999, 1000).await.unwrap(),
            0
        );
        let item = repo
            .list_health_job_items(&active.id)
            .await
            .unwrap()
            .remove(0);
        repo.acquire_health_pair_lease(PairLeaseAcquireRequest {
            resource_id: resource,
            relay_node_id: node,
            item_id: item.id,
            lease_owner: "w",
            lease_expires_at_ms: 100_000,
            now_ms: 1,
        })
        .await
        .unwrap();
        assert_eq!(
            repo.list_released_health_pair_lease_prune_candidates(99_999, 1000)
                .await
                .unwrap(),
            Vec::<(i64, i64)>::new()
        );
        assert_eq!(
            repo.prune_released_health_pair_leases(99_999, 1000)
                .await
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn health_database_constraints_reject_invalid_jobs_items_and_slots() {
        let (repo, resource, node) = fixture().await;
        let ready_plan: Vec<(i64, i64, i64, String)> = sqlx::query_as(
            "EXPLAIN QUERY PLAN SELECT id FROM socks5_check_job_items
             WHERE state='QUEUED' AND not_before_ms <= 1000 LIMIT 100",
        )
        .fetch_all(&repo.pool)
        .await
        .unwrap();
        assert!(ready_plan
            .iter()
            .any(|(_, _, _, detail)| detail.contains("idx_socks5_check_job_items_ready")));
        let (empty_job, _) = job("empty-job", resource, node, None);
        assert!(matches!(
            repo.create_health_job(&empty_job, &[]).await,
            Err(DbError::ConstraintViolation)
        ));

        let (duplicate_job, item) = job("duplicate-pair", resource, node, None);
        let duplicate_items = [item[0].clone(), item[0].clone()];
        assert!(matches!(
            repo.create_health_job(&duplicate_job, &duplicate_items)
                .await,
            Err(DbError::UniqueViolation)
        ));
        assert!(repo
            .find_health_job(&duplicate_job.id)
            .await
            .unwrap()
            .is_none());

        let policy_id = repo
            .create_health_policy(&NewHealthPolicy {
                name: "slot-policy".into(),
                enabled: true,
                resource_selector_json: "{}".into(),
                node_selector_json: "{}".into(),
                interval_seconds: 3600,
                jitter_seconds: 0,
                max_items: 10,
                next_run_at_ms: 10,
                created_by: Some(1),
                now_ms: 1,
            })
            .await
            .unwrap();
        for id in ["slot-a", "slot-b"] {
            let scheduled = NewHealthJob {
                id: id.into(),
                source: HealthJobSource::Scheduled,
                policy_id: Some(policy_id),
                parent_job_id: None,
                actor_id: None,
                request_fingerprint: "c".repeat(64),
                snapshot_hash: snapshot_hash(&[(resource, node)]),
                resource_selector_json: "{}".into(),
                node_selector_json: "{}".into(),
                scheduled_for_ms: Some(50_000),
                created_at_ms: 1,
            };
            let result = repo
                .create_health_job(
                    &scheduled,
                    &[NewHealthJobItem {
                        resource_id: resource,
                        relay_node_id: node,
                        not_before_ms: 1,
                        deadline_at_ms: None,
                    }],
                )
                .await;
            if id == "slot-a" {
                assert!(result.is_ok());
            } else {
                assert!(matches!(result, Err(DbError::UniqueViolation)));
            }
        }
        assert!(matches!(
            sqlx::query("UPDATE socks5_check_job_items SET state='BOGUS' WHERE job_id='slot-a'")
                .execute(&repo.pool)
                .await
                .map_err(DbError::from),
            Err(DbError::ConstraintViolation)
        ));
        assert!(matches!(
            sqlx::query("UPDATE socks5_check_jobs SET queued_count=0 WHERE id='slot-a'")
                .execute(&repo.pool)
                .await
                .map_err(DbError::from),
            Err(DbError::ConstraintViolation)
        ));
        assert!(matches!(
            sqlx::query("UPDATE socks5_check_jobs SET status='SUCCEEDED' WHERE id='slot-a'")
                .execute(&repo.pool)
                .await
                .map_err(DbError::from),
            Err(DbError::ConstraintViolation)
        ));
    }
}
