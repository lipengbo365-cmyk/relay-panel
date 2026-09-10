use super::PgRepository;
use crate::db::error::DbError;
use crate::db::repo::{
    BulkImportOutcome, BulkSocks5Resource, RelayNodeCapacityRecord, RelayNodeRecord,
    SmartRelayCreateInput, SmartRelayCreateOutcome, SmartRelayCreatedRecord,
    SmartRelayReceiptRecord, Socks5CheckHistoryRecord, Socks5HealthRecord,
    Socks5LatestHealthRecord, Socks5RecommendationHealthRecord, Socks5Repository,
    Socks5ResourceQuery, Socks5ResourceRecord, Socks5RuleConfigRecord, Socks5RuleViewRecord,
};
use async_trait::async_trait;

fn validate_stage4_node_status(
    raw: &str,
    required_protocol_version: u32,
    max_cpu_percent: f64,
    max_memory_percent: f64,
) -> Result<(), &'static str> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(raw) else {
        return Err("NODE_OFFLINE");
    };
    let online = value
        .get("last_seen")
        .and_then(|value| value.as_str())
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .is_some_and(|seen| {
            let age = chrono::Utc::now()
                .signed_duration_since(seen.with_timezone(&chrono::Utc))
                .num_seconds();
            (0..=120).contains(&age)
        });
    if !online {
        return Err("NODE_OFFLINE");
    }
    if value
        .get("config_protocol_version")
        .and_then(|value| value.as_u64())
        != Some(u64::from(required_protocol_version))
        || value.get("socks5_check_queue_depth").is_none()
    {
        return Err("NODE_UNSUPPORTED");
    }
    if value
        .get("cpu")
        .and_then(|value| value.as_f64())
        .is_some_and(|cpu| cpu >= max_cpu_percent)
        || value
            .get("mem")
            .and_then(|value| value.as_f64())
            .is_some_and(|memory| memory >= max_memory_percent)
    {
        return Err("NODE_OVERLOADED");
    }
    Ok(())
}

fn stage4_health_fresh(checked_at: &str, ttl_seconds: i64) -> bool {
    use chrono::TimeZone;
    let checked = chrono::DateTime::parse_from_rfc3339(checked_at)
        .map(|value| value.with_timezone(&chrono::Utc))
        .ok()
        .or_else(|| {
            chrono::NaiveDateTime::parse_from_str(checked_at, "%Y-%m-%d %H:%M:%S%.f")
                .ok()
                .map(|value| chrono::Utc.from_utc_datetime(&value))
        });
    checked.is_some_and(|checked| {
        let age = chrono::Utc::now()
            .signed_duration_since(checked)
            .num_seconds();
        (0..=ttl_seconds).contains(&age)
    })
}

fn apply_pg_resource_filters<'a>(
    builder: &mut sqlx::QueryBuilder<'a, sqlx::Postgres>,
    query: &'a Socks5ResourceQuery,
) {
    if let Some(value) = query.search.as_deref().filter(|v| !v.is_empty()) {
        let pattern = format!("%{}%", value.to_lowercase());
        builder
            .push(" AND (LOWER(name) LIKE ")
            .push_bind(pattern.clone())
            .push(" OR LOWER(host) LIKE ")
            .push_bind(pattern.clone())
            .push(" OR LOWER(COALESCE(detected_exit_ip,'')) LIKE ")
            .push_bind(pattern)
            .push(")");
    }
    if let Some(value) = query.status.as_deref().filter(|v| !v.is_empty()) {
        builder.push(" AND status = ").push_bind(value);
    }
    if let Some(value) = query.country.as_deref().filter(|v| !v.is_empty()) {
        builder.push(" AND country_code = ").push_bind(value);
    }
    if let Some(value) = query.detected_country.as_deref().filter(|v| !v.is_empty()) {
        builder.push(" AND detected_country = ").push_bind(value);
    }
    if let Some(value) = query.tag.as_deref().filter(|v| !v.is_empty()) {
        builder
            .push(" AND EXISTS (SELECT 1 FROM jsonb_array_elements_text(tags::jsonb) AS tag_value WHERE LOWER(tag_value) = LOWER(")
            .push_bind(value)
            .push("))");
    }
    if let Some(enabled) = query.enabled {
        builder.push(" AND enabled = ").push_bind(enabled);
    }
}

#[async_trait]
impl Socks5Repository for PgRepository {
    async fn insert_socks5_resource(
        &self,
        name: &str,
        host: &str,
        port: i32,
        username: Option<&str>,
        password_ciphertext: Option<&str>,
        password_nonce: Option<&str>,
        password_key_version: i32,
        country: &str,
        country_code: &str,
        region: &str,
        city: &str,
        isp: &str,
        remark: &str,
        enabled: bool,
    ) -> Result<i64, DbError> {
        Ok(sqlx::query_scalar(
            "INSERT INTO socks5_resources
             (name,host,port,username,password_ciphertext,password_nonce,password_key_version,
              country,country_code,region,city,isp,remark,status,enabled)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,CASE WHEN $14 THEN 'UNKNOWN' ELSE 'DISABLED' END,$14)
             RETURNING id")
            .bind(name).bind(host).bind(port).bind(username).bind(password_ciphertext)
            .bind(password_nonce).bind(password_key_version).bind(country).bind(country_code)
            .bind(region).bind(city).bind(isp).bind(remark).bind(enabled)
            .fetch_one(&self.pool).await?)
    }
    async fn list_socks5_resources(&self) -> Result<Vec<Socks5ResourceRecord>, DbError> {
        Ok(
            sqlx::query_as("SELECT * FROM socks5_resources ORDER BY id DESC")
                .fetch_all(&self.pool)
                .await?,
        )
    }
    async fn query_socks5_resources(
        &self,
        query: &Socks5ResourceQuery,
    ) -> Result<(Vec<Socks5ResourceRecord>, i64), DbError> {
        let mut builder =
            sqlx::QueryBuilder::<sqlx::Postgres>::new("SELECT * FROM socks5_resources WHERE TRUE");
        apply_pg_resource_filters(&mut builder, query);
        let sort = match query.sort.as_str() {
            "name" => "name",
            "host" => "host",
            "country" => "country_code",
            "status" => "status",
            "latency" => "latency_ms",
            "last_check" => "last_check_at",
            _ => "id",
        };
        builder.push(format!(
            " ORDER BY {sort} {}, id DESC LIMIT ",
            if query.descending { "DESC" } else { "ASC" }
        ));
        builder
            .push_bind(query.limit)
            .push(" OFFSET ")
            .push_bind(query.offset);
        let rows = builder
            .build_query_as::<Socks5ResourceRecord>()
            .fetch_all(&self.pool)
            .await?;

        let mut count = sqlx::QueryBuilder::<sqlx::Postgres>::new(
            "SELECT COUNT(*) FROM socks5_resources WHERE TRUE",
        );
        apply_pg_resource_filters(&mut count, query);
        let total = count
            .build_query_scalar::<i64>()
            .fetch_one(&self.pool)
            .await?;
        Ok((rows, total))
    }

    async fn list_latest_socks5_health_for_resources(
        &self,
        resource_ids: &[i64],
    ) -> Result<Vec<Socks5LatestHealthRecord>, DbError> {
        if resource_ids.is_empty() {
            return Ok(Vec::new());
        }
        Ok(sqlx::query_as(
            "SELECT DISTINCT ON (h.resource_id) h.resource_id,h.relay_node_id,
                    CASE WHEN n.name='' THEN n.node_key ELSE n.name END AS relay_node_name,
                    h.status,h.total_latency_ms,h.exit_ip,h.country,h.consecutive_failures,h.checked_at
             FROM socks5_resource_health h JOIN relay_nodes n ON n.id=h.relay_node_id
             WHERE h.resource_id = ANY($1)
             ORDER BY h.resource_id,h.checked_at DESC,h.relay_node_id DESC",
        )
        .bind(resource_ids)
        .fetch_all(&self.pool)
        .await?)
    }
    async fn find_socks5_resources_by_keys(
        &self,
        keys: &[(String, i32, Option<String>)],
    ) -> Result<Vec<Socks5ResourceRecord>, DbError> {
        let mut found = Vec::new();
        for chunk in keys.chunks(500) {
            if chunk.is_empty() {
                continue;
            }
            let mut query = sqlx::QueryBuilder::new("SELECT * FROM socks5_resources WHERE ");
            let mut separated = query.separated(" OR ");
            for (host, port, username) in chunk {
                separated
                    .push("(host=")
                    .push_bind(host)
                    .push(" AND port=")
                    .push_bind(port)
                    .push(" AND COALESCE(username,'')=")
                    .push_bind(username.as_deref().unwrap_or(""))
                    .push(")");
            }
            found.extend(query.build_query_as().fetch_all(&self.pool).await?);
        }
        Ok(found)
    }
    async fn bulk_import_socks5_resources(
        &self,
        rows: &[BulkSocks5Resource],
        update_credentials: bool,
    ) -> Result<BulkImportOutcome, DbError> {
        let mut tx = self.pool.begin().await?;
        let mut outcome = BulkImportOutcome::default();
        for row in rows {
            let existing: Option<i64> = sqlx::query_scalar(
                "SELECT id FROM socks5_resources WHERE host=$1 AND port=$2 AND COALESCE(username,'')=$3 FOR UPDATE"
            ).bind(&row.host).bind(row.port).bind(row.username.as_deref().unwrap_or(""))
            .fetch_optional(&mut *tx).await?;
            if let Some(id) = existing {
                if update_credentials && row.password_ciphertext.is_some() {
                    sqlx::query("UPDATE socks5_resources SET password_ciphertext=$1,password_nonce=$2,password_key_version=$3,health_generation=health_generation+1,status='UNKNOWN',last_check_at=NULL,updated_at=to_char(now() AT TIME ZONE 'UTC','YYYY-MM-DD HH24:MI:SS') WHERE id=$4")
                        .bind(&row.password_ciphertext).bind(&row.password_nonce).bind(row.password_key_version)
                        .bind(id).execute(&mut *tx).await?;
                    outcome.updated += 1;
                } else {
                    outcome.skipped += 1;
                }
                continue;
            }
            let inserted = sqlx::query("INSERT INTO socks5_resources(name,host,port,username,password_ciphertext,password_nonce,password_key_version,status,enabled) VALUES($1,$2,$3,$4,$5,$6,$7,'UNKNOWN',TRUE) ON CONFLICT DO NOTHING")
                .bind(&row.name).bind(&row.host).bind(row.port).bind(&row.username)
                .bind(&row.password_ciphertext).bind(&row.password_nonce).bind(row.password_key_version)
                .execute(&mut *tx).await?.rows_affected();
            if inserted == 1 {
                outcome.created += 1;
            } else if update_credentials && row.password_ciphertext.is_some() {
                // Another transaction may have inserted the same key after our
                // SELECT observed no row. Preserve UPDATE_CREDENTIAL semantics
                // instead of silently degrading that race to SKIP_DUPLICATE.
                let updated = sqlx::query(
                    "UPDATE socks5_resources SET password_ciphertext=$1,password_nonce=$2,password_key_version=$3,health_generation=health_generation+1,status='UNKNOWN',last_check_at=NULL,updated_at=to_char(now() AT TIME ZONE 'UTC','YYYY-MM-DD HH24:MI:SS') WHERE host=$4 AND port=$5 AND COALESCE(username,'')=$6",
                )
                .bind(&row.password_ciphertext)
                .bind(&row.password_nonce)
                .bind(row.password_key_version)
                .bind(&row.host)
                .bind(row.port)
                .bind(row.username.as_deref().unwrap_or(""))
                .execute(&mut *tx)
                .await?
                .rows_affected();
                if updated == 1 {
                    outcome.updated += 1;
                } else {
                    outcome.skipped += 1;
                }
            } else {
                outcome.skipped += 1;
            }
        }
        tx.commit().await?;
        Ok(outcome)
    }
    async fn find_socks5_resource(&self, id: i64) -> Result<Option<Socks5ResourceRecord>, DbError> {
        Ok(sqlx::query_as("SELECT * FROM socks5_resources WHERE id=$1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?)
    }
    async fn update_socks5_resource_full(
        &self,
        id: i64,
        name: &str,
        host: &str,
        port: i32,
        username: Option<&str>,
        password_ciphertext: Option<&str>,
        password_nonce: Option<&str>,
        password_key_version: i32,
        country: &str,
        country_code: &str,
        region: &str,
        city: &str,
        isp: &str,
        remark: &str,
        enabled: bool,
    ) -> Result<u64, DbError> {
        Ok(sqlx::query(
            "UPDATE socks5_resources SET name=$1,host=$2,port=$3,username=$4,password_ciphertext=$5,
             password_nonce=$6,password_key_version=$7,country=$8,country_code=$9,region=$10,city=$11,
             isp=$12,remark=$13,enabled=$14,status=CASE WHEN $14 THEN CASE WHEN status='DISABLED' THEN 'UNKNOWN' ELSE status END
             ELSE 'DISABLED' END,health_generation=health_generation+1,updated_at=to_char(now() AT TIME ZONE 'UTC','YYYY-MM-DD HH24:MI:SS') WHERE id=$15")
            .bind(name).bind(host).bind(port).bind(username).bind(password_ciphertext).bind(password_nonce)
            .bind(password_key_version).bind(country).bind(country_code).bind(region).bind(city).bind(isp)
            .bind(remark).bind(enabled).bind(id).execute(&self.pool).await?.rows_affected())
    }
    async fn set_socks5_resource_enabled(&self, id: i64, enabled: bool) -> Result<u64, DbError> {
        Ok(sqlx::query("UPDATE socks5_resources SET enabled=$1,status=CASE WHEN $1 THEN 'UNKNOWN' ELSE 'DISABLED' END,health_generation=health_generation+1,updated_at=to_char(now() AT TIME ZONE 'UTC','YYYY-MM-DD HH24:MI:SS') WHERE id=$2")
            .bind(enabled).bind(id).execute(&self.pool).await?.rows_affected())
    }
    async fn bulk_set_socks5_resources_enabled(
        &self,
        ids: &[i64],
        enabled: bool,
    ) -> Result<u64, DbError> {
        if ids.is_empty() {
            return Ok(0);
        }
        Ok(sqlx::query("UPDATE socks5_resources SET enabled=$1,status=CASE WHEN $1 THEN CASE WHEN status='DISABLED' THEN 'UNKNOWN' ELSE status END ELSE 'DISABLED' END,health_generation=health_generation+1,updated_at=to_char(now() AT TIME ZONE 'UTC','YYYY-MM-DD HH24:MI:SS') WHERE id = ANY($2)")
            .bind(enabled).bind(ids).execute(&self.pool).await?.rows_affected())
    }
    async fn bulk_set_socks5_resource_tags(
        &self,
        ids: &[i64],
        tags_json: &str,
    ) -> Result<u64, DbError> {
        if ids.is_empty() {
            return Ok(0);
        }
        Ok(sqlx::query("UPDATE socks5_resources SET tags=$1,updated_at=to_char(now() AT TIME ZONE 'UTC','YYYY-MM-DD HH24:MI:SS') WHERE id = ANY($2)")
            .bind(tags_json).bind(ids).execute(&self.pool).await?.rows_affected())
    }
    async fn bulk_delete_socks5_resources_guarded(
        &self,
        ids: &[i64],
    ) -> Result<(u64, Vec<(i64, i64)>), DbError> {
        if ids.is_empty() {
            return Ok((0, Vec::new()));
        }
        let mut tx = self.pool.begin().await?;
        let blockers = sqlx::query_as::<_, (i64, i64)>("SELECT socks5_resource_id,rule_id FROM socks5_rule_bindings WHERE socks5_resource_id = ANY($1) ORDER BY socks5_resource_id,rule_id FOR SHARE")
            .bind(ids).fetch_all(&mut *tx).await?;
        let deleted = sqlx::query("DELETE FROM socks5_resources r WHERE r.id = ANY($1) AND NOT EXISTS (SELECT 1 FROM socks5_rule_bindings b WHERE b.socks5_resource_id=r.id)")
            .bind(ids).execute(&mut *tx).await?.rows_affected();
        tx.commit().await?;
        Ok((deleted, blockers))
    }
    async fn delete_socks5_resource(&self, id: i64) -> Result<u64, DbError> {
        Ok(sqlx::query("DELETE FROM socks5_resources WHERE id=$1")
            .bind(id)
            .execute(&self.pool)
            .await?
            .rows_affected())
    }
    async fn count_socks5_resource_bindings(&self, id: i64) -> Result<i64, DbError> {
        Ok(sqlx::query_scalar(
            "SELECT COUNT(*) FROM socks5_rule_bindings WHERE socks5_resource_id=$1",
        )
        .bind(id)
        .fetch_one(&self.pool)
        .await?)
    }
    async fn find_socks5_rule_config(
        &self,
        rule_id: i64,
    ) -> Result<Option<Socks5RuleConfigRecord>, DbError> {
        Ok(sqlx::query_as("SELECT b.rule_id,b.socks5_resource_id,b.relay_node_id,b.selection_mode,n.enabled relay_node_enabled,b.remote_dns,b.relay_username,b.relay_password_ciphertext,b.relay_password_nonce,b.relay_password_key_version,b.allow_no_auth,r.name resource_name,r.host resource_host,r.port resource_port,r.username resource_username,r.password_ciphertext resource_password_ciphertext,r.password_nonce resource_password_nonce,r.password_key_version resource_password_key_version,r.enabled resource_enabled FROM socks5_rule_bindings b JOIN socks5_resources r ON r.id=b.socks5_resource_id LEFT JOIN relay_nodes n ON n.id=b.relay_node_id WHERE b.rule_id=$1").bind(rule_id).fetch_optional(&self.pool).await?)
    }
    async fn list_socks5_rule_views(&self) -> Result<Vec<Socks5RuleViewRecord>, DbError> {
        Ok(sqlx::query_as("SELECT f.id rule_id,f.name,f.listen_port,f.device_group_in,g.connect_host,f.paused,f.traffic_used,b.socks5_resource_id,r.name resource_name,r.detected_exit_ip,r.detected_country,b.relay_node_id,n.name relay_node_name,n.country_code relay_node_country_code,n.advertise_host,n.public_ip relay_node_public_ip,n.enabled relay_node_enabled,b.selection_mode,b.relay_username,b.allow_no_auth,b.remote_dns,f.created_at FROM forward_rules f JOIN socks5_rule_bindings b ON b.rule_id=f.id JOIN socks5_resources r ON r.id=b.socks5_resource_id LEFT JOIN relay_nodes n ON n.id=b.relay_node_id JOIN device_groups g ON g.id=f.device_group_in ORDER BY f.id DESC").fetch_all(&self.pool).await?)
    }
    async fn list_relay_node_capacities(&self) -> Result<Vec<RelayNodeCapacityRecord>, DbError> {
        Ok(sqlx::query_as(
            "SELECT n.id relay_node_id,n.device_group_id,g.port_range,
                    COALESCE(p.port_used,0)::BIGINT port_used,g.group_type,g.capabilities group_capabilities
             FROM relay_nodes n JOIN device_groups g ON g.id=n.device_group_id
             LEFT JOIN (
                 SELECT device_group_in,COUNT(DISTINCT listen_port)::BIGINT port_used
                 FROM forward_rules WHERE protocol IN ('tcp','tcp_udp') GROUP BY device_group_in
             ) p ON p.device_group_in=n.device_group_id
             ORDER BY n.id",
        )
        .fetch_all(&self.pool)
        .await?)
    }
    async fn list_socks5_recommendation_health(
        &self,
        resource_id: i64,
    ) -> Result<Vec<Socks5RecommendationHealthRecord>, DbError> {
        Ok(sqlx::query_as(
            "SELECT h.resource_id,h.relay_node_id,h.status,h.total_latency_ms,h.exit_ip,h.country,
                    h.checked_at,h.resource_revision,h.generation,
                    COALESCE(g.generation,0) current_generation
             FROM socks5_resource_health h
             LEFT JOIN socks5_check_generations g
               ON g.resource_id=h.resource_id AND g.relay_node_id=h.relay_node_id
             WHERE h.resource_id=$1 ORDER BY h.relay_node_id",
        )
        .bind(resource_id)
        .fetch_all(&self.pool)
        .await?)
    }
    async fn create_socks5_rule_full(
        &self,
        name: &str,
        uid: i64,
        listen_port: i32,
        device_group_in: i64,
        socks5_resource_id: i64,
        remote_dns: bool,
        relay_username: Option<&str>,
        relay_password_ciphertext: Option<&str>,
        relay_password_nonce: Option<&str>,
        relay_password_key_version: i32,
        allow_no_auth: bool,
        enabled: bool,
    ) -> Result<Option<i64>, DbError> {
        let mut tx = self.pool.begin().await?;
        super::lock_rule_creation_scope(&mut tx, &[device_group_in], uid).await?;
        let resource_ok: Option<i32> =
            sqlx::query_scalar("SELECT 1 FROM socks5_resources WHERE id=$1 AND enabled=TRUE")
                .bind(socks5_resource_id)
                .fetch_optional(&mut *tx)
                .await?;
        if resource_ok.is_none() {
            tx.rollback().await?;
            return Err(DbError::NotFound);
        }
        let conflict:Option<i32>=sqlx::query_scalar("SELECT 1 FROM forward_rules WHERE device_group_in=$1 AND listen_port=$2 AND protocol IN ('tcp','tcp_udp') LIMIT 1")
            .bind(device_group_in).bind(listen_port).fetch_optional(&mut *tx).await?;
        if conflict.is_some() {
            tx.rollback().await?;
            return Err(DbError::PortConflict);
        }
        let rule_id:Option<i64>=sqlx::query_scalar(
            "INSERT INTO forward_rules(name,uid,paused,listen_port,protocol,public_transport,node_transport,route_mode,entry_transport,device_group_in,device_group_out,forward_mode,target_addr,target_port)
             SELECT $1,$2,$3,$4,'tcp','raw','raw','direct','raw',$5,NULL,'direct','',0
             WHERE (SELECT max_rules FROM users WHERE id=$2)=0 OR (SELECT COUNT(*) FROM forward_rules WHERE uid=$2)<(SELECT max_rules FROM users WHERE id=$2) RETURNING id")
            .bind(name).bind(uid).bind(!enabled).bind(listen_port).bind(device_group_in).fetch_optional(&mut *tx).await?;
        let Some(rule_id) = rule_id else {
            tx.commit().await?;
            return Ok(None);
        };
        sqlx::query("INSERT INTO socks5_rule_bindings(rule_id,socks5_resource_id,remote_dns,relay_username,relay_password_ciphertext,relay_password_nonce,relay_password_key_version,allow_no_auth) VALUES($1,$2,$3,$4,$5,$6,$7,$8)")
            .bind(rule_id).bind(socks5_resource_id).bind(remote_dns).bind(relay_username)
            .bind(relay_password_ciphertext).bind(relay_password_nonce).bind(relay_password_key_version)
            .bind(allow_no_auth).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(Some(rule_id))
    }

    async fn create_smart_relay(
        &self,
        input: &SmartRelayCreateInput,
    ) -> Result<SmartRelayCreateOutcome, DbError> {
        let mut tx = self.pool.begin().await?;
        let idempotency_lock = format!("{}:{}", input.actor_id, input.idempotency_key);
        // Two-int advisory keys use a separate namespace from the one-bigint
        // node-group locks. Keeping lock classes disjoint prevents a crafted
        // idempotency hash from becoming an accidental group lock and creating
        // an AB/BA cycle between two smart-relay transactions.
        sqlx::query("SELECT pg_advisory_xact_lock($1,hashtext($2))")
            .bind(0x534B_4934_i32)
            .bind(&idempotency_lock)
            .execute(&mut *tx)
            .await?;
        let idempotency_cutoff: String = sqlx::query_scalar(
            "SELECT to_char(now() AT TIME ZONE 'UTC' - interval '7 days',
                            'YYYY-MM-DD HH24:MI:SS')",
        )
        .fetch_one(&mut *tx)
        .await?;
        sqlx::query(
            "DELETE FROM relay_creation_receipts WHERE id IN (
                SELECT id FROM relay_creation_receipts
                WHERE created_at < $1
                ORDER BY id LIMIT 10000
             )",
        )
        .bind(&idempotency_cutoff)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "DELETE FROM relay_creation_idempotency_keys WHERE (actor_id,idempotency_key) IN (
                SELECT actor_id,idempotency_key FROM relay_creation_idempotency_keys
                WHERE created_at < $1
                ORDER BY created_at LIMIT 10000
             )",
        )
        .bind(&idempotency_cutoff)
        .execute(&mut *tx)
        .await?;
        // Global pruning is storage maintenance only. Expire the current key
        // independently so bounded cleanup can never decide idempotency.
        sqlx::query(
            "DELETE FROM relay_creation_receipts
             WHERE actor_id=$1 AND idempotency_key=$2 AND created_at < $3",
        )
        .bind(input.actor_id)
        .bind(&input.idempotency_key)
        .bind(&idempotency_cutoff)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "DELETE FROM relay_creation_idempotency_keys
             WHERE actor_id=$1 AND idempotency_key=$2 AND created_at < $3",
        )
        .bind(input.actor_id)
        .bind(&input.idempotency_key)
        .bind(&idempotency_cutoff)
        .execute(&mut *tx)
        .await?;
        let receipt_fingerprint: Option<String> = sqlx::query_scalar(
            "SELECT request_fingerprint FROM relay_creation_receipts
             WHERE actor_id=$1 AND idempotency_key=$2 AND created_at >= $3",
        )
        .bind(input.actor_id)
        .bind(&input.idempotency_key)
        .bind(&idempotency_cutoff)
        .fetch_optional(&mut *tx)
        .await?;
        if receipt_fingerprint
            .as_deref()
            .is_some_and(|fingerprint| fingerprint != input.request_fingerprint)
        {
            tx.rollback().await?;
            return Ok(SmartRelayCreateOutcome::Rejected("IDEMPOTENCY_KEY_REUSED"));
        }
        let replay: Option<SmartRelayCreatedRecord> = sqlx::query_as(
            "SELECT r.rule_id,r.relay_node_id,r.resource_id,r.endpoint_host,r.listen_port,
                    r.relay_username,r.exit_ip,r.exit_country,r.selection_mode
             FROM relay_creation_receipts r
             INNER JOIN forward_rules f ON f.id=r.rule_id
             WHERE r.actor_id=$1 AND r.idempotency_key=$2
               AND r.created_at >= $3
             FOR KEY SHARE OF f",
        )
        .bind(input.actor_id)
        .bind(&input.idempotency_key)
        .bind(&idempotency_cutoff)
        .fetch_optional(&mut *tx)
        .await?;
        if let Some(replay) = replay {
            tx.commit().await?;
            return Ok(SmartRelayCreateOutcome::Replay(replay));
        }
        // A legacy orphan can exist only before migration 34 or after external
        // FK enforcement was disabled. It is never a valid replay target.
        sqlx::query(
            "DELETE FROM relay_creation_receipts
             WHERE actor_id=$1 AND idempotency_key=$2",
        )
        .bind(input.actor_id)
        .bind(&input.idempotency_key)
        .execute(&mut *tx)
        .await?;
        let key_fingerprint: Option<String> = sqlx::query_scalar(
            "SELECT request_fingerprint FROM relay_creation_idempotency_keys
             WHERE actor_id=$1 AND idempotency_key=$2 AND created_at >= $3",
        )
        .bind(input.actor_id)
        .bind(&input.idempotency_key)
        .bind(&idempotency_cutoff)
        .fetch_optional(&mut *tx)
        .await?;
        if key_fingerprint
            .as_deref()
            .is_some_and(|fingerprint| fingerprint != input.request_fingerprint)
        {
            tx.rollback().await?;
            return Ok(SmartRelayCreateOutcome::Rejected("IDEMPOTENCY_KEY_REUSED"));
        }

        let resource: Option<(bool, i64)> = sqlx::query_as(
            "SELECT enabled,health_generation FROM socks5_resources WHERE id=$1 FOR SHARE",
        )
        .bind(input.resource_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((resource_enabled, resource_revision)) = resource else {
            tx.rollback().await?;
            return Ok(SmartRelayCreateOutcome::Rejected("RESOURCE_NOT_FOUND"));
        };
        if !resource_enabled {
            tx.rollback().await?;
            return Ok(SmartRelayCreateOutcome::Rejected("RESOURCE_DISABLED"));
        }
        if resource_revision != input.expected_resource_revision {
            tx.rollback().await?;
            return Ok(SmartRelayCreateOutcome::Rejected("RESOURCE_CHANGED"));
        }

        let node: Option<(i64, String, bool, String, String, String)> = sqlx::query_as(
            "SELECT device_group_id,node_key,enabled,identity_secret_hash,advertise_host,public_ip
             FROM relay_nodes WHERE id=$1 FOR SHARE",
        )
        .bind(input.relay_node_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((group_id, node_key, node_enabled, identity_hash, advertise_host, public_ip)) =
            node
        else {
            tx.rollback().await?;
            return Ok(SmartRelayCreateOutcome::Rejected("NODE_NOT_FOUND"));
        };
        if !node_enabled {
            tx.rollback().await?;
            return Ok(SmartRelayCreateOutcome::Rejected("NODE_DISABLED"));
        }
        if identity_hash.len() != 64 {
            tx.rollback().await?;
            return Ok(SmartRelayCreateOutcome::Rejected("NODE_IDENTITY_UNTRUSTED"));
        }
        let endpoint_host = if advertise_host.is_empty() {
            public_ip
        } else {
            advertise_host
        };
        if endpoint_host.is_empty() {
            tx.rollback().await?;
            return Ok(SmartRelayCreateOutcome::Rejected(
                "NODE_ACCESS_HOST_MISSING",
            ));
        }

        // Canonical rule-create lock order is group advisory lock, then user
        // row lock. The group lock protects the listen-port namespace; the
        // user lock serializes max_rules checks across different groups.
        super::lock_rule_creation_scope(&mut tx, &[group_id], input.actor_id).await?;

        let status_key = format!("node_status:{group_id}:{node_key}");
        let status: Option<String> =
            sqlx::query_scalar("SELECT value FROM kvs WHERE key=$1 FOR SHARE")
                .bind(&status_key)
                .fetch_optional(&mut *tx)
                .await?;
        let status_result = status.as_deref().map_or(Err("NODE_OFFLINE"), |raw| {
            validate_stage4_node_status(
                raw,
                input.required_protocol_version,
                input.max_cpu_percent,
                input.max_memory_percent,
            )
        });
        if let Err(code) = status_result {
            tx.rollback().await?;
            return Ok(SmartRelayCreateOutcome::Rejected(code));
        }

        let group: Option<(String, String, String)> = sqlx::query_as(
            "SELECT group_type,port_range,capabilities FROM device_groups WHERE id=$1 FOR SHARE",
        )
        .bind(group_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((group_type, port_range, capabilities)) = group else {
            tx.rollback().await?;
            return Ok(SmartRelayCreateOutcome::Rejected("NODE_NOT_FOUND"));
        };
        let tcp_capable = serde_json::from_str::<Vec<String>>(&capabilities).unwrap_or_default();
        if group_type != "in"
            || (!tcp_capable.is_empty()
                && !tcp_capable
                    .iter()
                    .any(|value| value == "tcp" || value == "tcp_udp"))
        {
            tx.rollback().await?;
            return Ok(SmartRelayCreateOutcome::Rejected("NODE_UNSUPPORTED"));
        }

        let health: Option<(String, Option<String>, Option<String>, String, i64, i64)> =
            sqlx::query_as(
                "SELECT status,exit_ip,country,checked_at,resource_revision,generation
                 FROM socks5_resource_health WHERE resource_id=$1 AND relay_node_id=$2 FOR SHARE",
            )
            .bind(input.resource_id)
            .bind(input.relay_node_id)
            .fetch_optional(&mut *tx)
            .await?;
        let Some((health_status, exit_ip, exit_country, checked_at, health_revision, generation)) =
            health
        else {
            tx.rollback().await?;
            return Ok(SmartRelayCreateOutcome::Rejected("HEALTH_MISSING"));
        };
        if health_status != "ONLINE" {
            tx.rollback().await?;
            return Ok(SmartRelayCreateOutcome::Rejected("HEALTH_NOT_ONLINE"));
        }
        if health_revision != resource_revision {
            tx.rollback().await?;
            return Ok(SmartRelayCreateOutcome::Rejected("RESOURCE_CHANGED"));
        }
        if generation != input.expected_health_generation
            || checked_at != input.expected_health_checked_at
        {
            tx.rollback().await?;
            return Ok(SmartRelayCreateOutcome::Rejected("RECOMMENDATION_STALE"));
        }
        let current_generation: Option<i64> = sqlx::query_scalar(
            "SELECT generation FROM socks5_check_generations
             WHERE resource_id=$1 AND relay_node_id=$2 FOR SHARE",
        )
        .bind(input.resource_id)
        .bind(input.relay_node_id)
        .fetch_optional(&mut *tx)
        .await?;
        if current_generation != Some(generation) {
            tx.rollback().await?;
            return Ok(SmartRelayCreateOutcome::Rejected("RECOMMENDATION_STALE"));
        }
        if !stage4_health_fresh(&checked_at, input.health_ttl_seconds) {
            tx.rollback().await?;
            return Ok(SmartRelayCreateOutcome::Rejected("HEALTH_STALE"));
        }
        let Some(exit_ip) = exit_ip.filter(|value| value.parse::<std::net::IpAddr>().is_ok())
        else {
            tx.rollback().await?;
            return Ok(SmartRelayCreateOutcome::Rejected("EXIT_IP_MISMATCH"));
        };

        let (low, high) = crate::service::rules::resolve_auto_port_range(&port_range);
        let used_ports: Vec<i32> = sqlx::query_scalar(
            "SELECT listen_port FROM forward_rules
             WHERE device_group_in=$1 AND protocol IN ('tcp','tcp_udp')",
        )
        .bind(group_id)
        .fetch_all(&mut *tx)
        .await?;
        let used = used_ports
            .into_iter()
            .collect::<std::collections::HashSet<_>>();
        let listen_port = match input.requested_port {
            Some(port) if port < i32::from(low) || port > i32::from(high) => {
                tx.rollback().await?;
                return Ok(SmartRelayCreateOutcome::Rejected("PORT_OUT_OF_RANGE"));
            }
            Some(port) if used.contains(&port) => {
                tx.rollback().await?;
                return Ok(SmartRelayCreateOutcome::Rejected("PORT_CONFLICT"));
            }
            Some(port) => port,
            None => match (low..=high)
                .map(i32::from)
                .find(|port| !used.contains(port))
            {
                Some(port) => port,
                None => {
                    tx.rollback().await?;
                    return Ok(SmartRelayCreateOutcome::Rejected("NO_AVAILABLE_PORT"));
                }
            },
        };

        let rule_id: Option<i64> = sqlx::query_scalar(
            "INSERT INTO forward_rules
             (name,uid,paused,listen_port,protocol,public_transport,node_transport,route_mode,
              entry_transport,device_group_in,device_group_out,forward_mode,target_addr,target_port)
             SELECT $1,$2,FALSE,$3,'tcp','raw','raw','direct','raw',$4,NULL,'direct','',0
             WHERE (SELECT max_rules FROM users WHERE id=$2)=0 OR
                   (SELECT COUNT(*) FROM forward_rules WHERE uid=$2)<
                   (SELECT max_rules FROM users WHERE id=$2) RETURNING id",
        )
        .bind(&input.name)
        .bind(input.actor_id)
        .bind(listen_port)
        .bind(group_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(rule_id) = rule_id else {
            tx.rollback().await?;
            return Ok(SmartRelayCreateOutcome::QuotaExceeded);
        };
        sqlx::query(
            "INSERT INTO socks5_rule_bindings
             (rule_id,socks5_resource_id,relay_node_id,selection_mode,remote_dns,relay_username,
              relay_password_ciphertext,relay_password_nonce,relay_password_key_version,allow_no_auth)
             VALUES($1,$2,$3,$4,TRUE,$5,$6,$7,$8,FALSE)",
        )
        .bind(rule_id)
        .bind(input.resource_id)
        .bind(input.relay_node_id)
        .bind(&input.selection_mode)
        .bind(&input.relay_username)
        .bind(&input.relay_password_ciphertext)
        .bind(&input.relay_password_nonce)
        .bind(input.relay_password_key_version)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO relay_creation_idempotency_keys
             (actor_id,idempotency_key,request_fingerprint,created_at)
             VALUES($1,$2,$3,to_char(now() AT TIME ZONE 'UTC','YYYY-MM-DD HH24:MI:SS'))
             ON CONFLICT(actor_id,idempotency_key) DO UPDATE
             SET created_at=EXCLUDED.created_at
             WHERE relay_creation_idempotency_keys.request_fingerprint=EXCLUDED.request_fingerprint",
        )
        .bind(input.actor_id)
        .bind(&input.idempotency_key)
        .bind(&input.request_fingerprint)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO relay_creation_receipts
             (actor_id,idempotency_key,request_fingerprint,rule_id,relay_node_id,resource_id,
              endpoint_host,listen_port,relay_username,exit_ip,exit_country,selection_mode)
             VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",
        )
        .bind(input.actor_id)
        .bind(&input.idempotency_key)
        .bind(&input.request_fingerprint)
        .bind(rule_id)
        .bind(input.relay_node_id)
        .bind(input.resource_id)
        .bind(&endpoint_host)
        .bind(listen_port)
        .bind(&input.relay_username)
        .bind(&exit_ip)
        .bind(&exit_country)
        .bind(&input.selection_mode)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(SmartRelayCreateOutcome::Created(SmartRelayCreatedRecord {
            rule_id,
            relay_node_id: input.relay_node_id,
            resource_id: input.resource_id,
            endpoint_host,
            listen_port,
            relay_username: input.relay_username.clone(),
            exit_ip,
            exit_country,
            selection_mode: input.selection_mode.clone(),
        }))
    }
    async fn find_smart_relay_receipt(
        &self,
        actor_id: i64,
        idempotency_key: &str,
    ) -> Result<Option<SmartRelayReceiptRecord>, DbError> {
        let mut tx = self.pool.begin().await?;
        let receipt = sqlx::query_as(
            "SELECT r.request_fingerprint,r.rule_id,r.relay_node_id,r.resource_id,r.endpoint_host,
                    r.listen_port,r.relay_username,r.exit_ip,r.exit_country,r.selection_mode
             FROM relay_creation_receipts r
             INNER JOIN forward_rules f ON f.id=r.rule_id
             WHERE r.actor_id=$1 AND r.idempotency_key=$2
               AND r.created_at >= to_char(now() AT TIME ZONE 'UTC' - interval '7 days',
                                           'YYYY-MM-DD HH24:MI:SS')
             FOR KEY SHARE OF f",
        )
        .bind(actor_id)
        .bind(idempotency_key)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(receipt)
    }
    async fn find_smart_relay_idempotency_fingerprint(
        &self,
        actor_id: i64,
        idempotency_key: &str,
    ) -> Result<Option<String>, DbError> {
        Ok(sqlx::query_scalar(
            "SELECT request_fingerprint FROM relay_creation_idempotency_keys
             WHERE actor_id=$1 AND idempotency_key=$2
               AND created_at >= to_char(now() AT TIME ZONE 'UTC' - interval '7 days',
                                         'YYYY-MM-DD HH24:MI:SS')",
        )
        .bind(actor_id)
        .bind(idempotency_key)
        .fetch_optional(&self.pool)
        .await?)
    }
    async fn update_socks5_rule_full(
        &self,
        rule_id: i64,
        name: &str,
        listen_port: i32,
        device_group_in: i64,
        socks5_resource_id: i64,
        remote_dns: bool,
        enabled: bool,
    ) -> Result<u64, DbError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(device_group_in)
            .execute(&mut *tx)
            .await?;
        let resource_ok: Option<i32> =
            sqlx::query_scalar("SELECT 1 FROM socks5_resources WHERE id=$1 AND enabled=TRUE")
                .bind(socks5_resource_id)
                .fetch_optional(&mut *tx)
                .await?;
        if resource_ok.is_none() {
            tx.rollback().await?;
            return Err(DbError::NotFound);
        }
        let conflict: Option<i32> = sqlx::query_scalar(
            "SELECT 1 FROM forward_rules WHERE id<>$1 AND device_group_in=$2 AND listen_port=$3
             AND protocol IN ('tcp','tcp_udp') LIMIT 1",
        )
        .bind(rule_id)
        .bind(device_group_in)
        .bind(listen_port)
        .fetch_optional(&mut *tx)
        .await?;
        if conflict.is_some() {
            tx.rollback().await?;
            return Err(DbError::PortConflict);
        }
        let updated = sqlx::query(
            "UPDATE forward_rules SET name=$1,listen_port=$2,device_group_in=$3,paused=$4,auto_paused=FALSE
             WHERE id=$5 AND EXISTS (SELECT 1 FROM socks5_rule_bindings WHERE rule_id=$5)",
        )
        .bind(name)
        .bind(listen_port)
        .bind(device_group_in)
        .bind(!enabled)
        .bind(rule_id)
        .execute(&mut *tx)
        .await?;
        if updated.rows_affected() == 0 {
            tx.rollback().await?;
            return Ok(0);
        }
        sqlx::query(
            "UPDATE socks5_rule_bindings SET socks5_resource_id=$1,remote_dns=$2,
             updated_at=to_char(now() AT TIME ZONE 'UTC','YYYY-MM-DD HH24:MI:SS') WHERE rule_id=$3",
        )
        .bind(socks5_resource_id)
        .bind(remote_dns)
        .bind(rule_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(1)
    }
    async fn reset_socks5_rule_credential(
        &self,
        rule_id: i64,
        relay_username: &str,
        relay_password_ciphertext: &str,
        relay_password_nonce: &str,
        relay_password_key_version: i32,
    ) -> Result<u64, DbError> {
        Ok(sqlx::query("UPDATE socks5_rule_bindings SET relay_username=$1,relay_password_ciphertext=$2,relay_password_nonce=$3,relay_password_key_version=$4,allow_no_auth=FALSE,updated_at=to_char(now() AT TIME ZONE 'UTC','YYYY-MM-DD HH24:MI:SS') WHERE rule_id=$5")
            .bind(relay_username).bind(relay_password_ciphertext).bind(relay_password_nonce)
            .bind(relay_password_key_version).bind(rule_id).execute(&self.pool).await?.rows_affected())
    }
    async fn upsert_relay_node_seen(
        &self,
        device_group_id: i64,
        node_key: &str,
        identity_secret_hash: &str,
        public_ip: &str,
        seen_at: &str,
    ) -> Result<Option<i64>, DbError> {
        Ok(sqlx::query_scalar("INSERT INTO relay_nodes(device_group_id,node_key,identity_secret_hash,name,public_ip,first_seen_at,last_seen_at) VALUES($1,$2,$3,$2,$4,$5,$5) ON CONFLICT(device_group_id,node_key) DO UPDATE SET identity_secret_hash=CASE WHEN relay_nodes.identity_secret_hash='' THEN excluded.identity_secret_hash ELSE relay_nodes.identity_secret_hash END,public_ip=CASE WHEN excluded.public_ip='' THEN relay_nodes.public_ip ELSE excluded.public_ip END,last_seen_at=excluded.last_seen_at,updated_at=to_char(now() AT TIME ZONE 'UTC','YYYY-MM-DD HH24:MI:SS') WHERE relay_nodes.identity_secret_hash='' OR relay_nodes.identity_secret_hash=excluded.identity_secret_hash RETURNING id")
            .bind(device_group_id).bind(node_key).bind(identity_secret_hash).bind(public_ip).bind(seen_at).fetch_optional(&self.pool).await?)
    }
    async fn list_relay_nodes(&self) -> Result<Vec<RelayNodeRecord>, DbError> {
        Ok(sqlx::query_as("SELECT * FROM relay_nodes ORDER BY id")
            .fetch_all(&self.pool)
            .await?)
    }
    async fn find_relay_node(&self, id: i64) -> Result<Option<RelayNodeRecord>, DbError> {
        Ok(sqlx::query_as("SELECT * FROM relay_nodes WHERE id=$1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?)
    }
    async fn replace_relay_node_identity(
        &self,
        id: i64,
        identity_secret_hash: &str,
    ) -> Result<u64, DbError> {
        Ok(sqlx::query("UPDATE relay_nodes SET identity_secret_hash=$1,updated_at=to_char(now() AT TIME ZONE 'UTC','YYYY-MM-DD HH24:MI:SS') WHERE id=$2")
            .bind(identity_secret_hash).bind(id).execute(&self.pool).await?.rows_affected())
    }
    async fn update_relay_node(
        &self,
        id: i64,
        name: &str,
        country: &str,
        country_code: &str,
        region: &str,
        city: &str,
        provider: &str,
        advertise_host: &str,
        bandwidth_mbps: i32,
        remark: &str,
        tags: &str,
        enabled: bool,
    ) -> Result<u64, DbError> {
        Ok(sqlx::query("UPDATE relay_nodes SET name=$1,country=$2,country_code=$3,region=$4,city=$5,provider=$6,advertise_host=$7,bandwidth_mbps=$8,remark=$9,tags=$10,enabled=$11,updated_at=to_char(now() AT TIME ZONE 'UTC','YYYY-MM-DD HH24:MI:SS') WHERE id=$12")
            .bind(name).bind(country).bind(country_code).bind(region).bind(city).bind(provider).bind(advertise_host).bind(bandwidth_mbps)
            .bind(remark).bind(tags).bind(enabled).bind(id).execute(&self.pool).await?.rows_affected())
    }
    async fn begin_socks5_health_check(
        &self,
        resource_id: i64,
        relay_node_id: i64,
    ) -> Result<Option<(Socks5ResourceRecord, i64)>, DbError> {
        let mut tx = self.pool.begin().await?;
        let resource: Option<Socks5ResourceRecord> =
            sqlx::query_as("SELECT * FROM socks5_resources WHERE id=$1 AND enabled=TRUE FOR SHARE")
                .bind(resource_id)
                .fetch_optional(&mut *tx)
                .await?;
        let Some(resource) = resource else {
            tx.rollback().await?;
            return Ok(None);
        };
        let generation: i64 = sqlx::query_scalar(
            "INSERT INTO socks5_check_generations(resource_id,relay_node_id,generation)
             VALUES($1,$2,1) ON CONFLICT(resource_id,relay_node_id) DO UPDATE SET
             generation=socks5_check_generations.generation+1 RETURNING generation",
        )
        .bind(resource_id)
        .bind(relay_node_id)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(Some((resource, generation)))
    }

    async fn record_socks5_health(
        &self,
        health: &Socks5HealthRecord,
        resource_generation: i64,
        generation: i64,
    ) -> Result<bool, DbError> {
        let mut tx = self.pool.begin().await?;
        let current: Option<i64> = sqlx::query_scalar(
            "SELECT health_generation FROM socks5_resources WHERE id=$1 FOR UPDATE",
        )
        .bind(health.resource_id)
        .fetch_optional(&mut *tx)
        .await?;
        let current_check: Option<i64> = sqlx::query_scalar(
            "SELECT generation FROM socks5_check_generations WHERE resource_id=$1 AND relay_node_id=$2 FOR UPDATE",
        )
        .bind(health.resource_id)
        .bind(health.relay_node_id)
        .fetch_optional(&mut *tx)
        .await?;
        if current != Some(resource_generation) || current_check != Some(generation) {
            tx.rollback().await?;
            return Ok(false);
        }
        let previous:i32=sqlx::query_scalar("SELECT COALESCE((SELECT consecutive_failures FROM socks5_resource_health WHERE resource_id=$1 AND relay_node_id=$2),0)")
            .bind(health.resource_id).bind(health.relay_node_id).fetch_one(&mut *tx).await?;
        let failures = if health.status == "ONLINE" {
            0
        } else {
            previous.saturating_add(1)
        };
        let last_success = if health.status == "ONLINE" {
            Some(health.checked_at.as_str())
        } else {
            health.last_success_at.as_deref()
        };
        sqlx::query("INSERT INTO socks5_resource_health(resource_id,relay_node_id,status,tcp_latency_ms,handshake_latency_ms,connect_latency_ms,total_latency_ms,exit_ip,country,error_stage,error_code,safe_error_message,consecutive_failures,resource_revision,generation,checked_at,last_success_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17) ON CONFLICT(resource_id,relay_node_id) DO UPDATE SET status=excluded.status,tcp_latency_ms=excluded.tcp_latency_ms,handshake_latency_ms=excluded.handshake_latency_ms,connect_latency_ms=excluded.connect_latency_ms,total_latency_ms=excluded.total_latency_ms,exit_ip=excluded.exit_ip,country=excluded.country,error_stage=excluded.error_stage,error_code=excluded.error_code,safe_error_message=excluded.safe_error_message,consecutive_failures=excluded.consecutive_failures,resource_revision=excluded.resource_revision,generation=excluded.generation,checked_at=excluded.checked_at,last_success_at=COALESCE(excluded.last_success_at,socks5_resource_health.last_success_at)")
            .bind(health.resource_id).bind(health.relay_node_id).bind(&health.status).bind(health.tcp_latency_ms)
            .bind(health.handshake_latency_ms).bind(health.connect_latency_ms).bind(health.total_latency_ms)
            .bind(&health.exit_ip).bind(&health.country).bind(&health.error_stage).bind(&health.error_code)
            .bind(&health.safe_error_message).bind(failures).bind(resource_generation).bind(generation).bind(&health.checked_at).bind(last_success)
            .execute(&mut *tx).await?;
        sqlx::query("INSERT INTO socks5_check_history(resource_id,relay_node_id,status,tcp_latency_ms,handshake_latency_ms,connect_latency_ms,total_latency_ms,exit_ip,country,error_stage,error_code,safe_error_message,checked_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)")
            .bind(health.resource_id).bind(health.relay_node_id).bind(&health.status).bind(health.tcp_latency_ms)
            .bind(health.handshake_latency_ms).bind(health.connect_latency_ms).bind(health.total_latency_ms)
            .bind(&health.exit_ip).bind(&health.country).bind(&health.error_stage).bind(&health.error_code)
            .bind(&health.safe_error_message).bind(&health.checked_at).execute(&mut *tx).await?;
        sqlx::query("UPDATE socks5_resources SET status=$1,detected_exit_ip=$2,detected_country=$3,latency_ms=$4,consecutive_failures=$5,last_check_at=$6,last_success_at=COALESCE($7,last_success_at),updated_at=to_char(now() AT TIME ZONE 'UTC','YYYY-MM-DD HH24:MI:SS') WHERE id=$8")
            .bind(&health.status).bind(&health.exit_ip).bind(&health.country).bind(health.total_latency_ms)
            .bind(failures).bind(&health.checked_at).bind(last_success).bind(health.resource_id)
            .execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(true)
    }
    async fn list_socks5_health(
        &self,
        resource_id: i64,
    ) -> Result<Vec<Socks5HealthRecord>, DbError> {
        Ok(sqlx::query_as(
            "SELECT * FROM socks5_resource_health WHERE resource_id=$1 ORDER BY relay_node_id",
        )
        .bind(resource_id)
        .fetch_all(&self.pool)
        .await?)
    }
    async fn list_socks5_check_history(
        &self,
        resource_id: i64,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Socks5CheckHistoryRecord>, DbError> {
        Ok(sqlx::query_as("SELECT * FROM socks5_check_history WHERE resource_id=$1 ORDER BY checked_at DESC,id DESC LIMIT $2 OFFSET $3")
            .bind(resource_id).bind(limit).bind(offset).fetch_all(&self.pool).await?)
    }
    async fn prune_socks5_check_history(&self, cutoff: &str) -> Result<u64, DbError> {
        Ok(sqlx::query(
            "DELETE FROM socks5_check_history WHERE id IN (
                    SELECT id FROM socks5_check_history
                    WHERE checked_at < $1 ORDER BY id LIMIT 10000
                 )",
        )
        .bind(cutoff)
        .execute(&self.pool)
        .await?
        .rows_affected())
    }
}
