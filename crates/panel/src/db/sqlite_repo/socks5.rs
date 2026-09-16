use super::SqliteRepository;
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

#[async_trait]
impl Socks5Repository for SqliteRepository {
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
        let result = sqlx::query(
            "INSERT INTO socks5_resources
             (name,host,port,username,password_ciphertext,password_nonce,password_key_version,
              country,country_code,region,city,isp,remark,status,enabled)
             VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,CASE WHEN ? THEN 'UNKNOWN' ELSE 'DISABLED' END,?)",
        )
        .bind(name)
        .bind(host)
        .bind(port)
        .bind(username)
        .bind(password_ciphertext)
        .bind(password_nonce)
        .bind(password_key_version)
        .bind(country)
        .bind(country_code)
        .bind(region)
        .bind(city)
        .bind(isp)
        .bind(remark)
        .bind(enabled)
        .bind(enabled)
        .execute(&self.pool)
        .await?;
        Ok(result.last_insert_rowid())
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
        let mut where_sql = Vec::new();
        let mut values = Vec::<String>::new();
        if let Some(value) = query.search.as_deref().filter(|v| !v.is_empty()) {
            where_sql.push("(LOWER(name) LIKE ? OR LOWER(host) LIKE ? OR LOWER(COALESCE(detected_exit_ip,'')) LIKE ?)");
            let pattern = format!("%{}%", value.to_lowercase());
            values.extend([pattern.clone(), pattern.clone(), pattern]);
        }
        for (column, value) in [
            ("status", query.status.as_ref()),
            ("country_code", query.country.as_ref()),
            ("detected_country", query.detected_country.as_ref()),
        ] {
            if let Some(value) = value.filter(|v| !v.is_empty()) {
                where_sql.push(match column {
                    "status" => "status = ?",
                    "country_code" => "country_code = ?",
                    _ => "detected_country = ?",
                });
                values.push(value.to_owned());
            }
        }
        if let Some(tag) = query.tag.as_deref().filter(|v| !v.is_empty()) {
            where_sql.push(
                "EXISTS (SELECT 1 FROM json_each(socks5_resources.tags) WHERE LOWER(value) = ?)",
            );
            values.push(tag.to_lowercase());
        }
        if query.enabled.is_some() {
            where_sql.push("enabled = ?");
        }
        let clause = if where_sql.is_empty() {
            String::new()
        } else {
            format!(" WHERE {}", where_sql.join(" AND "))
        };
        let count_sql = format!("SELECT COUNT(*) FROM socks5_resources{clause}");
        let mut count_query = sqlx::query_scalar::<_, i64>(&count_sql);
        for value in &values {
            count_query = count_query.bind(value);
        }
        if let Some(enabled) = query.enabled {
            count_query = count_query.bind(enabled);
        }
        let total = count_query.fetch_one(&self.pool).await?;
        let sort = match query.sort.as_str() {
            "name" => "name",
            "host" => "host",
            "country" => "country_code",
            "status" => "status",
            "latency" => "latency_ms",
            "last_check" => "last_check_at",
            _ => "id",
        };
        let direction = if query.descending { "DESC" } else { "ASC" };
        let sql = format!(
            "SELECT * FROM socks5_resources{clause} ORDER BY {sort} {direction}, id DESC LIMIT ? OFFSET ?"
        );
        let mut rows_query = sqlx::query_as::<_, Socks5ResourceRecord>(&sql);
        for value in &values {
            rows_query = rows_query.bind(value);
        }
        if let Some(enabled) = query.enabled {
            rows_query = rows_query.bind(enabled);
        }
        let rows = rows_query
            .bind(query.limit)
            .bind(query.offset)
            .fetch_all(&self.pool)
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
        let placeholders = vec!["?"; resource_ids.len()].join(",");
        let sql = format!(
            "SELECT resource_id,relay_node_id,relay_node_name,status,total_latency_ms,exit_ip,country,consecutive_failures,checked_at FROM (
                SELECT h.resource_id,h.relay_node_id,
                       CASE WHEN n.name='' THEN n.node_key ELSE n.name END AS relay_node_name,
                       h.status,h.total_latency_ms,h.exit_ip,h.country,h.consecutive_failures,h.checked_at,
                       ROW_NUMBER() OVER (PARTITION BY h.resource_id ORDER BY h.checked_at DESC,h.relay_node_id DESC) AS row_number
                FROM socks5_resource_health h JOIN relay_nodes n ON n.id=h.relay_node_id
                WHERE h.resource_id IN ({placeholders})
             ) ranked WHERE row_number=1"
        );
        let mut query = sqlx::query_as(&sql);
        for id in resource_ids {
            query = query.bind(id);
        }
        Ok(query.fetch_all(&self.pool).await?)
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
        let mut conn = self.pool.acquire().await?;
        sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;
        macro_rules! try_ {
            ($expr:expr) => {
                match $expr {
                    Ok(v) => v,
                    Err(e) => {
                        let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                        return Err(DbError::from(e));
                    }
                }
            };
        }
        let mut outcome = BulkImportOutcome::default();
        for row in rows {
            let existing: Option<i64> = try_!(sqlx::query_scalar(
                "SELECT id FROM socks5_resources WHERE host=? AND port=? AND COALESCE(username,'')=?"
            )
            .bind(&row.host).bind(row.port).bind(row.username.as_deref().unwrap_or(""))
            .fetch_optional(&mut *conn).await);
            if let Some(id) = existing {
                if update_credentials && row.password_ciphertext.is_some() {
                    try_!(sqlx::query(
                        "UPDATE socks5_resources SET password_ciphertext=?,password_nonce=?,password_key_version=?,health_generation=health_generation+1,status='UNKNOWN',last_check_at=NULL,updated_at=datetime('now') WHERE id=?"
                    ).bind(&row.password_ciphertext).bind(&row.password_nonce)
                    .bind(row.password_key_version).bind(id).execute(&mut *conn).await);
                    outcome.updated += 1;
                } else {
                    outcome.skipped += 1;
                }
                continue;
            }
            try_!(sqlx::query(
                "INSERT INTO socks5_resources(name,host,port,username,password_ciphertext,password_nonce,password_key_version,status,enabled) VALUES(?,?,?,?,?,?,?,'UNKNOWN',1)"
            ).bind(&row.name).bind(&row.host).bind(row.port).bind(&row.username)
            .bind(&row.password_ciphertext).bind(&row.password_nonce).bind(row.password_key_version)
            .execute(&mut *conn).await);
            outcome.created += 1;
        }
        sqlx::query("COMMIT").execute(&mut *conn).await?;
        Ok(outcome)
    }

    async fn find_socks5_resource(&self, id: i64) -> Result<Option<Socks5ResourceRecord>, DbError> {
        Ok(sqlx::query_as("SELECT * FROM socks5_resources WHERE id=?")
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
        let result = sqlx::query(
            "UPDATE socks5_resources SET name=?,host=?,port=?,username=?,password_ciphertext=?,
             password_nonce=?,password_key_version=?,country=?,country_code=?,region=?,city=?,isp=?,
             remark=?,enabled=?,status=CASE WHEN ? THEN CASE WHEN status='DISABLED' THEN 'UNKNOWN' ELSE status END
             ELSE 'DISABLED' END,health_generation=health_generation+1,updated_at=datetime('now') WHERE id=?")
            .bind(name).bind(host).bind(port).bind(username).bind(password_ciphertext)
            .bind(password_nonce).bind(password_key_version).bind(country).bind(country_code)
            .bind(region).bind(city).bind(isp).bind(remark).bind(enabled).bind(enabled).bind(id)
            .execute(&self.pool).await?;
        Ok(result.rows_affected())
    }

    async fn set_socks5_resource_enabled(&self, id: i64, enabled: bool) -> Result<u64, DbError> {
        let result = sqlx::query(
            "UPDATE socks5_resources SET enabled=?,status=CASE WHEN ? THEN 'UNKNOWN' ELSE 'DISABLED' END,
             health_generation=health_generation+1,updated_at=datetime('now') WHERE id=?")
            .bind(enabled).bind(enabled).bind(id).execute(&self.pool).await?;
        Ok(result.rows_affected())
    }

    async fn bulk_set_socks5_resources_enabled(
        &self,
        ids: &[i64],
        enabled: bool,
    ) -> Result<u64, DbError> {
        if ids.is_empty() {
            return Ok(0);
        }
        let placeholders = vec!["?"; ids.len()].join(",");
        let sql = format!(
            "UPDATE socks5_resources SET enabled=?,status=CASE WHEN ? THEN CASE WHEN status='DISABLED' THEN 'UNKNOWN' ELSE status END ELSE 'DISABLED' END,health_generation=health_generation+1,updated_at=datetime('now') WHERE id IN ({placeholders})"
        );
        let mut query = sqlx::query(&sql).bind(enabled).bind(enabled);
        for id in ids {
            query = query.bind(id);
        }
        Ok(query.execute(&self.pool).await?.rows_affected())
    }

    async fn bulk_set_socks5_resource_tags(
        &self,
        ids: &[i64],
        tags_json: &str,
    ) -> Result<u64, DbError> {
        if ids.is_empty() {
            return Ok(0);
        }
        let placeholders = vec!["?"; ids.len()].join(",");
        let sql = format!(
            "UPDATE socks5_resources SET tags=?,updated_at=datetime('now') WHERE id IN ({placeholders})"
        );
        let mut query = sqlx::query(&sql).bind(tags_json);
        for id in ids {
            query = query.bind(id);
        }
        Ok(query.execute(&self.pool).await?.rows_affected())
    }

    async fn bulk_delete_socks5_resources_guarded(
        &self,
        ids: &[i64],
    ) -> Result<(u64, Vec<(i64, i64)>), DbError> {
        if ids.is_empty() {
            return Ok((0, Vec::new()));
        }
        let placeholders = vec!["?"; ids.len()].join(",");
        let mut tx = self.pool.begin().await?;
        let blocker_sql = format!(
            "SELECT socks5_resource_id,rule_id FROM socks5_rule_bindings WHERE socks5_resource_id IN ({placeholders}) ORDER BY socks5_resource_id,rule_id"
        );
        let mut blockers_query = sqlx::query_as::<_, (i64, i64)>(&blocker_sql);
        for id in ids {
            blockers_query = blockers_query.bind(id);
        }
        let blockers = blockers_query.fetch_all(&mut *tx).await?;
        let blocked = blockers
            .iter()
            .map(|row| row.0)
            .collect::<std::collections::HashSet<_>>();
        let deletable = ids
            .iter()
            .filter(|id| !blocked.contains(id))
            .copied()
            .collect::<Vec<_>>();
        let deleted = if deletable.is_empty() {
            0
        } else {
            let delete_placeholders = vec!["?"; deletable.len()].join(",");
            let delete_sql =
                format!("DELETE FROM socks5_resources WHERE id IN ({delete_placeholders})");
            let mut delete_query = sqlx::query(&delete_sql);
            for id in deletable {
                delete_query = delete_query.bind(id);
            }
            delete_query.execute(&mut *tx).await?.rows_affected()
        };
        tx.commit().await?;
        Ok((deleted, blockers))
    }

    async fn delete_socks5_resource(&self, id: i64) -> Result<u64, DbError> {
        Ok(sqlx::query("DELETE FROM socks5_resources WHERE id=?")
            .bind(id)
            .execute(&self.pool)
            .await?
            .rows_affected())
    }

    async fn count_socks5_resource_bindings(&self, id: i64) -> Result<i64, DbError> {
        Ok(sqlx::query_scalar(
            "SELECT COUNT(*) FROM socks5_rule_bindings WHERE socks5_resource_id=?",
        )
        .bind(id)
        .fetch_one(&self.pool)
        .await?)
    }

    async fn find_socks5_rule_config(
        &self,
        rule_id: i64,
    ) -> Result<Option<Socks5RuleConfigRecord>, DbError> {
        Ok(sqlx::query_as(
            "SELECT b.rule_id,b.socks5_resource_id,b.remote_dns,b.relay_username,
             b.relay_node_id,b.selection_mode,n.enabled relay_node_enabled,
             b.relay_password_ciphertext,b.relay_password_nonce,b.relay_password_key_version,b.allow_no_auth,
             r.name resource_name,r.host resource_host,r.port resource_port,r.username resource_username,
             r.password_ciphertext resource_password_ciphertext,r.password_nonce resource_password_nonce,
             r.password_key_version resource_password_key_version,r.enabled resource_enabled
             FROM socks5_rule_bindings b JOIN socks5_resources r ON r.id=b.socks5_resource_id
             LEFT JOIN relay_nodes n ON n.id=b.relay_node_id
             WHERE b.rule_id=?")
            .bind(rule_id).fetch_optional(&self.pool).await?)
    }

    async fn list_socks5_rule_views(&self) -> Result<Vec<Socks5RuleViewRecord>, DbError> {
        Ok(sqlx::query_as(
            "SELECT f.id rule_id,f.name,f.listen_port,f.device_group_in,g.connect_host,f.paused,f.traffic_used,
             b.socks5_resource_id,r.name resource_name,r.detected_exit_ip,r.detected_country,
             b.relay_node_id,n.name relay_node_name,n.country_code relay_node_country_code,
             n.advertise_host,n.public_ip relay_node_public_ip,n.enabled relay_node_enabled,
             b.selection_mode,b.relay_username,
             b.allow_no_auth,b.remote_dns,f.created_at
             FROM forward_rules f JOIN socks5_rule_bindings b ON b.rule_id=f.id
             JOIN socks5_resources r ON r.id=b.socks5_resource_id
             LEFT JOIN relay_nodes n ON n.id=b.relay_node_id
             JOIN device_groups g ON g.id=f.device_group_in ORDER BY f.id DESC")
            .fetch_all(&self.pool).await?)
    }

    async fn list_relay_node_capacities(&self) -> Result<Vec<RelayNodeCapacityRecord>, DbError> {
        Ok(sqlx::query_as(
            "SELECT n.id relay_node_id,n.device_group_id,g.port_range,
                    COALESCE(p.port_used,0) port_used,g.group_type,g.capabilities group_capabilities
             FROM relay_nodes n JOIN device_groups g ON g.id=n.device_group_id
             LEFT JOIN (
                 SELECT device_group_in,COUNT(DISTINCT listen_port) port_used
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
             WHERE h.resource_id=? ORDER BY h.relay_node_id",
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
        let mut conn = self.pool.acquire().await?;
        sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;
        macro_rules! try_ {
            ($expr:expr) => {
                match $expr {
                    Ok(v) => v,
                    Err(e) => {
                        let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                        return Err(DbError::from(e));
                    }
                }
            };
        }

        let resource_ok: Option<(i64,)> = try_!(
            sqlx::query_as("SELECT 1 FROM socks5_resources WHERE id=? AND enabled=1")
                .bind(socks5_resource_id)
                .fetch_optional(&mut *conn)
                .await
        );
        if resource_ok.is_none() {
            let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
            return Err(DbError::NotFound);
        }
        let conflict: Option<(i64,)> = try_!(
            sqlx::query_as(
                "SELECT 1 FROM forward_rules WHERE device_group_in=? AND listen_port=?
             AND protocol IN ('tcp','tcp_udp') LIMIT 1"
            )
            .bind(device_group_in)
            .bind(listen_port)
            .fetch_optional(&mut *conn)
            .await
        );
        if conflict.is_some() {
            let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
            return Err(DbError::PortConflict);
        }

        let result = try_!(sqlx::query(
            "INSERT INTO forward_rules
             (name,uid,paused,listen_port,protocol,public_transport,node_transport,route_mode,entry_transport,
              device_group_in,device_group_out,forward_mode,target_addr,target_port)
             SELECT ?,?,?,?,'tcp','raw','raw','direct','raw',?,NULL,'direct','',0
             WHERE (SELECT max_rules FROM users WHERE id=?)=0 OR
             (SELECT COUNT(*) FROM forward_rules WHERE uid=?) < (SELECT max_rules FROM users WHERE id=?)")
            .bind(name).bind(uid).bind(!enabled).bind(listen_port).bind(device_group_in)
            .bind(uid).bind(uid).bind(uid).execute(&mut *conn).await);
        if result.rows_affected() == 0 {
            sqlx::query("COMMIT").execute(&mut *conn).await?;
            return Ok(None);
        }
        let rule_id = result.last_insert_rowid();
        try_!(
            sqlx::query(
                "INSERT INTO socks5_rule_bindings
             (rule_id,socks5_resource_id,remote_dns,relay_username,relay_password_ciphertext,
              relay_password_nonce,relay_password_key_version,allow_no_auth)
             VALUES (?,?,?,?,?,?,?,?)"
            )
            .bind(rule_id)
            .bind(socks5_resource_id)
            .bind(remote_dns)
            .bind(relay_username)
            .bind(relay_password_ciphertext)
            .bind(relay_password_nonce)
            .bind(relay_password_key_version)
            .bind(allow_no_auth)
            .execute(&mut *conn)
            .await
        );
        sqlx::query("COMMIT").execute(&mut *conn).await?;
        Ok(Some(rule_id))
    }

    async fn create_smart_relay(
        &self,
        input: &SmartRelayCreateInput,
    ) -> Result<SmartRelayCreateOutcome, DbError> {
        let mut conn = self.pool.acquire().await?;
        sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;
        macro_rules! rollback_reject {
            ($code:expr) => {{
                sqlx::query("ROLLBACK").execute(&mut *conn).await?;
                return Ok(SmartRelayCreateOutcome::Rejected($code));
            }};
        }

        let operation = async {
            let idempotency_cutoff: String =
                sqlx::query_scalar("SELECT datetime('now','-7 days')")
                    .fetch_one(&mut *conn)
                    .await?;
            sqlx::query(
                "DELETE FROM relay_creation_receipts WHERE id IN (
                    SELECT id FROM relay_creation_receipts
                    WHERE created_at < ? ORDER BY id LIMIT 10000
                 )",
            )
            .bind(&idempotency_cutoff)
            .execute(&mut *conn)
            .await?;
            sqlx::query(
                "DELETE FROM relay_creation_idempotency_keys WHERE rowid IN (
                    SELECT rowid FROM relay_creation_idempotency_keys
                    WHERE created_at < ? ORDER BY created_at LIMIT 10000
                 )",
            )
            .bind(&idempotency_cutoff)
            .execute(&mut *conn)
            .await?;
            // Global pruning is storage maintenance only. Expire the current
            // key independently so bounded cleanup cannot decide idempotency.
            sqlx::query(
                "DELETE FROM relay_creation_receipts
                 WHERE actor_id=? AND idempotency_key=? AND created_at < ?",
            )
            .bind(input.actor_id)
            .bind(&input.idempotency_key)
            .bind(&idempotency_cutoff)
            .execute(&mut *conn)
            .await?;
            sqlx::query(
                "DELETE FROM relay_creation_idempotency_keys
                 WHERE actor_id=? AND idempotency_key=? AND created_at < ?",
            )
            .bind(input.actor_id)
            .bind(&input.idempotency_key)
            .bind(&idempotency_cutoff)
            .execute(&mut *conn)
            .await?;
            let receipt_fingerprint: Option<String> = sqlx::query_scalar(
                "SELECT request_fingerprint FROM relay_creation_receipts
                 WHERE actor_id=? AND idempotency_key=? AND created_at >= ?",
            )
            .bind(input.actor_id)
            .bind(&input.idempotency_key)
            .bind(&idempotency_cutoff)
            .fetch_optional(&mut *conn)
            .await?;
            if receipt_fingerprint
                .as_deref()
                .is_some_and(|fingerprint| fingerprint != input.request_fingerprint)
            {
                return Ok::<_, sqlx::Error>(Err("IDEMPOTENCY_KEY_REUSED"));
            }
            let replay: Option<SmartRelayCreatedRecord> = sqlx::query_as(
                "SELECT r.rule_id,r.relay_node_id,r.resource_id,r.endpoint_host,r.listen_port,
                        r.relay_username,r.exit_ip,r.exit_country,r.selection_mode
                 FROM relay_creation_receipts r
                 INNER JOIN forward_rules f ON f.id=r.rule_id
                 WHERE r.actor_id=? AND r.idempotency_key=? AND r.created_at >= ?",
            )
            .bind(input.actor_id)
            .bind(&input.idempotency_key)
            .bind(&idempotency_cutoff)
            .fetch_optional(&mut *conn)
            .await?;
            if let Some(replay) = replay {
                return Ok(Ok(SmartRelayCreateOutcome::Replay(replay)));
            }
            sqlx::query(
                "DELETE FROM relay_creation_receipts
                 WHERE actor_id=? AND idempotency_key=?",
            )
            .bind(input.actor_id)
            .bind(&input.idempotency_key)
            .execute(&mut *conn)
            .await?;
            let key_fingerprint: Option<String> = sqlx::query_scalar(
                "SELECT request_fingerprint FROM relay_creation_idempotency_keys
                 WHERE actor_id=? AND idempotency_key=? AND created_at >= ?",
            )
            .bind(input.actor_id)
            .bind(&input.idempotency_key)
            .bind(&idempotency_cutoff)
            .fetch_optional(&mut *conn)
            .await?;
            if key_fingerprint
                .as_deref()
                .is_some_and(|fingerprint| fingerprint != input.request_fingerprint)
            {
                return Ok::<_, sqlx::Error>(Err("IDEMPOTENCY_KEY_REUSED"));
            }

            let resource: Option<(bool, i64)> = sqlx::query_as(
                "SELECT enabled,health_generation FROM socks5_resources WHERE id=?",
            )
            .bind(input.resource_id)
            .fetch_optional(&mut *conn)
            .await?;
            let Some((resource_enabled, resource_revision)) = resource else {
                return Ok(Err("RESOURCE_NOT_FOUND"));
            };
            if !resource_enabled {
                return Ok(Err("RESOURCE_DISABLED"));
            }
            if resource_revision != input.expected_resource_revision {
                return Ok(Err("RESOURCE_CHANGED"));
            }

            let node: Option<(i64, String, bool, String, String, String)> = sqlx::query_as(
                "SELECT device_group_id,node_key,enabled,identity_secret_hash,advertise_host,public_ip
                 FROM relay_nodes WHERE id=?",
            )
            .bind(input.relay_node_id)
            .fetch_optional(&mut *conn)
            .await?;
            let Some((group_id, node_key, node_enabled, identity_hash, advertise_host, public_ip)) = node else {
                return Ok(Err("NODE_NOT_FOUND"));
            };
            if !node_enabled {
                return Ok(Err("NODE_DISABLED"));
            }
            if identity_hash.len() != 64 {
                return Ok(Err("NODE_IDENTITY_UNTRUSTED"));
            }
            let endpoint_host = if advertise_host.is_empty() { public_ip } else { advertise_host };
            if endpoint_host.is_empty() {
                return Ok(Err("NODE_ACCESS_HOST_MISSING"));
            }
            let status_key = format!("node_status:{group_id}:{node_key}");
            let status: Option<String> =
                sqlx::query_scalar("SELECT value FROM kvs WHERE key=?")
                    .bind(&status_key)
                    .fetch_optional(&mut *conn)
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
                return Ok(Err(code));
            }

            let group: Option<(String, String, String)> = sqlx::query_as(
                "SELECT group_type,port_range,capabilities FROM device_groups WHERE id=?",
            )
            .bind(group_id)
            .fetch_optional(&mut *conn)
            .await?;
            let Some((group_type, port_range, capabilities)) = group else {
                return Ok(Err("NODE_NOT_FOUND"));
            };
            let tcp_capable = serde_json::from_str::<Vec<String>>(&capabilities)
                .unwrap_or_default();
            if group_type != "in"
                || (!tcp_capable.is_empty()
                    && !tcp_capable.iter().any(|value| value == "tcp" || value == "tcp_udp"))
            {
                return Ok(Err("NODE_UNSUPPORTED"));
            }

            let health: Option<(String, Option<String>, Option<String>, String, i64, i64)> =
                sqlx::query_as(
                    "SELECT status,exit_ip,country,checked_at,resource_revision,generation
                     FROM socks5_resource_health WHERE resource_id=? AND relay_node_id=?",
                )
                .bind(input.resource_id)
                .bind(input.relay_node_id)
                .fetch_optional(&mut *conn)
                .await?;
            let Some((health_status, exit_ip, exit_country, checked_at, health_revision, generation)) = health else {
                return Ok(Err("HEALTH_MISSING"));
            };
            if health_status != "ONLINE" {
                return Ok(Err("HEALTH_NOT_ONLINE"));
            }
            if health_revision != resource_revision {
                return Ok(Err("RESOURCE_CHANGED"));
            }
            if generation != input.expected_health_generation
                || checked_at != input.expected_health_checked_at
            {
                return Ok(Err("RECOMMENDATION_STALE"));
            }
            let current_generation: Option<i64> = sqlx::query_scalar(
                "SELECT generation FROM socks5_check_generations WHERE resource_id=? AND relay_node_id=?",
            )
            .bind(input.resource_id)
            .bind(input.relay_node_id)
            .fetch_optional(&mut *conn)
            .await?;
            if current_generation != Some(generation) {
                return Ok(Err("RECOMMENDATION_STALE"));
            }
            if !stage4_health_fresh(&checked_at, input.health_ttl_seconds) {
                return Ok(Err("HEALTH_STALE"));
            }
            let Some(exit_ip) = exit_ip.filter(|value| value.parse::<std::net::IpAddr>().is_ok()) else {
                return Ok(Err("EXIT_IP_MISMATCH"));
            };

            let (low, high) = crate::service::rules::resolve_auto_port_range(&port_range);
            let used_ports: Vec<i32> = sqlx::query_scalar(
                "SELECT listen_port FROM forward_rules
                 WHERE device_group_in=? AND protocol IN ('tcp','tcp_udp')",
            )
            .bind(group_id)
            .fetch_all(&mut *conn)
            .await?;
            let used = used_ports.into_iter().collect::<std::collections::HashSet<_>>();
            let listen_port = match input.requested_port {
                Some(port) => {
                    if port < i32::from(low) || port > i32::from(high) {
                        return Ok(Err("PORT_OUT_OF_RANGE"));
                    }
                    if used.contains(&port) {
                        return Ok(Err("PORT_CONFLICT"));
                    }
                    port
                }
                None => match (low..=high).map(i32::from).find(|port| !used.contains(port)) {
                    Some(port) => port,
                    None => return Ok(Err("NO_AVAILABLE_PORT")),
                },
            };

            let inserted = sqlx::query(
                "INSERT INTO forward_rules
                 (name,uid,paused,listen_port,protocol,public_transport,node_transport,route_mode,
                  entry_transport,device_group_in,device_group_out,forward_mode,target_addr,target_port)
                 SELECT ?,?,0,?,'tcp','raw','raw','direct','raw',?,NULL,'direct','',0
                 WHERE (SELECT max_rules FROM users WHERE id=?)=0 OR
                       (SELECT COUNT(*) FROM forward_rules WHERE uid=?) <
                       (SELECT max_rules FROM users WHERE id=?)",
            )
            .bind(&input.name)
            .bind(input.actor_id)
            .bind(listen_port)
            .bind(group_id)
            .bind(input.actor_id)
            .bind(input.actor_id)
            .bind(input.actor_id)
            .execute(&mut *conn)
            .await?;
            if inserted.rows_affected() == 0 {
                return Ok(Ok(SmartRelayCreateOutcome::QuotaExceeded));
            }
            let rule_id = inserted.last_insert_rowid();
            sqlx::query(
                "INSERT INTO socks5_rule_bindings
                 (rule_id,socks5_resource_id,relay_node_id,selection_mode,remote_dns,relay_username,
                  relay_password_ciphertext,relay_password_nonce,relay_password_key_version,allow_no_auth)
                 VALUES(?,?,?,?,1,?,?,?,?,0)",
            )
            .bind(rule_id)
            .bind(input.resource_id)
            .bind(input.relay_node_id)
            .bind(&input.selection_mode)
            .bind(&input.relay_username)
            .bind(&input.relay_password_ciphertext)
            .bind(&input.relay_password_nonce)
            .bind(input.relay_password_key_version)
            .execute(&mut *conn)
            .await?;
            sqlx::query(
                "INSERT INTO relay_creation_idempotency_keys
                 (actor_id,idempotency_key,request_fingerprint,created_at)
                 VALUES(?,?,?,datetime('now'))
                 ON CONFLICT(actor_id,idempotency_key) DO UPDATE
                 SET created_at=excluded.created_at
                 WHERE relay_creation_idempotency_keys.request_fingerprint=excluded.request_fingerprint",
            )
            .bind(input.actor_id)
            .bind(&input.idempotency_key)
            .bind(&input.request_fingerprint)
            .execute(&mut *conn)
            .await?;
            sqlx::query(
                "INSERT INTO relay_creation_receipts
                 (actor_id,idempotency_key,request_fingerprint,rule_id,relay_node_id,resource_id,
                  endpoint_host,listen_port,relay_username,exit_ip,exit_country,selection_mode)
                 VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
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
            .execute(&mut *conn)
            .await?;
            Ok(Ok(SmartRelayCreateOutcome::Created(SmartRelayCreatedRecord {
                rule_id,
                relay_node_id: input.relay_node_id,
                resource_id: input.resource_id,
                endpoint_host,
                listen_port,
                relay_username: input.relay_username.clone(),
                exit_ip,
                exit_country,
                selection_mode: input.selection_mode.clone(),
            })))
        }
        .await;

        match operation {
            Ok(Ok(outcome)) => {
                sqlx::query("COMMIT").execute(&mut *conn).await?;
                Ok(outcome)
            }
            Ok(Err(code)) => rollback_reject!(code),
            Err(error) => {
                let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                Err(DbError::from(error))
            }
        }
    }

    async fn find_smart_relay_receipt(
        &self,
        actor_id: i64,
        idempotency_key: &str,
    ) -> Result<Option<SmartRelayReceiptRecord>, DbError> {
        let mut conn = self.pool.acquire().await?;
        // The single INNER JOIN reads receipt and live rule from one consistent
        // snapshot. A concurrent delete after that snapshot can linearize after
        // replay; a delete committed before a new replay makes the JOIN empty.
        sqlx::query("BEGIN").execute(&mut *conn).await?;
        let receipt = sqlx::query_as(
            "SELECT r.request_fingerprint,r.rule_id,r.relay_node_id,r.resource_id,r.endpoint_host,
                    r.listen_port,r.relay_username,r.exit_ip,r.exit_country,r.selection_mode
             FROM relay_creation_receipts r
             INNER JOIN forward_rules f ON f.id=r.rule_id
             WHERE r.actor_id=? AND r.idempotency_key=?
               AND r.created_at >= datetime('now','-7 days')",
        )
        .bind(actor_id)
        .bind(idempotency_key)
        .fetch_optional(&mut *conn)
        .await;
        match receipt {
            Ok(receipt) => {
                sqlx::query("COMMIT").execute(&mut *conn).await?;
                Ok(receipt)
            }
            Err(error) => {
                let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                Err(error.into())
            }
        }
    }
    async fn find_smart_relay_idempotency_fingerprint(
        &self,
        actor_id: i64,
        idempotency_key: &str,
    ) -> Result<Option<String>, DbError> {
        Ok(sqlx::query_scalar(
            "SELECT request_fingerprint FROM relay_creation_idempotency_keys
             WHERE actor_id=? AND idempotency_key=?
               AND created_at >= datetime('now','-7 days')",
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
        let mut conn = self.pool.acquire().await?;
        sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;
        macro_rules! try_ {
            ($expr:expr) => {
                match $expr {
                    Ok(v) => v,
                    Err(e) => {
                        let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                        return Err(DbError::from(e));
                    }
                }
            };
        }

        let resource_ok: Option<(i64,)> = try_!(
            sqlx::query_as("SELECT 1 FROM socks5_resources WHERE id=? AND enabled=1")
                .bind(socks5_resource_id)
                .fetch_optional(&mut *conn)
                .await
        );
        if resource_ok.is_none() {
            let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
            return Err(DbError::NotFound);
        }
        let conflict: Option<(i64,)> = try_!(
            sqlx::query_as(
                "SELECT 1 FROM forward_rules WHERE id<>? AND device_group_in=? AND listen_port=?
                 AND protocol IN ('tcp','tcp_udp') LIMIT 1",
            )
            .bind(rule_id)
            .bind(device_group_in)
            .bind(listen_port)
            .fetch_optional(&mut *conn)
            .await
        );
        if conflict.is_some() {
            let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
            return Err(DbError::PortConflict);
        }
        let updated = try_!(
            sqlx::query(
                "UPDATE forward_rules SET name=?,listen_port=?,device_group_in=?,paused=?,auto_paused=0
                 WHERE id=? AND EXISTS (SELECT 1 FROM socks5_rule_bindings WHERE rule_id=?)",
            )
            .bind(name)
            .bind(listen_port)
            .bind(device_group_in)
            .bind(!enabled)
            .bind(rule_id)
            .bind(rule_id)
            .execute(&mut *conn)
            .await
        );
        if updated.rows_affected() == 0 {
            let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
            return Ok(0);
        }
        try_!(
            sqlx::query(
                "UPDATE socks5_rule_bindings SET socks5_resource_id=?,remote_dns=?,updated_at=datetime('now')
                 WHERE rule_id=?",
            )
            .bind(socks5_resource_id)
            .bind(remote_dns)
            .bind(rule_id)
            .execute(&mut *conn)
            .await
        );
        sqlx::query("COMMIT").execute(&mut *conn).await?;
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
        Ok(sqlx::query(
            "UPDATE socks5_rule_bindings SET relay_username=?,relay_password_ciphertext=?,
             relay_password_nonce=?,relay_password_key_version=?,allow_no_auth=0,updated_at=datetime('now')
             WHERE rule_id=?")
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
        Ok(sqlx::query_scalar(
            "INSERT INTO relay_nodes(device_group_id,node_key,identity_secret_hash,name,public_ip,first_seen_at,last_seen_at)
             VALUES(?,?,?,?,?,?,?) ON CONFLICT(device_group_id,node_key) DO UPDATE SET
             identity_secret_hash=CASE WHEN relay_nodes.identity_secret_hash='' THEN excluded.identity_secret_hash ELSE relay_nodes.identity_secret_hash END,
             public_ip=CASE WHEN excluded.public_ip='' THEN relay_nodes.public_ip ELSE excluded.public_ip END,
             last_seen_at=excluded.last_seen_at,updated_at=datetime('now')
             WHERE relay_nodes.identity_secret_hash='' OR relay_nodes.identity_secret_hash=excluded.identity_secret_hash
             RETURNING id",
        )
        .bind(device_group_id)
        .bind(node_key)
        .bind(identity_secret_hash)
        .bind(node_key)
        .bind(public_ip)
        .bind(seen_at)
        .bind(seen_at)
        .fetch_optional(&self.pool)
        .await?)
    }

    async fn list_relay_nodes(&self) -> Result<Vec<RelayNodeRecord>, DbError> {
        Ok(sqlx::query_as("SELECT * FROM relay_nodes ORDER BY id")
            .fetch_all(&self.pool)
            .await?)
    }

    async fn find_relay_node(&self, id: i64) -> Result<Option<RelayNodeRecord>, DbError> {
        Ok(sqlx::query_as("SELECT * FROM relay_nodes WHERE id=?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?)
    }

    async fn replace_relay_node_identity(
        &self,
        id: i64,
        identity_secret_hash: &str,
    ) -> Result<u64, DbError> {
        Ok(sqlx::query(
            "UPDATE relay_nodes SET identity_secret_hash=?,updated_at=datetime('now') WHERE id=?",
        )
        .bind(identity_secret_hash)
        .bind(id)
        .execute(&self.pool)
        .await?
        .rows_affected())
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
        Ok(sqlx::query(
            "UPDATE relay_nodes SET name=?,country=?,country_code=?,region=?,city=?,provider=?,advertise_host=?,bandwidth_mbps=?,remark=?,tags=?,enabled=?,updated_at=datetime('now') WHERE id=?"
        ).bind(name).bind(country).bind(country_code).bind(region).bind(city).bind(provider)
        .bind(advertise_host).bind(bandwidth_mbps).bind(remark).bind(tags).bind(enabled).bind(id)
        .execute(&self.pool).await?.rows_affected())
    }

    async fn begin_socks5_health_check(
        &self,
        resource_id: i64,
        relay_node_id: i64,
    ) -> Result<Option<(Socks5ResourceRecord, i64)>, DbError> {
        let mut conn = self.pool.acquire().await?;
        sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;
        macro_rules! try_rollback {
            ($expression:expr) => {
                match $expression {
                    Ok(value) => value,
                    Err(error) => {
                        let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                        return Err(DbError::from(error));
                    }
                }
            };
        }
        let resource: Option<Socks5ResourceRecord> = try_rollback!(
            sqlx::query_as("SELECT * FROM socks5_resources WHERE id=? AND enabled=1")
                .bind(resource_id)
                .fetch_optional(&mut *conn)
                .await
        );
        let Some(resource) = resource else {
            sqlx::query("ROLLBACK").execute(&mut *conn).await?;
            return Ok(None);
        };
        let generation: i64 = try_rollback!(
            sqlx::query_scalar(
                "INSERT INTO socks5_check_generations(resource_id,relay_node_id,generation)
             VALUES(?,?,1) ON CONFLICT(resource_id,relay_node_id) DO UPDATE SET
             generation=socks5_check_generations.generation+1 RETURNING generation",
            )
            .bind(resource_id)
            .bind(relay_node_id)
            .fetch_one(&mut *conn)
            .await
        );
        try_rollback!(sqlx::query("COMMIT").execute(&mut *conn).await);
        Ok(Some((resource, generation)))
    }

    async fn begin_socks5_health_check_if_resource_generation(
        &self,
        resource_id: i64,
        relay_node_id: i64,
        expected_resource_generation: i64,
    ) -> Result<Option<(Socks5ResourceRecord, i64)>, DbError> {
        let mut conn = self.pool.acquire().await?;
        sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;
        let operation: Result<Option<(Socks5ResourceRecord, i64)>, DbError> = async {
            let resource: Option<Socks5ResourceRecord> = sqlx::query_as(
                "SELECT * FROM socks5_resources
                 WHERE id=? AND enabled=1 AND health_generation=?",
            )
            .bind(resource_id)
            .bind(expected_resource_generation)
            .fetch_optional(&mut *conn)
            .await?;
            let Some(resource) = resource else {
                return Ok(None);
            };
            let generation: i64 = sqlx::query_scalar(
                "INSERT INTO socks5_check_generations(resource_id,relay_node_id,generation)
                 VALUES(?,?,1) ON CONFLICT(resource_id,relay_node_id) DO UPDATE SET
                 generation=socks5_check_generations.generation+1 RETURNING generation",
            )
            .bind(resource_id)
            .bind(relay_node_id)
            .fetch_one(&mut *conn)
            .await?;
            Ok(Some((resource, generation)))
        }
        .await;
        match operation {
            Ok(value) => {
                sqlx::query("COMMIT").execute(&mut *conn).await?;
                Ok(value)
            }
            Err(error) => {
                let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                Err(error)
            }
        }
    }

    async fn record_socks5_health(
        &self,
        health: &Socks5HealthRecord,
        resource_generation: i64,
        generation: i64,
    ) -> Result<bool, DbError> {
        let mut conn = self.pool.acquire().await?;
        sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;
        let operation: Result<bool, DbError> = async {
            let current: Option<i64> =
                sqlx::query_scalar("SELECT health_generation FROM socks5_resources WHERE id=?")
                    .bind(health.resource_id)
                    .fetch_optional(&mut *conn)
                    .await?;
            let current_check: Option<i64> = sqlx::query_scalar(
                "SELECT generation FROM socks5_check_generations WHERE resource_id=? AND relay_node_id=?",
            )
            .bind(health.resource_id)
            .bind(health.relay_node_id)
            .fetch_optional(&mut *conn)
            .await?;
            if current != Some(resource_generation) || current_check != Some(generation) {
                return Ok(false);
            }
            let previous: i32 = sqlx::query_scalar(
            "SELECT COALESCE((SELECT consecutive_failures FROM socks5_resource_health WHERE resource_id=? AND relay_node_id=?),0)"
        ).bind(health.resource_id).bind(health.relay_node_id).fetch_one(&mut *conn).await?;
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
            sqlx::query(
            "INSERT INTO socks5_resource_health(resource_id,relay_node_id,status,tcp_latency_ms,handshake_latency_ms,connect_latency_ms,total_latency_ms,exit_ip,country,error_stage,error_code,safe_error_message,consecutive_failures,resource_revision,generation,checked_at,last_success_at)
             VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(resource_id,relay_node_id) DO UPDATE SET
             status=excluded.status,tcp_latency_ms=excluded.tcp_latency_ms,handshake_latency_ms=excluded.handshake_latency_ms,
             connect_latency_ms=excluded.connect_latency_ms,total_latency_ms=excluded.total_latency_ms,exit_ip=excluded.exit_ip,
             country=excluded.country,error_stage=excluded.error_stage,error_code=excluded.error_code,
             safe_error_message=excluded.safe_error_message,consecutive_failures=excluded.consecutive_failures,
             resource_revision=excluded.resource_revision,generation=excluded.generation,
             checked_at=excluded.checked_at,last_success_at=COALESCE(excluded.last_success_at,socks5_resource_health.last_success_at)"
        ).bind(health.resource_id).bind(health.relay_node_id).bind(&health.status)
        .bind(health.tcp_latency_ms).bind(health.handshake_latency_ms).bind(health.connect_latency_ms)
        .bind(health.total_latency_ms).bind(&health.exit_ip).bind(&health.country).bind(&health.error_stage)
        .bind(&health.error_code).bind(&health.safe_error_message).bind(failures)
        .bind(resource_generation).bind(generation).bind(&health.checked_at)
        .bind(last_success).execute(&mut *conn).await?;
            sqlx::query(
            "INSERT INTO socks5_check_history(resource_id,relay_node_id,status,tcp_latency_ms,handshake_latency_ms,connect_latency_ms,total_latency_ms,exit_ip,country,error_stage,error_code,safe_error_message,checked_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)"
        ).bind(health.resource_id).bind(health.relay_node_id).bind(&health.status)
        .bind(health.tcp_latency_ms).bind(health.handshake_latency_ms).bind(health.connect_latency_ms)
        .bind(health.total_latency_ms).bind(&health.exit_ip).bind(&health.country).bind(&health.error_stage)
        .bind(&health.error_code).bind(&health.safe_error_message).bind(&health.checked_at)
        .execute(&mut *conn).await?;
            sqlx::query(
            "UPDATE socks5_resources SET status=?,detected_exit_ip=?,detected_country=?,latency_ms=?,consecutive_failures=?,last_check_at=?,last_success_at=COALESCE(?,last_success_at),updated_at=datetime('now') WHERE id=?"
        ).bind(&health.status).bind(&health.exit_ip).bind(&health.country).bind(health.total_latency_ms)
        .bind(failures).bind(&health.checked_at).bind(last_success).bind(health.resource_id)
        .execute(&mut *conn).await?;
            Ok(true)
        }
        .await;
        match operation {
            Ok(true) => {
                sqlx::query("COMMIT").execute(&mut *conn).await?;
                Ok(true)
            }
            Ok(false) => {
                sqlx::query("ROLLBACK").execute(&mut *conn).await?;
                Ok(false)
            }
            Err(error) => {
                let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                Err(error)
            }
        }
    }

    async fn list_socks5_health(
        &self,
        resource_id: i64,
    ) -> Result<Vec<Socks5HealthRecord>, DbError> {
        Ok(sqlx::query_as(
            "SELECT * FROM socks5_resource_health WHERE resource_id=? ORDER BY relay_node_id",
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
        Ok(sqlx::query_as("SELECT * FROM socks5_check_history WHERE resource_id=? ORDER BY checked_at DESC,id DESC LIMIT ? OFFSET ?")
            .bind(resource_id).bind(limit).bind(offset).fetch_all(&self.pool).await?)
    }

    async fn prune_socks5_check_history(&self, cutoff: &str) -> Result<u64, DbError> {
        Ok(sqlx::query(
            "DELETE FROM socks5_check_history WHERE id IN (
                    SELECT id FROM socks5_check_history
                    WHERE checked_at < ? ORDER BY id LIMIT 10000
                 )",
        )
        .bind(cutoff)
        .execute(&self.pool)
        .await?
        .rows_affected())
    }
}
