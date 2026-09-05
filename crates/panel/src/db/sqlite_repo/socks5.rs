use super::SqliteRepository;
use crate::db::error::DbError;
use crate::db::repo::{
    Socks5Repository, Socks5ResourceRecord, Socks5RuleConfigRecord, Socks5RuleViewRecord,
};
use async_trait::async_trait;

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
             ELSE 'DISABLED' END,updated_at=datetime('now') WHERE id=?")
            .bind(name).bind(host).bind(port).bind(username).bind(password_ciphertext)
            .bind(password_nonce).bind(password_key_version).bind(country).bind(country_code)
            .bind(region).bind(city).bind(isp).bind(remark).bind(enabled).bind(enabled).bind(id)
            .execute(&self.pool).await?;
        Ok(result.rows_affected())
    }

    async fn set_socks5_resource_enabled(&self, id: i64, enabled: bool) -> Result<u64, DbError> {
        let result = sqlx::query(
            "UPDATE socks5_resources SET enabled=?,status=CASE WHEN ? THEN 'UNKNOWN' ELSE 'DISABLED' END,
             updated_at=datetime('now') WHERE id=?")
            .bind(enabled).bind(enabled).bind(id).execute(&self.pool).await?;
        Ok(result.rows_affected())
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
             b.relay_password_ciphertext,b.relay_password_nonce,b.relay_password_key_version,b.allow_no_auth,
             r.name resource_name,r.host resource_host,r.port resource_port,r.username resource_username,
             r.password_ciphertext resource_password_ciphertext,r.password_nonce resource_password_nonce,
             r.password_key_version resource_password_key_version,r.enabled resource_enabled
             FROM socks5_rule_bindings b JOIN socks5_resources r ON r.id=b.socks5_resource_id
             WHERE b.rule_id=?")
            .bind(rule_id).fetch_optional(&self.pool).await?)
    }

    async fn list_socks5_rule_views(&self) -> Result<Vec<Socks5RuleViewRecord>, DbError> {
        Ok(sqlx::query_as(
            "SELECT f.id rule_id,f.name,f.listen_port,f.device_group_in,g.connect_host,f.paused,f.traffic_used,
             b.socks5_resource_id,r.name resource_name,r.detected_exit_ip,b.relay_username,
             b.allow_no_auth,b.remote_dns,f.created_at
             FROM forward_rules f JOIN socks5_rule_bindings b ON b.rule_id=f.id
             JOIN socks5_resources r ON r.id=b.socks5_resource_id
             JOIN device_groups g ON g.id=f.device_group_in ORDER BY f.id DESC")
            .fetch_all(&self.pool).await?)
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
}
