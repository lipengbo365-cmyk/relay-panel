use super::PgRepository;
use crate::db::error::DbError;
use crate::db::repo::{
    Socks5Repository, Socks5ResourceRecord, Socks5RuleConfigRecord, Socks5RuleViewRecord,
};
use async_trait::async_trait;

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
             ELSE 'DISABLED' END,updated_at=to_char(now() AT TIME ZONE 'UTC','YYYY-MM-DD HH24:MI:SS') WHERE id=$15")
            .bind(name).bind(host).bind(port).bind(username).bind(password_ciphertext).bind(password_nonce)
            .bind(password_key_version).bind(country).bind(country_code).bind(region).bind(city).bind(isp)
            .bind(remark).bind(enabled).bind(id).execute(&self.pool).await?.rows_affected())
    }
    async fn set_socks5_resource_enabled(&self, id: i64, enabled: bool) -> Result<u64, DbError> {
        Ok(sqlx::query("UPDATE socks5_resources SET enabled=$1,status=CASE WHEN $1 THEN 'UNKNOWN' ELSE 'DISABLED' END,updated_at=to_char(now() AT TIME ZONE 'UTC','YYYY-MM-DD HH24:MI:SS') WHERE id=$2")
            .bind(enabled).bind(id).execute(&self.pool).await?.rows_affected())
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
        Ok(sqlx::query_as("SELECT b.rule_id,b.socks5_resource_id,b.remote_dns,b.relay_username,b.relay_password_ciphertext,b.relay_password_nonce,b.relay_password_key_version,b.allow_no_auth,r.name resource_name,r.host resource_host,r.port resource_port,r.username resource_username,r.password_ciphertext resource_password_ciphertext,r.password_nonce resource_password_nonce,r.password_key_version resource_password_key_version,r.enabled resource_enabled FROM socks5_rule_bindings b JOIN socks5_resources r ON r.id=b.socks5_resource_id WHERE b.rule_id=$1").bind(rule_id).fetch_optional(&self.pool).await?)
    }
    async fn list_socks5_rule_views(&self) -> Result<Vec<Socks5RuleViewRecord>, DbError> {
        Ok(sqlx::query_as("SELECT f.id rule_id,f.name,f.listen_port,f.device_group_in,g.connect_host,f.paused,f.traffic_used,b.socks5_resource_id,r.name resource_name,r.detected_exit_ip,b.relay_username,b.allow_no_auth,b.remote_dns,f.created_at FROM forward_rules f JOIN socks5_rule_bindings b ON b.rule_id=f.id JOIN socks5_resources r ON r.id=b.socks5_resource_id JOIN device_groups g ON g.id=f.device_group_in ORDER BY f.id DESC").fetch_all(&self.pool).await?)
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
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(device_group_in)
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT 1 FROM users WHERE id=$1 FOR UPDATE")
            .bind(uid)
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
}
