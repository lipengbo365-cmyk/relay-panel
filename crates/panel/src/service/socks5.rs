use crate::db::repo::{Socks5ResourceRecord, Socks5RuleViewRecord};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct Socks5ResourcePublic {
    pub id: i64,
    pub name: String,
    pub host: String,
    pub port: i32,
    pub username_masked: Option<String>,
    pub has_password: bool,
    pub country: String,
    pub country_code: String,
    pub region: String,
    pub city: String,
    pub isp: String,
    pub remark: String,
    pub tags: Vec<String>,
    pub status: String,
    pub enabled: bool,
    pub detected_exit_ip: Option<String>,
    pub detected_country: Option<String>,
    pub latency_ms: Option<i32>,
    pub consecutive_failures: i32,
    pub last_check_at: Option<String>,
    pub last_success_at: Option<String>,
    pub last_relay_node_id: Option<i64>,
    pub last_relay_node_name: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl From<Socks5ResourceRecord> for Socks5ResourcePublic {
    fn from(r: Socks5ResourceRecord) -> Self {
        Self {
            id: r.id,
            name: r.name,
            host: r.host,
            port: r.port,
            username_masked: r.username.as_deref().map(mask_username),
            has_password: r.password_ciphertext.is_some(),
            country: r.country,
            country_code: r.country_code,
            region: r.region,
            city: r.city,
            isp: r.isp,
            remark: r.remark,
            tags: serde_json::from_str(&r.tags).unwrap_or_default(),
            status: r.status,
            enabled: r.enabled,
            detected_exit_ip: r.detected_exit_ip,
            detected_country: r.detected_country,
            latency_ms: r.latency_ms,
            consecutive_failures: r.consecutive_failures,
            last_check_at: r.last_check_at,
            last_success_at: r.last_success_at,
            last_relay_node_id: None,
            last_relay_node_name: None,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Socks5RulePublic {
    pub rule_id: i64,
    pub name: String,
    pub listen_port: i32,
    pub device_group_in: i64,
    pub paused: bool,
    pub proxy_address: String,
    pub traffic_used: i64,
    pub socks5_resource_id: i64,
    pub resource_name: String,
    pub detected_exit_ip: Option<String>,
    pub relay_username_masked: Option<String>,
    pub allow_no_auth: bool,
    pub remote_dns: bool,
    pub created_at: String,
}

impl From<Socks5RuleViewRecord> for Socks5RulePublic {
    fn from(r: Socks5RuleViewRecord) -> Self {
        Self {
            rule_id: r.rule_id,
            name: r.name,
            listen_port: r.listen_port,
            device_group_in: r.device_group_in,
            proxy_address: format!("{}:{}", r.connect_host, r.listen_port),
            paused: r.paused,
            traffic_used: r.traffic_used,
            socks5_resource_id: r.socks5_resource_id,
            resource_name: r.resource_name,
            detected_exit_ip: r.detected_exit_ip,
            relay_username_masked: r.relay_username.as_deref().map(mask_username),
            allow_no_auth: r.allow_no_auth,
            remote_dns: r.remote_dns,
            created_at: r.created_at,
        }
    }
}

pub fn mask_username(value: &str) -> String {
    let mut chars = value.chars();
    match chars.next() {
        None => String::new(),
        Some(first) => format!("{}***", first),
    }
}

pub fn validate_endpoint(name: &str, host: &str, port: i32) -> Result<(), String> {
    if name.trim().is_empty() {
        return Err("名称不能为空".into());
    }
    if host.trim().is_empty() {
        return Err("主机不能为空".into());
    }
    if !(1..=65535).contains(&port) {
        return Err("端口必须在 1-65535 之间".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_resource_never_serializes_stored_secret_material() {
        let public = Socks5ResourcePublic::from(Socks5ResourceRecord {
            id: 1,
            name: "upstream".into(),
            host: "proxy.example".into(),
            port: 1080,
            username: Some("operator".into()),
            password_ciphertext: Some("ciphertext-secret".into()),
            password_nonce: Some("nonce-secret".into()),
            password_key_version: 1,
            country: "United States".into(),
            country_code: "US".into(),
            region: String::new(),
            city: String::new(),
            isp: String::new(),
            remark: String::new(),
            tags: "[]".into(),
            status: "UNKNOWN".into(),
            enabled: true,
            detected_exit_ip: None,
            detected_country: None,
            latency_ms: None,
            consecutive_failures: 0,
            health_generation: 0,
            last_check_at: None,
            last_success_at: None,
            created_at: "2026-09-04 00:00:00".into(),
            updated_at: "2026-09-04 00:00:00".into(),
        });

        let json = serde_json::to_string(&public).unwrap();
        assert_eq!(public.username_masked.as_deref(), Some("o***"));
        assert!(public.has_password);
        assert!(!json.contains("operator"));
        assert!(!json.contains("ciphertext-secret"));
        assert!(!json.contains("nonce-secret"));
        assert!(!json.contains("password_ciphertext"));
        assert!(!json.contains("password_nonce"));
    }
}
