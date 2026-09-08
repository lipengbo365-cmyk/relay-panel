use crate::config::Config;
use crate::db::error::DbError;
use crate::db::repo::{RelayNodeCapacityRecord, Socks5RecommendationHealthRecord};
use crate::db::Repository;
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use relay_shared::protocol::CONFIG_PROTOCOL_VERSION;
use serde::Serialize;
use std::collections::HashMap;

const NODE_ONLINE_TTL_SECONDS: i64 = 120;

#[derive(Debug, Clone, Serialize)]
pub struct RelayRecommendation {
    pub resource_id: i64,
    pub resource_name: String,
    pub resource_revision: i64,
    pub resource_enabled: bool,
    pub declared_country: Option<String>,
    pub detected_country: Option<String>,
    pub generated_at: String,
    pub health_ttl_seconds: i64,
    pub candidates: Vec<RelayCandidate>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RelayCandidate {
    pub relay_node_id: i64,
    pub device_group_id: i64,
    pub relay_node_name: String,
    pub country: String,
    pub country_code: String,
    pub region: String,
    pub city: String,
    pub provider: String,
    pub advertise_host: String,
    pub public_ip: String,
    pub endpoint_host: String,
    pub online: bool,
    pub identity_trusted: bool,
    pub protocol_version: Option<u64>,
    pub supports_socks5_relay: bool,
    pub eligible: bool,
    pub health_status: String,
    pub health_checked_at: Option<String>,
    pub health_age_seconds: Option<i64>,
    pub health_fresh: bool,
    pub health_generation: Option<i64>,
    pub health_resource_revision: Option<i64>,
    pub latency_ms: Option<i32>,
    pub detected_exit_ip: Option<String>,
    pub detected_country: Option<String>,
    pub node_cpu: Option<f64>,
    pub node_memory: Option<f64>,
    pub node_connections: Option<u64>,
    pub port_available: i64,
    pub port_total: i64,
    pub port_used: i64,
    pub country_match: String,
    pub score: i32,
    pub rank: u32,
    pub recommended: bool,
    pub reasons: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Default)]
struct LiveNodeMetrics {
    online: bool,
    cpu: Option<f64>,
    memory: Option<f64>,
    connections: Option<u64>,
    protocol_version: Option<u64>,
    supports_socks5_relay: bool,
}

pub async fn recommend(
    db: &dyn Repository,
    config: &Config,
    resource_id: i64,
) -> Result<Option<RelayRecommendation>, DbError> {
    let Some(resource) = db.find_socks5_resource(resource_id).await? else {
        return Ok(None);
    };
    let (nodes, capacities, health_rows, kvs_rows) = tokio::try_join!(
        db.list_relay_nodes(),
        db.list_relay_node_capacities(),
        db.list_socks5_recommendation_health(resource_id),
        db.scan_prefix("node_status:"),
    )?;
    let capacities = capacities
        .into_iter()
        .map(|row| (row.relay_node_id, row))
        .collect::<HashMap<_, _>>();
    let health = health_rows
        .into_iter()
        .map(|row| (row.relay_node_id, row))
        .collect::<HashMap<_, _>>();
    let live = parse_live_metrics(kvs_rows);
    let now = Utc::now();

    let mut candidates = nodes
        .into_iter()
        .map(|node| {
            let capacity = capacities.get(&node.id);
            let health = health.get(&node.id);
            let metrics = live
                .get(&(node.device_group_id, node.node_key.clone()))
                .cloned()
                .unwrap_or_default();
            build_candidate(&resource, node, capacity, health, metrics, config, now)
        })
        .collect::<Vec<_>>();

    sort_candidates(&mut candidates);
    let recommended_id = candidates
        .iter()
        .find(|candidate| candidate.eligible)
        .map(|c| c.relay_node_id);
    for (index, candidate) in candidates.iter_mut().enumerate() {
        candidate.rank = u32::try_from(index + 1).unwrap_or(u32::MAX);
        candidate.recommended = Some(candidate.relay_node_id) == recommended_id;
    }

    Ok(Some(RelayRecommendation {
        resource_id: resource.id,
        resource_name: resource.name,
        resource_revision: resource.health_generation,
        resource_enabled: resource.enabled,
        declared_country: normalize_country(&resource.country_code)
            .or_else(|| normalize_country(&resource.country)),
        detected_country: resource
            .detected_country
            .as_deref()
            .and_then(normalize_country),
        generated_at: now.to_rfc3339(),
        health_ttl_seconds: config.relay_recommend_health_ttl_seconds,
        candidates,
    }))
}

fn sort_candidates(candidates: &mut [RelayCandidate]) {
    candidates.sort_by(|a, b| {
        b.eligible
            .cmp(&a.eligible)
            .then_with(|| country_sort(&b.country_match).cmp(&country_sort(&a.country_match)))
            .then_with(|| {
                a.latency_ms
                    .unwrap_or(i32::MAX)
                    .cmp(&b.latency_ms.unwrap_or(i32::MAX))
            })
            .then_with(|| node_load(a).total_cmp(&node_load(b)))
            .then_with(|| b.port_available.cmp(&a.port_available))
            .then_with(|| a.relay_node_id.cmp(&b.relay_node_id))
    });
}

fn build_candidate(
    resource: &crate::db::repo::Socks5ResourceRecord,
    node: crate::db::repo::RelayNodeRecord,
    capacity: Option<&RelayNodeCapacityRecord>,
    health: Option<&Socks5RecommendationHealthRecord>,
    metrics: LiveNodeMetrics,
    config: &Config,
    now: DateTime<Utc>,
) -> RelayCandidate {
    let mut reasons = Vec::new();
    let mut warnings = Vec::new();
    let mut eligible = true;
    let identity_trusted = node.identity_secret_hash.len() == 64;
    let endpoint_host = if node.advertise_host.is_empty() {
        node.public_ip.clone()
    } else {
        node.advertise_host.clone()
    };
    let (port_total, port_used, port_available, group_usable) =
        capacity.map(port_capacity).unwrap_or((0, 0, 0, false));
    let health_age = health
        .and_then(|row| parse_db_utc(&row.checked_at))
        .map(|checked| now.signed_duration_since(checked).num_seconds().max(0));
    let health_fresh =
        health_age.is_some_and(|age| age <= config.relay_recommend_health_ttl_seconds);
    let valid_exit_ip = health
        .and_then(|row| row.exit_ip.as_deref())
        .is_some_and(|ip| ip.parse::<std::net::IpAddr>().is_ok());
    let health_revision_matches =
        health.is_some_and(|row| row.resource_revision == resource.health_generation);
    let generation_matches =
        health.is_some_and(|row| row.generation > 0 && row.generation == row.current_generation);

    let effective_country = health
        .and_then(|row| row.country.as_deref())
        .and_then(normalize_country)
        .or_else(|| {
            resource
                .detected_country
                .as_deref()
                .and_then(normalize_country)
        })
        .or_else(|| normalize_country(&resource.country_code))
        .or_else(|| normalize_country(&resource.country));
    let node_country = normalize_country(&node.country_code);
    let country_match = match (&effective_country, &node_country) {
        (Some(resource_country), Some(node_country)) if resource_country == node_country => {
            "MATCHED"
        }
        (Some(_), Some(_)) => "CROSS_COUNTRY",
        _ => "UNKNOWN",
    };

    macro_rules! reject {
        ($condition:expr, $reason:expr) => {
            if $condition {
                eligible = false;
                warnings.push($reason.to_string());
            }
        };
    }
    reject!(!resource.enabled, "RESOURCE_DISABLED");
    reject!(!node.enabled, "NODE_DISABLED");
    reject!(!metrics.online, "NODE_OFFLINE");
    reject!(!identity_trusted, "NODE_IDENTITY_UNTRUSTED");
    reject!(
        metrics.protocol_version != Some(u64::from(CONFIG_PROTOCOL_VERSION)),
        "NODE_UNSUPPORTED"
    );
    reject!(!metrics.supports_socks5_relay, "NODE_UNSUPPORTED");
    reject!(endpoint_host.is_empty(), "NODE_ACCESS_HOST_MISSING");
    reject!(!group_usable, "DEVICE_GROUP_PORTS_UNAVAILABLE");
    reject!(port_available <= 0, "NO_AVAILABLE_PORT");
    reject!(health.is_none(), "HEALTH_MISSING");
    reject!(
        health.is_some_and(|row| row.status != "ONLINE"),
        "HEALTH_NOT_ONLINE"
    );
    reject!(!health_revision_matches, "RESOURCE_CHANGED");
    reject!(!generation_matches, "HEALTH_GENERATION_INVALID");
    reject!(!health_fresh, "HEALTH_STALE");
    reject!(!valid_exit_ip, "EXIT_IP_MISMATCH");
    reject!(
        metrics
            .cpu
            .is_some_and(|cpu| cpu >= config.relay_recommend_max_cpu_percent)
            || metrics
                .memory
                .is_some_and(|memory| memory >= config.relay_recommend_max_memory_percent),
        "NODE_OVERLOADED"
    );

    if country_match == "MATCHED" {
        reasons.push("Same detected country".to_string());
    } else if country_match == "CROSS_COUNTRY" {
        warnings.push("COUNTRY_MISMATCH_WARNING".to_string());
    } else {
        warnings.push("COUNTRY_UNKNOWN".to_string());
    }
    if health_fresh {
        reasons.push(format!("Health checked {}s ago", health_age.unwrap_or(0)));
    }
    if let Some(latency) = health.and_then(|row| row.total_latency_ms) {
        reasons.push(format!("{} ms latency", latency));
    }
    if let Some(cpu) = metrics.cpu {
        reasons.push(format!("CPU {:.1}%", cpu));
    }
    reasons.push(format!("{} ports available", port_available));

    let score = score_candidate(
        country_match,
        health_age,
        config.relay_recommend_health_ttl_seconds,
        health.and_then(|row| row.total_latency_ms),
        metrics.cpu,
        metrics.memory,
        port_available,
        port_total,
    );

    RelayCandidate {
        relay_node_id: node.id,
        device_group_id: node.device_group_id,
        relay_node_name: node.name,
        country: node.country,
        country_code: node.country_code,
        region: node.region,
        city: node.city,
        provider: node.provider,
        advertise_host: node.advertise_host,
        public_ip: node.public_ip,
        endpoint_host,
        online: metrics.online,
        identity_trusted,
        protocol_version: metrics.protocol_version,
        supports_socks5_relay: metrics.supports_socks5_relay,
        eligible,
        health_status: health.map_or_else(|| "MISSING".to_string(), |row| row.status.clone()),
        health_checked_at: health.map(|row| row.checked_at.clone()),
        health_age_seconds: health_age,
        health_fresh,
        health_generation: health.map(|row| row.generation),
        health_resource_revision: health.map(|row| row.resource_revision),
        latency_ms: health.and_then(|row| row.total_latency_ms),
        detected_exit_ip: health.and_then(|row| row.exit_ip.clone()),
        detected_country: effective_country,
        node_cpu: metrics.cpu,
        node_memory: metrics.memory,
        node_connections: metrics.connections,
        port_available,
        port_total,
        port_used,
        country_match: country_match.to_string(),
        score,
        rank: 0,
        recommended: false,
        reasons,
        warnings,
    }
}

fn parse_live_metrics(rows: Vec<(String, String)>) -> HashMap<(i64, String), LiveNodeMetrics> {
    let now = Utc::now();
    let mut result = HashMap::new();
    for (key, raw) in rows {
        let Some(rest) = key.strip_prefix("node_status:") else {
            continue;
        };
        let Some((group, node_key)) = rest.split_once(':') else {
            continue;
        };
        let Ok(group_id) = group.parse::<i64>() else {
            continue;
        };
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&raw) else {
            continue;
        };
        let online = value
            .get("last_seen")
            .and_then(|value| value.as_str())
            .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
            .is_some_and(|seen| {
                let age = now
                    .signed_duration_since(seen.with_timezone(&Utc))
                    .num_seconds();
                (0..=NODE_ONLINE_TTL_SECONDS).contains(&age)
            });
        let protocol_version = value
            .get("config_protocol_version")
            .and_then(|value| value.as_u64());
        result.insert(
            (group_id, node_key.to_owned()),
            LiveNodeMetrics {
                online,
                cpu: value.get("cpu").and_then(|value| value.as_f64()),
                memory: value.get("mem").and_then(|value| value.as_f64()),
                connections: value.get("connections").and_then(|value| value.as_u64()),
                protocol_version,
                supports_socks5_relay: protocol_version == Some(u64::from(CONFIG_PROTOCOL_VERSION))
                    && value.get("socks5_check_queue_depth").is_some(),
            },
        );
    }
    result
}

fn port_capacity(row: &RelayNodeCapacityRecord) -> (i64, i64, i64, bool) {
    let (low, high) = super::rules::resolve_auto_port_range(&row.port_range);
    let total = i64::from(high) - i64::from(low) + 1;
    let used = row.port_used.clamp(0, total);
    let capabilities =
        serde_json::from_str::<Vec<String>>(&row.group_capabilities).unwrap_or_default();
    let supports_tcp = capabilities.is_empty()
        || capabilities
            .iter()
            .any(|value| value == "tcp" || value == "tcp_udp");
    (
        total,
        used,
        total - used,
        row.group_type == "in" && supports_tcp,
    )
}

fn parse_db_utc(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .map(|value| value.with_timezone(&Utc))
        .ok()
        .or_else(|| {
            NaiveDateTime::parse_from_str(value, "%Y-%m-%d %H:%M:%S%.f")
                .ok()
                .map(|value| Utc.from_utc_datetime(&value))
        })
}

fn normalize_country(value: &str) -> Option<String> {
    let value = value.trim().to_ascii_uppercase();
    (value.len() == 2 && value.bytes().all(|byte| byte.is_ascii_alphabetic())).then_some(value)
}

fn country_sort(value: &str) -> u8 {
    match value {
        "MATCHED" => 2,
        "CROSS_COUNTRY" => 1,
        _ => 0,
    }
}

fn node_load(candidate: &RelayCandidate) -> f64 {
    candidate
        .node_cpu
        .into_iter()
        .chain(candidate.node_memory)
        .fold(0.0, f64::max)
}

#[allow(clippy::too_many_arguments)]
fn score_candidate(
    country_match: &str,
    health_age: Option<i64>,
    health_ttl: i64,
    latency_ms: Option<i32>,
    cpu: Option<f64>,
    memory: Option<f64>,
    port_available: i64,
    port_total: i64,
) -> i32 {
    let country = if country_match == "MATCHED" {
        40.0
    } else {
        0.0
    };
    let freshness = health_age.map_or(0.0, |age| {
        15.0 * (1.0 - age.max(0) as f64 / health_ttl.max(1) as f64).clamp(0.0, 1.0)
    });
    let latency = latency_ms.map_or(0.0, |latency| {
        25.0 * (1.0 - latency.max(0) as f64 / 2_000.0).clamp(0.0, 1.0)
    });
    let load = cpu
        .into_iter()
        .chain(memory)
        .reduce(f64::max)
        .map_or(5.0, |load| 10.0 * (1.0 - load / 100.0).clamp(0.0, 1.0));
    let ports = if port_total > 0 {
        10.0 * (port_available.max(0) as f64 / port_total as f64).clamp(0.0, 1.0)
    } else {
        0.0
    };
    (country + freshness + latency + load + ports)
        .round()
        .clamp(0.0, 100.0) as i32
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::repo::{RelayNodeRecord, Socks5Repository, Socks5ResourceRecord};
    use crate::db::schema::SCHEMA_SQL;
    use crate::db::sqlite_repo::SqliteRepository;
    use sqlx::sqlite::SqlitePoolOptions;

    fn test_config() -> Config {
        Config {
            database_path: "sqlite::memory:".into(),
            listen: "127.0.0.1:0".into(),
            key: "test".into(),
            jwt_secret: "test".into(),
            public_dir: "public".into(),
            public_panel_url: String::new(),
            registration_enabled: false,
            cors_origins: vec![],
            geoip_enabled: false,
            geoip_cache_ttl: 60,
            socks5_credential_key: Some("11".repeat(32)),
            socks5_check_urls: vec![],
            socks5_check_concurrency: 10,
            socks5_check_retention_days: 30,
            relay_recommend_health_ttl_seconds: 600,
            relay_recommend_max_cpu_percent: 95.0,
            relay_recommend_max_memory_percent: 95.0,
        }
    }

    #[test]
    fn score_is_clamped_and_country_dominates_latency() {
        let matched = score_candidate(
            "MATCHED",
            Some(10),
            600,
            Some(200),
            Some(20.0),
            Some(30.0),
            800,
            1000,
        );
        let cross = score_candidate(
            "CROSS_COUNTRY",
            Some(10),
            600,
            Some(10),
            Some(5.0),
            Some(5.0),
            1000,
            1000,
        );
        assert!((0..=100).contains(&matched));
        assert!(matched > cross);
    }

    #[test]
    fn country_normalization_is_iso_alpha_two_only() {
        assert_eq!(normalize_country(" us ").as_deref(), Some("US"));
        assert_eq!(normalize_country("USA"), None);
        assert_eq!(normalize_country(""), None);
    }

    fn sample_resource() -> Socks5ResourceRecord {
        Socks5ResourceRecord {
            id: 1,
            name: "resource".into(),
            host: "198.51.100.7".into(),
            port: 1080,
            username: None,
            password_ciphertext: None,
            password_nonce: None,
            password_key_version: 1,
            country: "Japan".into(),
            country_code: "JP".into(),
            region: String::new(),
            city: String::new(),
            isp: String::new(),
            remark: String::new(),
            tags: "[]".into(),
            status: "ONLINE".into(),
            enabled: true,
            detected_exit_ip: Some("198.51.100.8".into()),
            detected_country: Some("US".into()),
            latency_ms: Some(100),
            consecutive_failures: 0,
            health_generation: 1,
            last_check_at: None,
            last_success_at: None,
            created_at: String::new(),
            updated_at: String::new(),
        }
    }

    fn sample_node(id: i64) -> RelayNodeRecord {
        RelayNodeRecord {
            id,
            device_group_id: 1,
            node_key: format!("node-{id}"),
            identity_secret_hash: "a".repeat(64),
            name: format!("US-{id}"),
            country: "United States".into(),
            country_code: "US".into(),
            region: String::new(),
            city: String::new(),
            provider: String::new(),
            public_ip: "192.0.2.1".into(),
            advertise_host: String::new(),
            bandwidth_mbps: 1000,
            remark: String::new(),
            tags: "[]".into(),
            enabled: true,
            first_seen_at: String::new(),
            last_seen_at: String::new(),
            created_at: String::new(),
            updated_at: String::new(),
        }
    }

    fn sample_health(now: DateTime<Utc>) -> Socks5RecommendationHealthRecord {
        Socks5RecommendationHealthRecord {
            resource_id: 1,
            relay_node_id: 1,
            status: "ONLINE".into(),
            total_latency_ms: Some(100),
            exit_ip: Some("198.51.100.8".into()),
            country: Some("US".into()),
            checked_at: now.to_rfc3339(),
            resource_revision: 1,
            generation: 1,
            current_generation: 1,
        }
    }

    fn sample_capacity() -> RelayNodeCapacityRecord {
        RelayNodeCapacityRecord {
            relay_node_id: 1,
            device_group_id: 1,
            port_range: "20000-20009".into(),
            port_used: 0,
            group_type: "in".into(),
            group_capabilities: "[]".into(),
        }
    }

    fn sample_metrics() -> LiveNodeMetrics {
        LiveNodeMetrics {
            online: true,
            cpu: Some(10.0),
            memory: Some(20.0),
            connections: Some(1),
            protocol_version: Some(u64::from(CONFIG_PROTOCOL_VERSION)),
            supports_socks5_relay: true,
        }
    }

    #[test]
    fn eligibility_matrix_is_fail_closed_and_sorting_is_stable() {
        let now = Utc::now();
        let config = test_config();
        let resource = sample_resource();
        let node = sample_node(1);
        let capacity = sample_capacity();
        let health = sample_health(now);
        let metrics = sample_metrics();
        let candidate = build_candidate(
            &resource,
            node.clone(),
            Some(&capacity),
            Some(&health),
            metrics.clone(),
            &config,
            now,
        );
        assert!(candidate.eligible);
        assert_eq!(candidate.country_match, "MATCHED");
        assert_eq!(candidate.detected_country.as_deref(), Some("US"));

        let mut cross_node = node.clone();
        cross_node.country_code = "JP".into();
        let cross = build_candidate(
            &resource,
            cross_node,
            Some(&capacity),
            Some(&health),
            metrics.clone(),
            &config,
            now,
        );
        assert!(cross.eligible);
        assert_eq!(cross.country_match, "CROSS_COUNTRY");
        assert!(cross
            .warnings
            .iter()
            .any(|value| value == "COUNTRY_MISMATCH_WARNING"));

        for status in ["AUTH_FAILED", "TIMEOUT", "CONNECT_FAILED"] {
            let mut failed = health.clone();
            failed.status = status.into();
            let result = build_candidate(
                &resource,
                node.clone(),
                Some(&capacity),
                Some(&failed),
                metrics.clone(),
                &config,
                now,
            );
            assert!(!result.eligible, "{status} was eligible");
            assert!(result
                .warnings
                .iter()
                .any(|value| value == "HEALTH_NOT_ONLINE"));
        }

        let mut disabled_resource = resource.clone();
        disabled_resource.enabled = false;
        let mut disabled_node = node.clone();
        disabled_node.enabled = false;
        let mut invalid_exit = health.clone();
        invalid_exit.exit_ip = Some("not-an-ip".into());
        let mut stale = health.clone();
        stale.checked_at = "2020-01-01T00:00:00+00:00".into();
        let mut exhausted = capacity.clone();
        exhausted.port_used = 10;
        let mut overloaded = metrics.clone();
        overloaded.cpu = Some(95.0);
        let mut unsupported = metrics.clone();
        unsupported.protocol_version = Some(0);
        unsupported.supports_socks5_relay = false;
        let cases = [
            build_candidate(
                &disabled_resource,
                node.clone(),
                Some(&capacity),
                Some(&health),
                metrics.clone(),
                &config,
                now,
            ),
            build_candidate(
                &resource,
                disabled_node,
                Some(&capacity),
                Some(&health),
                metrics.clone(),
                &config,
                now,
            ),
            build_candidate(
                &resource,
                node.clone(),
                Some(&capacity),
                None,
                metrics.clone(),
                &config,
                now,
            ),
            build_candidate(
                &resource,
                node.clone(),
                Some(&capacity),
                Some(&invalid_exit),
                metrics.clone(),
                &config,
                now,
            ),
            build_candidate(
                &resource,
                node.clone(),
                Some(&capacity),
                Some(&stale),
                metrics.clone(),
                &config,
                now,
            ),
            build_candidate(
                &resource,
                node.clone(),
                Some(&exhausted),
                Some(&health),
                metrics.clone(),
                &config,
                now,
            ),
            build_candidate(
                &resource,
                node.clone(),
                Some(&capacity),
                Some(&health),
                overloaded,
                &config,
                now,
            ),
            build_candidate(
                &resource,
                node.clone(),
                Some(&capacity),
                Some(&health),
                unsupported,
                &config,
                now,
            ),
            build_candidate(
                &resource,
                node.clone(),
                Some(&capacity),
                Some(&health),
                LiveNodeMetrics::default(),
                &config,
                now,
            ),
        ];
        assert!(cases.iter().all(|value| !value.eligible));

        let mut slow = candidate.clone();
        slow.relay_node_id = 2;
        slow.latency_ms = Some(200);
        let mut tie_high_id = candidate.clone();
        tie_high_id.relay_node_id = 3;
        let mut ranked = vec![slow, tie_high_id, candidate];
        sort_candidates(&mut ranked);
        assert_eq!(
            ranked
                .iter()
                .map(|value| value.relay_node_id)
                .collect::<Vec<_>>(),
            vec![1, 3, 2]
        );
    }

    #[tokio::test]
    async fn real_matrix_prefers_detected_country_then_latency_and_rejects_stale_health() {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query(SCHEMA_SQL).execute(&pool).await.unwrap();
        let db = SqliteRepository::new(pool.clone());
        for (group_id, name) in [(501_i64, "US-A"), (502, "US-B"), (503, "JP-C")] {
            sqlx::query(
                "INSERT INTO device_groups(id,name,group_type,token,uid,port_range)
                 VALUES(?,?,'in',?,1,'20000-20099')",
            )
            .bind(group_id)
            .bind(name)
            .bind(format!("token-{group_id}"))
            .execute(&pool)
            .await
            .unwrap();
        }
        let now = Utc::now().to_rfc3339();
        let mut nodes = Vec::new();
        for (group_id, key, country, latency, cpu) in [
            (501_i64, "node-a", "US", 120_i32, 50.0_f64),
            (502, "node-b", "US", 190, 10.0),
            (503, "node-c", "JP", 70, 5.0),
        ] {
            let node_id = db
                .upsert_relay_node_seen(group_id, key, &"a".repeat(64), "192.0.2.10", &now)
                .await
                .unwrap()
                .unwrap();
            sqlx::query("UPDATE relay_nodes SET name=?,country_code=? WHERE id=?")
                .bind(key)
                .bind(country)
                .bind(node_id)
                .execute(&pool)
                .await
                .unwrap();
            let status = serde_json::json!({
                "last_seen": now,
                "config_protocol_version": CONFIG_PROTOCOL_VERSION,
                "socks5_check_queue_depth": 0,
                "cpu": cpu,
                "mem": 20.0,
                "connections": 5
            });
            sqlx::query("INSERT INTO kvs(key,value) VALUES(?,?)")
                .bind(format!("node_status:{group_id}:{key}"))
                .bind(status.to_string())
                .execute(&pool)
                .await
                .unwrap();
            nodes.push((node_id, latency));
        }
        let resource_id: i64 = sqlx::query_scalar(
            "INSERT INTO socks5_resources
             (name,host,port,country_code,detected_country,detected_exit_ip,status,enabled,health_generation)
             VALUES('resource','198.51.100.7',1080,'JP','US','198.51.100.8','ONLINE',1,1)
             RETURNING id",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        for (node_id, latency) in &nodes {
            sqlx::query("INSERT INTO socks5_check_generations(resource_id,relay_node_id,generation) VALUES(?,?,1)")
                .bind(resource_id).bind(node_id).execute(&pool).await.unwrap();
            sqlx::query(
                "INSERT INTO socks5_resource_health
                 (resource_id,relay_node_id,status,total_latency_ms,exit_ip,country,checked_at,
                  resource_revision,generation)
                 VALUES(?,?,'ONLINE',?,'198.51.100.8','US',?,1,1)",
            )
            .bind(resource_id)
            .bind(node_id)
            .bind(latency)
            .bind(&now)
            .execute(&pool)
            .await
            .unwrap();
        }

        let result = recommend(&db, &test_config(), resource_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(result.detected_country.as_deref(), Some("US"));
        assert_eq!(result.declared_country.as_deref(), Some("JP"));
        assert_eq!(
            result
                .candidates
                .iter()
                .map(|candidate| candidate.relay_node_id)
                .collect::<Vec<_>>(),
            vec![nodes[0].0, nodes[1].0, nodes[2].0]
        );
        assert!(result.candidates[0].recommended);
        assert_eq!(result.candidates[0].country_match, "MATCHED");
        assert_eq!(result.candidates[2].country_match, "CROSS_COUNTRY");

        sqlx::query(
            "UPDATE socks5_resource_health SET checked_at='2020-01-01T00:00:00+00:00'
             WHERE resource_id=? AND relay_node_id=?",
        )
        .bind(resource_id)
        .bind(nodes[1].0)
        .execute(&pool)
        .await
        .unwrap();
        let stale = recommend(&db, &test_config(), resource_id)
            .await
            .unwrap()
            .unwrap();
        let stale_b = stale
            .candidates
            .iter()
            .find(|candidate| candidate.relay_node_id == nodes[1].0)
            .unwrap();
        assert!(!stale_b.eligible);
        assert!(stale_b
            .warnings
            .iter()
            .any(|warning| warning == "HEALTH_STALE"));

        sqlx::query(
            "UPDATE socks5_check_generations SET generation=2
             WHERE resource_id=? AND relay_node_id=?",
        )
        .bind(resource_id)
        .bind(nodes[0].0)
        .execute(&pool)
        .await
        .unwrap();
        let superseded = recommend(&db, &test_config(), resource_id)
            .await
            .unwrap()
            .unwrap();
        let superseded_a = superseded
            .candidates
            .iter()
            .find(|candidate| candidate.relay_node_id == nodes[0].0)
            .unwrap();
        assert!(!superseded_a.eligible);
        assert!(superseded_a
            .warnings
            .iter()
            .any(|warning| warning == "HEALTH_GENERATION_INVALID"));
    }

    #[tokio::test]
    async fn recommendation_handles_one_thousand_nodes_without_n_plus_one_queries() {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query(SCHEMA_SQL).execute(&pool).await.unwrap();
        sqlx::query(
            "INSERT INTO device_groups(id,name,group_type,token,uid,port_range)
             VALUES(601,'perf-group','in','perf-token',1,'30000-39999')",
        )
        .execute(&pool)
        .await
        .unwrap();
        let now = Utc::now().to_rfc3339();
        sqlx::query(
            "WITH RECURSIVE seq(value) AS (
                 SELECT 1 UNION ALL SELECT value + 1 FROM seq WHERE value < 1000
             )
             INSERT INTO relay_nodes
                 (device_group_id,node_key,identity_secret_hash,name,country_code,public_ip,
                  first_seen_at,last_seen_at)
             SELECT 601,'perf-' || value,printf('%064d',value),'Node ' || value,'US',
                    '192.0.2.1',?,? FROM seq",
        )
        .bind(&now)
        .bind(&now)
        .execute(&pool)
        .await
        .unwrap();
        let resource_id: i64 = sqlx::query_scalar(
            "INSERT INTO socks5_resources
             (name,host,port,country_code,detected_country,detected_exit_ip,status,enabled,
              health_generation)
             VALUES('perf-resource','198.51.100.7',1080,'US','US','198.51.100.8','ONLINE',1,1)
             RETURNING id",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO socks5_check_generations(resource_id,relay_node_id,generation)
             SELECT ?,id,1 FROM relay_nodes WHERE device_group_id=601",
        )
        .bind(resource_id)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO socks5_resource_health
                 (resource_id,relay_node_id,status,total_latency_ms,exit_ip,country,checked_at,
                  resource_revision,generation)
             SELECT ?,id,'ONLINE',100 + (id % 100),'198.51.100.8','US',?,1,1
             FROM relay_nodes WHERE device_group_id=601",
        )
        .bind(resource_id)
        .bind(&now)
        .execute(&pool)
        .await
        .unwrap();
        let status = serde_json::json!({
            "last_seen": now,
            "config_protocol_version": CONFIG_PROTOCOL_VERSION,
            "socks5_check_queue_depth": 0,
            "cpu": 15.0,
            "mem": 20.0,
            "connections": 5
        });
        sqlx::query(
            "INSERT INTO kvs(key,value)
             SELECT 'node_status:601:' || node_key,? FROM relay_nodes WHERE device_group_id=601",
        )
        .bind(status.to_string())
        .execute(&pool)
        .await
        .unwrap();

        let started = std::time::Instant::now();
        let result = recommend(
            &SqliteRepository::new(pool.clone()),
            &test_config(),
            resource_id,
        )
        .await
        .unwrap()
        .unwrap();
        let elapsed = started.elapsed();
        println!("stage4 sqlite recommendation 1000 nodes: {elapsed:?}");
        assert_eq!(result.candidates.len(), 1000);
        assert!(result.candidates.iter().all(|candidate| candidate.eligible));
        assert!(
            elapsed < std::time::Duration::from_secs(3),
            "elapsed={elapsed:?}"
        );

        let plan: Vec<(i64, i64, i64, String)> = sqlx::query_as(
            "EXPLAIN QUERY PLAN
             SELECT h.resource_id,h.relay_node_id
             FROM socks5_resource_health h
             LEFT JOIN socks5_check_generations g
               ON g.resource_id=h.resource_id AND g.relay_node_id=h.relay_node_id
             WHERE h.resource_id=? ORDER BY h.relay_node_id",
        )
        .bind(resource_id)
        .fetch_all(&pool)
        .await
        .unwrap();
        assert!(plan.iter().any(|(_, _, _, detail)| {
            detail.contains("socks5_resource_health") || detail.contains("sqlite_autoindex")
        }));
    }
}
