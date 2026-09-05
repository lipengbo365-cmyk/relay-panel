//! Shared node-config builder for the HTTP poll path (`get_config`) and the
//! WebSocket push path (`build_config_snapshot`).
//!
//! **Why this exists (v0.3.6 fix):** v0.3.5 had TWO copies of "turn a device
//! group into a NodeConfigResponse". They drifted — the HTTP path JOINed
//! `users` (to drop banned / over-quota rules) but the WS path did NOT, so a
//! freshly-(re)connected node could be handed a banned user's rules until the
//! next HTTP poll corrected it. There was also duplicated target resolution +
//! `build_listeners_for_rule` wiring in both files.
//!
//! This module is the single source of truth. Both callers go through
//! [`build_node_config`], so the filter, target resolution, protocol expansion,
//! transport derivation and ws_path passthrough are identical by construction.
//!
//! Error policy: a DB failure is surfaced as `Err(DbError)` instead of
//! silently returning an empty config. An empty result that came from a real
//! "no rules" state is indistinguishable from a DB failure under the old
//! `unwrap_or_default()` — that masked real errors as "no rules", which is
//! dangerous for quota enforcement. Callers decide how to render the error
//! (HTTP returns an empty config + logs; WS skips the snapshot push + logs).

use crate::db::error::DbError;
use crate::db::repo::{GroupRepository, ProfileScope, ResourceScope, TunnelProfileRepository};
use crate::db::Repository;
use crate::service::credentials::CredentialCipher;
use relay_shared::models::{DeviceGroup, ForwardRule};
use relay_shared::protocol::{
    IngressConfig, NodeConfigResponse, SecretString, Socks5InboundAuth, UpstreamConfig,
};

const RESOURCE_PASSWORD_PURPOSE: &str = "socks5-resource-password";
const RELAY_PASSWORD_PURPOSE: &str = "socks5-relay-password";

/// Build the full [`NodeConfigResponse`] for a device group.
///
/// This is the ONE function both `get_config` (HTTP) and `build_config_snapshot`
/// (WS) call. It performs, in order:
///
/// 1. Group lookup + "only `in` groups receive listeners" gate.
/// 2. Rule query with the unified filter:
///    - `device_group_in` matches the group
///    - `paused = 0`
///    - owning user `banned = 0`
///    - quota: `traffic_limit = 0` (unlimited) OR `traffic_used < traffic_limit`
/// 3. Per-rule target resolution (direct addr vs outbound group connect_host).
/// 4. [`relay_shared::protocol::build_listeners_for_rule`] for protocol
///    expansion + transport derivation + ws_path passthrough.
///
/// Returns `Ok(empty)` only for a legitimate empty state (non-`in` group, or an
/// `in` group with no matching rules). A DB error is `Err`.
#[cfg(test)]
pub async fn build_node_config(
    db: &dyn Repository,
    group_id: i64,
) -> Result<NodeConfigResponse, DbError> {
    build_node_config_with_key(db, group_id, None).await
}

/// Build node configuration and decrypt SOCKS5 credentials only at the final
/// serialization boundary. A missing/invalid key skips SOCKS5 listeners while
/// leaving legacy direct rules available.
pub async fn build_node_config_with_key(
    db: &dyn Repository,
    group_id: i64,
    credential_key: Option<&str>,
) -> Result<NodeConfigResponse, DbError> {
    // 1. Group + "in" gate. Non-`in` groups (out / monitor / chained_outbound)
    //    never receive listeners — they are egress/observation only.
    // find_by_id exists on both UserRepository and GroupRepository; we want the
    // group one, so qualify the call.
    let group = match GroupRepository::find_by_id(db, group_id, &ResourceScope::All).await? {
        Some(g) if g.group_type == "in" => g,
        _ => return Ok(NodeConfigResponse { listeners: vec![] }),
    };

    // 2. Filtered rule query. The JOIN on users is the fix for the v0.3.5 WS
    //    drift: without it a banned / over-quota user's rules would still be
    //    pushed to a reconnecting node. Both paths now share this exact query.
    //
    //    Quota note (unchanged from v0.3.0, documented): there is a leak window
    //    of up to one poll cycle (default 10s) because quota is re-checked only
    //    when the node fetches config, not per-packet. Offline nodes serve an
    //    unfiltered cached config ("forward over bill" trade-off). Do not change
    //    without a product decision.
    let rules: Vec<ForwardRule> = db.list_active_for_config(group.id).await?;

    // 3 + 4. Resolve targets and build listener configs. Target resolution needs
    //    a DB lookup (outbound group's connect_host), so it stays async and lives
    //    here; the pure ListenerConfig assembly (transport/ws_path/protocol) is
    //    delegated to the shared `build_listeners_for_rule` so that part can never
    //    drift between paths.
    let mut listeners = Vec::new();
    for rule in &rules {
        if let Some(binding) = db.find_socks5_rule_config(rule.id).await? {
            if !binding.resource_enabled {
                tracing::warn!(
                    rule_id = rule.id,
                    resource_id = binding.socks5_resource_id,
                    "SOCKS5 resource is disabled; listener omitted"
                );
                continue;
            }
            let cipher = match CredentialCipher::from_config(credential_key) {
                Ok(cipher) => cipher,
                Err(error) => {
                    tracing::error!(
                        rule_id = rule.id,
                        error = ?error,
                        "SOCKS5 credential key unavailable; listener omitted"
                    );
                    continue;
                }
            };
            let upstream_password = match decrypt_optional(
                &cipher,
                binding.resource_password_ciphertext.as_deref(),
                binding.resource_password_nonce.as_deref(),
                binding.resource_password_key_version,
                RESOURCE_PASSWORD_PURPOSE,
            ) {
                Ok(password) => password,
                Err(()) => {
                    tracing::error!(
                        rule_id = rule.id,
                        resource_id = binding.socks5_resource_id,
                        "SOCKS5 upstream credential decryption failed; listener omitted"
                    );
                    continue;
                }
            };
            if binding.resource_username.is_some() != upstream_password.is_some() {
                tracing::error!(
                    rule_id = rule.id,
                    resource_id = binding.socks5_resource_id,
                    "SOCKS5 upstream credential pair is incomplete; listener omitted"
                );
                continue;
            }
            let inbound_auth = if binding.allow_no_auth {
                Socks5InboundAuth::NoAuth
            } else {
                let Some(username) = binding.relay_username else {
                    tracing::error!(
                        rule_id = rule.id,
                        "relay username missing; listener omitted"
                    );
                    continue;
                };
                let password = match decrypt_optional(
                    &cipher,
                    binding.relay_password_ciphertext.as_deref(),
                    binding.relay_password_nonce.as_deref(),
                    binding.relay_password_key_version,
                    RELAY_PASSWORD_PURPOSE,
                ) {
                    Ok(Some(password)) => password,
                    _ => {
                        tracing::error!(
                            rule_id = rule.id,
                            "relay credential decryption failed; listener omitted"
                        );
                        continue;
                    }
                };
                Socks5InboundAuth::UsernamePassword {
                    username,
                    password: SecretString::new(password),
                }
            };
            let mut built = relay_shared::protocol::build_listeners_for_rule(rule, Vec::new());
            let Some(mut listener) = built.pop() else {
                tracing::error!(rule_id = rule.id, "SOCKS5 listener expansion failed");
                continue;
            };
            listener.ingress = IngressConfig::Socks5 { auth: inbound_auth };
            listener.upstream = UpstreamConfig::Socks5 {
                resource_id: binding.socks5_resource_id,
                resource_name: binding.resource_name,
                host: binding.resource_host,
                port: u16::try_from(binding.resource_port).unwrap_or_default(),
                username: binding.resource_username,
                password: upstream_password.map(SecretString::new),
                remote_dns: binding.remote_dns,
            };
            if listener.port == 0
                || matches!(&listener.upstream, UpstreamConfig::Socks5 { port: 0, .. })
            {
                tracing::error!(
                    rule_id = rule.id,
                    "invalid SOCKS5 listener endpoint; omitted"
                );
                continue;
            }
            listeners.push(listener);
            continue;
        }
        // v0.4.7: if the rule is bound to a tunnel profile, the profile is the
        // source of transport config (node_transport + ws_path). We resolve it
        // here and override the rule's stored columns for this build only — the
        // DB row is NOT rewritten. A NULL/missing profile falls back to the
        // rule's own public_transport/ws_path (legacy behavior, zero break).
        //
        // If a bound profile no longer exists (deleted out from under the rule,
        // or a stale FK), we skip the rule's listeners rather than emit a
        // half-resolved config. The admin sees no listener for that rule.
        let mut effective_rule = rule.clone();
        if let Some(pid) = rule.tunnel_profile_id {
            // v0.4.10: profile lookup here is a system-internal config build (no
            // user context), so it uses ProfileScope::All to resolve the real
            // binding. The dirty-data migration + list_active_for_config filter
            // (this PR) ensure a regular user's rule can't reach this point bound
            // to a non-builtin profile.
            match TunnelProfileRepository::find_profile_by_id(db, pid, &ProfileScope::All).await? {
                Some(profile) => {
                    // Profile transport vocab: "direct" → node "raw"; "ws" → "ws";
                    // "tls_simple" → "tls_simple".
                    let node_transport = match profile.transport.as_str() {
                        "direct" => "raw",
                        "ws" => "ws",
                        "tls_simple" => "tls_simple",
                        other => other,
                    };
                    effective_rule.node_transport = node_transport.to_string();
                    effective_rule.ws_path = if profile.transport == "ws" {
                        Some(profile.ws_path.clone())
                    } else {
                        None
                    };
                }
                None => {
                    tracing::warn!(
                        "rule {} bound to missing tunnel_profile_id {}; skipping (rebind or pause the rule)",
                        rule.id,
                        pid
                    );
                    continue;
                }
            }
        }
        let targets = resolve_targets(db, rule).await?;
        listeners.extend(relay_shared::protocol::build_listeners_for_rule(
            &effective_rule,
            targets,
        ));
    }

    Ok(NodeConfigResponse { listeners })
}

fn decrypt_optional(
    cipher: &CredentialCipher,
    ciphertext: Option<&str>,
    nonce: Option<&str>,
    version: i32,
    purpose: &str,
) -> Result<Option<String>, ()> {
    match (ciphertext, nonce) {
        (None, None) => Ok(None),
        (Some(ciphertext), Some(nonce)) => cipher
            .decrypt(ciphertext, nonce, version, purpose)
            .map(Some)
            .map_err(|_| ()),
        _ => Err(()),
    }
}

/// Resolve a rule's target address list.
///
/// - `forward_mode = "direct"` OR `device_group_out` is NULL → the rule's own
///   `target_addr:target_port`.
/// - otherwise → the outbound group's `connect_host:target_port`, falling back
///   to the rule's own `target_addr` when the outbound group is missing or has
///   no `connect_host` configured.
///
/// `targets` is the single place target resolution happens — both config paths
/// used to duplicate this `match` block.
async fn resolve_targets(db: &dyn Repository, rule: &ForwardRule) -> Result<Vec<String>, DbError> {
    let mut targets = db
        .list_enabled_rule_targets(rule.id, &ResourceScope::All)
        .await?;
    if targets.is_empty() {
        targets.push(relay_shared::models::ForwardRuleTarget {
            id: 0,
            rule_id: rule.id,
            host: rule.target_addr.clone(),
            port: rule.target_port,
            position: 1,
            enabled: true,
            created_at: String::new(),
        });
    }

    match (rule.forward_mode.as_str(), rule.device_group_out) {
        ("direct", _) | (_, None) => Ok(targets
            .into_iter()
            .map(|t| format!("{}:{}", t.host, t.port))
            .collect()),
        (_, Some(out_id)) => {
            // Qualify: find_by_id is on both UserRepository and GroupRepository.
            let og = GroupRepository::find_by_id(db, out_id, &ResourceScope::All).await?;
            Ok(match og {
                Some(DeviceGroup { connect_host, .. }) if !connect_host.is_empty() => targets
                    .into_iter()
                    .map(|t| format!("{}:{}", connect_host, t.port))
                    .collect(),
                _ => targets
                    .into_iter()
                    .map(|t| format!("{}:{}", t.host, t.port))
                    .collect(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::repo::TrafficRepository;
    use crate::db::schema::SCHEMA_SQL;
    use crate::db::sqlite_repo::SqliteRepository;
    use sqlx::sqlite::SqlitePoolOptions;
    use sqlx::SqlitePool;

    async fn pool() -> SqlitePool {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query(SCHEMA_SQL).execute(&pool).await.unwrap();
        pool
    }

    /// Wrap the pool in a SqliteRepository so build_node_config can be invoked
    /// the same way the real callers (get_config, build_config_snapshot) do.
    fn repo(pool: &SqlitePool) -> SqliteRepository {
        SqliteRepository::new(pool.clone())
    }

    async fn add_user(pool: &SqlitePool, id: i64) {
        let hash = bcrypt::hash(format!("pw-{id}"), 4).unwrap();
        sqlx::query("INSERT INTO users (id, username, password, admin) VALUES (?, ?, ?, 0)")
            .bind(id)
            .bind(format!("u{id}"))
            .bind(&hash)
            .execute(pool)
            .await
            .unwrap();
    }

    async fn add_group(pool: &SqlitePool, id: i64, gtype: &str, uid: i64) {
        sqlx::query(
            "INSERT INTO device_groups (id, name, group_type, token, uid) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(id)
        .bind(format!("g{id}"))
        .bind(gtype)
        .bind(format!("tok-{id}"))
        .bind(uid)
        .execute(pool)
        .await
        .unwrap();
    }

    async fn add_rule(pool: &SqlitePool, id: i64, uid: i64, in_group: i64, port: i64) {
        sqlx::query(
            "INSERT INTO forward_rules \
             (id, name, uid, listen_port, device_group_in, target_addr, target_port) \
             VALUES (?, ?, ?, ?, ?, '127.0.0.1', 80)",
        )
        .bind(id)
        .bind(format!("r{id}"))
        .bind(uid)
        .bind(port)
        .bind(in_group)
        .execute(pool)
        .await
        .unwrap();
    }

    /// A normal active user's rule on an `in` group must produce one listener.
    #[tokio::test]
    async fn active_rule_produces_listener() {
        let pool = pool().await;
        add_user(&pool, 2).await;
        add_group(&pool, 10, "in", 2).await;
        add_rule(&pool, 100, 2, 10, 20000).await;

        let cfg = build_node_config(&repo(&pool), 10).await.unwrap();
        assert_eq!(cfg.listeners.len(), 1);
        assert_eq!(cfg.listeners[0].port, 20000);
    }

    /// A banned user's rule must NOT appear — this is the regression the WS path
    /// was missing (v0.3.5 drift). Both paths now share this query, so the test
    /// pins the filter itself.
    #[tokio::test]
    async fn banned_user_rule_is_filtered() {
        let pool = pool().await;
        add_user(&pool, 2).await;
        add_group(&pool, 10, "in", 2).await;
        add_rule(&pool, 100, 2, 10, 20000).await;
        sqlx::query("UPDATE users SET banned = 1 WHERE id = 2")
            .execute(&pool)
            .await
            .unwrap();

        let cfg = build_node_config(&repo(&pool), 10).await.unwrap();
        assert!(
            cfg.listeners.is_empty(),
            "banned user rule must be filtered"
        );
    }

    /// An over-quota user's rule must be filtered.
    #[tokio::test]
    async fn over_quota_user_rule_is_filtered() {
        let pool = pool().await;
        add_user(&pool, 2).await;
        add_group(&pool, 10, "in", 2).await;
        add_rule(&pool, 100, 2, 10, 20000).await;
        sqlx::query("UPDATE users SET traffic_limit = 100, traffic_used = 100 WHERE id = 2")
            .execute(&pool)
            .await
            .unwrap();

        let cfg = build_node_config(&repo(&pool), 10).await.unwrap();
        assert!(cfg.listeners.is_empty(), "over-quota rule must be filtered");
    }

    /// A paused rule must be filtered.
    #[tokio::test]
    async fn paused_rule_is_filtered() {
        let pool = pool().await;
        add_user(&pool, 2).await;
        add_group(&pool, 10, "in", 2).await;
        add_rule(&pool, 100, 2, 10, 20000).await;
        sqlx::query("UPDATE forward_rules SET paused = 1 WHERE id = 100")
            .execute(&pool)
            .await
            .unwrap();

        let cfg = build_node_config(&repo(&pool), 10).await.unwrap();
        assert!(cfg.listeners.is_empty(), "paused rule must be filtered");
    }

    /// Non-`in` groups (out/monitor/chained_outbound) never receive listeners.
    #[tokio::test]
    async fn non_in_group_yields_no_listeners() {
        let pool = pool().await;
        add_user(&pool, 2).await;
        add_group(&pool, 10, "out", 2).await;
        add_rule(&pool, 100, 2, 10, 20000).await;

        let cfg = build_node_config(&repo(&pool), 10).await.unwrap();
        assert!(cfg.listeners.is_empty());
    }

    /// traffic_limit = 0 means unlimited — never filtered by quota even if
    /// traffic_used is huge.
    #[tokio::test]
    async fn unlimited_quota_never_filtered() {
        let pool = pool().await;
        add_user(&pool, 2).await;
        add_group(&pool, 10, "in", 2).await;
        add_rule(&pool, 100, 2, 10, 20000).await;
        sqlx::query("UPDATE users SET traffic_limit = 0, traffic_used = 999999999 WHERE id = 2")
            .execute(&pool)
            .await
            .unwrap();

        let cfg = build_node_config(&repo(&pool), 10).await.unwrap();
        assert_eq!(cfg.listeners.len(), 1);
    }

    /// v0.4.7: a rule bound to a WS tunnel profile must take its node_transport
    /// and ws_path FROM the profile (the rule's own columns are ignored).
    #[tokio::test]
    async fn profile_overrides_transport_and_ws_path() {
        let pool = pool().await;
        add_user(&pool, 2).await;
        add_group(&pool, 10, "in", 2).await;
        // The test pool only runs SCHEMA_SQL (no builtin seeds), so insert a ws
        // profile explicitly rather than rely on the Migration 6 seed.
        sqlx::query(
            "INSERT INTO tunnel_profiles (id, name, transport, tls_mode, ws_path, host_header, sni, is_builtin, uid) \
             VALUES (50, 'ws-relay', 'ws', 'none', '/relay', '', '', 1, 1)",
        )
        .execute(&pool)
        .await
        .unwrap();
        add_rule(&pool, 100, 2, 10, 20000).await;
        sqlx::query("UPDATE forward_rules SET tunnel_profile_id = 50 WHERE id = 100")
            .execute(&pool)
            .await
            .unwrap();

        let cfg = build_node_config(&repo(&pool), 10).await.unwrap();
        assert_eq!(cfg.listeners.len(), 1);
        assert_eq!(
            cfg.listeners[0].node_transport,
            relay_shared::protocol::NodeTransport::Ws,
            "profile transport must override the rule's stored raw transport"
        );
        assert_eq!(
            cfg.listeners[0].ws_path.as_deref(),
            Some("/relay"),
            "ws_path must come from the profile"
        );
    }

    /// v0.4.7: a rule with NO profile (tunnel_profile_id NULL) keeps using its
    /// own stored public_transport/ws_path — legacy behavior, zero break.
    #[tokio::test]
    async fn null_profile_falls_back_to_rule_transport() {
        let pool = pool().await;
        add_user(&pool, 2).await;
        add_group(&pool, 10, "in", 2).await;
        // A raw rule, no profile binding.
        add_rule(&pool, 100, 2, 10, 20000).await;

        let cfg = build_node_config(&repo(&pool), 10).await.unwrap();
        assert_eq!(cfg.listeners.len(), 1);
        assert_eq!(
            cfg.listeners[0].node_transport,
            relay_shared::protocol::NodeTransport::Raw
        );
        assert!(cfg.listeners[0].ws_path.is_none());
    }

    /// v0.4.7: a rule bound to a DELETED profile is skipped (no listener), not
    /// silently downgraded to raw.
    #[tokio::test]
    async fn missing_profile_skips_rule() {
        let pool = pool().await;
        add_user(&pool, 2).await;
        add_group(&pool, 10, "in", 2).await;
        add_rule(&pool, 100, 2, 10, 20000).await;
        // Point at a profile id that doesn't exist. Disable FK enforcement for
        // this insert so SQLite accepts the dangling reference (production code
        // prevents this via Migration 22's NULL-out + delete usage count, but
        // we want to pin the builder's defensive skip behavior).
        sqlx::query("PRAGMA foreign_keys = OFF")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("UPDATE forward_rules SET tunnel_profile_id = 99999 WHERE id = 100")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("PRAGMA foreign_keys = ON")
            .execute(&pool)
            .await
            .unwrap();

        let cfg = build_node_config(&repo(&pool), 10).await.unwrap();
        assert!(
            cfg.listeners.is_empty(),
            "a rule bound to a missing profile must be skipped, not downgraded"
        );
    }

    #[tokio::test]
    async fn socks5_rule_is_decrypted_only_at_config_boundary_and_fails_closed_without_key() {
        use crate::service::credentials::CredentialCipher;
        use relay_shared::protocol::{IngressConfig, Socks5InboundAuth, UpstreamConfig};

        let pool = pool().await;
        add_user(&pool, 2).await;
        add_group(&pool, 10, "in", 2).await;
        add_rule(&pool, 100, 2, 10, 20000).await;
        let key = "11".repeat(32);
        let cipher = CredentialCipher::from_config(Some(&key)).unwrap();
        let (upstream_ciphertext, upstream_nonce, upstream_version) = cipher
            .encrypt("upstream-secret", RESOURCE_PASSWORD_PURPOSE)
            .unwrap();
        let (relay_ciphertext, relay_nonce, relay_version) = cipher
            .encrypt("relay-secret", RELAY_PASSWORD_PURPOSE)
            .unwrap();
        sqlx::query(
            "INSERT INTO socks5_resources
             (id, name, host, port, username, password_ciphertext, password_nonce,
              password_key_version, enabled)
             VALUES (7, 'mock-upstream', '127.0.0.1', 1080, 'up-user', ?, ?, ?, 1)",
        )
        .bind(&upstream_ciphertext)
        .bind(&upstream_nonce)
        .bind(upstream_version)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO socks5_rule_bindings
             (rule_id, socks5_resource_id, remote_dns, relay_username,
              relay_password_ciphertext, relay_password_nonce,
              relay_password_key_version, allow_no_auth)
             VALUES (100, 7, 1, 'relay-user', ?, ?, ?, 0)",
        )
        .bind(&relay_ciphertext)
        .bind(&relay_nonce)
        .bind(relay_version)
        .execute(&pool)
        .await
        .unwrap();

        let config = build_node_config_with_key(&repo(&pool), 10, Some(&key))
            .await
            .unwrap();
        assert_eq!(config.listeners.len(), 1);
        let listener = &config.listeners[0];
        assert!(listener.targets.is_empty());
        match &listener.ingress {
            IngressConfig::Socks5 {
                auth: Socks5InboundAuth::UsernamePassword { username, password },
            } => {
                assert_eq!(username, "relay-user");
                assert_eq!(password.expose(), "relay-secret");
            }
            other => panic!("unexpected ingress: {other:?}"),
        }
        match &listener.upstream {
            UpstreamConfig::Socks5 {
                resource_id,
                host,
                port,
                username,
                password,
                remote_dns,
                ..
            } => {
                assert_eq!(*resource_id, 7);
                assert_eq!(host, "127.0.0.1");
                assert_eq!(*port, 1080);
                assert_eq!(username.as_deref(), Some("up-user"));
                assert_eq!(
                    password.as_ref().map(|value| value.expose()),
                    Some("upstream-secret")
                );
                assert!(*remote_dns);
            }
            other => panic!("unexpected upstream: {other:?}"),
        }
        let serialized = serde_json::to_string(listener).unwrap();
        assert!(
            serialized.contains("relay-secret"),
            "wire config carries the runtime secret"
        );
        assert!(!serialized.contains(&relay_ciphertext));
        assert!(!serialized.contains(&upstream_ciphertext));

        let repository = repo(&pool);
        let results = repository
            .apply_traffic_batch(
                10,
                &[relay_shared::protocol::TrafficEntry {
                    rule_id: 100,
                    upload: 120,
                    download: 80,
                }],
            )
            .await
            .unwrap();
        assert_eq!(results.len(), 1);
        let rule_traffic: i64 =
            sqlx::query_scalar("SELECT traffic_used FROM forward_rules WHERE id = 100")
                .fetch_one(&pool)
                .await
                .unwrap();
        let user_traffic: i64 = sqlx::query_scalar("SELECT traffic_used FROM users WHERE id = 2")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(rule_traffic, 200);
        assert_eq!(user_traffic, 200);

        let fail_closed = build_node_config_with_key(&repo(&pool), 10, None)
            .await
            .unwrap();
        assert!(fail_closed.listeners.is_empty());

        sqlx::query("UPDATE socks5_resources SET enabled = 0 WHERE id = 7")
            .execute(&pool)
            .await
            .unwrap();
        let disabled_resource = build_node_config_with_key(&repo(&pool), 10, Some(&key))
            .await
            .unwrap();
        assert!(
            disabled_resource.listeners.is_empty(),
            "a disabled upstream resource must remove the listener"
        );

        sqlx::query("UPDATE socks5_resources SET enabled = 1 WHERE id = 7")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("UPDATE forward_rules SET paused = 1 WHERE id = 100")
            .execute(&pool)
            .await
            .unwrap();
        let paused_rule = build_node_config_with_key(&repo(&pool), 10, Some(&key))
            .await
            .unwrap();
        assert!(
            paused_rule.listeners.is_empty(),
            "a paused SOCKS5 rule must remove the listener"
        );
    }
}
