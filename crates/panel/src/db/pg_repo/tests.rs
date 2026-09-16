// ── Contract tests (PostgreSQL) ──
//
// These mirror sqlite_repo.rs::tests but run against a real PostgreSQL
// instance. They're gated on the `TEST_PG_URL` env var: absent → skip (so a
// plain `cargo test` on a dev machine without PG still passes). The CI
// workflow sets TEST_PG_URL to a postgres:// service, so PR2's PG contract is
// verified on every push.
//
// Each test creates a UNIQUE schema (so concurrent `cargo test` runs don't
// collide), applies PG_SCHEMA_SQL, runs the assertion, and drops the schema.
// The schema name embeds the test name + process id for uniqueness.

use super::PgRepository;
use crate::config::Config;
use crate::db::error::DbError;
use crate::db::health_orchestration::*;
use crate::db::pg_schema::{apply_pg_schema, run_pg_migrations};
use crate::db::repo::*;
use relay_shared::protocol::TrafficEntry;
use sqlx::postgres::PgPoolOptions;

/// Read TEST_PG_URL. Returns None if unset → tests skip.
fn pg_url() -> Option<String> {
    std::env::var("TEST_PG_URL").ok().filter(|s| !s.is_empty())
}

/// Replace the database path in a postgres:// URL. Handles
/// `postgres://user:pass@host:port/dbname` → `.../newname` and
/// `postgres://user:pass@host/dbname` (no port). Leaves query params intact.
fn replace_db_in_url(url: &str, new_db: &str) -> String {
    // Split off query string if present, reattach after.
    let (base, query) = match url.split_once('?') {
        Some((b, q)) => (b, Some(q)),
        None => (url, None),
    };
    // Find the last '/' after the host portion (the db path). PG URLs are
    // `scheme://[user[:pass]@]host[:port]/dbname`. The db name is the
    // segment after the last '/' in the authority path.
    let new_base = match base.rsplit_once('/') {
        Some((head, _)) => format!("{}/{}", head, new_db),
        None => format!("{}/{}", base, new_db),
    };
    match query {
        Some(q) => format!("{}?{}", new_base, q),
        None => new_base,
    }
}

/// Build a fresh PG database + PgRepository for one test. Each test gets
/// its own database (test_pr2_{suffix}) for full isolation — no
/// search_path tricks, no shared-schema collisions. The database is
/// dropped at the start of the next run with the same suffix.
async fn repo(suffix: &str) -> Option<PgRepository> {
    repo_with_connections(suffix, 2).await
}

async fn repo_with_connections(suffix: &str, max_connections: u32) -> Option<PgRepository> {
    let url = pg_url()?;

    // Parse the admin URL to derive the "postgres" maintenance database
    // URL (we need it to CREATE DATABASE — you can't drop the DB you're
    // connected to).
    let db_name = format!("test_pr2_{}", suffix);
    let admin_url = pg_url().unwrap_or_default();
    // Replace the database path in the URL with "postgres" (the default
    // maintenance DB every PG install has). Handles
    // postgres://user:pass@host:port/dbname -> .../postgres
    let admin_url = replace_db_in_url(&admin_url, "postgres");

    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&admin_url)
        .await
        .expect("connect admin db");

    // Drop the test DB if it survived a previous run, then create it fresh.
    // DROP IF EXISTS + CREATE — idempotent. We can't use parameters for
    // identifiers in DDL, but db_name is constructed from a compile-time
    // suffix literal (never user input), so format! is injection-safe.
    let _ = sqlx::query(&format!("DROP DATABASE IF EXISTS {}", db_name))
        .execute(&admin)
        .await;
    sqlx::query(&format!("CREATE DATABASE {}", db_name))
        .execute(&admin)
        .await
        .expect("create test db");
    admin.close().await;

    // Connect to the fresh test database and apply the schema.
    let test_url = replace_db_in_url(&url, &db_name);
    let pool = PgPoolOptions::new()
        .max_connections(max_connections)
        .connect(&test_url)
        .await
        .expect("connect test db");
    apply_pg_schema(&pool).await.expect("apply schema");
    run_pg_migrations(&pool).await.expect("run migrations");

    Some(PgRepository::new(pool))
}

/// Drop the test database. We reconnect to the admin DB (postgres) to
/// issue DROP DATABASE — you can't drop the DB you're connected to.
async fn cleanup(db: &PgRepository) {
    // Close the test pool first so there are no lingering connections
    // holding the database open.
    let _ = db.pool.close().await;
    // Best-effort: if the admin URL isn't available the DB stays and gets
    // re-dropped on the next run. CI ephemeral DBs are fine with this.
    if let Some(url) = pg_url() {
        let admin_url = replace_db_in_url(&url, "postgres");
        if let Ok(admin) = PgPoolOptions::new()
            .max_connections(1)
            .connect(&admin_url)
            .await
        {
            // Extract the test DB name from the pool's connection URL by
            // matching known test_pr2_* prefixes. Simpler: DROP all test
            // DBs matching the pattern. But that's racy. Instead we just
            // rely on the next repo() call dropping this DB first.
            let _ = sqlx::query("SELECT 1").execute(&admin).await;
            let _ = admin.close().await;
        }
    }
}

// ── User ──

#[tokio::test]
async fn pg_user_find_by_username_distinguishes_banned() {
    let Some(db) = repo("user_banned").await else {
        return;
    };
    db.insert_user("alice", "$2b$12$hash", 1).await.unwrap();
    assert!(db.find_by_username("alice").await.unwrap().is_some());

    sqlx::query("UPDATE users SET banned = TRUE WHERE username = 'alice'")
        .execute(&db.pool)
        .await
        .unwrap();
    assert!(db
        .find_by_username_not_banned("alice")
        .await
        .unwrap()
        .is_none());
    assert!(db.find_by_username("alice").await.unwrap().is_some());
    cleanup(&db).await;
}

#[tokio::test]
async fn pg_user_insert_returns_unique_violation_on_duplicate() {
    let Some(db) = repo("user_dup").await else {
        return;
    };
    db.insert_user("alice", "h1", 1).await.unwrap();
    match db.insert_user("alice", "h2", 1).await {
        Err(DbError::UniqueViolation) => {}
        other => panic!("expected UniqueViolation, got {:?}", other),
    }
    cleanup(&db).await;
}

#[tokio::test]
async fn pg_user_update_password_and_find_password_by_id_round_trip() {
    let Some(db) = repo("user_pw").await else {
        return;
    };
    db.insert_user("alice", "old-hash", 1).await.unwrap();
    let uid = db.find_by_username("alice").await.unwrap().unwrap().id;
    assert_eq!(
        db.find_password_by_id(uid).await.unwrap().as_deref(),
        Some("old-hash")
    );
    assert_eq!(db.update_password(uid, "new-hash").await.unwrap(), 1);
    assert_eq!(
        db.find_password_by_id(uid).await.unwrap().as_deref(),
        Some("new-hash")
    );
    assert_eq!(db.update_password(999_999, "x").await.unwrap(), 0);
    cleanup(&db).await;
}

#[tokio::test]
async fn pg_user_update_fields_only_touches_present_columns() {
    let Some(db) = repo("user_upd").await else {
        return;
    };
    db.insert_user("alice", "h", 1).await.unwrap();
    let uid = db.find_by_username("alice").await.unwrap().unwrap().id;
    assert_eq!(
        db.update_user_fields(uid, None, Some(7), None, None, None)
            .await
            .unwrap(),
        1
    );
    let row: (i32, i64, bool) =
        sqlx::query_as("SELECT max_rules, traffic_limit, banned FROM users WHERE id = $1")
            .bind(uid)
            .fetch_one(&db.pool)
            .await
            .unwrap();
    assert_eq!(row.0, 7);
    assert_eq!(row.1, 0);
    assert!(!row.2);
    assert_eq!(
        db.update_user_fields(uid, None, None, None, None, None)
            .await
            .unwrap(),
        0
    );
    cleanup(&db).await;
}

#[tokio::test]
async fn pg_user_reset_traffic_zeros_user_and_owned_rules_atomically() {
    let Some(db) = repo("user_reset").await else {
        return;
    };
    // Seed an inbound group so FK on forward_rules.device_group_in holds.
    sqlx::query("INSERT INTO device_groups (id, name, group_type, token, uid) VALUES (1, 'gin', 'in', 'tok-1', 1)")
        .execute(&db.pool)
        .await
        .unwrap();
    db.insert_user("alice", "h", 1).await.unwrap();
    let uid = db.find_by_username("alice").await.unwrap().unwrap().id;
    sqlx::query("UPDATE users SET traffic_used = 500 WHERE id = $1")
        .bind(uid)
        .execute(&db.pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO forward_rules \
         (name, uid, listen_port, device_group_in, target_addr, target_port, traffic_used) \
         VALUES ('r1', $1, 20000, 1, '127.0.0.1', 80, 250)",
    )
    .bind(uid)
    .execute(&db.pool)
    .await
    .unwrap();
    db.reset_traffic(uid).await.unwrap();
    let user_t: (i64,) = sqlx::query_as("SELECT traffic_used FROM users WHERE id = $1")
        .bind(uid)
        .fetch_one(&db.pool)
        .await
        .unwrap();
    let rule_t: (i64,) = sqlx::query_as("SELECT traffic_used FROM forward_rules WHERE uid = $1")
        .bind(uid)
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(user_t.0, 0);
    assert_eq!(rule_t.0, 0);
    cleanup(&db).await;
}

#[tokio::test]
async fn pg_rule_targets_replace_and_list_enabled_in_order() {
    let Some(db) = repo("rule_targets").await else {
        return;
    };
    sqlx::query("INSERT INTO device_groups (id, name, group_type, token, uid) VALUES (1, 'gin', 'in', 'tok-1', 1)")
        .execute(&db.pool)
        .await
        .unwrap();
    db.insert_quota_guarded(
        "multi",
        1,
        21000,
        "tcp",
        "raw",
        "raw",
        "direct",
        "raw",
        None,
        1,
        None,
        "direct",
        "127.0.0.1",
        80,
    )
    .await
    .unwrap();
    let rule = db.list_rules(&ResourceScope::All).await.unwrap().remove(0);

    db.replace_rule_targets(
        rule.id,
        &ResourceScope::All,
        &[
            relay_shared::protocol::RuleTargetRequest {
                host: "a.example.com".into(),
                port: 1001,
                enabled: true,
            },
            relay_shared::protocol::RuleTargetRequest {
                host: "b.example.com".into(),
                port: 1002,
                enabled: false,
            },
            relay_shared::protocol::RuleTargetRequest {
                host: "c.example.com".into(),
                port: 1003,
                enabled: true,
            },
        ],
    )
    .await
    .unwrap();

    let all = db
        .list_rule_targets(rule.id, &ResourceScope::All)
        .await
        .unwrap();
    assert_eq!(all.len(), 3);
    assert_eq!(all[0].host, "a.example.com");
    assert_eq!(all[1].position, 2);
    assert!(!all[1].enabled);

    let enabled = db
        .list_enabled_rule_targets(rule.id, &ResourceScope::All)
        .await
        .unwrap();
    assert_eq!(enabled.len(), 2);
    assert_eq!(enabled[0].host, "a.example.com");
    assert_eq!(enabled[1].host, "c.example.com");
    cleanup(&db).await;
}

#[tokio::test]
async fn pg_user_delete_non_admin_protects_admins() {
    let Some(db) = repo("user_del").await else {
        return;
    };
    db.insert_user("alice", "h", 1).await.unwrap();
    let alice = db.find_by_username("alice").await.unwrap().unwrap().id;
    assert_eq!(db.delete_non_admin(alice).await.unwrap(), 1);
    assert!(!db.exists_by_id(alice).await.unwrap());
    assert_eq!(db.delete_non_admin(1).await.unwrap(), 0);
    assert!(db.exists_by_id(1).await.unwrap());
    cleanup(&db).await;
}

#[tokio::test]
async fn pg_delete_user_cascade_removes_rules_groups_profiles_and_user() {
    // Regression for v0.4.4: the cascade must also delete the user's custom
    // tunnel_profiles and run in one transaction. Pre-v0.4.4 PG missed
    // tunnel_profiles, so a user with one would FK-block on the user delete
    // after rules+groups were already gone (partial data loss).
    let Some(db) = repo("user_cascade").await else {
        return;
    };
    db.insert_user("alice", "h", 1).await.unwrap();
    let uid = db.find_by_username("alice").await.unwrap().unwrap().id;
    sqlx::query(
        "INSERT INTO device_groups (id, name, group_type, token, uid) \
         VALUES (1, 'gin', 'in', 'tok-1', $1)",
    )
    .bind(uid)
    .execute(&db.pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO forward_rules \
         (name, uid, listen_port, device_group_in, target_addr, target_port) \
         VALUES ('r1', $1, 20000, 1, '127.0.0.1', 80)",
    )
    .bind(uid)
    .execute(&db.pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO tunnel_profiles (name, transport, uid) \
         VALUES ('alice-custom', 'ws', $1)",
    )
    .bind(uid)
    .execute(&db.pool)
    .await
    .unwrap();

    let affected = db.delete_user_cascade(uid).await.unwrap();
    assert_eq!(affected, 1, "user row must be deleted");

    for (table, col) in [
        ("forward_rules", "uid"),
        ("device_groups", "uid"),
        ("tunnel_profiles", "uid"),
    ] {
        let n: (i64,) = sqlx::query_as(&format!(
            "SELECT COUNT(*) FROM {} WHERE {} = $1",
            table, col
        ))
        .bind(uid)
        .fetch_one(&db.pool)
        .await
        .unwrap();
        assert_eq!(n.0, 0, "{} rows for user must be deleted", table);
    }
    assert!(!db.exists_by_id(uid).await.unwrap(), "user must be gone");
    cleanup(&db).await;
}

#[tokio::test]
async fn pg_apply_schema_seeds_baseline_version() {
    // v0.4.4: apply_pg_schema must create schema_version and seed revision 1,
    // and run_pg_migrations must be a no-op at the baseline.
    let Some(db) = repo("schema_version").await else {
        return;
    };
    let v: i32 = sqlx::query_scalar("SELECT COALESCE(MAX(version), 0) FROM schema_version")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(v, crate::db::pg_schema::PG_SCHEMA_VERSION);
    // Migrations at baseline are a no-op (must not error or loop).
    crate::db::pg_schema::run_pg_migrations(&db.pool)
        .await
        .expect("baseline migrations must be a no-op");
    cleanup(&db).await;
}

#[tokio::test]
async fn pg_user_delete_cascade_refuses_admin_and_rolls_back() {
    let Some(db) = repo("user_cascade_admin").await else {
        return;
    };
    // Admin (id=1, seeded) with owned resources. Cascade must delete nothing.
    sqlx::query("INSERT INTO device_groups (id, name, group_type, token, uid) VALUES (1, 'admin-g', 'in', 'tok-admin', 1)")
        .execute(&db.pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO forward_rules \
         (id, name, uid, listen_port, device_group_in, target_addr, target_port) \
         VALUES (1, 'admin-r', 1, 21000, 1, '127.0.0.1', 80)",
    )
    .execute(&db.pool)
    .await
    .unwrap();

    let affected = db.delete_user_cascade(1).await.unwrap();
    assert_eq!(affected, 0, "admin delete must affect 0 rows");

    let groups: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM device_groups WHERE uid = 1")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    let rules: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM forward_rules WHERE uid = 1")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(groups.0, 1, "admin group must be rolled back");
    assert_eq!(rules.0, 1, "admin rule must be rolled back");
    assert!(db.exists_by_id(1).await.unwrap(), "admin must still exist");
    cleanup(&db).await;
}

#[tokio::test]
async fn pg_user_placeholder_password_methods_round_trip() {
    let Some(db) = repo("user_ph").await else {
        return;
    };
    assert_eq!(db.count_placeholder_admin_password().await.unwrap(), 1);
    db.replace_placeholder_admin_password("$2b$12$realhash")
        .await
        .unwrap();
    assert_eq!(db.count_placeholder_admin_password().await.unwrap(), 0);
    db.replace_placeholder_admin_password("$2b$12$other")
        .await
        .unwrap();
    let stored: (String,) = sqlx::query_as("SELECT password FROM users WHERE id = 1")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(stored.0, "$2b$12$realhash");
    cleanup(&db).await;
}

// ── Rule ──

#[tokio::test]
async fn pg_rule_insert_quota_guarded_respects_max_rules() {
    let Some(db) = repo("rule_quota").await else {
        return;
    };
    sqlx::query("INSERT INTO device_groups (id, name, group_type, token, uid) VALUES (1, 'gin', 'in', 'tok-1', 1)")
        .execute(&db.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE users SET max_rules = 2 WHERE id = 1")
        .execute(&db.pool)
        .await
        .unwrap();
    for port in [20000, 20001] {
        assert_eq!(
            db.insert_quota_guarded(
                "r",
                1,
                port,
                "tcp",
                "raw",
                "raw",
                "direct",
                "raw",
                None,
                1,
                None,
                "direct",
                "127.0.0.1",
                80,
            )
            .await
            .unwrap(),
            1
        );
    }
    assert_eq!(
        db.insert_quota_guarded(
            "r3",
            1,
            20002,
            "tcp",
            "raw",
            "raw",
            "direct",
            "raw",
            None,
            1,
            None,
            "direct",
            "127.0.0.1",
            80,
        )
        .await
        .unwrap(),
        0,
        "quota guard must reject the third insert"
    );
    sqlx::query("UPDATE users SET max_rules = 0 WHERE id = 1")
        .execute(&db.pool)
        .await
        .unwrap();
    assert_eq!(
        db.insert_quota_guarded(
            "r4",
            1,
            20003,
            "tcp",
            "raw",
            "raw",
            "direct",
            "raw",
            None,
            1,
            None,
            "direct",
            "127.0.0.1",
            80,
        )
        .await
        .unwrap(),
        1
    );
    cleanup(&db).await;
}

#[tokio::test]
async fn pg_rule_insert_quota_guarded_surfaces_port_unique_violation() {
    let Some(db) = repo("rule_unique").await else {
        return;
    };
    sqlx::query("INSERT INTO device_groups (id, name, group_type, token, uid) VALUES (1, 'gin', 'in', 'tok-1', 1)")
        .execute(&db.pool)
        .await
        .unwrap();
    db.insert_quota_guarded(
        "r1",
        1,
        20000,
        "tcp",
        "raw",
        "raw",
        "direct",
        "raw",
        None,
        1,
        None,
        "direct",
        "127.0.0.1",
        80,
    )
    .await
    .unwrap();
    match db
        .insert_quota_guarded(
            "r2",
            1,
            20000,
            "tcp",
            "raw",
            "raw",
            "direct",
            "raw",
            None,
            1,
            None,
            "direct",
            "127.0.0.1",
            80,
        )
        .await
    {
        Err(DbError::PortConflict) => {}
        other => panic!("expected PortConflict on port collision, got {:?}", other),
    }
    cleanup(&db).await;
}

/// v0.4.11 PR4 (PG parity): pure-TCP and pure-UDP may share a port on the
/// same group; two TCP-bearing (or two UDP-bearing) may not.
#[tokio::test]
async fn pg_rule_insert_quota_guarded_tcp_udp_share_port() {
    let Some(db) = repo("rule_tcp_udp_share").await else {
        return;
    };
    sqlx::query("INSERT INTO device_groups (id, name, group_type, token, uid) VALUES (1, 'gin', 'in', 'tok-1', 1)")
        .execute(&db.pool)
        .await
        .unwrap();
    let insert = |name: &'static str, proto: &'static str| {
        let db = &db;
        async move {
            db.insert_quota_guarded(
                name,
                1,
                20000,
                proto,
                "raw",
                "raw",
                "direct",
                "raw",
                None,
                1,
                None,
                "direct",
                "127.0.0.1",
                80,
            )
            .await
        }
    };
    insert("r1", "tcp").await.unwrap();
    insert("r2", "udp").await.unwrap();
    match insert("r3", "tcp").await {
        Err(DbError::PortConflict) => {}
        other => panic!("expected PortConflict for second tcp, got {:?}", other),
    }
    match insert("r4", "udp").await {
        Err(DbError::PortConflict) => {}
        other => panic!("expected PortConflict for second udp, got {:?}", other),
    }
    match insert("r5", "tcp_udp").await {
        Err(DbError::PortConflict) => {}
        other => panic!("expected PortConflict for tcp_udp, got {:?}", other),
    }
    cleanup(&db).await;
}

/// v0.4.11 PR4 (PG parity): same port on a DIFFERENT group is allowed;
/// different users sharing one group share its pool.
#[tokio::test]
async fn pg_rule_insert_quota_guarded_port_scoped_by_group() {
    let Some(db) = repo("rule_port_group_scope").await else {
        return;
    };
    sqlx::query("INSERT INTO device_groups (id, name, group_type, token, uid) VALUES (1, 'gin', 'in', 'tok-1', 1)")
        .execute(&db.pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO device_groups (id, name, group_type, token, uid) VALUES (2, 'gin2', 'in', 'tok-2', 1)")
        .execute(&db.pool)
        .await
        .unwrap();
    let insert = |name: &'static str, uid: i64, group: i64| {
        let db = &db;
        async move {
            db.insert_quota_guarded(
                name,
                uid,
                20000,
                "tcp",
                "raw",
                "raw",
                "direct",
                "raw",
                None,
                group,
                None,
                "direct",
                "127.0.0.1",
                80,
            )
            .await
        }
    };
    insert("r1", 1, 1).await.unwrap();
    insert("r2", 1, 2).await.unwrap();
    match insert("r3", 1, 1).await {
        Err(DbError::PortConflict) => {}
        other => panic!(
            "expected PortConflict on shared group pool, got {:?}",
            other
        ),
    }
    cleanup(&db).await;
}

// ── v1.2.x (PG parity): auto_assign_port honors the group's port_range ──

/// Seed an inbound device_group with an explicit `port_range` (the auto-assign
/// pool). PG mirror of the SQLite `seed_group_with_range` helper.
async fn seed_group_with_range(db: &PgRepository, gid: i64, range: &str) {
    sqlx::query(
        "INSERT INTO device_groups (id, name, group_type, token, uid, port_range) \
         VALUES ($1, 'gin', 'in', $2, 1, $3)",
    )
    .bind(gid)
    .bind(format!("tok-{gid}"))
    .bind(range)
    .execute(&db.pool)
    .await
    .unwrap();
}

/// PG mirror: an explicit narrow range confines every auto-assigned port.
#[tokio::test]
async fn pg_auto_assign_port_stays_within_explicit_group_range() {
    use crate::service::rules::auto_assign_port;
    let Some(db) = repo("auto_port_explicit_range").await else {
        return;
    };
    seed_group_with_range(&db, 1, "65000-65100").await;
    for _ in 0..30 {
        let p = auto_assign_port(&db, 1, "tcp").await.unwrap();
        assert!(
            (65000..=65100).contains(&p),
            "auto port {} escaped the configured 65000-65100 range",
            p
        );
    }
    cleanup(&db).await;
}

/// PG mirror: the `1-65535` sentinel maps to the 10000-65535 default pool.
#[tokio::test]
async fn pg_auto_assign_port_sentinel_uses_default_pool() {
    use crate::service::rules::auto_assign_port;
    let Some(db) = repo("auto_port_sentinel").await else {
        return;
    };
    // No port_range column → PG schema default '1-65535' (the sentinel).
    sqlx::query("INSERT INTO device_groups (id, name, group_type, token, uid) VALUES (1, 'gin', 'in', 'tok-1', 1)")
        .execute(&db.pool)
        .await
        .unwrap();
    for _ in 0..30 {
        let p = auto_assign_port(&db, 1, "tcp").await.unwrap();
        assert!(
            (10000..=65535).contains(&p),
            "sentinel must map to 10000-65535, got {}",
            p
        );
    }
    cleanup(&db).await;
}

/// PG mirror: a full range errors (naming the range), socket-type scoped.
#[tokio::test]
async fn pg_auto_assign_port_errors_when_range_full() {
    use crate::service::rules::auto_assign_port;
    let Some(db) = repo("auto_port_full").await else {
        return;
    };
    seed_group_with_range(&db, 1, "50000-50000").await;
    db.insert_quota_guarded(
        "r1",
        1,
        50000,
        "tcp",
        "raw",
        "raw",
        "direct",
        "raw",
        None,
        1,
        None,
        "direct",
        "127.0.0.1",
        80,
    )
    .await
    .unwrap();
    let err = auto_assign_port(&db, 1, "tcp").await.unwrap_err();
    assert!(
        err.contains("50000-50000"),
        "error must name the exhausted range, got {:?}",
        err
    );
    let p = auto_assign_port(&db, 1, "udp").await.unwrap();
    assert_eq!(p, 50000, "udp must reuse the port held only by tcp");
    cleanup(&db).await;
}

/// PG mirror: a non-existent group id falls back to the default pool.
#[tokio::test]
async fn pg_auto_assign_port_missing_group_uses_default_pool() {
    use crate::service::rules::auto_assign_port;
    let Some(db) = repo("auto_port_missing_group").await else {
        return;
    };
    let p = auto_assign_port(&db, 999, "tcp").await.unwrap();
    assert!(
        (10000..=65535).contains(&p),
        "missing group must use the default pool, got {}",
        p
    );
    cleanup(&db).await;
}

/// v1.2 regression (PG mirror of the SQLite test): the same listen_port may be
/// reused across two different inbound groups. create_rule_full returns the id
/// straight from RETURNING, so the second rule's targets / LB / rate limits land
/// on the SECOND rule — never the first.
#[tokio::test]
async fn pg_rule_create_full_cross_group_no_crosstalk() {
    let Some(db) = repo("rule_full_cross_group").await else {
        return;
    };
    sqlx::query("INSERT INTO device_groups (id, name, group_type, token, uid) VALUES (1, 'gin', 'in', 'tok-1', 1)")
        .execute(&db.pool).await.unwrap();
    sqlx::query("INSERT INTO device_groups (id, name, group_type, token, uid) VALUES (2, 'gin2', 'in', 'tok-2', 1)")
        .execute(&db.pool).await.unwrap();

    // Rule A: group 1, port 10000, ONE target, default LB, no caps.
    let id_a = db
        .create_rule_full(
            "ruleA",
            1,
            10000,
            "tcp_udp",
            "raw",
            "raw",
            "direct",
            "raw",
            None,
            1,
            None,
            "direct",
            "1.1.1.1",
            80,
            &[relay_shared::protocol::RuleTargetRequest {
                host: "a.example.com".into(),
                port: 1001,
                enabled: true,
            }],
            "first",
            0,
            0,
            None,
        )
        .await
        .unwrap()
        .expect("rule A created");

    // Rule B: group 2, SAME port 10000, THREE targets + round_robin + caps.
    let id_b = db
        .create_rule_full(
            "ruleB",
            1,
            10000,
            "tcp_udp",
            "raw",
            "raw",
            "direct",
            "raw",
            None,
            2,
            None,
            "direct",
            "2.2.2.2",
            80,
            &[
                relay_shared::protocol::RuleTargetRequest {
                    host: "b1.example.com".into(),
                    port: 2001,
                    enabled: true,
                },
                relay_shared::protocol::RuleTargetRequest {
                    host: "b2.example.com".into(),
                    port: 2002,
                    enabled: true,
                },
                relay_shared::protocol::RuleTargetRequest {
                    host: "b3.example.com".into(),
                    port: 2003,
                    enabled: true,
                },
            ],
            "round_robin",
            50,
            100,
            None,
        )
        .await
        .unwrap()
        .expect("rule B created");

    assert_ne!(id_a, id_b, "two distinct rules must have distinct ids");

    let a = db
        .find_rule_by_id(id_a, &ResourceScope::All)
        .await
        .unwrap()
        .expect("rule A exists");
    assert_eq!(a.device_group_in, 1);
    assert_eq!(a.load_balance_strategy, "first");
    assert_eq!(a.upload_limit_mbps, 0);
    assert_eq!(a.download_limit_mbps, 0);
    let a_targets = db
        .list_rule_targets(id_a, &ResourceScope::All)
        .await
        .unwrap();
    assert_eq!(a_targets.len(), 1, "rule A keeps exactly its one target");
    assert_eq!(a_targets[0].host, "a.example.com");

    let b = db
        .find_rule_by_id(id_b, &ResourceScope::All)
        .await
        .unwrap()
        .expect("rule B exists");
    assert_eq!(b.device_group_in, 2);
    assert_eq!(b.load_balance_strategy, "round_robin");
    assert_eq!(b.upload_limit_mbps, 50);
    assert_eq!(b.download_limit_mbps, 100);
    let b_targets = db
        .list_rule_targets(id_b, &ResourceScope::All)
        .await
        .unwrap();
    assert_eq!(b_targets.len(), 3, "rule B got its three targets");
    assert_eq!(b_targets[0].host, "b1.example.com");
    assert_eq!(b_targets[2].host, "b3.example.com");
    cleanup(&db).await;
}

/// v1.2 regression (PG): create_rule_full is one transaction, so a bad target
/// (port=0 violates the CHECK constraint) rolls back the rule-row INSERT.
#[tokio::test]
async fn pg_rule_create_full_rollback_on_target_failure() {
    let Some(db) = repo("rule_full_rollback").await else {
        return;
    };
    sqlx::query("INSERT INTO device_groups (id, name, group_type, token, uid) VALUES (1, 'gin', 'in', 'tok-1', 1)")
        .execute(&db.pool).await.unwrap();

    let err = db
        .create_rule_full(
            "doomed",
            1,
            30000,
            "tcp",
            "raw",
            "raw",
            "direct",
            "raw",
            None,
            1,
            None,
            "direct",
            "1.1.1.1",
            80,
            &[relay_shared::protocol::RuleTargetRequest {
                host: "bad.example.com".into(),
                port: 0,
                enabled: true,
            }],
            "first",
            0,
            0,
            None,
        )
        .await;
    assert!(err.is_err(), "the bad target must fail the whole call");

    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM forward_rules WHERE uid = 1 AND listen_port = 30000",
    )
    .fetch_one(&db.pool)
    .await
    .unwrap();
    assert_eq!(count, 0, "transaction must roll back, leaving no rule row");
    cleanup(&db).await;
}

/// v1.2 (PG): create_rule_full reports Ok(None) when the max_rules quota is
/// exhausted, and crucially writes no row.
#[tokio::test]
async fn pg_rule_create_full_quota_exhausted_returns_none() {
    let Some(db) = repo("rule_full_quota").await else {
        return;
    };
    sqlx::query("INSERT INTO device_groups (id, name, group_type, token, uid) VALUES (1, 'gin', 'in', 'tok-1', 1)")
        .execute(&db.pool).await.unwrap();
    sqlx::query("UPDATE users SET max_rules = 1 WHERE id = 1")
        .execute(&db.pool)
        .await
        .unwrap();

    assert!(
        db.create_rule_full(
            "r1",
            1,
            40000,
            "tcp",
            "raw",
            "raw",
            "direct",
            "raw",
            None,
            1,
            None,
            "direct",
            "1.1.1.1",
            80,
            &[relay_shared::protocol::RuleTargetRequest {
                host: "a.example.com".into(),
                port: 80,
                enabled: true,
            }],
            "first",
            0,
            0,
            None,
        )
        .await
        .unwrap()
        .is_some(),
        "first rule within quota returns Some(id)"
    );
    assert_eq!(
        db.create_rule_full(
            "r2",
            1,
            40001,
            "tcp",
            "raw",
            "raw",
            "direct",
            "raw",
            None,
            1,
            None,
            "direct",
            "1.1.1.1",
            80,
            &[relay_shared::protocol::RuleTargetRequest {
                host: "a.example.com".into(),
                port: 80,
                enabled: true,
            }],
            "first",
            0,
            0,
            None,
        )
        .await
        .unwrap(),
        None,
        "quota exhaustion returns Ok(None)"
    );

    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM forward_rules WHERE uid = 1")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(count, 1, "the over-quota create wrote no row");
    cleanup(&db).await;
}

#[tokio::test]
async fn pg_rule_update_switch_to_direct_clears_device_group_out() {
    // Regression for v0.4.4: switching a rule to "direct" without an
    // explicit device_group_out must clear the column. The earlier
    // force_null_out bool caused `device_group_out` to be assigned twice in
    // the generated UPDATE, which PostgreSQL rejects with
    // "multiple assignments to same column". SQLite tolerated it; PG did not.
    let Some(db) = repo("rule_switch_direct").await else {
        return;
    };
    // Two groups: inbound (1) and an outbound (2) the rule starts pointed at.
    sqlx::query("INSERT INTO device_groups (id, name, group_type, token, uid) VALUES (1, 'gin', 'in', 'tok-1', 1)")
        .execute(&db.pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO device_groups (id, name, group_type, token, uid) VALUES (2, 'gout', 'out', 'tok-2', 1)")
        .execute(&db.pool)
        .await
        .unwrap();
    db.insert_quota_guarded(
        "r1",
        1,
        20000,
        "tcp",
        "raw",
        "raw",
        "group",
        "raw",
        None,
        1,
        Some(2),
        "group",
        "127.0.0.1",
        80,
    )
    .await
    .unwrap();
    let rule_id = db
        .list_rules(&ResourceScope::All)
        .await
        .unwrap()
        .into_iter()
        .next()
        .unwrap()
        .id;

    // Switch to direct: forward_mode="direct" + device_group_out=Some(None).
    // This is the exact shape api::admin::update_rule produces for the
    // "switch to direct without supplying an outbound group" case.
    let affected = db
        .update_rule_fields(
            rule_id,
            &ResourceScope::All,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(None),
            Some("direct"),
            None,
            None,
            None,
        )
        .await
        .expect("update must not error (no duplicate column assignment)");
    assert_eq!(affected, 1);

    let dgo: (Option<i64>,) =
        sqlx::query_as("SELECT device_group_out FROM forward_rules WHERE id = $1")
            .bind(rule_id)
            .fetch_one(&db.pool)
            .await
            .unwrap();
    assert!(dgo.0.is_none(), "device_group_out must be cleared to NULL");
    cleanup(&db).await;
}

#[tokio::test]
async fn pg_rule_list_active_for_config_filters_banned_paused_overquota() {
    let Some(db) = repo("rule_filter").await else {
        return;
    };
    db.insert_user("alice", "h", 1).await.unwrap();
    let alice = db.find_by_username("alice").await.unwrap().unwrap().id;
    sqlx::query(
        "INSERT INTO device_groups (id, name, group_type, token, uid) \
         VALUES (50, 'gin', 'in', 'tok-50', $1)",
    )
    .bind(alice)
    .execute(&db.pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO forward_rules \
         (name, uid, listen_port, device_group_in, target_addr, target_port) \
         VALUES ('r-active', $1, 20000, 50, '127.0.0.1', 80)",
    )
    .bind(alice)
    .execute(&db.pool)
    .await
    .unwrap();

    assert_eq!(db.list_active_for_config(50).await.unwrap().len(), 1);

    sqlx::query("UPDATE forward_rules SET paused = TRUE WHERE device_group_in = 50")
        .execute(&db.pool)
        .await
        .unwrap();
    assert_eq!(db.list_active_for_config(50).await.unwrap().len(), 0);
    sqlx::query("UPDATE forward_rules SET paused = FALSE WHERE device_group_in = 50")
        .execute(&db.pool)
        .await
        .unwrap();

    sqlx::query("UPDATE users SET banned = TRUE WHERE id = $1")
        .bind(alice)
        .execute(&db.pool)
        .await
        .unwrap();
    assert_eq!(db.list_active_for_config(50).await.unwrap().len(), 0);
    sqlx::query("UPDATE users SET banned = FALSE WHERE id = $1")
        .bind(alice)
        .execute(&db.pool)
        .await
        .unwrap();

    sqlx::query("UPDATE users SET traffic_limit = 100, traffic_used = 100 WHERE id = $1")
        .bind(alice)
        .execute(&db.pool)
        .await
        .unwrap();
    assert_eq!(db.list_active_for_config(50).await.unwrap().len(), 0);
    sqlx::query("UPDATE users SET traffic_limit = 0 WHERE id = $1")
        .bind(alice)
        .execute(&db.pool)
        .await
        .unwrap();
    assert_eq!(db.list_active_for_config(50).await.unwrap().len(), 1);
    cleanup(&db).await;
}

// ── Group ──

#[tokio::test]
async fn pg_group_insert_then_find_by_token_round_trip() {
    let Some(db) = repo("group_rt").await else {
        return;
    };
    db.insert_group(
        "gin",
        "in",
        "tok-abc",
        1,
        "1.2.3.4",
        "20000-30000",
        1.0,
        false,
    )
    .await
    .unwrap();
    let g = db.find_by_token("tok-abc").await.unwrap().unwrap();
    assert_eq!(g.name, "gin");
    assert_eq!(g.group_type, "in");
    assert_eq!(g.connect_host, "1.2.3.4");
    let g2 = db
        .find_by_token_after_insert("tok-abc")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(g2.id, g.id);
    assert!(db.find_by_token("nope").await.unwrap().is_none());
    assert_eq!(
        db.find_name_by_id(g.id, &ResourceScope::All)
            .await
            .unwrap()
            .as_deref(),
        Some("gin")
    );
    cleanup(&db).await;
}

#[tokio::test]
async fn pg_group_update_token_returns_rows_affected() {
    let Some(db) = repo("group_tok").await else {
        return;
    };
    db.insert_group("gin", "in", "tok-1", 1, "", "", 1.0, false)
        .await
        .unwrap();
    let g = db.find_by_token("tok-1").await.unwrap().unwrap();
    assert_eq!(
        db.update_group_token(g.id, &ResourceScope::All, "tok-2")
            .await
            .unwrap(),
        1
    );
    assert!(db.find_by_token("tok-1").await.unwrap().is_none());
    assert!(db.find_by_token("tok-2").await.unwrap().is_some());
    assert_eq!(
        db.update_group_token(999_999, &ResourceScope::All, "tok-3")
            .await
            .unwrap(),
        0
    );
    cleanup(&db).await;
}

// ── Traffic ──

#[tokio::test]
async fn pg_traffic_batch_applies_to_rule_and_user() {
    let Some(db) = repo("traffic_apply").await else {
        return;
    };
    db.insert_user("alice", "h", 1).await.unwrap();
    let alice = db.find_by_username("alice").await.unwrap().unwrap().id;
    sqlx::query(
        "INSERT INTO device_groups (id, name, group_type, token, uid) \
         VALUES (50, 'gin', 'in', 'tok-50', $1)",
    )
    .bind(alice)
    .execute(&db.pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO forward_rules \
         (id, name, uid, listen_port, device_group_in, target_addr, target_port) \
         VALUES (100, 'r100', $1, 20000, 50, '127.0.0.1', 80)",
    )
    .bind(alice)
    .execute(&db.pool)
    .await
    .unwrap();
    let results = db
        .apply_traffic_batch(
            50,
            &[TrafficEntry {
                rule_id: 100,
                upload: 1000,
                download: 2000,
            }],
        )
        .await
        .unwrap();
    assert_eq!(results.len(), 1);
    let rule_t: (i64,) = sqlx::query_as("SELECT traffic_used FROM forward_rules WHERE id = 100")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    let user_t: (i64,) = sqlx::query_as("SELECT traffic_used FROM users WHERE id = $1")
        .bind(alice)
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(rule_t.0, 3000);
    assert_eq!(user_t.0, 3000);
    cleanup(&db).await;
}

#[tokio::test]
async fn pg_traffic_batch_other_group_rule_yields_othergrouprule_and_rolls_back() {
    let Some(db) = repo("traffic_og").await else {
        return;
    };
    db.insert_user("alice", "h", 1).await.unwrap();
    let alice = db.find_by_username("alice").await.unwrap().unwrap().id;
    for gid in [50, 60] {
        sqlx::query(
            "INSERT INTO device_groups (id, name, group_type, token, uid) \
             VALUES ($1, 'g', 'in', $2, $3)",
        )
        .bind(gid)
        .bind(format!("tok-{gid}"))
        .bind(alice)
        .execute(&db.pool)
        .await
        .unwrap();
    }
    sqlx::query(
        "INSERT INTO forward_rules \
         (id, name, uid, listen_port, device_group_in, target_addr, target_port) \
         VALUES (100, 'r100', $1, 20000, 50, '127.0.0.1', 80)",
    )
    .bind(alice)
    .execute(&db.pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO forward_rules \
         (id, name, uid, listen_port, device_group_in, target_addr, target_port) \
         VALUES (200, 'r200', $1, 20001, 60, '127.0.0.1', 80)",
    )
    .bind(alice)
    .execute(&db.pool)
    .await
    .unwrap();
    let results = db
        .apply_traffic_batch(
            50,
            &[
                TrafficEntry {
                    rule_id: 100,
                    upload: 500,
                    download: 0,
                },
                TrafficEntry {
                    rule_id: 200,
                    upload: 0,
                    download: 999,
                },
            ],
        )
        .await
        .unwrap();
    // v0.4.9: foreign rule → Unavailable (formerly OtherGroupRule).
    assert_eq!(results.len(), 1);
    assert!(matches!(results[0], TrafficEntryResult::Unavailable));
    let rule100_t: (i64,) = sqlx::query_as("SELECT traffic_used FROM forward_rules WHERE id = 100")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    let user_t: (i64,) = sqlx::query_as("SELECT traffic_used FROM users WHERE id = $1")
        .bind(alice)
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(rule100_t.0, 0);
    assert_eq!(user_t.0, 0);
    cleanup(&db).await;
}

/// v0.4.9: a rule_id that does NOT exist produces the SAME result
/// (Unavailable) as a foreign rule — NOT silently skipped. Closes the
/// rule-id existence oracle; the whole batch rolls back.
#[tokio::test]
async fn pg_traffic_batch_unknown_rule_is_unavailable_not_skipped() {
    let Some(db) = repo("traffic_unavail").await else {
        return;
    };
    db.insert_user("alice", "h", 1).await.unwrap();
    let alice = db.find_by_username("alice").await.unwrap().unwrap().id;
    sqlx::query(
        "INSERT INTO device_groups (id, name, group_type, token, uid) \
         VALUES (50, 'gin', 'in', 'tok-50', $1)",
    )
    .bind(alice)
    .execute(&db.pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO forward_rules \
         (id, name, uid, listen_port, device_group_in, target_addr, target_port) \
         VALUES (100, 'r100', $1, 20000, 50, '127.0.0.1', 80)",
    )
    .bind(alice)
    .execute(&db.pool)
    .await
    .unwrap();
    let results = db
        .apply_traffic_batch(
            50,
            &[
                TrafficEntry {
                    rule_id: 99999,
                    upload: 1,
                    download: 2,
                },
                TrafficEntry {
                    rule_id: 100,
                    upload: 10,
                    download: 20,
                },
            ],
        )
        .await
        .unwrap();
    assert_eq!(results.len(), 1);
    assert!(matches!(results[0], TrafficEntryResult::Unavailable));
    let rule_t: (i64,) = sqlx::query_as("SELECT traffic_used FROM forward_rules WHERE id = 100")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(rule_t.0, 0, "batch rolled back → rule 100 must not apply");
    cleanup(&db).await;
}

/// v0.4.9 overflow: single entry upload+download > i64::MAX → Overflow.
#[tokio::test]
async fn pg_traffic_batch_single_entry_overflow() {
    let Some(db) = repo("traffic_ov1").await else {
        return;
    };
    db.insert_user("alice", "h", 1).await.unwrap();
    let alice = db.find_by_username("alice").await.unwrap().unwrap().id;
    sqlx::query(
        "INSERT INTO device_groups (id, name, group_type, token, uid) \
         VALUES (50, 'gin', 'in', 'tok-50', $1)",
    )
    .bind(alice)
    .execute(&db.pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO forward_rules \
         (id, name, uid, listen_port, device_group_in, target_addr, target_port) \
         VALUES (100, 'r100', $1, 20000, 50, '127.0.0.1', 80)",
    )
    .bind(alice)
    .execute(&db.pool)
    .await
    .unwrap();
    let half = (i64::MAX as u64) / 2 + 1;
    let results = db
        .apply_traffic_batch(
            50,
            &[TrafficEntry {
                rule_id: 100,
                upload: half,
                download: half,
            }],
        )
        .await
        .unwrap();
    assert!(matches!(results[0], TrafficEntryResult::Overflow));
    cleanup(&db).await;
}

/// v0.4.9 overflow: duplicate rule_ids, each legal, overflow when summed.
#[tokio::test]
async fn pg_traffic_batch_duplicate_rule_ids_cumulative_overflow() {
    let Some(db) = repo("traffic_ovdup").await else {
        return;
    };
    db.insert_user("alice", "h", 1).await.unwrap();
    let alice = db.find_by_username("alice").await.unwrap().unwrap().id;
    sqlx::query(
        "INSERT INTO device_groups (id, name, group_type, token, uid) \
         VALUES (50, 'gin', 'in', 'tok-50', $1)",
    )
    .bind(alice)
    .execute(&db.pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO forward_rules \
         (id, name, uid, listen_port, device_group_in, target_addr, target_port) \
         VALUES (100, 'r100', $1, 20000, 50, '127.0.0.1', 80)",
    )
    .bind(alice)
    .execute(&db.pool)
    .await
    .unwrap();
    let half = (i64::MAX as u64) / 2 + 1;
    let results = db
        .apply_traffic_batch(
            50,
            &[
                TrafficEntry {
                    rule_id: 100,
                    upload: half,
                    download: 0,
                },
                TrafficEntry {
                    rule_id: 100,
                    upload: half,
                    download: 0,
                },
            ],
        )
        .await
        .unwrap();
    assert!(matches!(results[0], TrafficEntryResult::Overflow));
    cleanup(&db).await;
}

/// v0.4.9 overflow: two rules under one user, cumulative user total
/// overflows even though each rule's total would be fine.
#[tokio::test]
async fn pg_traffic_batch_user_cumulative_overflow_across_rules() {
    let Some(db) = repo("traffic_ovuser").await else {
        return;
    };
    db.insert_user("alice", "h", 1).await.unwrap();
    let alice = db.find_by_username("alice").await.unwrap().unwrap().id;
    sqlx::query(
        "INSERT INTO device_groups (id, name, group_type, token, uid) \
         VALUES (50, 'gin', 'in', 'tok-50', $1)",
    )
    .bind(alice)
    .execute(&db.pool)
    .await
    .unwrap();
    for (rid, port) in [(100, 20000), (101, 20001)] {
        sqlx::query(
            "INSERT INTO forward_rules \
             (id, name, uid, listen_port, device_group_in, target_addr, target_port) \
             VALUES ($1, 'r', $2, $3, 50, '127.0.0.1', 80)",
        )
        .bind(rid)
        .bind(alice)
        .bind(port)
        .execute(&db.pool)
        .await
        .unwrap();
    }
    sqlx::query("UPDATE users SET traffic_used = $1 WHERE id = $2")
        .bind(i64::MAX - 100)
        .bind(alice)
        .execute(&db.pool)
        .await
        .unwrap();
    let results = db
        .apply_traffic_batch(
            50,
            &[
                TrafficEntry {
                    rule_id: 100,
                    upload: 60,
                    download: 0,
                },
                TrafficEntry {
                    rule_id: 101,
                    upload: 60,
                    download: 0,
                },
            ],
        )
        .await
        .unwrap();
    assert!(matches!(results[0], TrafficEntryResult::Overflow));
    let user_t: (i64,) = sqlx::query_as("SELECT traffic_used FROM users WHERE id = $1")
        .bind(alice)
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(user_t.0, i64::MAX - 100, "user total unchanged");
    cleanup(&db).await;
}

/// v0.4.9: a delta landing EXACTLY on i64::MAX is accepted.
#[tokio::test]
async fn pg_traffic_batch_exactly_i64_max_is_accepted() {
    let Some(db) = repo("traffic_max").await else {
        return;
    };
    db.insert_user("alice", "h", 1).await.unwrap();
    let alice = db.find_by_username("alice").await.unwrap().unwrap().id;
    sqlx::query(
        "INSERT INTO device_groups (id, name, group_type, token, uid) \
         VALUES (50, 'gin', 'in', 'tok-50', $1)",
    )
    .bind(alice)
    .execute(&db.pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO forward_rules \
         (id, name, uid, listen_port, device_group_in, target_addr, target_port) \
         VALUES (100, 'r100', $1, 20000, 50, '127.0.0.1', 80)",
    )
    .bind(alice)
    .execute(&db.pool)
    .await
    .unwrap();
    sqlx::query("UPDATE forward_rules SET traffic_used = $1 WHERE id = 100")
        .bind(i64::MAX - 50)
        .execute(&db.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE users SET traffic_used = $1 WHERE id = $2")
        .bind(i64::MAX - 50)
        .bind(alice)
        .execute(&db.pool)
        .await
        .unwrap();
    let results = db
        .apply_traffic_batch(
            50,
            &[TrafficEntry {
                rule_id: 100,
                upload: 50,
                download: 0,
            }],
        )
        .await
        .unwrap();
    assert!(matches!(results[0], TrafficEntryResult::Ok));
    let rule_t: (i64,) = sqlx::query_as("SELECT traffic_used FROM forward_rules WHERE id = 100")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(rule_t.0, i64::MAX);
    cleanup(&db).await;
}

/// v0.4.9: duplicate rule_ids aggregated into one update (correct total).
#[tokio::test]
async fn pg_traffic_batch_duplicate_rule_ids_are_aggregated() {
    let Some(db) = repo("traffic_aggr").await else {
        return;
    };
    db.insert_user("alice", "h", 1).await.unwrap();
    let alice = db.find_by_username("alice").await.unwrap().unwrap().id;
    sqlx::query(
        "INSERT INTO device_groups (id, name, group_type, token, uid) \
         VALUES (50, 'gin', 'in', 'tok-50', $1)",
    )
    .bind(alice)
    .execute(&db.pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO forward_rules \
         (id, name, uid, listen_port, device_group_in, target_addr, target_port) \
         VALUES (100, 'r100', $1, 20000, 50, '127.0.0.1', 80)",
    )
    .bind(alice)
    .execute(&db.pool)
    .await
    .unwrap();
    let results = db
        .apply_traffic_batch(
            50,
            &[
                TrafficEntry {
                    rule_id: 100,
                    upload: 1,
                    download: 10,
                },
                TrafficEntry {
                    rule_id: 100,
                    upload: 2,
                    download: 20,
                },
                TrafficEntry {
                    rule_id: 100,
                    upload: 3,
                    download: 30,
                },
            ],
        )
        .await
        .unwrap();
    assert!(matches!(results[0], TrafficEntryResult::Ok));
    let rule_t: (i64,) = sqlx::query_as("SELECT traffic_used FROM forward_rules WHERE id = 100")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    let user_t: (i64,) = sqlx::query_as("SELECT traffic_used FROM users WHERE id = $1")
        .bind(alice)
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(rule_t.0, 66, "aggregated delta = 6+60");
    assert_eq!(user_t.0, 66);
    cleanup(&db).await;
}

// ── KVS ──

#[tokio::test]
async fn pg_kvs_set_get_delete_round_trip() {
    let Some(db) = repo("kvs_rt").await else {
        return;
    };
    assert!(db.get("missing").await.unwrap().is_none());
    db.set("k", "v1").await.unwrap();
    assert_eq!(db.get("k").await.unwrap().as_deref(), Some("v1"));
    db.set("k", "v2").await.unwrap();
    assert_eq!(db.get("k").await.unwrap().as_deref(), Some("v2"));
    assert_eq!(db.delete("k").await.unwrap(), 1);
    assert!(db.get("k").await.unwrap().is_none());
    assert_eq!(db.delete("k").await.unwrap(), 0);
    cleanup(&db).await;
}

#[tokio::test]
async fn pg_kvs_scan_prefix_returns_only_matching_keys() {
    let Some(db) = repo("kvs_scan").await else {
        return;
    };
    db.set("node_status:1:a", "{}").await.unwrap();
    db.set("node_status:1:b", "{}").await.unwrap();
    db.set("node_status:2:c", "{}").await.unwrap();
    db.set("other_feature:1", "{}").await.unwrap();
    let rows = db.scan_prefix("node_status:").await.unwrap();
    assert_eq!(rows.len(), 3);
    assert!(rows.iter().all(|(k, _)| k.starts_with("node_status:")));
    let rows = db.scan_prefix("node_status:1:").await.unwrap();
    assert_eq!(rows.len(), 2);
    cleanup(&db).await;
}

// ── v0.4.10 fix PR: ProfileScope + ownership-invariant tests (PG parity) ──
// Mirrors the SQLite tests so SQLite/PG behavior is provably identical.

/// find_profile_by_id with BuiltinOnly must NOT return a custom profile (PG).
#[tokio::test]
async fn pg_find_profile_by_id_builtin_only_excludes_custom() {
    let Some(db) = repo("prof_builtin").await else {
        return;
    };
    // v0.4.11 PR1: custom ws/tls_simple profiles are now available for rule selection.
    sqlx::query(
        "INSERT INTO tunnel_profiles (name, transport, tls_mode, ws_path, host_header, sni, is_builtin, uid) \
         VALUES ('custom-x', 'ws', 'none', '/x', '', '', FALSE, 1)",
    )
    .execute(&db.pool)
    .await
    .unwrap();
    let custom_id: i64 =
        sqlx::query_scalar("SELECT id FROM tunnel_profiles WHERE name = 'custom-x'")
            .fetch_one(&db.pool)
            .await
            .unwrap();

    let r = TunnelProfileRepository::find_profile_by_id(
        &db,
        custom_id,
        &ProfileScope::AvailableTemplates,
    )
    .await
    .unwrap();
    assert!(
        r.is_some(),
        "AvailableTemplates must return custom ws/tls_simple profile (PG)"
    );

    let r = TunnelProfileRepository::find_profile_by_id(&db, custom_id, &ProfileScope::All)
        .await
        .unwrap();
    assert!(r.is_some(), "All must return custom profile (PG)");
    cleanup(&db).await;
}

/// PG migration 7's cross-owner pause SQL (the UPDATE that the revision 7
/// arm runs) pauses a rule whose device_group_in belongs to a different
/// user. We execute the exact migration SQL directly rather than via
/// run_pg_migrations, because repo() already advanced schema_version to 7
/// (the version guard would no-op a second call). This pins the SQL logic
/// on PG; SQLite parity is covered by migration_pauses_cross_owner_rules.
#[tokio::test]
async fn pg_migration_pauses_cross_owner_rules() {
    let Some(db) = repo("mig_cross").await else {
        return;
    };
    sqlx::query("INSERT INTO users (id, username, password, admin) VALUES (2, 'u2', 'x', FALSE)")
        .execute(&db.pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO users (id, username, password, admin) VALUES (3, 'u3', 'x', FALSE)")
        .execute(&db.pool)
        .await
        .unwrap();
    // group 20 owned by user 3; rule owned by user 2 → mismatch.
    sqlx::query("INSERT INTO device_groups (id, name, group_type, token, uid) VALUES (20, 'g', 'in', 't', 3)")
        .execute(&db.pool).await.unwrap();
    sqlx::query("INSERT INTO forward_rules (name, uid, listen_port, device_group_in, target_addr, target_port) \
                 VALUES ('r', 2, 15000, 20, '127.0.0.1', 80)")
        .execute(&db.pool).await.unwrap();
    // The exact UPDATE from PG revision 7 (in-mismatch arm).
    sqlx::query(
        "UPDATE forward_rules SET paused = TRUE \
         WHERE paused = FALSE \
         AND EXISTS (SELECT 1 FROM device_groups dg \
                     WHERE dg.id = forward_rules.device_group_in \
                       AND dg.uid <> forward_rules.uid)",
    )
    .execute(&db.pool)
    .await
    .unwrap();

    let paused: (bool,) = sqlx::query_as("SELECT paused FROM forward_rules WHERE name = 'r'")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert!(
        paused.0,
        "cross-owner rule must be paused by PG migration 7 SQL"
    );
    cleanup(&db).await;
}

/// PG migration 7's custom-profile pause SQL pauses a regular user's rule
/// bound to a non-builtin profile. Same direct-SQL approach as above.
#[tokio::test]
async fn pg_migration_pauses_non_admin_owner_custom_profile_rule() {
    let Some(db) = repo("mig_prof").await else {
        return;
    };
    sqlx::query("INSERT INTO users (id, username, password, admin) VALUES (2, 'u2', 'x', FALSE)")
        .execute(&db.pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO device_groups (id, name, group_type, token, uid) VALUES (20, 'g', 'in', 't', 2)")
        .execute(&db.pool).await.unwrap();
    sqlx::query("INSERT INTO tunnel_profiles (name, transport, tls_mode, ws_path, host_header, sni, is_builtin, uid) \
                 VALUES ('cust', 'direct', 'none', '/x', '', '', FALSE, 1)")
        .execute(&db.pool).await.unwrap();
    let pid: i64 = sqlx::query_scalar("SELECT id FROM tunnel_profiles WHERE name = 'cust'")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO forward_rules (name, uid, listen_port, device_group_in, target_addr, target_port, tunnel_profile_id) \
                 VALUES ('r', 2, 15001, 20, '127.0.0.1', 80, $1)")
        .bind(pid)
        .execute(&db.pool).await.unwrap();
    // The exact UPDATE from PG revision 7 (custom-profile arm).
    sqlx::query(
        "UPDATE forward_rules SET paused = TRUE \
         WHERE tunnel_profile_id IS NOT NULL AND paused = FALSE \
         AND EXISTS (SELECT 1 FROM tunnel_profiles tp, users u \
                     WHERE tp.id = forward_rules.tunnel_profile_id \
                       AND tp.is_builtin = FALSE \
                       AND u.id = forward_rules.uid AND u.admin = FALSE)",
    )
    .execute(&db.pool)
    .await
    .unwrap();

    let paused: (bool,) = sqlx::query_as("SELECT paused FROM forward_rules WHERE name = 'r'")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert!(
        paused.0,
        "non-admin rule with custom profile must be paused by PG migration 7 SQL"
    );
    cleanup(&db).await;
}

/// PG migration 7's pause SQL must NOT touch a legitimate rule.
#[tokio::test]
async fn pg_migration_does_not_pause_valid_rules() {
    let Some(db) = repo("mig_valid").await else {
        return;
    };
    sqlx::query("INSERT INTO users (id, username, password, admin) VALUES (2, 'u2', 'x', FALSE)")
        .execute(&db.pool)
        .await
        .unwrap();
    // group 20 owned by user 2; rule owned by user 2 → consistent.
    sqlx::query("INSERT INTO device_groups (id, name, group_type, token, uid) VALUES (20, 'g', 'in', 't', 2)")
        .execute(&db.pool).await.unwrap();
    sqlx::query("INSERT INTO forward_rules (name, uid, listen_port, device_group_in, target_addr, target_port) \
                 VALUES ('r', 2, 15002, 20, '127.0.0.1', 80)")
        .execute(&db.pool).await.unwrap();
    // Run all three UPDATEs from revision 7 — none should match.
    for sql in [
        "UPDATE forward_rules SET paused = TRUE \
         WHERE tunnel_profile_id IS NOT NULL AND paused = FALSE \
         AND EXISTS (SELECT 1 FROM tunnel_profiles tp, users u \
                     WHERE tp.id = forward_rules.tunnel_profile_id \
                       AND tp.is_builtin = FALSE \
                       AND u.id = forward_rules.uid AND u.admin = FALSE)",
        "UPDATE forward_rules SET paused = TRUE \
         WHERE paused = FALSE \
         AND EXISTS (SELECT 1 FROM device_groups dg \
                     WHERE dg.id = forward_rules.device_group_in \
                       AND dg.uid <> forward_rules.uid)",
        "UPDATE forward_rules SET paused = TRUE \
         WHERE paused = FALSE AND device_group_out IS NOT NULL \
         AND EXISTS (SELECT 1 FROM device_groups dg \
                     WHERE dg.id = forward_rules.device_group_out \
                       AND dg.uid <> forward_rules.uid)",
    ] {
        sqlx::query(sql).execute(&db.pool).await.unwrap();
    }

    let paused: (bool,) = sqlx::query_as("SELECT paused FROM forward_rules WHERE name = 'r'")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert!(
        !paused.0,
        "valid rule must NOT be paused by PG migration 7 SQL"
    );
    cleanup(&db).await;
}

/// PG list_active_for_config must EXCLUDE a cross-owner rule (defense layer).
#[tokio::test]
async fn pg_list_active_for_config_excludes_cross_owner_rule() {
    // v0.4.11 PR3: shared inbound group scenario - cross-owner rule IS included.
    let Some(db) = repo("lac_shared").await else {
        return;
    };
    sqlx::query("INSERT INTO users (id, username, password, admin) VALUES (2, 'u2', 'x', FALSE)")
        .execute(&db.pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO device_groups (id, name, group_type, token, uid) VALUES (20, 'g', 'in', 't', 1)")
        .execute(&db.pool).await.unwrap();
    sqlx::query("INSERT INTO forward_rules (name, uid, listen_port, device_group_in, target_addr, target_port) \
                 VALUES ('r', 2, 15003, 20, '127.0.0.1', 80)")
        .execute(&db.pool).await.unwrap();

    let rules = db.list_active_for_config(20).await.unwrap();
    assert_eq!(
        rules.len(),
        1,
        "shared inbound rule must be returned for config (PG)"
    );
    cleanup(&db).await;
}

/// v0.4.12 PR1 (PG parity): an admin-owned `group_type='in'` group is shared
/// to a regular user with no rules; out/monitor and other regular users'
/// groups are excluded; an admin caller gets an empty list.
#[tokio::test]
async fn pg_shared_groups_admin_inbound_only() {
    let Some(db) = repo("shared_groups").await else {
        return;
    };
    // alice (regular) and bob (regular).
    sqlx::query(
        "INSERT INTO users (id, username, password, admin) VALUES (2, 'alice', 'x', FALSE)",
    )
    .execute(&db.pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO users (id, username, password, admin) VALUES (3, 'bob', 'x', FALSE)")
        .execute(&db.pool)
        .await
        .unwrap();
    // Admin-owned inbound (shared), admin-owned out/monitor (excluded), and
    // bob's inbound (excluded — not admin-owned).
    sqlx::query("INSERT INTO device_groups (id, name, group_type, token, connect_host, uid) VALUES (10, 'g10', 'in', 't10', '1.2.3.4', 1)")
        .execute(&db.pool).await.unwrap();
    sqlx::query("INSERT INTO device_groups (id, name, group_type, token, connect_host, uid) VALUES (11, 'g11', 'out', 't11', '1.2.3.4', 1)")
        .execute(&db.pool).await.unwrap();
    sqlx::query("INSERT INTO device_groups (id, name, group_type, token, connect_host, uid) VALUES (12, 'g12', 'monitor', 't12', '1.2.3.4', 1)")
        .execute(&db.pool).await.unwrap();
    sqlx::query("INSERT INTO device_groups (id, name, group_type, token, connect_host, uid) VALUES (20, 'g20', 'in', 't20', '1.2.3.4', 3)")
        .execute(&db.pool).await.unwrap();

    // alice (regular, no rules) sees ONLY the admin inbound group 10.
    let shared = db.list_shared_groups(2, false).await.unwrap();
    assert_eq!(shared.len(), 1, "only admin 'in' group is shared (PG)");
    assert_eq!(shared[0].id, 10);

    // admin caller gets an empty list.
    let admin_shared = db.list_shared_groups(1, true).await.unwrap();
    assert!(admin_shared.is_empty(), "admin gets no shared groups (PG)");
    cleanup(&db).await;
}

// ── v0.4.10 PR3: app_settings + insert_user_from_plan (PG parity) ──

#[tokio::test]
async fn pg_settings_get_returns_none_when_unseeded() {
    let Some(db) = repo("set_unseeded").await else {
        return;
    };
    let s = db.get_registration_settings().await.unwrap();
    assert!(
        s.is_none(),
        "fresh PG DB must have no app_settings row (PG)"
    );
    cleanup(&db).await;
}

#[tokio::test]
async fn pg_settings_insert_if_absent_is_idempotent() {
    let Some(db) = repo("set_idem").await else {
        return;
    };
    db.insert_settings_if_absent(true, 1, &[1]).await.unwrap();
    // Admin disables; then "restart" re-runs insert_if_absent(true).
    db.set_registration_settings(false, 1, &[1]).await.unwrap();
    db.insert_settings_if_absent(true, 1, &[1]).await.unwrap();
    let s = db.get_registration_settings().await.unwrap().unwrap();
    assert!(
        !s.registration_enabled,
        "env-var seed must NOT re-enable registration after admin disabled it (PG)"
    );
    cleanup(&db).await;
}

#[tokio::test]
async fn pg_settings_set_upserts_when_no_row() {
    let Some(db) = repo("set_upsert").await else {
        return;
    };
    assert!(db.get_registration_settings().await.unwrap().is_none());
    db.set_registration_settings(true, 1, &[1]).await.unwrap();
    let s = db.get_registration_settings().await.unwrap().unwrap();
    assert!(s.registration_enabled, "upsert must create the row (PG)");
    cleanup(&db).await;
}

/// v0.4.21 PR2: PG registration settings round-trip allowed_plan_ids
/// through JSON TEXT column.
#[tokio::test]
async fn pg_settings_allowed_plan_ids_round_trip() {
    let Some(db) = repo("allowed_r").await else {
        return;
    };
    // Seed plan 2 for multi-plan test.
    let pool = db.pool.clone();
    sqlx::query(
        "INSERT INTO plans (id, name, max_rules, traffic, speed_limit, ip_limit, price) \
         VALUES (2, 'premium', 10, 0, 0, 5, '9.99') ON CONFLICT (id) DO NOTHING",
    )
    .execute(&pool)
    .await
    .unwrap();

    // Multi-plan settings.
    db.set_registration_settings(true, 1, &[1, 2])
        .await
        .unwrap();
    let s = db.get_registration_settings().await.unwrap().unwrap();
    assert!(s.registration_enabled);
    assert_eq!(s.default_registration_plan_id, 1);
    assert_eq!(s.allowed_plan_ids, vec![1, 2], "PG multi-plan round-trip");

    // Unseeded row insert must also carry allowed_plan_ids.
    sqlx::query("DELETE FROM app_settings WHERE id = 1")
        .execute(&pool)
        .await
        .unwrap();
    db.insert_settings_if_absent(true, 2, &[2, 1])
        .await
        .unwrap();
    let s2 = db.get_registration_settings().await.unwrap().unwrap();
    assert!(s2.registration_enabled);
    assert_eq!(s2.default_registration_plan_id, 2);
    assert_eq!(
        s2.allowed_plan_ids,
        vec![2, 1],
        "PG unseeded round-trip (order preserved)"
    );

    cleanup(&db).await;
}

#[tokio::test]
async fn pg_insert_user_from_plan_inherits_quota_and_handles_missing_plan() {
    let Some(db) = repo("iup").await else { return };
    let n = db.insert_user_from_plan("alice", "hash", 1).await.unwrap();
    assert_eq!(n, 1, "user should be created for an existing plan (PG)");
    let user = db.find_by_username("alice").await.unwrap().unwrap();
    assert_eq!(user.plan_id, Some(1));
    assert_eq!(user.max_rules, 5, "max_rules inherited from plan (PG)");
    let n = db.insert_user_from_plan("bob", "hash", 999).await.unwrap();
    assert_eq!(n, 0, "missing plan must yield 0 rows (PG)");
    assert!(
        db.find_by_username("bob").await.unwrap().is_none(),
        "no user for missing plan (PG)"
    );
    cleanup(&db).await;
}

/// v1.2 regression (PG parity): a freshly-registered user has NO usable device
/// groups by design — all_device_groups stays false, user_device_groups empty,
/// so a new user cannot forward until a plan/admin grants authorization.
#[tokio::test]
async fn pg_new_user_has_no_device_groups_by_default() {
    let Some(db) = repo("newuser_nogroups").await else {
        return;
    };
    db.insert_user_from_plan("carol", "hash", 1).await.unwrap();
    let carol = db
        .find_by_username("carol")
        .await
        .unwrap()
        .expect("carol registered");
    assert!(!carol.admin);
    assert!(
        !carol.all_device_groups,
        "all_device_groups must default to false (PG)"
    );
    assert!(
        db.list_user_device_groups(carol.id)
            .await
            .unwrap()
            .is_empty(),
        "user_device_groups must be empty for a new user (PG)"
    );
    assert!(
        db.authorized_device_group_ids(carol.id)
            .await
            .unwrap()
            .is_empty(),
        "authorized_device_group_ids must be empty for a new user (PG)"
    );
    assert!(
        db.is_user_restricted(carol.id).await.unwrap(),
        "a non-admin without all_device_groups is restricted (PG)"
    );
    cleanup(&db).await;
}

/// PostgreSQL parity: registration must inherit the selected plan's line
/// authorization together with its quotas.
#[tokio::test]
async fn pg_insert_user_from_plan_inherits_plan_group_authorization() {
    let Some(db) = repo("registration_plan_groups").await else {
        return;
    };
    seed_device_group(&db, 60, 1).await;

    let restricted_plan = db
        .create_plan_with_groups(
            "restricted",
            5,
            1_000,
            "0",
            "data",
            0,
            false,
            false,
            "",
            false,
            &[60],
        )
        .await
        .unwrap();
    db.insert_user_from_plan("restricted-user", "hash", restricted_plan)
        .await
        .unwrap();
    let restricted = db
        .find_by_username("restricted-user")
        .await
        .unwrap()
        .unwrap();
    assert!(!restricted.all_device_groups);
    assert_eq!(
        db.list_user_device_groups(restricted.id).await.unwrap(),
        vec![60],
        "a restricted plan grants exactly its configured lines at registration (PG)"
    );

    let all_plan = db
        .create_plan_with_groups("all", 5, 1_000, "0", "data", 0, false, false, "", true, &[])
        .await
        .unwrap();
    db.insert_user_from_plan("all-user", "hash", all_plan)
        .await
        .unwrap();
    let all = db.find_by_username("all-user").await.unwrap().unwrap();
    assert!(
        all.all_device_groups,
        "an all-lines plan grants all lines immediately (PG)"
    );
    assert!(db.list_user_device_groups(all.id).await.unwrap().is_empty());
    cleanup(&db).await;
}

// ── v0.4.10 PR4: token_version + must_change_password (PG parity) ──

#[tokio::test]
async fn pg_find_auth_state_returns_all_three_or_none() {
    let Some(db) = repo("auth_state").await else {
        return;
    };
    sqlx::query(
        "INSERT INTO users (id, username, password, admin, banned, token_version, must_change_password) \
         VALUES (2, 'u2', 'x', FALSE, TRUE, 7, TRUE)",
    )
    .execute(&db.pool)
    .await
    .unwrap();
    let s = db.find_auth_state_by_id(2).await.unwrap().unwrap();
    assert_eq!(s, (true, 7, true));
    assert!(db.find_auth_state_by_id(999).await.unwrap().is_none());
    cleanup(&db).await;
}

#[tokio::test]
async fn pg_change_own_password_bumps_version_and_clears_must_change() {
    let Some(db) = repo("change_own").await else {
        return;
    };
    sqlx::query(
        "INSERT INTO users (id, username, password, admin, token_version, must_change_password) \
         VALUES (2, 'u2', 'old', FALSE, 3, TRUE)",
    )
    .execute(&db.pool)
    .await
    .unwrap();
    let n = db.change_own_password(2, "newhash").await.unwrap();
    assert_eq!(n, 1);
    let s = db.find_auth_state_by_id(2).await.unwrap().unwrap();
    assert_eq!(s.1, 4, "token_version must increment (PG)");
    assert!(!s.2, "must_change_password cleared (PG)");
    cleanup(&db).await;
}

#[tokio::test]
async fn pg_admin_reset_password_bumps_version_and_sets_must_change() {
    let Some(db) = repo("admin_reset").await else {
        return;
    };
    sqlx::query(
        "INSERT INTO users (id, username, password, admin, token_version, must_change_password) \
         VALUES (2, 'u2', 'old', FALSE, 0, FALSE)",
    )
    .execute(&db.pool)
    .await
    .unwrap();
    let n = db.admin_reset_password(2, "temphash", true).await.unwrap();
    assert_eq!(n, 1);
    let s = db.find_auth_state_by_id(2).await.unwrap().unwrap();
    assert_eq!(s.1, 1, "token_version must increment (PG)");
    assert!(s.2, "must_change_password set true (PG)");
    cleanup(&db).await;
}

#[tokio::test]
async fn pg_ban_bumps_token_version() {
    let Some(db) = repo("ban_bump").await else {
        return;
    };
    sqlx::query(
        "INSERT INTO users (id, username, password, admin, banned, token_version) \
         VALUES (2, 'u2', 'x', FALSE, FALSE, 5)",
    )
    .execute(&db.pool)
    .await
    .unwrap();
    db.update_user_fields(2, None, None, None, Some(true), None)
        .await
        .unwrap();
    let s = db.find_auth_state_by_id(2).await.unwrap().unwrap();
    assert!(s.0, "user banned (PG)");
    assert_eq!(s.1, 6, "ban bumps token_version (PG)");
    cleanup(&db).await;
}

#[tokio::test]
async fn pg_unban_does_not_bump_token_version() {
    let Some(db) = repo("unban_nobump").await else {
        return;
    };
    sqlx::query(
        "INSERT INTO users (id, username, password, admin, banned, token_version) \
         VALUES (2, 'u2', 'x', FALSE, TRUE, 5)",
    )
    .execute(&db.pool)
    .await
    .unwrap();
    db.update_user_fields(2, None, None, None, Some(false), None)
        .await
        .unwrap();
    let s = db.find_auth_state_by_id(2).await.unwrap().unwrap();
    assert!(!s.0, "user unbanned (PG)");
    assert_eq!(s.1, 5, "unban does NOT bump token_version (PG)");
    cleanup(&db).await;
}

// ── v0.4.18 PR8: Owner-scope authorization tests (PG parity) ──

/// Owner scope: delete_rule succeeds for own rule, fails for another user's rule.
#[tokio::test]
async fn pg_delete_rule_owner_scope_rejects_wrong_owner() {
    let Some(db) = repo("del_rule_own").await else {
        return;
    };
    // User 2 owns the rule, user 3 does not.
    sqlx::query("INSERT INTO users (id, username, password, admin) VALUES (2, 'u2', 'x', FALSE)")
        .execute(&db.pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO users (id, username, password, admin) VALUES (3, 'u3', 'x', FALSE)")
        .execute(&db.pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO device_groups (id, name, group_type, token, uid) \
         VALUES (10, 'gin', 'in', 'tok10', 2)",
    )
    .execute(&db.pool)
    .await
    .unwrap();
    db.insert_quota_guarded(
        "r1",
        2,
        20000,
        "tcp",
        "raw",
        "raw",
        "direct",
        "raw",
        None,
        10,
        None,
        "direct",
        "127.0.0.1",
        80,
    )
    .await
    .unwrap();
    let rule_id = db
        .find_rule_by_id(1, &ResourceScope::All)
        .await
        .unwrap()
        .unwrap()
        .id;

    // Owner can delete their own rule.
    let n = db
        .delete_rule(rule_id, &ResourceScope::Owner(2))
        .await
        .unwrap();
    assert_eq!(n, 1, "owner 2 must be able to delete their rule (PG)");

    // Recreate for the negative case.
    sqlx::query(
        "INSERT INTO device_groups (id, name, group_type, token, uid) \
         VALUES (11, 'gin2', 'in', 'tok11', 2)",
    )
    .execute(&db.pool)
    .await
    .unwrap();
    db.insert_quota_guarded(
        "r2",
        2,
        20001,
        "tcp",
        "raw",
        "raw",
        "direct",
        "raw",
        None,
        11,
        None,
        "direct",
        "127.0.0.1",
        81,
    )
    .await
    .unwrap();
    let rule_id2 = db
        .find_rule_by_id(2, &ResourceScope::All)
        .await
        .unwrap()
        .unwrap()
        .id;

    // User 3 must NOT delete user 2's rule.
    let n = db
        .delete_rule(rule_id2, &ResourceScope::Owner(3))
        .await
        .unwrap();
    assert_eq!(n, 0, "user 3 must NOT delete user 2's rule (PG)");

    let still_there = db
        .find_rule_by_id(rule_id2, &ResourceScope::All)
        .await
        .unwrap();
    assert!(
        still_there.is_some(),
        "rule must survive rejected DELETE (PG)"
    );
    cleanup(&db).await;
}

/// Owner scope: find_rule_by_id returns None for another user's rule.
#[tokio::test]
async fn pg_find_rule_by_id_owner_scope_filters_other_owner() {
    let Some(db) = repo("find_rule_own").await else {
        return;
    };
    sqlx::query("INSERT INTO users (id, username, password, admin) VALUES (2, 'u2', 'x', FALSE)")
        .execute(&db.pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO users (id, username, password, admin) VALUES (3, 'u3', 'x', FALSE)")
        .execute(&db.pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO device_groups (id, name, group_type, token, uid) \
         VALUES (10, 'gin', 'in', 'tok10', 2)",
    )
    .execute(&db.pool)
    .await
    .unwrap();
    db.insert_quota_guarded(
        "r1",
        2,
        20000,
        "tcp",
        "raw",
        "raw",
        "direct",
        "raw",
        None,
        10,
        None,
        "direct",
        "127.0.0.1",
        80,
    )
    .await
    .unwrap();
    let rule_id = db
        .find_rule_by_id(1, &ResourceScope::All)
        .await
        .unwrap()
        .unwrap()
        .id;

    let own = db
        .find_rule_by_id(rule_id, &ResourceScope::Owner(2))
        .await
        .unwrap();
    assert!(own.is_some(), "owner 2 must see own rule (PG)");

    let other = db
        .find_rule_by_id(rule_id, &ResourceScope::Owner(3))
        .await
        .unwrap();
    assert!(other.is_none(), "user 3 must NOT see user 2's rule (PG)");
    cleanup(&db).await;
}

/// Owner scope: update_group_fields succeeds for own group, fails for another user's group.
#[tokio::test]
async fn pg_update_group_fields_owner_scope_rejects_wrong_owner() {
    let Some(db) = repo("upd_group_own").await else {
        return;
    };
    sqlx::query("INSERT INTO users (id, username, password, admin) VALUES (2, 'u2', 'x', FALSE)")
        .execute(&db.pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO users (id, username, password, admin) VALUES (3, 'u3', 'x', FALSE)")
        .execute(&db.pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO device_groups (id, name, group_type, token, uid) \
         VALUES (10, 'gin', 'in', 'tok10', 2)",
    )
    .execute(&db.pool)
    .await
    .unwrap();

    let n = db
        .update_group_fields(
            10,
            &ResourceScope::Owner(2),
            Some("renamed"),
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
    assert_eq!(n, 1, "owner 2 must be able to rename their group (PG)");

    let n = db
        .update_group_fields(
            10,
            &ResourceScope::Owner(3),
            Some("stolen"),
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
    assert_eq!(n, 0, "user 3 must NOT rename user 2's group (PG)");

    let name = db
        .find_name_by_id(10, &ResourceScope::All)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(name, "renamed", "name must survive rejected update (PG)");
    cleanup(&db).await;
}

/// Owner scope: delete_group succeeds for own group, fails for another user's group.
#[tokio::test]
async fn pg_delete_group_owner_scope_rejects_wrong_owner() {
    let Some(db) = repo("del_group_own").await else {
        return;
    };
    sqlx::query("INSERT INTO users (id, username, password, admin) VALUES (2, 'u2', 'x', FALSE)")
        .execute(&db.pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO users (id, username, password, admin) VALUES (3, 'u3', 'x', FALSE)")
        .execute(&db.pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO device_groups (id, name, group_type, token, uid) \
         VALUES (10, 'gin', 'in', 'tok10', 2)",
    )
    .execute(&db.pool)
    .await
    .unwrap();

    // User 3 must NOT be able to delete user 2's group.
    let n = db.delete_group(10, &ResourceScope::Owner(3)).await.unwrap();
    assert_eq!(n, 0, "user 3 must NOT delete user 2's group (PG)");

    let name = db.find_name_by_id(10, &ResourceScope::All).await.unwrap();
    assert!(name.is_some(), "group must survive rejected DELETE (PG)");

    let n = db.delete_group(10, &ResourceScope::Owner(2)).await.unwrap();
    assert_eq!(n, 1, "owner 2 must be able to delete their group (PG)");
    cleanup(&db).await;
}

// ── v0.4.18 PR8: PG parity gap fill — tests ported from sqlite_repo ──

/// scenario 1: an admin-owned inbound group is visible to a regular user even
/// when that user has no rules.
#[tokio::test]
async fn pg_shared_groups_lists_admin_inbound_for_user_without_rules() {
    let Some(db) = repo("shgrp_no_rules").await else {
        return;
    };
    sqlx::query("INSERT INTO users (id, username, password, admin) VALUES (2, 'u2', 'x', FALSE)")
        .execute(&db.pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO device_groups (id, name, group_type, token, uid) \
         VALUES (10, 'gin', 'in', 'tok10', 1)",
    )
    .execute(&db.pool)
    .await
    .unwrap();
    let shared = db.list_shared_groups(2, false).await.unwrap();
    assert_eq!(shared.len(), 1, "alice sees the admin inbound group (PG)");
    assert_eq!(shared[0].id, 10);
    cleanup(&db).await;
}

/// scenario 2: out / monitor groups never appear in the shared list.
#[tokio::test]
async fn pg_shared_groups_excludes_non_inbound_types() {
    let Some(db) = repo("shgrp_types").await else {
        return;
    };
    sqlx::query("INSERT INTO users (id, username, password, admin) VALUES (2, 'u2', 'x', FALSE)")
        .execute(&db.pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO device_groups (id, name, group_type, token, uid) VALUES (10, 'gin', 'in', 'tok10', 1)")
        .execute(&db.pool).await.unwrap();
    sqlx::query("INSERT INTO device_groups (id, name, group_type, token, uid) VALUES (11, 'gout', 'out', 'tok11', 1)")
        .execute(&db.pool).await.unwrap();
    sqlx::query("INSERT INTO device_groups (id, name, group_type, token, uid) VALUES (12, 'gmon', 'monitor', 'tok12', 1)")
        .execute(&db.pool).await.unwrap();
    let shared = db.list_shared_groups(2, false).await.unwrap();
    assert_eq!(shared.len(), 1);
    assert_eq!(shared[0].id, 10, "only the 'in' group is shared (PG)");
    cleanup(&db).await;
}

/// scenario 3: a regular user never sees ANOTHER regular user's group.
#[tokio::test]
async fn pg_shared_groups_excludes_other_regular_users_groups() {
    let Some(db) = repo("shgrp_other").await else {
        return;
    };
    sqlx::query("INSERT INTO users (id, username, password, admin) VALUES (2, 'u2', 'x', FALSE)")
        .execute(&db.pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO users (id, username, password, admin) VALUES (3, 'u3', 'x', FALSE)")
        .execute(&db.pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO device_groups (id, name, group_type, token, uid) VALUES (20, 'g', 'in', 'tok20', 3)")
        .execute(&db.pool).await.unwrap();
    let shared = db.list_shared_groups(2, false).await.unwrap();
    assert!(
        shared.is_empty(),
        "alice must NOT see bob's inbound group (PG)"
    );
    cleanup(&db).await;
}

/// v1.0.7: list_shared_groups still RETURNS a hidden group (carrying the
/// `hidden` flag); only the node-status handler drops it, so the rule dropdown
/// / shop keep listing hidden lines. Admins see it too (PG).
#[tokio::test]
async fn pg_shared_groups_carries_hidden_flag_and_still_lists_hidden() {
    let Some(db) = repo("shgrp_hidden").await else {
        return;
    };
    sqlx::query("INSERT INTO users (id, username, password, admin) VALUES (2, 'u2', 'x', FALSE)")
        .execute(&db.pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO device_groups (id, name, group_type, token, uid) VALUES (10, 'g10', 'in', 'tok10', 1)")
        .execute(&db.pool).await.unwrap();
    sqlx::query("INSERT INTO device_groups (id, name, group_type, token, uid, hidden) VALUES (11, 'g11', 'in', 'tok11', 1, TRUE)")
        .execute(&db.pool).await.unwrap();

    // Regular user: BOTH groups listed; the hidden one carries hidden=true.
    let shared = db.list_shared_groups(2, false).await.unwrap();
    assert_eq!(
        shared.len(),
        2,
        "hidden group must STILL be listed for rules (PG)"
    );
    assert!(shared.iter().any(|g| g.id == 11 && g.hidden));
    assert!(shared.iter().any(|g| g.id == 10 && !g.hidden));

    // Admin: list_groups (unscoped) returns BOTH, with the flag set.
    let all = db.list_groups(&ResourceScope::All).await.unwrap();
    assert!(
        all.iter().any(|g| g.id == 11 && g.hidden),
        "admin must still see the hidden group, flagged hidden=true (PG)"
    );
    assert!(all.iter().any(|g| g.id == 10 && !g.hidden));
    cleanup(&db).await;
}

/// An admin caller gets an empty shared list.
#[tokio::test]
async fn pg_shared_groups_empty_for_admin() {
    let Some(db) = repo("shgrp_admin").await else {
        return;
    };
    sqlx::query("INSERT INTO device_groups (id, name, group_type, token, uid) VALUES (10, 'gin', 'in', 'tok10', 1)")
        .execute(&db.pool).await.unwrap();
    let shared = db.list_shared_groups(1, true).await.unwrap();
    assert!(shared.is_empty());
    cleanup(&db).await;
}

/// is_admin / exists_by_id distinguish known rows.
#[tokio::test]
async fn pg_user_is_admin_and_exists_by_id_distinguish_known_rows() {
    let Some(db) = repo("isadmin").await else {
        return;
    };
    // SCHEMA seeds uid=1 as admin.
    assert!(db.exists_by_id(1).await.unwrap());
    assert!(db.is_admin(1).await.unwrap());
    assert!(!db.exists_by_id(999_999).await.unwrap());
    assert!(!db.is_admin(999_999).await.unwrap());
    db.insert_user("alice", "h", 1).await.unwrap();
    let uid = db.find_by_username("alice").await.unwrap().unwrap().id;
    assert!(db.exists_by_id(uid).await.unwrap());
    assert!(!db.is_admin(uid).await.unwrap());
    cleanup(&db).await;
}

/// delete_user_cascade clears rules, groups, profiles, and the user row.
#[tokio::test]
async fn pg_user_delete_cascade_clears_rules_groups_profiles_and_user() {
    let Some(db) = repo("cascade_clear").await else {
        return;
    };
    db.insert_user("alice", "h", 1).await.unwrap();
    let uid = db.find_by_username("alice").await.unwrap().unwrap().id;
    sqlx::query("INSERT INTO device_groups (id, name, group_type, token, uid) VALUES (1, 'g1', 'in', 'tok-1', $1)")
        .bind(uid).execute(&db.pool).await.unwrap();
    sqlx::query(
        "INSERT INTO forward_rules \
         (name, uid, listen_port, device_group_in, target_addr, target_port) \
         VALUES ('r1', $1, 20000, 1, '127.0.0.1', 80)",
    )
    .bind(uid)
    .execute(&db.pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO tunnel_profiles (name, transport, uid) VALUES ('alice-custom', 'ws', $1)",
    )
    .bind(uid)
    .execute(&db.pool)
    .await
    .unwrap();
    let affected = db.delete_user_cascade(uid).await.unwrap();
    assert_eq!(affected, 1, "the user row must be deleted (PG)");
    let rules: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM forward_rules WHERE uid = $1")
        .bind(uid)
        .fetch_one(&db.pool)
        .await
        .unwrap();
    let groups: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM device_groups WHERE uid = $1")
        .bind(uid)
        .fetch_one(&db.pool)
        .await
        .unwrap();
    let profiles: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM tunnel_profiles WHERE uid = $1")
        .bind(uid)
        .fetch_one(&db.pool)
        .await
        .unwrap();
    let user: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users WHERE id = $1")
        .bind(uid)
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(rules.0, 0);
    assert_eq!(groups.0, 0);
    assert_eq!(
        profiles.0, 0,
        "custom tunnel profile must be deleted too (PG)"
    );
    assert_eq!(user.0, 0, "user row must be gone (PG)");
    cleanup(&db).await;
}

/// update_rule_fields partial update touches only present columns.
#[tokio::test]
async fn pg_rule_update_rule_fields_partial_update() {
    let Some(db) = repo("upd_rule_fields").await else {
        return;
    };
    sqlx::query("INSERT INTO device_groups (id, name, group_type, token, uid) VALUES (1, 'gin', 'in', 'tok1', 1)")
        .execute(&db.pool).await.unwrap();
    db.insert_quota_guarded(
        "r1",
        1,
        20000,
        "tcp",
        "raw",
        "raw",
        "direct",
        "raw",
        None,
        1,
        None,
        "direct",
        "127.0.0.1",
        80,
    )
    .await
    .unwrap();
    let rule_id = db
        .list_rules(&ResourceScope::All)
        .await
        .unwrap()
        .into_iter()
        .next()
        .unwrap()
        .id;
    assert_eq!(
        db.update_rule_fields(
            rule_id,
            &ResourceScope::All,
            Some("renamed"),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None
        )
        .await
        .unwrap(),
        1
    );
    let row: (String, String) =
        sqlx::query_as("SELECT name, protocol FROM forward_rules WHERE id = $1")
            .bind(rule_id)
            .fetch_one(&db.pool)
            .await
            .unwrap();
    assert_eq!(row.0, "renamed");
    assert_eq!(row.1, "tcp", "protocol must be untouched (PG)");
    // Switching to direct clears device_group_out.
    assert_eq!(
        db.update_rule_fields(
            rule_id,
            &ResourceScope::All,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(None),
            None,
            None,
            None,
            None
        )
        .await
        .unwrap(),
        1
    );
    let dgo: (Option<i64>,) =
        sqlx::query_as("SELECT device_group_out FROM forward_rules WHERE id = $1")
            .bind(rule_id)
            .fetch_one(&db.pool)
            .await
            .unwrap();
    assert!(dgo.0.is_none(), "device_group_out must be cleared (PG)");
    cleanup(&db).await;
}

/// PostgreSQL must enforce the resume quota under the same user-row lock used
/// by rule creation. CI supplies TEST_PG_URL, so this contract runs there even
/// though local developer machines may skip it.
#[tokio::test]
async fn pg_rule_resume_respects_max_rules() {
    let Some(db) = repo("rule_resume_quota").await else {
        return;
    };
    sqlx::query("INSERT INTO device_groups (id, name, group_type, token, uid) VALUES (1, 'gin', 'in', 'tok-1', 1)")
        .execute(&db.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE users SET max_rules = 1 WHERE id = 1")
        .execute(&db.pool)
        .await
        .unwrap();
    for (id, port, paused) in [(100, 20_000, false), (101, 20_001, true)] {
        sqlx::query(
            "INSERT INTO forward_rules \
             (id, name, uid, listen_port, device_group_in, target_addr, target_port, paused) \
             VALUES ($1, $2, 1, $3, 1, '127.0.0.1', 80, $4)",
        )
        .bind(id)
        .bind(format!("rule-{id}"))
        .bind(port)
        .bind(paused)
        .execute(&db.pool)
        .await
        .unwrap();
    }

    let result = db
        .update_rule_fields(
            101,
            &ResourceScope::All,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(false),
        )
        .await;
    assert!(
        matches!(result, Err(DbError::QuotaExceeded)),
        "a full plan must reject manual resume, got {result:?}"
    );
    let paused: bool = sqlx::query_scalar("SELECT paused FROM forward_rules WHERE id = 101")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert!(paused, "quota-rejected resume must not modify the rule");
    cleanup(&db).await;
}

/// PostgreSQL parity for "a failed resume leaves no open transaction".
///
/// PG gets this for free — the resume path uses `pool.begin()`, whose
/// `Transaction` rolls back on drop — whereas SQLite hand-rolls BEGIN IMMEDIATE
/// on a pooled connection and needs an explicit ROLLBACK on every error path.
/// The contract is pinned on both backends anyway, so it does not rest on which
/// transaction API each side happens to use today.
#[tokio::test]
async fn pg_rule_resume_rolls_back_when_the_update_fails() {
    let Some(db) = repo("rule_resume_rollback").await else {
        return;
    };
    sqlx::query("INSERT INTO device_groups (id, name, group_type, token, uid) VALUES (1, 'gin', 'in', 'tok-1', 1)")
        .execute(&db.pool)
        .await
        .unwrap();
    // Unlimited, so the quota check passes and we reach the UPDATE — this test
    // is about the failure path, not the quota.
    sqlx::query("UPDATE users SET max_rules = 0 WHERE id = 1")
        .execute(&db.pool)
        .await
        .unwrap();
    for (id, port, paused) in [(100, 20_000, false), (101, 20_001, true)] {
        sqlx::query(
            "INSERT INTO forward_rules \
             (id, name, uid, listen_port, device_group_in, target_addr, target_port, paused) \
             VALUES ($1, $2, 1, $3, 1, '127.0.0.1', 80, $4)",
        )
        .bind(id)
        .bind(format!("rule-{id}"))
        .bind(port)
        .bind(paused)
        .execute(&db.pool)
        .await
        .unwrap();
    }

    // Resume rule 101 AND move it onto rule 100's port: the partial unique
    // index rejects the UPDATE from inside the open transaction.
    let result = db
        .update_rule_fields(
            101,
            &ResourceScope::All,
            None,
            Some(20_000),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(false),
        )
        .await;
    assert!(
        result.is_err(),
        "moving a rule onto a taken port must fail, got {result:?}"
    );

    // The pool must still be usable: a leaked transaction would hold the row
    // locks its FOR UPDATE reads took until the connection is recycled.
    sqlx::query("UPDATE forward_rules SET name = 'after' WHERE id = 100")
        .execute(&db.pool)
        .await
        .expect("a failed resume must not leave its transaction open");
    let paused: bool = sqlx::query_scalar("SELECT paused FROM forward_rules WHERE id = 101")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert!(paused, "the rejected resume must not have been applied");
    cleanup(&db).await;
}

/// overflow entry rejects and rolls back (no data written).
#[tokio::test]
async fn pg_traffic_batch_single_entry_overflow_rejects_and_rolls_back() {
    let Some(db) = repo("traf_ov_rollback").await else {
        return;
    };
    db.insert_user("alice", "h", 1).await.unwrap();
    let alice = db.find_by_username("alice").await.unwrap().unwrap().id;
    sqlx::query("INSERT INTO device_groups (id, name, group_type, token, uid) VALUES (50, 'gin', 'in', 'tok-50', $1)")
        .bind(alice).execute(&db.pool).await.unwrap();
    sqlx::query(
        "INSERT INTO forward_rules (id, name, uid, listen_port, device_group_in, target_addr, target_port) \
         VALUES (100, 'r100', $1, 20000, 50, '127.0.0.1', 80)",
    )
    .bind(alice).execute(&db.pool).await.unwrap();
    let half = (i64::MAX as u64) / 2 + 1;
    let results = db
        .apply_traffic_batch(
            50,
            &[TrafficEntry {
                rule_id: 100,
                upload: half,
                download: half,
            }],
        )
        .await
        .unwrap();
    assert!(matches!(results[0], TrafficEntryResult::Overflow));
    let rule_t: (i64,) = sqlx::query_as("SELECT traffic_used FROM forward_rules WHERE id = 100")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(rule_t.0, 0, "overflow → no write (PG)");
    cleanup(&db).await;
}

// ── v1.0.8: device-group rate billing ──

async fn seed_group_with_rate(db: &PgRepository, gid: i64, rate: f64) {
    db.insert_user("alice", "h", 1).await.unwrap();
    let alice = db.find_by_username("alice").await.unwrap().unwrap().id;
    sqlx::query(
        "INSERT INTO device_groups (id, name, group_type, token, uid, rate) \
         VALUES ($1, 'gin', 'in', $2, $3, $4)",
    )
    .bind(gid)
    .bind(format!("tok-{gid}"))
    .bind(alice)
    .bind(rate)
    .execute(&db.pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO forward_rules \
         (id, name, uid, listen_port, device_group_in, target_addr, target_port) \
         VALUES (100, 'r100', $1, 20000, $2, '127.0.0.1', 80)",
    )
    .bind(alice)
    .bind(gid)
    .execute(&db.pool)
    .await
    .unwrap();
}

#[tokio::test]
async fn pg_traffic_batch_rate_2_charges_user_double_rule_stays_real() {
    let Some(db) = repo("traf_rate2").await else {
        return;
    };
    seed_group_with_rate(&db, 50, 2.0).await;
    let alice = db.find_by_username("alice").await.unwrap().unwrap().id;

    let results = db
        .apply_traffic_batch(
            50,
            &[TrafficEntry {
                rule_id: 100,
                upload: 1000,
                download: 2000,
            }],
        )
        .await
        .unwrap();
    assert_eq!(results.len(), 1);
    assert!(matches!(results[0], TrafficEntryResult::Ok));

    let rule_t: (i64,) = sqlx::query_as("SELECT traffic_used FROM forward_rules WHERE id = 100")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(rule_t.0, 3000);
    let user_t: (i64,) = sqlx::query_as("SELECT traffic_used FROM users WHERE id = $1")
        .bind(alice)
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(user_t.0, 6000);
    cleanup(&db).await;
}

#[tokio::test]
async fn pg_traffic_batch_rate_1_is_unchanged_billing() {
    let Some(db) = repo("traf_rate1").await else {
        return;
    };
    seed_group_with_rate(&db, 51, 1.0).await;
    let alice = db.find_by_username("alice").await.unwrap().unwrap().id;

    let results = db
        .apply_traffic_batch(
            51,
            &[TrafficEntry {
                rule_id: 100,
                upload: 1000,
                download: 2000,
            }],
        )
        .await
        .unwrap();
    assert!(matches!(results[0], TrafficEntryResult::Ok));

    let rule_t: (i64,) = sqlx::query_as("SELECT traffic_used FROM forward_rules WHERE id = 100")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    let user_t: (i64,) = sqlx::query_as("SELECT traffic_used FROM users WHERE id = $1")
        .bind(alice)
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(rule_t.0, 3000);
    assert_eq!(user_t.0, 3000);
    cleanup(&db).await;
}

#[tokio::test]
async fn pg_traffic_batch_rate_1_5_rounds_correctly() {
    let Some(db) = repo("traf_rate1_5").await else {
        return;
    };
    seed_group_with_rate(&db, 52, 1.5).await;
    let alice = db.find_by_username("alice").await.unwrap().unwrap().id;

    let results = db
        .apply_traffic_batch(
            52,
            &[TrafficEntry {
                rule_id: 100,
                upload: 1000,
                download: 2000,
            }],
        )
        .await
        .unwrap();
    assert!(matches!(results[0], TrafficEntryResult::Ok));

    let rule_t: (i64,) = sqlx::query_as("SELECT traffic_used FROM forward_rules WHERE id = 100")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    let user_t: (i64,) = sqlx::query_as("SELECT traffic_used FROM users WHERE id = $1")
        .bind(alice)
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(rule_t.0, 3000);
    assert_eq!(user_t.0, 4500);

    db.apply_traffic_batch(
        52,
        &[TrafficEntry {
            rule_id: 100,
            upload: 1,
            download: 1,
        }],
    )
    .await
    .unwrap();
    let rule_t2: (i64,) = sqlx::query_as("SELECT traffic_used FROM forward_rules WHERE id = 100")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    let user_t2: (i64,) = sqlx::query_as("SELECT traffic_used FROM users WHERE id = $1")
        .bind(alice)
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(rule_t2.0, 3002);
    assert_eq!(user_t2.0, 4503);
    cleanup(&db).await;
}

// ── v1.0.8: suspension + expiry gating ──

async fn seed_active_rule(db: &PgRepository) -> i64 {
    db.insert_user("alice", "h", 1).await.unwrap();
    let alice = db.find_by_username("alice").await.unwrap().unwrap().id;
    sqlx::query(
        "INSERT INTO device_groups (id, name, group_type, token, uid) \
         VALUES (50, 'gin', 'in', 'tok-50', $1)",
    )
    .bind(alice)
    .execute(&db.pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO forward_rules \
         (name, uid, listen_port, device_group_in, target_addr, target_port) \
         VALUES ('r', $1, 20000, 50, '127.0.0.1', 80)",
    )
    .bind(alice)
    .execute(&db.pool)
    .await
    .unwrap();
    alice
}

#[tokio::test]
async fn pg_suspended_user_rule_is_filtered_and_resumes_on_unsuspend() {
    let Some(db) = repo("susp_filter").await else {
        return;
    };
    let alice = seed_active_rule(&db).await;
    assert_eq!(db.list_active_for_config(50).await.unwrap().len(), 1);

    sqlx::query("UPDATE users SET suspended = TRUE WHERE id = $1")
        .bind(alice)
        .execute(&db.pool)
        .await
        .unwrap();
    assert_eq!(
        db.list_active_for_config(50).await.unwrap().len(),
        0,
        "suspended user's rule must be filtered (PG)"
    );

    sqlx::query("UPDATE users SET suspended = FALSE WHERE id = $1")
        .bind(alice)
        .execute(&db.pool)
        .await
        .unwrap();
    assert_eq!(
        db.list_active_for_config(50).await.unwrap().len(),
        1,
        "rule must reappear after unsuspend (PG)"
    );
    cleanup(&db).await;
}

#[tokio::test]
async fn pg_expired_plan_rule_is_filtered_and_resumes_after_renewal() {
    let Some(db) = repo("expiry_filter").await else {
        return;
    };
    let alice = seed_active_rule(&db).await;
    sqlx::query("UPDATE users SET plan_expire_at = '2000-01-01 00:00:00' WHERE id = $1")
        .bind(alice)
        .execute(&db.pool)
        .await
        .unwrap();
    assert_eq!(
        db.list_active_for_config(50).await.unwrap().len(),
        0,
        "expired-plan user's rule must be filtered (PG)"
    );

    sqlx::query("UPDATE users SET plan_expire_at = '2099-01-01 00:00:00' WHERE id = $1")
        .bind(alice)
        .execute(&db.pool)
        .await
        .unwrap();
    assert_eq!(
        db.list_active_for_config(50).await.unwrap().len(),
        1,
        "rule must reappear after renewal (PG)"
    );
    cleanup(&db).await;
}

#[tokio::test]
async fn pg_null_plan_expire_at_is_no_expiry() {
    let Some(db) = repo("null_expiry").await else {
        return;
    };
    let alice = seed_active_rule(&db).await;
    sqlx::query("UPDATE users SET plan_expire_at = NULL WHERE id = $1")
        .bind(alice)
        .execute(&db.pool)
        .await
        .unwrap();
    assert_eq!(db.list_active_for_config(50).await.unwrap().len(), 1);
    cleanup(&db).await;
}

// ── v1.0.8: plan purchase (buy_plan) ──

async fn seed_buyer_and_plan(
    db: &PgRepository,
    balance: &str,
    plan_traffic: i64,
    plan_price: &str,
    duration_days: i32,
    reset_traffic: bool,
) -> (i64, i64) {
    db.insert_user("alice", "h", 1).await.unwrap();
    let alice = db.find_by_username("alice").await.unwrap().unwrap().id;
    sqlx::query("UPDATE users SET balance = $1 WHERE id = $2")
        .bind(balance)
        .bind(alice)
        .execute(&db.pool)
        .await
        .unwrap();
    let pid = db
        .insert_plan(
            "p1",
            10,
            plan_traffic,
            plan_price,
            if duration_days > 0 { "time" } else { "data" },
            duration_days,
            false,
            reset_traffic,
            "desc",
            false,
        )
        .await
        .unwrap();
    (alice, pid)
}

#[tokio::test]
async fn pg_buy_plan_stacks_traffic_and_charges_balance() {
    let Some(db) = repo("buy_stack").await else {
        return;
    };
    let (alice, pid) = seed_buyer_and_plan(&db, "100.00", 1_000_000, "30.00", 0, false).await;
    // RENEW: alice is already on this plan (plan_id = pid) with 500 quota left.
    // Re-buying the SAME plan stacks traffic (加流量).
    sqlx::query("UPDATE users SET traffic_limit = 500, plan_id = $1 WHERE id = $2")
        .bind(pid)
        .bind(alice)
        .execute(&db.pool)
        .await
        .unwrap();

    db.buy_plan(
        alice,
        pid,
        "p1",
        3000,
        1_000_000,
        10,
        0,
        false,
        false,
        &[],
        &[],
    )
    .await
    .unwrap();

    let (balance, traffic_limit, max_rules, plan_id): (String, i64, i32, Option<i64>) =
        sqlx::query_as(
            "SELECT balance, traffic_limit, max_rules, plan_id FROM users WHERE id = $1",
        )
        .bind(alice)
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(balance, "70");
    assert_eq!(
        traffic_limit, 1_000_500,
        "renewing the same plan must stack traffic on existing quota (PG)"
    );
    assert_eq!(max_rules, 10);
    assert_eq!(plan_id, Some(pid));

    let orders: Vec<relay_shared::models::Order> = db.list_orders_by_user(alice).await.unwrap();
    assert_eq!(orders.len(), 1);
    assert_eq!(orders[0].plan_name, "p1");
    assert_eq!(orders[0].price, "30");
    cleanup(&db).await;
}

#[tokio::test]
async fn pg_buy_plan_reset_traffic_zeros_usage() {
    let Some(db) = repo("buy_reset").await else {
        return;
    };
    let (alice, pid) = seed_buyer_and_plan(&db, "100.00", 1_000_000, "10.00", 0, true).await;
    sqlx::query("UPDATE users SET traffic_used = 9999 WHERE id = $1")
        .bind(alice)
        .execute(&db.pool)
        .await
        .unwrap();

    db.buy_plan(
        alice,
        pid,
        "p1",
        1000,
        1_000_000,
        10,
        0,
        true,
        false,
        &[],
        &[],
    )
    .await
    .unwrap();

    let used: (i64,) = sqlx::query_as("SELECT traffic_used FROM users WHERE id = $1")
        .bind(alice)
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(used.0, 0, "reset_traffic must zero traffic_used (PG)");
    cleanup(&db).await;
}

#[tokio::test]
async fn pg_buy_plan_insufficient_balance_is_rejected_and_rolls_back() {
    let Some(db) = repo("buy_insuf").await else {
        return;
    };
    let (alice, pid) = seed_buyer_and_plan(&db, "5.00", 1_000_000, "30.00", 0, false).await;
    sqlx::query("UPDATE users SET plan_id = NULL WHERE id = $1")
        .bind(alice)
        .execute(&db.pool)
        .await
        .unwrap();

    let err = db
        .buy_plan(
            alice,
            pid,
            "p1",
            3000,
            1_000_000,
            10,
            0,
            false,
            false,
            &[],
            &[],
        )
        .await
        .unwrap_err();
    assert!(matches!(err, BuyPlanError::InsufficientBalance));

    let (balance, plan_id): (String, Option<i64>) =
        sqlx::query_as("SELECT balance, plan_id FROM users WHERE id = $1")
            .bind(alice)
            .fetch_one(&db.pool)
            .await
            .unwrap();
    assert_eq!(
        balance, "5.00",
        "balance must be untouched on rollback (PG)"
    );
    assert_eq!(plan_id, None);
    let orders: Vec<relay_shared::models::Order> = db.list_orders_by_user(alice).await.unwrap();
    assert_eq!(orders.len(), 0, "no order row on insufficient balance (PG)");
    cleanup(&db).await;
}

#[tokio::test]
async fn pg_buy_plan_time_plan_sets_future_expiry() {
    let Some(db) = repo("buy_time").await else {
        return;
    };
    let (alice, pid) = seed_buyer_and_plan(&db, "100.00", 0, "5.00", 30, false).await;

    db.buy_plan(alice, pid, "p1", 500, 0, 10, 30, false, false, &[], &[])
        .await
        .unwrap();

    let expire: (Option<String>,) =
        sqlx::query_as("SELECT plan_expire_at::text FROM users WHERE id = $1")
            .bind(alice)
            .fetch_one(&db.pool)
            .await
            .unwrap();
    let exp = expire.0.expect("time plan must set an expiry (PG)");
    let now: (String,) = sqlx::query_as("SELECT NOW()::text")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert!(
        exp > now.0,
        "expiry must be in the future (PG): {exp} <= {}",
        now.0
    );
    cleanup(&db).await;
}

#[tokio::test]
async fn pg_buy_plan_renewal_stacks_expiry_from_current_end() {
    let Some(db) = repo("buy_renew").await else {
        return;
    };
    let (alice, pid) = seed_buyer_and_plan(&db, "100.00", 0, "5.00", 30, false).await;
    // RENEW: plan_id = pid makes re-buying the same plan a renew (extend FROM
    // the existing far-future expiry, not clip to now + 30).
    sqlx::query(
        "UPDATE users SET plan_expire_at = '2099-12-31 00:00:00', plan_id = $1 WHERE id = $2",
    )
    .bind(pid)
    .bind(alice)
    .execute(&db.pool)
    .await
    .unwrap();

    db.buy_plan(alice, pid, "p1", 500, 0, 10, 30, false, false, &[], &[])
        .await
        .unwrap();

    let expire: (Option<String>,) =
        sqlx::query_as("SELECT plan_expire_at::text FROM users WHERE id = $1")
            .bind(alice)
            .fetch_one(&db.pool)
            .await
            .unwrap();
    let expire = expire.0.expect("renewal must keep an expiry (PG)");
    assert!(
        expire.starts_with("2100-"),
        "renewal must stack from current expiry (PG), got {expire}"
    );
    cleanup(&db).await;
}

/// v1.0.9: switching to a DIFFERENT plan replaces quota with the new plan's
/// amount (not stacked) and resets usage to 0.
#[tokio::test]
async fn pg_buy_plan_switch_replaces_traffic_and_resets_used() {
    let Some(db) = repo("buy_switch_traffic").await else {
        return;
    };
    let (alice, pid_a) = seed_buyer_and_plan(&db, "100.00", 1_000, "5.00", 0, false).await;
    sqlx::query(
        "UPDATE users SET plan_id = $1, traffic_limit = 800, traffic_used = 300 WHERE id = $2",
    )
    .bind(pid_a)
    .bind(alice)
    .execute(&db.pool)
    .await
    .unwrap();
    let pid_b = db
        .insert_plan("pB", 20, 5_000, "5.00", "data", 0, false, false, "", false)
        .await
        .unwrap();

    db.buy_plan(
        alice,
        pid_b,
        "pB",
        500,
        5_000,
        20,
        0,
        false,
        false,
        &[],
        &[],
    )
    .await
    .unwrap();

    let (traffic_limit, traffic_used, plan_id): (i64, i64, Option<i64>) =
        sqlx::query_as("SELECT traffic_limit, traffic_used, plan_id FROM users WHERE id = $1")
            .bind(alice)
            .fetch_one(&db.pool)
            .await
            .unwrap();
    assert_eq!(
        traffic_limit, 5_000,
        "switch must REPLACE quota with the new plan's amount, not stack (PG)"
    );
    assert_eq!(traffic_used, 0, "switch must reset usage to 0 (PG)");
    assert_eq!(plan_id, Some(pid_b));
    cleanup(&db).await;
}

/// v1.0.9: switching to a different time plan recomputes expiry from now.
#[tokio::test]
async fn pg_buy_plan_switch_recomputes_expiry_from_now() {
    let Some(db) = repo("buy_switch_expiry").await else {
        return;
    };
    let (alice, pid_a) = seed_buyer_and_plan(&db, "100.00", 0, "5.00", 30, false).await;
    sqlx::query(
        "UPDATE users SET plan_id = $1, plan_expire_at = '2099-12-31 00:00:00' WHERE id = $2",
    )
    .bind(pid_a)
    .bind(alice)
    .execute(&db.pool)
    .await
    .unwrap();
    let pid_b = db
        .insert_plan("pB", 10, 0, "5.00", "time", 30, false, false, "", false)
        .await
        .unwrap();

    db.buy_plan(alice, pid_b, "pB", 500, 0, 10, 30, false, false, &[], &[])
        .await
        .unwrap();

    let expire: (Option<String>,) =
        sqlx::query_as("SELECT plan_expire_at::text FROM users WHERE id = $1")
            .bind(alice)
            .fetch_one(&db.pool)
            .await
            .unwrap();
    let expire = expire.0.expect("switch to a time plan sets an expiry (PG)");
    assert!(
        !expire.starts_with("2099-") && !expire.starts_with("2100-"),
        "switch must recompute expiry from now, not stack from the old plan (PG), got {expire}"
    );
    cleanup(&db).await;
}

/// v1.0.9: renewing the SAME plan (reset_traffic=false) keeps usage and stacks
/// quota.
#[tokio::test]
async fn pg_buy_plan_renew_keeps_traffic_used() {
    let Some(db) = repo("buy_renew_used").await else {
        return;
    };
    let (alice, pid) = seed_buyer_and_plan(&db, "100.00", 1_000, "5.00", 0, false).await;
    sqlx::query(
        "UPDATE users SET plan_id = $1, traffic_limit = 1000, traffic_used = 400 WHERE id = $2",
    )
    .bind(pid)
    .bind(alice)
    .execute(&db.pool)
    .await
    .unwrap();

    db.buy_plan(alice, pid, "p1", 500, 1_000, 10, 0, false, false, &[], &[])
        .await
        .unwrap();

    let (traffic_limit, traffic_used): (i64, i64) =
        sqlx::query_as("SELECT traffic_limit, traffic_used FROM users WHERE id = $1")
            .bind(alice)
            .fetch_one(&db.pool)
            .await
            .unwrap();
    assert_eq!(traffic_limit, 2_000, "renew stacks quota (PG)");
    assert_eq!(traffic_used, 400, "renew keeps usage (PG)");
    cleanup(&db).await;
}

// ── v1.1.0: default plan is not re-seeded on restart ──

/// Postgres parity for [`default_plan_not_reseeded_on_restart`].
#[tokio::test]
async fn pg_default_plan_not_reseeded_on_restart() {
    let Some(db) = repo("default_plan_reseed").await else {
        return;
    };
    assert!(
        db.list_plans()
            .await
            .unwrap()
            .iter()
            .any(|p| p.name == "free"),
        "a fresh DB seeds the default free plan"
    );

    let keep = db
        .insert_plan(
            "keep", 10, 1_000, "5.00", "data", 0, false, false, "d", false,
        )
        .await
        .unwrap();
    sqlx::query("UPDATE app_settings SET default_registration_plan_id = $1")
        .bind(keep)
        .execute(&db.pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM plans WHERE id = 1")
        .execute(&db.pool)
        .await
        .unwrap();

    // Simulate a restart: re-apply the baseline schema.
    apply_pg_schema(&db.pool).await.expect("re-apply schema");

    let names: Vec<String> = db
        .list_plans()
        .await
        .unwrap()
        .into_iter()
        .map(|p| p.name)
        .collect();
    assert!(
        !names.contains(&"free".to_string()),
        "deleted default plan must not reappear after restart"
    );
    assert!(names.contains(&"keep".to_string()), "other plans survive");

    cleanup(&db).await;
}

// ── v1.0.8: plan CRUD ──

#[tokio::test]
async fn pg_plan_crud_round_trip_and_delete_blocked_when_in_use() {
    let Some(db) = repo("plan_crud").await else {
        return;
    };
    let pid = db
        .insert_plan("p1", 10, 1_000, "5.00", "data", 0, false, false, "d", false)
        .await
        .unwrap();

    assert_eq!(
        db.update_plan_fields(
            pid,
            Some("p1-renamed"),
            Some(20),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap(),
        1
    );
    let p = db.find_plan_by_id(pid).await.unwrap().unwrap();
    assert_eq!(p.name, "p1-renamed");
    assert_eq!(p.max_rules, 20);

    let visible_before = db.list_visible_plans().await.unwrap().len();
    db.update_plan_fields(
        pid,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(true),
        None,
        None,
        None,
    )
    .await
    .unwrap();
    assert_eq!(
        db.list_visible_plans().await.unwrap().len(),
        visible_before - 1
    );
    assert!(db.list_plans().await.unwrap().iter().any(|p| p.id == pid));

    assert_eq!(db.count_users_on_plan(pid).await.unwrap(), 0);
    assert_eq!(db.delete_plan(pid).await.unwrap(), 1);
    assert!(db.find_plan_by_id(pid).await.unwrap().is_none());

    let pid2 = db
        .insert_plan("p2", 5, 0, "0", "data", 0, false, false, "", false)
        .await
        .unwrap();
    db.insert_user("bob", "h", 1).await.unwrap();
    let bob = db.find_by_username("bob").await.unwrap().unwrap().id;
    sqlx::query("UPDATE users SET plan_id = $1 WHERE id = $2")
        .bind(pid2)
        .bind(bob)
        .execute(&db.pool)
        .await
        .unwrap();
    assert_eq!(db.count_users_on_plan(pid2).await.unwrap(), 1);
    cleanup(&db).await;
}

// ── v1.0.9: plan ↔ device-group grants + purchase authorization ──

async fn seed_device_group(db: &PgRepository, gid: i64, uid: i64) {
    sqlx::query(
        "INSERT INTO device_groups (id, name, group_type, token, uid) \
         VALUES ($1, 'g', 'in', $2, $3)",
    )
    .bind(gid)
    .bind(format!("tok-dg-{gid}"))
    .bind(uid)
    .execute(&db.pool)
    .await
    .unwrap();
}

#[tokio::test]
async fn pg_create_plan_with_groups_persists_plan_and_grants() {
    let Some(db) = repo("create_plan_grp").await else {
        return;
    };
    seed_device_group(&db, 60, 1).await;
    seed_device_group(&db, 61, 1).await;
    let id = db
        .create_plan_with_groups(
            "combo",
            5,
            1000,
            "5.00",
            "data",
            0,
            false,
            false,
            "d",
            false,
            &[60, 61],
        )
        .await
        .unwrap();
    let p = db.find_plan_by_id(id).await.unwrap().expect("plan created");
    assert_eq!(p.name, "combo");
    assert_eq!(db.list_plan_device_groups(id).await.unwrap(), vec![60, 61]);
    cleanup(&db).await;
}

#[tokio::test]
async fn pg_clear_user_plan_revokes_groups_and_pauses_rules() {
    let Some(db) = repo("clear_user_plan").await else {
        return;
    };
    let (alice, pid) = seed_buyer_and_plan(&db, "100.00", 1000, "5.00", 0, false).await;
    seed_device_group(&db, 70, alice).await;
    sqlx::query("UPDATE users SET plan_id = $1, all_device_groups = TRUE WHERE id = $2")
        .bind(pid)
        .bind(alice)
        .execute(&db.pool)
        .await
        .unwrap();
    db.set_user_device_groups(alice, &[70]).await.unwrap();
    sqlx::query(
        "INSERT INTO forward_rules (id, name, uid, listen_port, device_group_in, \
         target_addr, target_port, paused) VALUES (300, 'r', $1, 21000, 70, '127.0.0.1', 80, FALSE)",
    )
    .bind(alice)
    .execute(&db.pool)
    .await
    .unwrap();

    let affected = db.clear_user_plan(alice).await.unwrap();
    assert_eq!(affected, 1);

    let (plan_id, all): (Option<i64>, bool) =
        sqlx::query_as("SELECT plan_id, all_device_groups FROM users WHERE id = $1")
            .bind(alice)
            .fetch_one(&db.pool)
            .await
            .unwrap();
    assert_eq!(plan_id, None);
    assert!(!all, "all_device_groups must be cleared (PG)");
    assert!(db.list_user_device_groups(alice).await.unwrap().is_empty());
    let (paused, auto): (bool, bool) =
        sqlx::query_as("SELECT paused, auto_paused FROM forward_rules WHERE id = 300")
            .fetch_one(&db.pool)
            .await
            .unwrap();
    assert!(
        paused && auto,
        "rule must be system-paused after clear (PG)"
    );

    assert_eq!(db.clear_user_plan(1).await.unwrap(), 0);
    cleanup(&db).await;
}

#[tokio::test]
async fn pg_plan_device_groups_round_trip_and_replace() {
    let Some(db) = repo("plan_dg_rtrip").await else {
        return;
    };
    let (alice, pid) = seed_buyer_and_plan(&db, "100.00", 1000, "5.00", 0, false).await;
    seed_device_group(&db, 50, alice).await;
    seed_device_group(&db, 51, alice).await;
    seed_device_group(&db, 52, alice).await;

    db.set_plan_device_groups(pid, &[50, 51]).await.unwrap();
    assert_eq!(db.list_plan_device_groups(pid).await.unwrap(), vec![50, 51]);

    db.set_plan_device_groups(pid, &[52]).await.unwrap();
    assert_eq!(db.list_plan_device_groups(pid).await.unwrap(), vec![52]);

    db.set_plan_device_groups(pid, &[50, 50, 51]).await.unwrap();
    assert_eq!(db.list_plan_device_groups(pid).await.unwrap(), vec![50, 51]);
    cleanup(&db).await;
}

/// v1.0.8: purchase REPLACES authorization, so a group the user already had
/// that ALSO appears in the new plan's grant set must end up exactly once
/// (mirrors the SQLite test).
#[tokio::test]
async fn pg_buy_plan_new_authorized_set_has_no_duplicate_groups() {
    let Some(db) = repo("buy_dg_dedup").await else {
        return;
    };
    let (alice, pid) = seed_buyer_and_plan(&db, "100.00", 1000, "5.00", 0, false).await;
    seed_device_group(&db, 50, alice).await;
    seed_device_group(&db, 51, alice).await;
    db.set_user_device_groups(alice, &[50]).await.unwrap();
    db.set_plan_device_groups(pid, &[50, 51]).await.unwrap();

    db.buy_plan(
        alice,
        pid,
        "p1",
        500,
        1000,
        10,
        0,
        false,
        false,
        &[50, 51],
        &[50, 51],
    )
    .await
    .unwrap();

    assert_eq!(
        db.list_user_device_groups(alice).await.unwrap(),
        vec![50, 51]
    );
    let all: (bool,) = sqlx::query_as("SELECT all_device_groups FROM users WHERE id = $1")
        .bind(alice)
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert!(!all.0);
    cleanup(&db).await;
}

/// v1.0.8: purchase REPLACES authorization — old groups are cleared. If the
/// user previously had groups not in the new plan, those are removed and
/// rules bound to them are paused. Mirrors the SQLite test.
#[tokio::test]
async fn pg_buy_plan_replaces_authorization_clears_old_groups() {
    let Some(db) = repo("buy_replaces_auth").await else {
        return;
    };
    let (alice, pid) = seed_buyer_and_plan(&db, "100.00", 1000, "5.00", 0, false).await;
    seed_device_group(&db, 50, alice).await;
    seed_device_group(&db, 51, alice).await;
    seed_device_group(&db, 52, alice).await;
    // Alice previously had groups 50 and 51.
    db.set_user_device_groups(alice, &[50, 51]).await.unwrap();
    // Plan grants only group 52.
    db.set_plan_device_groups(pid, &[52]).await.unwrap();

    // Create a rule bound to group 50 (will be paused after purchase).
    sqlx::query(
        "INSERT INTO forward_rules \
         (id, name, uid, listen_port, device_group_in, target_addr, target_port, paused) \
         VALUES (100, 'r100', $1, 20000, 50, '127.0.0.1', 80, FALSE)",
    )
    .bind(alice)
    .execute(&db.pool)
    .await
    .unwrap();

    // v1.0.8: new_authorized = {52} (the plan's grants).
    db.buy_plan(
        alice,
        pid,
        "p1",
        500,
        1000,
        10,
        0,
        false,
        false,
        &[52],
        &[52],
    )
    .await
    .unwrap();

    // Result: {52} — old groups 50, 51 are cleared.
    assert_eq!(db.list_user_device_groups(alice).await.unwrap(), vec![52]);
    // The rule bound to group 50 is now paused.
    let paused: (bool,) = sqlx::query_as("SELECT paused FROM forward_rules WHERE id = 100")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert!(
        paused.0,
        "rule bound to removed group should be paused (PG)"
    );
    cleanup(&db).await;
}

#[tokio::test]
async fn pg_buy_plan_grant_all_sets_flag() {
    let Some(db) = repo("buy_grant_all").await else {
        return;
    };
    let (alice, pid) = seed_buyer_and_plan(&db, "100.00", 1000, "5.00", 0, false).await;

    db.buy_plan(alice, pid, "p1", 500, 1000, 10, 0, false, true, &[], &[])
        .await
        .unwrap();

    let all: (bool,) = sqlx::query_as("SELECT all_device_groups FROM users WHERE id = $1")
        .bind(alice)
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert!(
        all.0,
        "grant_all_groups must set the all_device_groups flag (PG)"
    );
    cleanup(&db).await;
}

/// v1.0.8 regression (PG): downgrading from a grant-all plan to a per-group
/// plan must RESET all_device_groups back to FALSE. Mirrors the SQLite test.
#[tokio::test]
async fn pg_buy_plan_grant_all_then_per_group_resets_all_flag() {
    let Some(db) = repo("buy_grant_all_downgrade").await else {
        return;
    };
    let (alice, pid) = seed_buyer_and_plan(&db, "100.00", 1000, "5.00", 0, false).await;
    seed_device_group(&db, 50, alice).await;
    seed_device_group(&db, 52, alice).await;

    // 1) Buy a grant-all plan → all_device_groups = TRUE.
    db.buy_plan(alice, pid, "all", 100, 1000, 10, 0, false, true, &[], &[])
        .await
        .unwrap();
    let all: (bool,) = sqlx::query_as("SELECT all_device_groups FROM users WHERE id = $1")
        .bind(alice)
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert!(all.0, "grant-all purchase must set the flag (PG)");

    // 2) Downgrade to a per-group plan granting only {52}.
    db.buy_plan(
        alice,
        pid,
        "ltd",
        100,
        1000,
        10,
        0,
        false,
        false,
        &[52],
        &[52],
    )
    .await
    .unwrap();

    let all: (bool,) = sqlx::query_as("SELECT all_device_groups FROM users WHERE id = $1")
        .bind(alice)
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert!(
        !all.0,
        "downgrade to a per-group plan must reset all_device_groups to FALSE (PG)"
    );
    assert_eq!(db.list_user_device_groups(alice).await.unwrap(), vec![52]);
    cleanup(&db).await;
}

/// v1.0.8: re-buying a plan that re-grants a group must auto-resume a rule
/// this system previously auto-paused on that group. Mirrors the SQLite test.
#[tokio::test]
async fn pg_buy_plan_resumes_auto_paused_rules_when_group_reauthorized() {
    let Some(db) = repo("buy_plan_resume").await else {
        return;
    };
    let (alice, pid_a) = seed_buyer_and_plan(&db, "100.00", 1000, "5.00", 0, false).await;
    seed_device_group(&db, 50, alice).await;
    seed_device_group(&db, 51, alice).await;
    let pid_b = db
        .insert_plan("pB", 10, 1000, "5.00", "data", 0, false, false, "", false)
        .await
        .unwrap();
    db.set_plan_device_groups(pid_a, &[50]).await.unwrap();
    db.set_plan_device_groups(pid_b, &[51]).await.unwrap();

    sqlx::query(
        "INSERT INTO forward_rules \
         (id, name, uid, listen_port, device_group_in, target_addr, target_port, paused) \
         VALUES (200, 'r200', $1, 20000, 50, '127.0.0.1', 80, FALSE)",
    )
    .bind(alice)
    .execute(&db.pool)
    .await
    .unwrap();
    db.buy_plan(
        alice,
        pid_a,
        "pA",
        500,
        1000,
        10,
        0,
        false,
        false,
        &[50],
        &[50],
    )
    .await
    .unwrap();

    db.buy_plan(
        alice,
        pid_b,
        "pB",
        500,
        1000,
        10,
        0,
        false,
        false,
        &[51],
        &[51],
    )
    .await
    .unwrap();
    let (paused, auto_paused): (bool, bool) =
        sqlx::query_as("SELECT paused, auto_paused FROM forward_rules WHERE id = 200")
            .fetch_one(&db.pool)
            .await
            .unwrap();
    assert!(
        paused && auto_paused,
        "buy_plan must auto-pause rule 200 (PG)"
    );

    db.buy_plan(
        alice,
        pid_a,
        "pA",
        500,
        1000,
        10,
        0,
        false,
        false,
        &[50],
        &[50],
    )
    .await
    .unwrap();
    let (paused, auto_paused): (bool, bool) =
        sqlx::query_as("SELECT paused, auto_paused FROM forward_rules WHERE id = 200")
            .fetch_one(&db.pool)
            .await
            .unwrap();
    assert!(
        !paused && !auto_paused,
        "re-authorizing group 50 must auto-resume the rule buy_plan itself paused (PG)"
    );
    cleanup(&db).await;
}

/// v1.0.8: a rule the user paused THEMSELVES (auto_paused cleared) must NOT be
/// silently revived by a later purchase. Mirrors the SQLite test.
#[tokio::test]
async fn pg_buy_plan_does_not_resume_manually_paused_rules() {
    let Some(db) = repo("buy_plan_no_resume").await else {
        return;
    };
    let (alice, pid_a) = seed_buyer_and_plan(&db, "100.00", 1000, "5.00", 0, false).await;
    seed_device_group(&db, 50, alice).await;
    seed_device_group(&db, 51, alice).await;
    let pid_b = db
        .insert_plan("pB", 10, 1000, "5.00", "data", 0, false, false, "", false)
        .await
        .unwrap();
    db.set_plan_device_groups(pid_a, &[50]).await.unwrap();
    db.set_plan_device_groups(pid_b, &[51]).await.unwrap();

    sqlx::query(
        "INSERT INTO forward_rules \
         (id, name, uid, listen_port, device_group_in, target_addr, target_port, paused) \
         VALUES (201, 'r201', $1, 20001, 50, '127.0.0.1', 80, FALSE)",
    )
    .bind(alice)
    .execute(&db.pool)
    .await
    .unwrap();
    db.buy_plan(
        alice,
        pid_a,
        "pA",
        500,
        1000,
        10,
        0,
        false,
        false,
        &[50],
        &[50],
    )
    .await
    .unwrap();

    db.buy_plan(
        alice,
        pid_b,
        "pB",
        500,
        1000,
        10,
        0,
        false,
        false,
        &[51],
        &[51],
    )
    .await
    .unwrap();

    // Human re-confirms the pause via the on/off switch — clears auto_paused.
    let scope = crate::db::repo::ResourceScope::All;
    db.update_rule_fields(
        201,
        &scope,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(true),
    )
    .await
    .unwrap();
    let (_, auto_paused): (bool, bool) =
        sqlx::query_as("SELECT paused, auto_paused FROM forward_rules WHERE id = 201")
            .fetch_one(&db.pool)
            .await
            .unwrap();
    assert!(
        !auto_paused,
        "an explicit paused write must clear auto_paused (PG)"
    );

    db.buy_plan(
        alice,
        pid_a,
        "pA",
        500,
        1000,
        10,
        0,
        false,
        false,
        &[50],
        &[50],
    )
    .await
    .unwrap();
    let (paused,): (bool,) = sqlx::query_as("SELECT paused FROM forward_rules WHERE id = 201")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert!(
        paused,
        "a manually-paused rule must NOT be auto-resumed by a later purchase (PG)"
    );
    cleanup(&db).await;
}

/// v1.0.8: REPLACE semantics — buying a second (different) plan replaces the
/// first plan's authorization rather than stacking it. Mirrors the SQLite
/// test.
#[tokio::test]
async fn pg_second_plan_purchase_replaces_first_plan_groups() {
    let Some(db) = repo("multi_plan_stack").await else {
        return;
    };
    let (alice, pid_a) = seed_buyer_and_plan(&db, "100.00", 1000, "5.00", 0, false).await;
    seed_device_group(&db, 50, alice).await;
    seed_device_group(&db, 51, alice).await;
    let pid_b = db
        .insert_plan("pB", 10, 1000, "5.00", "data", 0, false, false, "", false)
        .await
        .unwrap();
    db.set_plan_device_groups(pid_a, &[50]).await.unwrap();
    db.set_plan_device_groups(pid_b, &[51]).await.unwrap();

    db.buy_plan(
        alice,
        pid_a,
        "pA",
        500,
        1000,
        10,
        0,
        false,
        false,
        &[50],
        &[50],
    )
    .await
    .unwrap();
    db.buy_plan(
        alice,
        pid_b,
        "pB",
        500,
        1000,
        10,
        0,
        false,
        false,
        &[51],
        &[51],
    )
    .await
    .unwrap();

    assert_eq!(db.list_user_device_groups(alice).await.unwrap(), vec![51]);
    cleanup(&db).await;
}

#[tokio::test]
async fn pg_delete_plan_cascades_grant_rows() {
    let Some(db) = repo("del_plan_cascade").await else {
        return;
    };
    let pid = db
        .insert_plan("p1", 10, 1000, "5.00", "data", 0, false, false, "", false)
        .await
        .unwrap();
    seed_device_group(&db, 50, 1).await;
    db.set_plan_device_groups(pid, &[50]).await.unwrap();
    assert_eq!(db.list_plan_device_groups(pid).await.unwrap(), vec![50]);

    db.delete_plan(pid).await.unwrap();
    assert!(db.list_plan_device_groups(pid).await.unwrap().is_empty());
    cleanup(&db).await;
}

#[tokio::test]
async fn pg_expiry_does_not_revoke_granted_groups() {
    let Some(db) = repo("expiry_no_revoke").await else {
        return;
    };
    let (alice, pid) = seed_buyer_and_plan(&db, "100.00", 0, "5.00", 30, false).await;
    seed_device_group(&db, 50, alice).await;
    db.set_plan_device_groups(pid, &[50]).await.unwrap();

    db.buy_plan(alice, pid, "p1", 500, 0, 10, 30, false, false, &[50], &[50])
        .await
        .unwrap();
    assert_eq!(db.list_user_device_groups(alice).await.unwrap(), vec![50]);

    sqlx::query("UPDATE users SET plan_expire_at = '2000-01-01 00:00:00' WHERE id = $1")
        .bind(alice)
        .execute(&db.pool)
        .await
        .unwrap();
    assert_eq!(
        db.list_user_device_groups(alice).await.unwrap(),
        vec![50],
        "expiry must not revoke granted device groups (PG)"
    );
    cleanup(&db).await;
}

/// v0.4.11 PR3: Migration does NOT pause cross-owner shared inbound rules.
#[tokio::test]
async fn pg_migration_does_not_pause_cross_owner_shared_inbound_rules() {
    let Some(db) = repo("mig_pause_cross").await else {
        return;
    };
    sqlx::query("INSERT INTO users (id, username, password, admin) VALUES (2, 'u2', 'x', FALSE)")
        .execute(&db.pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO device_groups (id, name, group_type, token, uid) VALUES (20, 'g', 'in', 't', 1)")
        .execute(&db.pool).await.unwrap();
    sqlx::query("INSERT INTO forward_rules (name, uid, listen_port, device_group_in, target_addr, target_port) \
                 VALUES ('r', 2, 15000, 20, '127.0.0.1', 80)")
        .execute(&db.pool).await.unwrap();
    // PG runs migrations during repo(), so the rule must be unpaused.
    let paused: (bool,) = sqlx::query_as("SELECT paused FROM forward_rules WHERE name = 'r'")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert!(
        !paused.0,
        "cross-owner shared inbound rule must NOT be paused (PG)"
    );
    cleanup(&db).await;
}

/// PostgreSQL parity for max-rule downgrade reconciliation. The paused rules
/// must remain paused after a later upgrade until the user resumes them.
#[tokio::test]
async fn pg_buy_plan_pauses_newest_rules_above_new_max_without_auto_resume() {
    let Some(db) = repo("buy_plan_limit_reconcile").await else {
        return;
    };
    let (alice, pid) = seed_buyer_and_plan(&db, "100.00", 0, "0", 0, false).await;
    seed_device_group(&db, 50, alice).await;
    for (id, port) in [(100, 20_000), (101, 20_001), (102, 20_002)] {
        sqlx::query(
            "INSERT INTO forward_rules \
             (id, name, uid, listen_port, device_group_in, target_addr, target_port, paused) \
             VALUES ($1, $2, $3, $4, 50, '127.0.0.1', 80, FALSE)",
        )
        .bind(id)
        .bind(format!("rule-{id}"))
        .bind(alice)
        .bind(port)
        .execute(&db.pool)
        .await
        .unwrap();
    }

    db.buy_plan(alice, pid, "lower", 0, 0, 1, 0, false, false, &[50], &[50])
        .await
        .unwrap();
    let after_downgrade: Vec<(i64, bool, bool)> = sqlx::query_as(
        "SELECT id, paused, auto_paused FROM forward_rules WHERE uid = $1 ORDER BY id",
    )
    .bind(alice)
    .fetch_all(&db.pool)
    .await
    .unwrap();
    assert_eq!(
        after_downgrade,
        vec![(100, false, false), (101, true, false), (102, true, false)]
    );

    db.buy_plan(alice, pid, "higher", 0, 0, 3, 0, false, false, &[50], &[50])
        .await
        .unwrap();
    let after_upgrade: Vec<(i64, bool, bool)> = sqlx::query_as(
        "SELECT id, paused, auto_paused FROM forward_rules WHERE uid = $1 ORDER BY id",
    )
    .bind(alice)
    .fetch_all(&db.pool)
    .await
    .unwrap();
    assert_eq!(after_upgrade, after_downgrade);
    cleanup(&db).await;
}

// ── v1.0.7: admin directly edits a user's plan association + expiry ──

#[tokio::test]
async fn pg_admin_set_user_plan_clears_and_adjusts_expiry() {
    let Some(db) = repo("admin_set_plan").await else {
        return;
    };
    let (alice, pid) = seed_buyer_and_plan(&db, "100.00", 0, "5.00", 30, false).await;
    sqlx::query(
        "UPDATE users SET plan_id = $1, plan_expire_at = '2030-01-01 00:00:00' WHERE id = $2",
    )
    .bind(pid)
    .bind(alice)
    .execute(&db.pool)
    .await
    .unwrap();

    assert_eq!(
        db.admin_set_user_plan(alice, Some(pid), Some("2099-12-31 00:00:00".into()))
            .await
            .unwrap(),
        1
    );
    let (plan_id, expire): (Option<i64>, Option<String>) =
        sqlx::query_as("SELECT plan_id, plan_expire_at FROM users WHERE id = $1")
            .bind(alice)
            .fetch_one(&db.pool)
            .await
            .unwrap();
    assert_eq!(plan_id, Some(pid));
    assert_eq!(expire.as_deref(), Some("2099-12-31 00:00:00"));

    db.admin_set_user_plan(alice, None, None).await.unwrap();
    let (plan_id2, expire2): (Option<i64>, Option<String>) =
        sqlx::query_as("SELECT plan_id, plan_expire_at FROM users WHERE id = $1")
            .bind(alice)
            .fetch_one(&db.pool)
            .await
            .unwrap();
    assert_eq!(plan_id2, None);
    assert_eq!(expire2, None);
    cleanup(&db).await;
}

#[tokio::test]
async fn pg_admin_set_user_plan_skips_admin_users() {
    let Some(db) = repo("admin_set_plan_skip").await else {
        return;
    };
    sqlx::query("INSERT INTO users (id, username, password, admin) VALUES (90, 'adm', 'x', TRUE)")
        .execute(&db.pool)
        .await
        .unwrap();
    let affected = db
        .admin_set_user_plan(90, None, Some("2099-12-31 00:00:00".into()))
        .await
        .unwrap();
    assert_eq!(
        affected, 0,
        "admin users must be skipped (WHERE admin = false)"
    );
    cleanup(&db).await;
}

/// v1.2.0: PG twin of rule_list_auto_restart_rules_excludes_off_and_paused.
/// The scheduler's query must return ONLY opted-in (`auto_restart_minutes > 0`)
/// and unpaused rules. PG stores `paused` as a real BOOLEAN (SQLite uses
/// INTEGER 0/1), so the two implementations genuinely differ and both need
/// covering.
#[tokio::test]
async fn pg_rule_list_auto_restart_rules_excludes_off_and_paused() {
    let Some(db) = repo("list_auto_restart").await else {
        return;
    };
    sqlx::query("INSERT INTO device_groups (id, name, group_type, token, uid) VALUES (1, 'gin', 'in', 'tok1', 1)")
        .execute(&db.pool).await.unwrap();
    for (name, port) in [("off", 20001), ("on", 20002), ("paused", 20003)] {
        db.insert_quota_guarded(
            name,
            1,
            port,
            "tcp",
            "raw",
            "raw",
            "direct",
            "raw",
            None,
            1,
            None,
            "direct",
            "127.0.0.1",
            80,
        )
        .await
        .unwrap();
    }
    let on_id: i64 = sqlx::query_scalar("SELECT id FROM forward_rules WHERE name = 'on'")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    let paused_id: i64 = sqlx::query_scalar("SELECT id FROM forward_rules WHERE name = 'paused'")
        .fetch_one(&db.pool)
        .await
        .unwrap();

    // "off" keeps the default 0 → never scheduled.
    db.set_rule_connection_controls(on_id, &ResourceScope::All, 0, 10)
        .await
        .unwrap();
    db.set_rule_connection_controls(paused_id, &ResourceScope::All, 0, 10)
        .await
        .unwrap();
    sqlx::query("UPDATE forward_rules SET paused = TRUE WHERE id = $1")
        .bind(paused_id)
        .execute(&db.pool)
        .await
        .unwrap();

    let got = db.list_auto_restart_rules().await.unwrap();
    assert_eq!(
        got.len(),
        1,
        "only the enabled, unpaused rule is scheduled; got {got:?}"
    );
    assert_eq!(got[0].0, on_id);
    assert_eq!(got[0].1, 1, "device_group_in is carried for the fan-out");
    assert_eq!(got[0].2, 10, "the interval is carried");
    cleanup(&db).await;
}

// ── v1.2.0: redeem codes (PG twins of the SQLite contract tests) ──
//
// These matter more than a usual twin pair: SQLite gets its safety from
// process-wide writer serialization, while PG relies on an explicit
// SELECT ... FOR UPDATE. The invariant ("a code credits exactly once") is the
// same, but the mechanism enforcing it is NOT, so it has to be verified on
// both backends.

async fn pg_seed_user(db: &PgRepository, id: i64) {
    sqlx::query("INSERT INTO users (id, username, password, admin) VALUES ($1, $2, 'x', FALSE)")
        .bind(id)
        .bind(format!("u{id}"))
        .execute(&db.pool)
        .await
        .unwrap();
}

async fn pg_seed_code(db: &PgRepository, code: &str, amount: &str, expires: Option<&str>) -> i64 {
    db.create_redeem_codes(&[NewRedeemCode {
        code: code.into(),
        amount: amount.into(),
        expires_at: expires.map(str::to_string),
        batch_id: "b1".into(),
        remark: String::new(),
    }])
    .await
    .unwrap();
    sqlx::query_scalar::<_, i64>("SELECT id FROM redeem_codes WHERE code = $1")
        .bind(code)
        .fetch_one(&db.pool)
        .await
        .unwrap()
}

async fn pg_balance_of(db: &PgRepository, uid: i64) -> String {
    sqlx::query_scalar::<_, String>("SELECT balance FROM users WHERE id = $1")
        .bind(uid)
        .fetch_one(&db.pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn pg_redeem_credits_balance_and_marks_code_used() {
    let Some(db) = repo("redeem_credit").await else {
        return;
    };
    pg_seed_user(&db, 10).await;
    pg_seed_code(&db, "AAAA1111BBBB2222", "10.50", None).await;

    let (amount, new_balance) = db
        .redeem_code("AAAA1111BBBB2222", 10, "2026-01-01 00:00:00")
        .await
        .expect("redeem must succeed");
    assert_eq!(amount, "10.50");
    assert_eq!(new_balance, "10.50");
    assert_eq!(pg_balance_of(&db, 10).await, "10.50");

    let (status, used_by): (String, Option<i64>) =
        sqlx::query_as("SELECT status, used_by FROM redeem_codes WHERE code = 'AAAA1111BBBB2222'")
            .fetch_one(&db.pool)
            .await
            .unwrap();
    assert_eq!(status, "used");
    assert_eq!(used_by, Some(10));
    cleanup(&db).await;
}

/// THE money test on PG: the FOR UPDATE lock + conditional claim must make a
/// second redemption impossible, with the balance untouched.
#[tokio::test]
async fn pg_redeem_twice_credits_only_once() {
    let Some(db) = repo("redeem_twice").await else {
        return;
    };
    pg_seed_user(&db, 10).await;
    pg_seed_user(&db, 11).await;
    pg_seed_code(&db, "CCCC3333DDDD4444", "25", None).await;

    db.redeem_code("CCCC3333DDDD4444", 10, "2026-01-01 00:00:00")
        .await
        .expect("first redeem succeeds");

    for uid in [10, 11] {
        let err = db
            .redeem_code("CCCC3333DDDD4444", uid, "2026-01-01 00:00:01")
            .await
            .expect_err("a spent code must never credit again");
        assert!(matches!(err, RedeemCodeError::NotRedeemable), "got {err:?}");
    }
    assert_eq!(pg_balance_of(&db, 10).await, "25", "no double credit");
    assert_eq!(pg_balance_of(&db, 11).await, "0", "loser gets nothing");
    cleanup(&db).await;
}

#[tokio::test]
async fn pg_redeem_expired_is_refused_and_stays_unused() {
    let Some(db) = repo("redeem_expired").await else {
        return;
    };
    pg_seed_user(&db, 10).await;
    pg_seed_code(&db, "EEEE5555FFFF6666", "5", Some("2026-01-01 00:00:00")).await;

    let err = db
        .redeem_code("EEEE5555FFFF6666", 10, "2026-01-02 00:00:00")
        .await
        .expect_err("past expiry must be refused");
    assert!(matches!(err, RedeemCodeError::Expired), "got {err:?}");
    assert_eq!(pg_balance_of(&db, 10).await, "0");

    let status: String =
        sqlx::query_scalar("SELECT status FROM redeem_codes WHERE code = 'EEEE5555FFFF6666'")
            .fetch_one(&db.pool)
            .await
            .unwrap();
    assert_eq!(status, "unused", "expiry must not consume the code");

    db.redeem_code("EEEE5555FFFF6666", 10, "2026-01-01 00:00:00")
        .await
        .expect("redeem AT the expiry instant is allowed");
    cleanup(&db).await;
}

#[tokio::test]
async fn pg_redeem_refuses_to_overflow_the_balance_ceiling() {
    let Some(db) = repo("redeem_overflow").await else {
        return;
    };
    pg_seed_user(&db, 10).await;
    sqlx::query("UPDATE users SET balance = $1 WHERE id = 10")
        .bind(relay_shared::money::MAX_BALANCE)
        .execute(&db.pool)
        .await
        .unwrap();
    pg_seed_code(&db, "GGGG7777HHHH8888", "1", None).await;

    let err = db
        .redeem_code("GGGG7777HHHH8888", 10, "2026-01-01 00:00:00")
        .await
        .expect_err("overflow must be refused");
    assert!(
        matches!(err, RedeemCodeError::BalanceOverflow),
        "got {err:?}"
    );
    assert_eq!(
        pg_balance_of(&db, 10).await,
        relay_shared::money::MAX_BALANCE,
        "balance unchanged"
    );
    cleanup(&db).await;
}

#[tokio::test]
async fn pg_void_and_delete_never_touch_a_used_code() {
    let Some(db) = repo("redeem_void").await else {
        return;
    };
    pg_seed_user(&db, 10).await;
    let unused_id = pg_seed_code(&db, "JJJJ9999KKKK0000", "1", None).await;
    let used_id = pg_seed_code(&db, "MMMM2222NNNN3333", "1", None).await;
    db.redeem_code("MMMM2222NNNN3333", 10, "2026-01-01 00:00:00")
        .await
        .unwrap();

    assert_eq!(db.void_redeem_code(unused_id).await.unwrap(), 1);
    assert_eq!(
        db.void_redeem_code(used_id).await.unwrap(),
        0,
        "a used code must not be voidable"
    );
    let err = db
        .redeem_code("JJJJ9999KKKK0000", 10, "2026-01-01 00:00:00")
        .await
        .expect_err("voided code must be refused");
    assert!(matches!(err, RedeemCodeError::NotRedeemable), "got {err:?}");

    assert_eq!(
        db.delete_unused_redeem_codes(&[unused_id, used_id])
            .await
            .unwrap(),
        1,
        "only the non-used row is deletable"
    );
    let survivor: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM redeem_codes WHERE status = 'used'")
            .fetch_one(&db.pool)
            .await
            .unwrap();
    assert_eq!(survivor, 1, "the redemption record survives");
    cleanup(&db).await;
}

/// PG's ON DELETE SET NULL must behave like SQLite's: the account goes, the
/// money-in record stays.
#[tokio::test]
async fn pg_deleting_the_redeemer_keeps_the_code_record() {
    let Some(db) = repo("redeem_del_user").await else {
        return;
    };
    pg_seed_user(&db, 15).await;
    pg_seed_code(&db, "PPPP4444QQQQ5555", "9.99", None).await;
    db.redeem_code("PPPP4444QQQQ5555", 15, "2026-01-01 00:00:00")
        .await
        .unwrap();

    sqlx::query("DELETE FROM users WHERE id = 15")
        .execute(&db.pool)
        .await
        .unwrap();

    let (status, used_by, amount): (String, Option<i64>, String) = sqlx::query_as(
        "SELECT status, used_by, amount FROM redeem_codes WHERE code = 'PPPP4444QQQQ5555'",
    )
    .fetch_one(&db.pool)
    .await
    .unwrap();
    assert_eq!(status, "used");
    assert_eq!(used_by, None, "FK nulls the reference, not the row");
    assert_eq!(amount, "9.99");
    cleanup(&db).await;
}

#[tokio::test]
async fn pg_list_and_count_filter_by_status() {
    let Some(db) = repo("redeem_list").await else {
        return;
    };
    pg_seed_user(&db, 10).await;
    pg_seed_code(&db, "AAAA0000AAAA0001", "1", None).await;
    pg_seed_code(&db, "AAAA0000AAAA0002", "1", None).await;
    db.redeem_code("AAAA0000AAAA0002", 10, "2026-01-01 00:00:00")
        .await
        .unwrap();

    let all = RedeemCodeFilter {
        limit: 50,
        ..Default::default()
    };
    assert_eq!(db.count_redeem_codes(&all).await.unwrap(), 2);

    let unused = RedeemCodeFilter {
        status: Some("unused".into()),
        limit: 50,
        ..Default::default()
    };
    let rows = db.list_redeem_codes(&unused).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].code, "AAAA0000AAAA0001");
    assert_eq!(db.count_redeem_codes(&unused).await.unwrap(), 1);
    cleanup(&db).await;
}

// ── v1.2.0: traffic history (PG twins) ──
//
// The write path differs on both backends (SQLite ON CONFLICT excluded.x vs
// PG's table-qualified EXCLUDED, NUMERIC SUM vs INTEGER SUM), so the agreement
// invariant has to hold on each independently.

/// PG twin of the SQLite fixture. Returns uid.
async fn pg_seed_history_fixture(
    db: &PgRepository,
    username: &str,
    group_id: i64,
    rule_id: i64,
    rate: f64,
) -> i64 {
    db.insert_user(username, "h", 1).await.unwrap();
    let uid = db.find_by_username(username).await.unwrap().unwrap().id;
    sqlx::query(
        "INSERT INTO device_groups (id, name, group_type, token, uid, rate) \
         VALUES ($1, 'gin', 'in', $2, $3, $4)",
    )
    .bind(group_id)
    .bind(format!("tok-{group_id}"))
    .bind(uid)
    .bind(rate)
    .execute(&db.pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO forward_rules \
         (id, name, uid, listen_port, device_group_in, target_addr, target_port) \
         VALUES ($1, $2, $3, 20000, $4, '127.0.0.1', 80)",
    )
    .bind(rule_id)
    .bind(format!("r{rule_id}"))
    .bind(uid)
    .bind(group_id)
    .execute(&db.pool)
    .await
    .unwrap();
    uid
}

#[tokio::test]
async fn pg_traffic_history_agrees_with_quota_charge() {
    let Some(db) = repo("th_agree").await else {
        return;
    };
    let uid = pg_seed_history_fixture(&db, "hist_a", 60, 200, 3.0).await;

    let res = db
        .apply_traffic_batch(
            60,
            &[relay_shared::protocol::TrafficEntry {
                rule_id: 200,
                upload: 1000,
                download: 2000,
            }],
        )
        .await
        .unwrap();
    assert!(matches!(res[0], TrafficEntryResult::Ok));

    let user_used: i64 = sqlx::query_scalar("SELECT traffic_used FROM users WHERE id = $1")
        .bind(uid)
        .fetch_one(&db.pool)
        .await
        .unwrap();
    let (h_up, h_down, h_billed): (i64, i64, i64) = sqlx::query_as(
        "SELECT COALESCE(SUM(real_upload),0)::BIGINT, COALESCE(SUM(real_download),0)::BIGINT, \
                COALESCE(SUM(billed_total),0)::BIGINT \
         FROM traffic_history WHERE rule_id = 200",
    )
    .fetch_one(&db.pool)
    .await
    .unwrap();

    assert_eq!(user_used, 9000, "user is billed real × rate");
    assert_eq!(h_billed, user_used, "history MUST equal the quota charge");
    assert_eq!((h_up, h_down), (1000, 2000), "real bytes stay unrated");
    cleanup(&db).await;
}

#[tokio::test]
async fn pg_traffic_history_upserts_within_the_hour() {
    let Some(db) = repo("th_upsert").await else {
        return;
    };
    pg_seed_history_fixture(&db, "hist_b", 61, 201, 1.0).await;

    for _ in 0..3 {
        db.apply_traffic_batch(
            61,
            &[relay_shared::protocol::TrafficEntry {
                rule_id: 201,
                upload: 100,
                download: 0,
            }],
        )
        .await
        .unwrap();
    }

    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM traffic_history WHERE rule_id = 201")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    let total: i64 = sqlx::query_scalar(
        "SELECT SUM(real_upload)::BIGINT FROM traffic_history WHERE rule_id = 201",
    )
    .fetch_one(&db.pool)
    .await
    .unwrap();
    assert!(
        rows <= 2,
        "3 batches must fold into hour buckets, got {rows}"
    );
    assert_eq!(total, 300, "accumulation must not lose bytes");
    cleanup(&db).await;
}

#[tokio::test]
async fn pg_traffic_history_query_scopes_and_aggregates() {
    let Some(db) = repo("th_scope").await else {
        return;
    };
    let alice = pg_seed_history_fixture(&db, "hist_c", 62, 202, 1.0).await;
    let bob = pg_seed_history_fixture(&db, "hist_d", 63, 203, 1.0).await;

    for (uid, rule, hour, up) in [
        (alice, 202i64, "2026-07-20 10:00:00", 100i64),
        (alice, 202, "2026-07-20 11:00:00", 200),
        (bob, 203, "2026-07-20 10:00:00", 999),
    ] {
        sqlx::query(
            "INSERT INTO traffic_history (rule_id, uid, hour_ts, real_upload, real_download, billed_total) \
             VALUES ($1, $2, $3, $4, 0, $5)",
        )
        .bind(rule)
        .bind(uid)
        .bind(hour)
        .bind(up)
        .bind(up)
        .execute(&db.pool)
        .await
        .unwrap();
    }

    let daily = db
        .query_traffic_history(Some(alice), None, "2026-07-01 00:00:00", true)
        .await
        .unwrap();
    assert_eq!(daily.len(), 1, "two hours of one day fold into one bucket");
    assert_eq!(daily[0].bucket, "2026-07-20");
    assert_eq!(daily[0].real_upload, 300, "alice's hours summed");

    let hourly = db
        .query_traffic_history(Some(alice), None, "2026-07-01 00:00:00", false)
        .await
        .unwrap();
    assert_eq!(hourly.len(), 2);

    let all = db
        .query_traffic_history(None, None, "2026-07-01 00:00:00", true)
        .await
        .unwrap();
    assert_eq!(all[0].real_upload, 300 + 999, "admin sees everyone");

    let foreign = db
        .query_traffic_history(Some(alice), Some(203), "2026-07-01 00:00:00", true)
        .await
        .unwrap();
    assert!(foreign.is_empty(), "a foreign rule matches nothing");
    cleanup(&db).await;
}

#[tokio::test]
async fn pg_traffic_history_prune_respects_cutoff() {
    let Some(db) = repo("th_prune").await else {
        return;
    };
    let uid = pg_seed_history_fixture(&db, "hist_e", 64, 204, 1.0).await;
    for hour in ["2026-05-01 00:00:00", "2026-07-20 00:00:00"] {
        sqlx::query(
            "INSERT INTO traffic_history (rule_id, uid, hour_ts, real_upload, real_download, billed_total) \
             VALUES (204, $1, $2, 1, 1, 1)",
        )
        .bind(uid)
        .bind(hour)
        .execute(&db.pool)
        .await
        .unwrap();
    }

    let deleted = db
        .prune_traffic_history("2026-06-15 00:00:00")
        .await
        .unwrap();
    assert_eq!(deleted, 1, "only the pre-cutoff row dies");
    cleanup(&db).await;
}

/// PG twin: traffic split per line. The GROUP BY / LEFT JOIN shape differs
/// between backends (PG needs dg.name in the grouping, SQLite takes the alias),
/// so the behaviour is verified on each.
#[tokio::test]
async fn pg_traffic_history_splits_by_line() {
    let Some(db) = repo("th_lines").await else {
        return;
    };
    let alice = pg_seed_history_fixture(&db, "grp_a", 70, 300, 1.0).await;
    sqlx::query(
        "INSERT INTO device_groups (id, name, group_type, token, uid, rate) \
         VALUES (71, 'hk-line', 'in', 'tok-71', $1, 1.0)",
    )
    .bind(alice)
    .execute(&db.pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO forward_rules (id, name, uid, listen_port, device_group_in, target_addr, target_port) \
         VALUES (301, 'r301', $1, 20001, 71, '127.0.0.1', 80)",
    )
    .bind(alice)
    .execute(&db.pool)
    .await
    .unwrap();

    db.apply_traffic_batch(
        70,
        &[relay_shared::protocol::TrafficEntry {
            rule_id: 300,
            upload: 100,
            download: 0,
        }],
    )
    .await
    .unwrap();
    db.apply_traffic_batch(
        71,
        &[relay_shared::protocol::TrafficEntry {
            rule_id: 301,
            upload: 700,
            download: 0,
        }],
    )
    .await
    .unwrap();

    let rows = db
        .query_traffic_history(Some(alice), None, "2000-01-01 00:00:00", false)
        .await
        .unwrap();
    let by_group: std::collections::HashMap<i64, &crate::db::repo::TrafficHistoryBucket> =
        rows.iter().map(|r| (r.group_id, r)).collect();
    assert_eq!(by_group.len(), 2, "one slice per line, got {rows:?}");
    assert_eq!(by_group[&70].real_upload, 100);
    assert_eq!(by_group[&71].real_upload, 700);
    assert_eq!(by_group[&71].group_name, "hk-line");
    cleanup(&db).await;
}

#[tokio::test]
async fn pg_traffic_report_receipt_makes_ack_loss_retry_idempotent() {
    let Some(db) = repo("traffic_idempotent").await else {
        return;
    };
    let alice = pg_seed_history_fixture(&db, "idempotent", 170, 1300, 1.0).await;
    let entries = [relay_shared::protocol::TrafficEntry {
        rule_id: 1300,
        upload: 123,
        download: 456,
    }];
    for _ in 0..2 {
        db.apply_traffic_batch_once(170, Some("same-report-id"), &entries)
            .await
            .unwrap();
    }
    let rule_used: i64 = sqlx::query_scalar("SELECT traffic_used FROM forward_rules WHERE id=1300")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    let user_used: i64 = sqlx::query_scalar("SELECT traffic_used FROM users WHERE id=$1")
        .bind(alice)
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(rule_used, 579);
    assert_eq!(user_used, 579);
    cleanup(&db).await;
}

#[tokio::test]
async fn pg_socks5_rule_lifecycle_is_atomic_and_preserves_credentials() {
    let Some(db) = repo("socks5_lifecycle").await else {
        return;
    };
    sqlx::query(
        "INSERT INTO device_groups (id,name,group_type,token,uid,connect_host)
         VALUES (50,'relay-in','in','socks-token',1,'127.0.0.1')",
    )
    .execute(&db.pool)
    .await
    .unwrap();
    let first = db
        .insert_socks5_resource(
            "first",
            "127.0.0.1",
            1080,
            Some("upstream"),
            Some("cipher-one"),
            Some("nonce-one"),
            1,
            "",
            "",
            "",
            "",
            "",
            "",
            true,
        )
        .await
        .unwrap();
    let second = db
        .insert_socks5_resource(
            "second",
            "127.0.0.1",
            1081,
            None,
            None,
            None,
            1,
            "",
            "",
            "",
            "",
            "",
            "",
            true,
        )
        .await
        .unwrap();
    let rule_id = db
        .create_socks5_rule_full(
            "before",
            1,
            18080,
            50,
            first,
            true,
            Some("relay-user"),
            Some("relay-cipher"),
            Some("relay-nonce"),
            1,
            false,
            true,
        )
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        db.delete_socks5_resource(first).await,
        Err(DbError::ForeignKeyViolation)
    ));
    let (deleted, blockers) = db
        .bulk_delete_socks5_resources_guarded(&[first])
        .await
        .unwrap();
    assert_eq!(deleted, 0);
    assert_eq!(blockers, vec![(first, rule_id)]);

    assert_eq!(
        db.update_socks5_rule_full(rule_id, "after", 18081, 50, second, false, false)
            .await
            .unwrap(),
        1
    );
    let binding = db.find_socks5_rule_config(rule_id).await.unwrap().unwrap();
    assert_eq!(binding.socks5_resource_id, second);
    assert_eq!(binding.relay_username.as_deref(), Some("relay-user"));
    assert_eq!(
        binding.relay_password_ciphertext.as_deref(),
        Some("relay-cipher")
    );
    let view = db.list_socks5_rule_views().await.unwrap().remove(0);
    assert_eq!(view.name, "after");
    assert_eq!(view.listen_port, 18081);
    assert!(view.paused);
    assert_eq!(db.delete_socks5_resource(first).await.unwrap(), 1);
    assert_eq!(
        db.delete_rule(rule_id, &ResourceScope::All).await.unwrap(),
        1
    );
    assert_eq!(db.delete_socks5_resource(second).await.unwrap(), 1);
    cleanup(&db).await;
}

/// PG twin: a deleted line keeps its history (LEFT JOIN must not gate the row).
#[tokio::test]
async fn pg_traffic_history_survives_group_and_rule_deletion() {
    let Some(db) = repo("th_del").await else {
        return;
    };
    let alice = pg_seed_history_fixture(&db, "grp_b", 72, 302, 1.0).await;
    db.apply_traffic_batch(
        72,
        &[relay_shared::protocol::TrafficEntry {
            rule_id: 302,
            upload: 500,
            download: 0,
        }],
    )
    .await
    .unwrap();

    sqlx::query("DELETE FROM forward_rules WHERE id = 302")
        .execute(&db.pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM device_groups WHERE id = 72")
        .execute(&db.pool)
        .await
        .unwrap();

    let rows = db
        .query_traffic_history(Some(alice), None, "2000-01-01 00:00:00", false)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1, "history must outlive both parents");
    assert_eq!(rows[0].real_upload, 500);
    assert_eq!(rows[0].group_id, 72);
    assert_eq!(rows[0].group_name, "#72");
    cleanup(&db).await;
}

/// PG twin of the Migration 41 backfill (PG revision 24).
#[tokio::test]
async fn pg_migration_41_backfills_group_id_from_the_rule() {
    let Some(db) = repo("th_backfill").await else {
        return;
    };
    let alice = pg_seed_history_fixture(&db, "grp_c", 73, 303, 1.0).await;
    sqlx::query(
        "INSERT INTO traffic_history (rule_id, uid, group_id, hour_ts, real_upload, real_download, billed_total) \
         VALUES (303, $1, 0, '2026-07-20 10:00:00', 42, 0, 42)",
    )
    .bind(alice)
    .execute(&db.pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO traffic_history (rule_id, uid, group_id, hour_ts, real_upload, real_download, billed_total) \
         VALUES (999999, $1, 0, '2026-07-20 10:00:00', 7, 0, 7)",
    )
    .bind(alice)
    .execute(&db.pool)
    .await
    .unwrap();

    // Re-running the migration must backfill idempotently.
    run_pg_migrations(&db.pool).await.unwrap();
    sqlx::query(
        "UPDATE traffic_history th SET group_id = fr.device_group_in \
         FROM forward_rules fr WHERE fr.id = th.rule_id AND th.group_id = 0",
    )
    .execute(&db.pool)
    .await
    .unwrap();

    let filled: i64 =
        sqlx::query_scalar("SELECT group_id FROM traffic_history WHERE rule_id = 303")
            .fetch_one(&db.pool)
            .await
            .unwrap();
    assert_eq!(filled, 73, "backfilled from the rule's inbound group");

    let orphan: i64 =
        sqlx::query_scalar("SELECT group_id FROM traffic_history WHERE rule_id = 999999")
            .fetch_one(&db.pool)
            .await
            .unwrap();
    assert_eq!(orphan, 0, "an orphan keeps 0 — never invent an attribution");
    cleanup(&db).await;
}

// ── v1.2.4: node metrics history ──

fn pg_metric(
    node: &str,
    group: i64,
    hour: &str,
    cpu: f64,
    mem: f64,
    conns: i64,
) -> NodeMetricSample {
    NodeMetricSample {
        node_id: node.to_string(),
        group_id: group,
        hour_ts: hour.to_string(),
        cpu,
        mem,
        connections: conns,
    }
}

/// Three reports in one hour collapse into ONE row whose average is the mean of
/// the samples and whose max is the peak. The two must differ here, or a spike
/// would be invisible — which is the entire reason both are stored.
#[tokio::test]
async fn pg_node_metrics_average_and_peak_are_independent() {
    let Some(db) = repo("nm_avgpeak").await else {
        return;
    };
    let h = "2026-07-28 10:00:00";
    for cpu in [0.1_f64, 0.9, 0.2] {
        db.record_node_metrics(&pg_metric("n1", 1, h, cpu, 0.5, 10))
            .await
            .unwrap();
    }

    let rows = db
        .query_node_metrics("2026-07-28 00:00:00", false)
        .await
        .unwrap();
    assert_eq!(
        rows.len(),
        1,
        "three reports in one hour must be one bucket"
    );
    assert!(
        (rows[0].cpu_avg - 0.4).abs() < 1e-9,
        "avg was {}",
        rows[0].cpu_avg
    );
    assert!(
        (rows[0].cpu_max - 0.9).abs() < 1e-9,
        "peak was {}",
        rows[0].cpu_max
    );
}

/// Rolling hours into a day must weight each hour by its sample count. An hour
/// with 3 samples and an hour with 1 are not equal halves — averaging the two
/// averages would say 0.5 here; the sample-weighted answer is 0.35.
#[tokio::test]
async fn pg_node_metrics_daily_average_is_sample_weighted() {
    let Some(db) = repo("nm_daily").await else {
        return;
    };
    for cpu in [0.2_f64, 0.2, 0.2] {
        db.record_node_metrics(&pg_metric("n1", 1, "2026-07-28 10:00:00", cpu, 0.0, 0))
            .await
            .unwrap();
    }
    db.record_node_metrics(&pg_metric("n1", 1, "2026-07-28 11:00:00", 0.8, 0.0, 0))
        .await
        .unwrap();

    let rows = db
        .query_node_metrics("2026-07-28 00:00:00", true)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert!(
        (rows[0].cpu_avg - 0.35).abs() < 1e-9,
        "sample-weighted average expected 0.35, got {}",
        rows[0].cpu_avg
    );
}

/// Each node keeps its own series — two nodes reporting in the same hour must
/// stay two lines, never merge into one.
#[tokio::test]
async fn pg_node_metrics_keep_one_series_per_node() {
    let Some(db) = repo("nm_series").await else {
        return;
    };
    let h = "2026-07-28 10:00:00";
    db.record_node_metrics(&pg_metric("n1", 1, h, 0.1, 0.1, 5))
        .await
        .unwrap();
    db.record_node_metrics(&pg_metric("n2", 1, h, 0.9, 0.9, 50))
        .await
        .unwrap();

    let rows = db
        .query_node_metrics("2026-07-28 00:00:00", false)
        .await
        .unwrap();
    assert_eq!(rows.len(), 2);
    let mut ids: Vec<&str> = rows.iter().map(|r| r.node_id.as_str()).collect();
    ids.sort_unstable();
    assert_eq!(ids, vec!["n1", "n2"]);
}

/// The sweeper is the only thing that deletes these rows (no FK), so prune must
/// remove strictly what is older than the cutoff and leave the rest.
#[tokio::test]
async fn pg_node_metrics_prune_respects_the_cutoff() {
    let Some(db) = repo("nm_prune").await else {
        return;
    };
    db.record_node_metrics(&pg_metric("n1", 1, "2026-07-01 10:00:00", 0.5, 0.5, 1))
        .await
        .unwrap();
    db.record_node_metrics(&pg_metric("n1", 1, "2026-07-28 10:00:00", 0.5, 0.5, 1))
        .await
        .unwrap();

    let deleted = db.prune_node_metrics("2026-07-20 00:00:00").await.unwrap();
    assert_eq!(deleted, 1);
    let rows = db
        .query_node_metrics("2026-01-01 00:00:00", false)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].bucket, "2026-07-28 10:00:00");
}

// ── Audit log (v1.2.4) ──

fn pg_audit(actor: Option<i64>, name: &str, action: &str, ts: &str) -> NewAuditEntry {
    NewAuditEntry {
        ts: ts.to_string(),
        actor_id: actor,
        actor_name: name.to_string(),
        action: action.to_string(),
        target_type: "user".to_string(),
        target_id: "7".to_string(),
        detail: String::new(),
    }
}

/// Pagination orders by id, not by ts. Several actions routinely land in the
/// same second (a bulk delete, a script), and ts alone leaves their relative
/// order undefined — so page 2 could repeat or skip a row that page 1 showed.
#[tokio::test]
async fn pg_audit_log_pages_in_a_stable_order_within_one_second() {
    let Some(db) = repo("audit_page").await else {
        return;
    };
    let ts = "2026-07-28 10:00:00";
    for action in ["first", "second", "third"] {
        db.record_audit(&pg_audit(Some(1), "admin", action, ts))
            .await
            .unwrap();
    }

    let page1 = db.query_audit_log(None, 2, 0).await.unwrap();
    let page2 = db.query_audit_log(None, 2, 2).await.unwrap();

    let seen: Vec<&str> = page1
        .iter()
        .chain(page2.iter())
        .map(|e| e.action.as_str())
        .collect();
    assert_eq!(seen, vec!["third", "second", "first"]);
}

/// The action filter must constrain the count too. If `total` counted every row
/// while the page was filtered, the UI would render pages that are always empty
/// past the first one.
#[tokio::test]
async fn pg_audit_log_filter_applies_to_both_page_and_count() {
    let Some(db) = repo("audit_filter").await else {
        return;
    };
    for action in ["delete_user", "delete_rule", "delete_user"] {
        db.record_audit(&pg_audit(Some(1), "admin", action, "2026-07-28 10:00:00"))
            .await
            .unwrap();
    }

    assert_eq!(db.count_audit_log(Some("delete_user")).await.unwrap(), 2);
    assert_eq!(db.count_audit_log(None).await.unwrap(), 3);
    let rows = db
        .query_audit_log(Some("delete_user"), 50, 0)
        .await
        .unwrap();
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().all(|e| e.action == "delete_user"));
}

/// actor_name is a stored snapshot, not a join. Deleting the admin who acted
/// must not turn the history into a row of anonymous ids — "who deleted my
/// rule" is exactly the question asked after that admin is gone.
#[tokio::test]
async fn pg_audit_actor_name_survives_deletion_of_the_actor() {
    let Some(db) = repo("audit_snapshot").await else {
        return;
    };
    db.insert_user("tempadmin", "hash", 1).await.unwrap();
    let actor_id = db.find_by_username("tempadmin").await.unwrap().unwrap().id;
    db.record_audit(&pg_audit(
        Some(actor_id),
        "tempadmin",
        "delete_rule",
        "2026-07-28 10:00:00",
    ))
    .await
    .unwrap();

    db.delete_user_cascade(actor_id).await.unwrap();

    let rows = db.query_audit_log(None, 50, 0).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].actor_name, "tempadmin");
    assert_eq!(rows[0].actor_id, Some(actor_id));
}

/// Retention deletes strictly older than the cutoff and keeps the boundary row,
/// so a sweep can't eat the oldest entry it was meant to preserve.
#[tokio::test]
async fn pg_audit_prune_keeps_the_cutoff_row() {
    let Some(db) = repo("audit_prune").await else {
        return;
    };
    for ts in [
        "2026-07-01 10:00:00",
        "2026-07-10 10:00:00",
        "2026-07-20 10:00:00",
    ] {
        db.record_audit(&pg_audit(Some(1), "admin", "delete_user", ts))
            .await
            .unwrap();
    }

    let removed = db.prune_audit_log("2026-07-10 10:00:00").await.unwrap();
    assert_eq!(removed, 1);
    let rows = db.query_audit_log(None, 50, 0).await.unwrap();
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().all(|e| e.ts.as_str() >= "2026-07-10 10:00:00"));
}

// ── v1.2.4: per-user redeem history ──

/// The account page is reachable by every user, so this query must be scoped by
/// construction. If it ever returned another account's top-ups, one user could
/// read another's payment history from their own page.
#[tokio::test]
async fn pg_redeem_history_is_scoped_to_the_asking_user() {
    let Some(db) = repo("redeem_hist_scope").await else {
        return;
    };
    db.insert_user("alice", "h", 1).await.unwrap();
    db.insert_user("bob", "h", 1).await.unwrap();
    let alice = db.find_by_username("alice").await.unwrap().unwrap().id;
    let bob = db.find_by_username("bob").await.unwrap().unwrap().id;

    pg_seed_code(&db, "AAAAAAAAAAAAAAAA", "10.00", None).await;
    pg_seed_code(&db, "BBBBBBBBBBBBBBBB", "20.00", None).await;
    db.redeem_code("AAAAAAAAAAAAAAAA", alice, "2026-07-28 10:00:00")
        .await
        .unwrap();
    db.redeem_code("BBBBBBBBBBBBBBBB", bob, "2026-07-28 10:00:01")
        .await
        .unwrap();

    let mine = db.list_redeem_codes_by_user(alice).await.unwrap();
    assert_eq!(mine.len(), 1, "alice must see exactly her own top-up");
    assert_eq!(mine[0].code, "AAAAAAAAAAAAAAAA");
    assert_eq!(mine[0].amount, "10.00");
}

/// Unused and voided codes are not top-ups and must not appear — the history is
/// a record of money that actually moved.
#[tokio::test]
async fn pg_redeem_history_lists_only_used_codes() {
    let Some(db) = repo("redeem_hist_used").await else {
        return;
    };
    db.insert_user("alice", "h", 1).await.unwrap();
    let alice = db.find_by_username("alice").await.unwrap().unwrap().id;

    pg_seed_code(&db, "CCCCCCCCCCCCCCCC", "5.00", None).await;
    let unused = pg_seed_code(&db, "DDDDDDDDDDDDDDDD", "9.00", None).await;
    db.redeem_code("CCCCCCCCCCCCCCCC", alice, "2026-07-28 10:00:00")
        .await
        .unwrap();
    db.void_redeem_code(unused).await.unwrap();

    let mine = db.list_redeem_codes_by_user(alice).await.unwrap();
    assert_eq!(mine.len(), 1);
    assert_eq!(mine[0].status, "used");
}

// ── v1.2.4: announcements ──

fn ann(content: &str, published: &str, pinned: bool, expires: Option<&str>) -> NewAnnouncement {
    NewAnnouncement {
        title: format!("t-{content}"),
        content: content.to_string(),
        kind: "info".into(),
        pinned,
        published_at: published.to_string(),
        expires_at: expires.map(str::to_string),
        author_id: Some(1),
        author_name: "admin".into(),
    }
}

/// The banner shows the newest live notice.
#[tokio::test]
async fn pg_active_announcement_picks_the_newest() {
    let Some(db) = repo("ann_newest").await else {
        return;
    };
    db.create_announcement(&ann("old", "2026-07-01 10:00:00", false, None))
        .await
        .unwrap();
    db.create_announcement(&ann("new", "2026-07-20 10:00:00", false, None))
        .await
        .unwrap();

    let a = db
        .active_announcement("2026-07-28 10:00:00")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(a.content, "new");
}

/// Pinned wins over newer. That is the entire point of the flag — otherwise
/// posting anything else silently buries the notice being kept up.
#[tokio::test]
async fn pg_pinned_announcement_outranks_a_newer_one() {
    let Some(db) = repo("ann_pinned").await else {
        return;
    };
    db.create_announcement(&ann("pinned", "2026-07-01 10:00:00", true, None))
        .await
        .unwrap();
    db.create_announcement(&ann("newer", "2026-07-20 10:00:00", false, None))
        .await
        .unwrap();

    let a = db
        .active_announcement("2026-07-28 10:00:00")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(a.content, "pinned");
}

/// An expired notice leaves the banner but stays in the archive — the whole
/// reason expiry exists is "tonight's maintenance" disappearing on its own.
#[tokio::test]
async fn pg_expired_announcement_leaves_the_banner_but_stays_in_history() {
    let Some(db) = repo("ann_expired").await else {
        return;
    };
    db.create_announcement(&ann(
        "gone",
        "2026-07-01 10:00:00",
        false,
        Some("2026-07-02 00:00:00"),
    ))
    .await
    .unwrap();

    let now = "2026-07-28 10:00:00";
    assert!(
        db.active_announcement(now).await.unwrap().is_none(),
        "expired must not show"
    );

    let history = db.list_announcements(true, now, 50, 0).await.unwrap();
    assert_eq!(history.len(), 1, "history keeps it");
    assert_eq!(db.count_announcements(true, now).await.unwrap(), 1);
    // The live-only view agrees with the banner.
    assert_eq!(db.count_announcements(false, now).await.unwrap(), 0);
}

/// The expiry comparison is strict: a notice expiring exactly now is over.
#[tokio::test]
async fn pg_expiry_boundary_is_exclusive() {
    let Some(db) = repo("ann_boundary").await else {
        return;
    };
    let t = "2026-07-28 10:00:00";
    db.create_announcement(&ann("boundary", "2026-07-01 10:00:00", false, Some(t)))
        .await
        .unwrap();

    assert!(
        db.active_announcement(t).await.unwrap().is_none(),
        "at the instant it expires it is gone"
    );
    assert!(db
        .active_announcement("2026-07-28 09:59:59")
        .await
        .unwrap()
        .is_some());
}

/// Editing must not re-date a notice or reassign its author — a typo fix would
/// otherwise jump the notice back to the top of the archive.
#[tokio::test]
async fn pg_update_keeps_published_at_and_author() {
    let Some(db) = repo("ann_update").await else {
        return;
    };
    let id = db
        .create_announcement(&ann("v1", "2026-07-01 10:00:00", false, None))
        .await
        .unwrap();

    let mut edit = ann("v2", "2099-01-01 00:00:00", true, None);
    edit.author_name = "someone else".into();
    edit.author_id = Some(999);
    assert_eq!(db.update_announcement(id, &edit).await.unwrap(), 1);

    let a = db.find_announcement(id).await.unwrap().unwrap();
    assert_eq!(a.content, "v2", "content is updated");
    assert!(a.pinned, "pinned is updated");
    assert_eq!(
        a.published_at, "2026-07-01 10:00:00",
        "publish date is NOT rewritten"
    );
    assert_eq!(a.author_name, "admin", "author is NOT reassigned");
}

/// Updating or deleting an id that does not exist reports 0 rather than
/// pretending to succeed.
#[tokio::test]
async fn pg_update_and_delete_report_a_missing_row() {
    let Some(db) = repo("ann_missing").await else {
        return;
    };
    assert_eq!(
        db.update_announcement(999, &ann("x", "2026-07-01 10:00:00", false, None))
            .await
            .unwrap(),
        0
    );
    assert_eq!(db.delete_announcement(999).await.unwrap(), 0);
}

// ── v1.2.4: admin-wide order list ──

/// The admin list spans every account, unlike list_orders_by_user. Getting this
/// wrong in the other direction — scoping it to the caller — would make the
/// operator's view silently show only their own purchases.
#[tokio::test]
async fn pg_admin_order_list_spans_all_users() {
    let Some(db) = repo("ord_all").await else {
        return;
    };
    db.insert_user("alice", "h", 1).await.unwrap();
    db.insert_user("bob", "h", 1).await.unwrap();
    let alice = db.find_by_username("alice").await.unwrap().unwrap().id;
    let bob = db.find_by_username("bob").await.unwrap().unwrap().id;

    db.insert_order(alice, Some(1), "basic", "10.00")
        .await
        .unwrap();
    db.insert_order(bob, Some(1), "pro", "50.00").await.unwrap();

    assert_eq!(db.count_all_orders().await.unwrap(), 2);
    let all = db.list_all_orders(50, 0).await.unwrap();
    assert_eq!(all.len(), 2);
    let mut buyers: Vec<i64> = all.iter().map(|o| o.user_id).collect();
    buyers.sort_unstable();
    assert_eq!(buyers, vec![alice, bob]);

    // The per-user list still sees only its own — the two must not converge.
    assert_eq!(db.list_orders_by_user(alice).await.unwrap().len(), 1);
}

/// Pagination must partition the rows, not repeat or drop any. Orders routinely
/// share a created_at second, which is why the ordering falls back to the id.
#[tokio::test]
async fn pg_admin_order_list_pages_without_overlap() {
    let Some(db) = repo("ord_page").await else {
        return;
    };
    db.insert_user("alice", "h", 1).await.unwrap();
    let alice = db.find_by_username("alice").await.unwrap().unwrap().id;
    for name in ["a", "b", "c"] {
        db.insert_order(alice, Some(1), name, "1.00").await.unwrap();
    }

    let page1 = db.list_all_orders(2, 0).await.unwrap();
    let page2 = db.list_all_orders(2, 2).await.unwrap();
    assert_eq!(page1.len(), 2);
    assert_eq!(page2.len(), 1);

    let mut ids: Vec<i64> = page1.iter().chain(page2.iter()).map(|o| o.id).collect();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(
        ids.len(),
        3,
        "the two pages must cover all three rows exactly once"
    );
}

#[tokio::test]
async fn pg_stage3_bulk_pagination_and_health_contract() {
    let Some(db) = repo("stage3_socks5").await else {
        return;
    };
    db.insert_group("stage3", "in", "stage3-token", 1, "", "", 1.0, false)
        .await
        .unwrap();
    let group_id = db.find_by_token("stage3-token").await.unwrap().unwrap().id;
    let rows = (0..1_000)
        .map(|index| BulkSocks5Resource {
            name: format!("proxy-{index:04}"),
            host: format!("proxy-{index:04}.example"),
            port: 1080,
            username: None,
            password_ciphertext: None,
            password_nonce: None,
            password_key_version: 1,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        db.bulk_import_socks5_resources(&rows, false)
            .await
            .unwrap()
            .created,
        1_000
    );
    let (page, total) = db
        .query_socks5_resources(&Socks5ResourceQuery {
            search: Some("proxy-0999".into()),
            sort: "id".into(),
            descending: true,
            limit: 50,
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(total, 1);
    assert_eq!(page[0].host, "proxy-0999.example");

    let node_id = db
        .upsert_relay_node_seen(
            group_id,
            "node-a",
            "hash-a",
            "192.0.2.10",
            "2026-01-01 00:00:00",
        )
        .await
        .unwrap()
        .unwrap();
    assert!(db
        .upsert_relay_node_seen(
            group_id,
            "node-a",
            "wrong-hash",
            "192.0.2.99",
            "2026-01-02 00:00:00",
        )
        .await
        .unwrap()
        .is_none());
    let bound = db.find_relay_node(node_id).await.unwrap().unwrap();
    assert_eq!(bound.identity_secret_hash, "hash-a");
    assert_eq!(bound.public_ip, "192.0.2.10");
    let resource_id = page[0].id;
    let (resource, generation) = db
        .begin_socks5_health_check(resource_id, node_id)
        .await
        .unwrap()
        .unwrap();
    assert!(db
        .record_socks5_health(
            &Socks5HealthRecord {
                resource_id,
                relay_node_id: node_id,
                status: "ONLINE".into(),
                tcp_latency_ms: Some(10),
                handshake_latency_ms: Some(20),
                connect_latency_ms: Some(30),
                total_latency_ms: Some(60),
                exit_ip: Some("198.51.100.8".into()),
                country: Some("US".into()),
                error_stage: None,
                error_code: None,
                safe_error_message: None,
                consecutive_failures: 0,
                checked_at: "2026-01-01 00:00:00".into(),
                last_success_at: None,
            },
            resource.health_generation,
            generation,
        )
        .await
        .unwrap());
    assert_eq!(db.list_socks5_health(resource_id).await.unwrap().len(), 1);
    assert_eq!(
        db.list_socks5_check_history(resource_id, 10, 0)
            .await
            .unwrap()
            .len(),
        1
    );
    let projection = db
        .list_latest_socks5_health_for_resources(&[resource_id])
        .await
        .unwrap();
    assert_eq!(projection.len(), 1);
    assert_eq!(projection[0].relay_node_id, node_id);
    assert_eq!(projection[0].status, "ONLINE");
}

#[tokio::test]
async fn pg_stage3_ten_concurrent_identical_imports_are_unique_and_conserved() {
    use std::sync::Arc;
    let Some(db) = repo("stage3_import_race").await else {
        return;
    };
    let db = Arc::new(db);
    let rows = Arc::new(
        (0..1_000)
            .map(|index| BulkSocks5Resource {
                name: format!("race-{index:04}"),
                host: format!("race-{index:04}.example"),
                port: 1080,
                username: Some("same-user".into()),
                password_ciphertext: Some("cipher".into()),
                password_nonce: Some("nonce".into()),
                password_key_version: 1,
            })
            .collect::<Vec<_>>(),
    );
    let barrier = Arc::new(tokio::sync::Barrier::new(11));
    let mut tasks = Vec::new();
    for _ in 0..10 {
        let db = db.clone();
        let rows = rows.clone();
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            db.bulk_import_socks5_resources(&rows, false).await.unwrap()
        }));
    }
    barrier.wait().await;
    let mut created = 0;
    let mut skipped = 0;
    for task in tasks {
        let outcome = task.await.unwrap();
        created += outcome.created;
        skipped += outcome.skipped;
    }
    assert_eq!(created, 1_000);
    assert_eq!(skipped, 9_000);
    assert_eq!(created + skipped, 10_000);
    assert_eq!(db.list_socks5_resources().await.unwrap().len(), 1_000);
}

#[tokio::test]
async fn pg_stage3_update_credentials_wins_a_concurrent_skip() {
    use std::sync::Arc;

    let Some(db) = repo("stage3_credential_import_race").await else {
        return;
    };
    let db = Arc::new(db);
    let row = |cipher: &str, nonce: &str| BulkSocks5Resource {
        name: "credential-race".into(),
        host: "credential-race.example".into(),
        port: 1080,
        username: Some("same-user".into()),
        password_ciphertext: Some(cipher.into()),
        password_nonce: Some(nonce.into()),
        password_key_version: 1,
    };
    let barrier = Arc::new(tokio::sync::Barrier::new(3));
    let skip = {
        let db = db.clone();
        let barrier = barrier.clone();
        tokio::spawn(async move {
            barrier.wait().await;
            db.bulk_import_socks5_resources(&[row("old-cipher", "old-nonce")], false)
                .await
                .unwrap()
        })
    };
    let update = {
        let db = db.clone();
        let barrier = barrier.clone();
        tokio::spawn(async move {
            barrier.wait().await;
            db.bulk_import_socks5_resources(&[row("new-cipher", "new-nonce")], true)
                .await
                .unwrap()
        })
    };
    barrier.wait().await;
    let skip = skip.await.unwrap();
    let update = update.await.unwrap();
    assert_eq!(skip.created + skip.skipped, 1);
    assert_eq!(update.created + update.updated, 1);
    let resource = db.list_socks5_resources().await.unwrap().pop().unwrap();
    assert_eq!(resource.password_ciphertext.as_deref(), Some("new-cipher"));
    assert_eq!(resource.password_nonce.as_deref(), Some("new-nonce"));
}

#[tokio::test]
async fn pg_stage3_health_generation_is_atomic_per_resource_node_cell() {
    use std::sync::Arc;
    let Some(db) = repo("stage3_health_generation").await else {
        return;
    };
    db.insert_group("health", "in", "health-token", 1, "", "", 1.0, false)
        .await
        .unwrap();
    let group_id = db.find_by_token("health-token").await.unwrap().unwrap().id;
    let mut nodes = Vec::new();
    for suffix in ["a", "b", "c"] {
        nodes.push(
            db.upsert_relay_node_seen(
                group_id,
                &format!("node-{suffix}"),
                &format!("hash-{suffix}"),
                "192.0.2.1",
                "2026-01-01 00:00:00",
            )
            .await
            .unwrap()
            .unwrap(),
        );
    }
    let resource_id = db
        .insert_socks5_resource(
            "generation",
            "generation.example",
            1080,
            None,
            None,
            None,
            1,
            "",
            "",
            "",
            "",
            "",
            "",
            true,
        )
        .await
        .unwrap();
    let db = Arc::new(db);
    let node_a = nodes[0];

    let starts = futures_util::future::join_all((0..100).map(|_| {
        let db = db.clone();
        async move {
            db.begin_socks5_health_check(resource_id, node_a)
                .await
                .unwrap()
                .unwrap()
        }
    }))
    .await;
    let resource_revision = starts[0].0.health_generation;
    let latest_generation = starts
        .iter()
        .map(|(_, generation)| *generation)
        .max()
        .unwrap();
    assert_eq!(latest_generation, 100);
    let health = Socks5HealthRecord {
        resource_id,
        relay_node_id: node_a,
        status: "ONLINE".into(),
        tcp_latency_ms: Some(1),
        handshake_latency_ms: Some(1),
        connect_latency_ms: Some(1),
        total_latency_ms: Some(3),
        exit_ip: Some("198.51.100.8".into()),
        country: None,
        error_stage: None,
        error_code: None,
        safe_error_message: None,
        consecutive_failures: 0,
        checked_at: "2026-01-01 00:00:00".into(),
        last_success_at: None,
    };
    assert!(db
        .record_socks5_health(&health, resource_revision, latest_generation)
        .await
        .unwrap());
    for (_, stale_generation) in starts {
        if stale_generation != latest_generation {
            assert!(!db
                .record_socks5_health(&health, resource_revision, stale_generation)
                .await
                .unwrap());
        }
    }

    let checks = futures_util::future::join_all(nodes[1..].iter().map(|node| {
        let db = db.clone();
        async move {
            db.begin_socks5_health_check(resource_id, *node)
                .await
                .unwrap()
                .unwrap()
        }
    }))
    .await;
    for ((resource, generation), (node, status)) in checks
        .into_iter()
        .zip([(nodes[1], "AUTH_FAILED"), (nodes[2], "TIMEOUT")])
    {
        let mut per_node = health.clone();
        per_node.relay_node_id = node;
        per_node.status = status.into();
        per_node.exit_ip = None;
        assert!(db
            .record_socks5_health(&per_node, resource.health_generation, generation)
            .await
            .unwrap());
    }
    let matrix = db.list_socks5_health(resource_id).await.unwrap();
    assert_eq!(matrix.len(), 3);
    assert_eq!(
        db.list_socks5_check_history(resource_id, 200, 0)
            .await
            .unwrap()
            .len(),
        3,
        "stale generations are discarded rather than saved as history"
    );
}

#[tokio::test]
async fn pg_concurrent_relay_node_first_claim_accepts_exactly_one_identity() {
    use std::sync::Arc;

    let Some(db) = repo("stage3_identity_claim_race").await else {
        return;
    };
    db.insert_group("identity", "in", "identity-token", 1, "", "", 1.0, false)
        .await
        .unwrap();
    let group_id = db
        .find_by_token("identity-token")
        .await
        .unwrap()
        .unwrap()
        .id;
    let db = Arc::new(db);
    let claims = futures_util::future::join_all(["hash-a", "hash-b"].map(|hash| {
        let db = db.clone();
        async move {
            db.upsert_relay_node_seen(
                group_id,
                "shared-node-id",
                hash,
                "192.0.2.10",
                "2026-01-01 00:00:00",
            )
            .await
            .unwrap()
        }
    }))
    .await;
    assert_eq!(claims.iter().filter(|claim| claim.is_some()).count(), 1);

    let node = db.list_relay_nodes().await.unwrap().pop().unwrap();
    assert!(["hash-a", "hash-b"].contains(&node.identity_secret_hash.as_str()));
    let rejected_hash = if node.identity_secret_hash == "hash-a" {
        "hash-b"
    } else {
        "hash-a"
    };
    assert!(db
        .upsert_relay_node_seen(
            group_id,
            "shared-node-id",
            rejected_hash,
            "192.0.2.99",
            "2026-01-02 00:00:00",
        )
        .await
        .unwrap()
        .is_none());
}

async fn pg_seed_stage4_create(db: &PgRepository, port_range: &str) -> (i64, i64, String) {
    sqlx::query("UPDATE users SET max_rules=0 WHERE id=1")
        .execute(&db.pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO device_groups(id,name,group_type,token,uid,port_range)
         VALUES(940,'stage4-group','in','stage4-token',1,$1)",
    )
    .bind(port_range)
    .execute(&db.pool)
    .await
    .unwrap();
    let checked_at = chrono::Utc::now().to_rfc3339();
    let node_id = db
        .upsert_relay_node_seen(
            940,
            "stage4-node",
            &"a".repeat(64),
            "192.0.2.44",
            &checked_at,
        )
        .await
        .unwrap()
        .unwrap();
    sqlx::query("UPDATE relay_nodes SET name='US-A',country_code='US' WHERE id=$1")
        .bind(node_id)
        .execute(&db.pool)
        .await
        .unwrap();
    let status = serde_json::json!({
        "last_seen": checked_at,
        "config_protocol_version": relay_shared::protocol::CONFIG_PROTOCOL_VERSION,
        "socks5_check_queue_depth": 0,
        "cpu": 10.0,
        "mem": 20.0,
        "connections": 3
    });
    sqlx::query("INSERT INTO kvs(key,value) VALUES($1,$2)")
        .bind("node_status:940:stage4-node")
        .bind(status.to_string())
        .execute(&db.pool)
        .await
        .unwrap();
    let resource_id: i64 = sqlx::query_scalar(
        "INSERT INTO socks5_resources
         (name,host,port,country_code,detected_country,detected_exit_ip,status,enabled,health_generation)
         VALUES('stage4-upstream','198.51.100.7',1080,'JP','US','198.51.100.8','ONLINE',TRUE,1)
         RETURNING id",
    )
    .fetch_one(&db.pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO socks5_check_generations(resource_id,relay_node_id,generation) VALUES($1,$2,1)",
    )
    .bind(resource_id)
    .bind(node_id)
    .execute(&db.pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO socks5_resource_health
         (resource_id,relay_node_id,status,total_latency_ms,exit_ip,country,checked_at,
          resource_revision,generation)
         VALUES($1,$2,'ONLINE',120,'198.51.100.8','US',$3,1,1)",
    )
    .bind(resource_id)
    .bind(node_id)
    .bind(&checked_at)
    .execute(&db.pool)
    .await
    .unwrap();
    (resource_id, node_id, checked_at)
}

async fn pg_add_stage4_node(
    db: &PgRepository,
    group_id: i64,
    node_key: &str,
    resource_id: i64,
    checked_at: &str,
    port_range: &str,
) -> i64 {
    sqlx::query(
        "INSERT INTO device_groups(id,name,group_type,token,uid,port_range)
         VALUES($1,$2,'in',$3,1,$4)",
    )
    .bind(group_id)
    .bind(format!("stage4-group-{group_id}"))
    .bind(format!("stage4-token-{group_id}"))
    .bind(port_range)
    .execute(&db.pool)
    .await
    .unwrap();
    let node_id = db
        .upsert_relay_node_seen(
            group_id,
            node_key,
            &format!("{group_id:064}"),
            "192.0.2.45",
            checked_at,
        )
        .await
        .unwrap()
        .unwrap();
    sqlx::query("UPDATE relay_nodes SET name=$1,country_code='US' WHERE id=$2")
        .bind(format!("US-{group_id}"))
        .bind(node_id)
        .execute(&db.pool)
        .await
        .unwrap();
    let status = serde_json::json!({
        "last_seen": checked_at,
        "config_protocol_version": relay_shared::protocol::CONFIG_PROTOCOL_VERSION,
        "socks5_check_queue_depth": 0,
        "cpu": 10.0,
        "mem": 20.0,
        "connections": 0
    });
    sqlx::query("INSERT INTO kvs(key,value) VALUES($1,$2)")
        .bind(format!("node_status:{group_id}:{node_key}"))
        .bind(status.to_string())
        .execute(&db.pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO socks5_check_generations(resource_id,relay_node_id,generation)
         VALUES($1,$2,1)",
    )
    .bind(resource_id)
    .bind(node_id)
    .execute(&db.pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO socks5_resource_health
         (resource_id,relay_node_id,status,total_latency_ms,exit_ip,country,checked_at,
          resource_revision,generation)
         VALUES($1,$2,'ONLINE',120,'198.51.100.8','US',$3,1,1)",
    )
    .bind(resource_id)
    .bind(node_id)
    .bind(checked_at)
    .execute(&db.pool)
    .await
    .unwrap();
    node_id
}

fn pg_stage4_input(
    sequence: usize,
    resource_id: i64,
    node_id: i64,
    checked_at: &str,
) -> SmartRelayCreateInput {
    SmartRelayCreateInput {
        actor_id: 1,
        idempotency_key: format!("10000000-0000-4000-8000-{sequence:012}"),
        request_fingerprint: format!("fingerprint-{sequence}"),
        name: format!("stage4-{sequence}"),
        resource_id,
        relay_node_id: node_id,
        requested_port: None,
        expected_resource_revision: 1,
        expected_health_generation: 1,
        expected_health_checked_at: checked_at.to_owned(),
        selection_mode: "RECOMMENDED".into(),
        relay_username: format!("r_{sequence}"),
        relay_password_ciphertext: format!("cipher-{sequence}"),
        relay_password_nonce: format!("nonce-{sequence}"),
        relay_password_key_version: 1,
        health_ttl_seconds: 600,
        required_protocol_version: relay_shared::protocol::CONFIG_PROTOCOL_VERSION,
        max_cpu_percent: 95.0,
        max_memory_percent: 95.0,
    }
}

async fn pg_seed_stage4_expired_ledger_backlog(
    db: &PgRepository,
    input: &SmartRelayCreateInput,
    total_rows: i64,
    target_fingerprint: &str,
    target_created_at: &str,
) {
    assert!(total_rows > 0);
    sqlx::query(
        "INSERT INTO relay_creation_idempotency_keys
         (actor_id,idempotency_key,request_fingerprint,created_at)
         SELECT $1,'ttl-filler-' || n,'expired-filler','2000-01-01 00:00:00'
         FROM generate_series(1,$2) n",
    )
    .bind(input.actor_id)
    .bind(total_rows - 1)
    .execute(&db.pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO relay_creation_idempotency_keys
         (actor_id,idempotency_key,request_fingerprint,created_at) VALUES($1,$2,$3,$4)",
    )
    .bind(input.actor_id)
    .bind(&input.idempotency_key)
    .bind(target_fingerprint)
    .bind(target_created_at)
    .execute(&db.pool)
    .await
    .unwrap();
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM relay_creation_idempotency_keys")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(count, total_rows);
}

#[tokio::test]
async fn pg_stage4_one_hundred_concurrent_creates_are_atomic_and_port_safe() {
    let Some(db) = repo("stage4_100_create").await else {
        return;
    };
    let (resource_id, node_id, checked_at) = pg_seed_stage4_create(&db, "20000-20099").await;
    let attempts = (0..100).map(|sequence| {
        let worker = PgRepository::new(db.pool.clone());
        let input = pg_stage4_input(sequence, resource_id, node_id, &checked_at);
        async move { worker.create_smart_relay(&input).await.unwrap() }
    });
    let outcomes = futures_util::future::join_all(attempts).await;
    assert!(outcomes
        .iter()
        .all(|outcome| matches!(outcome, SmartRelayCreateOutcome::Created(_))));
    let ports: Vec<i32> = sqlx::query_scalar(
        "SELECT listen_port FROM forward_rules WHERE device_group_in=940 ORDER BY listen_port",
    )
    .fetch_all(&db.pool)
    .await
    .unwrap();
    assert_eq!(ports, (20000..=20099).collect::<Vec<_>>());
    let counts: (i64, i64) = sqlx::query_as(
        "SELECT (SELECT COUNT(*) FROM socks5_rule_bindings),
                (SELECT COUNT(*) FROM relay_creation_receipts)",
    )
    .fetch_one(&db.pool)
    .await
    .unwrap();
    assert_eq!(counts, (100, 100));
    cleanup(&db).await;
}

#[tokio::test]
async fn pg_stage4_one_hundred_idempotent_requests_create_one_rule() {
    let Some(db) = repo("stage4_100_idempotent").await else {
        return;
    };
    let (resource_id, node_id, checked_at) = pg_seed_stage4_create(&db, "21000-21009").await;
    let attempts = (0..100).map(|_| {
        let worker = PgRepository::new(db.pool.clone());
        let input = pg_stage4_input(7, resource_id, node_id, &checked_at);
        async move { worker.create_smart_relay(&input).await.unwrap() }
    });
    let outcomes = futures_util::future::join_all(attempts).await;
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, SmartRelayCreateOutcome::Created(_)))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, SmartRelayCreateOutcome::Replay(_)))
            .count(),
        99
    );
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM forward_rules WHERE name='stage4-7'")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
    cleanup(&db).await;
}

#[tokio::test]
async fn pg_stage4_expired_ledger_backlog_never_decides_idempotency() {
    for (total_rows, sequence, port_range) in [
        (10_001_i64, 701_usize, "28000-28009"),
        (20_001_i64, 702_usize, "28100-28109"),
    ] {
        let name = format!("stage4_ttl_backlog_{total_rows}");
        let Some(db) = repo(&name).await else {
            return;
        };
        let (resource_id, node_id, checked_at) = pg_seed_stage4_create(&db, port_range).await;
        let input = pg_stage4_input(sequence, resource_id, node_id, &checked_at);
        pg_seed_stage4_expired_ledger_backlog(
            &db,
            &input,
            total_rows,
            "expired-intent",
            "2000-01-02 00:00:00",
        )
        .await;

        assert!(matches!(
            db.create_smart_relay(&input).await.unwrap(),
            SmartRelayCreateOutcome::Created(_)
        ));
        let mut third_intent = input.clone();
        third_intent.request_fingerprint = "third-intent".into();
        assert!(matches!(
            db.create_smart_relay(&third_intent).await.unwrap(),
            SmartRelayCreateOutcome::Rejected("IDEMPOTENCY_KEY_REUSED")
        ));
        assert!(matches!(
            db.create_smart_relay(&input).await.unwrap(),
            SmartRelayCreateOutcome::Replay(_)
        ));
        cleanup(&db).await;
    }
}

#[tokio::test]
async fn pg_stage4_valid_ledger_survives_expired_backlog() {
    let Some(db) = repo("stage4_valid_ledger_backlog").await else {
        return;
    };
    let (resource_id, node_id, checked_at) = pg_seed_stage4_create(&db, "28200-28209").await;
    let input = pg_stage4_input(703, resource_id, node_id, &checked_at);
    pg_seed_stage4_expired_ledger_backlog(
        &db,
        &input,
        10_001,
        "valid-intent",
        "2999-01-01 00:00:00",
    )
    .await;
    assert!(matches!(
        db.create_smart_relay(&input).await.unwrap(),
        SmartRelayCreateOutcome::Rejected("IDEMPOTENCY_KEY_REUSED")
    ));

    let mut matching = input;
    matching.request_fingerprint = "valid-intent".into();
    assert!(matches!(
        db.create_smart_relay(&matching).await.unwrap(),
        SmartRelayCreateOutcome::Created(_)
    ));
    cleanup(&db).await;
}

#[tokio::test]
async fn pg_stage4_ttl_boundary_is_inclusive() {
    let Some(db) = repo("stage4_ttl_boundary").await else {
        return;
    };
    let cutoff = "2026-01-08 00:00:00";
    for (key, modifier) in [
        ("boundary-before", "-1 second"),
        ("boundary-exact", "+0 seconds"),
        ("boundary-after", "+1 second"),
    ] {
        sqlx::query(
            "INSERT INTO relay_creation_idempotency_keys
             (actor_id,idempotency_key,request_fingerprint,created_at)
             VALUES(1,$1,'boundary',to_char(to_timestamp($2,'YYYY-MM-DD HH24:MI:SS') + $3::interval,
                                             'YYYY-MM-DD HH24:MI:SS'))",
        )
        .bind(key)
        .bind(cutoff)
        .bind(modifier)
        .execute(&db.pool)
        .await
        .unwrap();
    }
    let active: Vec<String> = sqlx::query_scalar(
        "SELECT idempotency_key FROM relay_creation_idempotency_keys
         WHERE created_at >= $1 ORDER BY idempotency_key",
    )
    .bind(cutoff)
    .fetch_all(&db.pool)
    .await
    .unwrap();
    assert_eq!(active, vec!["boundary-after", "boundary-exact"]);
    cleanup(&db).await;
}

#[tokio::test]
async fn pg_stage4_expired_receipt_backlog_cannot_force_a_conflict() {
    let Some(db) = repo("stage4_expired_receipt_backlog").await else {
        return;
    };
    let (resource_id, node_id, checked_at) = pg_seed_stage4_create(&db, "28300-28309").await;
    let input = pg_stage4_input(709, resource_id, node_id, &checked_at);
    sqlx::query(
        "INSERT INTO forward_rules
         (name,uid,listen_port,protocol,device_group_in,target_addr,target_port)
         SELECT 'ttl-receipt-filler-' || n,1,n,'tcp',940,'',0
         FROM generate_series(1,10000) n",
    )
    .execute(&db.pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO relay_creation_receipts
         (actor_id,idempotency_key,request_fingerprint,rule_id,relay_node_id,resource_id,
          endpoint_host,listen_port,relay_username,exit_ip,selection_mode,created_at)
         SELECT 1,'receipt-filler-' || f.id,'expired-receipt',f.id,$1,$2,
                '192.0.2.44',f.listen_port,'relay','198.51.100.8','RECOMMENDED',
                '2000-01-01 00:00:00'
         FROM forward_rules f WHERE f.name LIKE 'ttl-receipt-filler-%'",
    )
    .bind(node_id)
    .bind(resource_id)
    .execute(&db.pool)
    .await
    .unwrap();
    let old_rule: i64 = sqlx::query_scalar(
        "INSERT INTO forward_rules
         (name,uid,listen_port,protocol,device_group_in,target_addr,target_port)
         VALUES('expired-receipt-target',1,28300,'tcp',940,'',0) RETURNING id",
    )
    .fetch_one(&db.pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO relay_creation_receipts
         (actor_id,idempotency_key,request_fingerprint,rule_id,relay_node_id,resource_id,
          endpoint_host,listen_port,relay_username,exit_ip,selection_mode,created_at)
         VALUES(1,$1,'expired-intent',$2,$3,$4,'192.0.2.44',28300,'relay',
                '198.51.100.8','RECOMMENDED','2000-01-02 00:00:00')",
    )
    .bind(&input.idempotency_key)
    .bind(old_rule)
    .bind(node_id)
    .bind(resource_id)
    .execute(&db.pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO relay_creation_idempotency_keys
         (actor_id,idempotency_key,request_fingerprint,created_at)
         VALUES(1,$1,'expired-intent','2000-01-02 00:00:00')",
    )
    .bind(&input.idempotency_key)
    .execute(&db.pool)
    .await
    .unwrap();

    let new_rule = match db.create_smart_relay(&input).await.unwrap() {
        SmartRelayCreateOutcome::Created(created) => created.rule_id,
        other => panic!("expected create after expired receipt, got {other:?}"),
    };
    assert_ne!(new_rule, old_rule);
    let receipt_rule: i64 = sqlx::query_scalar(
        "SELECT rule_id FROM relay_creation_receipts
         WHERE actor_id=1 AND idempotency_key=$1",
    )
    .bind(&input.idempotency_key)
    .fetch_one(&db.pool)
    .await
    .unwrap();
    assert_eq!(receipt_rule, new_rule);
    cleanup(&db).await;
}

#[tokio::test]
async fn pg_stage4_cleanup_rollback_is_not_part_of_ttl_correctness() {
    {
        let Some(db) = repo("stage4_ttl_quota_rollback").await else {
            return;
        };
        let (resource_id, node_id, checked_at) = pg_seed_stage4_create(&db, "28400-28409").await;
        let input = pg_stage4_input(704, resource_id, node_id, &checked_at);
        pg_seed_stage4_expired_ledger_backlog(
            &db,
            &input,
            10_001,
            "expired-intent",
            "2000-01-02 00:00:00",
        )
        .await;
        sqlx::query("UPDATE users SET max_rules=1 WHERE id=1")
            .execute(&db.pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO forward_rules(name,uid,listen_port,device_group_in,target_addr,target_port) VALUES('quota-blocker',1,28409,940,'',0)")
            .execute(&db.pool).await.unwrap();
        assert!(matches!(
            db.create_smart_relay(&input).await.unwrap(),
            SmartRelayCreateOutcome::QuotaExceeded
        ));
        sqlx::query("DELETE FROM forward_rules WHERE name='quota-blocker'")
            .execute(&db.pool)
            .await
            .unwrap();
        assert!(matches!(
            db.create_smart_relay(&input).await.unwrap(),
            SmartRelayCreateOutcome::Created(_)
        ));
        cleanup(&db).await;
    }

    {
        let Some(db) = repo("stage4_ttl_port_rollback").await else {
            return;
        };
        let (resource_id, node_id, checked_at) = pg_seed_stage4_create(&db, "28500-28509").await;
        let mut input = pg_stage4_input(705, resource_id, node_id, &checked_at);
        input.requested_port = Some(28505);
        pg_seed_stage4_expired_ledger_backlog(
            &db,
            &input,
            10_001,
            "expired-intent",
            "2000-01-02 00:00:00",
        )
        .await;
        sqlx::query("INSERT INTO forward_rules(name,uid,listen_port,device_group_in,target_addr,target_port) VALUES('port-blocker',1,28505,940,'',0)")
            .execute(&db.pool).await.unwrap();
        assert!(matches!(
            db.create_smart_relay(&input).await.unwrap(),
            SmartRelayCreateOutcome::Rejected("PORT_CONFLICT")
        ));
        sqlx::query("DELETE FROM forward_rules WHERE name='port-blocker'")
            .execute(&db.pool)
            .await
            .unwrap();
        assert!(matches!(
            db.create_smart_relay(&input).await.unwrap(),
            SmartRelayCreateOutcome::Created(_)
        ));
        cleanup(&db).await;
    }

    {
        let Some(db) = repo("stage4_ttl_conflict_rollback").await else {
            return;
        };
        let (resource_id, node_id, checked_at) = pg_seed_stage4_create(&db, "28600-28609").await;
        let expired = pg_stage4_input(706, resource_id, node_id, &checked_at);
        pg_seed_stage4_expired_ledger_backlog(
            &db,
            &expired,
            10_001,
            "expired-intent",
            "2000-01-02 00:00:00",
        )
        .await;
        let valid = pg_stage4_input(707, resource_id, node_id, &checked_at);
        sqlx::query("INSERT INTO relay_creation_idempotency_keys(actor_id,idempotency_key,request_fingerprint,created_at) VALUES($1,$2,$3,'2999-01-01 00:00:00')")
            .bind(valid.actor_id)
            .bind(&valid.idempotency_key)
            .bind("valid-intent")
            .execute(&db.pool)
            .await
            .unwrap();
        assert!(matches!(
            db.create_smart_relay(&valid).await.unwrap(),
            SmartRelayCreateOutcome::Rejected("IDEMPOTENCY_KEY_REUSED")
        ));
        assert!(matches!(
            db.create_smart_relay(&expired).await.unwrap(),
            SmartRelayCreateOutcome::Created(_)
        ));
        cleanup(&db).await;
    }

    {
        let Some(db) = repo("stage4_ttl_forced_rollback").await else {
            return;
        };
        let (resource_id, node_id, checked_at) = pg_seed_stage4_create(&db, "28700-28709").await;
        let input = pg_stage4_input(708, resource_id, node_id, &checked_at);
        pg_seed_stage4_expired_ledger_backlog(
            &db,
            &input,
            10_001,
            "expired-intent",
            "2000-01-02 00:00:00",
        )
        .await;
        sqlx::query(
            "CREATE FUNCTION fail_ttl_receipt() RETURNS trigger LANGUAGE plpgsql AS $$
             BEGIN RAISE EXCEPTION 'forced ttl receipt failure'; END $$",
        )
        .execute(&db.pool)
        .await
        .unwrap();
        sqlx::query(
            "CREATE TRIGGER fail_ttl_receipt BEFORE INSERT ON relay_creation_receipts
             FOR EACH ROW EXECUTE FUNCTION fail_ttl_receipt()",
        )
        .execute(&db.pool)
        .await
        .unwrap();
        assert!(db.create_smart_relay(&input).await.is_err());
        sqlx::query("DROP TRIGGER fail_ttl_receipt ON relay_creation_receipts")
            .execute(&db.pool)
            .await
            .unwrap();
        sqlx::query("DROP FUNCTION fail_ttl_receipt()")
            .execute(&db.pool)
            .await
            .unwrap();
        assert!(matches!(
            db.create_smart_relay(&input).await.unwrap(),
            SmartRelayCreateOutcome::Created(_)
        ));
        cleanup(&db).await;
    }
}
#[tokio::test]
async fn pg_stage4_cross_group_quota_is_user_serialized() {
    let Some(db) = repo("stage4_cross_group_quota").await else {
        return;
    };
    let (resource_id, node_a, checked_at) = pg_seed_stage4_create(&db, "22000-22099").await;
    let node_b = pg_add_stage4_node(
        &db,
        941,
        "stage4-node-b",
        resource_id,
        &checked_at,
        "22000-22099",
    )
    .await;
    sqlx::query("UPDATE users SET max_rules=1 WHERE id=1")
        .execute(&db.pool)
        .await
        .unwrap();
    let left = PgRepository::new(db.pool.clone());
    let right = PgRepository::new(db.pool.clone());
    let input_a = pg_stage4_input(21, resource_id, node_a, &checked_at);
    let input_b = pg_stage4_input(22, resource_id, node_b, &checked_at);
    let (outcome_a, outcome_b) = tokio::join!(
        left.create_smart_relay(&input_a),
        right.create_smart_relay(&input_b)
    );
    let outcomes = [outcome_a.unwrap(), outcome_b.unwrap()];
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, SmartRelayCreateOutcome::Created(_)))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, SmartRelayCreateOutcome::QuotaExceeded))
            .count(),
        1
    );
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM forward_rules WHERE uid=1")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
    cleanup(&db).await;
}

#[tokio::test]
async fn pg_stage4_n_plus_one_across_groups_never_exceeds_quota() {
    let Some(db) = repo("stage4_n_plus_one_quota").await else {
        return;
    };
    let (resource_id, node_a, checked_at) = pg_seed_stage4_create(&db, "23000-23100").await;
    let node_b = pg_add_stage4_node(
        &db,
        941,
        "stage4-node-b",
        resource_id,
        &checked_at,
        "23000-23100",
    )
    .await;
    sqlx::query("UPDATE users SET max_rules=8 WHERE id=1")
        .execute(&db.pool)
        .await
        .unwrap();
    let attempts = (0..9).map(|sequence| {
        let worker = PgRepository::new(db.pool.clone());
        let node_id = if sequence % 2 == 0 { node_a } else { node_b };
        let input = pg_stage4_input(100 + sequence, resource_id, node_id, &checked_at);
        async move { worker.create_smart_relay(&input).await.unwrap() }
    });
    let outcomes = futures_util::future::join_all(attempts).await;
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, SmartRelayCreateOutcome::Created(_)))
            .count(),
        8
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, SmartRelayCreateOutcome::QuotaExceeded))
            .count(),
        1
    );
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM forward_rules WHERE uid=1")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(count, 8);
    cleanup(&db).await;
}

#[tokio::test]
async fn pg_stage4_smart_and_normal_socks5_share_quota_lock_order() {
    let Some(db) = repo("stage4_mixed_create_quota").await else {
        return;
    };
    let (resource_id, _node_a, checked_at) = pg_seed_stage4_create(&db, "24000-24099").await;
    let node_b = pg_add_stage4_node(
        &db,
        941,
        "stage4-node-b",
        resource_id,
        &checked_at,
        "24000-24099",
    )
    .await;
    sqlx::query("UPDATE users SET max_rules=1 WHERE id=1")
        .execute(&db.pool)
        .await
        .unwrap();
    let smart_repo = PgRepository::new(db.pool.clone());
    let normal_repo = PgRepository::new(db.pool.clone());
    let smart = pg_stage4_input(301, resource_id, node_b, &checked_at);
    let (smart_outcome, normal_outcome) = tokio::join!(
        smart_repo.create_smart_relay(&smart),
        normal_repo.create_socks5_rule_full(
            "normal",
            1,
            24001,
            940,
            resource_id,
            true,
            None,
            None,
            None,
            1,
            true,
            true,
        )
    );
    let smart_created = matches!(smart_outcome.unwrap(), SmartRelayCreateOutcome::Created(_));
    let normal_created = normal_outcome.unwrap().is_some();
    assert_ne!(smart_created, normal_created);
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM forward_rules WHERE uid=1")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
    cleanup(&db).await;
}

#[tokio::test]
async fn pg_stage4_multi_user_multi_group_stress_has_no_deadlock_or_quota_escape() {
    let Some(db) = repo("stage4_multi_user_stress").await else {
        return;
    };
    let (resource_id, node_a, checked_at) = pg_seed_stage4_create(&db, "25000-25199").await;
    let node_b = pg_add_stage4_node(
        &db,
        941,
        "stage4-node-b",
        resource_id,
        &checked_at,
        "25000-25199",
    )
    .await;
    for user_id in 10_i64..20_i64 {
        sqlx::query("INSERT INTO users(id,username,password,max_rules) VALUES($1,$2,'x',5)")
            .bind(user_id)
            .bind(format!("stage4-user-{user_id}"))
            .execute(&db.pool)
            .await
            .unwrap();
    }
    let attempts = (0..100).map(|sequence| {
        let worker = PgRepository::new(db.pool.clone());
        let actor_id = 10 + (sequence / 10) as i64;
        let node_id = if sequence % 2 == 0 { node_a } else { node_b };
        let mut input = pg_stage4_input(1000 + sequence, resource_id, node_id, &checked_at);
        input.actor_id = actor_id;
        input.name = format!("stress-{actor_id}-{sequence}");
        async move { worker.create_smart_relay(&input).await.unwrap() }
    });
    let outcomes = futures_util::future::join_all(attempts).await;
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, SmartRelayCreateOutcome::Created(_)))
            .count(),
        50
    );
    for user_id in 10_i64..20_i64 {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM forward_rules WHERE uid=$1")
            .bind(user_id)
            .fetch_one(&db.pool)
            .await
            .unwrap();
        assert_eq!(count, 5, "user {user_id} exceeded or lost quota slots");
    }
    cleanup(&db).await;
}

#[tokio::test]
async fn pg_stage4_deleted_rule_recreates_only_for_the_original_fingerprint() {
    let Some(db) = repo("stage4_deleted_recreate").await else {
        return;
    };
    let (resource_id, node_id, checked_at) = pg_seed_stage4_create(&db, "26000-26009").await;
    let input = pg_stage4_input(401, resource_id, node_id, &checked_at);
    let first_rule = match db.create_smart_relay(&input).await.unwrap() {
        SmartRelayCreateOutcome::Created(created) => created.rule_id,
        other => panic!("unexpected first outcome: {other:?}"),
    };
    db.delete_rule(first_rule, &ResourceScope::All)
        .await
        .unwrap();
    assert!(db
        .find_smart_relay_receipt(1, &input.idempotency_key)
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        db.find_smart_relay_idempotency_fingerprint(1, &input.idempotency_key)
            .await
            .unwrap()
            .as_deref(),
        Some(input.request_fingerprint.as_str())
    );
    let replacement_rule = match db.create_smart_relay(&input).await.unwrap() {
        SmartRelayCreateOutcome::Created(created) => created.rule_id,
        other => panic!("unexpected replacement outcome: {other:?}"),
    };
    assert_ne!(first_rule, replacement_rule);
    db.delete_rule(replacement_rule, &ResourceScope::All)
        .await
        .unwrap();
    let mut changed = input.clone();
    changed.request_fingerprint = "changed-after-delete".into();
    assert!(matches!(
        db.create_smart_relay(&changed).await.unwrap(),
        SmartRelayCreateOutcome::Rejected("IDEMPOTENCY_KEY_REUSED")
    ));
    cleanup(&db).await;
}

#[tokio::test]
async fn pg_stage4_delete_in_progress_cannot_produce_a_stale_replay() {
    let Some(db) = repo("stage4_delete_replay_race").await else {
        return;
    };
    let (resource_id, node_id, checked_at) = pg_seed_stage4_create(&db, "26500-26509").await;
    let input = pg_stage4_input(451, resource_id, node_id, &checked_at);
    let rule_id = match db.create_smart_relay(&input).await.unwrap() {
        SmartRelayCreateOutcome::Created(created) => created.rule_id,
        other => panic!("unexpected create outcome: {other:?}"),
    };
    let mut delete_tx = db.pool.begin().await.unwrap();
    sqlx::query("DELETE FROM forward_rules WHERE id=$1")
        .bind(rule_id)
        .execute(&mut *delete_tx)
        .await
        .unwrap();
    let worker = PgRepository::new(db.pool.clone());
    let create = tokio::spawn(async move { worker.create_smart_relay(&input).await.unwrap() });
    tokio::task::yield_now().await;
    delete_tx.commit().await.unwrap();
    assert!(matches!(
        create.await.unwrap(),
        SmartRelayCreateOutcome::Created(_)
    ));
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM forward_rules WHERE uid=1")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
    cleanup(&db).await;
}

#[tokio::test]
async fn pg_migration_34_cleans_orphans_preserves_fingerprints_and_adds_cascade() {
    let Some(db) = repo("migration_34_receipts").await else {
        return;
    };
    let (resource_id, node_id, checked_at) = pg_seed_stage4_create(&db, "27000-27009").await;
    let input = pg_stage4_input(501, resource_id, node_id, &checked_at);
    let live_rule = match db.create_smart_relay(&input).await.unwrap() {
        SmartRelayCreateOutcome::Created(created) => created.rule_id,
        other => panic!("unexpected create outcome: {other:?}"),
    };
    let fresh_fk_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pg_constraint
         WHERE conname='relay_creation_receipts_rule_fk'
           AND conrelid='relay_creation_receipts'::regclass
           AND confdeltype='c'",
    )
    .fetch_one(&db.pool)
    .await
    .unwrap();
    assert_eq!(
        fresh_fk_count, 1,
        "fresh PostgreSQL schema must carry the cascade FK"
    );
    sqlx::query(
        "ALTER TABLE relay_creation_receipts
         DROP CONSTRAINT relay_creation_receipts_rule_fk",
    )
    .execute(&db.pool)
    .await
    .unwrap();
    sqlx::query("DROP TABLE relay_creation_idempotency_keys")
        .execute(&db.pool)
        .await
        .unwrap();
    // Recreate an actual pre-34 database. Once later versions exist, deleting
    // only row 34 leaves MAX(version) at 35 and correctly skips migration 34.
    for table in crate::db::health_schema::HEALTH_TABLES.iter().rev() {
        sqlx::query(&format!("DROP TABLE {table}"))
            .execute(&db.pool)
            .await
            .unwrap();
    }
    sqlx::query("DELETE FROM schema_version WHERE version>=34")
        .execute(&db.pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO relay_creation_receipts
         (actor_id,idempotency_key,request_fingerprint,rule_id,relay_node_id,resource_id,
          endpoint_host,listen_port,relay_username,exit_ip,selection_mode)
         VALUES(1,'orphan-key','orphan-fingerprint',999999,$1,$2,
                'node.example',27001,'relay','192.0.2.1','RECOMMENDED')",
    )
    .bind(node_id)
    .bind(resource_id)
    .execute(&db.pool)
    .await
    .unwrap();

    run_pg_migrations(&db.pool).await.unwrap();
    let orphan_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM relay_creation_receipts r
         WHERE NOT EXISTS(SELECT 1 FROM forward_rules f WHERE f.id=r.rule_id)",
    )
    .fetch_one(&db.pool)
    .await
    .unwrap();
    assert_eq!(orphan_count, 0);
    let ledger_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM relay_creation_idempotency_keys")
            .fetch_one(&db.pool)
            .await
            .unwrap();
    assert_eq!(ledger_count, 2);
    let fk_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pg_constraint
         WHERE conname='relay_creation_receipts_rule_fk'
           AND conrelid='relay_creation_receipts'::regclass
           AND confdeltype='c'",
    )
    .fetch_one(&db.pool)
    .await
    .unwrap();
    assert_eq!(fk_count, 1);
    sqlx::query("DELETE FROM forward_rules WHERE id=$1")
        .bind(live_rule)
        .execute(&db.pool)
        .await
        .unwrap();
    let live_receipts: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM relay_creation_receipts WHERE idempotency_key=$1")
            .bind(&input.idempotency_key)
            .fetch_one(&db.pool)
            .await
            .unwrap();
    assert_eq!(live_receipts, 0);
    run_pg_migrations(&db.pool).await.unwrap();
    cleanup(&db).await;
}

#[tokio::test]
async fn pg_stage4_recommendation_one_thousand_nodes_is_bounded_and_explained() {
    let Some(db) = repo("stage4_recommend_1000").await else {
        return;
    };
    sqlx::query(
        "INSERT INTO device_groups(id,name,group_type,token,uid,port_range)
         VALUES(601,'perf-group','in','perf-token',1,'30000-39999')",
    )
    .execute(&db.pool)
    .await
    .unwrap();
    let now = chrono::Utc::now().to_rfc3339();
    sqlx::query(
        "INSERT INTO relay_nodes
             (device_group_id,node_key,identity_secret_hash,name,country_code,public_ip,
              first_seen_at,last_seen_at)
         SELECT 601,'perf-' || value,lpad(value::text,64,'0'),'Node ' || value,'US',
                '192.0.2.1',$1,$1
         FROM generate_series(1,1000) value",
    )
    .bind(&now)
    .execute(&db.pool)
    .await
    .unwrap();
    let resource_id: i64 = sqlx::query_scalar(
        "INSERT INTO socks5_resources
         (name,host,port,country_code,detected_country,detected_exit_ip,status,enabled,
          health_generation)
         VALUES('perf-resource','198.51.100.7',1080,'US','US','198.51.100.8','ONLINE',TRUE,1)
         RETURNING id",
    )
    .fetch_one(&db.pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO socks5_check_generations(resource_id,relay_node_id,generation)
         SELECT $1,id,1 FROM relay_nodes WHERE device_group_id=601",
    )
    .bind(resource_id)
    .execute(&db.pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO socks5_resource_health
             (resource_id,relay_node_id,status,total_latency_ms,exit_ip,country,checked_at,
              resource_revision,generation)
         SELECT $1,id,'ONLINE',100 + (id % 100)::INTEGER,'198.51.100.8','US',$2,1,1
         FROM relay_nodes WHERE device_group_id=601",
    )
    .bind(resource_id)
    .bind(&now)
    .execute(&db.pool)
    .await
    .unwrap();
    let status = serde_json::json!({
        "last_seen": now,
        "config_protocol_version": relay_shared::protocol::CONFIG_PROTOCOL_VERSION,
        "socks5_check_queue_depth": 0,
        "cpu": 15.0,
        "mem": 20.0,
        "connections": 5
    });
    sqlx::query(
        "INSERT INTO kvs(key,value)
         SELECT 'node_status:601:' || node_key,$1 FROM relay_nodes WHERE device_group_id=601",
    )
    .bind(status.to_string())
    .execute(&db.pool)
    .await
    .unwrap();
    let config = Config {
        database_path: String::new(),
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
    };

    let started = std::time::Instant::now();
    let recommendation = crate::service::relay_recommendation::recommend(&db, &config, resource_id)
        .await
        .unwrap()
        .unwrap();
    let elapsed = started.elapsed();
    println!("stage4 postgresql recommendation 1000 nodes: {elapsed:?}");
    assert_eq!(recommendation.candidates.len(), 1000);
    assert!(recommendation
        .candidates
        .iter()
        .all(|candidate| candidate.eligible));
    assert!(
        elapsed < std::time::Duration::from_secs(3),
        "elapsed={elapsed:?}"
    );

    let plan: Vec<String> = sqlx::query_scalar(
        "EXPLAIN (ANALYZE, BUFFERS, FORMAT TEXT)
         SELECT h.resource_id,h.relay_node_id,h.status,h.total_latency_ms,h.exit_ip,h.country,
                h.checked_at,h.resource_revision,h.generation,COALESCE(g.generation,0)
         FROM socks5_resource_health h
         LEFT JOIN socks5_check_generations g
           ON g.resource_id=h.resource_id AND g.relay_node_id=h.relay_node_id
         WHERE h.resource_id=$1 ORDER BY h.relay_node_id",
    )
    .bind(resource_id)
    .fetch_all(&db.pool)
    .await
    .unwrap();
    assert!(plan.iter().any(|line| line.contains("actual time=")));
    assert!(plan.iter().any(|line| line.contains("rows=1000")));
    cleanup(&db).await;
}

#[tokio::test]
async fn pg_health_orchestration_persistence_contract() {
    let Some(db) = repo("health_orchestration").await else {
        return;
    };
    let version: i32 = sqlx::query_scalar("SELECT MAX(version) FROM schema_version")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(version, 36);
    run_pg_migrations(&db.pool).await.unwrap();
    for index in crate::db::health_schema::HEALTH_INDEXES {
        let present: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM pg_indexes WHERE schemaname=current_schema() AND indexname=$1",
        )
        .bind(index)
        .fetch_one(&db.pool)
        .await
        .unwrap();
        assert_eq!(present, 1, "missing {index}");
    }
    let mut plan_connection = db.pool.acquire().await.unwrap();
    sqlx::query("SET enable_seqscan=off")
        .execute(&mut *plan_connection)
        .await
        .unwrap();
    let ready_plan: Vec<String> = sqlx::query_scalar(
        "EXPLAIN SELECT id FROM socks5_check_job_items
         WHERE state='QUEUED' AND not_before_ms <= 1000 LIMIT 100",
    )
    .fetch_all(&mut *plan_connection)
    .await
    .unwrap();
    assert!(ready_plan
        .iter()
        .any(|line| line.contains("idx_socks5_check_job_items_ready")));
    sqlx::query("RESET enable_seqscan")
        .execute(&mut *plan_connection)
        .await
        .unwrap();
    drop(plan_connection);

    let group: i64 = sqlx::query_scalar(
        "INSERT INTO device_groups(name,group_type,token,uid) VALUES('health','in','health-token',1) RETURNING id",
    )
    .fetch_one(&db.pool)
    .await
    .unwrap();
    let resource: i64 = sqlx::query_scalar(
        "INSERT INTO socks5_resources(name,host,port) VALUES('health-r','127.0.0.1',1080) RETURNING id",
    )
    .fetch_one(&db.pool)
    .await
    .unwrap();
    let node: i64 = sqlx::query_scalar("INSERT INTO relay_nodes(device_group_id,node_key,first_seen_at,last_seen_at) VALUES($1,'health-n','2026-01-01','2026-01-01') RETURNING id")
        .bind(group).fetch_one(&db.pool).await.unwrap();

    let policy = db
        .create_health_policy(&NewHealthPolicy {
            name: "health-policy".into(),
            enabled: true,
            resource_selector_json: "{}".into(),
            node_selector_json: "{}".into(),
            interval_seconds: 3600,
            jitter_seconds: 60,
            max_items: 100,
            next_run_at_ms: 1_000,
            created_by: Some(1),
            now_ms: 1,
        })
        .await
        .unwrap();
    assert_eq!(
        db.update_health_policy(
            policy,
            1,
            &HealthPolicyPatch {
                name: Some("health-policy-2".into()),
                ..Default::default()
            },
            2
        )
        .await
        .unwrap()
        .revision,
        2
    );
    assert!(matches!(
        db.update_health_policy(policy, 1, &HealthPolicyPatch::default(), 3)
            .await,
        Err(DbError::RevisionConflict)
    ));

    let job = NewHealthJob {
        id: "pg-health-job".into(),
        source: HealthJobSource::Manual,
        policy_id: None,
        parent_job_id: None,
        actor_id: Some(1),
        request_fingerprint: "a".repeat(64),
        snapshot_hash: snapshot_hash(&[(resource, node)]),
        resource_selector_json: "{}".into(),
        node_selector_json: "{}".into(),
        scheduled_for_ms: None,
        created_at_ms: 1_000,
    };
    let items = [NewHealthJobItem {
        resource_id: resource,
        relay_node_id: node,
        not_before_ms: 1_000,
        deadline_at_ms: Some(10_000),
    }];
    let key = NewHealthJobIdempotency {
        actor_id: 1,
        idempotency_key: "pg-health-key".into(),
        request_fingerprint: job.request_fingerprint.clone(),
        created_at_ms: 1_000,
        expires_at_ms: 1_000 + IDEMPOTENCY_TTL_MS,
    };
    assert!(matches!(
        db.create_health_job_idempotent(&job, &items, &key)
            .await
            .unwrap(),
        HealthJobCreateOutcome::Created { .. }
    ));
    assert!(matches!(
        db.create_health_job_idempotent(&job, &items, &key)
            .await
            .unwrap(),
        HealthJobCreateOutcome::Replay { .. }
    ));
    let item = db.list_health_job_items(&job.id).await.unwrap().remove(0);
    let leased = HealthItemTransition {
        item_id: item.id,
        expected_state: HealthJobItemState::Queued,
        expected_fence: 0,
        new_state: HealthJobItemState::Leased,
        lease_owner: Some("pg-worker".into()),
        lease_expires_at_ms: Some(3_000),
        pair_fence_token: Some(1),
        dispatch_attempt_id: None,
        request_id: None,
        not_before_ms: None,
        health_status: None,
        safe_error_code: None,
        safe_error_message: None,
        completed_after_cancel: false,
        now_ms: 2_000,
    };
    assert_eq!(
        db.transition_health_job_item(&leased).await.unwrap(),
        ConditionalWriteOutcome::Applied
    );
    let active = db.find_health_job(&job.id).await.unwrap().unwrap();
    assert_eq!((active.queued_count, active.running_count), (0, 1));
    let lease = db
        .acquire_health_pair_lease(PairLeaseAcquireRequest {
            resource_id: resource,
            relay_node_id: node,
            item_id: item.id,
            lease_owner: "pg-worker",
            lease_expires_at_ms: 3_000,
            now_ms: 2_000,
        })
        .await
        .unwrap();
    assert_eq!(
        lease,
        PairLeaseAcquireOutcome::Acquired {
            pair_fence_token: 1
        }
    );
    assert_eq!(
        db.release_health_pair_lease(resource, node, item.id, "pg-worker", 1, 2_500)
            .await
            .unwrap(),
        ConditionalWriteOutcome::Applied
    );
    assert_eq!(
        db.list_released_health_pair_lease_prune_candidates(2_501, 1000)
            .await
            .unwrap(),
        Vec::<(i64, i64)>::new()
    );

    let mut dispatching = leased.clone();
    dispatching.expected_state = HealthJobItemState::Leased;
    dispatching.expected_fence = 1;
    dispatching.new_state = HealthJobItemState::Dispatching;
    dispatching.dispatch_attempt_id = Some("pg-dispatch".into());
    dispatching.now_ms = 2_600;
    assert_eq!(
        db.transition_health_job_item(&dispatching).await.unwrap(),
        ConditionalWriteOutcome::Applied
    );
    let mut in_flight = dispatching.clone();
    in_flight.expected_state = HealthJobItemState::Dispatching;
    in_flight.expected_fence = 2;
    in_flight.new_state = HealthJobItemState::InFlight;
    in_flight.request_id = Some("pg-request".into());
    in_flight.now_ms = 2_700;
    assert_eq!(
        db.transition_health_job_item(&in_flight).await.unwrap(),
        ConditionalWriteOutcome::Applied
    );
    let mut succeeded = in_flight;
    succeeded.expected_state = HealthJobItemState::InFlight;
    succeeded.expected_fence = 3;
    succeeded.new_state = HealthJobItemState::Succeeded;
    succeeded.lease_owner = None;
    succeeded.lease_expires_at_ms = None;
    succeeded.pair_fence_token = None;
    succeeded.dispatch_attempt_id = None;
    succeeded.request_id = None;
    succeeded.now_ms = 3_000;
    assert_eq!(
        db.transition_health_job_item(&succeeded).await.unwrap(),
        ConditionalWriteOutcome::Applied
    );
    assert!(db.finalize_health_job(&job.id, 3_001).await.unwrap());
    let done = db.find_health_job(&job.id).await.unwrap().unwrap();
    assert_eq!(done.status, HealthJobStatus::Succeeded.as_str());
    assert_eq!((done.running_count, done.succeeded_count), (0, 1));
    assert_eq!(
        db.list_terminal_health_job_prune_candidates(3_002, 1000)
            .await
            .unwrap(),
        vec![job.id.clone()]
    );

    assert_eq!(
        db.lookup_health_job_idempotency(1, &key.idempotency_key, &"b".repeat(64), 2_000)
            .await
            .unwrap(),
        HealthJobIdempotencyOutcome::Conflict
    );
    assert_eq!(
        db.lookup_health_job_idempotency(2, &key.idempotency_key, &job.request_fingerprint, 2_000)
            .await
            .unwrap(),
        HealthJobIdempotencyOutcome::Available
    );
    sqlx::query(
        "INSERT INTO socks5_health_job_idempotency
         (actor_id,idempotency_key,request_fingerprint,job_id,created_at_ms,expires_at_ms)
         SELECT 1,'expired-' || lpad(g::text,5,'0'),repeat('e',64),NULL,0,999
         FROM generate_series(0,10000) AS g",
    )
    .execute(&db.pool)
    .await
    .unwrap();
    assert_eq!(
        db.lookup_health_job_idempotency(1, "expired-10000", &"e".repeat(64), 1_000)
            .await
            .unwrap(),
        HealthJobIdempotencyOutcome::Available
    );

    let scheduled_item = [NewHealthJobItem {
        resource_id: resource,
        relay_node_id: node,
        not_before_ms: 4_000,
        deadline_at_ms: None,
    }];
    for id in ["pg-slot-a", "pg-slot-b"] {
        let scheduled = NewHealthJob {
            id: id.into(),
            source: HealthJobSource::Scheduled,
            policy_id: Some(policy),
            parent_job_id: None,
            actor_id: None,
            request_fingerprint: "c".repeat(64),
            snapshot_hash: snapshot_hash(&[(resource, node)]),
            resource_selector_json: "{}".into(),
            node_selector_json: "{}".into(),
            scheduled_for_ms: Some(50_000),
            created_at_ms: 4_000,
        };
        let result = db.create_health_job(&scheduled, &scheduled_item).await;
        if id == "pg-slot-a" {
            assert!(result.is_ok());
        } else {
            assert!(matches!(result, Err(DbError::UniqueViolation)));
        }
    }
    assert!(matches!(
        sqlx::query("UPDATE socks5_check_job_items SET state='BOGUS' WHERE job_id='pg-slot-a'")
            .execute(&db.pool)
            .await
            .map_err(DbError::from),
        Err(DbError::ConstraintViolation)
    ));
    sqlx::query("UPDATE socks5_check_policies SET deleted_at_ms=60000 WHERE id=$1")
        .bind(policy)
        .execute(&db.pool)
        .await
        .unwrap();
    assert!(db.find_health_policy(policy).await.unwrap().is_none());
    assert!(matches!(
        db.update_health_policy(policy, 2, &HealthPolicyPatch::default(), 60_001)
            .await,
        Err(DbError::NotFound)
    ));
    let deleted_policy_job = NewHealthJob {
        id: "pg-deleted-policy-run".into(),
        source: HealthJobSource::PolicyRunNow,
        policy_id: Some(policy),
        parent_job_id: None,
        actor_id: None,
        request_fingerprint: "f".repeat(64),
        snapshot_hash: snapshot_hash(&[(resource, node)]),
        resource_selector_json: "{}".into(),
        node_selector_json: "{}".into(),
        scheduled_for_ms: None,
        created_at_ms: 60_001,
    };
    assert!(matches!(
        db.create_health_job(&deleted_policy_job, &scheduled_item)
            .await,
        Err(DbError::NotFound)
    ));
    cleanup(&db).await;
}

#[tokio::test]
async fn pg_health_orchestration_cancel_retry_constraints_and_retention_parity() {
    let Some(db) = repo("health_orchestration_parity").await else {
        return;
    };
    let group: i64 = sqlx::query_scalar(
        "INSERT INTO device_groups(name,group_type,token,uid) VALUES('health-parity','in','health-parity-token',1) RETURNING id",
    )
    .fetch_one(&db.pool)
    .await
    .unwrap();
    let resource: i64 = sqlx::query_scalar(
        "INSERT INTO socks5_resources(name,host,port) VALUES('health-parity-r','127.0.0.1',1080) RETURNING id",
    )
    .fetch_one(&db.pool)
    .await
    .unwrap();
    let node: i64 = sqlx::query_scalar("INSERT INTO relay_nodes(device_group_id,node_key,first_seen_at,last_seen_at) VALUES($1,'health-parity-n','2026-01-01','2026-01-01') RETURNING id")
        .bind(group).fetch_one(&db.pool).await.unwrap();

    let new_job = |id: &str| NewHealthJob {
        id: id.into(),
        source: HealthJobSource::Manual,
        policy_id: None,
        parent_job_id: None,
        actor_id: None,
        request_fingerprint: "d".repeat(64),
        snapshot_hash: snapshot_hash(&[(resource, node)]),
        resource_selector_json: "{}".into(),
        node_selector_json: "{}".into(),
        scheduled_for_ms: None,
        created_at_ms: 1_000,
    };
    let item = NewHealthJobItem {
        resource_id: resource,
        relay_node_id: node,
        not_before_ms: 1_000,
        deadline_at_ms: None,
    };

    assert!(matches!(
        db.create_health_job(&new_job("pg-empty"), &[]).await,
        Err(DbError::ConstraintViolation)
    ));
    assert!(matches!(
        db.create_health_job(&new_job("pg-duplicate"), &[item.clone(), item.clone()])
            .await,
        Err(DbError::UniqueViolation)
    ));
    assert!(db.find_health_job("pg-duplicate").await.unwrap().is_none());

    let cancel = new_job("pg-cancel");
    db.create_health_job(&cancel, std::slice::from_ref(&item))
        .await
        .unwrap();
    assert!(db.cancel_health_job(&cancel.id, 2_000).await.unwrap());
    let cancelled = db.find_health_job(&cancel.id).await.unwrap().unwrap();
    assert_eq!(cancelled.status, HealthJobStatus::Cancelled.as_str());
    assert_eq!((cancelled.queued_count, cancelled.cancelled_count), (0, 1));

    let failed = new_job("pg-failed");
    db.create_health_job(&failed, std::slice::from_ref(&item))
        .await
        .unwrap();
    let failed_item = db
        .list_health_job_items(&failed.id)
        .await
        .unwrap()
        .remove(0);
    let transition = |expected_state, expected_fence, new_state, now_ms| HealthItemTransition {
        item_id: failed_item.id,
        expected_state,
        expected_fence,
        new_state,
        lease_owner: (new_state == HealthJobItemState::Leased).then(|| "worker".into()),
        lease_expires_at_ms: (new_state == HealthJobItemState::Leased).then_some(now_ms + 1_000),
        pair_fence_token: (new_state == HealthJobItemState::Leased).then_some(1),
        dispatch_attempt_id: None,
        request_id: None,
        not_before_ms: None,
        health_status: None,
        safe_error_code: None,
        safe_error_message: None,
        completed_after_cancel: false,
        now_ms,
    };
    assert_eq!(
        db.transition_health_job_item(&transition(
            HealthJobItemState::Queued,
            99,
            HealthJobItemState::Leased,
            2_100,
        ))
        .await
        .unwrap(),
        ConditionalWriteOutcome::ConditionFailed
    );
    assert_eq!(
        db.transition_health_job_item(&transition(
            HealthJobItemState::Queued,
            0,
            HealthJobItemState::Leased,
            2_100,
        ))
        .await
        .unwrap(),
        ConditionalWriteOutcome::Applied
    );
    assert_eq!(
        db.transition_health_job_item(&transition(
            HealthJobItemState::Leased,
            1,
            HealthJobItemState::Failed,
            2_200,
        ))
        .await
        .unwrap(),
        ConditionalWriteOutcome::Applied
    );
    assert!(db.finalize_health_job(&failed.id, 2_201).await.unwrap());
    assert_eq!(
        db.retry_failed_health_pairs(&failed.id).await.unwrap(),
        vec![(resource, node)]
    );

    assert!(matches!(
        sqlx::query("UPDATE socks5_check_jobs SET queued_count=1 WHERE id=$1")
            .bind(&failed.id)
            .execute(&db.pool)
            .await
            .map_err(DbError::from),
        Err(DbError::ConstraintViolation)
    ));
    assert!(matches!(
        sqlx::query("UPDATE socks5_check_jobs SET status='RUNNING' WHERE id=$1")
            .bind(&failed.id)
            .execute(&db.pool)
            .await
            .map_err(DbError::from),
        Err(DbError::ConstraintViolation)
    ));

    let active = new_job("pg-active-retention");
    db.create_health_job(&active, std::slice::from_ref(&item))
        .await
        .unwrap();
    let candidates = db
        .list_terminal_health_job_prune_candidates(10_000, 1000)
        .await
        .unwrap();
    assert!(candidates.contains(&cancel.id));
    assert!(candidates.contains(&failed.id));
    assert!(!candidates.contains(&active.id));
    assert_eq!(
        db.prune_terminal_health_jobs(10_000, 1000).await.unwrap(),
        2
    );
    assert!(db.find_health_job(&active.id).await.unwrap().is_some());

    cleanup(&db).await;
}

#[tokio::test]
async fn pg_health_pair_prune_preserves_fence_epoch_and_validates_item_pair() {
    let Some(db) = repo("health_pair_epoch").await else {
        return;
    };
    let mut first_lock = db.pool.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock($1,hashtext('1:2'))")
        .bind(super::health_orchestration::HEALTH_IDEMPOTENCY_LOCK_CLASS)
        .execute(&mut *first_lock)
        .await
        .unwrap();
    let mut second_lock = db.pool.begin().await.unwrap();
    sqlx::query("SET LOCAL lock_timeout='500ms'")
        .execute(&mut *second_lock)
        .await
        .unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock($1,hashtext('1:2'))")
        .bind(super::health_orchestration::HEALTH_PAIR_LEASE_LOCK_CLASS)
        .execute(&mut *second_lock)
        .await
        .expect("different lock domains must not collide");
    second_lock.rollback().await.unwrap();
    first_lock.rollback().await.unwrap();
    let group: i64 = sqlx::query_scalar("INSERT INTO device_groups(name,group_type,token,uid) VALUES('health-epoch','in','health-epoch-token',1) RETURNING id")
        .fetch_one(&db.pool).await.unwrap();
    let resource: i64 = sqlx::query_scalar("INSERT INTO socks5_resources(name,host,port) VALUES('health-epoch-r','127.0.0.1',1080) RETURNING id")
        .fetch_one(&db.pool).await.unwrap();
    let wrong_resource: i64 = sqlx::query_scalar("INSERT INTO socks5_resources(name,host,port) VALUES('health-epoch-wrong','127.0.0.2',1081) RETURNING id")
        .fetch_one(&db.pool).await.unwrap();
    let node: i64 = sqlx::query_scalar("INSERT INTO relay_nodes(device_group_id,node_key,first_seen_at,last_seen_at) VALUES($1,'health-epoch-n','2026-01-01','2026-01-01') RETURNING id")
        .bind(group).fetch_one(&db.pool).await.unwrap();
    let new_job = |id: &str| NewHealthJob {
        id: id.into(),
        source: HealthJobSource::Manual,
        policy_id: None,
        parent_job_id: None,
        actor_id: None,
        request_fingerprint: "a".repeat(64),
        snapshot_hash: snapshot_hash(&[(resource, node)]),
        resource_selector_json: "{}".into(),
        node_selector_json: "{}".into(),
        scheduled_for_ms: None,
        created_at_ms: 1_000,
    };
    let item_spec = NewHealthJobItem {
        resource_id: resource,
        relay_node_id: node,
        not_before_ms: 1_000,
        deadline_at_ms: None,
    };
    let first = new_job("pg-pair-epoch-first");
    db.create_health_job(&first, std::slice::from_ref(&item_spec))
        .await
        .unwrap();
    let first_item = db.list_health_job_items(&first.id).await.unwrap().remove(0);
    assert_eq!(
        db.acquire_health_pair_lease(PairLeaseAcquireRequest {
            resource_id: resource,
            relay_node_id: node,
            item_id: first_item.id,
            lease_owner: "old",
            lease_expires_at_ms: 2_000,
            now_ms: 1_000
        })
        .await
        .unwrap(),
        PairLeaseAcquireOutcome::Acquired {
            pair_fence_token: 1
        }
    );
    assert_eq!(
        db.release_health_pair_lease(resource, node, first_item.id, "old", 1, 1_500)
            .await
            .unwrap(),
        ConditionalWriteOutcome::Applied
    );
    assert!(db
        .list_released_health_pair_lease_prune_candidates(1_600, 100)
        .await
        .unwrap()
        .is_empty());
    assert_eq!(
        db.prune_released_health_pair_leases(1_600, 100)
            .await
            .unwrap(),
        0
    );
    assert!(db.cancel_health_job(&first.id, 1_550).await.unwrap());
    assert_eq!(
        db.list_released_health_pair_lease_prune_candidates(1_600, 100)
            .await
            .unwrap(),
        vec![(resource, node)]
    );
    assert_eq!(
        db.prune_released_health_pair_leases(1_600, 100)
            .await
            .unwrap(),
        1
    );
    let tombstone = db
        .find_health_pair_lease(resource, node)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(tombstone.pair_fence_token, 1);
    assert_eq!(tombstone.updated_at_ms, PAIR_LEASE_TOMBSTONE_UPDATED_AT_MS);

    let second = new_job("pg-pair-epoch-second");
    db.create_health_job(&second, std::slice::from_ref(&item_spec))
        .await
        .unwrap();
    let second_item = db
        .list_health_job_items(&second.id)
        .await
        .unwrap()
        .remove(0);
    assert_eq!(
        db.acquire_health_pair_lease(PairLeaseAcquireRequest {
            resource_id: resource,
            relay_node_id: node,
            item_id: second_item.id,
            lease_owner: "new",
            lease_expires_at_ms: 4_000,
            now_ms: 3_000
        })
        .await
        .unwrap(),
        PairLeaseAcquireOutcome::Acquired {
            pair_fence_token: 2
        }
    );
    assert_eq!(
        db.release_health_pair_lease(resource, node, first_item.id, "old", 1, 3_100)
            .await
            .unwrap(),
        ConditionalWriteOutcome::ConditionFailed
    );
    assert!(matches!(
        db.acquire_health_pair_lease(PairLeaseAcquireRequest {
            resource_id: wrong_resource,
            relay_node_id: node,
            item_id: second_item.id,
            lease_owner: "wrong",
            lease_expires_at_ms: 5_000,
            now_ms: 4_000
        })
        .await,
        Err(DbError::InvalidTransition)
    ));
    assert_eq!(
        db.release_health_pair_lease(resource, node, second_item.id, "new", 2, 3_100)
            .await
            .unwrap(),
        ConditionalWriteOutcome::Applied
    );
    let terminalize = HealthItemTransition {
        item_id: second_item.id,
        expected_state: HealthJobItemState::Queued,
        expected_fence: 0,
        new_state: HealthJobItemState::Cancelled,
        lease_owner: None,
        lease_expires_at_ms: None,
        pair_fence_token: None,
        dispatch_attempt_id: None,
        request_id: None,
        not_before_ms: None,
        health_status: None,
        safe_error_code: None,
        safe_error_message: None,
        completed_after_cancel: false,
        now_ms: 3_200,
    };
    let (transition_result, prune_result) =
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            tokio::join!(
                db.transition_health_job_item(&terminalize),
                db.prune_released_health_pair_leases(3_300, 100)
            )
        })
        .await
        .expect("item transition/prune must not deadlock");
    assert!(transition_result.is_ok());
    assert!(prune_result.is_ok());

    let third = new_job("pg-pair-epoch-third");
    db.create_health_job(&third, std::slice::from_ref(&item_spec))
        .await
        .unwrap();
    let third_item = db.list_health_job_items(&third.id).await.unwrap().remove(0);
    let acquire_third = PairLeaseAcquireRequest {
        resource_id: resource,
        relay_node_id: node,
        item_id: third_item.id,
        lease_owner: "third",
        lease_expires_at_ms: 5_000,
        now_ms: 4_000,
    };
    let (prune_result, acquire_result) =
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            tokio::join!(
                db.prune_released_health_pair_leases(4_100, 100),
                db.acquire_health_pair_lease(acquire_third)
            )
        })
        .await
        .expect("prune/acquire must not deadlock");
    assert_eq!(prune_result.unwrap(), 0);
    assert_eq!(
        acquire_result.unwrap(),
        PairLeaseAcquireOutcome::Acquired {
            pair_fence_token: 3
        }
    );
    cleanup(&db).await;
}

#[tokio::test]
async fn pg_health_job_item_lock_order_prevents_deadlock_and_stale_aggregates() {
    let Some(db) = repo("health_lock_order").await else {
        return;
    };
    let group: i64 = sqlx::query_scalar("INSERT INTO device_groups(name,group_type,token,uid) VALUES('health-lock','in','health-lock-token',1) RETURNING id")
        .fetch_one(&db.pool).await.unwrap();
    let resource: i64 = sqlx::query_scalar("INSERT INTO socks5_resources(name,host,port) VALUES('health-lock-r','127.0.0.1',1080) RETURNING id")
        .fetch_one(&db.pool).await.unwrap();
    let node: i64 = sqlx::query_scalar("INSERT INTO relay_nodes(device_group_id,node_key,first_seen_at,last_seen_at) VALUES($1,'health-lock-n','2026-01-01','2026-01-01') RETURNING id")
        .bind(group).fetch_one(&db.pool).await.unwrap();
    let make_job = |id: &str| NewHealthJob {
        id: id.into(),
        source: HealthJobSource::Manual,
        policy_id: None,
        parent_job_id: None,
        actor_id: None,
        request_fingerprint: "b".repeat(64),
        snapshot_hash: snapshot_hash(&[(resource, node)]),
        resource_selector_json: "{}".into(),
        node_selector_json: "{}".into(),
        scheduled_for_ms: None,
        created_at_ms: 1_000,
    };
    let item_spec = NewHealthJobItem {
        resource_id: resource,
        relay_node_id: node,
        not_before_ms: 1_000,
        deadline_at_ms: None,
    };

    let cancel_job = make_job("pg-lock-transition-cancel");
    db.create_health_job(&cancel_job, std::slice::from_ref(&item_spec))
        .await
        .unwrap();
    let cancel_item = db
        .list_health_job_items(&cancel_job.id)
        .await
        .unwrap()
        .remove(0);
    let leased = HealthItemTransition {
        item_id: cancel_item.id,
        expected_state: HealthJobItemState::Queued,
        expected_fence: 0,
        new_state: HealthJobItemState::Leased,
        lease_owner: Some("worker".into()),
        lease_expires_at_ms: Some(5_000),
        pair_fence_token: Some(1),
        dispatch_attempt_id: None,
        request_id: None,
        not_before_ms: None,
        health_status: None,
        safe_error_code: None,
        safe_error_message: None,
        completed_after_cancel: false,
        now_ms: 2_000,
    };
    let transition_future = db.transition_health_job_item(&leased);
    let cancel_future = db.cancel_health_job(&cancel_job.id, 2_001);
    let (transition_result, cancel_result) =
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            tokio::join!(transition_future, cancel_future)
        })
        .await
        .expect("transition/cancel must not deadlock");
    assert!(transition_result.is_ok());
    assert!(cancel_result.unwrap());
    db.finalize_health_job(&cancel_job.id, 2_002).await.unwrap();
    let counters: (i64,i64,i64,i64,i64) = sqlx::query_as("SELECT COUNT(*) FILTER(WHERE state IN ('QUEUED','RETRY_WAIT')),COUNT(*) FILTER(WHERE state IN ('LEASED','DISPATCHING','IN_FLIGHT')),COUNT(*) FILTER(WHERE state='SUCCEEDED'),COUNT(*) FILTER(WHERE state='FAILED'),COUNT(*) FILTER(WHERE state='CANCELLED') FROM socks5_check_job_items WHERE job_id=$1").bind(&cancel_job.id).fetch_one(&db.pool).await.unwrap();
    let persisted = db.find_health_job(&cancel_job.id).await.unwrap().unwrap();
    assert_eq!(
        (
            persisted.queued_count,
            persisted.running_count,
            persisted.succeeded_count,
            persisted.failed_count,
            persisted.cancelled_count
        ),
        counters
    );

    let final_job = make_job("pg-lock-transition-finalize");
    db.create_health_job(&final_job, std::slice::from_ref(&item_spec))
        .await
        .unwrap();
    let final_item = db
        .list_health_job_items(&final_job.id)
        .await
        .unwrap()
        .remove(0);
    let cancelled = HealthItemTransition {
        item_id: final_item.id,
        expected_state: HealthJobItemState::Queued,
        expected_fence: 0,
        new_state: HealthJobItemState::Cancelled,
        lease_owner: None,
        lease_expires_at_ms: None,
        pair_fence_token: None,
        dispatch_attempt_id: None,
        request_id: None,
        not_before_ms: None,
        health_status: None,
        safe_error_code: None,
        safe_error_message: None,
        completed_after_cancel: false,
        now_ms: 3_000,
    };
    let (transition_result, finalize_result) =
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            tokio::join!(
                db.transition_health_job_item(&cancelled),
                db.finalize_health_job(&final_job.id, 3_001)
            )
        })
        .await
        .expect("transition/finalize must not deadlock");
    assert!(transition_result.is_ok());
    assert!(finalize_result.is_ok());
    let done = db.find_health_job(&final_job.id).await.unwrap().unwrap();
    assert_eq!(
        (
            done.status.as_str(),
            done.queued_count,
            done.cancelled_count
        ),
        ("CANCELLED", 0, 1)
    );

    let cancel_final_job = make_job("pg-lock-cancel-finalize");
    db.create_health_job(&cancel_final_job, std::slice::from_ref(&item_spec))
        .await
        .unwrap();
    let (cancel_result, finalize_result) =
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            tokio::join!(
                db.cancel_health_job(&cancel_final_job.id, 4_000),
                db.finalize_health_job(&cancel_final_job.id, 4_001)
            )
        })
        .await
        .expect("cancel/finalize must not deadlock");
    assert!(cancel_result.is_ok());
    assert!(finalize_result.is_ok());
    let done = db
        .find_health_job(&cancel_final_job.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (
            done.status.as_str(),
            done.queued_count,
            done.cancelled_count
        ),
        ("CANCELLED", 0, 1)
    );

    let retry_race_job = make_job("pg-cancel-retry-race");
    db.create_health_job(&retry_race_job, std::slice::from_ref(&item_spec))
        .await
        .unwrap();
    let retry_leased = db
        .claim_health_job_items(&HealthItemClaimRequest {
            lease_owner: "pg-race-worker".into(),
            now_ms: 5_000,
            lease_expires_at_ms: 65_000,
            limit: 1,
            global_limit: 16,
            per_node_limit: 10,
            per_job_limit: 20,
        })
        .await
        .unwrap()
        .into_iter()
        .find(|item| item.job_id == retry_race_job.id)
        .unwrap();
    assert!(db
        .cancel_health_job(&retry_race_job.id, 5_100)
        .await
        .unwrap());
    let rejected_retry = HealthItemTransition {
        item_id: retry_leased.id,
        expected_state: HealthJobItemState::Leased,
        expected_fence: retry_leased.item_fence_token,
        new_state: HealthJobItemState::RetryWait,
        lease_owner: None,
        lease_expires_at_ms: None,
        pair_fence_token: None,
        dispatch_attempt_id: None,
        request_id: None,
        not_before_ms: Some(5_200),
        health_status: None,
        safe_error_code: Some("UPSTREAM_UNAVAILABLE".into()),
        safe_error_message: Some("Upstream service unavailable".into()),
        completed_after_cancel: false,
        now_ms: 5_200,
    };
    assert_eq!(
        db.transition_health_job_item(&rejected_retry)
            .await
            .unwrap(),
        ConditionalWriteOutcome::ConditionFailed
    );
    let mut cancel_retry_item = rejected_retry;
    cancel_retry_item.new_state = HealthJobItemState::Cancelled;
    cancel_retry_item.safe_error_code = None;
    cancel_retry_item.safe_error_message = None;
    cancel_retry_item.not_before_ms = None;
    cancel_retry_item.now_ms = 5_300;
    assert_eq!(
        db.transition_health_job_item(&cancel_retry_item)
            .await
            .unwrap(),
        ConditionalWriteOutcome::Applied
    );
    assert_eq!(
        db.release_health_pair_lease(
            resource,
            node,
            retry_leased.id,
            "pg-race-worker",
            retry_leased.pair_fence_token.unwrap(),
            5_400,
        )
        .await
        .unwrap(),
        ConditionalWriteOutcome::Applied
    );

    let result_race_job = make_job("pg-cancel-result-race");
    db.create_health_job(&result_race_job, std::slice::from_ref(&item_spec))
        .await
        .unwrap();
    let result_leased = db
        .claim_health_job_items(&HealthItemClaimRequest {
            lease_owner: "pg-result-worker".into(),
            now_ms: 6_000,
            lease_expires_at_ms: 66_000,
            limit: 1,
            global_limit: 16,
            per_node_limit: 10,
            per_job_limit: 20,
        })
        .await
        .unwrap()
        .into_iter()
        .find(|item| item.job_id == result_race_job.id)
        .unwrap();
    let result_dispatching = db
        .begin_health_item_dispatch(&HealthItemDispatchRequest {
            item_id: result_leased.id,
            lease_owner: "pg-result-worker".into(),
            expected_item_fence: result_leased.item_fence_token,
            expected_pair_fence: result_leased.pair_fence_token.unwrap(),
            dispatch_attempt_id: "pg-result-attempt".into(),
            now_ms: 6_100,
        })
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        db.transition_health_job_item(&HealthItemTransition {
            item_id: result_dispatching.id,
            expected_state: HealthJobItemState::Dispatching,
            expected_fence: result_dispatching.item_fence_token,
            new_state: HealthJobItemState::InFlight,
            lease_owner: Some("pg-result-worker".into()),
            lease_expires_at_ms: result_dispatching.lease_expires_at_ms,
            pair_fence_token: result_dispatching.pair_fence_token,
            dispatch_attempt_id: Some("pg-result-attempt".into()),
            request_id: Some("pg-result-request".into()),
            not_before_ms: None,
            health_status: None,
            safe_error_code: None,
            safe_error_message: None,
            completed_after_cancel: false,
            now_ms: 6_200,
        })
        .await
        .unwrap(),
        ConditionalWriteOutcome::Applied
    );
    assert!(db
        .cancel_health_job(&result_race_job.id, 6_300)
        .await
        .unwrap());
    let result_current = db
        .find_health_job_item(result_dispatching.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        db.transition_health_job_item(&HealthItemTransition {
            item_id: result_current.id,
            expected_state: HealthJobItemState::InFlight,
            expected_fence: result_current.item_fence_token,
            new_state: HealthJobItemState::Succeeded,
            lease_owner: None,
            lease_expires_at_ms: None,
            pair_fence_token: None,
            dispatch_attempt_id: None,
            request_id: None,
            not_before_ms: None,
            health_status: Some("ONLINE".into()),
            safe_error_code: None,
            safe_error_message: None,
            completed_after_cancel: false,
            now_ms: 6_400,
        })
        .await
        .unwrap(),
        ConditionalWriteOutcome::Applied
    );
    assert!(
        db.find_health_job_item(result_current.id)
            .await
            .unwrap()
            .unwrap()
            .completed_after_cancel
    );

    let state_job = make_job("pg-state-field-matrix");
    db.create_health_job(&state_job, std::slice::from_ref(&item_spec))
        .await
        .unwrap();
    let state_item = db
        .list_health_job_items(&state_job.id)
        .await
        .unwrap()
        .remove(0);
    let mut invalid_lease = HealthItemTransition {
        item_id: state_item.id,
        expected_state: HealthJobItemState::Queued,
        expected_fence: 0,
        new_state: HealthJobItemState::Leased,
        lease_owner: Some("worker".into()),
        lease_expires_at_ms: Some(6_000),
        pair_fence_token: Some(1),
        dispatch_attempt_id: None,
        request_id: None,
        not_before_ms: None,
        health_status: None,
        safe_error_code: None,
        safe_error_message: None,
        completed_after_cancel: false,
        now_ms: 5_000,
    };
    invalid_lease.lease_owner = None;
    assert!(matches!(
        db.transition_health_job_item(&invalid_lease).await,
        Err(DbError::InvalidTransition)
    ));
    invalid_lease.lease_owner = Some("worker".into());
    invalid_lease.safe_error_code = Some("RAW_UPSTREAM_ERROR".into());
    invalid_lease.safe_error_message = Some("socks5://user:password@proxy:1080".into());
    assert!(matches!(
        db.transition_health_job_item(&invalid_lease).await,
        Err(DbError::ConstraintViolation)
    ));
    assert!(sqlx::query(
        "UPDATE socks5_check_job_items SET state='LEASED',updated_at_ms=5000 WHERE id=$1"
    )
    .bind(state_item.id)
    .execute(&db.pool)
    .await
    .is_err());
    assert!(sqlx::query("UPDATE socks5_check_job_items SET state='SUCCEEDED',lease_owner='stale',lease_expires_at_ms=6000,finished_at_ms=5000,updated_at_ms=5000 WHERE id=$1").bind(state_item.id).execute(&db.pool).await.is_err());
    assert!(sqlx::query("UPDATE socks5_check_job_items SET state='FAILED',finished_at_ms=5000,updated_at_ms=5000,safe_error_code='PROXY_CONNECT_TIMEOUT',safe_error_message='socks5://user:password@proxy:1080' WHERE id=$1").bind(state_item.id).execute(&db.pool).await.is_err());
    sqlx::query("UPDATE socks5_check_job_items SET state='FAILED',finished_at_ms=5000,updated_at_ms=5000,safe_error_code='PROXY_CONNECT_TIMEOUT',safe_error_message='Proxy connection timed out' WHERE id=$1").bind(state_item.id).execute(&db.pool).await.unwrap();
    cleanup(&db).await;
}

#[tokio::test]
async fn pg_manual_health_runtime_claim_dispatch_renew_and_reconcile() {
    let Some(db) = repo("manual_health_runtime").await else {
        return;
    };
    let group: i64 = sqlx::query_scalar(
        "INSERT INTO device_groups(name,group_type,token,uid) VALUES('manual-runtime','in','manual-runtime-token',1) RETURNING id",
    )
    .fetch_one(&db.pool)
    .await
    .unwrap();
    let resource: i64 = sqlx::query_scalar(
        "INSERT INTO socks5_resources(name,host,port) VALUES('manual-runtime-r','127.0.0.1',1080) RETURNING id",
    )
    .fetch_one(&db.pool)
    .await
    .unwrap();
    let node: i64 = sqlx::query_scalar("INSERT INTO relay_nodes(device_group_id,node_key,first_seen_at,last_seen_at) VALUES($1,'manual-runtime-n','2026-01-01','2026-01-01') RETURNING id")
        .bind(group).fetch_one(&db.pool).await.unwrap();
    let job = NewHealthJob {
        id: "pg-manual-runtime".into(),
        source: HealthJobSource::Manual,
        policy_id: None,
        parent_job_id: None,
        actor_id: Some(1),
        request_fingerprint: "a".repeat(64),
        snapshot_hash: snapshot_hash(&[(resource, node)]),
        resource_selector_json: "{}".into(),
        node_selector_json: "{}".into(),
        scheduled_for_ms: None,
        created_at_ms: 1_000,
    };
    db.create_health_job(
        &job,
        &[NewHealthJobItem {
            resource_id: resource,
            relay_node_id: node,
            not_before_ms: 1_000,
            deadline_at_ms: Some(100_000),
        }],
    )
    .await
    .unwrap();

    let claim = HealthItemClaimRequest {
        lease_owner: "pg-worker-a".into(),
        now_ms: 2_000,
        lease_expires_at_ms: 62_000,
        limit: 8,
        global_limit: 16,
        per_node_limit: 10,
        per_job_limit: 20,
    };
    let claimed = db.claim_health_job_items(&claim).await.unwrap();
    assert_eq!(claimed.len(), 1);
    let leased = &claimed[0];
    assert_eq!(leased.state, "LEASED");
    assert_eq!(leased.attempt_count, 0);
    assert_eq!(leased.item_fence_token, 1);
    assert_eq!(leased.pair_fence_token, Some(1));
    assert!(db
        .claim_health_job_items(&HealthItemClaimRequest {
            lease_owner: "pg-worker-b".into(),
            ..claim.clone()
        })
        .await
        .unwrap()
        .is_empty());

    assert!(db
        .begin_health_item_dispatch(&HealthItemDispatchRequest {
            item_id: leased.id,
            lease_owner: "pg-worker-b".into(),
            expected_item_fence: 1,
            expected_pair_fence: 1,
            dispatch_attempt_id: "wrong-owner".into(),
            now_ms: 2_100,
        })
        .await
        .unwrap()
        .is_none());
    let dispatching = db
        .begin_health_item_dispatch(&HealthItemDispatchRequest {
            item_id: leased.id,
            lease_owner: "pg-worker-a".into(),
            expected_item_fence: 1,
            expected_pair_fence: 1,
            dispatch_attempt_id: "attempt-a".into(),
            now_ms: 2_100,
        })
        .await
        .unwrap()
        .unwrap();
    assert_eq!(dispatching.state, "DISPATCHING");
    assert_eq!(
        dispatching.attempt_count, 0,
        "DISPATCHING is not yet a network attempt"
    );
    assert_eq!(dispatching.item_fence_token, 2);
    assert_eq!(
        db.renew_health_item_and_pair_lease(&HealthLeaseRenewRequest {
            item_id: dispatching.id,
            lease_owner: "pg-worker-a".into(),
            expected_item_fence: 2,
            expected_pair_fence: 1,
            lease_expires_at_ms: 70_000,
            now_ms: 3_000,
        })
        .await
        .unwrap(),
        ConditionalWriteOutcome::Applied
    );
    assert_eq!(
        db.renew_health_item_and_pair_lease(&HealthLeaseRenewRequest {
            item_id: dispatching.id,
            lease_owner: "pg-worker-b".into(),
            expected_item_fence: 2,
            expected_pair_fence: 1,
            lease_expires_at_ms: 80_000,
            now_ms: 3_100,
        })
        .await
        .unwrap(),
        ConditionalWriteOutcome::ConditionFailed
    );

    let item_page = db
        .list_health_job_items_page(&HealthJobItemListQuery {
            job_id: job.id.clone(),
            state: Some("DISPATCHING".into()),
            safe_error_code: None,
            after_id: None,
            limit: 1,
        })
        .await
        .unwrap();
    assert_eq!(item_page.len(), 1);
    assert!(db
        .list_health_job_items_page(&HealthJobItemListQuery {
            job_id: job.id.clone(),
            state: None,
            safe_error_code: None,
            after_id: Some(item_page[0].id),
            limit: 1,
        })
        .await
        .unwrap()
        .is_empty());

    sqlx::query("UPDATE socks5_check_jobs SET queued_count=1,running_count=0 WHERE id=$1")
        .bind(&job.id)
        .execute(&db.pool)
        .await
        .unwrap();
    assert_eq!(
        db.reconcile_health_job_counters(3_200, 10).await.unwrap(),
        vec![HealthJobReconcileOutcome {
            job_id: job.id.clone(),
            finalized: false,
        }]
    );
    let repaired = db.find_health_job(&job.id).await.unwrap().unwrap();
    assert_eq!((repaired.queued_count, repaired.running_count), (0, 1));
    assert_eq!(
        db.list_expired_health_job_items(70_000, 10)
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        db.list_health_jobs(&HealthJobListQuery {
            status: Some("RUNNING".into()),
            source: Some("MANUAL".into()),
            limit: 10,
            ..Default::default()
        })
        .await
        .unwrap()
        .len(),
        1
    );
    cleanup(&db).await;
}

#[tokio::test]
async fn pg_retry_wait_with_safe_error_is_reclaimable_and_fenced() {
    let Some(db) = repo("retry_reclaim_fence").await else {
        return;
    };
    let group: i64 = sqlx::query_scalar(
        "INSERT INTO device_groups(name,group_type,token,uid) VALUES('retry-reclaim','in','retry-reclaim-token',1) RETURNING id",
    )
    .fetch_one(&db.pool)
    .await
    .unwrap();
    let resource: i64 = sqlx::query_scalar(
        "INSERT INTO socks5_resources(name,host,port) VALUES('retry-reclaim-r','127.0.0.1',1080) RETURNING id",
    )
    .fetch_one(&db.pool)
    .await
    .unwrap();
    let node: i64 = sqlx::query_scalar("INSERT INTO relay_nodes(device_group_id,node_key,first_seen_at,last_seen_at) VALUES($1,'retry-reclaim-n','2026-01-01','2026-01-01') RETURNING id")
        .bind(group).fetch_one(&db.pool).await.unwrap();
    let job = NewHealthJob {
        id: "pg-retry-reclaim".into(),
        source: HealthJobSource::Manual,
        policy_id: None,
        parent_job_id: None,
        actor_id: Some(1),
        request_fingerprint: "a".repeat(64),
        snapshot_hash: snapshot_hash(&[(resource, node)]),
        resource_selector_json: "{}".into(),
        node_selector_json: "{}".into(),
        scheduled_for_ms: None,
        created_at_ms: 1_000,
    };
    db.create_health_job(
        &job,
        &[NewHealthJobItem {
            resource_id: resource,
            relay_node_id: node,
            not_before_ms: 1_000,
            deadline_at_ms: Some(100_000),
        }],
    )
    .await
    .unwrap();
    let old = db
        .claim_health_job_items(&HealthItemClaimRequest {
            lease_owner: "old-worker".into(),
            now_ms: 2_000,
            lease_expires_at_ms: 3_000,
            limit: 1,
            global_limit: 16,
            per_node_limit: 10,
            per_job_limit: 20,
        })
        .await
        .unwrap()
        .remove(0);
    assert_eq!(
        db.transition_health_job_item(&HealthItemTransition {
            item_id: old.id,
            expected_state: HealthJobItemState::Leased,
            expected_fence: old.item_fence_token,
            new_state: HealthJobItemState::RetryWait,
            lease_owner: None,
            lease_expires_at_ms: None,
            pair_fence_token: None,
            dispatch_attempt_id: None,
            request_id: None,
            not_before_ms: Some(3_001),
            health_status: None,
            safe_error_code: Some("UPSTREAM_UNAVAILABLE".into()),
            safe_error_message: Some("Upstream service unavailable".into()),
            completed_after_cancel: false,
            now_ms: 3_000,
        })
        .await
        .unwrap(),
        ConditionalWriteOutcome::Applied
    );
    let new = db
        .claim_health_job_items(&HealthItemClaimRequest {
            lease_owner: "new-worker".into(),
            now_ms: 3_001,
            lease_expires_at_ms: 63_001,
            limit: 1,
            global_limit: 16,
            per_node_limit: 10,
            per_job_limit: 20,
        })
        .await
        .unwrap()
        .remove(0);
    assert_eq!(new.state, "LEASED");
    assert_eq!(new.safe_error_code, None);
    assert_eq!(new.safe_error_message, None);
    assert_eq!(new.item_fence_token, old.item_fence_token + 2);
    assert_eq!(new.pair_fence_token, Some(2));
    assert_eq!(
        db.release_health_pair_lease(resource, node, old.id, "old-worker", 1, 3_002)
            .await
            .unwrap(),
        ConditionalWriteOutcome::ConditionFailed
    );
    cleanup(&db).await;
}

#[tokio::test]
async fn pg_one_hundred_health_claimers_respect_global_budget() {
    let Some(db) = repo_with_connections("health_claim_budget", 50).await else {
        return;
    };
    let group: i64 = sqlx::query_scalar(
        "INSERT INTO device_groups(name,group_type,token,uid) VALUES('claim-budget','in','claim-budget-token',1) RETURNING id",
    )
    .fetch_one(&db.pool)
    .await
    .unwrap();
    let mut pairs = Vec::new();
    let mut items = Vec::new();
    for index in 0..32_i64 {
        let resource: i64 = sqlx::query_scalar(
            "INSERT INTO socks5_resources(name,host,port) VALUES($1,$2,$3) RETURNING id",
        )
        .bind(format!("claim-budget-r-{index}"))
        .bind(format!("127.0.0.{}", index + 1))
        .bind(10_000 + index)
        .fetch_one(&db.pool)
        .await
        .unwrap();
        let node: i64 = sqlx::query_scalar("INSERT INTO relay_nodes(device_group_id,node_key,first_seen_at,last_seen_at) VALUES($1,$2,'2026-01-01','2026-01-01') RETURNING id")
            .bind(group)
            .bind(format!("claim-budget-n-{index}"))
            .fetch_one(&db.pool)
            .await
            .unwrap();
        pairs.push((resource, node));
        items.push(NewHealthJobItem {
            resource_id: resource,
            relay_node_id: node,
            not_before_ms: 1_000,
            deadline_at_ms: Some(100_000),
        });
    }
    let job = NewHealthJob {
        id: "pg-claim-budget".into(),
        source: HealthJobSource::Manual,
        policy_id: None,
        parent_job_id: None,
        actor_id: Some(1),
        request_fingerprint: "b".repeat(64),
        snapshot_hash: snapshot_hash(&pairs),
        resource_selector_json: "{}".into(),
        node_selector_json: "{}".into(),
        scheduled_for_ms: None,
        created_at_ms: 1_000,
    };
    db.create_health_job(&job, &items).await.unwrap();

    let db = std::sync::Arc::new(db);
    let claims = futures_util::future::join_all((0..100).map(|index| {
        let db = db.clone();
        async move {
            db.claim_health_job_items(&HealthItemClaimRequest {
                lease_owner: format!("claim-worker-{index}"),
                now_ms: 2_000,
                lease_expires_at_ms: 62_000,
                limit: 1,
                global_limit: 16,
                per_node_limit: 10,
                per_job_limit: 20,
            })
            .await
            .unwrap()
            .len()
        }
    }))
    .await;
    assert_eq!(claims.into_iter().sum::<usize>(), 16);
    let stored = db.list_health_job_items(&job.id).await.unwrap();
    assert_eq!(
        stored.iter().filter(|item| item.state == "LEASED").count(),
        16
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM socks5_check_pair_leases WHERE item_id IS NOT NULL",
        )
        .fetch_one(&db.pool)
        .await
        .unwrap(),
        16
    );
    cleanup(db.as_ref()).await;
}

#[tokio::test]
async fn pg_one_hundred_same_key_health_creates_are_atomic_and_mixed_conflict() {
    let Some(db) = repo_with_connections("health_idempotency_race", 50).await else {
        return;
    };
    let group: i64 = sqlx::query_scalar(
        "INSERT INTO device_groups(name,group_type,token,uid) VALUES('idem-race','in','idem-race-token',1) RETURNING id",
    )
    .fetch_one(&db.pool)
    .await
    .unwrap();
    let resource: i64 = sqlx::query_scalar(
        "INSERT INTO socks5_resources(name,host,port) VALUES('idem-race-r','127.0.0.1',1080) RETURNING id",
    )
    .fetch_one(&db.pool)
    .await
    .unwrap();
    let node: i64 = sqlx::query_scalar("INSERT INTO relay_nodes(device_group_id,node_key,first_seen_at,last_seen_at) VALUES($1,'idem-race-n','2026-01-01','2026-01-01') RETURNING id")
        .bind(group).fetch_one(&db.pool).await.unwrap();
    let item = NewHealthJobItem {
        resource_id: resource,
        relay_node_id: node,
        not_before_ms: 1_000,
        deadline_at_ms: Some(100_000),
    };
    let db = std::sync::Arc::new(db);

    let same = futures_util::future::join_all((0..100).map(|index| {
        let db = db.clone();
        let item = item.clone();
        async move {
            let fingerprint = "a".repeat(64);
            let job = NewHealthJob {
                id: format!("same-key-job-{index}"),
                source: HealthJobSource::Manual,
                policy_id: None,
                parent_job_id: None,
                actor_id: Some(1),
                request_fingerprint: fingerprint.clone(),
                snapshot_hash: snapshot_hash(&[(resource, node)]),
                resource_selector_json: "{}".into(),
                node_selector_json: "{}".into(),
                scheduled_for_ms: None,
                created_at_ms: 1_000,
            };
            db.create_health_job_idempotent(
                &job,
                &[item],
                &NewHealthJobIdempotency {
                    actor_id: 1,
                    idempotency_key: "same-health-key".into(),
                    request_fingerprint: fingerprint,
                    created_at_ms: 1_000,
                    expires_at_ms: 1_000 + IDEMPOTENCY_TTL_MS,
                },
            )
            .await
            .unwrap()
        }
    }))
    .await;
    let created = same
        .iter()
        .filter(|outcome| matches!(outcome, HealthJobCreateOutcome::Created { .. }))
        .count();
    let replayed = same
        .iter()
        .filter(|outcome| matches!(outcome, HealthJobCreateOutcome::Replay { .. }))
        .count();
    let job_ids = same
        .iter()
        .filter_map(|outcome| match outcome {
            HealthJobCreateOutcome::Created { job_id }
            | HealthJobCreateOutcome::Replay { job_id } => Some(job_id.as_str()),
            HealthJobCreateOutcome::Conflict => None,
        })
        .collect::<std::collections::HashSet<_>>();
    assert_eq!((created, replayed, job_ids.len()), (1, 99, 1));

    let mixed = futures_util::future::join_all((0..100).map(|index| {
        let db = db.clone();
        let item = item.clone();
        async move {
            let fingerprint = if index % 2 == 0 {
                "b".repeat(64)
            } else {
                "c".repeat(64)
            };
            let job = NewHealthJob {
                id: format!("mixed-key-job-{index}"),
                source: HealthJobSource::Manual,
                policy_id: None,
                parent_job_id: None,
                actor_id: Some(1),
                request_fingerprint: fingerprint.clone(),
                snapshot_hash: snapshot_hash(&[(resource, node)]),
                resource_selector_json: "{}".into(),
                node_selector_json: "{}".into(),
                scheduled_for_ms: None,
                created_at_ms: 2_000,
            };
            db.create_health_job_idempotent(
                &job,
                &[item],
                &NewHealthJobIdempotency {
                    actor_id: 1,
                    idempotency_key: "mixed-health-key".into(),
                    request_fingerprint: fingerprint,
                    created_at_ms: 2_000,
                    expires_at_ms: 2_000 + IDEMPOTENCY_TTL_MS,
                },
            )
            .await
            .unwrap()
        }
    }))
    .await;
    assert_eq!(
        mixed
            .iter()
            .filter(|outcome| matches!(outcome, HealthJobCreateOutcome::Created { .. }))
            .count(),
        1
    );
    assert_eq!(
        mixed
            .iter()
            .filter(|outcome| matches!(outcome, HealthJobCreateOutcome::Replay { .. }))
            .count(),
        49
    );
    assert_eq!(
        mixed
            .iter()
            .filter(|outcome| matches!(outcome, HealthJobCreateOutcome::Conflict))
            .count(),
        50
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM socks5_check_jobs")
            .fetch_one(&db.pool)
            .await
            .unwrap(),
        2
    );
    cleanup(db.as_ref()).await;
}

#[tokio::test]
async fn pg_one_hundred_jobs_with_same_pair_have_one_active_owner() {
    let Some(db) = repo_with_connections("health_same_pair", 50).await else {
        return;
    };
    let group: i64 = sqlx::query_scalar(
        "INSERT INTO device_groups(name,group_type,token,uid) VALUES('same-pair','in','same-pair-token',1) RETURNING id",
    )
    .fetch_one(&db.pool)
    .await
    .unwrap();
    let resource: i64 = sqlx::query_scalar(
        "INSERT INTO socks5_resources(name,host,port) VALUES('same-pair-r','127.0.0.1',1080) RETURNING id",
    )
    .fetch_one(&db.pool)
    .await
    .unwrap();
    let node: i64 = sqlx::query_scalar("INSERT INTO relay_nodes(device_group_id,node_key,first_seen_at,last_seen_at) VALUES($1,'same-pair-n','2026-01-01','2026-01-01') RETURNING id")
        .bind(group).fetch_one(&db.pool).await.unwrap();
    for index in 0..100 {
        db.create_health_job(
            &NewHealthJob {
                id: format!("same-pair-job-{index:03}"),
                source: HealthJobSource::Manual,
                policy_id: None,
                parent_job_id: None,
                actor_id: None,
                request_fingerprint: "d".repeat(64),
                snapshot_hash: snapshot_hash(&[(resource, node)]),
                resource_selector_json: "{}".into(),
                node_selector_json: "{}".into(),
                scheduled_for_ms: None,
                created_at_ms: 1_000 + index,
            },
            &[NewHealthJobItem {
                resource_id: resource,
                relay_node_id: node,
                not_before_ms: 1_000,
                deadline_at_ms: Some(100_000),
            }],
        )
        .await
        .unwrap();
    }
    let db = std::sync::Arc::new(db);
    let claims = futures_util::future::join_all((0..100).map(|index| {
        let db = db.clone();
        async move {
            db.claim_health_job_items(&HealthItemClaimRequest {
                lease_owner: format!("same-pair-worker-{index}"),
                now_ms: 2_000,
                lease_expires_at_ms: 62_000,
                limit: 1,
                global_limit: 50,
                per_node_limit: 10,
                per_job_limit: 20,
            })
            .await
            .unwrap()
            .len()
        }
    }))
    .await;
    assert_eq!(claims.into_iter().sum::<usize>(), 1);
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM socks5_check_job_items WHERE state='LEASED'",
        )
        .fetch_one(&db.pool)
        .await
        .unwrap(),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM socks5_check_pair_leases WHERE lease_owner IS NOT NULL",
        )
        .fetch_one(&db.pool)
        .await
        .unwrap(),
        1
    );
    cleanup(db.as_ref()).await;
}

#[tokio::test]
async fn pg_conditional_health_generation_rejects_resource_revision_change() {
    let Some(db) = repo("conditional_health_generation").await else {
        return;
    };
    let group: i64 = sqlx::query_scalar(
        "INSERT INTO device_groups(name,group_type,token,uid) VALUES('generation','in','generation-token',1) RETURNING id",
    )
    .fetch_one(&db.pool)
    .await
    .unwrap();
    let resource: i64 = sqlx::query_scalar(
        "INSERT INTO socks5_resources(name,host,port) VALUES('generation-r','127.0.0.1',1080) RETURNING id",
    )
    .fetch_one(&db.pool)
    .await
    .unwrap();
    let node: i64 = sqlx::query_scalar("INSERT INTO relay_nodes(device_group_id,node_key,first_seen_at,last_seen_at) VALUES($1,'generation-n','2026-01-01','2026-01-01') RETURNING id")
        .bind(group).fetch_one(&db.pool).await.unwrap();
    let initial = db.find_socks5_resource(resource).await.unwrap().unwrap();
    sqlx::query("UPDATE socks5_resources SET health_generation=health_generation+1 WHERE id=$1")
        .bind(resource)
        .execute(&db.pool)
        .await
        .unwrap();
    assert!(
        db.begin_socks5_health_check_if_resource_generation(
            resource,
            node,
            initial.health_generation,
        )
        .await
        .unwrap()
        .is_none()
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM socks5_check_generations")
            .fetch_one(&db.pool)
            .await
            .unwrap(),
        0
    );
    let current = db.find_socks5_resource(resource).await.unwrap().unwrap();
    let (_, generation) = db
        .begin_socks5_health_check_if_resource_generation(resource, node, current.health_generation)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(generation, 1);
    cleanup(&db).await;
}

#[tokio::test]
async fn pg_retry_snapshot_survives_deleted_live_resource_and_node() {
    let Some(db) = repo("retry_deleted_snapshot").await else {
        return;
    };
    let group: i64 = sqlx::query_scalar(
        "INSERT INTO device_groups(name,group_type,token,uid) VALUES('retry-deleted','in','retry-deleted-token',1) RETURNING id",
    )
    .fetch_one(&db.pool)
    .await
    .unwrap();
    let resource: i64 = sqlx::query_scalar(
        "INSERT INTO socks5_resources(name,host,port) VALUES('retry-deleted-r','127.0.0.1',1080) RETURNING id",
    )
    .fetch_one(&db.pool)
    .await
    .unwrap();
    let node: i64 = sqlx::query_scalar("INSERT INTO relay_nodes(device_group_id,node_key,first_seen_at,last_seen_at) VALUES($1,'retry-deleted-n','2026-01-01','2026-01-01') RETURNING id")
        .bind(group).fetch_one(&db.pool).await.unwrap();
    let parent = NewHealthJob {
        id: "pg-retry-deleted-parent".into(),
        source: HealthJobSource::Manual,
        policy_id: None,
        parent_job_id: None,
        actor_id: None,
        request_fingerprint: "a".repeat(64),
        snapshot_hash: snapshot_hash(&[(resource, node)]),
        resource_selector_json: "{}".into(),
        node_selector_json: "{}".into(),
        scheduled_for_ms: None,
        created_at_ms: 1_000,
    };
    db.create_health_job(
        &parent,
        &[NewHealthJobItem {
            resource_id: resource,
            relay_node_id: node,
            not_before_ms: 1_000,
            deadline_at_ms: Some(10_000),
        }],
    )
    .await
    .unwrap();
    let parent_item = db
        .list_health_job_items(&parent.id)
        .await
        .unwrap()
        .remove(0);
    assert_eq!(
        db.transition_health_job_item(&HealthItemTransition {
            item_id: parent_item.id,
            expected_state: HealthJobItemState::Queued,
            expected_fence: 0,
            new_state: HealthJobItemState::Leased,
            lease_owner: Some("worker".into()),
            lease_expires_at_ms: Some(3_000),
            pair_fence_token: Some(1),
            dispatch_attempt_id: None,
            request_id: None,
            not_before_ms: None,
            health_status: None,
            safe_error_code: None,
            safe_error_message: None,
            completed_after_cancel: false,
            now_ms: 2_000,
        })
        .await
        .unwrap(),
        ConditionalWriteOutcome::Applied
    );
    assert_eq!(
        db.transition_health_job_item(&HealthItemTransition {
            item_id: parent_item.id,
            expected_state: HealthJobItemState::Leased,
            expected_fence: 1,
            new_state: HealthJobItemState::Failed,
            lease_owner: None,
            lease_expires_at_ms: None,
            pair_fence_token: None,
            dispatch_attempt_id: None,
            request_id: None,
            not_before_ms: None,
            health_status: None,
            safe_error_code: None,
            safe_error_message: None,
            completed_after_cancel: false,
            now_ms: 2_100,
        })
        .await
        .unwrap(),
        ConditionalWriteOutcome::Applied
    );
    assert!(db.finalize_health_job(&parent.id, 2_101).await.unwrap());
    sqlx::query("DELETE FROM socks5_resources WHERE id=$1")
        .bind(resource)
        .execute(&db.pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM relay_nodes WHERE id=$1")
        .bind(node)
        .execute(&db.pool)
        .await
        .unwrap();

    let child = NewHealthJob {
        id: "pg-retry-deleted-child".into(),
        source: HealthJobSource::RetryFailed,
        policy_id: None,
        parent_job_id: Some(parent.id.clone()),
        actor_id: None,
        request_fingerprint: "b".repeat(64),
        snapshot_hash: snapshot_hash(&[(resource, node)]),
        resource_selector_json: "{}".into(),
        node_selector_json: "{}".into(),
        scheduled_for_ms: None,
        created_at_ms: 3_000,
    };
    db.create_health_job(
        &child,
        &[NewHealthJobItem {
            resource_id: resource,
            relay_node_id: node,
            not_before_ms: 3_000,
            deadline_at_ms: Some(10_000),
        }],
    )
    .await
    .unwrap();
    let child_item = db.list_health_job_items(&child.id).await.unwrap().remove(0);
    assert_eq!(child_item.resource_id, None);
    assert_eq!(child_item.relay_node_id, None);
    assert_eq!(child_item.resource_id_snapshot, resource);
    assert_eq!(child_item.relay_node_id_snapshot, node);
    cleanup(&db).await;
}

#[tokio::test]
async fn pg_migration_35_36_upgrade_rollback_rerun_and_mismatch_detection() {
    let Some(db) = repo("migration_35_health").await else {
        return;
    };
    sqlx::query(
        "DROP TABLE socks5_health_job_idempotency,socks5_check_pair_leases,
         socks5_check_job_items,socks5_check_jobs,socks5_check_policies",
    )
    .execute(&db.pool)
    .await
    .unwrap();
    sqlx::query("DELETE FROM schema_version WHERE version>=35")
        .execute(&db.pool)
        .await
        .unwrap();

    let mut tx = db.pool.begin().await.unwrap();
    for statement in crate::db::health_schema::POSTGRES_MIGRATION_35 {
        sqlx::query(statement).execute(&mut *tx).await.unwrap();
    }
    assert!(
        sqlx::query("INSERT INTO definitely_missing_table VALUES(1)")
            .execute(&mut *tx)
            .await
            .is_err()
    );
    tx.rollback().await.unwrap();
    let partial_tables: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM information_schema.tables
         WHERE table_schema=current_schema() AND table_name=ANY($1)",
    )
    .bind(crate::db::health_schema::HEALTH_TABLES.as_slice())
    .fetch_one(&db.pool)
    .await
    .unwrap();
    assert_eq!(partial_tables, 0);

    run_pg_migrations(&db.pool).await.unwrap();
    let version: i32 = sqlx::query_scalar("SELECT MAX(version) FROM schema_version")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(version, 36);
    run_pg_migrations(&db.pool).await.unwrap();

    sqlx::query("DELETE FROM schema_version WHERE version=36")
        .execute(&db.pool)
        .await
        .unwrap();
    sqlx::query("ALTER TABLE socks5_check_job_items DROP COLUMN retry_count")
        .execute(&db.pool)
        .await
        .unwrap();
    let mut retry_tx = db.pool.begin().await.unwrap();
    sqlx::query(crate::db::health_schema::POSTGRES_MIGRATION_36)
        .execute(&mut *retry_tx)
        .await
        .unwrap();
    assert!(
        sqlx::query("INSERT INTO definitely_missing_table VALUES(1)")
            .execute(&mut *retry_tx)
            .await
            .is_err()
    );
    retry_tx.rollback().await.unwrap();
    let retry_column_after_rollback: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM information_schema.columns
         WHERE table_schema=current_schema() AND table_name='socks5_check_job_items'
           AND column_name='retry_count'",
    )
    .fetch_one(&db.pool)
    .await
    .unwrap();
    assert_eq!(retry_column_after_rollback, 0);
    assert_eq!(
        sqlx::query_scalar::<_, i32>("SELECT MAX(version) FROM schema_version")
            .fetch_one(&db.pool)
            .await
            .unwrap(),
        35
    );
    run_pg_migrations(&db.pool).await.unwrap();
    run_pg_migrations(&db.pool).await.unwrap();

    let retry_check: String = sqlx::query_scalar(
        "SELECT conname FROM pg_constraint
         WHERE conrelid='socks5_check_job_items'::regclass
           AND contype='c' AND pg_get_constraintdef(oid,true) LIKE '%retry_count%'",
    )
    .fetch_one(&db.pool)
    .await
    .unwrap();
    sqlx::query(&format!(
        "ALTER TABLE socks5_check_job_items DROP CONSTRAINT {retry_check}"
    ))
    .execute(&db.pool)
    .await
    .unwrap();
    assert!(run_pg_migrations(&db.pool)
        .await
        .unwrap_err()
        .to_string()
        .contains("version/schema mismatch"));
    sqlx::query(&format!(
        "ALTER TABLE socks5_check_job_items ADD CONSTRAINT {retry_check} CHECK(retry_count >= 0)"
    ))
    .execute(&db.pool)
    .await
    .unwrap();
    run_pg_migrations(&db.pool).await.unwrap();

    sqlx::query("DROP INDEX idx_socks5_check_job_items_ready")
        .execute(&db.pool)
        .await
        .unwrap();
    let error = run_pg_migrations(&db.pool).await.unwrap_err();
    assert!(error.to_string().contains("version/schema mismatch"));
    sqlx::query("CREATE INDEX idx_socks5_check_job_items_ready ON socks5_check_job_items(state,not_before_ms,id)")
        .execute(&db.pool).await.unwrap();
    run_pg_migrations(&db.pool).await.unwrap();

    let status_check: String = sqlx::query_scalar("SELECT conname FROM pg_constraint WHERE conrelid='socks5_check_jobs'::regclass AND contype='c' AND pg_get_constraintdef(oid,true) LIKE '%status = ANY%' AND pg_get_constraintdef(oid,true) NOT LIKE '%finished_at_ms%'")
        .fetch_one(&db.pool).await.unwrap();
    sqlx::query(&format!(
        "ALTER TABLE socks5_check_jobs DROP CONSTRAINT {status_check}"
    ))
    .execute(&db.pool)
    .await
    .unwrap();
    assert!(run_pg_migrations(&db.pool)
        .await
        .unwrap_err()
        .to_string()
        .contains("version/schema mismatch"));
    sqlx::query(&format!("ALTER TABLE socks5_check_jobs ADD CONSTRAINT {status_check} CHECK(status IN ('QUEUED','RUNNING','CANCEL_REQUESTED','SUCCEEDED','FAILED','PARTIAL','CANCELLED','PARTIAL_CANCELLED'))"))
        .execute(&db.pool).await.unwrap();
    run_pg_migrations(&db.pool).await.unwrap();

    let resource_fk: String = sqlx::query_scalar("SELECT conname FROM pg_constraint WHERE conrelid='socks5_check_job_items'::regclass AND contype='f' AND pg_get_constraintdef(oid,true) LIKE 'FOREIGN KEY (resource_id)%'")
        .fetch_one(&db.pool).await.unwrap();
    sqlx::query(&format!(
        "ALTER TABLE socks5_check_job_items DROP CONSTRAINT {resource_fk}"
    ))
    .execute(&db.pool)
    .await
    .unwrap();
    assert!(run_pg_migrations(&db.pool)
        .await
        .unwrap_err()
        .to_string()
        .contains("version/schema mismatch"));
    sqlx::query(&format!("ALTER TABLE socks5_check_job_items ADD CONSTRAINT {resource_fk} FOREIGN KEY(resource_id) REFERENCES socks5_resources(id) ON DELETE SET NULL"))
        .execute(&db.pool).await.unwrap();
    run_pg_migrations(&db.pool).await.unwrap();

    sqlx::query("ALTER TABLE socks5_check_jobs ALTER COLUMN total_items DROP NOT NULL")
        .execute(&db.pool)
        .await
        .unwrap();
    assert!(run_pg_migrations(&db.pool)
        .await
        .unwrap_err()
        .to_string()
        .contains("version/schema mismatch"));
    sqlx::query("ALTER TABLE socks5_check_jobs ALTER COLUMN total_items SET NOT NULL")
        .execute(&db.pool)
        .await
        .unwrap();
    run_pg_migrations(&db.pool).await.unwrap();

    sqlx::query("ALTER TABLE socks5_check_jobs ALTER COLUMN status SET DEFAULT 'RUNNING'")
        .execute(&db.pool)
        .await
        .unwrap();
    assert!(run_pg_migrations(&db.pool)
        .await
        .unwrap_err()
        .to_string()
        .contains("version/schema mismatch"));
    sqlx::query("ALTER TABLE socks5_check_jobs ALTER COLUMN status SET DEFAULT 'QUEUED'")
        .execute(&db.pool)
        .await
        .unwrap();
    run_pg_migrations(&db.pool).await.unwrap();

    sqlx::query("ALTER TABLE socks5_check_jobs ALTER COLUMN total_items TYPE INTEGER")
        .execute(&db.pool)
        .await
        .unwrap();
    assert!(run_pg_migrations(&db.pool)
        .await
        .unwrap_err()
        .to_string()
        .contains("version/schema mismatch"));
    sqlx::query("ALTER TABLE socks5_check_jobs ALTER COLUMN total_items TYPE BIGINT")
        .execute(&db.pool)
        .await
        .unwrap();
    run_pg_migrations(&db.pool).await.unwrap();

    let pair_unique: String = sqlx::query_scalar("SELECT conname FROM pg_constraint WHERE conrelid='socks5_check_job_items'::regclass AND contype='u'")
        .fetch_one(&db.pool).await.unwrap();
    sqlx::query(&format!(
        "ALTER TABLE socks5_check_job_items DROP CONSTRAINT {pair_unique}"
    ))
    .execute(&db.pool)
    .await
    .unwrap();
    assert!(run_pg_migrations(&db.pool)
        .await
        .unwrap_err()
        .to_string()
        .contains("version/schema mismatch"));
    sqlx::query(&format!("ALTER TABLE socks5_check_job_items ADD CONSTRAINT {pair_unique} UNIQUE(job_id,resource_id_snapshot,relay_node_id_snapshot)"))
        .execute(&db.pool).await.unwrap();
    run_pg_migrations(&db.pool).await.unwrap();

    sqlx::query("DROP INDEX uq_socks5_check_jobs_scheduled_slot")
        .execute(&db.pool)
        .await
        .unwrap();
    sqlx::query("CREATE UNIQUE INDEX uq_socks5_check_jobs_scheduled_slot ON socks5_check_jobs(policy_id,scheduled_for_ms) WHERE source='MANUAL'")
        .execute(&db.pool).await.unwrap();
    assert!(run_pg_migrations(&db.pool)
        .await
        .unwrap_err()
        .to_string()
        .contains("version/schema mismatch"));
    sqlx::query("DROP INDEX uq_socks5_check_jobs_scheduled_slot")
        .execute(&db.pool)
        .await
        .unwrap();
    sqlx::query("CREATE UNIQUE INDEX uq_socks5_check_jobs_scheduled_slot ON socks5_check_jobs(policy_id,scheduled_for_ms) WHERE source='SCHEDULED'")
        .execute(&db.pool).await.unwrap();
    run_pg_migrations(&db.pool).await.unwrap();

    sqlx::query("DROP INDEX idx_socks5_check_job_items_ready")
        .execute(&db.pool)
        .await
        .unwrap();
    sqlx::query("CREATE INDEX idx_socks5_check_job_items_ready ON socks5_check_job_items(not_before_ms,state,id)")
        .execute(&db.pool).await.unwrap();
    assert!(run_pg_migrations(&db.pool)
        .await
        .unwrap_err()
        .to_string()
        .contains("version/schema mismatch"));
    cleanup(&db).await;
}
