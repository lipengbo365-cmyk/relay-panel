# SOCKS5 Stage 3 operations

Stage 3 adds bulk SOCKS5 resource management and health checks executed by a
specific physical Relay Node. It does not add scheduling, pools, load
balancing, failover, rotation, UDP ASSOCIATE, HTTP proxying, TUN, or proxy
chains.

## Data model

- `relay_nodes` stores stable physical-node identity and administrator metadata.
  Real-time CPU, RAM, connections, online state, and check queue depth remain in
  the existing `node_status` KVS path.
- `socks5_resource_health` stores the latest result for each
  `(resource_id, relay_node_id)` pair.
- `socks5_check_history` stores individual checks. Panel opportunistically
  removes rows older than `SOCKS5_CHECK_RETENTION_DAYS` after a successful
  result is received.
- `socks5_resources.tags` is a JSON array represented consistently by the
  SQLite and PostgreSQL repositories.

All migrations are additive. Back up the database before deployment and deploy
Panel before the Stage 3 Nodes. Stage 2 images and the `v1.0.0-alpha1` source
tag remain the rollback baseline.

## Configuration

Panel:

| Variable | Default | Purpose |
|---|---:|---|
| `SOCKS5_CHECK_URLS` | `https://api.ipify.org,https://ifconfig.me/ip` | Comma-separated primary and fallback public-IP endpoints; at most four are sent per task. |
| `SOCKS5_CHECK_CONCURRENCY` | `50` | Maximum Panel-side in-flight checks in one batch. |
| `SOCKS5_CHECK_RETENTION_DAYS` | `30` | History retention, clamped to 1–3650 days. |

Node:

| Variable | Default | Purpose |
|---|---:|---|
| `SOCKS5_CHECK_CONCURRENCY` | `50` | Maximum health checks executing concurrently. |
| `SOCKS5_CHECK_QUEUE_LIMIT` | `200` | Maximum checks waiting for a Node permit. Excess work returns `NODE_BUSY`. |

Production still requires an HTTPS `PUBLIC_PANEL_URL`, an HTTPS `PANEL_URL`,
and WSS-capable reverse proxying. `ALLOW_INSECURE_SOCKS5_CONFIG=1` is only a
local development override. Check credentials use the existing
`SOCKS5_CREDENTIAL_KEY`, cross the existing directed WebSocket channel, remain
in Node memory only, and are never written to its cache.

## Check path and classification

Panel registers a random request ID and challenge, sends one command to the
selected physical Node, and accepts one token-authenticated result matching the
request, challenge, resource, relational Node, and stable node key. Panel writes
health before completing the waiting admin request.

The Node performs `TCP_CONNECT`, `SOCKS5_NEGOTIATION`, `AUTHENTICATION`,
`SOCKS5_CONNECT`, `INTERNET_REQUEST`, and `EXIT_IP_PARSE`. A successful check
must fetch an IPv4 or IPv6 address through the proxy. If that address equals the
Relay Node public IP, the result is `CONNECT_FAILED/EXIT_IP_MISMATCH`.

An offline Relay Node returns `NODE_OFFLINE` without mutating SOCKS5 health.
Queue rejection returns `NODE_BUSY` without mutating health. A failed check
updates only the selected Resource × Node pair and never disables a resource.

## Rollback

Pause Stage 3 checks, deploy the Stage 2 Panel and Node images together, and
leave additive tables unused. For database rollback, stop all components and
restore the pre-deployment backup; do not improvise destructive reverse
migrations on a live database.

## Deferred technical debt

Traffic batches awaiting Panel ACK remain only in Node memory. A hard Node or
host crash can lose up to one reporting interval, while network retry, Panel
restart, and lost ACK handling remain idempotent through the existing
`report_id`/receipt mechanism. A traffic WAL is intentionally outside Stage 3.
