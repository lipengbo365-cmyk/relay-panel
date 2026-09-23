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

The alpha3 migrations preserve existing rows while adding physical-node
fingerprints, resource revisions, per-Resource×Node generations, constraints,
and indexes. Back up the database before deployment. Because config protocol 6
is an exact-match gate, deploy Panel and every Node in one maintenance window.
The frozen `v1.0.0-alpha2` tag remains the historical pre-audit build.

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
selected physical Node, and atomically consumes at most one result matching the
request, challenge, resource revision, per-Resource×Node generation, relational
Node, instance-key fingerprint, and current WebSocket session. A superseded
result is discarded completely: it updates neither latest health nor history.
Panel receive time in UTC is authoritative; Node wall-clock time is ignored.

The Node performs `TCP_CONNECT`, `SOCKS5_NEGOTIATION`, `AUTHENTICATION`,
`SOCKS5_CONNECT`, `INTERNET_REQUEST`, and `EXIT_IP_PARSE`. A successful check
must fetch an IPv4 or IPv6 address through the proxy. If that address equals the
Relay Node public IP, the result is `CONNECT_FAILED/EXIT_IP_MISMATCH`.

An offline Relay Node returns `NODE_OFFLINE` without mutating SOCKS5 health.
Queue rejection returns `NODE_BUSY` without mutating health. A failed check
updates only the selected Resource × Node pair and never disables a resource.
The resource list is explicitly a projection of the most recently received
check and names that Relay Node; the detail view is the authoritative complete
Resource × Node matrix.

## Protocol 6 and physical-node identity

Protocol 6 requires two independent proofs: the DeviceGroup bearer token and a
random 256-bit instance key stored locally as
`/opt/relay-node/node-identity-secret` with mode `0600`. The Node sends the raw
key only as an HTTPS/WSS request header. Panel stores only its SHA-256
fingerprint and never serializes that fingerprint in admin resource responses.
The instance key is stable across ordinary restarts and container recreation
only when `/opt/relay-node` is persisted.

Lifecycle:

- First registration atomically claims `(device_group_id,node_id)` by TOFU.
- A restart with the same files is accepted; a different key is rejected.
- Loss of the key or a reinstall fails closed. Panel never overwrites an
  existing fingerprint during reconnect.
- For replacement or rotation, stop the old Node, generate the replacement key,
  calculate its SHA-256 fingerprint on the Node host, then call the admin-only
  `PUT /api/v1/admin/relay-nodes/{id}/identity` with `identity_hash`. Never send
  the raw key. The Panel closes the old WebSocket session before and after the
  atomic fingerprint replacement.
- Changing `node-id` creates a distinct physical-node record; it does not take
  over the previous identity.

Compatibility matrix:

| Panel | Node | Result |
|---|---|---|
| v6 | v6 | Config, Stage 2 relay, and Stage 3 health allowed after token + instance-key authentication. |
| v6 | v5 | HTTP config and WebSocket rejected with 426; no Stage 3 command is sent. |
| v5 | v6 | Node treats the mismatch as permanent and removes listeners; no health command runs. |
| v5 | v5 | Historical alpha2 behavior only; no alpha3 identity/session/generation guarantees. |

History retention runs after accepted results and deletes at most 10,000 old
rows per transaction. Repeated checks gradually drain a large backlog without
holding one transaction across millions of deletes; latest-health rows are in a
separate table and are never pruned.

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
