# SOCKS5 Stage 2 deployment and rollback

## Release images

Build and pin both project-owned images. Never deploy `latest`:

```sh
docker build --target panel -t relay-panel-socks5:v1.0.0-alpha1 .
docker build --target node -t relay-node-socks5:v1.0.0-alpha1 .
```

The release compose defaults to these exact tags. A registry deployment should
replace `RELAYPANEL_PANEL_IMAGE` and `RELAYPANEL_NODE_IMAGE` with immutable
registry tags or digests.

## Required configuration

- `JWT_SECRET`: independent random 32-byte value.
- `PANEL_KEY`: independent random value.
- `SOCKS5_CREDENTIAL_KEY`: independent 32-byte key encoded as 64 hex characters or standard base64. Back it up separately; losing it makes stored credentials undecryptable by design.
- `PUBLIC_PANEL_URL`: public `https://` panel origin used by the Panel security gate.
- `PANEL_URL`: the same reachable `https://` origin used by Node; WebSocket control automatically uses `wss://`.
- `NODE_TOKEN`: token of the inbound device group assigned to that Node.
- `ALLOW_INSECURE_SOCKS5_CONFIG=0`: mandatory in production.

Terminate TLS with Caddy, Nginx, or another reverse proxy that preserves
WebSocket upgrade headers. Panel-to-Node sensitive configuration is refused
unless both sides recognize a secure control URL.

Persist `/app/data` for SQLite. For PostgreSQL, persist the PostgreSQL data
volume and set `DATABASE_URL`; the Panel volume still holds operational files.
Both services use `restart: unless-stopped`, the Node raises `nofile` to 65536,
and the Panel image/compose health check probes `/api/v1/health`.

## Backup and upgrade

Before every upgrade:

```sh
pg_dump --format=custom --file=relaypanel-before-upgrade.dump "$DATABASE_URL"
# SQLite alternative, while Panel is stopped:
cp data.db data.db.before-upgrade
```

Deploy Panel first, confirm its health and migrations, then deploy every Node.
Protocol v5 is an exact-match gate: mixed v4/v5 control planes fail closed.
An additive migration creates `socks5_resources`, `socks5_rule_bindings`, and
`traffic_report_receipts`; no existing native-forwarding table is removed.

## Compatibility matrix

| Panel | Node | Config protocol | SOCKS5 | Allowed |
|---|---|---:|---:|---:|
| SOCKS5 alpha1 | SOCKS5 alpha1 | 5 | Yes | Yes |
| SOCKS5 alpha1 | upstream v4 | 4 vs 5 | No | No; HTTP/WS 426 |
| upstream v4 | SOCKS5 alpha1 | 5 vs 4 | No | No; Node stops listeners |
| upstream v4 | upstream v4 | 4 | No | Only legacy operation after coordinated rollback |

## Rollback

Do not roll back only one component. First pause/remove every SOCKS5 Relay Rule,
verify Nodes have removed their listeners, then roll back all Nodes and the
Panel as one maintenance operation. The additive SOCKS5 tables may remain
unused; this is the preferred application rollback because it preserves data.

For a full database rollback, stop Panel and Nodes and restore the pre-upgrade
backup. Never run ad-hoc destructive reverse migrations against a live system.
After rollback, verify protocol v4 on both sides before restoring legacy rules.

## Known technical debt

Traffic report retries are idempotent after a report has been created: the Node
reuses the same report ID until the Panel acknowledges it, and the Panel stores
the receipt in the same transaction as the counters. The pending report is still
memory-only, however. An abrupt Node process or host crash before acknowledgement
can therefore lose at most one reporting interval of unsubmitted traffic.

This is a non-blocking P2 for the alpha1 baseline. Before usage-based billing is
treated as financially authoritative, add a credential-free durable traffic WAL
to the existing reporting path. Do not introduce a second accounting pipeline.
