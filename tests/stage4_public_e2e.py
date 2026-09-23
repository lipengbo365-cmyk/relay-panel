#!/usr/bin/env python3
"""Stage 4 gate against an operator-supplied real public SOCKS5 upstream."""

from __future__ import annotations

import json
import os
import secrets
import shutil
import socket
import ssl
import struct
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

from stage4_local_e2e import (
    Api,
    BOOTSTRAP_PASSWORD,
    NODE_BINARY,
    PANEL_BINARY,
    free_port,
    free_range,
    port_closed,
    recv_exact,
    start_process,
    wait_until,
)


def socks5_tls_ip(
    relay_port: int, relay_username: str, relay_password: str, hostname: str
) -> str:
    raw = socket.create_connection(("127.0.0.1", relay_port), timeout=15)
    try:
        raw.sendall(b"\x05\x01\x02")
        assert recv_exact(raw, 2) == b"\x05\x02"
        username = relay_username.encode()
        password = relay_password.encode()
        raw.sendall(
            bytes((1, len(username)))
            + username
            + bytes((len(password),))
            + password
        )
        assert recv_exact(raw, 2) == b"\x01\x00"
        encoded_host = hostname.encode("idna")
        raw.sendall(
            b"\x05\x01\x00\x03"
            + bytes((len(encoded_host),))
            + encoded_host
            + struct.pack("!H", 443)
        )
        response = recv_exact(raw, 4)
        assert response[:2] == b"\x05\x00", f"relay CONNECT failed: {response!r}"
        if response[3] == 1:
            recv_exact(raw, 4)
        elif response[3] == 3:
            recv_exact(raw, recv_exact(raw, 1)[0])
        elif response[3] == 4:
            recv_exact(raw, 16)
        recv_exact(raw, 2)
        with ssl.create_default_context().wrap_socket(raw, server_hostname=hostname) as tls:
            raw = None
            tls.sendall(
                f"GET / HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n".encode()
            )
            chunks: list[bytes] = []
            while True:
                chunk = tls.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)
        response_body = b"".join(chunks).split(b"\r\n\r\n", 1)[1]
        return response_body.decode().strip()
    finally:
        if raw is not None:
            raw.close()


def main() -> None:
    upstream_host = os.environ["STAGE4_PUBLIC_SOCKS_HOST"]
    upstream_port = int(os.environ["STAGE4_PUBLIC_SOCKS_PORT"])
    upstream_username = os.environ["STAGE4_PUBLIC_SOCKS_USERNAME"]
    upstream_password = os.environ["STAGE4_PUBLIC_SOCKS_PASSWORD"]
    expected_exit_ip = os.environ["STAGE4_EXPECTED_EXIT_IP"]

    temp_root = Path(tempfile.mkdtemp(prefix="relaypanel-stage4-public-e2e-"))
    processes: list[subprocess.Popen[bytes]] = []
    logs: list[object] = []
    panel_port = free_port()
    range_start, range_end = free_range()
    api = Api(f"http://127.0.0.1:{panel_port}/api/v1")
    try:
        database_path = temp_root / "panel.db"
        panel, panel_log = start_process(
            [PANEL_BINARY],
            temp_root,
            {
                "DATABASE_URL": f"sqlite://{database_path}?mode=rwc",
                "LISTEN": f"127.0.0.1:{panel_port}",
                "PUBLIC_PANEL_URL": f"http://127.0.0.1:{panel_port}",
                "PUBLIC_DIR": str(temp_root / "public"),
                "JWT_SECRET": secrets.token_hex(32),
                "PANEL_KEY": secrets.token_hex(16),
                "SOCKS5_CREDENTIAL_KEY": secrets.token_hex(32),
                "SOCKS5_CHECK_URLS": "https://api.ipify.org",
                "GEOIP_ENABLED": "true",
                "GEOIP_CACHE_TTL": "3600",
                "REGISTRATION_ENABLED": "0",
                "ALLOW_INSECURE_SOCKS5_CONFIG": "1",
                "RELAY_RECOMMEND_HEALTH_TTL_SECONDS": "600",
                "RUST_LOG": "warn",
            },
            temp_root / "panel.log",
        )
        processes.append(panel)
        logs.append(panel_log)
        wait_until(
            "public-gate panel",
            lambda: api.request(
                "POST",
                "/auth/login",
                {"username": "admin", "password": BOOTSTRAP_PASSWORD},
            ),
        )
        login = api.request(
            "POST", "/auth/login", {"username": "admin", "password": BOOTSTRAP_PASSWORD}
        )
        assert isinstance(login, dict)
        api.token = str(login["token"])
        new_password = secrets.token_urlsafe(24)
        api.request(
            "PUT",
            "/user/password",
            {"current_password": BOOTSTRAP_PASSWORD, "new_password": new_password},
        )
        login = api.request(
            "POST", "/auth/login", {"username": "admin", "password": new_password}
        )
        assert isinstance(login, dict)
        api.token = str(login["token"])

        group = api.request(
            "POST",
            "/groups",
            {
                "name": "Stage4 Public Gate",
                "group_type": "in",
                "connect_host": "127.0.0.1",
                "port_range": f"{range_start}-{range_end}",
            },
        )
        assert isinstance(group, dict)
        node_dir = temp_root / "public-node"
        node_dir.mkdir()
        (node_dir / "node-id").write_text("stage4-public-node")
        identity = secrets.token_hex(32)
        identity_path = node_dir / "node-identity-secret"
        identity_path.write_text(identity)
        identity_path.chmod(0o600)
        node, node_log = start_process(
            [NODE_BINARY],
            node_dir,
            {
                "PANEL_URL": f"http://127.0.0.1:{panel_port}",
                "NODE_TOKEN": str(group["token"]),
                "POLL_INTERVAL": "1",
                "LISTEN_IPV4": "127.0.0.1",
                "LISTEN_IPV6": "",
                "ALLOW_INSECURE_SOCKS5_CONFIG": "1",
                "PUBLIC_IPV4_CHECK_URL": "https://api-ipv4.ip.sb/ip",
                "RUST_LOG": "warn",
            },
            node_dir / "node.log",
        )
        processes.append(node)
        logs.append(node_log)

        def live_node() -> dict | None:
            rows = api.request("GET", "/admin/relay-nodes")
            assert isinstance(rows, list)
            if len(rows) == 1 and rows[0]["online"]:
                return rows[0]
            return None

        relay_node = wait_until("public relay node", live_node, timeout=60)
        relay_node_id = int(relay_node["id"])
        api.request(
            "PUT",
            f"/admin/relay-nodes/{relay_node_id}",
            {
                "name": "PUBLIC-SG-01",
                "country": "Singapore",
                "country_code": "SG",
                "region": "Public Gate",
                "city": "Singapore",
                "provider": "real-egress-gate",
                "advertise_host": "127.0.0.1",
                "bandwidth_mbps": 1000,
                "remark": "Stage4 public SOCKS5 E2E",
                "tags": ["stage4", "public"],
                "enabled": True,
            },
        )
        resource = api.request(
            "POST",
            "/admin/socks5-resources",
            {
                "name": "Stage4 Real Public SOCKS",
                "host": upstream_host,
                "port": upstream_port,
                "username": upstream_username,
                "password": upstream_password,
                "country": "United States",
                "country_code": "US",
                "region": "Imported",
                "city": "Imported",
                "isp": "public-gate",
                "remark": "Stage4 public gate",
                "enabled": True,
            },
        )
        assert isinstance(resource, dict)
        resource_id = int(resource["id"])
        health = api.request(
            "POST",
            f"/admin/socks5-resources/{resource_id}/check",
            {"relay_node_id": relay_node_id},
        )
        assert isinstance(health, dict)
        assert health["outcome"] == "COMPLETED", health
        assert health["result"]["status"] == "ONLINE", health
        assert health["result"]["exit_ip"] == expected_exit_ip, health
        detected_country = health["result"]["detected_country"]
        assert detected_country, "GeoIP did not produce a detected country"

        recommendation = api.request(
            "GET",
            f"/admin/socks5-resources/{resource_id}/relay-recommendations?limit=10&include_unavailable=true",
        )
        assert isinstance(recommendation, dict)
        candidate = recommendation["candidates"][0]
        assert candidate["eligible"] is True
        assert candidate["recommended"] is True
        assert candidate["country_match"] == "MATCHED", candidate
        assert candidate["health_status"] == "ONLINE"
        assert candidate["detected_country"] == detected_country

        preview = api.request(
            "POST",
            "/admin/smart-relay/preview",
            {
                "resource_id": resource_id,
                "relay_node_id": relay_node_id,
                "port_mode": "AUTO",
                "manual_port": None,
            },
        )
        assert isinstance(preview, dict) and preview["eligible"] is True
        create_request = {
            "resource_id": resource_id,
            "relay_node_id": relay_node_id,
            "port_mode": "AUTO",
            "manual_port": None,
            "rule_name": "Stage4 Public One-click",
            "idempotency_key": str(uuid.uuid4()),
            "expected_resource_revision": int(preview["resource_revision"]),
            "expected_health_generation": int(preview["health_generation"]),
            "expected_health_checked_at": str(preview["health_checked_at"]),
        }
        created = api.request("POST", "/admin/smart-relay", create_request)
        assert isinstance(created, dict)
        relay_password = str(created["relay_password"])
        relay_username = str(created["relay_username"])
        relay_port = int(created["port"])
        rule_id = int(created["rule_id"])
        assert created["exit_ip"] == expected_exit_ip
        wait_until("public-gate listener", lambda: not port_closed(relay_port), timeout=30)

        actual_exit_ip = socks5_tls_ip(
            relay_port, relay_username, relay_password, "api.ipify.org"
        )
        assert actual_exit_ip == expected_exit_ip

        def traffic_result() -> tuple[int, int] | None:
            rules = api.request("GET", "/admin/socks5-rules")
            users = api.request("GET", "/admin/users")
            assert isinstance(rules, list) and isinstance(users, list)
            rule_traffic = int(next(row for row in rules if row["rule_id"] == rule_id)["traffic_used"])
            user_traffic = int(next(row for row in users if row["id"] == 1)["traffic_used"])
            return (rule_traffic, user_traffic) if rule_traffic > 0 and user_traffic > 0 else None

        rule_traffic, user_traffic = wait_until(
            "public-gate traffic accounting", traffic_result, timeout=30
        )
        latest_node = live_node() or relay_node
        relay_public_ip = str(latest_node.get("public_ip") or "")
        if not relay_public_ip:
            relay_public_ip = os.environ.get("STAGE4_RELAY_PUBLIC_IP", "")
        assert relay_public_ip and relay_public_ip != actual_exit_ip

        replay = api.request("POST", "/admin/smart-relay", create_request)
        assert isinstance(replay, dict)
        assert replay["rule_id"] == rule_id and replay["replayed"] is True
        assert "relay_password" not in replay

        api.request("DELETE", f"/admin/socks5-rules/{rule_id}")
        wait_until("public-gate listener close", lambda: port_closed(relay_port), timeout=30)
        print(
            json.dumps(
                {
                    "gate": "PASS",
                    "actual_exit_ip": actual_exit_ip,
                    "relay_public_ip": relay_public_ip,
                    "detected_country": detected_country,
                    "declared_country": "US",
                    "country_source": "detected_health",
                    "recommendation": "PUBLIC-SG-01",
                    "rule_traffic": rule_traffic,
                    "user_traffic": user_traffic,
                    "one_time_password": "PASS",
                    "listener_delete": "PASS",
                },
                separators=(",", ":"),
            )
        )
    finally:
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
        for process in reversed(processes):
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
        for log in logs:
            log.close()
        shutil.rmtree(temp_root, ignore_errors=True)


if __name__ == "__main__":
    main()
