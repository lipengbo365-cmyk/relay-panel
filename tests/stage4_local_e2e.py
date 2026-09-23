#!/usr/bin/env python3
"""Deterministic Stage 4 local gate with three real relay-node processes."""

from __future__ import annotations

import contextlib
import hashlib
import http.server
import json
import os
import secrets
import select
import shutil
import socket
import socketserver
import sqlite3
import struct
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path


PANEL_BINARY = os.environ.get("STAGE4_PANEL_BINARY", "/app/target/debug/relay-panel")
NODE_BINARY = os.environ.get("STAGE4_NODE_BINARY", "/app/target/debug/relay-node")
BOOTSTRAP_PASSWORD = os.environ["STAGE4_BOOTSTRAP_PASSWORD"]
EXIT_IP = "198.51.100.88"


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def free_range(width: int = 20) -> tuple[int, int]:
    for base in range(32000, 60000 - width):
        sockets: list[socket.socket] = []
        try:
            for port in range(base, base + width):
                sock = socket.socket()
                sock.bind(("127.0.0.1", port))
                sockets.append(sock)
            return base, base + width - 1
        except OSError:
            pass
        finally:
            for sock in sockets:
                sock.close()
    raise RuntimeError("no free contiguous TCP port range")


def recv_exact(sock: socket.socket, length: int) -> bytes:
    data = bytearray()
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise ConnectionError("unexpected EOF")
        data.extend(chunk)
    return bytes(data)


def relay_bidirectional(left: socket.socket, right: socket.socket) -> None:
    sockets = [left, right]
    while True:
        readable, _, _ = select.select(sockets, [], [], 10)
        if not readable:
            continue
        for source in readable:
            data = source.recv(65536)
            if not data:
                return
            (right if source is left else left).sendall(data)


class MockSocksHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        client = self.request
        client.settimeout(10)
        version, method_count = recv_exact(client, 2)
        if version != 5:
            return
        methods = recv_exact(client, method_count)
        if 0 not in methods:
            client.sendall(b"\x05\xff")
            return
        client.sendall(b"\x05\x00")
        version, command, _reserved, address_type = recv_exact(client, 4)
        if version != 5 or command != 1:
            return
        if address_type == 1:
            host = socket.inet_ntoa(recv_exact(client, 4))
        elif address_type == 3:
            host = recv_exact(client, recv_exact(client, 1)[0]).decode("idna")
        elif address_type == 4:
            host = socket.inet_ntop(socket.AF_INET6, recv_exact(client, 16))
        else:
            return
        port = struct.unpack("!H", recv_exact(client, 2))[0]
        try:
            upstream = socket.create_connection((host, port), timeout=10)
        except OSError:
            client.sendall(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
            return
        with upstream:
            client.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
            client.settimeout(None)
            upstream.settimeout(None)
            relay_bidirectional(client, upstream)


class ThreadingTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class IpEchoHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        body = EXIT_IP.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: object) -> None:
        return


class Api:
    def __init__(self, base_url: str) -> None:
        self.base_url = base_url
        self.token: str | None = None

    def request(
        self,
        method: str,
        path: str,
        payload: object | None = None,
        headers: dict[str, str] | None = None,
        envelope: bool = True,
    ) -> object:
        request_headers = {"Content-Type": "application/json"}
        if self.token:
            request_headers["Authorization"] = f"Bearer {self.token}"
        if headers:
            request_headers.update(headers)
        data = None if payload is None else json.dumps(payload).encode()
        request = urllib.request.Request(
            f"{self.base_url}{path}", data=data, method=method, headers=request_headers
        )
        try:
            with urllib.request.urlopen(request, timeout=45) as response:
                parsed = json.loads(response.read())
        except urllib.error.HTTPError as error:
            body = error.read().decode(errors="replace")
            raise AssertionError(f"{method} {path}: HTTP {error.code}: {body[:300]}") from error
        if not envelope:
            return parsed
        if parsed.get("code") != 0:
            raise AssertionError(
                f"{method} {path}: code={parsed.get('code')} message={parsed.get('message')}"
            )
        return parsed.get("data")


def wait_until(description: str, predicate, timeout: float = 45, interval: float = 0.25):
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            value = predicate()
            if value:
                return value
        except Exception as error:  # transient startup/network state
            last_error = error
        time.sleep(interval)
    suffix = f": {last_error}" if last_error else ""
    raise AssertionError(f"timed out waiting for {description}{suffix}")


def start_process(
    command: list[str], cwd: Path, env: dict[str, str], log_path: Path
) -> tuple[subprocess.Popen[bytes], object]:
    log = open(log_path, "wb")
    process = subprocess.Popen(
        command,
        cwd=cwd,
        env={**os.environ, **env},
        stdout=log,
        stderr=subprocess.STDOUT,
    )
    return process, log


def socks5_http_get(port: int, username: str, password: str, target_port: int) -> bytes:
    with socket.create_connection(("127.0.0.1", port), timeout=10) as sock:
        sock.sendall(b"\x05\x01\x02")
        assert recv_exact(sock, 2) == b"\x05\x02", "relay did not require USERPASS auth"
        user = username.encode()
        secret = password.encode()
        sock.sendall(bytes((1, len(user))) + user + bytes((len(secret),)) + secret)
        assert recv_exact(sock, 2) == b"\x01\x00", "relay credential rejected"
        sock.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", target_port))
        response = recv_exact(sock, 4)
        assert response[:2] == b"\x05\x00", f"relay CONNECT failed: {response!r}"
        address_type = response[3]
        if address_type == 1:
            recv_exact(sock, 4)
        elif address_type == 3:
            recv_exact(sock, recv_exact(sock, 1)[0])
        elif address_type == 4:
            recv_exact(sock, 16)
        recv_exact(sock, 2)
        sock.sendall(
            b"GET /ip HTTP/1.1\r\nHost: stage4.local\r\nConnection: close\r\n\r\n"
        )
        chunks: list[bytes] = []
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)


def port_closed(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.25):
            return False
    except OSError:
        return True


def main() -> None:
    temp_root = Path(tempfile.mkdtemp(prefix="relaypanel-stage4-e2e-"))
    processes: list[subprocess.Popen[bytes]] = []
    logs: list[object] = []
    servers: list[socketserver.BaseServer] = []
    panel_port = free_port()
    socks_port = free_port()
    echo_port = free_port()
    range_start, range_end = free_range()
    api = Api(f"http://127.0.0.1:{panel_port}/api/v1")

    try:
        echo_server = ThreadingTCPServer(("127.0.0.1", echo_port), IpEchoHandler)
        socks_server = ThreadingTCPServer(("127.0.0.1", socks_port), MockSocksHandler)
        servers.extend([echo_server, socks_server])
        for server in servers:
            threading.Thread(target=server.serve_forever, daemon=True).start()

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
                "SOCKS5_CHECK_URLS": f"http://127.0.0.1:{echo_port}/ip",
                "GEOIP_ENABLED": "false",
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
            "panel login endpoint",
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
        new_admin_password = secrets.token_urlsafe(24)
        api.request(
            "PUT",
            "/user/password",
            {"current_password": BOOTSTRAP_PASSWORD, "new_password": new_admin_password},
        )
        login = api.request(
            "POST", "/auth/login", {"username": "admin", "password": new_admin_password}
        )
        assert isinstance(login, dict)
        api.token = str(login["token"])

        group = api.request(
            "POST",
            "/groups",
            {
                "name": "Stage4 E2E Inbound",
                "group_type": "in",
                "connect_host": "127.0.0.1",
                "port_range": f"{range_start}-{range_end}",
                "rate": 1.0,
                "hidden": False,
            },
        )
        assert isinstance(group, dict)
        group_token = str(group["token"])

        node_specs = [
            ("stage4-us-a", "US-A", "US", 120),
            ("stage4-us-b", "US-B", "US", 200),
            ("stage4-jp-c", "JP-C", "JP", 60),
        ]
        identities: dict[str, str] = {}
        for node_key, _name, _country, _latency in node_specs:
            node_dir = temp_root / node_key
            node_dir.mkdir()
            (node_dir / "node-id").write_text(node_key)
            identity = secrets.token_hex(32)
            identities[node_key] = identity
            identity_path = node_dir / "node-identity-secret"
            identity_path.write_text(identity)
            identity_path.chmod(0o600)
            process, log = start_process(
                [NODE_BINARY],
                node_dir,
                {
                    "PANEL_URL": f"http://127.0.0.1:{panel_port}",
                    "NODE_TOKEN": group_token,
                    "POLL_INTERVAL": "1",
                    "LISTEN_IPV4": "127.0.0.1",
                    "LISTEN_IPV6": "",
                    "ALLOW_INSECURE_SOCKS5_CONFIG": "1",
                    "RUST_LOG": "warn",
                },
                node_dir / "node.log",
            )
            processes.append(process)
            logs.append(log)

        def online_nodes() -> list[dict]:
            rows = api.request("GET", "/admin/relay-nodes")
            assert isinstance(rows, list)
            return rows if len(rows) == 3 and all(row["online"] for row in rows) else []

        rows = wait_until("three online physical nodes", online_nodes, timeout=60)
        by_key = {row["node_key"]: row for row in rows}
        assert set(by_key) == {spec[0] for spec in node_specs}

        for node_key, name, country, _latency in node_specs:
            row = by_key[node_key]
            api.request(
                "PUT",
                f"/admin/relay-nodes/{row['id']}",
                {
                    "name": name,
                    "country": "United States" if country == "US" else "Japan",
                    "country_code": country,
                    "region": "Stage4",
                    "city": name,
                    "provider": "local-e2e",
                    "advertise_host": "127.0.0.1",
                    "bandwidth_mbps": 1000,
                    "remark": "deterministic local gate",
                    "tags": ["stage4", country.lower()],
                    "enabled": True,
                },
            )

        resource = api.request(
            "POST",
            "/admin/socks5-resources",
            {
                "name": "Stage4 Controlled SOCKS",
                "host": "127.0.0.1",
                "port": socks_port,
                "username": None,
                "password": None,
                "country": "United States",
                "country_code": "US",
                "region": "Stage4",
                "city": "Local",
                "isp": "controlled",
                "remark": "local deterministic E2E",
                "enabled": True,
            },
        )
        assert isinstance(resource, dict)
        resource_id = int(resource["id"])

        for node_key, _name, _country, _latency in node_specs:
            result = api.request(
                "POST",
                f"/admin/socks5-resources/{resource_id}/check",
                {"relay_node_id": int(by_key[node_key]["id"])},
            )
            assert isinstance(result, dict)
            assert result["outcome"] == "COMPLETED", result
            assert result["result"]["status"] == "ONLINE", result
            assert result["result"]["exit_ip"] == EXIT_IP, result

        with sqlite3.connect(database_path, timeout=30) as connection:
            for node_key, _name, _country, latency in node_specs:
                connection.execute(
                    """
                    UPDATE socks5_resource_health
                    SET country='US', total_latency_ms=?, exit_ip=?, status='ONLINE',
                        checked_at=datetime('now'), last_success_at=datetime('now')
                    WHERE resource_id=? AND relay_node_id=?
                    """,
                    (latency, EXIT_IP, resource_id, int(by_key[node_key]["id"])),
                )
            connection.execute(
                """
                UPDATE socks5_resources
                SET status='ONLINE', detected_exit_ip=?, detected_country='US',
                    latency_ms=120, last_check_at=datetime('now'), last_success_at=datetime('now')
                WHERE id=?
                """,
                (EXIT_IP, resource_id),
            )
            connection.commit()

        recommendation = api.request(
            "GET",
            f"/admin/socks5-resources/{resource_id}/relay-recommendations?limit=10&include_unavailable=true",
        )
        assert isinstance(recommendation, dict)
        candidates = recommendation["candidates"]
        assert [candidate["relay_node_name"] for candidate in candidates[:3]] == [
            "US-A",
            "US-B",
            "JP-C",
        ]
        assert candidates[0]["recommended"] is True
        selected = candidates[0]
        selected_id = int(selected["relay_node_id"])

        preview = api.request(
            "POST",
            "/admin/smart-relay/preview",
            {
                "resource_id": resource_id,
                "relay_node_id": selected_id,
                "port_mode": "AUTO",
                "manual_port": None,
            },
        )
        assert isinstance(preview, dict)
        assert preview["eligible"] is True

        create_request = {
            "resource_id": resource_id,
            "relay_node_id": selected_id,
            "port_mode": "AUTO",
            "manual_port": None,
            "rule_name": "Stage4 Three-Node E2E",
            "idempotency_key": str(uuid.uuid4()),
            "expected_resource_revision": int(preview["resource_revision"]),
            "expected_health_generation": int(preview["health_generation"]),
            "expected_health_checked_at": str(preview["health_checked_at"]),
        }
        created = api.request("POST", "/admin/smart-relay", create_request)
        assert isinstance(created, dict)
        assert created["relay_node_id"] == selected_id
        assert created["exit_ip"] == EXIT_IP
        assert created["replayed"] is False
        assert created["password_shown_once"] is True
        relay_username = str(created["relay_username"])
        relay_password = str(created["relay_password"])
        rule_id = int(created["rule_id"])
        relay_port = int(created["port"])

        replayed = api.request("POST", "/admin/smart-relay", create_request)
        assert isinstance(replayed, dict)
        assert replayed["rule_id"] == rule_id
        assert replayed["replayed"] is True
        assert replayed["password_shown_once"] is False
        assert "relay_password" not in replayed

        def node_config(node_key: str) -> dict:
            value = api.request(
                "GET",
                "/node/config",
                headers={
                    "Authorization": f"Bearer {group_token}",
                    "X-Node-ID": node_key,
                    "X-Node-Identity": identities[node_key],
                    "X-Accept-Sensitive-Config": "1",
                    "X-Config-Protocol-Version": "6",
                },
                envelope=False,
            )
            assert isinstance(value, dict)
            return value

        config_a = node_config("stage4-us-a")
        config_b = node_config("stage4-us-b")
        config_c = node_config("stage4-jp-c")
        assert len(config_a["listeners"]) == 1
        assert config_b["listeners"] == []
        assert config_c["listeners"] == []
        serialized_a = json.dumps(config_a)
        serialized_others = json.dumps([config_b, config_c])
        assert relay_username in serialized_a and relay_password in serialized_a
        assert relay_username not in serialized_others and relay_password not in serialized_others

        wait_until("US-A relay listener", lambda: not port_closed(relay_port), timeout=30)
        http_response = socks5_http_get(relay_port, relay_username, relay_password, echo_port)
        assert http_response.split(b"\r\n\r\n", 1)[1].strip() == EXIT_IP.encode()

        def traffic_accounted() -> bool:
            rules = api.request("GET", "/admin/socks5-rules")
            users = api.request("GET", "/admin/users")
            assert isinstance(rules, list) and isinstance(users, list)
            rule = next(row for row in rules if int(row["rule_id"]) == rule_id)
            admin = next(row for row in users if row["username"] == "admin")
            return int(rule["traffic_used"]) > 0 and int(admin["traffic_used"]) > 0

        wait_until("rule and user traffic accounting", traffic_accounted, timeout=30, interval=1)

        api.request("DELETE", f"/admin/socks5-rules/{rule_id}")
        wait_until("deleted listener to close", lambda: port_closed(relay_port), timeout=30)
        assert node_config("stage4-us-a")["listeners"] == []

        with sqlite3.connect(database_path) as connection:
            receipts = connection.execute(
                "SELECT COUNT(*) FROM relay_creation_receipts WHERE rule_id=?", (rule_id,)
            ).fetchone()[0]
            rules_left = connection.execute(
                "SELECT COUNT(*) FROM forward_rules WHERE id=?", (rule_id,)
            ).fetchone()[0]
        assert receipts == 0 and rules_left == 0

        print(
            json.dumps(
                {
                    "gate": "PASS",
                    "nodes": ["US-A", "US-B", "JP-C"],
                    "recommended": "US-A",
                    "actual_exit_ip": EXIT_IP,
                    "config_isolation": "PASS",
                    "idempotency": "PASS",
                    "traffic_accounting": "PASS",
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
            with contextlib.suppress(subprocess.TimeoutExpired):
                process.wait(timeout=5)
            if process.poll() is None:
                process.kill()
        for log in logs:
            log.close()
        for server in servers:
            server.shutdown()
            server.server_close()
        shutil.rmtree(temp_root, ignore_errors=True)


if __name__ == "__main__":
    main()
