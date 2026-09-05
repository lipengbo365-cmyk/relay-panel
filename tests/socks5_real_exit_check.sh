#!/usr/bin/env bash
set -euo pipefail

# Acceptance test for a deployed SOCKS5 relay rule. Keep credentials in
# environment variables and feed curl's sensitive options over stdin so they
# do not appear in the process argument list or on disk.
#
# Required:
#   RELAY_SOCKS5_HOST, RELAY_SOCKS5_PORT
#   RELAY_SOCKS5_USERNAME, RELAY_SOCKS5_PASSWORD
#   EXPECTED_EXIT_IP
# Optional:
#   RELAY_NODE_PUBLIC_IP (asserts the exit is not the relay node)
#   EXIT_CHECK_URL (defaults to api.ipify.org)

: "${RELAY_SOCKS5_HOST:?missing RELAY_SOCKS5_HOST}"
: "${RELAY_SOCKS5_PORT:?missing RELAY_SOCKS5_PORT}"
: "${RELAY_SOCKS5_USERNAME:?missing RELAY_SOCKS5_USERNAME}"
: "${RELAY_SOCKS5_PASSWORD:?missing RELAY_SOCKS5_PASSWORD}"
: "${EXPECTED_EXIT_IP:?missing EXPECTED_EXIT_IP}"

EXIT_CHECK_URL="${EXIT_CHECK_URL:-https://api.ipify.org}"

for value in "${RELAY_SOCKS5_HOST}" "${RELAY_SOCKS5_USERNAME}" "${RELAY_SOCKS5_PASSWORD}"; do
  if [[ "${value}" == *$'\n'* || "${value}" == *$'\r'* || "${value}" == *'"'* ]]; then
    printf 'FAIL: relay SOCKS5 values may not contain quotes or newlines\n' >&2
    exit 2
  fi
done

actual_exit_ip="$({
  printf 'fail\nsilent\nshow-error\nconnect-timeout = 10\nmax-time = 30\nproxy = "socks5h://%s:%s"\nproxy-user = "%s:%s"\n' \
    "${RELAY_SOCKS5_HOST}" "${RELAY_SOCKS5_PORT}" \
    "${RELAY_SOCKS5_USERNAME}" "${RELAY_SOCKS5_PASSWORD}" |
    curl --config - "${EXIT_CHECK_URL}"
} | tr -d '\r\n[:space:]')"

if [[ "${actual_exit_ip}" != "${EXPECTED_EXIT_IP}" ]]; then
  printf 'FAIL: expected SOCKS5 exit %s, got %s\n' "${EXPECTED_EXIT_IP}" "${actual_exit_ip}" >&2
  exit 1
fi

if [[ -n "${RELAY_NODE_PUBLIC_IP:-}" && "${actual_exit_ip}" == "${RELAY_NODE_PUBLIC_IP}" ]]; then
  printf 'FAIL: destination observed Relay Node IP %s\n' "${actual_exit_ip}" >&2
  exit 1
fi

printf 'PASS: destination observed upstream SOCKS5 exit IP %s\n' "${actual_exit_ip}"
