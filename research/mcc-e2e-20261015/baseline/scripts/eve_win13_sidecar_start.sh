#!/usr/bin/env bash
set -euo pipefail

NAME="${1:-User13}"
BASE_DIR="${BASE_DIR:-/root/hybrid-overlay}"
PID_FILE="${PID_FILE:-/var/run/hybrid-overlay-${NAME}.pid}"
LOG_FILE="${LOG_FILE:-/var/log/hybrid-overlay-${NAME}.log}"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root" >&2
  exit 1
fi

"${BASE_DIR}/scripts/eve_win13_sidecar_stop.sh" "${NAME}" >/dev/null 2>&1 || true

sysctl -w net.ipv4.ip_nonlocal_bind=1 >/dev/null || true
sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null || true
sysctl -w net.ipv4.conf.default.rp_filter=0 >/dev/null || true

cd "${BASE_DIR}"
: > "${LOG_FILE}"
setsid /usr/bin/python3 "${BASE_DIR}/node_daemon.py" --name "${NAME}" --ike-proxy \
  >>"${LOG_FILE}" 2>&1 < /dev/null &
echo "$!" > "${PID_FILE}"
sleep 1

if ! kill -0 "$(cat "${PID_FILE}")" 2>/dev/null; then
  echo "hybrid overlay sidecar failed to start, see ${LOG_FILE}" >&2
  exit 1
fi

echo "[OK] EVE Windows sidecar started as ${NAME}, pid=$(cat "${PID_FILE}")"
