#!/usr/bin/env bash
set -euo pipefail

NAME="${1:-User13}"
PID_FILE="${PID_FILE:-/var/run/hybrid-overlay-${NAME}.pid}"

if [[ -f "${PID_FILE}" ]]; then
  pid="$(cat "${PID_FILE}")"
  kill "${pid}" >/dev/null 2>&1 || true
  rm -f "${PID_FILE}"
fi

pids="$(pgrep -f "/root/hybrid-overlay/[n]ode_daemon.py --name ${NAME}" || true)"
if [[ -n "${pids}" ]]; then
  kill ${pids} >/dev/null 2>&1 || true
fi

echo "[OK] EVE Windows sidecar stopped as ${NAME}"
