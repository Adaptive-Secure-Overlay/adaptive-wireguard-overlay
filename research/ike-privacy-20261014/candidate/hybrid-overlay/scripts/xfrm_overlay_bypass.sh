#!/usr/bin/env bash
set -euo pipefail

# Keep overlay control traffic outside the CHILD_SA host-to-host policies.
# This is required for repeated-role routes such as A->B->A->B, where an
# overlay hop can be between the same endpoints that are negotiating IPsec.

OVERLAY_PORT="${OVERLAY_PORT:-9000}"
PRIORITY="${OVERLAY_XFRM_BYPASS_PRIORITY:-1}"

KNOWN_IPS=(
  192.168.101.10
  192.168.102.10
  192.168.103.10
  192.168.104.10
  192.168.105.10
  192.168.106.10
  192.168.107.10
  192.168.108.10
  192.168.109.10
  192.168.110.10
  10.255.11.2
  10.255.12.2
  192.168.113.199
)

LOCAL_IP=""
for ip in "${KNOWN_IPS[@]}"; do
  if ip -4 addr show | grep -qw "${ip}"; then
    LOCAL_IP="${ip}"
    break
  fi
done

if [[ -z "${LOCAL_IP}" ]]; then
  echo "[WARN] no known overlay local IP found; xfrm overlay bypass not installed" >&2
  exit 0
fi

add_policy() {
  local dir="$1"
  local src="$2"
  local dst="$3"
  ip xfrm policy delete dir "${dir}" src "${src}/32" dst "${dst}/32" \
    proto udp sport "${OVERLAY_PORT}" dport "${OVERLAY_PORT}" >/dev/null 2>&1 || true
  ip xfrm policy add dir "${dir}" src "${src}/32" dst "${dst}/32" \
    proto udp sport "${OVERLAY_PORT}" dport "${OVERLAY_PORT}" \
    action allow priority "${PRIORITY}"
}

for peer in "${KNOWN_IPS[@]}"; do
  [[ "${peer}" == "${LOCAL_IP}" ]] && continue
  add_policy out "${LOCAL_IP}" "${peer}"
  add_policy in "${peer}" "${LOCAL_IP}"
done

echo "[OK] XFRM overlay bypass installed for ${LOCAL_IP}: UDP/${OVERLAY_PORT}, priority ${PRIORITY}"
