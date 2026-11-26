#!/usr/bin/env bash
set -euo pipefail

# Parameterized nftables rules for an isolated container / Linux netns running
# Linux kernel WireGuard (wg0) alongside the Python MCC overlay daemon.
#
# Invariants:
#   1. WireGuard Type 4 (Transport Data, 0x04000000) bypasses conntrack (notrack)
#      and flows directly A <-> B without touching Python.
#   2. WireGuard Type 1/2/3 (0x01/0x02/0x03) are redirected to the local Python
#      MCC capture socket.
#   3. Adapter-injected datagrams (SO_MARK 0x53) bypass conntrack and redirect.
#
# Usage (inside isolated container / netns only):
#   PEER_IP=192.0.2.13 WG_PORT=4500 CAP_PORT=15202 MARK_HEX=0x53 bash wg_proxy_nft_apply.sh

PEER_IP="${PEER_IP:?Set PEER_IP to remote WireGuard peer IPv4 (e.g. 192.0.2.13)}"
WG_PORT="${WG_PORT:-4500}"
CAP_PORT="${CAP_PORT:-15202}"
MARK_HEX="${MARK_HEX:-0x53}"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root inside an isolated container or network namespace" >&2
  exit 1
fi

command -v nft >/dev/null 2>&1 || { echo "nft is not installed" >&2; exit 1; }

nft list table inet wgproxy >/dev/null 2>&1 && nft delete table inet wgproxy
nft -f - <<NFT
add table inet wgproxy
add chain inet wgproxy prerouting_raw { type filter hook prerouting priority raw; policy accept; }
add chain inet wgproxy output_raw { type filter hook output priority raw; policy accept; }
add chain inet wgproxy output { type nat hook output priority -100; policy accept; }

# Exempt direct WireGuard Type 4 transport data from conntrack in both directions
add rule inet wgproxy prerouting_raw ip saddr ${PEER_IP} udp sport ${WG_PORT} udp dport ${WG_PORT} @th,64,32 0x04000000 notrack
add rule inet wgproxy output_raw meta mark ${MARK_HEX} notrack
add rule inet wgproxy output_raw ip daddr ${PEER_IP} udp dport ${WG_PORT} @th,64,32 0x04000000 notrack

# Never re-capture packets raw-injected by the overlay adapter
add rule inet wgproxy output meta mark ${MARK_HEX} return

# Capture ONLY WireGuard control frames (Type 1 Initiation, Type 2 Response, Type 3 Cookie)
add rule inet wgproxy output ip daddr ${PEER_IP} udp dport ${WG_PORT} @th,64,32 0x01000000 redirect to :${CAP_PORT}
add rule inet wgproxy output ip daddr ${PEER_IP} udp dport ${WG_PORT} @th,64,32 0x02000000 redirect to :${CAP_PORT}
add rule inet wgproxy output ip daddr ${PEER_IP} udp dport ${WG_PORT} @th,64,32 0x03000000 redirect to :${CAP_PORT}
NFT

echo "[OK] nft wgproxy rules applied for peer=${PEER_IP}:${WG_PORT} -> :${CAP_PORT} (mark=${MARK_HEX}, Type 4 direct notrack)"
