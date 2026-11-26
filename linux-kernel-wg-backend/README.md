# Linux Kernel WireGuard (`wg0`) + Python MCC Overlay Backend

This directory implements the privileged Linux kernel `wg0` adapter that connects:
- the unmodified WireGuard framing parser ([`src/wg_handshake_overlay/parser.py`](../src/wg_handshake_overlay/parser.py)),
- the unmodified authenticated MCC E2E daemon ([`research/mcc-e2e-20261015/candidate/`](../research/mcc-e2e-20261015/candidate/)),
- native Linux kernel `wireguard` (`wg0`) for direct `Type 4` `ChaCha20-Poly1305` data-plane transport, and
- `nftables` + raw IPv4/UDP injection (`SO_MARK 0x53`, RFC 768 UDP checksum) so **only** WireGuard control frames (`Type 1` 148 B, `Type 2` 92 B, `Type 3` 64 B) traverse the multi-hop overlay (`A -> X1 -> X2 -> B`).

## How It Works

1. **`wg_proxy_nft_apply.sh`** installs isolated container/netns `nftables` rules:
   - `prerouting_raw` & `output_raw`: exempts `Type 4` (`@th,64,32 0x04000000`) and adapter-injected packets (`meta mark 0x53`) from Linux `conntrack` (`notrack`).
   - `output` (`dstnat`): redirects only `Type 1/2/3` (`0x01000000`, `0x02000000`, `0x03000000`) to the Python capture socket.
2. **`wan_py_wg_daemon.py`** validates every captured/injected payload via `wg_handshake_overlay.parser.parse_packet()` (rejecting `Type 4` fail-closed), maps `Type 1 sender_index` <-> `Type 2/3 receiver_index` into the MCC correlation header (`mcc_auth.py`), and injects received control frames into local `wg0` with RFC 768 UDP checksums.
3. **`wan_py_daemon.py`** adds authenticated NAT endpoint roaming and `--ike-local-ip` mapping for Dual-NAT Docker deployments without modifying MCC cryptography or SQLite anti-replay logic.
4. **Unmodified Python relays (`X1`, `X2`)** carry opaque encrypted MCC capsules and require zero WireGuard-specific changes.

> **Important operational note:** The synchronous single-threaded Python `serve_forever()` receive loop requires `PRECONNECT_ENABLED=1` so relay `MGMT` sessions are established before the first handshake. For non-blocking on-demand sessions (`--no-preconnect`) and rootless cross-platform userspace WireGuard (`boringtun`, Android/Windows/macOS), see the Rust port [`Adaptive-Secure-Overlay/cascade-control-overlay`](https://github.com/Adaptive-Secure-Overlay/cascade-control-overlay).

## Live 4-Node Geo-Distributed WAN Verification Summary (Dual NAT)

Measured across 4 geographically distributed Linux hosts (`Node A [Home NAT] -> Node X1 [City-1] -> Node X2 [City-2] -> Node B [City-3 NAT]`):

| Metric (`CPython 3.14.10` + `cryptography 50.0.2` + Kernel `wg0`) | Measured Result |
| :--- | :--- |
| Initial 1-RTT handshake (`PRECONNECT=1`, warm) | `~146 ms` (`167.2 ms` incl. first `Type 4` ICMP reply) |
| Direct control-plane leakage (`tcpdump` on `A` & `B`) | **`0`** (`WG_DIRECT_T1 = 0`, `T2 = 0`, `T3 = 0`, `OV_AB = 0`) |
| Steady-state tunnel RTT (10 probes, `0%` loss) | `20.65 / 21.03 / 21.76 ms` (`min / avg / max`) |
| `iperf3` TCP (`10 s`, receiver) | 1-stream `71.1 Mbps`; 4-stream `71.9 Mbps` (`A->B`), `88.0 Mbps` (`B->A`) |
| Automatic `120 s` PFS rekey under continuous ping | **`0 / 75` (`0.0%` loss)**, avg RTT `21.13 ms`, **`0`** direct `Type 1/2/3` (`453` direct `Type 4`) |
| Peak overlay daemon RAM (`VmHWM`) | `41.7–42.4 MB` (`12` threads; container image `248 MB`) |
| Overlay UDP packets per WG handshake (host `A`) | `354 pkts` (`168` `X1` + `186` `X2`) |

Full 2×2 comparison against Python IPsec, Rust IPsec, and 100% Rust userspace WireGuard (`boringtun 0.7.1`) is archived in [`adaptive-overlay-experiments/wan-2x2-benchmark-20261126`](https://github.com/Adaptive-Secure-Overlay/adaptive-overlay-experiments).
