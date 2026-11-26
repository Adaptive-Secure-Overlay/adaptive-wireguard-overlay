# -*- coding: utf-8 -*-
"""Linux Kernel WireGuard (wg0) + Python MCC Overlay backend.

Connects:
- Unmodified WireGuard framing parser (wg_handshake_overlay.parser)
- Unmodified authenticated MCC core (research/mcc-e2e-20261015/candidate)
- Native Linux kernel wireguard (wg0) for direct Type 4 ChaCha20-Poly1305 data plane
- nftables OUTPUT redirect for Type 1/2/3 only + RFC 768 raw IPv4/UDP injection (SO_MARK 0x53)
"""

from __future__ import annotations

import argparse
import os
import socket
import struct
from typing import Optional

from wg_handshake_overlay.parser import WireGuardMessageType, parse_packet


def is_wg_control_payload(udp_port: int, payload: bytes, *, expected_port: int = 4500) -> bool:
    """Allow ONLY WireGuard Handshake Type 1 (148 B), Type 2 (92 B), Type 3 (64 B).

    Type 4 (Transport Data) and malformed datagrams are rejected fail-closed.
    """
    if int(udp_port) != int(expected_port):
        return False
    try:
        pkt = parse_packet(payload)
        return pkt.is_handshake_control
    except (TypeError, ValueError):
        return False


def udp_ipv4_checksum(src_b: bytes, dst_b: bytes, udp_header_zero: bytes, payload: bytes) -> int:
    """Compute canonical RFC 768 IPv4 UDP checksum for kernel wg0 raw injection."""
    pseudo = src_b + dst_b + struct.pack("!BBH", 0, socket.IPPROTO_UDP, len(udp_header_zero) + len(payload))
    data = pseudo + udp_header_zero + payload
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
        total = (total & 0xFFFF) + (total >> 16)
    csum = (~total) & 0xFFFF
    return 0xFFFF if csum == 0 else csum


def build_wg_correlation_header(payload: bytes, udp_port: int, *, expected_port: int = 4500) -> bytes:
    """Synthesize a 28-byte correlation header consumed by the unmodified MCC auth core.

    Maps WireGuard handshake indices so mcc_auth.py correlates Type 1 <-> Type 2/3
    end-to-end (including automatic 120s PFS rekeys with fresh sender_index values):
    - [0..8]   initiator_spi = idx_bytes + 4 zero bytes
    - [18]     exchange_type = 1 (WG handshake)
    - [19]     flags (0x00 for Type 1 request, 0x20 for Type 2/3 response)
    - [20..24] message_id    = idx_bytes
    - [24..28] length        = len(payload)
    """
    if int(udp_port) != int(expected_port):
        raise ValueError(f"WireGuard overlay adapter expects UDP/{expected_port}")
    pkt = parse_packet(payload)
    if pkt.is_transport:
        raise ValueError("WireGuard Type 4 transport data is forbidden in overlay")

    if pkt.message_type == WireGuardMessageType.HANDSHAKE_INITIATION:
        idx_bytes = payload[4:8]   # initiator sender_index
        flags = 0x00               # request
    elif pkt.message_type == WireGuardMessageType.HANDSHAKE_RESPONSE:
        idx_bytes = payload[8:12]  # responder receiver_index == initiator sender_index
        flags = 0x20               # response
    elif pkt.message_type == WireGuardMessageType.COOKIE_REPLY:
        idx_bytes = payload[4:8]   # receiver_index
        flags = 0x20               # response
    else:
        raise ValueError("Unsupported WireGuard control message type")

    return (
        idx_bytes
        + b"\x00\x00\x00\x00"
        + b"\x00" * 8
        + bytes([0x00, 0x20, 0x01, flags])
        + idx_bytes
        + struct.pack("!I", len(payload))
    )


def _load_daemon_classes():
    """Import runtime daemon dependencies lazily so pure helpers stay unit-testable
    without binding sockets or requiring the full MCC runtime in offline tests."""
    import config
    import ike_proxy as ike_proxy_mod
    from ike_proxy import IkeInjectionOutcome, SO_MARK
    from wan_py_daemon import WanIkeProxy, WanNodeDaemon

    wg_port = int(os.environ.get("WG_OVERLAY_PORT", "4500"))
    ike_proxy_mod.is_ike_payload = lambda port, data: is_wg_control_payload(
        port, data, expected_port=wg_port
    )

    class WanWgProxy(WanIkeProxy):
        """Raw IPv4/UDP injector with RFC 768 UDP checksum for Linux kernel wg0."""

        def _raw_inject_ipv4_udp(
            self, payload: bytes, remote_ip: str, remote_port: int, local_port: int
        ) -> IkeInjectionOutcome:
            if not is_wg_control_payload(local_port, payload, expected_port=wg_port):
                self.logger.warning("[WG-PROXY] refusing to inject non-WG-control payload")
                return IkeInjectionOutcome.REJECTED

            local_ip = self.ike_local_ip or config.USERS[self.daemon.name]["ip"]
            src_b = socket.inet_aton(remote_ip)
            dst_b = socket.inet_aton(local_ip)

            udp_len = 8 + len(payload)
            ip_len = 20 + udp_len

            ip_header0 = struct.pack(
                "!BBHHHBBH4s4s",
                0x45, 0, ip_len, os.getpid() & 0xFFFF, 0, 64, socket.IPPROTO_UDP, 0, src_b, dst_b,
            )
            ip_sum = self._ip_checksum(ip_header0)
            ip_header = struct.pack(
                "!BBHHHBBH4s4s",
                0x45, 0, ip_len, os.getpid() & 0xFFFF, 0, 64, socket.IPPROTO_UDP, ip_sum, src_b, dst_b,
            )

            udp_zero = struct.pack("!HHHH", int(remote_port), int(local_port), udp_len, 0)
            csum = udp_ipv4_checksum(src_b, dst_b, udp_zero, payload)
            udp_header = struct.pack("!HHHH", int(remote_port), int(local_port), udp_len, csum)
            packet = ip_header + udp_header + payload

            rs = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            try:
                try:
                    rs.setsockopt(socket.SOL_SOCKET, SO_MARK, int(config.IKE_SOCKET_MARK))
                except OSError as exc:
                    self.logger.warning(f"[WG-PROXY] raw socket cannot set SO_MARK: {exc}")
                try:
                    rs.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                except OSError:
                    pass
                try:
                    sent = rs.sendto(packet, (local_ip, int(local_port)))
                except OSError:
                    return IkeInjectionOutcome.UNKNOWN
                if sent != len(packet):
                    return IkeInjectionOutcome.UNKNOWN
                pkt = parse_packet(payload)
                self.logger.info(
                    f"[WG-PROXY] RAW-INJECT wg_type={int(pkt.message_type)} ({pkt.name}) len={len(payload)} "
                    f"as {remote_ip}:{remote_port} -> local {local_ip}:{local_port}"
                )
                return IkeInjectionOutcome.SENT
            finally:
                try:
                    rs.close()
                except OSError:
                    pass

    class WanWgNodeDaemon(WanNodeDaemon):
        def start_ike_proxy(self):
            if self.ike_proxy is None:
                self.ike_proxy = WanWgProxy(self, ike_local_ip=self._ike_local_ip)
                self.ike_proxy.start()

        @staticmethod
        def _opaque_ike_header(payload, udp_port):
            return build_wg_correlation_header(payload, udp_port, expected_port=wg_port)

    return config, WanWgNodeDaemon


def main(argv: Optional[list[str]] = None) -> None:
    config, WanWgNodeDaemon = _load_daemon_classes()
    ap = argparse.ArgumentParser(description="Linux Kernel WireGuard + Python MCC Overlay daemon")
    ap.add_argument("--name", required=True, choices=list(config.USERS.keys()))
    ap.add_argument("--ike-proxy", action="store_true")
    ap.add_argument("--ike-default-dst", choices=list(config.USERS.keys()), default="")
    ap.add_argument("--ike-local-ip", default="")
    args = ap.parse_args(argv)

    if args.ike_default_dst:
        os.environ["IKE_PROXY_DEFAULT_DST_USER"] = args.ike_default_dst

    daemon = WanWgNodeDaemon(args.name, ike_local_ip=args.ike_local_ip)
    if args.ike_proxy:
        daemon.start_ike_proxy()
    try:
        daemon.serve_forever()
    except KeyboardInterrupt:
        daemon.stop()


if __name__ == "__main__":
    main()
