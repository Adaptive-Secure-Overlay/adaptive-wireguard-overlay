# -*- coding: utf-8 -*-
"""Docker / Dual-NAT wrapper around the reference Python MCC NodeDaemon.

Adds only two WAN/Docker plumbing capabilities without altering MCC cryptography,
Ed25519/X25519 capsules, JSON canonicalization, or SQLite anti-replay state:
1. Authenticated NAT endpoint roaming (dynamic src IP/port learning after AEAD
   verification or MGMT handshake for nodes behind residential NAT / Docker bridge).
2. --ike-local-ip mapping so local raw injection targets the container interface
   while signed MCC bodies retain the node's public underlay identity.
"""

from __future__ import annotations

import argparse
import os
import socket
import struct
import sys
from typing import Dict, Optional, Tuple

import cryptography

import config
from ike_proxy import IkeInjectionOutcome, IkeProxy, SO_MARK
from link_transport import T_LINK_FRAG
from node_daemon import NodeDaemon
from protocol import (
    T_ERROR,
    T_I1,
    T_I2,
    T_LOCAL_CONNECT,
    T_MCC_ACCEPT,
    T_MCC_OFFER,
    T_MCC_OPAQUE_FWD,
    T_MCC_START,
    T_MCC_X2,
    T_MGMT_AUTH,
    T_MGMT_AUTH_RESP,
    T_MGMT_INIT,
    T_MGMT_INIT_RESP,
    T_OKX2,
    T_PRIV_BACK,
    T_PRIV_BKEY_REQ,
    T_PRIV_BKEY_RESP,
    T_PRIV_DELIVER,
    T_PRIV_FWD,
    T_PRIV_INLINE_START,
    T_PRIV_INLINE_X2,
    T_PRIV_X1B_SEAL,
    T_PROXY_BLOB,
)

SECURE_TYPES = (
    T_I1, T_I2, T_OKX2, T_PROXY_BLOB,
    T_PRIV_FWD, T_PRIV_DELIVER, T_PRIV_BACK,
    T_PRIV_BKEY_REQ, T_PRIV_BKEY_RESP, T_PRIV_X1B_SEAL,
    T_PRIV_INLINE_START, T_PRIV_INLINE_X2,
    T_MCC_START, T_MCC_X2, T_MCC_OFFER, T_MCC_ACCEPT, T_MCC_OPAQUE_FWD,
)


class WanIkeProxy(IkeProxy):
    """IkeProxy subclass that injects raw IPv4/UDP packets to the container's local IP."""

    def __init__(self, daemon: "WanNodeDaemon", ike_local_ip: str = ""):
        super().__init__(daemon)
        self.ike_local_ip = ike_local_ip.strip()

    def _raw_inject_ipv4_udp(
        self, payload: bytes, remote_ip: str, remote_port: int, local_port: int
    ) -> IkeInjectionOutcome:
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

        udp_header = struct.pack("!HHHH", int(remote_port), int(local_port), udp_len, 0)
        packet = ip_header + udp_header + payload

        rs = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        try:
            try:
                rs.setsockopt(socket.SOL_SOCKET, SO_MARK, int(config.IKE_SOCKET_MARK))
            except OSError as exc:
                self.logger.warning(f"[IKE-PROXY] raw socket cannot set SO_MARK: {exc}")
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
            self.logger.info(
                f"[IKE-PROXY] RAW-INJECT len={len(payload)} "
                f"as {remote_ip}:{remote_port} -> local {local_ip}:{local_port}"
            )
            return IkeInjectionOutcome.SENT
        finally:
            try:
                rs.close()
            except OSError:
                pass


class WanNodeDaemon(NodeDaemon):
    def __init__(self, name: str, ike_local_ip: str = ""):
        self._nat_addrs: Dict[str, Tuple[str, int]] = {}
        self._ike_local_ip = ike_local_ip.strip()
        self._current_rx_src: Optional[Tuple[str, int]] = None
        super().__init__(name)
        self.logger.info(
            f"[WAN-PY] runtime Python={sys.version.split()[0]} "
            f"cryptography={cryptography.__version__} ike_local_ip={self._ike_local_ip or '-'}"
        )

    def start_ike_proxy(self):
        if self.ike_proxy is None:
            self.ike_proxy = WanIkeProxy(self, ike_local_ip=self._ike_local_ip)
            self.ike_proxy.start()

    def _ordered_route_candidates(self, candidates, env_name: str, role: str):
        ordered = super()._ordered_route_candidates(candidates, env_name, role)
        deprioritized = {
            x.strip()
            for x in os.environ.get(f"OVERLAY_DEPRIORITIZE_{role}", "").split(",")
            if x.strip()
        }
        if deprioritized:
            front = [u for u in ordered if u not in deprioritized]
            back = [u for u in ordered if u in deprioritized]
            ordered = front + back
        return ordered

    def send_ike_datagram(
        self, dst_user, ike_src_ip, ike_src_port, ike_dst_ip, ike_dst_port, payload, udp_port
    ):
        if self._ike_local_ip and ike_src_ip == self._ike_local_ip:
            ike_src_ip = config.USERS[self.name]["ip"]
        return super().send_ike_datagram(
            dst_user, ike_src_ip, ike_src_port, ike_dst_ip, ike_dst_port, payload, udp_port
        )

    def peer_addr(self, peer: str) -> Tuple[str, int]:
        with self.lock:
            roamed = self._nat_addrs.get(peer)
        if roamed is not None:
            return roamed
        return super().peer_addr(peer)

    def peer_from_src(self, src: Tuple[str, int]) -> Optional[str]:
        with self.lock:
            for u, addr in self._nat_addrs.items():
                if addr == src:
                    return u
        return super().peer_from_src(src)

    def _remember_nat_addr(self, peer: str, src: Tuple[str, int], reason: str) -> None:
        if not peer or peer == self.name or peer not in config.USERS:
            return
        with self.lock:
            prev = self._nat_addrs.get(peer)
            if prev != src:
                self._nat_addrs[peer] = src
                static_addr = super().peer_addr(peer)
                if src != static_addr:
                    self.logger.info(
                        f"[NAT-ROAM] peer={peer} addr={src[0]}:{src[1]} "
                        f"(static={static_addr[0]}:{static_addr[1]}) reason={reason}"
                    )

    def link_decrypt(self, msg: dict) -> bytes:
        plain = super().link_decrypt(msg)
        # Update dynamic NAT address ONLY after successful AES-GCM verification.
        src = self._current_rx_src
        peer = msg.get("from", "")
        if src is not None and peer in config.USERS:
            self._remember_nat_addr(peer, src, reason=f"aead:{msg.get('t')}")
        return plain

    def handle_packet(self, data: bytes, src: Tuple[str, int]):
        peer = self.peer_from_src(src)
        p = self.safe_load(data)
        if not p or not isinstance(p, dict):
            return

        t = p.get("t")
        if peer is None:
            cand = p.get("from")
            if isinstance(cand, str) and cand in config.USERS and cand != self.name:
                peer = cand

        if t == T_LINK_FRAG:
            full = self._handle_link_frag(p, peer)
            if full:
                self.handle_packet(full, src)
            return

        if t == T_LOCAL_CONNECT:
            self.on_local_connect(p, src)
            return

        if t == T_MGMT_INIT:
            if peer:
                self._remember_nat_addr(peer, src, reason="mgmt_init")
            self.on_mgmt_init(p, peer)
            return

        if t == T_MGMT_AUTH:
            if peer:
                self._remember_nat_addr(peer, src, reason="mgmt_auth")
            self.on_mgmt_auth(p, peer)
            return

        if t == T_MGMT_INIT_RESP:
            if peer:
                self._remember_nat_addr(peer, src, reason="mgmt_init_resp")
            sid = p.get("sid")
            if sid:
                with self.lock:
                    self.hs_initresp[sid] = p
                    ev = self.hs_init_ev.get(sid)
                if ev:
                    ev.set()
            return

        if t == T_MGMT_AUTH_RESP:
            if peer:
                self._remember_nat_addr(peer, src, reason="mgmt_auth_resp")
            sid = p.get("sid")
            if sid:
                with self.lock:
                    self.hs_authresp[sid] = p
                    ev = self.hs_auth_ev.get(sid)
                if ev:
                    ev.set()
            return

        if t == T_ERROR:
            self.on_error(p, peer)
            return

        if t in SECURE_TYPES:
            prev_src = self._current_rx_src
            self._current_rx_src = src
            try:
                self.on_secure_msg(p, peer)
            finally:
                self._current_rx_src = prev_src
            return

        self.logger.info(f"[DROP] unknown t={t} from={peer}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", required=True, choices=list(config.USERS.keys()))
    ap.add_argument("--ike-proxy", action="store_true")
    ap.add_argument("--ike-default-dst", choices=list(config.USERS.keys()), default="")
    ap.add_argument("--ike-local-ip", default="")
    args = ap.parse_args()

    if args.ike_default_dst:
        os.environ["IKE_PROXY_DEFAULT_DST_USER"] = args.ike_default_dst

    daemon = WanNodeDaemon(args.name, ike_local_ip=args.ike_local_ip)
    if args.ike_proxy:
        daemon.start_ike_proxy()
    try:
        daemon.serve_forever()
    except KeyboardInterrupt:
        daemon.stop()


if __name__ == "__main__":
    main()
