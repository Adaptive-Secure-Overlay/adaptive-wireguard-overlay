from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal, Protocol

from .models import Endpoint
from .parser import WireGuardPacket, parse_packet
from .trust_registry import TrustRegistryError, TrustedRegistryStore


class OverlayDaemonPort(Protocol):
    def send_protocol_datagram(
        self,
        *,
        protocol: str,
        peer_user: str,
        peer_public_key: str,
        payload: bytes,
        meta: dict[str, object],
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class CaptureResult:
    action: Literal["OVERLAY", "DIRECT_BYPASS", "DROP"]
    message_type: int | None
    reason: str = ""


@dataclass(frozen=True, slots=True)
class InjectionRequest:
    """Validated request for a future privileged backend; this class performs no I/O."""

    capture_id: str
    source: Endpoint
    destination: Endpoint
    packet: WireGuardPacket
    registry_id: str
    registry_version: int
    source_public_key: str = field(repr=False)
    destination_public_key: str = field(repr=False)
    payload: bytes = field(repr=False)


class WgProxyAdapter:
    """Protocol boundary that releases peer keys only from a verified registry."""

    def __init__(self, daemon: OverlayDaemonPort, registry: TrustedRegistryStore) -> None:
        self._daemon = daemon
        self._registry = registry

    def capture_datagram(
        self,
        *,
        payload: bytes,
        source: Endpoint,
        destination: Endpoint,
        source_node: str,
        destination_node: str,
        capture_id: str,
        source_public_key: str | None = None,
        destination_public_key: str | None = None,
    ) -> CaptureResult:
        if not _valid_token(source_node) or not _valid_token(destination_node) or not _valid_token(capture_id):
            return CaptureResult("DROP", None, "invalid metadata token")
        try:
            packet = parse_packet(payload)
        except (TypeError, ValueError):
            return CaptureResult("DROP", None, "invalid WireGuard framing")
        if packet.is_transport:
            return CaptureResult("DIRECT_BYPASS", int(packet.message_type))

        try:
            trusted_source, trusted_destination = self._registry.require_nodes(
                (source_node, destination_node)
            )
            if source_public_key is not None:
                self._registry.assert_presented_key(source_node, source_public_key)
            if destination_public_key is not None:
                self._registry.assert_presented_key(destination_node, destination_public_key)
            registry = self._registry.snapshot
        except TrustRegistryError:
            return CaptureResult("DROP", int(packet.message_type), "untrusted node registry binding")

        meta: dict[str, object] = {
            "capture_id": capture_id,
            "wg_message_type": int(packet.message_type),
            "src_ip": source.host,
            "src_port": source.port,
            "dst_ip": destination.host,
            "dst_port": destination.port,
            "src_node": source_node,
            "dst_node": destination_node,
            "registry_id": registry.registry_id,
            "registry_version": registry.version,
            "src_key_fingerprint": trusted_source.fingerprint,
            "dst_key_fingerprint": trusted_destination.fingerprint,
        }
        self._daemon.send_protocol_datagram(
            protocol="wireguard",
            peer_user=destination_node,
            peer_public_key=trusted_destination.public_key,
            payload=payload,
            meta=meta,
        )
        return CaptureResult("OVERLAY", int(packet.message_type))

    def deliver_protocol_datagram(
        self,
        *,
        protocol: str,
        payload: bytes,
        meta: dict[str, object],
    ) -> InjectionRequest:
        if protocol != "wireguard":
            raise ValueError("unsupported protocol")
        packet = parse_packet(payload)
        if packet.is_transport:
            raise ValueError("WireGuard transport type 4 is forbidden in overlay delivery")

        required = {
            "capture_id",
            "wg_message_type",
            "src_ip",
            "src_port",
            "dst_ip",
            "dst_port",
            "src_node",
            "dst_node",
            "registry_id",
            "registry_version",
            "src_key_fingerprint",
            "dst_key_fingerprint",
        }
        if not required.issubset(meta):
            raise ValueError("incomplete overlay metadata")
        if meta["wg_message_type"] != int(packet.message_type):
            raise ValueError("metadata and WireGuard message type disagree")
        for name in ("capture_id", "src_node", "dst_node"):
            if not isinstance(meta[name], str) or not _valid_token(meta[name]):
                raise ValueError(f"invalid {name}")
        if not isinstance(meta["src_ip"], str) or not isinstance(meta["dst_ip"], str):
            raise ValueError("endpoint hosts must be strings")
        if not isinstance(meta["src_port"], int) or isinstance(meta["src_port"], bool):
            raise ValueError("source port must be an integer")
        if not isinstance(meta["dst_port"], int) or isinstance(meta["dst_port"], bool):
            raise ValueError("destination port must be an integer")

        try:
            registry = self._registry.snapshot
            if meta["registry_id"] != registry.registry_id:
                raise ValueError("overlay registry id is not current")
            if type(meta["registry_version"]) is not int or meta["registry_version"] != registry.version:
                raise ValueError("overlay registry version is not current")
            trusted_source, trusted_destination = self._registry.require_nodes(
                (meta["src_node"], meta["dst_node"])
            )
            if meta["src_key_fingerprint"] != trusted_source.fingerprint:
                raise ValueError("source identity binding is not current")
            if meta["dst_key_fingerprint"] != trusted_destination.fingerprint:
                raise ValueError("destination identity binding is not current")
        except TrustRegistryError as exc:
            raise ValueError("untrusted node registry binding") from exc

        return InjectionRequest(
            capture_id=meta["capture_id"],
            source=Endpoint(meta["src_ip"], meta["src_port"]),
            destination=Endpoint(meta["dst_ip"], meta["dst_port"]),
            packet=packet,
            registry_id=registry.registry_id,
            registry_version=registry.version,
            source_public_key=trusted_source.public_key,
            destination_public_key=trusted_destination.public_key,
            payload=payload,
        )


def _valid_token(value: str) -> bool:
    return isinstance(value, str) and 0 < len(value) <= 128 and not any(char.isspace() for char in value)
