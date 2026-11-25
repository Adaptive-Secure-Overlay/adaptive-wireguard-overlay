from __future__ import annotations

from hashlib import sha256

from .models import Endpoint, Event, OverlayEnvelope, RelayVisibleView
from .parser import parse_packet
from .routing import RouteCache


class HandshakeOverlayEngine:
    """Pure fail-closed state machine; it performs no I/O or system changes."""

    def __init__(self, cache: RouteCache, relays: tuple[Endpoint, ...], privacy_mode: bool = True) -> None:
        if not relays:
            raise ValueError("at least one relay is required")
        self.cache = cache
        self.relays = relays
        self.privacy_mode = privacy_mode

    @staticmethod
    def fingerprint(packet: bytes, source: Endpoint, destination: Endpoint) -> str:
        return sha256(
            source.label().encode()
            + b"\0"
            + destination.label().encode()
            + b"\0"
            + packet
        ).hexdigest()[:16]

    def capture(self, source: Endpoint, destination: Endpoint, packet: bytes, now: float) -> tuple[Event, ...]:
        try:
            parsed = parse_packet(packet)
        except (TypeError, ValueError):
            return (Event("INVALID_DROP", "0000000000000000", source.label()),)

        message_id = self.fingerprint(packet, source, destination)
        if parsed.is_transport:
            return (Event("DIRECT_BYPASS", message_id, source.label(), destination.label()),)

        try:
            route = self.cache.get(source, destination, now)
            if route is None:
                route = self.cache.establish(source, self.relays, destination, now)
            envelope = OverlayEnvelope(message_id, route, 0, packet)
        except ValueError:
            return (Event("INVALID_DROP", message_id, source.label()),)
        return self.forward(envelope, now)

    def forward(self, envelope: OverlayEnvelope, now: float) -> tuple[Event, ...]:
        try:
            parsed = parse_packet(envelope.wireguard_packet)
        except (TypeError, ValueError):
            return (Event("INVALID_DROP", envelope.message_id, "unknown"),)
        if parsed.is_transport:
            node = envelope.route.nodes[envelope.hop_index]
            return (Event("INVALID_DROP", envelope.message_id, node.label()),)

        route = envelope.route
        node = route.nodes[envelope.hop_index]
        if route.expires_at <= now:
            return (Event("EXPIRED_DROP", envelope.message_id, node.label()),)
        if not self.cache.mark_once(f"{envelope.message_id}:{envelope.hop_index}", now):
            return (Event("DUPLICATE_DROP", envelope.message_id, node.label()),)
        if envelope.hop_index == len(route.nodes) - 1:
            return (
                Event(
                    "INJECT",
                    envelope.message_id,
                    node.label(),
                    route=tuple(item.label() for item in route.nodes),
                ),
            )

        visible_route = () if self.privacy_mode else tuple(item.label() for item in route.nodes)
        return (
            Event(
                "OVERLAY_FRAME",
                envelope.message_id,
                node.label(),
                route.nodes[envelope.hop_index + 1].label(),
                visible_route,
            ),
        )

    def advance(self, envelope: OverlayEnvelope, now: float) -> tuple[Event, ...]:
        """Model delivery by exactly one hop while retaining opaque WG bytes."""
        if envelope.hop_index + 1 >= len(envelope.route.nodes):
            return (Event("INVALID_DROP", envelope.message_id, envelope.route.nodes[-1].label()),)
        advanced = OverlayEnvelope(
            envelope.message_id,
            envelope.route,
            envelope.hop_index + 1,
            envelope.wireguard_packet,
        )
        return self.forward(advanced, now)

    def relay_view(self, envelope: OverlayEnvelope) -> RelayVisibleView:
        index = envelope.hop_index
        nodes = envelope.route.nodes
        previous = nodes[index - 1] if index else None
        following = nodes[index + 1] if index + 1 < len(nodes) else None
        final = None if self.privacy_mode else nodes[-1]
        return RelayVisibleView(envelope.message_id, previous, following, final)
