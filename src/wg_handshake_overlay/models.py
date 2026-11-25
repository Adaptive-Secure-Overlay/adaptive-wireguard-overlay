from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal


@dataclass(frozen=True, slots=True, order=True)
class Endpoint:
    """An opaque node name and UDP port. It never contains WireGuard keys."""
    host: str
    port: int

    def __post_init__(self) -> None:
        if not self.host or len(self.host) > 255 or any(c.isspace() for c in self.host):
            raise ValueError("endpoint host must be a non-empty token")
        if not 1 <= self.port <= 65535:
            raise ValueError("endpoint port must be between 1 and 65535")

    def label(self) -> str:
        return f"{self.host}:{self.port}"


@dataclass(frozen=True, slots=True)
class Route:
    nodes: tuple[Endpoint, ...]
    expires_at: float

    def __post_init__(self) -> None:
        if len(self.nodes) < 2 or len(set(self.nodes)) != len(self.nodes):
            raise ValueError("route must contain at least two distinct nodes")

    def reverse(self) -> "Route":
        return Route(tuple(reversed(self.nodes)), self.expires_at)

    def next_hop(self, node: Endpoint) -> Endpoint:
        try:
            return self.nodes[self.nodes.index(node) + 1]
        except (ValueError, IndexError) as exc:
            raise ValueError("node has no forward next hop") from exc


@dataclass(frozen=True, slots=True)
class OverlayEnvelope:
    """Opaque WG bytes are intentionally excluded from repr/logging."""
    message_id: str
    route: Route
    hop_index: int
    wireguard_packet: bytes = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if len(self.message_id) != 16 or any(c not in "0123456789abcdef" for c in self.message_id):
            raise ValueError("message_id must be a 16-character hexadecimal fingerprint")
        if not 0 <= self.hop_index < len(self.route.nodes):
            raise ValueError("hop_index is outside the route")


@dataclass(frozen=True, slots=True)
class Event:
    kind: Literal["OVERLAY_FRAME", "DIRECT_BYPASS", "INJECT", "DUPLICATE_DROP", "EXPIRED_DROP", "INVALID_DROP"]
    message_id: str
    node: str
    next_hop: str | None = None
    route: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class RelayVisibleView:
    """The information a relay is permitted to observe in privacy mode."""
    message_id: str
    previous_hop: Endpoint | None
    next_hop: Endpoint | None
    final_endpoint: Endpoint | None
