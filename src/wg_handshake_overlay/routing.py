from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

from .models import Endpoint, Route
from .trust_registry import RegistryKeyMismatchError, TrustedRegistryStore


@dataclass(slots=True)
class RouteCache:
    """Deterministic, bounded in-memory route registry; no route discovery I/O."""

    ttl_seconds: float = 60.0
    _routes: dict[tuple[Endpoint, Endpoint], Route] = field(
        default_factory=dict,
        init=False,
        repr=False,
    )
    _seen: dict[str, float] = field(default_factory=dict, init=False, repr=False)

    def __post_init__(self) -> None:
        if self.ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")

    def establish(
        self,
        source: Endpoint,
        relays: tuple[Endpoint, ...],
        destination: Endpoint,
        now: float,
    ) -> Route:
        if source == destination or source in relays or destination in relays:
            raise ValueError("route endpoints and relays must be distinct")
        route = Route((source, *relays, destination), now + self.ttl_seconds)
        self._routes[(source, destination)] = route
        self._routes[(destination, source)] = route.reverse()
        return route

    def get(self, source: Endpoint, destination: Endpoint, now: float) -> Route | None:
        key = (source, destination)
        route = self._routes.get(key)
        if route is None or route.expires_at <= now:
            self._routes.pop(key, None)
            return None
        return route

    def mark_once(self, message_id: str, now: float) -> bool:
        self._seen = {
            key: expiry
            for key, expiry in self._seen.items()
            if expiry > now
        }
        if message_id in self._seen:
            return False
        self._seen[message_id] = now + self.ttl_seconds
        return True


@dataclass(frozen=True, slots=True)
class _AuthenticatedRoute:
    """A route whose node identities and WG keys came from one verified snapshot."""

    route: Route
    registry_id: str
    registry_version: int
    signed_digest: str
    node_ids: tuple[str, ...]
    _registry: TrustedRegistryStore = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if not isinstance(self._registry, TrustedRegistryStore):
            raise ValueError("authenticated route requires a trusted registry store")
        snapshot = self._registry.snapshot
        if (
            snapshot.registry_id != self.registry_id
            or snapshot.version != self.registry_version
            or snapshot.signed_digest != self.signed_digest
        ):
            raise ValueError("authenticated route does not match the current signed registry")
        self._registry.require_nodes(self.node_ids)

    def public_key_for(self, node_id: str) -> str:
        if node_id not in self.node_ids:
            raise ValueError("node is not part of the authenticated route")
        snapshot = self._registry.snapshot
        if snapshot.version != self.registry_version or snapshot.signed_digest != self.signed_digest:
            raise ValueError("authenticated route registry is no longer current")
        return self._registry.require_node(node_id).public_key


class AuthenticatedRoutePlanner:
    """Enforce registry provenance before the low-level cache can build a route."""

    def __init__(self, cache: RouteCache, registry: TrustedRegistryStore) -> None:
        self.cache = cache
        self.registry = registry

    def establish(
        self,
        *,
        source_node: str,
        source: Endpoint,
        relays: tuple[tuple[str, Endpoint], ...],
        destination_node: str,
        destination: Endpoint,
        now: float,
        presented_public_keys: Mapping[str, str] | None = None,
    ) -> _AuthenticatedRoute:
        node_ids = (source_node, *(node_id for node_id, _ in relays), destination_node)
        self.registry.require_nodes(node_ids)
        if presented_public_keys is not None:
            if set(presented_public_keys) != set(node_ids):
                raise RegistryKeyMismatchError(
                    "presented public-key directory does not exactly match route membership"
                )
            for node_id in node_ids:
                self.registry.assert_presented_key(node_id, presented_public_keys[node_id])

        # This is intentionally after every trust and presented-key check.
        route = self.cache.establish(
            source,
            tuple(endpoint for _, endpoint in relays),
            destination,
            now,
        )
        snapshot = self.registry.snapshot
        return _AuthenticatedRoute(
            route=route,
            registry_id=snapshot.registry_id,
            registry_version=snapshot.version,
            signed_digest=snapshot.signed_digest,
            node_ids=node_ids,
            _registry=self.registry,
        )
