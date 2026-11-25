"""Safe, in-memory reference model for a WireGuard handshake overlay."""

from .engine import HandshakeOverlayEngine
from .models import Endpoint, Event, OverlayEnvelope, Route
from .parser import WireGuardMessageType, WireGuardPacket, parse_packet
from .routing import AuthenticatedRoutePlanner, RouteCache
from .trust_registry import (
    OpenSshEd25519Verifier,
    RegistryFormatError,
    RegistryKeyMismatchError,
    RegistryPersistenceError,
    RegistryRecoveryError,
    RegistryRollbackError,
    RegistrySignatureError,
    TrustAnchor,
    TrustedRegistryStore,
    UnknownNodeError,
    UnknownSignerError,
    build_registry_payload,
    canonical_signed_bytes,
)

__all__ = [
    "AuthenticatedRoutePlanner",
    "Endpoint",
    "Event",
    "HandshakeOverlayEngine",
    "OpenSshEd25519Verifier",
    "OverlayEnvelope",
    "RegistryFormatError",
    "RegistryKeyMismatchError",
    "RegistryPersistenceError",
    "RegistryRecoveryError",
    "RegistryRollbackError",
    "RegistrySignatureError",
    "Route",
    "RouteCache",
    "TrustAnchor",
    "TrustedRegistryStore",
    "UnknownNodeError",
    "UnknownSignerError",
    "WireGuardMessageType",
    "WireGuardPacket",
    "build_registry_payload",
    "canonical_signed_bytes",
    "parse_packet",
]
