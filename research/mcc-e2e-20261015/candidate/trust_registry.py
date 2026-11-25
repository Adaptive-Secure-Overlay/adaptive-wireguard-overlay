"""Version 2 cascade registry: separate encryption and message-signing keys.

The pinned-root format and the atomic, monotonic store protocol are retained
from :mod:`trust_registry_v1`.  A v1 node entry is deliberately not accepted as
a v2 entry.  The root signer must be different from every node message signer.
"""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Iterable, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

try:  # Support both a package import and the daemon's flat module directory.
    from . import trust_registry_v1 as _v1
except ImportError:
    import trust_registry_v1 as _v1

ROOT_SCHEMA = _v1.ROOT_SCHEMA
REGISTRY_SCHEMA = "ipsec-ike-cascade-trust-registry/v2"
STATE_SCHEMA = _v1.STATE_SCHEMA
TrustRegistryError = _v1.TrustRegistryError
registry_digest = _v1.registry_digest
_canonical_json = _v1._canonical_json
MAX_REGISTRY_BYTES = 262_144
MAX_NODES = 256
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}\Z")


def verification_key_id(verification_hex: str) -> str:
    """SHA-256 of the raw 32-byte Ed25519 public key (lowercase hex)."""
    return hashlib.sha256(_key(verification_hex)).hexdigest()


def _key(value: Any) -> bytes:
    if not isinstance(value, str) or len(value) != 64:
        raise TrustRegistryError("invalid_node_key", "expected a canonical 32-byte public key")
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise TrustRegistryError("invalid_node_key", "invalid public-key encoding") from exc
    if len(raw) != 32 or value != raw.hex():
        raise TrustRegistryError("invalid_node_key", "noncanonical public-key encoding")
    return raw


@dataclass(frozen=True)
class VerifiedRegistry:
    version: int
    signer_key_id: str
    nodes: Mapping[str, Mapping[str, Any]]
    sha256: str
    recovered: bool = False

    def __post_init__(self):
        # Keep verified key material immutable after validation, including the
        # nested entries.  Caller mutation must never change a verified key.
        frozen = {name: MappingProxyType(dict(entry)) for name, entry in self.nodes.items()}
        object.__setattr__(self, "nodes", MappingProxyType(frozen))

    def status(self) -> dict[str, Any]:
        return {
            "authenticated": True,
            "schema": REGISTRY_SCHEMA,
            "version": self.version,
            "signer_key_id": self.signer_key_id,
            "nodes": sorted(self.nodes),
            "sha256": self.sha256,
            "recovered": self.recovered,
        }


def _read(path: Path, label: str) -> bytes:
    try:
        with path.open("rb") as stream:
            raw = stream.read(MAX_REGISTRY_BYTES + 1)
    except OSError as exc:
        raise TrustRegistryError("missing_document", f"cannot read {label}") from exc
    if len(raw) > MAX_REGISTRY_BYTES:
        raise TrustRegistryError("registry_too_large", "registry document exceeds its size limit")
    return raw


def verify_registry_bytes(
    raw: bytes,
    trust_root_path: os.PathLike[str] | str,
    required_nodes: Iterable[str],
    *,
    minimum_version: int = 1,
    exact_version: int | None = None,
    exact_sha256: str | None = None,
) -> VerifiedRegistry:
    if not isinstance(raw, bytes) or len(raw) > MAX_REGISTRY_BYTES:
        raise TrustRegistryError("registry_too_large", "invalid registry byte length")
    envelope = _v1._decode_json_bytes(raw, "trust registry v2")
    _v1._expect_fields(envelope, ("signed", "signatures"), "trust registry")
    signed = envelope["signed"]
    if not isinstance(signed, dict):
        raise TrustRegistryError("invalid_signed_body", "signed body must be an object")
    _v1._expect_fields(signed, ("schema", "version", "nodes"), "signed body")
    if signed["schema"] != REGISTRY_SCHEMA:
        raise TrustRegistryError("invalid_schema", "a version 2 registry is required")
    version = signed["version"]
    if type(version) is not int or version < 1:
        raise TrustRegistryError("invalid_version", "registry version must be an integer >= 1")
    if exact_version is not None and version != exact_version:
        code = "stale_version" if version < exact_version else "uncommitted_version"
        raise TrustRegistryError(code, "registry does not match the accepted version")
    if version < minimum_version:
        raise TrustRegistryError("stale_version", "registry is below the required version")
    nodes = signed["nodes"]
    if not isinstance(nodes, dict) or not 1 <= len(nodes) <= MAX_NODES:
        raise TrustRegistryError("invalid_nodes", "registry node count is out of bounds")
    required = set(required_nodes)
    if any(not isinstance(name, str) or not _NAME.fullmatch(name) for name in required):
        raise TrustRegistryError("invalid_node", "invalid required node name")
    if required - nodes.keys():
        raise TrustRegistryError("missing_node", "registry lacks a required node")
    if nodes.keys() - required:
        raise TrustRegistryError("unknown_node", "registry contains an unexpected node")
    normalized: dict[str, dict[str, Any]] = {}
    encryption_keys, signing_keys = set(), set()
    for name, entry in nodes.items():
        if not isinstance(name, str) or not _NAME.fullmatch(name) or not isinstance(entry, dict):
            raise TrustRegistryError("invalid_node", "invalid node entry")
        _v1._expect_fields(entry, ("encryption", "verification", "key_id", "revoked"), "node")
        encryption = _key(entry["encryption"])
        verification = _key(entry["verification"])
        if entry["key_id"] != hashlib.sha256(verification).hexdigest():
            raise TrustRegistryError("invalid_key_id", "message key identifier does not match its public key")
        if type(entry["revoked"]) is not bool:
            raise TrustRegistryError("invalid_revocation", "revoked must be a boolean")
        if encryption in encryption_keys or verification in signing_keys or encryption == verification:
            raise TrustRegistryError("shared_node_key", "node encryption and signing keys must be individual")
        encryption_keys.add(encryption)
        signing_keys.add(verification)
        normalized[name] = dict(entry)
    signatures = envelope["signatures"]
    if not isinstance(signatures, list) or len(signatures) != 1 or not isinstance(signatures[0], dict):
        raise TrustRegistryError("missing_signature", "exactly one registry signature is required")
    signature = signatures[0]
    _v1._expect_fields(signature, ("key_id", "algorithm", "sig"), "signature")
    if signature["algorithm"] != "Ed25519":
        raise TrustRegistryError("unsupported_algorithm", "registry signature is not Ed25519")
    trust_keys = _v1._load_trust_root(Path(trust_root_path))
    if any(key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw) in signing_keys
           for key in trust_keys.values()):
        raise TrustRegistryError("root_key_reused", "registry root must not be a node message key")
    key_id = signature["key_id"]
    if not isinstance(key_id, str) or key_id not in trust_keys:
        raise TrustRegistryError("unknown_signer", "registry signer is not pinned")
    sig = _v1._b64url_decode(signature["sig"], "registry signature")
    if len(sig) != 64:
        raise TrustRegistryError("invalid_signature", "invalid Ed25519 signature length")
    try:
        trust_keys[key_id].verify(sig, _v1._canonical_json(signed))
    except InvalidSignature as exc:
        raise TrustRegistryError("bad_signature", "registry signature verification failed") from exc
    digest = registry_digest(raw)
    if exact_sha256 is not None and digest != exact_sha256:
        raise TrustRegistryError("same_version_replacement", "registry differs from the accepted document")
    return VerifiedRegistry(version, key_id, normalized, digest)


class TrustRegistryStore(_v1.TrustRegistryStore):
    """Versioned extension retaining v1's state, backup and commit ordering.

    The v1 implementation hard-codes its verifier in recovery/update methods;
    these overrides substitute the v2 verifier without changing that protocol.
    """

    def _verify_live(self, required_nodes: Iterable[str], state):
        raw = _read(self.registry_path, "live trust registry")
        constraints = {} if state is None else {"exact_version": state[0], "exact_sha256": state[1]}
        return verify_registry_bytes(raw, self.trust_root_path, required_nodes, **constraints), raw

    def load(self, required_nodes: Iterable[str]) -> VerifiedRegistry:
        required = tuple(required_nodes)
        state = _v1._read_state(self.state_path)
        try:
            verified, raw = self._verify_live(required, state)
        except TrustRegistryError as live_error:
            if state is None or not self.backup_path.exists():
                raise live_error
            raw = _read(self.backup_path, "last-valid trust registry")
            backup = verify_registry_bytes(
                raw, self.trust_root_path, required,
                exact_version=state[0], exact_sha256=state[1],
            )
            _v1._atomic_write(self.registry_path, raw)
            return VerifiedRegistry(backup.version, backup.signer_key_id, backup.nodes, backup.sha256, True)
        if state is None:
            _v1._atomic_write(self.state_path, _v1._state_bytes(verified))
        _v1._atomic_write(self.backup_path, raw)
        return verified

    def install_update(self, candidate_path: os.PathLike[str] | str, required_nodes: Iterable[str]):
        required = tuple(required_nodes)
        current = None
        if self.registry_path.exists() or self.state_path.exists() or self.backup_path.exists():
            current = self.load(required)
        raw = _read(Path(candidate_path), "candidate trust registry")
        candidate = verify_registry_bytes(
            raw, self.trust_root_path, required,
            minimum_version=1 if current is None else current.version + 1,
        )
        _v1._atomic_write(self.registry_path, raw)
        _v1._atomic_write(self.state_path, _v1._state_bytes(candidate))
        _v1._atomic_write(self.backup_path, raw)
        return candidate


def load_verified_registry_from_environment(required_nodes: Iterable[str]) -> VerifiedRegistry:
    if any(os.environ.get(name, "").strip() for name in (
        "IKE_CASCADE_PUBLIC_KEYS_JSON", "IKE_CASCADE_PUBLIC_KEYS_FILE",
    )):
        raise TrustRegistryError("unsigned_registry_rejected", "unsigned public keys are not accepted")
    registry = os.environ.get("IKE_CASCADE_TRUST_REGISTRY_FILE", "").strip()
    root = os.environ.get("IKE_CASCADE_TRUST_ROOT_FILE", "").strip()
    if not registry or not root:
        raise TrustRegistryError("missing_trust_configuration", "signed registry and pinned root files are required")
    state = os.environ.get("IKE_CASCADE_TRUST_STATE_FILE", "").strip() or registry + ".state.json"
    backup = os.environ.get("IKE_CASCADE_TRUST_BACKUP_FILE", "").strip() or registry + ".last-valid.json"
    return TrustRegistryStore(registry, root, state, backup).load(required_nodes)
