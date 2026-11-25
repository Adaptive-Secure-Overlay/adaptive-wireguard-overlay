# -*- coding: utf-8 -*-
"""Authenticated, rollback-resistant public-key registry for the IPsec/IKE cascade.

This is deliberately a small project-specific envelope, not a TUF implementation.
The pinned trust root authenticates a single Ed25519 signer.  A separately stored
accepted version and digest prevent rollback or same-version replacement.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


ROOT_SCHEMA = "ipsec-ike-cascade-trust-root/v1"
REGISTRY_SCHEMA = "ipsec-ike-cascade-trust-registry/v1"
STATE_SCHEMA = "ipsec-ike-cascade-trust-state/v1"


class TrustRegistryError(RuntimeError):
    """Fail-closed registry validation or update error with a stable code."""

    def __init__(self, code: str, message: str):
        self.code = str(code)
        super().__init__(f"{self.code}: {message}")


def _reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise TrustRegistryError("duplicate_json_key", f"duplicate key {key!r}")
        result[key] = value
    return result


def _decode_json_bytes(raw: bytes, source: str) -> Dict[str, Any]:
    try:
        text = raw.decode("utf-8")
        value = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except TrustRegistryError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TrustRegistryError("corrupt_json", f"cannot parse {source}") from exc
    if not isinstance(value, dict):
        raise TrustRegistryError("invalid_document", f"{source} must be a JSON object")
    return value


def _read_document(path: Path, label: str) -> Tuple[Dict[str, Any], bytes]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise TrustRegistryError("missing_document", f"cannot read {label}: {path}") from exc
    return _decode_json_bytes(raw, label), raw


def _expect_fields(value: Mapping[str, Any], expected: Iterable[str], label: str) -> None:
    actual = set(value)
    wanted = set(expected)
    if actual != wanted:
        missing = sorted(wanted - actual)
        unknown = sorted(actual - wanted)
        raise TrustRegistryError(
            "invalid_fields",
            f"{label} fields mismatch; missing={missing}, unknown={unknown}",
        )


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _b64url_decode(value: Any, label: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise TrustRegistryError("invalid_base64", f"{label} must be non-empty base64url")
    try:
        padding = "=" * ((4 - len(value) % 4) % 4)
        raw = base64.b64decode(value + padding, altchars=b"-_", validate=True)
    except (ValueError, TypeError) as exc:
        raise TrustRegistryError("invalid_base64", f"{label} is not valid base64url") from exc
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != value.rstrip("="):
        raise TrustRegistryError("invalid_base64", f"{label} is not canonical base64url")
    return raw


def registry_digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class VerifiedRegistry:
    version: int
    signer_key_id: str
    nodes: Dict[str, str]
    sha256: str
    recovered: bool = False

    def status(self) -> Dict[str, Any]:
        return {
            "authenticated": True,
            "schema": REGISTRY_SCHEMA,
            "version": self.version,
            "signer_key_id": self.signer_key_id,
            "nodes": sorted(self.nodes),
            "sha256": self.sha256,
            "recovered": self.recovered,
        }


def _load_trust_root(path: Path) -> Dict[str, Ed25519PublicKey]:
    root, _ = _read_document(path, "trust root")
    _expect_fields(root, ("schema", "signers"), "trust root")
    if root["schema"] != ROOT_SCHEMA:
        raise TrustRegistryError("invalid_schema", "unexpected trust-root schema")
    signers = root["signers"]
    if not isinstance(signers, dict) or not signers:
        raise TrustRegistryError("invalid_trust_root", "trust root has no signers")
    parsed: Dict[str, Ed25519PublicKey] = {}
    for key_id, record in signers.items():
        if not isinstance(key_id, str) or not key_id:
            raise TrustRegistryError("invalid_signer", "signer key id must be non-empty")
        if not isinstance(record, dict):
            raise TrustRegistryError("invalid_signer", f"signer {key_id} is not an object")
        _expect_fields(record, ("algorithm", "public_key"), f"signer {key_id}")
        if record["algorithm"] != "Ed25519":
            raise TrustRegistryError("unsupported_algorithm", f"signer {key_id} is not Ed25519")
        raw_key = _b64url_decode(record["public_key"], f"signer {key_id} public key")
        if len(raw_key) != 32:
            raise TrustRegistryError("invalid_signer", f"signer {key_id} key must be 32 bytes")
        parsed[key_id] = Ed25519PublicKey.from_public_bytes(raw_key)
    return parsed


def verify_registry_bytes(
    raw: bytes,
    trust_root_path: os.PathLike[str] | str,
    required_nodes: Iterable[str],
    *,
    minimum_version: int = 1,
    exact_version: Optional[int] = None,
    exact_sha256: Optional[str] = None,
) -> VerifiedRegistry:
    envelope = _decode_json_bytes(raw, "trust registry")
    _expect_fields(envelope, ("signed", "signatures"), "trust registry")
    signed = envelope["signed"]
    signatures = envelope["signatures"]
    if not isinstance(signed, dict):
        raise TrustRegistryError("invalid_signed_body", "signed body must be an object")
    _expect_fields(signed, ("schema", "version", "nodes"), "signed body")
    if signed["schema"] != REGISTRY_SCHEMA:
        raise TrustRegistryError("invalid_schema", "unexpected registry schema")
    version = signed["version"]
    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        raise TrustRegistryError("invalid_version", "registry version must be an integer >= 1")
    if exact_version is not None and version != exact_version:
        code = "stale_version" if version < exact_version else "uncommitted_version"
        raise TrustRegistryError(code, f"registry version {version} != accepted {exact_version}")
    if version < int(minimum_version):
        raise TrustRegistryError(
            "stale_version",
            f"registry version {version} is below required {int(minimum_version)}",
        )

    nodes = signed["nodes"]
    if not isinstance(nodes, dict):
        raise TrustRegistryError("invalid_nodes", "nodes must be an object")
    expected = {str(node) for node in required_nodes}
    actual = set(nodes)
    missing = sorted(expected - actual)
    unknown = sorted(actual - expected)
    if missing:
        raise TrustRegistryError("missing_node", f"registry is missing nodes: {', '.join(missing)}")
    if unknown:
        raise TrustRegistryError("unknown_node", f"registry has unknown nodes: {', '.join(unknown)}")
    normalized_nodes: Dict[str, str] = {}
    for name, value in nodes.items():
        if not isinstance(name, str) or not name:
            raise TrustRegistryError("invalid_node", "node name must be non-empty")
        if not isinstance(value, str):
            raise TrustRegistryError("invalid_node_key", f"public key for {name} must be hex")
        try:
            raw_key = bytes.fromhex(value)
        except ValueError as exc:
            raise TrustRegistryError("invalid_node_key", f"public key for {name} is not hex") from exc
        if len(raw_key) != 32 or value != raw_key.hex():
            raise TrustRegistryError(
                "invalid_node_key",
                f"public key for {name} must be canonical 32-byte lowercase hex",
            )
        normalized_nodes[name] = value

    if not isinstance(signatures, list) or len(signatures) != 1:
        raise TrustRegistryError("missing_signature", "exactly one registry signature is required")
    signature = signatures[0]
    if not isinstance(signature, dict):
        raise TrustRegistryError("invalid_signature", "signature entry must be an object")
    _expect_fields(signature, ("key_id", "algorithm", "sig"), "signature")
    if signature["algorithm"] != "Ed25519":
        raise TrustRegistryError("unsupported_algorithm", "registry signature is not Ed25519")
    key_id = signature["key_id"]
    trust_keys = _load_trust_root(Path(trust_root_path))
    if not isinstance(key_id, str) or key_id not in trust_keys:
        raise TrustRegistryError("unknown_signer", f"signer {key_id!r} is not trusted")
    sig_bytes = _b64url_decode(signature["sig"], "registry signature")
    if len(sig_bytes) != 64:
        raise TrustRegistryError("invalid_signature", "Ed25519 signature must be 64 bytes")
    try:
        trust_keys[key_id].verify(sig_bytes, _canonical_json(signed))
    except InvalidSignature as exc:
        raise TrustRegistryError("bad_signature", "registry signature verification failed") from exc

    digest = registry_digest(raw)
    if exact_sha256 is not None and digest != exact_sha256:
        raise TrustRegistryError(
            "same_version_replacement",
            "registry digest differs from the accepted document",
        )
    return VerifiedRegistry(version, key_id, normalized_nodes, digest)


def _atomic_write(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    temp_path = Path(temp_name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_path, path)
    finally:
        try:
            temp_path.unlink()
        except FileNotFoundError:
            pass


def _state_bytes(registry: VerifiedRegistry) -> bytes:
    value = {
        "schema": STATE_SCHEMA,
        "accepted_version": registry.version,
        "accepted_sha256": registry.sha256,
    }
    return _canonical_json(value) + b"\n"


def _read_state(path: Path) -> Optional[Tuple[int, str]]:
    if not path.exists():
        return None
    state, _ = _read_document(path, "trust state")
    _expect_fields(state, ("schema", "accepted_version", "accepted_sha256"), "trust state")
    if state["schema"] != STATE_SCHEMA:
        raise TrustRegistryError("invalid_schema", "unexpected trust-state schema")
    version = state["accepted_version"]
    digest = state["accepted_sha256"]
    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        raise TrustRegistryError("invalid_state", "accepted version must be an integer >= 1")
    if not isinstance(digest, str) or len(digest) != 64:
        raise TrustRegistryError("invalid_state", "accepted digest must be SHA-256 hex")
    try:
        bytes.fromhex(digest)
    except ValueError as exc:
        raise TrustRegistryError("invalid_state", "accepted digest must be SHA-256 hex") from exc
    return version, digest.lower()


class TrustRegistryStore:
    """Load, atomically update, and recover a signed cascade registry."""

    def __init__(
        self,
        registry_path: os.PathLike[str] | str,
        trust_root_path: os.PathLike[str] | str,
        state_path: os.PathLike[str] | str,
        backup_path: os.PathLike[str] | str,
    ):
        self.registry_path = Path(registry_path)
        self.trust_root_path = Path(trust_root_path)
        self.state_path = Path(state_path)
        self.backup_path = Path(backup_path)

    def _verify_live(self, required_nodes: Iterable[str], state) -> Tuple[VerifiedRegistry, bytes]:
        _, raw = _read_document(self.registry_path, "live trust registry")
        if state is None:
            verified = verify_registry_bytes(raw, self.trust_root_path, required_nodes)
        else:
            version, digest = state
            verified = verify_registry_bytes(
                raw,
                self.trust_root_path,
                required_nodes,
                exact_version=version,
                exact_sha256=digest,
            )
        return verified, raw

    def load(self, required_nodes: Iterable[str]) -> VerifiedRegistry:
        required = tuple(required_nodes)
        state = _read_state(self.state_path)
        try:
            verified, raw = self._verify_live(required, state)
        except TrustRegistryError as live_error:
            if state is None or not self.backup_path.exists():
                raise live_error
            _, backup_raw = _read_document(self.backup_path, "last-valid trust registry")
            version, digest = state
            backup = verify_registry_bytes(
                backup_raw,
                self.trust_root_path,
                required,
                exact_version=version,
                exact_sha256=digest,
            )
            _atomic_write(self.registry_path, backup_raw)
            return VerifiedRegistry(
                backup.version,
                backup.signer_key_id,
                backup.nodes,
                backup.sha256,
                recovered=True,
            )

        if state is None:
            _atomic_write(self.state_path, _state_bytes(verified))
        _atomic_write(self.backup_path, raw)
        return verified

    def install_update(
        self,
        candidate_path: os.PathLike[str] | str,
        required_nodes: Iterable[str],
    ) -> VerifiedRegistry:
        required = tuple(required_nodes)
        current: Optional[VerifiedRegistry]
        if self.registry_path.exists() or self.state_path.exists() or self.backup_path.exists():
            current = self.load(required)
        else:
            current = None
        _, candidate_raw = _read_document(Path(candidate_path), "candidate trust registry")
        minimum_version = 1 if current is None else current.version + 1
        candidate = verify_registry_bytes(
            candidate_raw,
            self.trust_root_path,
            required,
            minimum_version=minimum_version,
        )

        # Commit order is intentional.  If interrupted before state replacement,
        # load() restores the old backup.  If interrupted after state replacement,
        # the new live file is authoritative and load() refreshes the backup.
        _atomic_write(self.registry_path, candidate_raw)
        _atomic_write(self.state_path, _state_bytes(candidate))
        _atomic_write(self.backup_path, candidate_raw)
        return candidate


def load_verified_registry_from_environment(required_nodes: Iterable[str]):
    unsigned_json = os.environ.get("IKE_CASCADE_PUBLIC_KEYS_JSON", "").strip()
    unsigned_file = os.environ.get("IKE_CASCADE_PUBLIC_KEYS_FILE", "").strip()
    if unsigned_json or unsigned_file:
        raise TrustRegistryError(
            "unsigned_registry_rejected",
            "unsigned IKE_CASCADE_PUBLIC_KEYS_JSON/FILE is not accepted",
        )
    registry = os.environ.get("IKE_CASCADE_TRUST_REGISTRY_FILE", "").strip()
    trust_root = os.environ.get("IKE_CASCADE_TRUST_ROOT_FILE", "").strip()
    if not registry or not trust_root:
        raise TrustRegistryError(
            "missing_trust_configuration",
            "IKE_CASCADE_TRUST_REGISTRY_FILE and IKE_CASCADE_TRUST_ROOT_FILE are required",
        )
    state = os.environ.get("IKE_CASCADE_TRUST_STATE_FILE", "").strip()
    backup = os.environ.get("IKE_CASCADE_TRUST_BACKUP_FILE", "").strip()
    if not state:
        state = registry + ".state.json"
    if not backup:
        backup = registry + ".last-valid.json"
    verified = TrustRegistryStore(registry, trust_root, state, backup).load(required_nodes)
    return dict(verified.nodes), verified.status()
