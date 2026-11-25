from __future__ import annotations

import base64
import binascii
import json
import os
import re
import shutil
import struct
import subprocess
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path
from secrets import compare_digest
from typing import Iterator, Mapping


SSHSIG_NAMESPACE = "wg-node-registry-v1"
SIGNATURE_ALGORITHM = "sshsig-ed25519"
REGISTRY_SCHEMA_VERSION = 1
_MAX_DOCUMENT_BYTES = 1_048_576
_MAX_NODES = 4096
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_BASE64_LINE = re.compile(r"[A-Za-z0-9+/]+={0,2}\Z")
_VERIFIED_BINDING_PROOF = object()


class TrustRegistryError(ValueError):
    """Base class for fail-closed trust-registry errors."""


class RegistryFormatError(TrustRegistryError):
    pass


class RegistryDependencyError(TrustRegistryError):
    pass


class RegistrySignatureError(TrustRegistryError):
    pass


class UnknownSignerError(RegistrySignatureError):
    pass


class RegistryRollbackError(TrustRegistryError):
    pass


class RegistryPersistenceError(TrustRegistryError):
    pass


class RegistryRecoveryError(TrustRegistryError):
    pass


class UnknownNodeError(TrustRegistryError):
    pass


class RegistryKeyMismatchError(TrustRegistryError):
    pass


@dataclass(frozen=True, slots=True)
class TrustAnchor:
    """Pinned out-of-band OpenSSH Ed25519 verification key."""

    key_id: str
    public_key: str

    def __post_init__(self) -> None:
        if not _valid_identifier(self.key_id):
            raise RegistryFormatError("invalid trust-anchor key id")
        object.__setattr__(self, "public_key", _normalize_ssh_ed25519_public_key(self.public_key))

    @property
    def fingerprint(self) -> str:
        encoded = self.public_key.split()[1]
        blob = base64.b64decode(encoded, validate=True)
        return "SHA256:" + base64.b64encode(sha256(blob).digest()).decode("ascii").rstrip("=")


@dataclass(frozen=True, slots=True)
class _TrustedNode:
    node_id: str
    public_key: str = field(repr=False)
    _proof: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._proof is not _VERIFIED_BINDING_PROOF:
            raise RegistrySignatureError("trusted node bindings can only come from a verified registry")

    @property
    def fingerprint(self) -> str:
        raw = base64.b64decode(self.public_key, validate=True)
        return sha256(raw).hexdigest()[:16]


@dataclass(frozen=True, slots=True)
class _RegistrySnapshot:
    registry_id: str
    version: int
    signer_id: str
    signed_digest: str
    nodes: tuple[_TrustedNode, ...]

    def require_node(self, node_id: str) -> _TrustedNode:
        if not _valid_identifier(node_id):
            raise UnknownNodeError("invalid node id")
        for node in self.nodes:
            if node.node_id == node_id:
                return node
        raise UnknownNodeError(f"unknown registry node: {node_id}")


class OpenSshEd25519Verifier:
    """Verify detached SSHSIG signatures without implementing cryptography locally."""

    def __init__(self, executable: str = "ssh-keygen", timeout_seconds: float = 10.0) -> None:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        resolved = shutil.which(executable)
        if resolved is None:
            raise RegistryDependencyError("OpenSSH ssh-keygen with -Y verify support is required")
        self._executable = resolved
        self._timeout_seconds = timeout_seconds

    def verify(self, anchor: TrustAnchor, message: bytes, signature: str) -> None:
        normalized_signature = _normalize_signature(signature)
        creation_flags = 0
        if os.name == "nt":
            creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        environment = os.environ.copy()
        environment["SSH_ASKPASS_REQUIRE"] = "never"

        with tempfile.TemporaryDirectory(prefix="wg-registry-verify-") as temp_name:
            temp_dir = Path(temp_name)
            allowed_signers = temp_dir / "allowed_signers"
            signature_file = temp_dir / "registry.sshsig"
            allowed_signers.write_text(
                f"wg-registry-root {anchor.public_key}\n",
                encoding="ascii",
                newline="\n",
            )
            signature_file.write_text(normalized_signature, encoding="ascii", newline="\n")
            try:
                completed = subprocess.run(
                    [
                        self._executable,
                        "-Y",
                        "verify",
                        "-f",
                        str(allowed_signers),
                        "-I",
                        "wg-registry-root",
                        "-n",
                        SSHSIG_NAMESPACE,
                        "-s",
                        str(signature_file),
                    ],
                    input=message,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=self._timeout_seconds,
                    check=False,
                    creationflags=creation_flags,
                    env=environment,
                )
            except (OSError, subprocess.SubprocessError) as exc:
                raise RegistryDependencyError("OpenSSH signature verifier could not run") from exc
        if completed.returncode != 0:
            raise RegistrySignatureError("registry signature verification failed")


@dataclass(frozen=True, slots=True)
class _VerifiedRegistry:
    snapshot: _RegistrySnapshot
    serialized: bytes = field(repr=False)


def build_registry_payload(
    *,
    registry_id: str,
    version: int,
    nodes: Mapping[str, str],
) -> dict[str, object]:
    """Build the only signed representation accepted by the verifier."""

    normalized_nodes = _validate_nodes(
        {
            node_id: {"public_key": public_key}
            for node_id, public_key in nodes.items()
        }
    )
    if not _valid_identifier(registry_id):
        raise RegistryFormatError("invalid registry id")
    if type(version) is not int or not 1 <= version <= 2**63 - 1:
        raise RegistryFormatError("registry version must be a positive 63-bit integer")
    return {
        "schema_version": REGISTRY_SCHEMA_VERSION,
        "registry_id": registry_id,
        "version": version,
        "nodes": normalized_nodes,
    }


def canonical_signed_bytes(signed: Mapping[str, object]) -> bytes:
    normalized = _validate_signed_object(signed, expected_registry_id=None)
    return json.dumps(
        normalized,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


class TrustedRegistryStore:
    """Verified registry with monotonic updates and two recoverable atomic copies."""

    def __init__(
        self,
        directory: str | os.PathLike[str],
        *,
        trust_anchor: TrustAnchor,
        registry_id: str,
    ) -> None:
        if not _valid_identifier(registry_id):
            raise RegistryFormatError("invalid expected registry id")
        self.directory = Path(directory)
        self.active_path = self.directory / "registry.active.json"
        self.recovery_path = self.directory / "registry.last-valid.json"
        self.lock_path = self.directory / ".registry.lock"
        self.trust_anchor = trust_anchor
        self.registry_id = registry_id
        self._verifier = OpenSshEd25519Verifier()
        self._snapshot: _RegistrySnapshot | None = None

    @property
    def snapshot(self) -> _RegistrySnapshot:
        if self._snapshot is None:
            raise RegistryRecoveryError("trusted registry is not loaded")
        return self._snapshot

    def load_or_recover(self) -> _RegistrySnapshot:
        self.directory.mkdir(parents=True, exist_ok=True)
        with _exclusive_file_lock(self.lock_path):
            current = self._load_best_locked(allow_empty=False, heal=True)
        assert current is not None
        return current.snapshot

    def apply_update(self, document: bytes | str) -> _RegistrySnapshot:
        candidate = self._verify_document(document)
        self.directory.mkdir(parents=True, exist_ok=True)
        with _exclusive_file_lock(self.lock_path):
            current = self._load_best_locked(allow_empty=True, heal=True)
            if current is not None and candidate.snapshot.version <= current.snapshot.version:
                raise RegistryRollbackError(
                    f"registry version {candidate.snapshot.version} is not newer than "
                    f"{current.snapshot.version}"
                )

            try:
                self._atomic_write(self.active_path, candidate.serialized)
            except OSError as exc:
                raise RegistryPersistenceError("registry update was not committed") from exc

            self._snapshot = candidate.snapshot
            try:
                self._atomic_write(self.recovery_path, candidate.serialized)
            except OSError as exc:
                raise RegistryPersistenceError(
                    "registry was committed but the recovery copy could not be refreshed"
                ) from exc
        return candidate.snapshot

    def require_node(self, node_id: str) -> _TrustedNode:
        return self.snapshot.require_node(node_id)

    def require_nodes(self, node_ids: tuple[str, ...]) -> tuple[_TrustedNode, ...]:
        if len(set(node_ids)) != len(node_ids):
            raise UnknownNodeError("route node ids must be distinct")
        return tuple(self.require_node(node_id) for node_id in node_ids)

    def assert_presented_key(self, node_id: str, public_key: str) -> _TrustedNode:
        trusted = self.require_node(node_id)
        try:
            normalized = _normalize_wireguard_public_key(public_key)
        except RegistryFormatError as exc:
            raise RegistryKeyMismatchError(f"invalid presented key for node: {node_id}") from exc
        if not compare_digest(trusted.public_key, normalized):
            raise RegistryKeyMismatchError(f"public key does not match signed registry for node: {node_id}")
        return trusted

    def _verify_document(self, document: bytes | str) -> _VerifiedRegistry:
        raw = document.encode("utf-8") if isinstance(document, str) else document
        if not isinstance(raw, bytes):
            raise RegistryFormatError("registry document must be UTF-8 bytes or text")
        if not raw or len(raw) > _MAX_DOCUMENT_BYTES:
            raise RegistryFormatError("registry document size is invalid")
        parsed = _parse_json(raw)
        if set(parsed) != {"signed", "signature"}:
            raise RegistryFormatError("registry envelope fields are invalid")
        if not isinstance(parsed["signed"], dict) or not isinstance(parsed["signature"], dict):
            raise RegistryFormatError("registry envelope objects are invalid")

        signed = _validate_signed_object(parsed["signed"], self.registry_id)
        signature = _validate_signature_object(parsed["signature"], self.trust_anchor)
        canonical = canonical_signed_bytes(signed)
        self._verifier.verify(self.trust_anchor, canonical, signature["value"])

        nodes = tuple(
            _TrustedNode(node_id, entry["public_key"], _VERIFIED_BINDING_PROOF)
            for node_id, entry in signed["nodes"].items()
        )
        snapshot = _RegistrySnapshot(
            registry_id=signed["registry_id"],
            version=signed["version"],
            signer_id=signature["key_id"],
            signed_digest=sha256(canonical).hexdigest(),
            nodes=nodes,
        )
        envelope = {"signed": signed, "signature": signature}
        serialized = (
            json.dumps(
                envelope,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        )
        return _VerifiedRegistry(snapshot, serialized)

    def _load_best_locked(self, *, allow_empty: bool, heal: bool) -> _VerifiedRegistry | None:
        found_any = False
        valid: list[tuple[Path, _VerifiedRegistry]] = []
        for path in (self.active_path, self.recovery_path):
            if not path.exists():
                continue
            found_any = True
            try:
                valid.append((path, self._verify_document(_read_registry_file(path))))
            except TrustRegistryError:
                continue

        if not valid:
            if allow_empty and not found_any:
                self._snapshot = None
                return None
            raise RegistryRecoveryError("no valid signed registry copy is available")

        highest_version = max(item.snapshot.version for _, item in valid)
        highest = [item for _, item in valid if item.snapshot.version == highest_version]
        if len({item.snapshot.signed_digest for item in highest}) != 1:
            raise RegistryRecoveryError("conflicting signed registries have the same version")
        best = highest[0]

        if heal:
            for path in (self.active_path, self.recovery_path):
                current = next((item for item_path, item in valid if item_path == path), None)
                if current is None or current.snapshot.signed_digest != best.snapshot.signed_digest:
                    try:
                        self._atomic_write(path, best.serialized)
                    except OSError as exc:
                        raise RegistryPersistenceError("failed to restore the last valid registry") from exc
        self._snapshot = best.snapshot
        return best

    def _atomic_write(self, path: Path, data: bytes) -> None:
        if path.exists() and path.is_symlink():
            raise OSError("registry targets must not be symbolic links")
        file_descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.",
            suffix=".tmp",
            dir=self.directory,
        )
        temporary_path = Path(temporary_name)
        try:
            with os.fdopen(file_descriptor, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary_path, path)
            _fsync_directory(self.directory)
        finally:
            temporary_path.unlink(missing_ok=True)


def _parse_json(raw: bytes) -> dict[str, object]:
    try:
        text = raw.decode("utf-8")
        parsed = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except RegistryFormatError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RegistryFormatError("registry document is not strict UTF-8 JSON") from exc
    if not isinstance(parsed, dict):
        raise RegistryFormatError("registry document must be a JSON object")
    return parsed


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise RegistryFormatError(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> object:
    raise RegistryFormatError(f"non-finite JSON value is forbidden: {value}")


def _validate_signed_object(
    signed: Mapping[str, object],
    expected_registry_id: str | None,
) -> dict[str, object]:
    if set(signed) != {"schema_version", "registry_id", "version", "nodes"}:
        raise RegistryFormatError("signed registry fields are invalid")
    if signed["schema_version"] != REGISTRY_SCHEMA_VERSION or type(signed["schema_version"]) is not int:
        raise RegistryFormatError("unsupported registry schema version")
    registry_id = signed["registry_id"]
    if not isinstance(registry_id, str) or not _valid_identifier(registry_id):
        raise RegistryFormatError("invalid registry id")
    if expected_registry_id is not None and registry_id != expected_registry_id:
        raise RegistryFormatError("registry id does not match the pinned domain")
    version = signed["version"]
    if type(version) is not int or not 1 <= version <= 2**63 - 1:
        raise RegistryFormatError("registry version must be a positive 63-bit integer")
    if not isinstance(signed["nodes"], dict):
        raise RegistryFormatError("registry nodes must be an object")
    nodes = _validate_nodes(signed["nodes"])
    return {
        "schema_version": REGISTRY_SCHEMA_VERSION,
        "registry_id": registry_id,
        "version": version,
        "nodes": nodes,
    }


def _validate_nodes(nodes: Mapping[str, object]) -> dict[str, dict[str, str]]:
    if not 1 <= len(nodes) <= _MAX_NODES:
        raise RegistryFormatError("registry node count is invalid")
    normalized: dict[str, dict[str, str]] = {}
    seen_keys: set[str] = set()
    for node_id in sorted(nodes):
        if not isinstance(node_id, str) or not _valid_identifier(node_id):
            raise RegistryFormatError("invalid registry node id")
        entry = nodes[node_id]
        if isinstance(entry, Mapping) and set(entry) == {"public_key"}:
            public_key = entry["public_key"]
        else:
            raise RegistryFormatError(f"invalid registry entry for node: {node_id}")
        if not isinstance(public_key, str):
            raise RegistryFormatError(f"invalid public key for node: {node_id}")
        normalized_key = _normalize_wireguard_public_key(public_key)
        if normalized_key in seen_keys:
            raise RegistryFormatError("WireGuard public keys must be unique per node")
        seen_keys.add(normalized_key)
        normalized[node_id] = {"public_key": normalized_key}
    return normalized


def _validate_signature_object(
    signature: Mapping[str, object],
    anchor: TrustAnchor,
) -> dict[str, str]:
    if set(signature) != {"algorithm", "key_id", "value"}:
        raise RegistryFormatError("signature fields are invalid")
    if signature["algorithm"] != SIGNATURE_ALGORITHM:
        raise RegistrySignatureError("unsupported registry signature algorithm")
    key_id = signature["key_id"]
    if not isinstance(key_id, str) or not _valid_identifier(key_id):
        raise RegistryFormatError("invalid signature key id")
    if key_id != anchor.key_id:
        raise UnknownSignerError("registry signer is not the pinned trust root")
    value = signature["value"]
    if not isinstance(value, str):
        raise RegistryFormatError("registry signature must be text")
    return {
        "algorithm": SIGNATURE_ALGORITHM,
        "key_id": key_id,
        "value": _normalize_signature(value),
    }


def _normalize_signature(value: str) -> str:
    try:
        value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise RegistryFormatError("registry signature must be ASCII") from exc
    normalized = value.replace("\r\n", "\n")
    if "\r" in normalized or len(normalized) > 16384:
        raise RegistryFormatError("registry signature armor is invalid")
    lines = normalized.rstrip("\n").split("\n")
    if len(lines) < 3:
        raise RegistryFormatError("registry signature armor is incomplete")
    if lines[0] != "-----BEGIN SSH SIGNATURE-----" or lines[-1] != "-----END SSH SIGNATURE-----":
        raise RegistryFormatError("registry signature armor is invalid")
    if any(not line or len(line) > 128 or _BASE64_LINE.fullmatch(line) is None for line in lines[1:-1]):
        raise RegistryFormatError("registry signature body is invalid")
    return "\n".join(lines) + "\n"


def _normalize_wireguard_public_key(value: str) -> str:
    if value != value.strip() or any(char.isspace() for char in value):
        raise RegistryFormatError("WireGuard public key must be canonical base64")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise RegistryFormatError("WireGuard public key is not valid base64") from exc
    if len(raw) != 32 or not any(raw):
        raise RegistryFormatError("WireGuard public key must contain 32 non-zero bytes")
    normalized = base64.b64encode(raw).decode("ascii")
    if value != normalized:
        raise RegistryFormatError("WireGuard public key is not canonical base64")
    return normalized


def _normalize_ssh_ed25519_public_key(value: str) -> str:
    if not isinstance(value, str):
        raise RegistryFormatError("trust-anchor public key must be text")
    parts = value.strip().split()
    if len(parts) < 2 or parts[0] != "ssh-ed25519":
        raise RegistryFormatError("trust anchor must be an OpenSSH Ed25519 public key")
    try:
        blob = base64.b64decode(parts[1], validate=True)
    except (ValueError, binascii.Error) as exc:
        raise RegistryFormatError("trust-anchor public key is invalid") from exc
    try:
        key_type, offset = _read_ssh_string(blob, 0)
        key_bytes, offset = _read_ssh_string(blob, offset)
    except ValueError as exc:
        raise RegistryFormatError("trust-anchor public key is invalid") from exc
    if key_type != b"ssh-ed25519" or len(key_bytes) != 32 or offset != len(blob):
        raise RegistryFormatError("trust anchor is not a canonical Ed25519 key")
    return f"ssh-ed25519 {parts[1]}"


def _read_ssh_string(blob: bytes, offset: int) -> tuple[bytes, int]:
    if offset + 4 > len(blob):
        raise ValueError("truncated SSH string")
    length = struct.unpack(">I", blob[offset : offset + 4])[0]
    offset += 4
    end = offset + length
    if end > len(blob):
        raise ValueError("truncated SSH string")
    return blob[offset:end], end


def _read_registry_file(path: Path) -> bytes:
    if path.is_symlink():
        raise RegistryRecoveryError("registry copies must not be symbolic links")
    size = path.stat().st_size
    if not 1 <= size <= _MAX_DOCUMENT_BYTES:
        raise RegistryRecoveryError("stored registry size is invalid")
    return path.read_bytes()


@contextmanager
def _exclusive_file_lock(path: Path) -> Iterator[None]:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+b") as stream:
        stream.seek(0, os.SEEK_END)
        if stream.tell() == 0:
            stream.write(b"\0")
            stream.flush()
        stream.seek(0)
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(stream.fileno(), msvcrt.LK_LOCK, 1)
            try:
                yield
            finally:
                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def _fsync_directory(directory: Path) -> None:
    if os.name == "nt":
        return
    descriptor = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _valid_identifier(value: object) -> bool:
    return isinstance(value, str) and _IDENTIFIER.fullmatch(value) is not None
