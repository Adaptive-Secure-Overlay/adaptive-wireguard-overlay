"""Endpoint-authenticated MCC records and confidential recipient capsules.

Capsules reuse the existing cascade's X25519 / HKDF-SHA256 / AES-GCM
construction, with explicit context and purpose separation.  A capsule alone
does not authenticate its creator: endpoints MUST verify the Ed25519 record
inside it before selection, counters or replay admission.

Replay delivery is at-most-once: a durable in-flight reservation is committed
before the caller injects into IKE.  A crash during injection leaves that
reservation closed.  UDP has no transaction shared with SQLite, so this can
lose a delivery and does not promise exactly-once delivery.  ``failed_delivery``
is permitted only when the caller knows injection has not started.

Environment configuration is node-local.  Only this node's Ed25519 seed and
X25519 private key are loaded (canonical 32-byte lowercase hex files).  Linux
private files and replay state require mode 0600.  This module does not verify
Windows secrets ACLs; deployment must provision those separately.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import stat
import threading
import time
from collections import OrderedDict
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

try:
    from .trust_registry import VerifiedRegistry, load_verified_registry_from_environment
except ImportError:
    from trust_registry import VerifiedRegistry, load_verified_registry_from_environment

DOMAIN = "mcc-endpoint-message"
VERSION = 1
MAX_LIFETIME = 120
CLOCK_SKEW = 5
MAX_EXCHANGES = 1024
MAX_COPIES = 64
MAX_DELIVERY_ATTEMPTS = 3
MAX_CONCURRENT_CHECKS = 4
MAX_BODY_BYTES = 65_536
MAX_SEAL_PLAINTEXT = 524_288
MAX_JSON_BYTES = 2 * MAX_SEAL_PLAINTEXT + 1024
MAX_DEPTH = 12
MAX_ITEMS = 4096
MAX_FIELDS = 128
MAX_LEDGER_BYTES = 16 * 1024 * 1024
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,255}\Z")
_FIELDS = frozenset((
    "domain", "version", "sender", "receiver", "key_id", "context", "direction",
    "kind", "message_id", "nonce", "issued", "expires", "expected_copies", "copy_id", "body",
))


class MccSecurityError(ValueError):
    """Fail-closed error containing a stable reason code, never packet data."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _fail(code: str):
    raise MccSecurityError(code)


def _token(value: Any, maximum: int = 256) -> str:
    if not isinstance(value, str) or len(value) > maximum or not _TOKEN.fullmatch(value):
        _fail("invalid_identifier")
    return value


def _integer(value: Any, minimum: int, maximum: int):
    if type(value) is not int or not minimum <= value <= maximum:
        _fail("invalid_integer")
    return value


def _hex(value: Any, length: int | None = None, *, maximum: int = MAX_SEAL_PLAINTEXT + 16) -> bytes:
    if not isinstance(value, str) or len(value) > 2 * maximum or len(value) % 2:
        _fail("invalid_hex")
    if length is not None and len(value) != length * 2:
        _fail("invalid_hex")
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise MccSecurityError("invalid_hex") from exc
    if raw.hex() != value:
        _fail("invalid_hex")
    return raw


def _json_shape(value: Any, max_bytes: int) -> bytes:
    remaining = MAX_ITEMS

    def visit(item, depth):
        nonlocal remaining
        remaining -= 1
        if remaining < 0 or depth > MAX_DEPTH:
            _fail("json_resource_limit")
        if item is None or type(item) is bool:
            return
        if type(item) is int:
            _integer(item, -(2**63), 2**63 - 1)
        elif type(item) is str:
            if len(item) > max_bytes:
                _fail("json_resource_limit")
            try:
                item.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise MccSecurityError("invalid_unicode") from exc
        elif type(item) is list:
            if len(item) > MAX_ITEMS:
                _fail("json_resource_limit")
            for child in item:
                visit(child, depth + 1)
        elif type(item) is dict:
            if len(item) > MAX_FIELDS:
                _fail("json_resource_limit")
            for key, child in item.items():
                if type(key) is not str or len(key) > 128:
                    _fail("invalid_json_key")
                visit(key, depth + 1)
                visit(child, depth + 1)
        else:
            _fail("invalid_json_type")

    visit(value, 0)
    try:
        raw = json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    except (UnicodeEncodeError, ValueError, RecursionError) as exc:
        raise MccSecurityError("invalid_json") from exc
    if len(raw) > max_bytes:
        _fail("json_resource_limit")
    return raw


def canonical_json(value: dict, *, max_bytes: int = MAX_JSON_BYTES) -> bytes:
    if type(value) is not dict:
        _fail("invalid_json_object")
    return _json_shape(value, max_bytes)


def strict_json_loads(raw: bytes | str, *, max_bytes: int = MAX_JSON_BYTES) -> dict:
    """Bounded JSON object parser; reject duplicate keys, floats and constants."""
    if not isinstance(raw, (bytes, str)) or len(raw) > max_bytes:
        _fail("json_resource_limit")

    def pairs(values):
        if len(values) > MAX_FIELDS:
            _fail("json_resource_limit")
        result = {}
        for key, value in values:
            if key in result:
                _fail("duplicate_json_key")
            result[key] = value
        return result

    def integer(value):
        if len(value.lstrip("-")) > 19:
            _fail("invalid_integer")
        return _integer(int(value), -(2**63), 2**63 - 1)

    try:
        value = json.loads(
            raw.decode("utf-8") if isinstance(raw, bytes) else raw,
            object_pairs_hook=pairs, parse_int=integer,
            parse_float=lambda _: _fail("invalid_json_type"),
            parse_constant=lambda _: _fail("invalid_json_type"),
        )
    except MccSecurityError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise MccSecurityError("invalid_json") from exc
    canonical_json(value, max_bytes=max_bytes)
    return value


def _object(value: Any, maximum=MAX_JSON_BYTES):
    if isinstance(value, (bytes, str)):
        return strict_json_loads(value, max_bytes=maximum)
    # Round-tripping also detaches all mutable caller-owned containers.
    return strict_json_loads(canonical_json(value, max_bytes=maximum), max_bytes=maximum)


def _freeze(value):
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


def _without_path(body):
    body = dict(body)
    body.pop("transport_conn", None)
    return body


@dataclass(frozen=True, slots=True)
class VerifiedMessage:
    sender: str
    receiver: str
    key_id: str
    context: str
    direction: str
    kind: str
    message_id: str
    nonce: str
    issued: int
    expires: int
    expected_copies: int
    copy_id: int
    body: Mapping[str, Any]
    fingerprint: str
    message_key: str
    canonical: bytes
    _body_bytes: bytes = field(repr=False, compare=False)
    _verification_token: object = field(repr=False, compare=False)

    def body_dict(self) -> dict:
        """Return an independent mutable copy for the protocol-specific parser."""
        return strict_json_loads(self._body_bytes, max_bytes=MAX_BODY_BYTES)


def _private_file(path: Path, *, create=False):
    try:
        if create:
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            try:
                descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:
                pass
            else:
                os.close(descriptor)
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode):
            _fail("private_file_type")
        if os.name != "nt":
            if stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_uid != os.getuid():
                _fail("private_file_permissions")
    except OSError as exc:
        raise MccSecurityError("private_file_unavailable") from exc


def _read_private(path: str) -> bytes:
    file = Path(path)
    _private_file(file)
    try:
        with file.open("rb") as stream:
            raw = stream.read(67)
        # One trailing newline is permitted for operational key files.
        text = raw.removesuffix(b"\n").decode("ascii")
    except (OSError, UnicodeDecodeError) as exc:
        raise MccSecurityError("private_key_unavailable") from exc
    return _hex(text, 32)


class EndpointSecurity:
    def __init__(self, name, verified_registry, signing_private, encryption_private, state_path, clock=time.time):
        self.name = _token(name, 128)
        if not isinstance(verified_registry, VerifiedRegistry):
            _fail("unverified_registry")
        self.registry = verified_registry
        self.clock = clock
        self._token = object()
        self._signing = signing_private if isinstance(signing_private, Ed25519PrivateKey) else Ed25519PrivateKey.from_private_bytes(_hex(signing_private, 32) if isinstance(signing_private, str) else signing_private)
        self._encryption = encryption_private if isinstance(encryption_private, X25519PrivateKey) else X25519PrivateKey.from_private_bytes(_hex(encryption_private, 32) if isinstance(encryption_private, str) else encryption_private)
        if self._signing.private_bytes_raw() == self._encryption.private_bytes_raw():
            _fail("private_key_reused")
        own = self._node(self.name)
        if own["verification"] != self._signing.public_key().public_bytes_raw().hex() or own["encryption"] != self._encryption.public_key().public_bytes_raw().hex():
            _fail("private_key_mismatch")
        self.key_id = own["key_id"]
        if str(state_path) in ("", ":memory:"):
            _fail("persistent_state_required")
        self.state_path = Path(state_path)
        self._sign_cache = OrderedDict()
        self._sign_lock = threading.Lock()
        self._claims = {}
        self._claim_lock = threading.Lock()
        self._verification_slots = threading.BoundedSemaphore(MAX_CONCURRENT_CHECKS)
        _private_file(self.state_path, create=True)
        self._initialize_ledger()

    @classmethod
    def from_environment(cls, name, required_nodes):
        paths = {key: os.environ.get(key, "").strip() for key in (
            "MCC_SIGNING_KEY_FILE", "MCC_ENCRYPTION_KEY_FILE", "MCC_REPLAY_STATE_FILE",
        )}
        if not all(paths.values()):
            _fail("missing_endpoint_configuration")
        registry = load_verified_registry_from_environment(required_nodes)
        return cls(name, registry, _read_private(paths["MCC_SIGNING_KEY_FILE"]),
                   _read_private(paths["MCC_ENCRYPTION_KEY_FILE"]), paths["MCC_REPLAY_STATE_FILE"])

    def _now(self):
        try:
            instant = self.clock()
            if type(instant) not in (int, float) or not 0 <= instant < 2**53:
                _fail("invalid_clock")
            return int(instant)
        except (ValueError, TypeError, OverflowError) as exc:
            raise MccSecurityError("invalid_clock") from exc

    def _node(self, name):
        node = self.registry.nodes.get(name)
        if node is None:
            _fail("unknown_node")
        if node["revoked"]:
            _fail("revoked_key")
        return node

    @staticmethod
    def _aad(context, purpose):
        _token(context)
        if purpose not in ("hop", "endpoint"):
            _fail("invalid_purpose")
        return canonical_json({"domain": "mcc-recipient-capsule", "version": VERSION, "context": context, "purpose": purpose})

    @staticmethod
    def _capsule_key(shared, ephemeral, recipient, aad):
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=ephemeral + recipient,
                    info=b"mcc-recipient-capsule/v1\x00" + aad).derive(shared)

    def seal_to(self, recipient, obj, context, purpose="hop") -> dict:
        _token(recipient, 128)
        target = bytes.fromhex(self._node(recipient)["encryption"])
        aad = self._aad(context, purpose)
        plaintext = canonical_json(obj, max_bytes=MAX_SEAL_PLAINTEXT)
        ephemeral = X25519PrivateKey.generate()
        epk = ephemeral.public_key().public_bytes_raw()
        try:
            shared = ephemeral.exchange(X25519PublicKey.from_public_bytes(target))
            key = self._capsule_key(shared, epk, target, aad)
            nonce = os.urandom(12)
            ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
        except ValueError as exc:
            raise MccSecurityError("key_agreement_failed") from exc
        return {"v": VERSION, "epk": epk.hex(), "nonce": nonce.hex(), "ct": ciphertext.hex()}

    def open_for_me(self, seal, context, purpose="hop") -> dict:
        if not self._verification_slots.acquire(blocking=False):
            _fail("verification_capacity")
        try:
            return self._open_for_me(seal, context, purpose)
        finally:
            self._verification_slots.release()

    def _open_for_me(self, seal, context, purpose):
        self._node(self.name)
        value = _object(seal)
        if set(value) != {"v", "epk", "nonce", "ct"} or type(value["v"]) is not int or value["v"] != VERSION:
            _fail("invalid_capsule")
        epk, nonce, ciphertext = _hex(value["epk"], 32), _hex(value["nonce"], 12), _hex(value["ct"])
        if len(ciphertext) < 16:
            _fail("invalid_capsule")
        aad = self._aad(context, purpose)
        own = self._encryption.public_key().public_bytes_raw()
        try:
            shared = self._encryption.exchange(X25519PublicKey.from_public_bytes(epk))
            key = self._capsule_key(shared, epk, own, aad)
            plaintext = AESGCM(key).decrypt(nonce, ciphertext, aad)
        except (InvalidTag, ValueError) as exc:
            raise MccSecurityError("capsule_authentication_failed") from exc
        return strict_json_loads(plaintext, max_bytes=MAX_SEAL_PLAINTEXT)

    @staticmethod
    def _message_key(signed):
        identity = {key: signed[key] for key in ("sender", "receiver", "key_id", "context", "direction", "kind", "message_id")}
        return hashlib.sha256(canonical_json(identity)).hexdigest()

    @staticmethod
    def _fingerprint(signed):
        protected = {key: value for key, value in signed.items() if key != "copy_id"}
        protected["body"] = _without_path(protected["body"])
        return hashlib.sha256(canonical_json(protected)).hexdigest()

    def signed_message(self, recipient, context, body, copy_id, expected_copies,
                       direction="forward", kind="initial", message_id="0") -> dict:
        _token(recipient, 128)
        self._node(recipient)
        self._node(self.name)
        _token(context)
        self._labels(direction, kind, message_id)
        _integer(expected_copies, 1, MAX_COPIES)
        _integer(copy_id, 0, expected_copies - 1)
        body = _object(body, MAX_BODY_BYTES)
        base = {"domain": DOMAIN, "version": VERSION, "sender": self.name,
                "receiver": recipient, "key_id": self.key_id, "context": context,
                "direction": direction, "kind": kind, "message_id": message_id,
                "expected_copies": expected_copies, "copy_id": copy_id, "body": body}
        canonical_json(base, max_bytes=MAX_BODY_BYTES + 4096)
        message_key = self._message_key(base)
        semantic = {key: value for key, value in base.items() if key != "copy_id"}
        semantic["body"] = _without_path(body)
        semantic_digest = hashlib.sha256(canonical_json(semantic)).digest()
        now = self._now()
        with self._sign_lock:
            for key, cached in list(self._sign_cache.items()):
                if cached[3] + CLOCK_SKEW < now:
                    del self._sign_cache[key]
            cached = self._sign_cache.get(message_key)
            if cached is None:
                if len(self._sign_cache) >= MAX_EXCHANGES:
                    _fail("signer_capacity")
                cached = (semantic_digest, os.urandom(16).hex(), now, now + MAX_LIFETIME)
                self._sign_cache[message_key] = cached
            elif cached[0] != semantic_digest:
                _fail("conflicting_message")
            if cached[2] > now + CLOCK_SKEW:
                _fail("clock_rollback")
            base.update(nonce=cached[1], issued=cached[2], expires=cached[3])
        signature = self._signing.sign(canonical_json(base)).hex()
        return {"signed": base, "signature": signature}

    @staticmethod
    def _labels(direction, kind, message_id):
        if direction not in ("forward", "reverse"):
            _fail("invalid_direction")
        _token(kind, 32)
        _token(message_id, 128)

    def _fresh(self, issued, expires):
        _integer(issued, 0, 2**53 - 1)
        _integer(expires, 0, 2**53 - 1)
        now = self._now()
        if not 1 <= expires - issued <= MAX_LIFETIME or issued > now + CLOCK_SKEW or expires < now - CLOCK_SKEW:
            _fail("expired_or_future_message")

    def verify_signed(self, record, context, expected_sender=None,
                      direction="forward", kind="initial") -> VerifiedMessage:
        if not self._verification_slots.acquire(blocking=False):
            _fail("verification_capacity")
        try:
            return self._verify_signed(record, context, expected_sender, direction, kind)
        finally:
            self._verification_slots.release()

    def _verify_signed(self, record, context, expected_sender, direction, kind):
        value = _object(record, MAX_BODY_BYTES + 8192)
        if set(value) != {"signed", "signature"} or type(value["signed"]) is not dict:
            _fail("invalid_signed_record")
        signed = value["signed"]
        if set(signed) != _FIELDS or signed["domain"] != DOMAIN or type(signed["version"]) is not int or signed["version"] != VERSION:
            _fail("invalid_signed_record")
        _token(context)
        _token(signed["sender"], 128)
        _token(signed["receiver"], 128)
        self._labels(signed["direction"], signed["kind"], signed["message_id"])
        if signed["receiver"] != self.name or signed["context"] != context or signed["direction"] != direction or signed["kind"] != kind:
            _fail("wrong_message_scope")
        if expected_sender is not None and signed["sender"] != expected_sender:
            _fail("unexpected_sender")
        self._node(self.name)
        sender = self._node(signed["sender"])
        if signed["key_id"] != sender["key_id"]:
            _fail("unknown_key")
        _hex(signed["nonce"], 16)
        self._fresh(signed["issued"], signed["expires"])
        _integer(signed["expected_copies"], 1, MAX_COPIES)
        _integer(signed["copy_id"], 0, signed["expected_copies"] - 1)
        body_bytes = canonical_json(signed["body"], max_bytes=MAX_BODY_BYTES)
        canonical = canonical_json(signed, max_bytes=MAX_BODY_BYTES + 4096)
        signature = _hex(value["signature"], 64)
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(sender["verification"])).verify(signature, canonical)
        except InvalidSignature as exc:
            raise MccSecurityError("bad_signature") from exc
        return VerifiedMessage(
            *(signed[key] for key in ("sender", "receiver", "key_id", "context", "direction", "kind", "message_id", "nonce", "issued", "expires", "expected_copies", "copy_id")),
            _freeze(signed["body"]), self._fingerprint(signed), self._message_key(signed),
            canonical, body_bytes, self._token,
        )

    def _connect(self):
        _private_file(self.state_path)
        if self.state_path.stat().st_size > MAX_LEDGER_BYTES:
            _fail("state_resource_limit")
        conn = sqlite3.connect(self.state_path, timeout=1, isolation_level=None)
        try:
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA synchronous=FULL")
            conn.execute("PRAGMA trusted_schema=OFF")
            page_size = conn.execute("PRAGMA page_size").fetchone()[0]
            conn.execute(f"PRAGMA max_page_count={max(1, MAX_LEDGER_BYTES // page_size)}")
        except sqlite3.Error:
            conn.close()
            raise
        return conn

    def _initialize_ledger(self):
        conn = None
        try:
            conn = self._connect()
            conn.execute("BEGIN IMMEDIATE")
            version = conn.execute("PRAGMA user_version").fetchone()[0]
            tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
            if version == 0 and not tables:
                conn.execute("CREATE TABLE meta (id INTEGER PRIMARY KEY CHECK(id=1), schema TEXT NOT NULL, owner TEXT NOT NULL, key_id TEXT NOT NULL, last_seen INTEGER NOT NULL)")
                conn.execute("CREATE TABLE messages (message_key TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, expires INTEGER NOT NULL, expected INTEGER NOT NULL CHECK(expected BETWEEN 1 AND 64), status TEXT NOT NULL CHECK(status IN ('active','in_flight','delivered')), reserved_copy INTEGER, attempts INTEGER NOT NULL DEFAULT 0)")
                conn.execute("CREATE TABLE copies (message_key TEXT NOT NULL REFERENCES messages(message_key) ON DELETE CASCADE, copy_id INTEGER NOT NULL CHECK(copy_id BETWEEN 0 AND 63), PRIMARY KEY(message_key, copy_id))")
                conn.execute("INSERT INTO meta VALUES (1, 'mcc-replay/v1', ?, ?, ?)", (self.name, self.key_id, self._now()))
                conn.execute("PRAGMA user_version=1")
            elif version != 1:
                _fail("invalid_state_schema")
            self._check_meta(conn, update=False)
            conn.commit()
        except MccSecurityError:
            if conn is not None:
                conn.rollback()
            raise
        except (sqlite3.Error, OSError) as exc:
            if conn is not None:
                conn.rollback()
            raise MccSecurityError("state_unavailable") from exc
        finally:
            if conn is not None:
                conn.close()

    def _check_meta(self, conn, *, update):
        meta = conn.execute("SELECT schema, owner, key_id, last_seen FROM meta WHERE id=1").fetchone()
        if meta is None or meta[:3] != ("mcc-replay/v1", self.name, self.key_id):
            _fail("state_identity_mismatch")
        now = self._now()
        if type(meta[3]) is not int or now + CLOCK_SKEW < meta[3]:
            _fail("clock_rollback")
        if update:
            conn.execute("UPDATE meta SET last_seen=? WHERE id=1", (max(now, meta[3]),))
            conn.execute("DELETE FROM messages WHERE expires < ?", (now - CLOCK_SKEW,))

    @contextmanager
    def _transaction(self):
        conn = None
        try:
            conn = self._connect()
            conn.execute("BEGIN IMMEDIATE")
            self._check_meta(conn, update=True)
            yield conn
            conn.commit()
        except MccSecurityError:
            if conn is not None:
                conn.rollback()
            raise
        except (sqlite3.Error, OSError) as exc:
            if conn is not None:
                conn.rollback()
            raise MccSecurityError("state_unavailable") from exc
        finally:
            if conn is not None:
                conn.close()

    def _verified(self, verified):
        if not isinstance(verified, VerifiedMessage) or verified._verification_token is not self._token or verified.receiver != self.name:
            _fail("unverified_message")
        node = self._node(verified.sender)
        self._node(self.name)
        if verified.key_id != node["key_id"]:
            _fail("unknown_key")
        self._fresh(verified.issued, verified.expires)

    @staticmethod
    def _row(conn, verified, *, required=False):
        row = conn.execute("SELECT fingerprint, expires, expected, status, reserved_copy, attempts FROM messages WHERE message_key=?", (verified.message_key,)).fetchone()
        if row is None:
            if required:
                _fail("unadmitted_message")
            return None
        if row[:3] != (verified.fingerprint, verified.expires, verified.expected_copies):
            _fail("conflicting_message")
        return row

    def admit(self, verified: VerifiedMessage) -> str:
        self._verified(verified)
        with self._transaction() as conn:
            row = self._row(conn, verified)
            if row is None:
                if conn.execute("SELECT COUNT(*) FROM messages").fetchone()[0] >= MAX_EXCHANGES:
                    _fail("receiver_capacity")
                conn.execute("INSERT INTO messages(message_key,fingerprint,expires,expected,status) VALUES (?,?,?,?,'active')", (verified.message_key, verified.fingerprint, verified.expires, verified.expected_copies))
            elif row[3] != "active":
                return "delivered"
            if conn.execute("SELECT 1 FROM copies WHERE message_key=? AND copy_id=?", (verified.message_key, verified.copy_id)).fetchone():
                return "duplicate"
            count = conn.execute("SELECT COUNT(*) FROM copies WHERE message_key=?", (verified.message_key,)).fetchone()[0]
            if count >= verified.expected_copies or count >= MAX_COPIES:
                _fail("copy_capacity")
            conn.execute("INSERT INTO copies VALUES (?,?)", (verified.message_key, verified.copy_id))
            return "new"

    def claim_delivery(self, verified: VerifiedMessage) -> bool:
        """Persist a reservation before injection; false never permits injection."""
        self._verified(verified)
        with self._transaction() as conn:
            row = self._row(conn, verified, required=True)
            if not conn.execute("SELECT 1 FROM copies WHERE message_key=? AND copy_id=?", (verified.message_key, verified.copy_id)).fetchone():
                _fail("unadmitted_copy")
            if row[3] != "active" or row[5] >= MAX_DELIVERY_ATTEMPTS:
                return False
            conn.execute("UPDATE messages SET status='in_flight', reserved_copy=?, attempts=attempts+1 WHERE message_key=?", (verified.copy_id, verified.message_key))
        with self._claim_lock:
            self._prune_claims()
            self._claims[(verified.message_key, verified.copy_id)] = verified.expires
        return True

    def _prune_claims(self):
        now = self._now()
        for key, expires in list(self._claims.items()):
            if expires + CLOCK_SKEW < now:
                del self._claims[key]

    def delivered(self, verified: VerifiedMessage):
        self._verified(verified)
        with self._transaction() as conn:
            row = self._row(conn, verified, required=True)
            if row[3] == "delivered":
                return
            if row[3] != "in_flight" or row[4] != verified.copy_id:
                _fail("delivery_not_reserved")
            conn.execute("UPDATE messages SET status='delivered' WHERE message_key=?", (verified.message_key,))
        with self._claim_lock:
            self._claims.pop((verified.message_key, verified.copy_id), None)

    def failed_delivery(self, verified: VerifiedMessage):
        """Release only a known pre-injection failure; never use after uncertainty."""
        self._verified(verified)
        with self._claim_lock:
            self._prune_claims()
            if (verified.message_key, verified.copy_id) not in self._claims:
                _fail("delivery_not_reserved_here")
        with self._transaction() as conn:
            row = self._row(conn, verified, required=True)
            if row[3] != "in_flight" or row[4] != verified.copy_id:
                _fail("delivery_not_reserved")
            conn.execute("UPDATE messages SET status='active', reserved_copy=NULL WHERE message_key=?", (verified.message_key,))
        with self._claim_lock:
            self._claims.pop((verified.message_key, verified.copy_id), None)
