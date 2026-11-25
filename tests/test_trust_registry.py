from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

import wg_handshake_overlay
from trust_registry_support import EphemeralOpenSshSigner, node_keys, wireguard_key
from wg_handshake_overlay.models import Endpoint
from wg_handshake_overlay.routing import AuthenticatedRoutePlanner, RouteCache
from wg_handshake_overlay.trust_registry import (
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
)


REGISTRY_ID = "candidate-wireguard-nodes"
KEY_ID = "root-test-1"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class FailingCommitStore(TrustedRegistryStore):
    fail_next_active_write = False

    def _atomic_write(self, path: Path, data: bytes) -> None:
        if self.fail_next_active_write and path == self.active_path:
            self.fail_next_active_write = False
            raise OSError("injected failure before atomic replace")
        super()._atomic_write(path, data)


class TrustRegistryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.signer = EphemeralOpenSshSigner()

    @classmethod
    def tearDownClass(cls):
        cls.signer.close()

    def setUp(self):
        self.state = tempfile.TemporaryDirectory(prefix="wg-registry-state-")
        self.addCleanup(self.state.cleanup)
        self.nodes = node_keys("A", "B", "X1", "X2")
        self.anchor = TrustAnchor(KEY_ID, self.signer.public_key)
        self.document_v1 = self.signer.document(
            registry_id=REGISTRY_ID,
            version=1,
            nodes=self.nodes,
            key_id=KEY_ID,
        )
        self.store = TrustedRegistryStore(
            self.state.name,
            trust_anchor=self.anchor,
            registry_id=REGISTRY_ID,
        )
        self.store.apply_update(self.document_v1)

    def test_valid_update_is_resolved_and_route_is_authorized(self):
        self.assertEqual(self.store.snapshot.version, 1)
        self.assertEqual(self.store.require_node("B").public_key, self.nodes["B"])

        cache = RouteCache(30)
        planner = AuthenticatedRoutePlanner(cache, self.store)
        source = Endpoint("192.0.2.10", 51820)
        destination = Endpoint("192.0.2.20", 51820)
        authorized = planner.establish(
            source_node="A",
            source=source,
            relays=(("X1", Endpoint("198.51.100.11", 51820)), ("X2", Endpoint("203.0.113.12", 51820))),
            destination_node="B",
            destination=destination,
            now=0,
            presented_public_keys=self.nodes,
        )
        self.assertEqual(authorized.registry_version, 1)
        self.assertEqual(authorized.public_key_for("B"), self.nodes["B"])
        self.assertIsNotNone(cache.get(source, destination, 0))

    def test_remote_public_key_substitution_is_rejected_before_route(self):
        cache = RouteCache(30)
        planner = AuthenticatedRoutePlanner(cache, self.store)
        source = Endpoint("192.0.2.10", 51820)
        destination = Endpoint("192.0.2.20", 51820)
        substituted = dict(self.nodes)
        substituted["B"] = wireguard_key(99)

        with self.assertRaises(RegistryKeyMismatchError):
            planner.establish(
                source_node="A",
                source=source,
                relays=(("X1", Endpoint("198.51.100.11", 51820)), ("X2", Endpoint("203.0.113.12", 51820))),
                destination_node="B",
                destination=destination,
                now=0,
                presented_public_keys=substituted,
            )
        self.assertIsNone(cache.get(source, destination, 0))

    def test_remote_public_key_substitution_without_signed_registry_is_rejected(self):
        empty_directory = Path(self.state.name) / "no-signed-registry"
        empty_store = TrustedRegistryStore(
            empty_directory,
            trust_anchor=self.anchor,
            registry_id=REGISTRY_ID,
        )
        cache = RouteCache(30)
        planner = AuthenticatedRoutePlanner(cache, empty_store)
        source = Endpoint("192.0.2.10", 51820)
        destination = Endpoint("192.0.2.20", 51820)
        substituted = dict(self.nodes)
        substituted["B"] = wireguard_key(99)

        with self.assertRaises(RegistryRecoveryError):
            planner.establish(
                source_node="A",
                source=source,
                relays=(("X1", Endpoint("198.51.100.11", 51820)),),
                destination_node="B",
                destination=destination,
                now=0,
                presented_public_keys={
                    "A": substituted["A"],
                    "X1": substituted["X1"],
                    "B": substituted["B"],
                },
            )
        self.assertIsNone(cache.get(source, destination, 0))

    def test_missing_bad_unknown_and_modified_signatures_leave_state_unchanged(self):
        before_active = digest(self.store.active_path)
        before_recovery = digest(self.store.recovery_path)
        original = EphemeralOpenSshSigner.parse(self.document_v1)

        missing = dict(original)
        missing.pop("signature")

        bad_signature = json.loads(json.dumps(original))
        lines = bad_signature["signature"]["value"].splitlines()
        lines[1] = ("A" if lines[1][0] != "A" else "B") + lines[1][1:]
        bad_signature["signature"]["value"] = "\n".join(lines) + "\n"

        unknown_signer = json.loads(json.dumps(original))
        unknown_signer["signature"]["key_id"] = "unknown-root"

        modified_key = json.loads(json.dumps(original))
        modified_key["signed"]["nodes"]["B"]["public_key"] = wireguard_key(98)

        noncanonical_entry = json.loads(json.dumps(original))
        noncanonical_entry["signed"]["nodes"]["B"] = self.nodes["B"]

        duplicate_version = self.document_v1.replace(
            b'"version":1',
            b'"version":1,"version":1',
            1,
        )

        cases = (
            (RegistryFormatError, EphemeralOpenSshSigner.encode(missing)),
            (RegistrySignatureError, EphemeralOpenSshSigner.encode(bad_signature)),
            (UnknownSignerError, EphemeralOpenSshSigner.encode(unknown_signer)),
            (RegistrySignatureError, EphemeralOpenSshSigner.encode(modified_key)),
            (RegistryFormatError, EphemeralOpenSshSigner.encode(noncanonical_entry)),
            (RegistryFormatError, duplicate_version),
            (RegistryFormatError, b"{"),
        )
        for expected_error, document in cases:
            with self.subTest(expected_error=expected_error.__name__):
                with self.assertRaises(expected_error):
                    self.store.apply_update(document)
                self.assertEqual(digest(self.store.active_path), before_active)
                self.assertEqual(digest(self.store.recovery_path), before_recovery)
                self.assertEqual(self.store.snapshot.version, 1)

    def test_equal_and_older_versions_are_rejected(self):
        document_v2 = self.signer.document(
            registry_id=REGISTRY_ID,
            version=2,
            nodes=self.nodes,
            key_id=KEY_ID,
        )
        self.store.apply_update(document_v2)
        before = digest(self.store.active_path)

        for replay in (document_v2, self.document_v1):
            with self.subTest():
                with self.assertRaises(RegistryRollbackError):
                    self.store.apply_update(replay)
                self.assertEqual(digest(self.store.active_path), before)
                self.assertEqual(self.store.snapshot.version, 2)

    def test_unknown_node_is_rejected_before_route(self):
        cache = RouteCache(30)
        planner = AuthenticatedRoutePlanner(cache, self.store)
        source = Endpoint("192.0.2.10", 51820)
        destination = Endpoint("192.0.2.99", 51820)
        with self.assertRaises(UnknownNodeError):
            planner.establish(
                source_node="A",
                source=source,
                relays=(("X1", Endpoint("198.51.100.11", 51820)), ("X2", Endpoint("203.0.113.12", 51820))),
                destination_node="Rogue",
                destination=destination,
                now=0,
            )
        self.assertIsNone(cache.get(source, destination, 0))

    def test_corrupted_active_copy_recovers_highest_valid_version(self):
        document_v2 = self.signer.document(
            registry_id=REGISTRY_ID,
            version=2,
            nodes=self.nodes,
            key_id=KEY_ID,
        )
        self.store.apply_update(document_v2)
        expected = self.store.recovery_path.read_bytes()
        self.store.active_path.write_bytes(b"{")

        recovered = TrustedRegistryStore(
            self.state.name,
            trust_anchor=self.anchor,
            registry_id=REGISTRY_ID,
        )
        snapshot = recovered.load_or_recover()
        self.assertEqual(snapshot.version, 2)
        self.assertEqual(recovered.active_path.read_bytes(), expected)

    def test_failure_before_atomic_replace_preserves_last_valid_version(self):
        failing = FailingCommitStore(
            self.state.name,
            trust_anchor=self.anchor,
            registry_id=REGISTRY_ID,
        )
        failing.load_or_recover()
        before_active = digest(failing.active_path)
        before_recovery = digest(failing.recovery_path)
        document_v2 = self.signer.document(
            registry_id=REGISTRY_ID,
            version=2,
            nodes=self.nodes,
            key_id=KEY_ID,
        )
        failing.fail_next_active_write = True
        with self.assertRaises(RegistryPersistenceError):
            failing.apply_update(document_v2)
        self.assertEqual(digest(failing.active_path), before_active)
        self.assertEqual(digest(failing.recovery_path), before_recovery)
        self.assertEqual(failing.snapshot.version, 1)

    def test_verified_bindings_cannot_be_fabricated_or_reused_after_update(self):
        for unsafe_name in ("AuthenticatedRoute", "TrustedNode", "RegistrySnapshot"):
            with self.subTest(unsafe_name=unsafe_name):
                self.assertNotIn(unsafe_name, wg_handshake_overlay.__all__)
                self.assertFalse(hasattr(wg_handshake_overlay, unsafe_name))

        from wg_handshake_overlay.trust_registry import _TrustedNode

        with self.assertRaises(RegistrySignatureError):
            _TrustedNode("B", wireguard_key(99), object())

        planner = AuthenticatedRoutePlanner(RouteCache(30), self.store)
        authorized = planner.establish(
            source_node="A",
            source=Endpoint("192.0.2.10", 51820),
            relays=(("X1", Endpoint("198.51.100.11", 51820)),),
            destination_node="B",
            destination=Endpoint("192.0.2.20", 51820),
            now=0,
        )
        updated_nodes = dict(self.nodes)
        updated_nodes["B"] = wireguard_key(77)
        self.store.apply_update(
            self.signer.document(
                registry_id=REGISTRY_ID,
                version=2,
                nodes=updated_nodes,
                key_id=KEY_ID,
            )
        )
        with self.assertRaises(ValueError):
            authorized.public_key_for("B")


if __name__ == "__main__":
    unittest.main()
