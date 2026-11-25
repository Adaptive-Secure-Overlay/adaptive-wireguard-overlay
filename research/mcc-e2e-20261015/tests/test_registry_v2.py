from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "candidate"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
import trust_registry as registry


def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


class RegistryFixture:
    """Test coordinator owns generated seeds; each endpoint receives only its own."""

    def __init__(self, directory, names=("A", "B", "X1", "X2")):
        self.directory = Path(directory)
        self.names = tuple(names)
        self.root = Ed25519PrivateKey.generate()
        self.signing = {name: Ed25519PrivateKey.generate() for name in self.names}
        self.encryption = {name: X25519PrivateKey.generate() for name in self.names}
        self.nodes = {
            name: {
                "encryption": self.encryption[name].public_key().public_bytes_raw().hex(),
                "verification": self.signing[name].public_key().public_bytes_raw().hex(),
                "key_id": hashlib.sha256(self.signing[name].public_key().public_bytes_raw()).hexdigest(),
                "revoked": False,
            }
            for name in self.names
        }
        self.root_path = self.directory / "root.json"
        self.root_path.write_bytes(registry._canonical_json({
            "schema": registry.ROOT_SCHEMA,
            "signers": {"test-root": {"algorithm": "Ed25519", "public_key": b64(self.root.public_key().public_bytes_raw())}},
        }))

    def envelope(self, version=1, nodes=None):
        signed = {"schema": registry.REGISTRY_SCHEMA, "version": version, "nodes": copy.deepcopy(self.nodes if nodes is None else nodes)}
        return {"signed": signed, "signatures": [{
            "key_id": "test-root", "algorithm": "Ed25519", "sig": b64(self.root.sign(registry._canonical_json(signed))),
        }]}

    def raw(self, version=1, nodes=None):
        return registry._canonical_json(self.envelope(version, nodes))

    def verified(self, version=1, nodes=None):
        return registry.verify_registry_bytes(self.raw(version, nodes), self.root_path, self.names)

    def store(self):
        return registry.TrustRegistryStore(self.directory / "registry.json", self.root_path,
                                           self.directory / "accepted.json", self.directory / "last-valid.json")


class RegistryV2Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="mcc-registry-", dir=os.environ.get("MCC_TEST_TMP_DIR"))
        self.addCleanup(self.temp.cleanup)
        self.fixture = RegistryFixture(self.temp.name)

    def assert_code(self, code, function, *args, **kwargs):
        with self.assertRaises(registry.TrustRegistryError) as caught:
            function(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)

    def test_signed_v2_roundtrip_and_immutable_keys(self):
        verified = self.fixture.verified()
        self.assertEqual(verified.nodes["A"], self.fixture.nodes["A"])
        self.assertEqual(verified.status()["schema"], registry.REGISTRY_SCHEMA)
        self.assertEqual(registry.verification_key_id(self.fixture.nodes["A"]["verification"]), self.fixture.nodes["A"]["key_id"])
        with self.assertRaises(TypeError):
            verified.nodes["A"]["revoked"] = True
        with self.assertRaises(TypeError):
            verified.nodes["new"] = {}

    def test_trust_root_supports_original_serialization_api(self):
        # cryptography 3.4.x exposes public_bytes, not public_bytes_raw.
        actual = self.fixture.root.public_key()
        class OriginalApiPublicKey:
            def public_bytes(self, encoding, format):
                return actual.public_bytes(encoding, format)
            def verify(self, signature, data):
                return actual.verify(signature, data)
        with patch.object(registry._v1, '_load_trust_root', return_value={'test-root': OriginalApiPublicKey()}):
            verified = registry.verify_registry_bytes(self.fixture.raw(), self.fixture.root_path, self.fixture.names)
        self.assertEqual(verified.nodes['A'], self.fixture.nodes['A'])

    def test_v1_entries_do_not_migrate_implicitly(self):
        envelope = self.fixture.envelope()
        envelope["signed"]["schema"] = registry._v1.REGISTRY_SCHEMA
        envelope["signed"]["nodes"] = {name: node["encryption"] for name, node in self.fixture.nodes.items()}
        self.assert_code("invalid_schema", registry.verify_registry_bytes, registry._canonical_json(envelope), self.fixture.root_path, self.fixture.names)

    def test_unknown_root_tampered_and_missing_signature(self):
        for label in ("unknown", "tamper", "missing"):
            envelope = self.fixture.envelope()
            if label == "unknown":
                envelope["signatures"][0]["key_id"] = "untrusted"
                code = "unknown_signer"
            elif label == "tamper":
                envelope["signed"]["nodes"]["A"]["revoked"] = True
                code = "bad_signature"
            else:
                envelope["signatures"] = []
                code = "missing_signature"
            with self.subTest(label=label):
                self.assert_code(code, registry.verify_registry_bytes, registry._canonical_json(envelope), self.fixture.root_path, self.fixture.names)

    def test_duplicate_json_keys_rejected_at_all_levels(self):
        raw = self.fixture.raw()
        for old, new in ((b'"version":1', b'"version":1,"version":1'),
                         (b'"revoked":false', b'"revoked":false,"revoked":false')):
            with self.subTest(old=old):
                self.assert_code("duplicate_json_key", registry.verify_registry_bytes, raw.replace(old, new, 1), self.fixture.root_path, self.fixture.names)

    def test_node_key_format_key_id_and_revocation_are_strict(self):
        cases = (("encryption", "AA" * 32, "invalid_node_key"),
                 ("verification", " " + self.fixture.nodes["A"]["verification"], "invalid_node_key"),
                 ("key_id", "0" * 64, "invalid_key_id"),
                 ("revoked", 0, "invalid_revocation"))
        for field, value, code in cases:
            nodes = copy.deepcopy(self.fixture.nodes)
            nodes["A"][field] = value
            with self.subTest(field=field):
                self.assert_code(code, self.fixture.verified, nodes=nodes)
        nodes = copy.deepcopy(self.fixture.nodes)
        nodes["A"]["revoked"] = True
        self.assertTrue(self.fixture.verified(nodes=nodes).nodes["A"]["revoked"])

    def test_individual_node_keys_and_separate_root_are_enforced(self):
        nodes = copy.deepcopy(self.fixture.nodes)
        nodes["B"] = dict(nodes["A"])
        self.assert_code("shared_node_key", self.fixture.verified, nodes=nodes)
        nodes = copy.deepcopy(self.fixture.nodes)
        root_public = self.fixture.root.public_key().public_bytes_raw()
        nodes["A"]["verification"] = root_public.hex()
        nodes["A"]["key_id"] = hashlib.sha256(root_public).hexdigest()
        self.assert_code("root_key_reused", self.fixture.verified, nodes=nodes)

    def test_required_nodes_version_and_resource_limits(self):
        self.assert_code("unknown_node", registry.verify_registry_bytes, self.fixture.raw(), self.fixture.root_path, ("A", "B"))
        self.assert_code("missing_node", registry.verify_registry_bytes, self.fixture.raw(), self.fixture.root_path, (*self.fixture.names, "Z"))
        self.assert_code("registry_too_large", registry.verify_registry_bytes, b" " * (registry.MAX_REGISTRY_BYTES + 1), self.fixture.root_path, self.fixture.names)
        for version in (True, 0, 1.0):
            self.assert_code("invalid_version", self.fixture.verified, version=version)
        nodes = {f"n{i}": {} for i in range(registry.MAX_NODES + 1)}
        self.assert_code("invalid_nodes", registry.verify_registry_bytes, self.fixture.raw(nodes=nodes), self.fixture.root_path, nodes)

    def test_store_update_recovery_rollback_and_same_version_replacement(self):
        store = self.fixture.store()
        candidate = Path(self.temp.name) / "candidate.json"
        candidate.write_bytes(self.fixture.raw())
        store.install_update(candidate, self.fixture.names)
        candidate.write_bytes(self.fixture.raw(version=2))
        store.install_update(candidate, self.fixture.names)
        for raw in (self.fixture.raw(), self.fixture.raw(version=2)):
            candidate.write_bytes(raw)
            self.assert_code("stale_version", store.install_update, candidate, self.fixture.names)
        store.registry_path.write_bytes(self.fixture.raw())
        recovered = store.load(self.fixture.names)
        self.assertTrue(recovered.recovered)
        self.assertEqual(recovered.version, 2)
        self.assertEqual(store.registry_path.read_bytes(), self.fixture.raw(version=2))
        nodes = copy.deepcopy(self.fixture.nodes)
        nodes["A"]["revoked"] = True
        replaced = self.fixture.raw(version=2, nodes=nodes)
        store.registry_path.write_bytes(replaced)
        store.backup_path.write_bytes(replaced)
        self.assert_code("same_version_replacement", store.load, self.fixture.names)

    def test_interrupted_update_restores_old_committed_version(self):
        store = self.fixture.store()
        candidate = Path(self.temp.name) / "candidate.json"
        candidate.write_bytes(self.fixture.raw())
        store.install_update(candidate, self.fixture.names)
        candidate.write_bytes(self.fixture.raw(version=2))
        atomic = registry._v1._atomic_write

        def fail_state(path, raw):
            if path == store.state_path:
                raise OSError("injected state commit failure")
            atomic(path, raw)

        with patch.object(registry._v1, "_atomic_write", side_effect=fail_state):
            with self.assertRaises(OSError):
                store.install_update(candidate, self.fixture.names)
        recovered = store.load(self.fixture.names)
        self.assertEqual(recovered.version, 1)
        self.assertTrue(recovered.recovered)

    def test_environment_rejects_unsigned_or_missing_configuration(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assert_code("missing_trust_configuration", registry.load_verified_registry_from_environment, self.fixture.names)
        with patch.dict(os.environ, {"IKE_CASCADE_PUBLIC_KEYS_JSON": "{}"}, clear=True):
            self.assert_code("unsigned_registry_rejected", registry.load_verified_registry_from_environment, self.fixture.names)


if __name__ == "__main__":
    unittest.main()
