from __future__ import annotations

import copy
import hashlib
import json
import os
import sqlite3
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "candidate"))

import mcc_e2e as mcc
from test_registry_v2 import RegistryFixture


class MccE2ETests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="mcc-e2e-", dir=os.environ.get("MCC_TEST_TMP_DIR"))
        self.addCleanup(self.temp.cleanup)
        self.fixture = RegistryFixture(self.temp.name)
        self.registry = self.fixture.verified()
        self.now = 1_800_000_000
        self.nodes = {name: self.endpoint(name) for name in self.fixture.names}
        self.a, self.b, self.x1, self.x2 = (self.nodes[name] for name in self.fixture.names)
        self.body = {"ike_payload": "AQIDBA==", "ike_length": 4,
                     "a_ke": "1" * 64, "selection": "first", "transport_conn": "path-0"}

    def endpoint(self, name, *, suffix="", registry=None):
        return mcc.EndpointSecurity(name, self.registry if registry is None else registry,
                                    self.fixture.signing[name], self.fixture.encryption[name],
                                    Path(self.temp.name) / f"{name}{suffix}.sqlite", clock=lambda: self.now)

    def record(self, copy_id=0, expected=9, context="exchange-1", body=None, **kwargs):
        return self.a.signed_message("B", context, self.body if body is None else body,
                                     copy_id, expected, **kwargs)

    def verify(self, record, context="exchange-1", **kwargs):
        return self.b.verify_signed(record, context, **kwargs)

    def resign(self, record, sender="A"):
        record["signature"] = self.fixture.signing[sender].sign(mcc.canonical_json(record["signed"])).hex()
        return record

    def assert_code(self, code, function, *args, **kwargs):
        with self.assertRaises(mcc.MccSecurityError) as caught:
            function(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)

    def counts(self):
        with closing(sqlite3.connect(self.b.state_path)) as conn:
            return (conn.execute("SELECT COUNT(*) FROM messages").fetchone()[0],
                    conn.execute("SELECT COUNT(*) FROM copies").fetchone()[0])

    def test_real_hop_repackaging_preserves_endpoint_confidentiality(self):
        record = self.record()
        endpoint = self.a.seal_to("B", record, "exchange-1", purpose="endpoint")
        self.assertEqual(set(endpoint), {"v", "epk", "nonce", "ct"})
        for secret in (b'"sender"', b'"receiver"', b'"signature"', self.a.key_id.encode()):
            self.assertNotIn(secret, mcc.canonical_json(endpoint))
        hop = self.a.seal_to("X1", {"opaque": endpoint, "next": "X2"}, "exchange-1")
        x1_plain = self.x1.open_for_me(hop, "exchange-1")
        repacked = self.x1.seal_to("X2", x1_plain, "exchange-1")
        x2_plain = self.x2.open_for_me(repacked, "exchange-1")
        self.assertEqual(x2_plain["opaque"], endpoint)
        self.assert_code("capsule_authentication_failed", self.x2.open_for_me, endpoint, "exchange-1", purpose="endpoint")
        plaintext = self.b.open_for_me(x2_plain["opaque"], "exchange-1", purpose="endpoint")
        self.assertEqual(self.verify(plaintext).sender, "A")
        # A relay object contains its own private keys and the public registry.
        self.assertEqual(self.x2._signing.public_key().public_bytes_raw().hex(), self.registry.nodes["X2"]["verification"])
        self.assertEqual(self.x2._encryption.public_key().public_bytes_raw().hex(), self.registry.nodes["X2"]["encryption"])

    def test_capsule_context_purpose_receiver_and_headers_are_bound(self):
        seal = self.a.seal_to("B", {"message": "hello"}, "exchange-1", purpose="endpoint")
        for receiver, context, purpose in ((self.b, "other", "endpoint"), (self.b, "exchange-1", "hop"),
                                            (self.a, "exchange-1", "endpoint")):
            self.assert_code("capsule_authentication_failed", receiver.open_for_me, seal, context, purpose=purpose)
        changed = dict(seal, sender="A")
        self.assert_code("invalid_capsule", self.b.open_for_me, changed, "exchange-1", purpose="endpoint")
        changed = dict(seal, v=True)
        self.assert_code("invalid_capsule", self.b.open_for_me, changed, "exchange-1", purpose="endpoint")
        changed = dict(seal, epk="00" * 32)
        self.assert_code("capsule_authentication_failed", self.b.open_for_me, changed, "exchange-1", purpose="endpoint")

    def test_invalid_first_cannot_change_ledger_or_poison_valid_first(self):
        good = self.record()
        forged = copy.deepcopy(good)
        forged["signed"]["body"]["ike_payload"] = "Zm9yZ2Vk"
        # A compromised relay can produce an entirely new valid B capsule.
        seal = self.x2.seal_to("B", forged, "exchange-1", purpose="endpoint")
        opened = self.b.open_for_me(seal, "exchange-1", purpose="endpoint")
        before = self.b.state_path.read_bytes()
        self.assert_code("bad_signature", self.verify, opened)
        self.assert_code("unverified_message", self.b.admit, forged)
        self.assertEqual(self.b.state_path.read_bytes(), before)
        self.assertEqual(self.counts(), (0, 0))
        verified = self.verify(good)
        self.assertEqual(self.b.admit(verified), "new")
        self.assertTrue(self.b.claim_delivery(verified))
        self.b.delivered(verified)
        self.assertFalse(self.b.claim_delivery(verified))

    def test_one_and_three_identical_substitutions_in_fresh_recipient_capsules(self):
        for invalid in (1, 3, 9):
            for early in (True, False):
                context = f"attack-{invalid}-{int(early)}"
                authentic = [self.record(i, context=context) for i in range(9)]
                forged = []
                for original in authentic[:invalid]:
                    altered = copy.deepcopy(original)
                    altered["signed"]["body"]["ike_payload"] = "c2FtZS1mb3JnZXJ5"
                    # Sign with the attacker's real X2 key, while claiming A.
                    altered["signature"] = self.x2._signing.sign(mcc.canonical_json(altered["signed"])).hex()
                    forged.append(self.x2.seal_to("B", altered, context, purpose="endpoint"))
                valid = [self.a.seal_to("B", item, context, purpose="endpoint") for item in authentic[invalid:]]
                schedule = forged + valid if early else valid + forged
                accepted, rejected = [], 0
                for seal in schedule:
                    plain = self.b.open_for_me(seal, context, purpose="endpoint")
                    try:
                        verified = self.b.verify_signed(plain, context, expected_sender="A")
                    except mcc.MccSecurityError:
                        rejected += 1
                    else:
                        self.assertEqual(self.b.admit(verified), "new")
                        accepted.append(verified)
                self.assertEqual((len(accepted), rejected), (9 - invalid, invalid))
                if accepted:
                    self.assertTrue(self.b.claim_delivery(accepted[-1]))
                    self.b.delivered(accepted[-1])
                    self.assertTrue(all(not self.b.claim_delivery(item) for item in accepted))

    def test_nine_twenty_seven_and_sixty_four_copy_ids_share_freshness_and_fingerprint(self):
        for budget in (9, 27, 64):
            messages = []
            for copy_id in range(budget):
                body = dict(self.body, transport_conn=f"via-X2-{copy_id}")
                context = f"copies-{budget}"
                messages.append(self.b.verify_signed(self.record(copy_id, budget, context, body), context))
            self.assertEqual(len({message.fingerprint for message in messages}), 1)
            self.assertEqual(len({(message.nonce, message.issued, message.expires) for message in messages}), 1)
            for verified in reversed(messages):
                self.assertEqual(self.b.admit(verified), "new")
                self.assertEqual(self.b.admit(verified), "duplicate")
            self.assertTrue(self.b.claim_delivery(messages[0]))
            self.b.delivered(messages[0])

    def test_outer_branch_and_connection_metadata_cannot_increase_counts(self):
        record = self.record()
        for index in range(20):
            outer = {"branch_id": f"forged-{index}", "conn_id": f"other-{index}", "record": record}
            verified = self.verify(outer["record"])
            self.assertEqual(self.b.admit(verified), "new" if index == 0 else "duplicate")
        self.assertEqual(self.counts(), (1, 1))
        # The signed-record parser never silently accepts appended outer fields.
        self.assert_code("invalid_signed_record", self.verify, dict(record, branch_id="x"))

    def test_all_protected_fields_require_sender_signature(self):
        original = self.record()
        replacements = {"domain": "another-protocol", "version": 2, "sender": "X2", "receiver": "X1",
                        "key_id": "0" * 64, "context": "other", "direction": "reverse", "kind": "response",
                        "message_id": "1", "nonce": "0" * 32, "issued": self.now - 1, "expires": self.now + 119,
                        "expected_copies": 8, "copy_id": 1}
        for field, replacement in replacements.items():
            changed = copy.deepcopy(original)
            changed["signed"][field] = replacement
            with self.subTest(field=field), self.assertRaises(mcc.MccSecurityError):
                self.verify(changed)
        for field in ("ike_payload", "a_ke", "selection", "transport_conn"):
            changed = copy.deepcopy(original)
            changed["signed"]["body"][field] = "changed"
            with self.subTest(body=field):
                self.assert_code("bad_signature", self.verify, changed)

    def test_signature_unknown_revoked_and_expected_sender_are_rejected(self):
        record = self.record()
        self.assert_code("unexpected_sender", self.verify, record, expected_sender="X1")
        altered = copy.deepcopy(record)
        altered["signed"]["sender"] = "unknown"
        self.assert_code("unknown_node", self.verify, altered)
        altered = copy.deepcopy(record)
        altered["signature"] = "00" * 64
        self.assert_code("bad_signature", self.verify, altered)
        altered.pop("signature")
        self.assert_code("invalid_signed_record", self.verify, altered)
        nodes = copy.deepcopy(self.fixture.nodes)
        nodes["A"]["revoked"] = True
        revoked = self.endpoint("B", suffix="-revoked", registry=self.fixture.verified(version=2, nodes=nodes))
        self.assert_code("revoked_key", revoked.verify_signed, record, "exchange-1")
        self.assert_code("unverified_registry", mcc.EndpointSecurity, "B", self.fixture.nodes,
                         self.fixture.signing["B"], self.fixture.encryption["B"], Path(self.temp.name) / "bad.sqlite")

    def test_compromised_sender_cannot_poison_another_sender_with_same_context(self):
        malicious = self.x2.signed_message("B", "exchange-1", {"ike_payload": "wrong"}, 0, 1)
        attacker = self.verify(malicious)
        self.assertEqual(self.b.admit(attacker), "new")
        authentic = self.verify(self.record())
        self.assertNotEqual(attacker.message_key, authentic.message_key)
        self.assertEqual(self.b.admit(authentic), "new")
        self.assertTrue(self.b.claim_delivery(authentic))

    def test_correctly_signed_conflicts_are_rejected_but_path_variant_is_duplicate(self):
        original = self.record()
        verified = self.verify(original)
        self.b.admit(verified)
        for key, value in (("nonce", "0" * 32), ("expires", self.now + 119), ("expected_copies", 8)):
            changed = copy.deepcopy(original)
            changed["signed"][key] = value
            conflict = self.verify(self.resign(changed))
            self.assert_code("conflicting_message", self.b.admit, conflict)
        changed = copy.deepcopy(original)
        changed["signed"]["body"]["a_ke"] = "changed"
        self.assert_code("conflicting_message", self.b.admit, self.verify(self.resign(changed)))
        path = dict(self.body, transport_conn="another-path")
        variant = self.verify(self.record(body=path))
        self.assertEqual(variant.fingerprint, verified.fingerprint)
        self.assertEqual(self.b.admit(variant), "duplicate")
        self.assert_code("conflicting_message", self.record, body=dict(self.body, ike_length=5))

    def test_verified_body_is_deeply_immutable_and_detached(self):
        body = dict(self.body, nested={"list": [1, {"value": "original"}]})
        record = self.record(body=body)
        verified = self.verify(record)
        body["nested"]["list"][1]["value"] = "caller-changed"
        record["signed"]["body"]["nested"]["list"][1]["value"] = "wire-changed"
        with self.assertRaises(TypeError):
            verified.body["nested"]["list"][1]["value"] = "changed"
        detached = verified.body_dict()
        detached["nested"]["list"][1]["value"] = "changed"
        self.assertEqual(verified.body_dict()["nested"]["list"][1]["value"], "original")
        self.assertEqual(self.b.admit(verified), "new")

    def test_restart_preserves_delivered_and_in_flight_and_does_not_release_unknown_claim(self):
        record = self.record()
        verified = self.verify(record)
        self.b.admit(verified)
        self.assertTrue(self.b.claim_delivery(verified))
        restarted = self.endpoint("B")
        replay = restarted.verify_signed(record, "exchange-1")
        self.assertEqual(restarted.admit(replay), "delivered")
        self.assertFalse(restarted.claim_delivery(replay))
        self.assert_code("delivery_not_reserved_here", restarted.failed_delivery, replay)
        self.b.delivered(verified)
        restarted = self.endpoint("B")
        replay = restarted.verify_signed(record, "exchange-1")
        self.assertEqual(restarted.admit(replay), "delivered")
        self.assertFalse(restarted.claim_delivery(replay))

    def test_delivery_requires_admission_and_bounded_known_pre_injection_retry(self):
        record = self.record()
        verified = self.verify(record)
        self.assert_code("unadmitted_message", self.b.claim_delivery, verified)
        self.assert_code("delivery_not_reserved_here", self.b.failed_delivery, verified)
        self.b.admit(verified)
        self.assert_code("delivery_not_reserved", self.b.delivered, verified)
        for _ in range(mcc.MAX_DELIVERY_ATTEMPTS):
            self.assertTrue(self.b.claim_delivery(verified))
            self.assertFalse(self.b.claim_delivery(verified))
            self.b.failed_delivery(verified)
        self.assertFalse(self.b.claim_delivery(verified))

    def test_two_instances_cannot_both_claim_delivery(self):
        record = self.record()
        verified = self.verify(record)
        self.b.admit(verified)
        other = self.endpoint("B")
        replay = other.verify_signed(record, "exchange-1")
        with ThreadPoolExecutor(max_workers=2) as workers:
            futures = [workers.submit(endpoint.claim_delivery, message)
                       for endpoint, message in ((self.b, verified), (other, replay))]
            self.assertEqual(sorted(future.result() for future in futures), [False, True])

    def test_reverse_responses_are_authenticated_and_bound_to_request(self):
        request = self.verify(self.record())
        body = {"request_digest": request.fingerprint, "bke": "b" * 64, "success": True}
        record = self.b.signed_message("A", "exchange-1", body, 0, 1, direction="reverse", kind="response")
        cap = self.b.seal_to("A", record, "exchange-1", purpose="endpoint")
        opened = self.a.open_for_me(cap, "exchange-1", purpose="endpoint")
        response = self.a.verify_signed(opened, "exchange-1", expected_sender="B", direction="reverse", kind="response")
        self.assertEqual(response.body["request_digest"], request.fingerprint)
        self.assertEqual(self.a.admit(response), "new")
        self.assertTrue(self.a.claim_delivery(response))
        self.a.delivered(response)
        self.assertEqual(self.a.admit(response), "delivered")
        record["signed"]["body"]["bke"] = "attacker-key"
        fresh = self.x2.seal_to("A", record, "exchange-1", purpose="endpoint")
        opened = self.a.open_for_me(fresh, "exchange-1", purpose="endpoint")
        self.assert_code("bad_signature", self.a.verify_signed, opened, "exchange-1", direction="reverse", kind="response")
        self.assert_code("wrong_message_scope", self.a.verify_signed, record, "exchange-1", kind="response")

    def test_lifetime_skew_expiry_and_clock_rollback(self):
        original = self.record()
        for issued, expires in ((self.now, self.now + 121), (self.now + 6, self.now + 120),
                                (self.now - 126, self.now - 6), (self.now, self.now)):
            changed = copy.deepcopy(original)
            changed["signed"].update(issued=issued, expires=expires)
            self.assert_code("expired_or_future_message", self.verify, self.resign(changed))
        verified = self.verify(original)
        self.b.admit(verified)
        self.b.claim_delivery(verified)
        self.b.delivered(verified)
        self.now += mcc.MAX_LIFETIME + mcc.CLOCK_SKEW
        self.assertEqual(self.b.admit(self.verify(original)), "delivered")
        self.now += 1
        self.assert_code("expired_or_future_message", self.verify, original)
        fresh = self.record(context="fresh-after-expiry")
        self.assertEqual(self.b.admit(self.verify(fresh, context="fresh-after-expiry")), "new")
        self.now -= mcc.MAX_LIFETIME + mcc.CLOCK_SKEW + 1
        self.assert_code("clock_rollback", self.b.admit, self.verify(original))
        self.assert_code("clock_rollback", self.endpoint, "B")

    def test_resource_caps_and_expiry_reclamation(self):
        records = [self.record(context=f"cap-{i}") for i in range(3)]
        with patch.object(mcc, "MAX_EXCHANGES", 2):
            for i in range(2):
                self.b.admit(self.verify(records[i], context=f"cap-{i}"))
            self.assert_code("receiver_capacity", self.b.admit, self.verify(records[2], context="cap-2"))
            self.now += mcc.MAX_LIFETIME + mcc.CLOCK_SKEW + 1
            renewed = self.record(context="renewed")
            self.assertEqual(self.b.admit(self.verify(renewed, context="renewed")), "new")
            self.assertEqual(self.counts(), (1, 1))
        sender = self.endpoint("A", suffix="-signer-cap")
        with patch.object(mcc, "MAX_EXCHANGES", 2):
            for i in range(2):
                sender.signed_message("B", f"signer-{i}", {}, 0, 1)
            self.assert_code("signer_capacity", sender.signed_message, "B", "signer-2", {}, 0, 1)
        self.assert_code("invalid_integer", self.record, expected=65)
        self.assert_code("invalid_integer", self.record, copy_id=True)
        self.assert_code("invalid_integer", self.record, copy_id=9)

    def test_strict_json_limits_and_duplicate_keys(self):
        original = self.record()
        raw = mcc.canonical_json(original)
        duplicate = raw.replace(b'"copy_id":0', b'"copy_id":0,"copy_id":0', 1)
        self.assert_code("duplicate_json_key", self.verify, duplicate)
        seal = self.a.seal_to("B", {}, "exchange-1")
        duplicate = mcc.canonical_json(seal).replace(b'"v":1', b'"v":1,"v":1')
        self.assert_code("duplicate_json_key", self.b.open_for_me, duplicate, "exchange-1")
        bad_json = (b'{"x":1.0}', b'{"x":NaN}', b'{"x":Infinity}', b'{"x":9999999999999999999999999}',
                    b'{"x":"\xff"}', b'{"x":"\\ud800"}')
        for raw in bad_json:
            with self.subTest(raw=raw), self.assertRaises(mcc.MccSecurityError):
                mcc.strict_json_loads(raw)
        deep = {}
        for _ in range(mcc.MAX_DEPTH + 1):
            deep = {"n": deep}
        for body in ({"float": 1.1}, {"big": "x" * mcc.MAX_BODY_BYTES}, deep,
                     {str(i): i for i in range(mcc.MAX_FIELDS + 1)}, {"list": [0] * (mcc.MAX_ITEMS + 1)}):
            with self.assertRaises(mcc.MccSecurityError):
                self.record(context="invalid-json", body=body)
        self.assertEqual(self.counts(), (0, 0))

    def test_state_identity_corruption_and_size_fail_closed(self):
        verified = self.verify(self.record())
        self.assert_code("state_identity_mismatch", mcc.EndpointSecurity, "A", self.registry,
                         self.fixture.signing["A"], self.fixture.encryption["A"], self.b.state_path,
                         clock=lambda: self.now)
        with patch.object(mcc, "MAX_LEDGER_BYTES", 1):
            self.assert_code("state_resource_limit", self.b.admit, verified)
        self.b.state_path.write_bytes(b"not a database")
        self.assert_code("state_unavailable", self.b.admit, verified)

    def test_concurrent_verification_capacity_releases_without_state_mutation(self):
        record = self.record()
        seal = self.a.seal_to("B", record, "exchange-1", purpose="endpoint")
        for _ in range(mcc.MAX_CONCURRENT_CHECKS):
            self.assertTrue(self.b._verification_slots.acquire(blocking=False))
        try:
            self.assert_code("verification_capacity", self.verify, record)
            self.assert_code("verification_capacity", self.b.open_for_me, seal, "exchange-1", purpose="endpoint")
            self.assertEqual(self.counts(), (0, 0))
        finally:
            for _ in range(mcc.MAX_CONCURRENT_CHECKS):
                self.b._verification_slots.release()
        self.assertEqual(self.verify(record).sender, "A")

    @unittest.skipUnless(os.name == "posix", "requires native POSIX ownership and modes")
    def test_linux_private_key_permissions_require_owner_and_0600(self):
        private = Path(self.temp.name) / "private.key"
        private.write_text("00" * 32, encoding="ascii")
        private.chmod(0o644)
        self.assert_code("private_file_permissions", mcc._read_private, str(private))
        private.chmod(0o600)
        self.assertEqual(mcc._read_private(str(private)), bytes(32))

    def test_environment_loads_only_individual_keys_and_rejects_legacy_fallback(self):
        live = Path(self.temp.name) / "registry.json"
        live.write_bytes(self.fixture.raw())
        sign, enc = (Path(self.temp.name) / item for item in ("B.ed25519", "B.x25519"))
        sign.write_text(self.fixture.signing["B"].private_bytes_raw().hex(), encoding="ascii")
        enc.write_text(self.fixture.encryption["B"].private_bytes_raw().hex(), encoding="ascii")
        if os.name != "nt":
            sign.chmod(0o600)
            enc.chmod(0o600)
        env = {"MCC_SIGNING_KEY_FILE": str(sign), "MCC_ENCRYPTION_KEY_FILE": str(enc),
               "MCC_REPLAY_STATE_FILE": str(Path(self.temp.name) / "B-env.sqlite"),
               "IKE_CASCADE_TRUST_REGISTRY_FILE": str(live), "IKE_CASCADE_TRUST_ROOT_FILE": str(self.fixture.root_path)}
        with patch.dict(os.environ, env, clear=True):
            loaded = mcc.EndpointSecurity.from_environment("B", self.fixture.names)
            self.assertEqual(loaded.key_id, self.registry.nodes["B"]["key_id"])
        with patch.dict(os.environ, {"IKE_CASCADE_PRIVATE_KEY_HEX": self.fixture.encryption["B"].private_bytes_raw().hex()}, clear=True):
            self.assert_code("missing_endpoint_configuration", mcc.EndpointSecurity.from_environment, "B", self.fixture.names)
        sign.write_text(self.fixture.signing["A"].private_bytes_raw().hex(), encoding="ascii")
        with patch.dict(os.environ, env, clear=True):
            self.assert_code("private_key_mismatch", mcc.EndpointSecurity.from_environment, "B", self.fixture.names)


if __name__ == "__main__":
    unittest.main()
