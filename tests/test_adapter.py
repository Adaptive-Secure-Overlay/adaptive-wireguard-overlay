import tempfile
import unittest

from trust_registry_support import EphemeralOpenSshSigner, node_keys, wireguard_key
from wg_handshake_overlay.adapter import WgProxyAdapter
from wg_handshake_overlay.models import Endpoint
from wg_handshake_overlay.trust_registry import TrustAnchor, TrustedRegistryStore


def packet(kind, size, index=1):
    data = bytearray(size)
    data[0] = kind
    data[4:8] = index.to_bytes(4, "little")
    if kind == 2:
        data[8:12] = (index + 1).to_bytes(4, "little")
    return bytes(data)


class FakeDaemon:
    def __init__(self):
        self.calls = []

    def send_protocol_datagram(self, **kwargs):
        self.calls.append(kwargs)


class AdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.signer = EphemeralOpenSshSigner()

    @classmethod
    def tearDownClass(cls):
        cls.signer.close()

    def setUp(self):
        self.state = tempfile.TemporaryDirectory(prefix="wg-adapter-registry-")
        self.addCleanup(self.state.cleanup)
        self.nodes = node_keys("A", "B")
        registry = TrustedRegistryStore(
            self.state.name,
            trust_anchor=TrustAnchor("root-test-1", self.signer.public_key),
            registry_id="candidate-wireguard-nodes",
        )
        registry.apply_update(
            self.signer.document(
                registry_id="candidate-wireguard-nodes",
                version=1,
                nodes=self.nodes,
            )
        )
        self.daemon = FakeDaemon()
        self.adapter = WgProxyAdapter(self.daemon, registry)
        self.a = Endpoint("192.0.2.10", 51820)
        self.b = Endpoint("192.0.2.20", 51820)

    def test_control_is_sent_as_opaque_overlay_payload(self):
        payload = packet(1, 148, 42)
        result = self.adapter.capture_datagram(
            payload=payload,
            source=self.a,
            destination=self.b,
            source_node="A",
            destination_node="B",
            capture_id="case-001",
        )
        self.assertEqual(result.action, "OVERLAY")
        self.assertEqual(len(self.daemon.calls), 1)
        self.assertEqual(self.daemon.calls[0]["protocol"], "wireguard")
        self.assertEqual(self.daemon.calls[0]["peer_user"], "B")
        self.assertEqual(self.daemon.calls[0]["peer_public_key"], self.nodes["B"])
        self.assertEqual(self.daemon.calls[0]["meta"]["registry_version"], 1)
        self.assertIs(self.daemon.calls[0]["payload"], payload)

    def test_transport_never_enters_overlay(self):
        result = self.adapter.capture_datagram(
            payload=packet(4, 32),
            source=self.a,
            destination=self.b,
            source_node="A",
            destination_node="B",
            capture_id="case-002",
        )
        self.assertEqual(result.action, "DIRECT_BYPASS")
        self.assertEqual(self.daemon.calls, [])

    def test_substituted_remote_key_is_dropped_before_daemon(self):
        result = self.adapter.capture_datagram(
            payload=packet(1, 148),
            source=self.a,
            destination=self.b,
            source_node="A",
            destination_node="B",
            destination_public_key=wireguard_key(99),
            capture_id="case-substitution",
        )
        self.assertEqual(result.action, "DROP")
        self.assertEqual(result.reason, "untrusted node registry binding")
        self.assertEqual(self.daemon.calls, [])

    def test_missing_signed_registry_is_dropped_before_daemon(self):
        empty_state = tempfile.TemporaryDirectory(prefix="wg-adapter-empty-registry-")
        self.addCleanup(empty_state.cleanup)
        empty_registry = TrustedRegistryStore(
            empty_state.name,
            trust_anchor=TrustAnchor("root-test-1", self.signer.public_key),
            registry_id="candidate-wireguard-nodes",
        )
        daemon = FakeDaemon()
        adapter = WgProxyAdapter(daemon, empty_registry)
        result = adapter.capture_datagram(
            payload=packet(1, 148),
            source=self.a,
            destination=self.b,
            source_node="A",
            destination_node="B",
            destination_public_key=wireguard_key(99),
            capture_id="case-missing-registry",
        )
        self.assertEqual(result.action, "DROP")
        self.assertEqual(result.reason, "untrusted node registry binding")
        self.assertEqual(daemon.calls, [])

    def test_delivery_revalidates_type_and_metadata(self):
        payload = packet(2, 92)
        captured = self.adapter.capture_datagram(
            payload=payload,
            source=self.b,
            destination=self.a,
            source_node="B",
            destination_node="A",
            capture_id="case-003",
        )
        self.assertEqual(captured.action, "OVERLAY")
        meta = self.daemon.calls[-1]["meta"]
        request = self.adapter.deliver_protocol_datagram(protocol="wireguard", payload=payload, meta=meta)
        self.assertEqual(request.source, self.b)
        self.assertEqual(request.destination, self.a)
        self.assertEqual(request.registry_version, 1)
        self.assertEqual(request.destination_public_key, self.nodes["A"])
        self.assertNotIn(payload.hex(), repr(request))

        bad_meta = dict(meta, wg_message_type=1)
        with self.assertRaises(ValueError):
            self.adapter.deliver_protocol_datagram(protocol="wireguard", payload=payload, meta=bad_meta)
        with self.assertRaises(ValueError):
            self.adapter.deliver_protocol_datagram(protocol="wireguard", payload=packet(4, 32), meta=meta)

        stale_meta = dict(meta, registry_version=0)
        with self.assertRaises(ValueError):
            self.adapter.deliver_protocol_datagram(protocol="wireguard", payload=payload, meta=stale_meta)
