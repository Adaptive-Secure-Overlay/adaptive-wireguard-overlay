import unittest

from wg_handshake_overlay.engine import HandshakeOverlayEngine
from wg_handshake_overlay.models import Endpoint, OverlayEnvelope
from wg_handshake_overlay.routing import RouteCache


def packet(kind, size, index=1):
    data = bytearray(size)
    data[0] = kind
    data[4:8] = index.to_bytes(4, "little")
    if kind == 2:
        data[8:12] = (index + 1).to_bytes(4, "little")
    return bytes(data)


class EngineTests(unittest.TestCase):
    def setUp(self):
        self.a = Endpoint("A", 51820)
        self.b = Endpoint("B", 51820)
        self.x1 = Endpoint("X1", 51820)
        self.x2 = Endpoint("X2", 51820)
        self.cache = RouteCache(5)
        self.engine = HandshakeOverlayEngine(self.cache, (self.x1, self.x2))

    def test_control_routes_and_reverse_route_are_deterministic(self):
        event = self.engine.capture(self.a, self.b, packet(1, 148), 0)[0]
        self.assertEqual(event.kind, "OVERLAY_FRAME")
        self.assertEqual(event.next_hop, "X1:51820")
        self.assertEqual(event.route, ())
        self.assertEqual(
            tuple(node.host for node in self.cache.get(self.a, self.b, 0).nodes),
            ("A", "X1", "X2", "B"),
        )
        self.assertEqual(
            tuple(node.host for node in self.cache.get(self.b, self.a, 0).nodes),
            ("B", "X2", "X1", "A"),
        )

    def test_transport_bypasses_and_invalid_drops(self):
        self.assertEqual(self.engine.capture(self.a, self.b, packet(4, 32), 0)[0].kind, "DIRECT_BYPASS")
        self.assertEqual(self.engine.capture(self.a, self.b, b"bad", 0)[0].kind, "INVALID_DROP")

    def test_type_four_cannot_be_forced_into_overlay(self):
        route = self.cache.establish(self.a, (self.x1, self.x2), self.b, 0)
        data = packet(4, 32)
        envelope = OverlayEnvelope(self.engine.fingerprint(data, self.a, self.b), route, 1, data)
        self.assertEqual(self.engine.forward(envelope, 0)[0].kind, "INVALID_DROP")

    def test_duplicate_expiry_injection_and_privacy(self):
        data = packet(2, 92)
        first = self.engine.capture(self.a, self.b, data, 0)[0]
        self.assertEqual(first.kind, "OVERLAY_FRAME")
        route = self.cache.get(self.a, self.b, 0)

        x1_envelope = OverlayEnvelope(self.engine.fingerprint(data, self.a, self.b), route, 1, data)
        x1_view = self.engine.relay_view(x1_envelope)
        self.assertIsNone(x1_view.final_endpoint)
        self.assertEqual(x1_view.next_hop, self.x2)
        self.assertNotIn("host='B'", repr(x1_view))

        x2_envelope = OverlayEnvelope(self.engine.fingerprint(data, self.a, self.b), route, 2, data)
        self.assertEqual(self.engine.advance(x2_envelope, 0)[0].kind, "INJECT")
        self.assertEqual(self.engine.capture(self.a, self.b, data, 0)[0].kind, "DUPLICATE_DROP")
        self.assertEqual(self.engine.capture(self.a, self.b, packet(3, 64), 6)[0].kind, "OVERLAY_FRAME")

    def test_expired_envelope_is_dropped(self):
        data = packet(1, 148)
        self.engine.capture(self.a, self.b, data, 0)
        route = self.cache.get(self.a, self.b, 0)
        envelope = OverlayEnvelope(self.engine.fingerprint(data, self.a, self.b), route, 1, data)
        self.assertEqual(self.engine.forward(envelope, 6)[0].kind, "EXPIRED_DROP")
