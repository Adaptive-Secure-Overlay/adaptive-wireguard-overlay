import unittest

from wg_handshake_overlay.parser import WireGuardMessageType, parse_packet


def packet(kind, size, reserved=b"\0\0\0", sender_index=0x78563412, receiver_index=0xEFCDAB90):
    data = bytearray(size)
    if size >= 1:
        data[0] = kind
    if size >= 4:
        data[1:4] = reserved
    if size >= 8:
        data[4:8] = sender_index.to_bytes(4, "little")
    if kind == 2 and size >= 12:
        data[8:12] = receiver_index.to_bytes(4, "little")
    return bytes(data)


class ParserTests(unittest.TestCase):
    def test_valid_sizes_and_types(self):
        for kind, size in ((1, 148), (2, 92), (3, 64), (4, 32), (4, 48)):
            self.assertEqual(parse_packet(packet(kind, size)).message_type, kind)

    def test_indices_are_metadata_not_reserved_bytes(self):
        initiation = parse_packet(packet(1, 148))
        response = parse_packet(packet(2, 92))
        transport = parse_packet(packet(4, 32))
        self.assertEqual(initiation.message_type, WireGuardMessageType.HANDSHAKE_INITIATION)
        self.assertEqual(initiation.sender_index, 0x78563412)
        self.assertIsNone(initiation.receiver_index)
        self.assertEqual(response.receiver_index, 0xEFCDAB90)
        self.assertEqual(transport.receiver_index, 0x78563412)

    def test_invalid_framing_fails_closed(self):
        bad_packets = (
            b"",
            packet(5, 8),
            packet(1, 147),
            packet(4, 33),
            packet(2, 92, b"bad"),
        )
        for bad in bad_packets:
            with self.subTest(size=len(bad)):
                with self.assertRaises((TypeError, ValueError)):
                    parse_packet(bad)
