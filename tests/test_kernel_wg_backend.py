from __future__ import annotations

import socket
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "linux-kernel-wg-backend"))

from wan_py_wg_daemon import (  # noqa: E402
    build_wg_correlation_header,
    is_wg_control_payload,
    udp_ipv4_checksum,
)


def _make_wg_type1(sender_index: int) -> bytes:
    return struct.pack("<B3xI", 1, sender_index) + b"\x11" * (148 - 8)


def _make_wg_type2(sender_index: int, receiver_index: int) -> bytes:
    return struct.pack("<B3xII", 2, sender_index, receiver_index) + b"\x22" * (92 - 12)


def _make_wg_type3(receiver_index: int) -> bytes:
    return struct.pack("<B3xI", 3, receiver_index) + b"\x33" * (64 - 8)


def _make_wg_type4(receiver_index: int, counter: int = 0) -> bytes:
    return struct.pack("<B3xIQ", 4, receiver_index, counter) + b"\x44" * 32


class KernelWgBackendTests(unittest.TestCase):
    def test_control_filter_accepts_only_types_1_2_3_on_wg_port(self) -> None:
        self.assertTrue(is_wg_control_payload(4500, _make_wg_type1(0x11223344)))
        self.assertTrue(is_wg_control_payload(4500, _make_wg_type2(0x55667788, 0x11223344)))
        self.assertTrue(is_wg_control_payload(4500, _make_wg_type3(0x11223344)))

        # Type 4 transport data must NEVER enter the overlay
        self.assertFalse(is_wg_control_payload(4500, _make_wg_type4(0x11223344)))
        # Wrong port or malformed/truncated frames rejected fail-closed
        self.assertFalse(is_wg_control_payload(500, _make_wg_type1(0x11223344)))
        self.assertFalse(is_wg_control_payload(4500, b"\x01\x00\x00\x00" + b"\x00" * 10))
        self.assertFalse(is_wg_control_payload(4500, b"\x00\x00\x00\x00" + b"\x00" * 144))

    def test_correlation_header_links_type1_and_type2_indices(self) -> None:
        idx = 0xDEADBEEF
        h1 = build_wg_correlation_header(_make_wg_type1(idx), 4500)
        h2 = build_wg_correlation_header(_make_wg_type2(0x01020304, idx), 4500)
        h3 = build_wg_correlation_header(_make_wg_type3(idx), 4500)

        self.assertEqual(len(h1), 28)
        self.assertEqual(len(h2), 28)
        self.assertEqual(len(h3), 28)

        # Initiator SPI and message_id match across request (Type 1) and responses (Type 2/3)
        self.assertEqual(h1[:8], h2[:8])
        self.assertEqual(h1[:8], h3[:8])
        self.assertEqual(h1[20:24], h2[20:24])
        self.assertEqual(h1[20:24], h3[20:24])

        # Response bit (0x20) is clear on Type 1, set on Type 2 and Type 3
        self.assertEqual(h1[19] & 0x20, 0x00)
        self.assertEqual(h2[19] & 0x20, 0x20)
        self.assertEqual(h3[19] & 0x20, 0x20)

        # Separate PFS rekey with a fresh sender_index produces a distinct SPI/message_id
        h1_rekey = build_wg_correlation_header(_make_wg_type1(0xCAFEBABE), 4500)
        self.assertNotEqual(h1[:8], h1_rekey[:8])

    def test_correlation_header_rejects_type4_and_wrong_port(self) -> None:
        with self.assertRaises(ValueError):
            build_wg_correlation_header(_make_wg_type4(0x11223344), 4500)
        with self.assertRaises(ValueError):
            build_wg_correlation_header(_make_wg_type1(0x11223344), 500)

    def test_rfc768_udp_ipv4_checksum_verifies_to_all_ones(self) -> None:
        src = socket.inet_aton("192.0.2.10")
        dst = socket.inet_aton("198.51.100.10")
        payload = _make_wg_type1(0x12345678)
        udp_len = 8 + len(payload)
        udp_zero = struct.pack("!HHHH", 4500, 4500, udp_len, 0)
        csum = udp_ipv4_checksum(src, dst, udp_zero, payload)
        self.assertNotEqual(csum, 0)

        # Re-summing pseudo-header + UDP header (with computed csum) + payload yields 0xFFFF
        udp_full = struct.pack("!HHHH", 4500, 4500, udp_len, csum)
        pseudo = src + dst + struct.pack("!BBH", 0, socket.IPPROTO_UDP, udp_len)
        data = pseudo + udp_full + payload
        if len(data) % 2:
            data += b"\x00"
        total = 0
        for i in range(0, len(data), 2):
            total += (data[i] << 8) + data[i + 1]
            total = (total & 0xFFFF) + (total >> 16)
        self.assertEqual(total, 0xFFFF)


if __name__ == "__main__":
    unittest.main()
