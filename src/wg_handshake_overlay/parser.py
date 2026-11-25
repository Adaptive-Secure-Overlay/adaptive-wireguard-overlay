from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from struct import unpack_from


class WireGuardMessageType(IntEnum):
    HANDSHAKE_INITIATION = 1
    HANDSHAKE_RESPONSE = 2
    COOKIE_REPLY = 3
    TRANSPORT_DATA = 4


_EXACT_SIZES = {
    WireGuardMessageType.HANDSHAKE_INITIATION: 148,
    WireGuardMessageType.HANDSHAKE_RESPONSE: 92,
    WireGuardMessageType.COOKIE_REPLY: 64,
}


@dataclass(frozen=True, slots=True)
class WireGuardPacket:
    message_type: WireGuardMessageType
    name: str
    size: int
    sender_index: int | None
    receiver_index: int | None

    @property
    def is_handshake_control(self) -> bool:
        return self.message_type is not WireGuardMessageType.TRANSPORT_DATA

    @property
    def is_transport(self) -> bool:
        return self.message_type is WireGuardMessageType.TRANSPORT_DATA


def parse_packet(packet: bytes) -> WireGuardPacket:
    """Validate only public WireGuard framing; never decrypt or log payloads."""
    if not isinstance(packet, bytes):
        raise TypeError("packet must be bytes")
    if len(packet) < 4:
        raise ValueError("packet is shorter than WireGuard header")

    try:
        message_type = WireGuardMessageType(packet[0])
    except ValueError as exc:
        raise ValueError("unknown WireGuard message type") from exc
    if packet[1:4] != b"\x00\x00\x00":
        raise ValueError("WireGuard reserved bytes must be zero")

    expected = _EXACT_SIZES.get(message_type)
    if expected is not None and len(packet) != expected:
        raise ValueError(f"WireGuard type {int(message_type)} must be {expected} bytes")
    if message_type is WireGuardMessageType.TRANSPORT_DATA and (
        len(packet) < 32 or len(packet) % 16
    ):
        raise ValueError("WireGuard transport packet must be at least 32 bytes and a multiple of 16")

    sender_index: int | None = None
    receiver_index: int | None = None
    if message_type is WireGuardMessageType.HANDSHAKE_INITIATION:
        sender_index = unpack_from("<I", packet, 4)[0]
    elif message_type is WireGuardMessageType.HANDSHAKE_RESPONSE:
        sender_index = unpack_from("<I", packet, 4)[0]
        receiver_index = unpack_from("<I", packet, 8)[0]
    else:
        receiver_index = unpack_from("<I", packet, 4)[0]

    return WireGuardPacket(
        message_type=message_type,
        name=message_type.name,
        size=len(packet),
        sender_index=sender_index,
        receiver_index=receiver_index,
    )
