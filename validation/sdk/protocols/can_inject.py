"""CAN Inject protocol — UDP port 4000, little-endian 8-byte header + payload.

Wire format:
  Byte 0   Magic = 0xCA
  Byte 1   Channel (0=FDCAN1, 1=FDCAN2)
  Byte 2   Flags bitmask
  Byte 3   DataLen (0-64)
  Byte 4-7 CAN ID, uint32 little-endian
  Byte 8+  Payload (DataLen bytes)
"""

import socket
import struct
from dataclasses import dataclass, field
from typing import Optional

INJECT_UDP_PORT = 4000
INJECT_MAGIC    = 0xCA

INJECT_FLAG_EXT   = 0x01  # 29-bit extended ID
INJECT_FLAG_J1939 = 0x02  # J1939 informational tag
INJECT_FLAG_FD    = 0x04  # CAN FD frame
INJECT_FLAG_BRS   = 0x08  # Bit-rate switching (FD only)

_HEADER = struct.Struct("<BBBBI")  # magic, channel, flags, datalen, can_id


@dataclass
class CANFrame:
    can_id: int
    data: bytes = b""
    channel: int = 0
    extended: bool = False
    fd: bool = False
    brs: bool = False
    j1939: bool = False

    def flags(self) -> int:
        f = 0
        if self.extended: f |= INJECT_FLAG_EXT
        if self.j1939:    f |= INJECT_FLAG_J1939
        if self.fd:       f |= INJECT_FLAG_FD
        if self.brs:      f |= INJECT_FLAG_BRS
        return f


class CANInject:
    """Send CAN frames to the gateway via UDP CAN-inject protocol."""

    def __init__(self, host: str, port: int = INJECT_UDP_PORT):
        self._host = host
        self._port = port
        self._sock: Optional[socket.socket] = None

    def open(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def close(self) -> None:
        if self._sock:
            self._sock.close()
            self._sock = None

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, *_):
        self.close()

    def send(self, frame: CANFrame) -> None:
        """Send one CAN frame."""
        if self._sock is None:
            raise RuntimeError("CANInject not opened. Call open() first.")
        payload = bytes(frame.data)[:64]
        header = _HEADER.pack(
            INJECT_MAGIC,
            frame.channel & 0xFF,
            frame.flags(),
            len(payload),
            frame.can_id & 0x1FFFFFFF,
        )
        self._sock.sendto(header + payload, (self._host, self._port))

    def send_raw(self, can_id: int, data: bytes, channel: int = 0,
                 extended: bool = False) -> None:
        """Convenience: send a raw CAN frame."""
        self.send(CANFrame(can_id=can_id, data=data, channel=channel,
                           extended=extended))

    def send_j1939(self, pgn: int, sa: int, data: bytes,
                   priority: int = 6, da: int = 0xFF,
                   channel: int = 0) -> None:
        """Convenience: build and send a J1939 frame.

        Args:
            pgn: Parameter Group Number (18-bit)
            sa: Source Address (0-253)
            data: Payload bytes (0-8)
            priority: J1939 priority 0-7 (default 6)
            da: Destination address for PDU1 PGNs (PF < 0xF0).
                0xFF = broadcast / PDU2 global.
            channel: 0=FDCAN1, 1=FDCAN2
        """
        can_id = _build_j1939_id(pgn, sa, da, priority)
        self.send(CANFrame(can_id=can_id, data=data, channel=channel,
                           extended=True, j1939=True))


def _build_j1939_id(pgn: int, sa: int, da: int, priority: int) -> int:
    pf = (pgn >> 8) & 0xFF
    if pf < 0xF0:
        # PDU1: PS field = DA
        ps = da & 0xFF
        pgn_base = pgn & 0x3FF00  # clear PS
    else:
        # PDU2: PS field = Group Extension (embedded in PGN)
        ps = pgn & 0xFF
        pgn_base = pgn & 0x3FF00
    dp  = (pgn >> 17) & 0x01
    can_id = ((priority & 0x7) << 26) | (dp << 24) | (pf << 16) | (ps << 8) | (sa & 0xFF)
    return can_id
