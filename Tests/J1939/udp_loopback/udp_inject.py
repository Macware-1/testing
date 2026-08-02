"""
udp_inject.py — UDP-based CAN inject + CLOG receive helpers.

Replaces TecmpBusCompat / python-can for the J1939 loopback test suite.
No hardware CAN adapter or capture module required.

Inject direction:
  UdpInjector.send()  →  UDP port 4000  →  gateway FDCAN2 TX  →  CAN bus
                                                ↓ (physical wire)
                                         gateway FDCAN1 RX  →  J1939 library  →  CLOG ch1

Gateway-generated frames (address claim, PGN replies):
  gateway FDCAN1 TX  →  CAN bus  →  FDCAN2 RX  →  CLOG ch2 (TYPE_RAW_CAN)
  Received by ClogListener.recv_until().
"""

import os
import socket
import struct
import sys
import time

# ── Import shared J1939 utilities from parent folder ─────────────────────────
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from j1939_utils import (
    decode_clog, decode_j1939_id,
    CLOG_UDP_PORT, CLOG_TYPE_RAW_CAN, CLOG_TYPE_J1939, CLOG_TYPE_STATUS,
)

# ── Inject protocol constants ────────────────────────────────────────────────
INJECT_MAGIC      = 0xCA
INJECT_FLAG_EXT   = 0x01   # 29-bit extended ID
INJECT_FLAG_J1939 = 0x02   # informational J1939 tag (implies EXT)
INJECT_HDR_SIZE   = 8
UDP_INJECT_PORT   = 4000


# ── UdpInjector ──────────────────────────────────────────────────────────────

class UdpInjector:
    """Drop-in for python-can / TecmpBusCompat.

    Sends J1939 frames via the gateway's UDP inject API.
    Always uses INJECT_FLAG_EXT | INJECT_FLAG_J1939 (J1939 = 29-bit extended).

    Parameters
    ----------
    gw_ip   : gateway IP address
    channel : inject channel  0 = FDCAN1 TX  |  1 = FDCAN2 TX  (default 1)
    """

    def __init__(self, gw_ip: str, channel: int = 1):
        self.gw_ip   = gw_ip
        self.channel = channel
        self._sock   = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def send(self, msg) -> None:
        """Send a CanMessage (from j1939_utils) via UDP inject.

        Accepts duck-typed objects with attributes:
          arbitration_id : 29-bit CAN ID (without EXT_FLAG bit)
          data           : bytes-like payload
        """
        can_id   = int(msg.arbitration_id) & 0x1FFFFFFF
        payload  = bytes(msg.data)[:64]
        flags    = INJECT_FLAG_EXT | INJECT_FLAG_J1939
        pkt      = (struct.pack('<BBBBl', INJECT_MAGIC, self.channel,
                                flags, len(payload), can_id)
                    + payload)
        self._sock.sendto(pkt, (self.gw_ip, UDP_INJECT_PORT))

    def set_filters(self, filters) -> None:
        pass   # inject-only; no RX on this socket

    def shutdown(self) -> None:
        self._sock.close()


# ── ClogListener ─────────────────────────────────────────────────────────────

class ClogListener:
    """UDP socket that receives and decodes CLOG v2 frames.

    Open a listener, call recv_until() with a predicate, then close().

    Example — wait for a J1939 frame with SA=0x80 and PGN=0xEE00::

        with ClogListener() as cl:
            f = cl.recv_until(
                lambda f: (f['type'] == CLOG_TYPE_J1939
                           and f.get('sa') == 0x80
                           and f.get('pgn') == 0xEE00),
                deadline=time.monotonic() + 5.0
            )
    """

    def __init__(self, port: int = CLOG_UDP_PORT, rx_buf: int = 2048):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except AttributeError:
            pass
        self._sock.settimeout(0.1)
        self._sock.bind(('', port))
        self._rx_buf = rx_buf

    def recv_until(self, predicate, deadline: float):
        """Receive CLOG frames until predicate(frame) is True or deadline passes.

        Returns the matching frame dict, or None on timeout.
        Skips STATUS frames unless predicate accepts them.
        """
        while time.monotonic() < deadline:
            try:
                raw, _ = self._sock.recvfrom(self._rx_buf)
            except socket.timeout:
                continue
            except OSError:
                break
            f = decode_clog(raw)
            if f is None:
                continue
            if predicate(f):
                return f
        return None

    def recv_all_until(self, predicate, deadline: float) -> list:
        """Collect all frames matching predicate until deadline."""
        found = []
        while time.monotonic() < deadline:
            try:
                raw, _ = self._sock.recvfrom(self._rx_buf)
            except socket.timeout:
                continue
            except OSError:
                break
            f = decode_clog(raw)
            if f and predicate(f):
                found.append(f)
        return found

    def close(self) -> None:
        self._sock.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


# ── Helpers shared across tests ───────────────────────────────────────────────

def is_j1939_type(f: dict) -> bool:
    return f.get('type') == CLOG_TYPE_J1939

def is_raw_type(f: dict) -> bool:
    return f.get('type') == CLOG_TYPE_RAW_CAN

def raw_frame_j1939(f: dict) -> dict:
    """Decode J1939 fields from a TYPE_RAW_CAN CLOG frame (e.g. FDCAN2 RX)."""
    return decode_j1939_id(f['can_id'])
