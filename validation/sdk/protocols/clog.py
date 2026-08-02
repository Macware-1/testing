"""CLOG v2 receiver — UDP port 47808, big-endian binary protocol.

Common header (28 bytes, all multi-byte fields big-endian):
  0-3   Magic "CLOG"
  4     Version (2)
  5     Message type (0=STATUS, 1=RAW_CAN, 2=J1939)
  6     Channel ID
  7     Flags (CLOG_FLAG_*)
  8-11  Sequence (BE uint32)
 12-15  Timestamp seconds (BE uint32, PTP TAI)
 16-19  Timestamp nanoseconds (BE uint32)
 20-23  CAN ID (BE uint32, 29-bit)
  24    DLC
 25-27  Reserved

Type 0 STATUS: 40-byte payload follows header
Type 1 RAW_CAN: 0-64 bytes of CAN data follow header
Type 2 J1939: 8-byte routing header + 0-8 bytes data
"""

import socket
import struct
import threading
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Callable, List, Optional

CLOG_UDP_PORT = 47808
CLOG_MAGIC    = b"CLOG"
CLOG_VERSION  = 2

# Flags byte (byte 7)
CLOG_TYPE_EVENT = 3  # re-exported constant for convenience

CLOG_FLAG_FD  = 0x01
CLOG_FLAG_BRS = 0x02
CLOG_FLAG_ESI = 0x04
CLOG_FLAG_EXT = 0x08
CLOG_FLAG_RTR = 0x10

# Status payload flags (byte 28)
CLOG_ST_ETH_UP      = 0x01
CLOG_ST_CAN1_ACTIVE = 0x02
CLOG_ST_CAN2_ACTIVE = 0x04
CLOG_ST_PTP_LOCKED  = 0x08

# CAN bus state
CLOG_BUS_OK      = 0
CLOG_BUS_WARNING = 1
CLOG_BUS_PASSIVE = 2
CLOG_BUS_OFF     = 3

_HEADER = struct.Struct(">4sBBBBIIIIB3s")  # 28 bytes
_J1939  = struct.Struct(">BBBBI")           # 8 bytes: prio, sa, da, reserved(1), pgn(4)
_STATUS = struct.Struct(">BBBBB3sIIIIIIII") # 40 bytes

_DLC_TO_LEN = [0,1,2,3,4,5,6,7,8,12,16,20,24,32,48,64]


class CLOGType(IntEnum):
    STATUS  = 0
    RAW_CAN = 1
    J1939   = 2
    EVENT   = 3  # filter-rule-triggered event frame (msg_type = 0x03)


@dataclass
class CLOGFrame:
    msg_type:   CLOGType
    channel_id: int
    flags:      int
    sequence:   int
    ts_sec:     int
    ts_nsec:    float
    can_id:     int
    dlc:        int
    data:       bytes = b""
    # J1939 fields (populated for msg_type == J1939)
    priority:   int = 0
    sa:         int = 0
    da:         int = 0xFF
    pgn:        int = 0
    # Status fields (populated for msg_type == STATUS)
    status_flags: int = 0
    can1_state:   int = 0
    can2_state:   int = 0
    fw_major:     int = 0
    fw_minor:     int = 0
    uptime_sec:   int = 0
    ch1_rx: int = 0; ch2_rx: int = 0
    ch1_tx: int = 0; ch2_tx: int = 0
    ch1_errors: int = 0; ch2_errors: int = 0
    dropped: int = 0

    @property
    def timestamp(self) -> float:
        return self.ts_sec + self.ts_nsec * 1e-9

    @property
    def is_extended(self) -> bool:
        return bool(self.flags & CLOG_FLAG_EXT)

    @property
    def is_fd(self) -> bool:
        return bool(self.flags & CLOG_FLAG_FD)

    @property
    def data_len(self) -> int:
        return _DLC_TO_LEN[self.dlc] if self.dlc < 16 else 64

    def __repr__(self) -> str:
        if self.msg_type == CLOGType.J1939:
            return (f"CLOG[J1939 ch={self.channel_id} pgn=0x{self.pgn:05X} "
                    f"sa=0x{self.sa:02X} da=0x{self.da:02X} "
                    f"data={self.data.hex()}]")
        if self.msg_type == CLOGType.STATUS:
            return (f"CLOG[STATUS uptime={self.uptime_sec}s "
                    f"ch1_rx={self.ch1_rx} ch2_rx={self.ch2_rx}]")
        ext = "x" if self.is_extended else "s"
        return (f"CLOG[CAN ch={self.channel_id} id=0x{self.can_id:08X}{ext} "
                f"dlc={self.dlc} data={self.data.hex()}]")


def _parse(raw: bytes) -> Optional[CLOGFrame]:
    if len(raw) < 28:
        return None
    magic, ver, msg_type, channel_id, flags, seq, ts_sec, ts_nsec, can_id, dlc, _ = \
        _HEADER.unpack_from(raw, 0)
    if magic != CLOG_MAGIC or ver != CLOG_VERSION:
        return None

    f = CLOGFrame(
        msg_type=CLOGType(msg_type),
        channel_id=channel_id,
        flags=flags,
        sequence=seq,
        ts_sec=ts_sec,
        ts_nsec=ts_nsec,
        can_id=can_id,
        dlc=dlc,
    )

    dlen = _DLC_TO_LEN[dlc] if dlc < 16 else 64

    if msg_type == CLOGType.STATUS:
        if len(raw) >= 68:
            (f.status_flags, f.can1_state, f.can2_state, f.fw_major, f.fw_minor,
             _res, f.uptime_sec, f.ch1_rx, f.ch2_rx, f.ch1_tx, f.ch2_tx,
             f.ch1_errors, f.ch2_errors, f.dropped) = _STATUS.unpack_from(raw, 28)

    elif msg_type == CLOGType.J1939:
        if len(raw) >= 36:
            prio, sa, da, _res, pgn = _J1939.unpack_from(raw, 28)
            f.priority = prio
            f.sa = sa
            f.da = da
            f.pgn = pgn & 0x3FFFF
            f.data = raw[36:36 + dlen]

    else:  # RAW_CAN and EVENT share the same payload layout
        f.data = raw[28:28 + dlen]

    return f


class CLOGReceiver:
    """Receive and decode CLOG v2 frames on UDP port 47808.

    Usage::

        rx = CLOGReceiver(listen_ip="0.0.0.0")
        rx.on_frame = lambda f: print(f)
        rx.start()
        ...
        rx.stop()
    """

    def __init__(self, listen_ip: str = "0.0.0.0", port: int = CLOG_UDP_PORT):
        self._listen_ip = listen_ip
        self._port = port
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._frames: List[CLOGFrame] = []
        self._lock = threading.Lock()

        self.on_frame: Optional[Callable[[CLOGFrame], None]] = None

    def start(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self._listen_ip, self._port))
        self._sock.settimeout(0.5)
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        if self._sock:
            self._sock.close()
        if self._thread:
            self._thread.join(timeout=2.0)

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *_):
        self.stop()

    def get_frames(self, clear: bool = False) -> List[CLOGFrame]:
        with self._lock:
            frames = list(self._frames)
            if clear:
                self._frames.clear()
        return frames

    def _loop(self) -> None:
        while self._running:
            try:
                raw, _ = self._sock.recvfrom(1500)
            except socket.timeout:
                continue
            except OSError:
                break
            frame = _parse(raw)
            if frame is None:
                continue
            with self._lock:
                self._frames.append(frame)
                if len(self._frames) > 2000:
                    self._frames = self._frames[-2000:]
            if self.on_frame:
                try:
                    self.on_frame(frame)
                except Exception:
                    pass
