"""
tecmp_bus.py — TECMP CAN bus adapter, correct wire format from:
  https://github.com/Technica-Engineering/libtecmp (tecmp.h + actual PCAP trace)

Transport
─────────
  TECMP uses raw Ethernet frames, NOT UDP.
  EtherType: 0x99FE  (primary) or 0x2090
  Linux raw socket: AF_PACKET / SOCK_RAW bound to an interface name (e.g. 'eth0')
  Root / CAP_NET_RAW privilege required.

Ethernet frame layout
─────────────────────
  [ 6 bytes dst MAC ][ 6 bytes src MAC ][ 2 bytes EtherType 0x99FE ]
  [ 28 bytes TECMP header ]
  [ N bytes payload ]

TECMP header — 28 bytes, all fields big-endian, packed (no alignment padding)
─────────────────────────────────────────────────────────────────────────────
  Offset  Size  C type      Field          Notes
   0       2    uint16_t    cm_id          Capture Module ID (from device label/config)
   2       2    uint16_t    counter        per-CM sequence counter
   4       1    uint8_t     version        protocol version (typically 2)
   5       1    uint8_t     message_type   0x03 = LOGGING_STREAM (RX capture)
                                           0x0A = REPLAY_DATA    (TX injection)
   6       2    uint16_t    data_type      0x0002 = CAN classic
                                           0x0003 = CAN FD
   8       2    uint16_t    _reserved      0x0000
  10       2    uint16_t    cm_flags       device control flags (0x0000 for injection)
  12       4    uint32_t    channel_id     logical CAN channel number
  16       8    uint64_t    _timestamp     Unix epoch nanoseconds (big-endian)
  24       2    uint16_t    length         payload byte count after this header
  26       2    uint16_t    data_flags     CAN frame flags (see TECMP_FLAG_* below)

CAN payload — immediately follows the 28-byte header
────────────────────────────────────────────────────
  Offset  Size  Field
   0       4    CAN ID (uint32_t, big-endian)
                  Bits [28:0]  = raw CAN ID value
                  Bit [29..31] = 0 (IDE/extended indicated by data_flags bit 0)
   4       1    DLC  (0–8 for classic CAN, 0–15 for CAN FD)
   5       N    Data bytes  (N = DLC for classic, dlc_to_len(DLC) for FD)

data_flags bit definitions (uint16_t, big-endian)
──────────────────────────────────────────────────
  Bit 0  (0x0001)  Extended 29-bit ID
  Bit 1  (0x0002)  Remote frame
  Bit 2  (0x0004)  CAN FD frame
  Bit 3  (0x0008)  BRS (bit-rate switching, CAN FD)
  Bit 4  (0x0010)  ESI (error state indicator, CAN FD)
  Bit 7  (0x0080)  Direction: 0 = RX (captured), 1 = TX (injected)
  Bit 8  (0x0100)  CAN error frame
  Bit 9  (0x0200)  Reserved
  Bit 15 (0x8000)  Reserved

NOTE: exact data_flags bit positions verified from libtecmp source + Wireshark dissector.
      If your device uses a different firmware version, compare captures in Wireshark
      (Analyze → Decode As → TECMP) against this table.
"""

import socket
import struct
import time
import threading
from dataclasses import dataclass
from queue import Queue, Empty
from typing import Optional

# ── Protocol constants (from tecmp.h) ─────────────────────────────────────────
TECMP_ETHERTYPE         = 0x99FE
TECMP_ETHERTYPE_ALT     = 0x2090   # older devices / alternative

TECMP_VERSION           = 2

TECMP_MSG_LOGGING       = 0x03    # device → PC (captured frames)
TECMP_MSG_REPLAY        = 0x0A    # PC → device (inject onto bus)

TECMP_DATA_CAN          = 0x0002
TECMP_DATA_CANFD        = 0x0003

TECMP_FLAG_EXT_ID       = 0x0001   # data_flags: extended 29-bit ID
TECMP_FLAG_REMOTE       = 0x0002   # data_flags: remote frame
TECMP_FLAG_FD           = 0x0004   # data_flags: CAN FD frame
TECMP_FLAG_BRS          = 0x0008   # data_flags: bit-rate switching
TECMP_FLAG_ESI          = 0x0010   # data_flags: error state indicator
TECMP_FLAG_TX           = 0x0080   # data_flags: frame was transmitted
TECMP_FLAG_ERR          = 0x0100   # data_flags: error frame

TECMP_HDR_LEN           = 28   # sizeof(tecmp_header) with #pragma pack(1)
ETH_HDR_LEN             = 14   # dst(6) + src(6) + ethertype(2)

# Struct format for the 28-byte TECMP header (big-endian, packed)
# H=uint16, B=uint8, I=uint32, Q=uint64
# cm_id counter version msg_type data_type _reserved cm_flags channel_id _timestamp length data_flags
_HDR_FMT = '>HHBBHHHIQhH'   # note: 'h' for signed length/data_flags gives correct -1 on 0xFFFF

# Correct struct: all unsigned
_HDR_FMT = '>HHBBHHHIQHH'
#              HH   = cm_id(2) + counter(2)
#              BB   = version(1) + message_type(1)
#              HHH  = data_type(2) + _reserved(2) + cm_flags(2)
#              I    = channel_id(4)
#              Q    = _timestamp(8)
#              HH   = length(2) + data_flags(2)
# Total: 2+2+1+1+2+2+2+4+8+2+2 = 28 bytes ✓

_DLC_TO_LEN = [0, 1, 2, 3, 4, 5, 6, 7, 8, 12, 16, 20, 24, 32, 48, 64]


def dlc_to_len(dlc: int) -> int:
    return _DLC_TO_LEN[dlc] if dlc < 16 else 64


@dataclass
class TecmpFrame:
    can_id:    int
    data:      bytes
    dlc:       int
    timestamp: int        # nanoseconds
    extended:  bool = False
    fd:        bool = False
    brs:       bool = False
    remote:    bool = False
    error:     bool = False
    channel_id: int = 0
    cm_id:     int = 0


# ── Encoder ───────────────────────────────────────────────────────────────────

def build_eth_header(dst_mac: bytes, src_mac: bytes,
                     ethertype: int = TECMP_ETHERTYPE) -> bytes:
    return dst_mac + src_mac + struct.pack('>H', ethertype)


def encode_can_frame(can_id: int, data: bytes,
                     channel_id: int,
                     cm_id:      int,
                     src_mac:    bytes,
                     dst_mac:    bytes,
                     counter:    int  = 0,
                     extended:   bool = True,
                     fd:         bool = False,
                     brs:        bool = False) -> bytes:
    """Build a complete raw Ethernet TECMP REPLAY_DATA frame for CAN injection."""
    dlc   = len(data)
    dlc   = min(dlc, 8 if not fd else 64)
    data  = data[:dlc]
    ts_ns = time.time_ns()

    # data_flags
    flags = TECMP_FLAG_TX   # marking as TX (injected)
    if extended: flags |= TECMP_FLAG_EXT_ID
    if fd:       flags |= TECMP_FLAG_FD
    if brs:      flags |= TECMP_FLAG_BRS

    # CAN payload: CAN_ID(4) + DLC(1) + data
    can_payload = struct.pack('>IB', can_id & 0x1FFFFFFF, dlc) + data

    # TECMP header (28 bytes)
    data_type = TECMP_DATA_CANFD if fd else TECMP_DATA_CAN
    length    = len(can_payload)

    hdr = struct.pack(_HDR_FMT,
                      cm_id   & 0xFFFF,   # cm_id
                      counter & 0xFFFF,   # counter
                      TECMP_VERSION,       # version
                      TECMP_MSG_REPLAY,    # message_type = 0x0A
                      data_type,           # data_type
                      0x0000,              # _reserved
                      0x0000,              # cm_flags
                      channel_id,          # channel_id
                      ts_ns,               # _timestamp (Unix ns)
                      length,              # length
                      flags)               # data_flags

    eth = build_eth_header(dst_mac, src_mac)
    return eth + hdr + can_payload


# ── Decoder ───────────────────────────────────────────────────────────────────

def decode_tecmp_frame(raw: bytes) -> list[TecmpFrame]:
    """
    Decode a raw Ethernet frame that may contain one or more TECMP CAN entries.
    Returns a list of TecmpFrame objects (empty if not a valid TECMP CAN frame).
    """
    if len(raw) < ETH_HDR_LEN + TECMP_HDR_LEN:
        return []

    ethertype = struct.unpack_from('>H', raw, 12)[0]
    if ethertype not in (TECMP_ETHERTYPE, TECMP_ETHERTYPE_ALT):
        return []

    payload = raw[ETH_HDR_LEN:]
    if len(payload) < TECMP_HDR_LEN:
        return []

    (cm_id, counter, version, msg_type, data_type,
     _reserved, cm_flags, channel_id, timestamp, length, data_flags) = \
        struct.unpack_from(_HDR_FMT, payload, 0)

    if msg_type != TECMP_MSG_LOGGING:
        return []   # we only decode captured frames (not our own injected ones)

    if data_type not in (TECMP_DATA_CAN, TECMP_DATA_CANFD):
        return []

    can_payload = payload[TECMP_HDR_LEN: TECMP_HDR_LEN + length]
    if len(can_payload) < 5:    # minimum: 4-byte ID + 1-byte DLC
        return []

    can_id_raw, dlc = struct.unpack_from('>IB', can_payload, 0)
    can_id = can_id_raw & 0x1FFFFFFF
    dlen   = dlc_to_len(dlc) if data_type == TECMP_DATA_CANFD else min(dlc, 8)
    data   = bytes(can_payload[5: 5 + dlen])

    extended = bool(data_flags & TECMP_FLAG_EXT_ID)
    fd       = bool((data_flags & TECMP_FLAG_FD) or data_type == TECMP_DATA_CANFD)
    brs      = bool(data_flags & TECMP_FLAG_BRS)
    remote   = bool(data_flags & TECMP_FLAG_REMOTE)
    error    = bool(data_flags & TECMP_FLAG_ERR)

    return [TecmpFrame(
        can_id     = can_id,
        data       = data,
        dlc        = dlc,
        timestamp  = timestamp,
        extended   = extended,
        fd         = fd,
        brs        = brs,
        remote     = remote,
        error      = error,
        channel_id = channel_id,
        cm_id      = cm_id,
    )]


# ── TecmpBus ─────────────────────────────────────────────────────────────────

class TecmpBus:
    """
    Raw-Ethernet TECMP CAN bus.

    Requires root or CAP_NET_RAW on Linux.

    Parameters
    ──────────
    interface   : network interface name facing the TECMP device, e.g. 'eth0'
    device_mac  : MAC address of the TECMP device (bytes or 'AA:BB:CC:DD:EE:FF')
    cm_id       : Capture Module ID shown on the device label
    channel_id  : CAN channel number on the device (1-based)
    """

    def __init__(self,
                 interface:  str,
                 device_mac: str | bytes,
                 cm_id:      int = 0x0001,
                 channel_id: int = 1):

        self.interface  = interface
        self.cm_id      = cm_id
        self.channel_id = channel_id
        self._counter   = 0
        self._rx_queue: Queue[TecmpFrame] = Queue(maxsize=512)
        self._running   = True

        # Resolve device MAC
        if isinstance(device_mac, str):
            self._dst_mac = bytes.fromhex(device_mac.replace(':', ''))
        else:
            self._dst_mac = bytes(device_mac)

        # Open raw socket
        # ETH_P_ALL (0x0003) = capture every Ethernet protocol.
        # socket.ETH_P_ALL was only added as a named constant in Python 3.12;
        # use the raw value so this works on Python 3.10 / Ubuntu 22.04.
        _ETH_P_ALL = 0x0003
        self._sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                    socket.htons(_ETH_P_ALL))
        self._sock.bind((interface, 0))
        self._sock.settimeout(0.2)

        # Read back our own MAC from the bound interface
        import fcntl, struct as _st
        SIOCGIFHWADDR = 0x8927
        ifreq = struct.pack('256s', interface.encode()[:15])
        res   = fcntl.ioctl(self._sock.fileno(), SIOCGIFHWADDR, ifreq)
        self._src_mac = res[18:24]

        print(f"[TECMP] Interface  : {interface}  MAC={self._src_mac.hex(':')}")
        print(f"[TECMP] Device MAC : {self._dst_mac.hex(':')}")
        print(f"[TECMP] CM_ID=0x{cm_id:04X}  Channel={channel_id}")

        self._rx_thread = threading.Thread(target=self._rx_loop, daemon=True)
        self._rx_thread.start()

    def _rx_loop(self):
        while self._running:
            try:
                raw, _ = self._sock.recvfrom(65536)
            except (socket.timeout, OSError):
                continue
            for f in decode_tecmp_frame(raw):
                if not self._rx_queue.full():
                    self._rx_queue.put_nowait(f)

    def send(self, can_id: int, data: bytes,
             extended: bool = True, fd: bool = False, brs: bool = False):
        """Inject one CAN frame onto the bus via the TECMP device."""
        pkt = encode_can_frame(
            can_id     = can_id,
            data       = data,
            channel_id = self.channel_id,
            cm_id      = self.cm_id,
            src_mac    = self._src_mac,
            dst_mac    = self._dst_mac,
            counter    = self._counter,
            extended   = extended,
            fd         = fd,
            brs        = brs,
        )
        self._counter = (self._counter + 1) & 0xFFFF
        self._sock.send(pkt)

    def recv(self, timeout: float = 2.0) -> Optional[TecmpFrame]:
        """Block up to timeout seconds and return the next captured CAN frame."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                return self._rx_queue.get(timeout=min(deadline - time.monotonic(), 0.1))
            except Empty:
                pass
        return None

    def set_filters(self, _):
        pass

    def shutdown(self):
        self._running = False
        self._rx_thread.join(timeout=1.0)
        self._sock.close()

    def __enter__(self):  return self
    def __exit__(self, *_): self.shutdown()


# ── python-can compatible wrapper ─────────────────────────────────────────────

class TecmpCanMessage:
    """Wraps TecmpFrame to match the can.Message attribute API."""
    def __init__(self, frame: TecmpFrame):
        self.arbitration_id  = frame.can_id
        self.is_extended_id  = frame.extended
        self.data            = frame.data
        self.dlc             = frame.dlc
        self.timestamp       = frame.timestamp / 1e9
        self.is_fd           = frame.fd
        self.bitrate_switch  = frame.brs
        self._frame          = frame

    def __repr__(self):
        id_fmt = f"0x{self.arbitration_id:08X}" if self.is_extended_id \
                 else f"0x{self.arbitration_id:03X}"
        return f"TecmpCanMessage id={id_fmt} dlc={self.dlc} data={self.data.hex()}"


class TecmpBusCompat(TecmpBus):
    """
    Drop-in replacement for can.Bus.

    recv() returns a TecmpCanMessage (same attributes as can.Message).
    send() accepts either a CanMessage / can.Message object or raw args.
    """

    def recv(self, timeout: float = 2.0) -> Optional[TecmpCanMessage]:
        frame = super().recv(timeout)
        return TecmpCanMessage(frame) if frame else None

    def send(self, msg_or_id, data: bytes = b'',
             extended: bool = True, fd: bool = False, brs: bool = False):
        if hasattr(msg_or_id, 'arbitration_id'):
            msg = msg_or_id
            super().send(
                can_id   = msg.arbitration_id,
                data     = bytes(msg.data),
                extended = getattr(msg, 'is_extended_id', True),
                fd       = getattr(msg, 'is_fd', False),
                brs      = getattr(msg, 'bitrate_switch', False),
            )
        else:
            super().send(msg_or_id, data, extended=extended, fd=fd, brs=brs)
