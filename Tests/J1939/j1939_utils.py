"""
j1939_utils.py — shared helpers for building J1939 CAN IDs and decoding CLOG frames.

29-bit CAN ID layout
  Bits [28:26]  Priority  (0–7, lower = higher priority)
  Bit  [25]     Reserved  (always 0)
  Bit  [24]     Data Page (DP)
  Bits [23:16]  PDU Format (PF)
  Bits [15:8]   PDU Specific (PS):
                  PDU2 (PF >= 0xF0): PS = Group Extension (part of PGN)
                  PDU1 (PF < 0xF0) : PS = Destination Address (not part of PGN)
  Bits  [7:0]   Source Address (SA)

PGN encoding used in this project (matches Open-SAE-J1939 enum values)
  Bit  [16]     Data Page
  Bits [15:8]   PF
  Bits  [7:0]   GE  (0 for PDU1 PGNs)
"""

import struct
import socket
from dataclasses import dataclass, field


@dataclass
class CanMessage:
    """Minimal CAN frame — no python-can dependency required.
    Accepted by TecmpBusCompat.send() and compatible with can.Bus.send()
    (python-can uses duck-typing on these attributes)."""
    arbitration_id:  int
    data:            bytes = b''
    is_extended_id:  bool  = True
    is_remote_frame: bool  = False
    is_fd:           bool  = False
    bitrate_switch:  bool  = False
    dlc:             int   = 0

    def __post_init__(self):
        self.data = bytes(self.data)
        if self.dlc == 0:
            self.dlc = len(self.data)

# ── Well-known PGNs ──────────────────────────────────────────────────────────
PGN_REQUEST              = 0x00EA00
PGN_ACKNOWLEDGEMENT      = 0x00E800
PGN_TP_CM                = 0x00EC00   # Transport Protocol — Connection Management
PGN_TP_DT                = 0x00EB00   # Transport Protocol — Data Transfer
PGN_ADDRESS_CLAIMED      = 0x00EE00
PGN_PROPRIETARY_A        = 0x00EF00
PGN_DM1                  = 0x00FECA   # Active Diagnostics (SPN/FMI list)
PGN_DM2                  = 0x00FECB   # Previously Active Diagnostics
PGN_SOFTWARE_ID          = 0x00FEDA   # Software Identification
PGN_ECU_ID               = 0x00FDC5   # ECU Identification
PGN_COMPONENT_ID         = 0x00FEEB   # Component Identification
PGN_EEC1                 = 0x00F004   # Electronic Engine Controller 1 (61444)
PGN_EEC2                 = 0x00F003   # Electronic Engine Controller 2 (61443)
PGN_ENGINE_TEMPERATURE_1 = 0x00FEEE   # Engine Temperature 1 (65262)
PGN_VEHICLE_ELEC_POWER   = 0x00FEF7   # Vehicle Electrical Power (65271)
PGN_FUEL_ECONOMY         = 0x00FEF2   # Fuel Economy (65266)
PGN_AMBIENT_CONDITIONS   = 0x00FEF5   # Ambient Conditions (65269)
PGN_DASH_DISPLAY         = 0x00FEFC   # Dash Display (65276)

# TP_CM control byte values
TP_BAM   = 0x20   # Broadcast Announce Message — no handshake
TP_RTS   = 0x10   # Request To Send  (peer-to-peer)
TP_CTS   = 0x11   # Clear To Send    (peer-to-peer reply)
TP_EOMA  = 0x13   # End Of Message Acknowledgement
TP_ABORT = 0xFF   # Connection Abort

# ── CLOG protocol constants (mirrors clog.h) ──────────────────────────────────
CLOG_UDP_PORT     = 47808
CLOG_MAGIC        = b'CLOG'
CLOG_VERSION      = 2
CLOG_TYPE_STATUS  = 0x00
CLOG_TYPE_RAW_CAN = 0x01
CLOG_TYPE_J1939   = 0x02
CLOG_FLAG_FD      = 0x01
CLOG_FLAG_BRS     = 0x02
CLOG_FLAG_ESI     = 0x04
CLOG_FLAG_EXT     = 0x08
CLOG_FLAG_RTR     = 0x10

_DLC_TO_LEN = [0, 1, 2, 3, 4, 5, 6, 7, 8, 12, 16, 20, 24, 32, 48, 64]


def dlc_to_len(dlc: int) -> int:
    return _DLC_TO_LEN[dlc] if dlc < 16 else 64


# ── CAN ID helpers ────────────────────────────────────────────────────────────

def make_j1939_id(priority: int, pgn: int, sa: int, da: int = 0xFF) -> int:
    """Build a 29-bit J1939 CAN ID.

    priority  0-7  (6 is the J1939 default)
    pgn       18-bit PGN (bit 16 = DP, bits 15:8 = PF, bits 7:0 = GE)
    sa        Source Address 0x00–0xFE  (0xFE = null address)
    da        Destination Address — only used for PDU1 frames (PF < 0xF0)
    """
    dp = (pgn >> 16) & 0x01
    pf = (pgn >> 8)  & 0xFF
    ge =  pgn        & 0xFF
    ps = ge if pf >= 0xF0 else (da & 0xFF)
    return ((priority & 0x7) << 26) | (dp << 24) | (pf << 16) | (ps << 8) | (sa & 0xFF)


def decode_j1939_id(can_id: int) -> dict:
    """Decompose a 29-bit J1939 CAN ID."""
    priority = (can_id >> 26) & 0x7
    dp       = (can_id >> 24) & 0x1
    pf       = (can_id >> 16) & 0xFF
    ps       = (can_id >>  8) & 0xFF
    sa       =  can_id        & 0xFF
    if pf >= 0xF0:   # PDU2 — broadcast
        pgn = (dp << 16) | (pf << 8) | ps
        da  = 0xFF
    else:            # PDU1 — addressed
        pgn = (dp << 16) | (pf << 8)
        da  = ps
    return {'priority': priority, 'dp': dp, 'pf': pf, 'ps': ps,
            'sa': sa, 'da': da, 'pgn': pgn}


def make_request_frame(pgn_to_request: int, sa: int, da: int,
                        priority: int = 6) -> tuple[int, bytes]:
    """Build a PGN Request message (PGN 0xEA00, 3-byte little-endian PGN payload)."""
    can_id = make_j1939_id(priority, PGN_REQUEST, sa, da)
    data   = struct.pack('<I', pgn_to_request)[:3] + bytes(5)
    return can_id, data


# ── PGN name lookup ───────────────────────────────────────────────────────────

_PGN_NAMES = {
    PGN_REQUEST:              'Request',
    PGN_ACKNOWLEDGEMENT:      'Acknowledgement',
    PGN_TP_CM:                'TP-CM',
    PGN_TP_DT:                'TP-DT',
    PGN_ADDRESS_CLAIMED:      'AddressClaimed',
    PGN_PROPRIETARY_A:        'ProprietaryA',
    PGN_DM1:                  'DM1-ActiveDiag',
    PGN_DM2:                  'DM2-PrevDiag',
    PGN_SOFTWARE_ID:          'SoftwareID',
    PGN_ECU_ID:               'ECU_ID',
    PGN_COMPONENT_ID:         'ComponentID',
    PGN_EEC1:                 'EEC1-EngineSpeed',
    PGN_EEC2:                 'EEC2',
    PGN_ENGINE_TEMPERATURE_1: 'EngineTemp1',
    PGN_VEHICLE_ELEC_POWER:   'VehicleElecPower',
    PGN_FUEL_ECONOMY:         'FuelEconomy',
    PGN_AMBIENT_CONDITIONS:   'AmbientConditions',
    PGN_DASH_DISPLAY:         'DashDisplay',
}


def pgn_name(pgn: int) -> str:
    return _PGN_NAMES.get(pgn, f'PGN_0x{pgn:05X}')


# ── CLOG decoder ─────────────────────────────────────────────────────────────

def decode_clog(raw: bytes) -> dict | None:
    """Decode a raw CLOG v2 UDP payload. Returns None if invalid."""
    if len(raw) < 28:
        return None
    if raw[:4] != CLOG_MAGIC:
        return None
    if raw[4] != CLOG_VERSION:
        return None

    msg_type = raw[5]
    channel  = raw[6]
    flags    = raw[7]
    seq      = struct.unpack_from('>I', raw,  8)[0]
    ts_sec   = struct.unpack_from('>I', raw, 12)[0]
    ts_nsec  = struct.unpack_from('>I', raw, 16)[0]
    can_id   = struct.unpack_from('>I', raw, 20)[0]
    dlc      = raw[24]
    dlen     = dlc_to_len(dlc)
    payload  = raw[28:]

    frame = {
        'type':    msg_type,
        'channel': channel,
        'flags':   flags,
        'seq':     seq,
        'ts_sec':  ts_sec,
        'ts_nsec': ts_nsec,
        'ts':      ts_sec + ts_nsec * 1e-9,
        'can_id':  can_id,
        'dlc':     dlc,
        'dlen':    dlen,
        'ext':     bool(flags & CLOG_FLAG_EXT),
        'fd':      bool(flags & CLOG_FLAG_FD),
    }

    if msg_type == CLOG_TYPE_J1939 and len(payload) >= 8:
        # J1939 8-byte sub-header: priority, SA, DA, reserved, PGN (4 BE)
        priority = payload[0] & 0x07
        sa       = payload[1]
        da       = payload[2]
        # CLOG encodes PGN with dp<<17; normalise back to dp<<16 to match enum values
        pgn_raw  = struct.unpack_from('>I', payload, 4)[0]
        dp       = (pgn_raw >> 17) & 0x01
        pf       = (pgn_raw >>  8) & 0xFF
        ge       = pgn_raw & 0xFF
        pgn      = (dp << 16) | (pf << 8) | ge
        data     = bytes(payload[8: 8 + dlen])
        frame.update({'priority': priority, 'sa': sa, 'da': da,
                       'pgn': pgn, 'pgn_name': pgn_name(pgn), 'data': data})

    elif msg_type == CLOG_TYPE_RAW_CAN:
        frame['data'] = bytes(payload[:dlen])

    elif msg_type == CLOG_TYPE_STATUS and len(payload) >= 40:
        _bus = ['OK', 'WARNING', 'PASSIVE', 'BUS-OFF']
        st_flags   = payload[0]
        can1_state = payload[1]
        can2_state = payload[2]
        fw_major   = payload[3]
        fw_minor   = payload[4]
        uptime,   = struct.unpack_from('>I', payload,  8)
        ch1_rx,   = struct.unpack_from('>I', payload, 12)
        ch2_rx,   = struct.unpack_from('>I', payload, 16)
        dropped,  = struct.unpack_from('>I', payload, 36)
        frame.update({
            'status_flags': st_flags,
            'can1_state':   _bus[can1_state] if can1_state < 4 else '?',
            'can2_state':   _bus[can2_state] if can2_state < 4 else '?',
            'fw':           f'{fw_major}.{fw_minor}',
            'uptime_sec':   uptime,
            'ch1_rx':       ch1_rx,
            'ch2_rx':       ch2_rx,
            'dropped':      dropped,
        })

    return frame


def open_clog_socket(listen_ip: str = '', port: int = CLOG_UDP_PORT,
                      timeout: float = 5.0) -> socket.socket:
    """Open a UDP socket ready to receive CLOG frames."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(timeout)
    sock.bind((listen_ip, port))
    return sock
