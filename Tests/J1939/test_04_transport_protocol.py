#!/usr/bin/env python3
"""
test_04_transport_protocol.py
──────────────────────────────
Test: J1939 Transport Protocol — BAM (Broadcast Announce Message).

J1939-21 TP/BAM is used for messages longer than 8 bytes.  It sends a
Connection Management frame (TP.CM_BAM, PGN 0xEC00, DA=0xFF) announcing the
total length, then one or more Data Transfer frames (TP.DT, PGN 0xEB00).
The Open-SAE-J1939 library reassembles these and returns
RX_MSG_RESP_REQ_SOFTWARE_IDENTIFICATION when the full message is received.

We send a fake Software Identification string (PGN 0xFEDA) — this is one of
the PGNs the library actively parses, so it gives a strong signal of correct
TP reassembly.

Wire sequence (SA=0x01 → broadcast):
  TP.CM_BAM  ID=0x18ECFF01  data=[0x20, len_lo, len_hi, num_pkts, 0xFF, pgn0, pgn1, pgn2]
  TP.DT  #1  ID=0x18EBFF01  data=[seq, d0..d6]
  TP.DT  #2  ID=0x18EBFF01  data=[seq, d0..d6]  ← padded with 0xFF if needed
"""

import sys
import time
import struct
import threading
from config import (make_bus, CAN_INTERFACE, CAN_CHANNEL, CAN_BITRATE,
                    CLOG_LISTEN_IP, CLOG_LISTEN_PORT, CLOG_TIMEOUT_S)
from j1939_utils import (CanMessage, make_j1939_id, decode_clog, open_clog_socket, pgn_name,
                          PGN_TP_CM, PGN_TP_DT, PGN_SOFTWARE_ID,
                          TP_BAM, CLOG_TYPE_J1939)

TP_SENDER_SA = 0x01   # simulated engine ECU source address
DELAY_BETWEEN_DT = 0.005   # 5 ms inter-packet gap (J1939 requires ≥50 ms for RTS/CTS,
                             # but BAM allows continuous — we use 5 ms to be safe)


def build_bam_sequence(pgn: int, data: bytes, sa: int) -> list[tuple[int, bytes]]:
    """Build the full TP.CM_BAM + TP.DT frame list for the given payload."""
    total     = len(data)
    num_pkts  = (total + 6) // 7   # 7 data bytes per DT frame

    # TP.CM_BAM — destination always 0xFF (global)
    cm_id  = make_j1939_id(6, PGN_TP_CM, sa, da=0xFF)
    cm_pgn = struct.pack('<I', pgn)[:3]   # 3-byte LE PGN
    cm_data = bytes([TP_BAM, total & 0xFF, (total >> 8) & 0xFF, num_pkts, 0xFF]) + cm_pgn
    frames = [(cm_id, cm_data)]

    # TP.DT frames — destination also 0xFF for BAM
    dt_id = make_j1939_id(6, PGN_TP_DT, sa, da=0xFF)
    for i in range(num_pkts):
        chunk = data[i*7 : i*7 + 7]
        chunk = chunk + bytes(7 - len(chunk))   # pad with 0xFF
        frames.append((dt_id, bytes([i + 1]) + chunk))   # seq = 1-based

    return frames


def run() -> bool:
    print("=" * 60)
    print("TEST 04 — Transport Protocol / BAM (Software Identification)")
    print("=" * 60)

    # Software ID string: number-of-fields (1 byte) | field | '*' delimiter
    # Format: <n_fields=1> <version_string> <'*'>
    sw_string = b'\x01V1.2.3*'   # 1 field, "V1.2.3"
    # Pad to at least 5 bytes (J1939 minimum for SoftwareID)
    while len(sw_string) < 5:
        sw_string += b'\xFF'

    frames = build_bam_sequence(PGN_SOFTWARE_ID, sw_string, TP_SENDER_SA)
    total_bytes = len(sw_string)
    num_pkts    = len(frames) - 1

    print(f"  Software ID payload : {sw_string.hex()}  ({total_bytes} bytes)")
    print(f"  TP sequence         : 1× TP.CM_BAM + {num_pkts}× TP.DT")
    print(f"  Sender SA           : 0x{TP_SENDER_SA:02X}")

    # CLOG listener — watch for a J1939 frame from TP_SENDER_SA
    clog_found = []
    clog_event = threading.Event()

    def clog_listener():
        sock = open_clog_socket(CLOG_LISTEN_IP, CLOG_LISTEN_PORT,
                                 timeout=CLOG_TIMEOUT_S)
        deadline = time.monotonic() + CLOG_TIMEOUT_S + 1.0
        try:
            while time.monotonic() < deadline:
                try:
                    raw, _ = sock.recvfrom(256)
                    f = decode_clog(raw)
                    if (f and f['type'] == CLOG_TYPE_J1939
                            and f.get('sa') == TP_SENDER_SA):
                        clog_found.append(f)
                        clog_event.set()
                        break
                except TimeoutError:
                    break
        finally:
            sock.close()

    t = threading.Thread(target=clog_listener, daemon=True)
    t.start()

    bus = make_bus()
    try:
        print()
        for idx, (can_id, data) in enumerate(frames):
            label = 'TP.CM_BAM' if idx == 0 else f'TP.DT    #{idx}'
            print(f"    {label}  ID=0x{can_id:08X}  data={data.hex()}")
            msg = CanMessage(arbitration_id=can_id, is_extended_id=True, data=data)
            bus.send(msg)
            time.sleep(DELAY_BETWEEN_DT)
    finally:
        bus.shutdown()

    clog_event.wait(timeout=CLOG_TIMEOUT_S + 1)
    t.join(timeout=1)

    print()
    if clog_found:
        f = clog_found[0]
        print(f"  [PASS]  CLOG frame received from TP sender SA=0x{TP_SENDER_SA:02X}!")
        print(f"          PGN  = 0x{f.get('pgn',0):05X} ({pgn_name(f.get('pgn',0))})")
        print(f"          data = {f.get('data', b'').hex()}")
        return True
    else:
        print(f"  [FAIL]  No CLOG frame from SA=0x{TP_SENDER_SA:02X} within {CLOG_TIMEOUT_S}s.")
        print("  The library may not forward TP-reassembled frames via CLOG — check")
        print("  that poll_rx() forwards the frame even for RX_MSG_RESP_REQ_SOFTWARE_IDENTIFICATION.")
        return False


if __name__ == '__main__':
    sys.exit(0 if run() else 1)
