#!/usr/bin/env python3
"""
test_04_transport_protocol.py  (UDP loopback)
──────────────────────────────────────────────
Test: J1939 Transport Protocol — BAM (Broadcast Announce Message).

Sends a TP/BAM sequence for Software Identification (PGN 0xFEDA) via UDP inject.
The gateway's FDCAN1 receives the frames, Open_SAE_J1939 reassembles the TP
message, and logs the result via CLOG ch1 as TYPE_J1939.

Inject path:
  UDP inject ch1  →  FDCAN2 TX  →  bus  →  FDCAN1 RX
  →  J1939 TP reassembly  →  CLOG ch1  (TYPE_J1939)

BAM sequence (SA=TP_SENDER_SA → broadcast 0xFF):
  TP.CM_BAM  CAN ID 0x18ECFF01
  TP.DT #1   CAN ID 0x18EBFF01
  TP.DT #2   CAN ID 0x18EBFF01  (etc.)
"""

import sys
import os
import struct
import time
import threading
from config import GW_IP, INJECT_CHANNEL, CLOG_PORT, CLOG_TIMEOUT_S, TP_SENDER_SA

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from j1939_utils import (CanMessage, make_j1939_id, pgn_name,
                          PGN_TP_CM, PGN_TP_DT, PGN_SOFTWARE_ID,
                          TP_BAM, CLOG_TYPE_J1939)
from udp_inject import UdpInjector, ClogListener, is_j1939_type

DT_INTERVAL = 0.010   # 10 ms between DT packets (J1939 BAM allows continuous)


def build_bam_sequence(pgn: int, data: bytes, sa: int) -> list:
    """Return [(can_id, payload), ...] — CM_BAM then all DT frames."""
    total    = len(data)
    num_pkts = (total + 6) // 7

    cm_id   = make_j1939_id(6, PGN_TP_CM, sa, da=0xFF)
    cm_pgn  = struct.pack('<I', pgn)[:3]
    cm_data = bytes([TP_BAM, total & 0xFF, (total >> 8) & 0xFF, num_pkts, 0xFF]) + cm_pgn
    frames  = [(cm_id, cm_data)]

    dt_id = make_j1939_id(6, PGN_TP_DT, sa, da=0xFF)
    for i in range(num_pkts):
        chunk = (data[i*7 : i*7 + 7]).ljust(7, b'\xFF')
        frames.append((dt_id, bytes([i + 1]) + chunk))

    return frames


def run() -> bool:
    print("=" * 60)
    print("TEST 04 — Transport Protocol / BAM  (UDP loopback)")
    print("=" * 60)

    sw_payload = b'\x01V1.2.3*'
    while len(sw_payload) < 5:
        sw_payload += b'\xFF'

    frames   = build_bam_sequence(PGN_SOFTWARE_ID, sw_payload, TP_SENDER_SA)
    num_pkts = len(frames) - 1

    print(f"  SA      = 0x{TP_SENDER_SA:02X}")
    print(f"  PGN     = 0x{PGN_SOFTWARE_ID:05X} ({pgn_name(PGN_SOFTWARE_ID)})")
    print(f"  Payload = {sw_payload.hex()}  ({len(sw_payload)} bytes)")
    print(f"  Sequence: 1× TP.CM_BAM + {num_pkts}× TP.DT")
    print(f"  Inject via ch{INJECT_CHANNEL} (FDCAN{INJECT_CHANNEL + 1} TX → FDCAN1 RX) …")

    clog_found = []
    clog_event = threading.Event()
    deadline_rx = time.monotonic() + CLOG_TIMEOUT_S + 2.0

    def clog_listener():
        with ClogListener(port=CLOG_PORT) as cl:
            f = cl.recv_until(
                lambda x: is_j1939_type(x) and x.get('sa') == TP_SENDER_SA,
                deadline=deadline_rx,
            )
            if f:
                clog_found.append(f)
                clog_event.set()

    t = threading.Thread(target=clog_listener, daemon=True)
    t.start()

    injector = UdpInjector(GW_IP, channel=INJECT_CHANNEL)
    try:
        print()
        for idx, (can_id, data) in enumerate(frames):
            label = 'TP.CM_BAM' if idx == 0 else f'TP.DT  #{idx}'
            print(f"    {label}  ID=0x{can_id:08X}  data={data.hex()}")
            msg = CanMessage(arbitration_id=can_id, data=data, is_extended_id=True)
            injector.send(msg)
            time.sleep(DT_INTERVAL)
    finally:
        injector.shutdown()

    clog_event.wait(timeout=CLOG_TIMEOUT_S + 2)
    t.join(timeout=1)

    print()
    if clog_found:
        f = clog_found[0]
        print(f"  [PASS]  CLOG TYPE_J1939 from TP sender SA=0x{TP_SENDER_SA:02X}!")
        print(f"          PGN  = 0x{f.get('pgn',0):05X} ({pgn_name(f.get('pgn',0))})")
        print(f"          data = {f.get('data', b'').hex()}")
        return True
    else:
        print(f"  [FAIL]  No CLOG J1939 frame from SA=0x{TP_SENDER_SA:02X} "
              f"within {CLOG_TIMEOUT_S + 2:.0f}s.")
        print("  The J1939 library may not forward TP-reassembled frames via CLOG.")
        print("  Check poll_rx() in can_task.cpp forwards the frame after TP reassembly.")
        return False


if __name__ == '__main__':
    sys.exit(0 if run() else 1)
