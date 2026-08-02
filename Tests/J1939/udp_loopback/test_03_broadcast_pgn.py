#!/usr/bin/env python3
"""
test_03_broadcast_pgn.py  (UDP loopback)
──────────────────────────────────────────
Test: Send EEC1 broadcast frames and verify they arrive in CLOG as TYPE_J1939.

Inject path:
  UDP inject ch1  →  FDCAN2 TX  →  bus  →  FDCAN1 RX
  →  Open_SAE_J1939_Listen_For_Messages()
  →  g_clog.send_can(..., ch1, 0, j1939=true)
  →  CLOG ch1  (TYPE_J1939)

EEC1 = Electronic Engine Controller 1  (PGN 0xF004 = 61444)
This is a broadcast PDU2 PGN  (PF=0xF0, so PS=GE=0x04 is part of the PGN).
The J1939 library forwards it via CLOG even if it doesn't recognise the PGN
(it returns RX_MSG_NOT_SAE_J1939 or similar, and can_task.cpp still logs it).

EEC1 byte layout (J1939-71):
  [0]  Engine Torque Mode
  [1]  Driver Demand Engine - Percent Torque
  [2]  Actual Engine - Percent Torque
  [3-4] Engine Speed (1/8 rpm/bit, LE)
  [5]  Source Address of Controlling Device
  [6]  Engine Starter Mode
  [7]  Engine Demand - Percent Torque
"""

import sys
import os
import time
import threading
from config import GW_IP, MY_ADDRESS, INJECT_CHANNEL, CLOG_PORT, CLOG_TIMEOUT_S

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from j1939_utils import CanMessage, make_j1939_id, pgn_name, PGN_EEC1, CLOG_TYPE_J1939
from udp_inject import UdpInjector, ClogListener, is_j1939_type

FRAMES_TO_SEND = 5
SEND_INTERVAL  = 0.10   # 100 ms between frames


def encode_eec1(rpm: float) -> bytes:
    speed_raw = int(rpm * 8) & 0xFFFF
    return bytes([
        0xFF,                       # torque mode
        0xFF,                       # driver demand
        0xFF,                       # actual torque
        speed_raw & 0xFF,
        (speed_raw >> 8) & 0xFF,
        MY_ADDRESS,                 # controlling SA
        0xFF,                       # starter mode
        0xFF,                       # demand torque
    ])


def run() -> bool:
    print("=" * 60)
    print("TEST 03 — Broadcast PGN (EEC1)  (UDP loopback)")
    print("=" * 60)

    can_id = make_j1939_id(priority=6, pgn=PGN_EEC1, sa=MY_ADDRESS)
    print(f"  PGN    = 0x{PGN_EEC1:05X} ({pgn_name(PGN_EEC1)})")
    print(f"  CAN ID = 0x{can_id:08X}")
    print(f"  Sending {FRAMES_TO_SEND} frames via inject ch{INJECT_CHANNEL} "
          f"(FDCAN{INJECT_CHANNEL + 1} TX)  …")
    print(f"  Expect {FRAMES_TO_SEND} CLOG TYPE_J1939 frames on ch1 …")

    clog_received = []
    clog_event    = threading.Event()
    deadline_rx   = time.monotonic() + CLOG_TIMEOUT_S + SEND_INTERVAL * FRAMES_TO_SEND

    def clog_listener():
        with ClogListener(port=CLOG_PORT) as cl:
            while time.monotonic() < deadline_rx:
                f = cl.recv_until(
                    lambda x: is_j1939_type(x) and x.get('pgn') == PGN_EEC1,
                    deadline=time.monotonic() + 0.5,
                )
                if f:
                    clog_received.append(f)
                    if len(clog_received) >= FRAMES_TO_SEND:
                        clog_event.set()
                        break

    t = threading.Thread(target=clog_listener, daemon=True)
    t.start()

    injector = UdpInjector(GW_IP, channel=INJECT_CHANNEL)
    try:
        for i in range(FRAMES_TO_SEND):
            rpm  = 800.0 + i * 100
            data = encode_eec1(rpm)
            msg  = CanMessage(arbitration_id=can_id, data=data, is_extended_id=True)
            injector.send(msg)
            print(f"    Sent EEC1  rpm={rpm:.0f}  data={data.hex()}")
            time.sleep(SEND_INTERVAL)
    finally:
        injector.shutdown()

    clog_event.wait(timeout=CLOG_TIMEOUT_S + 1)
    t.join(timeout=1)

    print()
    if clog_received:
        print(f"  [PASS]  {len(clog_received)} CLOG J1939 frame(s) received:")
        for f in clog_received:
            raw = f.get('data', b'')
            rpm_rx = 0.0
            if len(raw) >= 5:
                rpm_rx = int.from_bytes(raw[3:5], 'little') / 8.0
            print(f"    seq={f['seq']}  SA=0x{f.get('sa',0):02X}  "
                  f"PGN={pgn_name(f.get('pgn',0))}  rpm={rpm_rx:.0f}  "
                  f"data={raw.hex()}")
        if len(clog_received) < FRAMES_TO_SEND:
            print(f"  [WARN]  Only {len(clog_received)}/{FRAMES_TO_SEND} frames "
                  f"received — possible frame loss.")
        return True
    else:
        print(f"  [FAIL]  No CLOG TYPE_J1939 frame for PGN 0x{PGN_EEC1:05X}.")
        print("  Check:")
        print("    - J1939 mode enabled? (config.can.j1939 = 1)")
        print("    - Physical bus wired FDCAN1 ↔ FDCAN2 with 120Ω at each end?")
        print("    - ch1 logging enabled?")
        return False


if __name__ == '__main__':
    sys.exit(0 if run() else 1)
