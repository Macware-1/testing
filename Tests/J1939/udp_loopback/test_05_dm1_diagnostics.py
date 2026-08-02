#!/usr/bin/env python3
"""
test_05_dm1_diagnostics.py  (UDP loopback)
───────────────────────────────────────────
Test: DM1 Active Diagnostics — gateway receives and logs DTC data.

DM1 (PGN 0xFECA) carries active Diagnostic Trouble Codes.
Open_SAE_J1939 parses it and can_task.cpp calls j1939_data_update_dtc()
to make the DTC visible on the web dashboard.

Inject path:
  UDP inject ch1  →  FDCAN2 TX  →  bus  →  FDCAN1 RX
  →  J1939 DM1 handler  →  CLOG ch1  (TYPE_J1939)

We send 3 DM1 frames at 1 Hz (J1939 spec requires ≥1 Hz repeat while fault active).

Test DTC:
  SPN = 100  (Engine Oil Pressure)
  FMI = 3    (Voltage above normal range)
  Count = 1
  Lamp = Red Stop  (0x11)

DM1 byte layout (single DTC, 8 bytes):
  [0]   Lamp status (bits[7:4]=protect, bits[3:0]=amber warning)
  [1]   Flash status (0x00 = not flashing)
  [2]   SPN bits [7:0]
  [3]   SPN bits [15:8]
  [4]   SPN bits [18:16] in upper 3 bits | FMI in lower 5 bits
  [5]   Occurrence count (7 bits) | CM bit
  [6-7] 0xFF 0xFF  (no second DTC)
"""

import sys
import os
import time
import threading
from config import GW_IP, INJECT_CHANNEL, CLOG_PORT, CLOG_TIMEOUT_S, TP_SENDER_SA as DM1_SA

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from j1939_utils import CanMessage, make_j1939_id, pgn_name, PGN_DM1, CLOG_TYPE_J1939
from udp_inject import UdpInjector, ClogListener, is_j1939_type


def encode_dm1(spn: int, fmi: int, occurrence: int, lamp: int = 0x11) -> bytes:
    spn_b0 =  spn        & 0xFF
    spn_b1 = (spn >>  8) & 0xFF
    spn_b2 = (spn >> 16) & 0x07
    byte4  = (spn_b2 << 5) | (fmi & 0x1F)
    byte5  = occurrence & 0x7F
    return bytes([lamp, 0x00, spn_b0, spn_b1, byte4, byte5, 0xFF, 0xFF])


def run() -> bool:
    print("=" * 60)
    print("TEST 05 — DM1 Active Diagnostics  (UDP loopback)")
    print("=" * 60)

    spn  = 100
    fmi  = 3
    cnt  = 1
    data   = encode_dm1(spn, fmi, cnt)
    can_id = make_j1939_id(6, PGN_DM1, DM1_SA)

    print(f"  SA     = 0x{DM1_SA:02X}")
    print(f"  PGN    = 0x{PGN_DM1:05X} ({pgn_name(PGN_DM1)})")
    print(f"  SPN={spn}  FMI={fmi}  count={cnt}  lamp=0x11 (Red Stop)")
    print(f"  CAN ID = 0x{can_id:08X}  data = {data.hex()}")
    print(f"  Sending 3× DM1 at 1 Hz via inject ch{INJECT_CHANNEL} …")

    clog_found = []
    clog_event = threading.Event()
    deadline_rx = time.monotonic() + CLOG_TIMEOUT_S + 4.0

    def clog_listener():
        with ClogListener(port=CLOG_PORT) as cl:
            f = cl.recv_until(
                lambda x: (is_j1939_type(x)
                           and x.get('pgn') == PGN_DM1
                           and x.get('sa')  == DM1_SA),
                deadline=deadline_rx,
            )
            if f:
                clog_found.append(f)
                clog_event.set()

    t = threading.Thread(target=clog_listener, daemon=True)
    t.start()

    injector = UdpInjector(GW_IP, channel=INJECT_CHANNEL)
    try:
        for i in range(3):
            msg = CanMessage(arbitration_id=can_id, data=data, is_extended_id=True)
            injector.send(msg)
            print(f"    Sent DM1 #{i + 1}")
            time.sleep(1.0)
    finally:
        injector.shutdown()

    clog_event.wait(timeout=CLOG_TIMEOUT_S + 4)
    t.join(timeout=1)

    print()
    if clog_found:
        f   = clog_found[0]
        raw = f.get('data', b'')
        print(f"  [PASS]  DM1 logged via CLOG ch1!")
        print(f"          SA   = 0x{f.get('sa', 0):02X}")
        print(f"          data = {raw.hex()}")
        if len(raw) >= 6:
            r_spn = raw[2] | (raw[3] << 8) | ((raw[4] >> 5) << 16)
            r_fmi = raw[4] & 0x1F
            r_cnt = raw[5] & 0x7F
            print(f"          Decoded: SPN={r_spn}  FMI={r_fmi}  count={r_cnt}")
            if r_spn == spn and r_fmi == fmi:
                print("          SPN/FMI match ✓")
            else:
                print(f"  [WARN]  Expected SPN={spn} FMI={fmi}, "
                      f"got SPN={r_spn} FMI={r_fmi}")
        return True
    else:
        print(f"  [FAIL]  No CLOG TYPE_J1939 DM1 from SA=0x{DM1_SA:02X}.")
        print("  Tip: DM1 requires the J1939 library DM1 handler to be active.")
        print("       Make sure j1939_mode = 1 in gateway config.")
        return False


if __name__ == '__main__':
    sys.exit(0 if run() else 1)
