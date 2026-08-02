#!/usr/bin/env python3
"""
test_05_dm1_diagnostics.py
───────────────────────────
Test: DM1 Active Diagnostics — the gateway parses and logs DTC information.

DM1 (PGN 0xFECA) broadcasts currently active Diagnostic Trouble Codes (DTCs).
Open-SAE-J1939 parses it with SAE_J1939_Read_DM1() and stores the result in
j1939.from_other_ecu_dm.dm1.  After each call to Listen_For_Messages() that
returns RX_MSG_RESP_REQ_DM1, can_task.cpp calls j1939_data_update_dtc() which
makes the DTC visible on the web dashboard.

DM1 frame layout (8 bytes for a single DTC):
  Byte 0   Lamp status (bits [7:4]=protect, [3:0]=amber)
  Byte 1   Flash status
  Byte 2-3 SPN bits [7:0] and [15:8]
  Byte 4   SPN bits [18:16] (upper 3) | FMI (lower 5)
  Byte 5   Occurrence count (7 bits) | CM (1 bit)
  Byte 6-7 0xFF 0xFF  (no second DTC)

We send one DM1 with:
  Lamp   = Red Stop (lamp byte = 0x11)
  SPN    = 100  (Engine Oil Pressure)
  FMI    = 3    (Voltage above normal range)
  Count  = 1
"""

import sys
import time
import threading
from config import (make_bus, CAN_INTERFACE, CAN_CHANNEL, CAN_BITRATE,
                    CLOG_LISTEN_IP, CLOG_LISTEN_PORT, CLOG_TIMEOUT_S)
from j1939_utils import (CanMessage, make_j1939_id, decode_clog, open_clog_socket,
                          PGN_DM1, CLOG_TYPE_J1939)

DM1_SENDER_SA = 0x00   # simulated engine ECU (SA=0x00 = engine)


def encode_dm1(spn: int, fmi: int, occurrence: int, lamp_byte: int = 0x11) -> bytes:
    """Encode a single-DTC DM1 payload (8 bytes)."""
    spn_b0 =  spn        & 0xFF
    spn_b1 = (spn >> 8)  & 0xFF
    spn_b2 = (spn >> 16) & 0x07   # upper 3 bits of SPN in bits [7:5]
    byte4  = (spn_b2 << 5) | (fmi & 0x1F)
    byte5  = (occurrence & 0x7F)   # CM=0 (no concurrent occurrences)
    return bytes([lamp_byte, 0x00, spn_b0, spn_b1, byte4, byte5, 0xFF, 0xFF])


def run() -> bool:
    print("=" * 60)
    print("TEST 05 — DM1 Active Diagnostics")
    print("=" * 60)

    spn  = 100   # Engine Oil Pressure
    fmi  = 3     # Voltage above normal range
    cnt  = 1

    data   = encode_dm1(spn, fmi, cnt)
    can_id = make_j1939_id(6, PGN_DM1, DM1_SENDER_SA)

    print(f"  DM1  SA=0x{DM1_SENDER_SA:02X}  SPN={spn}  FMI={fmi}  count={cnt}")
    print(f"  CAN ID = 0x{can_id:08X}  data = {data.hex()}")
    print()
    print("  Sending 3× DM1 at 1 Hz (J1939 spec: repeat every second while active) …")

    # CLOG listener
    clog_found = []
    clog_event = threading.Event()

    def clog_listener():
        sock = open_clog_socket(CLOG_LISTEN_IP, CLOG_LISTEN_PORT, timeout=CLOG_TIMEOUT_S)
        deadline = time.monotonic() + CLOG_TIMEOUT_S + 4.0
        try:
            while time.monotonic() < deadline:
                try:
                    raw, _ = sock.recvfrom(256)
                    f = decode_clog(raw)
                    if (f and f['type'] == CLOG_TYPE_J1939
                            and f.get('pgn') == PGN_DM1
                            and f.get('sa') == DM1_SENDER_SA):
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
        for i in range(3):
            msg = CanMessage(arbitration_id=can_id, is_extended_id=True, data=data)
            bus.send(msg)
            print(f"    Sent DM1 #{i+1}")
            time.sleep(1.0)
    finally:
        bus.shutdown()

    clog_event.wait(timeout=CLOG_TIMEOUT_S + 4)
    t.join(timeout=1)

    print()
    if clog_found:
        f = clog_found[0]
        raw = f.get('data', b'')
        print(f"  [PASS]  DM1 frame logged via CLOG!")
        print(f"          SA   = 0x{f.get('sa',0):02X}")
        print(f"          data = {raw.hex()}")
        if len(raw) >= 6:
            r_spn = raw[2] | (raw[3] << 8) | ((raw[4] >> 5) << 16)
            r_fmi = raw[4] & 0x1F
            r_cnt = raw[5] & 0x7F
            print(f"          SPN={r_spn}  FMI={r_fmi}  count={r_cnt}")
            if r_spn == spn and r_fmi == fmi:
                print("          SPN/FMI decoded correctly ✓")
            else:
                print(f"  [WARN]  Decoded SPN={r_spn} FMI={r_fmi}, expected SPN={spn} FMI={fmi}")
        return True
    else:
        print(f"  [FAIL]  No CLOG DM1 frame from SA=0x{DM1_SENDER_SA:02X}.")
        return False


if __name__ == '__main__':
    sys.exit(0 if run() else 1)
