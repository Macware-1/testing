#!/usr/bin/env python3
"""
test_03_broadcast_pgn.py
────────────────────────
Test: Send broadcast PGN frames and verify they appear in CLOG over USB ECM.

We send 5 EEC1 frames (Electronic Engine Controller 1, PGN 0xF004) as a
broadcast (PDU2, PF=0xF0, PS=0x04 = part of PGN).  The gateway should:
  1. Receive each frame via FDCAN interrupt.
  2. Pass it through Open_SAE_J1939_Listen_For_Messages().
  3. Return RX_MSG_NOT_SAE_J1939 or RX_MSG_UNKNOWN (EEC1 is not handled by the
     library — it gets forwarded raw).
  4. Forward to Ethernet (EtherType 0x88B5).
  5. Send a CLOG TYPE_J1939 frame on UDP 47808 to the USB ECM broadcast.

The test verifies step 5: at least one CLOG frame arrives for PGN 0xF004.

EEC1 byte layout (J1939-71):
  Byte 0    Engine Torque Mode
  Byte 1    Driver Demand Engine - Percent Torque
  Byte 2    Actual Engine - Percent Torque
  Bytes 3-4 Engine Speed (1/8 rpm per bit, little-endian)
  Byte 5    Source Address of Controlling Device
  Byte 6    Engine Starter Mode
  Byte 7    Engine Demand Engine - Percent Torque
"""

import sys
import time
import threading
from config import (make_bus, CAN_INTERFACE, CAN_CHANNEL, CAN_BITRATE,
                    MY_ADDRESS, CLOG_LISTEN_IP, CLOG_LISTEN_PORT, CLOG_TIMEOUT_S)
from j1939_utils import (CanMessage, make_j1939_id, decode_clog, open_clog_socket, pgn_name,
                          PGN_EEC1, CLOG_TYPE_J1939)

FRAMES_TO_SEND = 5
SEND_INTERVAL  = 0.1   # seconds between frames


def encode_eec1(rpm: float) -> bytes:
    """Encode a minimal EEC1 payload at the given engine speed."""
    speed_raw = int(rpm * 8) & 0xFFFF   # 1/8 rpm per bit
    return bytes([
        0xFF,                          # Byte 0: torque mode (not available)
        0xFF,                          # Byte 1: driver demand
        0xFF,                          # Byte 2: actual torque
        speed_raw & 0xFF,              # Byte 3: speed LSB
        (speed_raw >> 8) & 0xFF,       # Byte 4: speed MSB
        MY_ADDRESS,                    # Byte 5: controlling SA
        0xFF,                          # Byte 6: starter mode
        0xFF,                          # Byte 7: demand torque
    ])


def run() -> bool:
    print("=" * 60)
    print("TEST 03 — Broadcast PGN (EEC1) → CLOG over USB ECM")
    print("=" * 60)
    print(f"  Sending {FRAMES_TO_SEND}× EEC1 (PGN 0x{PGN_EEC1:05X}) frames …")

    can_id = make_j1939_id(priority=6, pgn=PGN_EEC1, sa=MY_ADDRESS)
    print(f"  CAN ID = 0x{can_id:08X}")

    clog_received = []
    clog_event = threading.Event()

    def clog_listener():
        sock = open_clog_socket(CLOG_LISTEN_IP, CLOG_LISTEN_PORT, timeout=CLOG_TIMEOUT_S)
        deadline = time.monotonic() + CLOG_TIMEOUT_S + SEND_INTERVAL * FRAMES_TO_SEND
        try:
            while time.monotonic() < deadline:
                try:
                    raw, _ = sock.recvfrom(256)
                    f = decode_clog(raw)
                    if f and f['type'] == CLOG_TYPE_J1939 and f.get('pgn') == PGN_EEC1:
                        clog_received.append(f)
                        if len(clog_received) >= FRAMES_TO_SEND:
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
        for i in range(FRAMES_TO_SEND):
            rpm = 800 + i * 100   # 800, 900, 1000, 1100, 1200 rpm
            data = encode_eec1(rpm)
            msg  = CanMessage(arbitration_id=can_id, is_extended_id=True, data=data)
            bus.send(msg)
            print(f"    Sent EEC1  {rpm} rpm  data={data.hex()}")
            time.sleep(SEND_INTERVAL)
    finally:
        bus.shutdown()

    t.join(timeout=CLOG_TIMEOUT_S + 1)

    print()
    if clog_received:
        print(f"  [PASS]  {len(clog_received)} CLOG J1939 frame(s) received on USB ECM:")
        for f in clog_received:
            rpm_raw = int.from_bytes(f['data'][3:5], 'little') / 8.0 if len(f['data']) >= 5 else 0
            print(f"    seq={f['seq']}  SA=0x{f.get('sa',0):02X}  "
                  f"PGN={pgn_name(f.get('pgn',0))}  "
                  f"rpm={rpm_raw:.0f}  data={f['data'].hex()}")
        return True
    else:
        print(f"  [FAIL]  No CLOG frame for PGN 0x{PGN_EEC1:05X} within {CLOG_TIMEOUT_S}s.")
        print("  Check:")
        print("    - USB ECM cable connected?")
        print("    - PC IP on 10.10.10.x/24?  (gateway USB IP = 10.10.10.15)")
        print("    - Logging enabled? (ch1.enabled=1, ch1.target=1 in web UI)")
        return False


if __name__ == '__main__':
    sys.exit(0 if run() else 1)
