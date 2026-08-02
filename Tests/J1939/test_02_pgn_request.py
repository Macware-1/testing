#!/usr/bin/env python3
"""
test_02_pgn_request.py
──────────────────────
Test: Send a PGN Request to the gateway and expect an Address Claimed reply.

PGN 0xEA00 (Request) carries a 3-byte little-endian PGN that the target ECU
should respond to.  We ask the gateway (SA=0x80) to re-send its Address Claimed
(PGN 0xEE00).  Open-SAE-J1939 handles this with
SAE_J1939_Response_Request_Address_Claimed().

Sent CAN ID:   0x18EA80FE  (priority=6, PF=0xEA, DA=0x80, SA=0xFE)
Expected reply: 0x18EEFF80  (priority=6, PF=0xEE, PS=0xFF, SA=0x80)
"""

import sys
import time
from config import (make_bus, CAN_INTERFACE, CAN_CHANNEL, CAN_BITRATE,
                    GW_ADDRESS, MY_ADDRESS, BUS_TIMEOUT_S)
from j1939_utils import (CanMessage, decode_j1939_id, make_request_frame,
                          PGN_ADDRESS_CLAIMED, PGN_REQUEST)


def run() -> bool:
    print("=" * 60)
    print("TEST 02 — PGN Request → Address Claimed reply")
    print("=" * 60)

    req_id, req_data = make_request_frame(PGN_ADDRESS_CLAIMED, MY_ADDRESS, GW_ADDRESS)
    print(f"  Sending PGN Request  ID=0x{req_id:08X}  data={req_data.hex()}")

    bus = make_bus()
    passed = False
    try:
        msg = CanMessage(arbitration_id=req_id, is_extended_id=True,
                          data=req_data, is_remote_frame=False)
        bus.send(msg)
        print(f"  Waiting up to {BUS_TIMEOUT_S}s for reply …")

        deadline = time.monotonic() + BUS_TIMEOUT_S
        while time.monotonic() < deadline:
            rx = bus.recv(timeout=deadline - time.monotonic())
            if rx is None:
                break
            if not rx.is_extended_id:
                continue
            d = decode_j1939_id(rx.arbitration_id)
            if d['sa'] == GW_ADDRESS and d['pgn'] == PGN_ADDRESS_CLAIMED:
                print(f"\n  [PASS]  Gateway replied with Address Claimed!")
                print(f"          CAN ID = 0x{rx.arbitration_id:08X}")
                print(f"          NAME   = {rx.data[:8].hex()}")
                passed = True
                break
    finally:
        bus.shutdown()

    if not passed:
        print(f"\n  [FAIL]  No reply from SA=0x{GW_ADDRESS:02X} within {BUS_TIMEOUT_S}s.")
        print("  Make sure the gateway is running and address claim completed (run test_01 first).")

    return passed


if __name__ == '__main__':
    sys.exit(0 if run() else 1)
