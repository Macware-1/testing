#!/usr/bin/env python3
"""
test_02_pgn_request.py  (UDP loopback)
───────────────────────────────────────
Test: Send a PGN Request and expect an Address Claimed reply from the gateway.

Inject path  :  UDP inject ch1  →  FDCAN2 TX  →  bus  →  FDCAN1 RX  →  J1939 lib
Reply path   :  J1939 lib  →  FDCAN1 TX  →  bus  →  FDCAN2 RX  →  CLOG ch2 (TYPE_RAW_CAN)

We send PGN_REQUEST (0xEA00) to DA=0x80 asking for Address Claimed (0xEE00).
Open_SAE_J1939 handles this with SAE_J1939_Response_Request_Address_Claimed().
The gateway's reply arrives via CLOG ch2 as a TYPE_RAW_CAN frame with
CAN ID 0x18EEFF80  (SA=0x80, PGN=0xEE00).
"""

import sys
import time
import os
from config import GW_IP, GW_ADDRESS, MY_ADDRESS, INJECT_CHANNEL, CLOG_PORT, CLOG_TIMEOUT_S

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from j1939_utils import CanMessage, make_request_frame, PGN_ADDRESS_CLAIMED, PGN_REQUEST
from udp_inject import UdpInjector, ClogListener, raw_frame_j1939, is_raw_type


def run() -> bool:
    print("=" * 60)
    print("TEST 02 — PGN Request → Address Claimed reply  (UDP loopback)")
    print("=" * 60)

    req_id, req_data = make_request_frame(PGN_ADDRESS_CLAIMED, MY_ADDRESS, GW_ADDRESS)
    print(f"  Sending PGN Request  ID=0x{req_id:08X}  data={req_data.hex()}")
    print(f"  Inject channel: {INJECT_CHANNEL} (FDCAN{INJECT_CHANNEL + 1} TX → bus → FDCAN1 RX)")
    print(f"  Expect reply via CLOG ch2 (FDCAN2 RX)  within {CLOG_TIMEOUT_S}s …")

    def is_address_claim_reply(f):
        if not is_raw_type(f):
            return False
        d = raw_frame_j1939(f)
        return d['pgn'] == PGN_ADDRESS_CLAIMED and d['sa'] == GW_ADDRESS

    injector = UdpInjector(GW_IP, channel=INJECT_CHANNEL)
    with ClogListener(port=CLOG_PORT) as cl:
        msg = CanMessage(arbitration_id=req_id, data=req_data, is_extended_id=True)
        injector.send(msg)
        print(f"  Sent.")
        found = cl.recv_until(is_address_claim_reply,
                              deadline=time.monotonic() + CLOG_TIMEOUT_S)
    injector.shutdown()

    if found:
        d = raw_frame_j1939(found)
        data = found.get('data', b'')
        print(f"\n  [PASS]  Address Claimed reply received via CLOG ch2!")
        print(f"          CAN ID = 0x{found['can_id']:08X}")
        print(f"          SA     = 0x{d['sa']:02X}")
        if data:
            print(f"          NAME   = {data.hex()}")
        return True
    else:
        print(f"\n  [FAIL]  No Address Claimed reply from SA=0x{GW_ADDRESS:02X} "
              f"within {CLOG_TIMEOUT_S}s.")
        print("  Check:")
        print("    - J1939 mode enabled? (run test_01 to confirm gateway is alive)")
        print("    - Physical bus connected with 120Ω termination at each end?")
        print("    - ch2 logging enabled and ch2.target matches network interface?")
        return False


if __name__ == '__main__':
    sys.exit(0 if run() else 1)
