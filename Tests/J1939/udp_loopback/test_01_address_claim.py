#!/usr/bin/env python3
"""
test_01_address_claim.py  (UDP loopback)
─────────────────────────────────────────
Test: Gateway broadcasts Address Claimed (PGN 0xEE00) on boot.

Loopback path:
  Gateway FDCAN1 TX  ──►  CAN bus  ──►  FDCAN2 RX  ──►  CLOG ch2  (TYPE_RAW_CAN)

The frame arrives at the PC as a CLOG TYPE_RAW_CAN frame (FDCAN2 does not
run the J1939 library).  We decode the J1939 CAN ID to confirm it is an
address-claim (PGN = 0xEE00) from SA = 0x80.

Expected CAN ID: 0x18EEFF80
  priority=6  PF=0xEE  PS=0xFF (global dest)  SA=0x80
"""

import sys
import time
from config import GW_IP, GW_ADDRESS, BOOT_WAIT_S, CLOG_PORT, CLOG_TIMEOUT_S
from udp_inject import ClogListener, raw_frame_j1939, is_raw_type

# Import shared utilities from parent J1939_test/
import os; sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from j1939_utils import PGN_ADDRESS_CLAIMED


def run() -> bool:
    print("=" * 60)
    print("TEST 01 — Address Claim  (UDP loopback)")
    print("=" * 60)
    print(f"  Expected: SA=0x{GW_ADDRESS:02X}  PGN=0x{PGN_ADDRESS_CLAIMED:05X} (AddressClaimed)")
    print(f"  Loopback: FDCAN1 TX → bus → FDCAN2 RX → CLOG ch2 (TYPE_RAW_CAN)")
    print()
    input("  >>> Power-cycle / reboot the gateway now, then press Enter <<<")
    print(f"  Listening on CLOG port {CLOG_PORT} for {BOOT_WAIT_S + 2:.0f}s …")

    deadline = time.monotonic() + BOOT_WAIT_S + 2.0

    def is_address_claim(f):
        if not is_raw_type(f):
            return False
        d = raw_frame_j1939(f)
        return d['pgn'] == PGN_ADDRESS_CLAIMED and d['sa'] == GW_ADDRESS

    with ClogListener(port=CLOG_PORT) as cl:
        found = cl.recv_until(is_address_claim, deadline)

    if found:
        d = raw_frame_j1939(found)
        data = found.get('data', b'')
        print(f"\n  [PASS]  Address Claim received via CLOG ch2!")
        print(f"          CAN ID   = 0x{found['can_id']:08X}")
        print(f"          SA       = 0x{d['sa']:02X}")
        print(f"          Priority = {d['priority']}")
        if data:
            print(f"          NAME     = {data.hex()}")
        return True
    else:
        print(f"\n  [FAIL]  No address claim from SA=0x{GW_ADDRESS:02X} "
              f"within {BOOT_WAIT_S + 2:.0f}s.")
        print("  Check:")
        print("    - J1939 mode enabled? (config.can.j1939 = 1)")
        print("    - Both channels logged? (ch1 + ch2 enabled, same target)")
        print("    - Physical bus connected? (FDCAN1 ↔ FDCAN2 with 120Ω each end)")
        return False


if __name__ == '__main__':
    sys.exit(0 if run() else 1)
