#!/usr/bin/env python3
"""
test_01_address_claim.py
────────────────────────
Test: Gateway broadcasts Address Claimed (PGN 0xEE00) on boot.

When the gateway starts in J1939 mode, Open_SAE_J1939_Startup_ECU() sends an
Address Claimed frame (PGN 0xEE00) with SA=0x80 so every node on the bus
knows it exists.

What this test does:
  1. Opens the CAN bus.
  2. Prompts you to power-cycle / reboot the gateway.
  3. Waits up to BOOT_WAIT_S seconds for PGN 0xEE00 from SA=0x80.
  4. PASS  — frame received, prints the 8-byte NAME field.
  5. FAIL  — timeout with no matching frame.

Expected CAN ID: 0x18EEFF80
  priority=6, PF=0xEE (PDU1), PS=0xFF (global dest), SA=0x80
"""

import sys
import time
from config import make_bus, CAN_INTERFACE, CAN_CHANNEL, CAN_BITRATE, GW_ADDRESS, BOOT_WAIT_S
from j1939_utils import CanMessage, decode_j1939_id, PGN_ADDRESS_CLAIMED


def run() -> bool:
    print("=" * 60)
    print("TEST 01 — Address Claim")
    print("=" * 60)
    print(f"Expected: SA=0x{GW_ADDRESS:02X}, PGN=0x{PGN_ADDRESS_CLAIMED:05X} (AddressClaimed)")
    print()
    input("  >>> Reboot / power-cycle the gateway now, then press Enter <<<")
    print(f"  Listening for {BOOT_WAIT_S}s …")

    bus = make_bus()
    bus.set_filters([{"can_id": 0, "can_mask": 0, "extended": True}])

    deadline = time.monotonic() + BOOT_WAIT_S
    found = False
    try:
        while time.monotonic() < deadline:
            msg = bus.recv(timeout=deadline - time.monotonic())
            if msg is None:
                break
            if not msg.is_extended_id:
                continue
            d = decode_j1939_id(msg.arbitration_id)
            if d['pgn'] == PGN_ADDRESS_CLAIMED and d['sa'] == GW_ADDRESS:
                name_hex = msg.data[:8].hex()
                print(f"\n  [PASS]  Address Claim received!")
                print(f"          SA       = 0x{d['sa']:02X}")
                print(f"          CAN ID   = 0x{msg.arbitration_id:08X}")
                print(f"          NAME     = {name_hex}")
                print(f"          Priority = {d['priority']}")
                found = True
                break
    finally:
        bus.shutdown()

    if not found:
        print(f"\n  [FAIL]  No Address Claim from SA=0x{GW_ADDRESS:02X} within {BOOT_WAIT_S}s.")
        print("  Check: J1939 mode enabled? (config_.can.j1939=1)")
        print("         Bit timing 250 kbps? (nbrp=4, ntseg1=59, ntseg2=20)")
        print("         CAN transceiver wired? Termination 120Ω each end?")

    return found


if __name__ == '__main__':
    sys.exit(0 if run() else 1)
