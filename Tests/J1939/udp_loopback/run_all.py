#!/usr/bin/env python3
"""
run_all.py — run the full UDP-loopback J1939 test suite.

Usage:
    python run_all.py           # all 5 tests
    python run_all.py 2 3 5     # only tests 02, 03, 05

Prerequisites
─────────────
1. Hardware:
     Nucleo H755ZI  ─── FDCAN1 transceiver (PD0/PD1) ─────┐
                                                            │ 120Ω
     Nucleo H755ZI  ─── FDCAN2 transceiver (PB5/PB6)  ─────┘
     (H-to-H, L-to-L, one 120Ω resistor at each transceiver end)

2. Gateway firmware settings (web UI):
     can.j1939           = 1     J1939 mode on FDCAN1
     can.fd_mode         = 0     classic CAN  (J1939 standard)
     logging.ch1.enabled = 1     FDCAN1 RX logging
     logging.ch2.enabled = 1     FDCAN2 RX logging (loopback receive)
     logging.ch1.target  = 0     0=Ethernet  1=USB ECM
     logging.ch2.target  = 0     same as ch1

3. PC IP on the same subnet as the gateway  (default 10.104.3.x/24),
   or USB ECM on 192.168.7.x/24 if using USB.

4. Edit config.py if your gateway IP is different.

No python-can or TECMP device required.
"""

import sys
import time
import os

# Make sure sibling modules are importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import test_01_address_claim
import test_02_pgn_request
import test_03_broadcast_pgn
import test_04_transport_protocol
import test_05_dm1_diagnostics

ALL_TESTS = [
    ('01', 'Address Claim (loopback)',        test_01_address_claim.run),
    ('02', 'PGN Request → reply (loopback)',  test_02_pgn_request.run),
    ('03', 'Broadcast PGN EEC1 (loopback)',   test_03_broadcast_pgn.run),
    ('04', 'TP / BAM reassembly (loopback)',  test_04_transport_protocol.run),
    ('05', 'DM1 Active Diagnostics (loopback)', test_05_dm1_diagnostics.run),
]


def main():
    if len(sys.argv) > 1:
        requested    = {f'{int(a):02d}' for a in sys.argv[1:]}
        tests_to_run = [(n, d, f) for n, d, f in ALL_TESTS if n in requested]
        if not tests_to_run:
            print(f"No matching tests for {sys.argv[1:]}")
            sys.exit(1)
    else:
        tests_to_run = ALL_TESTS

    print()
    print("╔══════════════════════════════════════════════════════════╗")
    print("║   CAN-ETH Gateway  —  J1939 UDP Loopback Test Suite     ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print()

    results = []
    for num, desc, fn in tests_to_run:
        try:
            ok = fn()
        except Exception as exc:
            import traceback
            print(f"\n  [ERROR] Test {num} raised: {exc}")
            traceback.print_exc()
            ok = False
        results.append((num, desc, ok))
        print()
        time.sleep(0.5)

    print("╔══════════════════════════════════════════════════════════╗")
    print("║  Results                                                 ║")
    print("╠══════════════════════════════════════════════════════════╣")
    all_pass = True
    for num, desc, ok in results:
        status = "PASS ✓" if ok else "FAIL ✗"
        line = f"  {num}  {desc:<38} {status}"
        print(f"║ {line:<56} ║")
        if not ok:
            all_pass = False
    print("╚══════════════════════════════════════════════════════════╝")
    print()
    if all_pass:
        print("All tests passed.")
    else:
        failed = [n for n, _, ok in results if not ok]
        print(f"Failed: {', '.join(failed)}")
    sys.exit(0 if all_pass else 1)


if __name__ == '__main__':
    main()
