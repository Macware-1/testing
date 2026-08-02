#!/usr/bin/env python3
"""
run_all_tests.py — run the full J1939 test suite in order.

Usage:
    python run_all_tests.py           # run all 5 tests
    python run_all_tests.py 2 3 5     # run only tests 02, 03, 05

Each test returns True (pass) or False (fail).
The suite prints a summary table and exits with code 0 if all pass, 1 if any fail.

Prerequisites
─────────────
1. Hardware:
     Nucleo H755ZI  ──►  CAN transceiver  ──►  CAN bus  ◄──  USB-CAN adapter (PC)
     120 Ω termination at each end of the bus.

2. Gateway firmware settings (via web UI):
     config_.can.j1939   = 1       (J1939 mode)
     config_.can.nbrp    = 4       ← 250 kbps at PLL2Q=80 MHz
     config_.can.ntseg1  = 59
     config_.can.ntseg2  = 20
     config_.can.nsjw    = 20
     config_.can.fd_mode = 0       ← classic CAN (J1939 does not use FD)
     config_.can.brs     = 0
     logging.ch1.enabled = 1
     logging.ch1.target  = 1       ← USB ECM

3. PC USB ECM interface configured with a 10.10.10.x/24 address
   (gateway USB IP = 10.10.10.15).

4. Edit config.py to match your CAN adapter.

5. Install dependencies:
     pip install python-can
"""

import sys
import time

import test_01_address_claim
import test_02_pgn_request
import test_03_broadcast_pgn
import test_04_transport_protocol
import test_05_dm1_diagnostics

ALL_TESTS = [
    ('01', 'Address Claim',           test_01_address_claim.run),
    ('02', 'PGN Request → Reply',     test_02_pgn_request.run),
    ('03', 'Broadcast PGN → CLOG',    test_03_broadcast_pgn.run),
    ('04', 'Transport Protocol / BAM',test_04_transport_protocol.run),
    ('05', 'DM1 Active Diagnostics',  test_05_dm1_diagnostics.run),
]


def main():
    # If the user supplied test numbers as arguments, run only those
    if len(sys.argv) > 1:
        requested = set(f'{int(a):02d}' for a in sys.argv[1:])
        tests_to_run = [(n, d, f) for n, d, f in ALL_TESTS if n in requested]
        if not tests_to_run:
            print(f"No matching tests for {sys.argv[1:]}")
            sys.exit(1)
    else:
        tests_to_run = ALL_TESTS

    print()
    print("╔══════════════════════════════════════════════════════════╗")
    print("║        CAN-ETH Gateway  —  J1939 Test Suite             ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print()

    results = []
    for num, desc, fn in tests_to_run:
        try:
            ok = fn()
        except Exception as exc:
            print(f"\n  [ERROR] Test {num} raised an exception: {exc}")
            ok = False
        results.append((num, desc, ok))
        print()
        time.sleep(0.5)

    # ── Summary ──────────────────────────────────────────────────────────────
    print("╔══════════════════════════════════════════════════════════╗")
    print("║  Results                                                 ║")
    print("╠══════════════════════════════════════════════════════════╣")
    all_pass = True
    for num, desc, ok in results:
        status = "PASS ✓" if ok else "FAIL ✗"
        line = f"  {num}  {desc:<36} {status}"
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
