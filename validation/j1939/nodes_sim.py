#!/usr/bin/env python3
"""
nodes_sim.py — J1939 Network Node discovery test tool.

Sends J1939 Address Claimed (PGN 0xEE00) frames from multiple simulated ECUs
to exercise the "J1939 Network Nodes" page of the web UI.

How it works:
  The gateway's J1939 library (Open-SAE-J1939, on FDCAN1) detects Address
  Claimed frames and populates its other_ECU_address[] table, which can_task
  writes to j1939_data via j1939_data_update_nodes().  The web UI polls
  /api/nodes every 5 seconds and shows the discovered addresses.

IMPORTANT: Physical CAN only (channel 1 = FDCAN2).
  The software sim path (channel 255) bypasses the J1939 library entirely,
  so address discovery never happens.  You must use channel 1: frames are
  injected OUT on FDCAN2 and FDCAN1 picks them up on the shared CAN bus.

Simulated ECUs:
  SA=0x00  Engine Controller (EEC)          — Function 0,   IG 0
  SA=0x03  Transmission Controller          — Function 3,   IG 0
  SA=0x17  ABS/Brake Controller             — Function 23,  IG 0
  SA=0x23  Instrument Cluster               — Function 40,  IG 0
  SA=0x27  Battery/Power Management ECU     — Function 14,  IG 0

Modes:
  default  — all ECUs broadcast Address Claimed continuously (1 s interval)
  --join   — ECUs appear on the bus one by one (--join-delay seconds each),
             then all broadcast continuously
  --count N — use only the first N ECUs (1–5)

Usage:
  python3 nodes_sim.py                          # broadcast all, channel 1
  python3 nodes_sim.py --join                   # join one-by-one, then all
  python3 nodes_sim.py --join --join-delay 8    # 8 s per new ECU
  python3 nodes_sim.py --count 3                # only 3 ECUs
  python3 nodes_sim.py --ip 192.168.1.x         # custom gateway IP
"""

import argparse
import socket
import struct
import sys
import time

import config

# ── Inject protocol ───────────────────────────────────────────────────────────
INJECT_MAGIC    = 0xCA
INJECT_FLAG_EXT = 0x01   # 29-bit extended frame
INJECT_FLAG_J1939 = 0x02

# ── J1939 PGN constants ───────────────────────────────────────────────────────
PGN_ADDR_CLAIMED = 0xEE00  # Address Claimed / Cannot Claim Address (PDU1, DA=0xFF=global)

# ── Terminal colours ──────────────────────────────────────────────────────────
GREEN  = "\033[92m"
CYAN   = "\033[96m"
YELLOW = "\033[93m"
GRAY   = "\033[90m"
BOLD   = "\033[1m"
RESET  = "\033[0m"


# ── J1939 NAME builder ────────────────────────────────────────────────────────

def make_j1939_name(identity=0, manufacturer=0x717, ecu_inst=0, func_inst=0,
                    function=0, vehicle_system=0, vehicle_sys_inst=0,
                    industry_group=0, arb_capable=1):
    """
    Pack a 64-bit J1939 NAME into 8 bytes (little-endian) per SAE J1939-81.

    Bit layout (bit 0 = LSB of 64-bit value):
      [0:20]  Identity Number (21 bits)
      [21:31] Manufacturer Code (11 bits)
      [32:34] ECU Instance (3 bits)
      [35:39] Function Instance (5 bits)
      [40:47] Function (8 bits)
      [48]    Reserved
      [49:55] Vehicle System (7 bits)
      [56:59] Vehicle System Instance (4 bits)
      [60:62] Industry Group (3 bits)
      [63]    Arbitrary Address Capable (1 bit)
    """
    b0 = identity & 0xFF
    b1 = (identity >> 8) & 0xFF
    b2 = ((identity >> 16) & 0x1F) | ((manufacturer & 0x07) << 5)
    b3 = (manufacturer >> 3) & 0xFF
    b4 = (ecu_inst & 0x07) | ((func_inst & 0x1F) << 3)
    b5 = function & 0xFF
    b6 = 0 | ((vehicle_system & 0x7F) << 1)   # bit 0 = reserved = 0
    b7 = ((vehicle_sys_inst & 0x0F)
          | ((industry_group & 0x07) << 4)
          | ((arb_capable & 0x01) << 7))
    return bytes([b0, b1, b2, b3, b4, b5, b6, b7])


# ── CAN ID builder for Address Claimed ────────────────────────────────────────

def addr_claimed_can_id(sa, priority=6):
    """
    Build 29-bit CAN ID for PGN 0xEE00 (Address Claimed) sent to global DA=0xFF.
    PF=0xEE < 0xF0 → PDU1: PS field = destination address = 0xFF (global).
    """
    pf = 0xEE
    dp = 0
    da = 0xFF   # global broadcast destination
    return ((priority & 0x7) << 26) | (dp << 24) | (pf << 16) | ((da & 0xFF) << 8) | (sa & 0xFF)


# ── Inject packet builder ─────────────────────────────────────────────────────

def inject_packet(can_id, payload, channel):
    flags = INJECT_FLAG_EXT | INJECT_FLAG_J1939
    hdr = struct.pack('<BBBBI', INJECT_MAGIC, channel & 0xFF, flags, len(payload), can_id)
    return hdr + payload


# ── Simulated ECU definitions ─────────────────────────────────────────────────
#
# Manufacturer codes (11-bit, assigned by SAE):
#   0x717 = generic test/simulation
#   0x33F = generic second manufacturer
#
# J1939-81 function codes (on-highway, IG=0):
#   0  = Engine
#   3  = Transmission
#   14 = Electrical System
#   23 = Brakes / Traction Control
#   40 = Instrument Cluster

ECUS = [
    {
        "name":     "Engine Controller (EEC)",
        "sa":       0x00,
        "name_payload": make_j1939_name(
            identity=0x0001, manufacturer=0x717,
            function=0, industry_group=0, arb_capable=1,
        ),
    },
    {
        "name":     "Transmission Controller",
        "sa":       0x03,
        "name_payload": make_j1939_name(
            identity=0x0002, manufacturer=0x717,
            function=3, industry_group=0, arb_capable=1,
        ),
    },
    {
        "name":     "ABS/Brake Controller",
        "sa":       0x17,
        "name_payload": make_j1939_name(
            identity=0x0010, manufacturer=0x33F,
            function=23, industry_group=0, arb_capable=1,
        ),
    },
    {
        "name":     "Instrument Cluster",
        "sa":       0x23,
        "name_payload": make_j1939_name(
            identity=0x0020, manufacturer=0x33F,
            function=40, industry_group=0, arb_capable=1,
        ),
    },
    {
        "name":     "Battery/Power Management ECU",
        "sa":       0x27,
        "name_payload": make_j1939_name(
            identity=0x0030, manufacturer=0x717,
            function=14, industry_group=0, arb_capable=1,
        ),
    },
]


# ── Display helpers ────────────────────────────────────────────────────────────

def print_status(active_ecus, mode_label):
    sys.stdout.write("\033[2J\033[H")
    print(f"{BOLD}=== J1939 Network Node Simulator ==={RESET}")
    print(f"  Mode: {CYAN}{mode_label}{RESET}")
    print()
    print(f"  {'SA':6}  {'Name'}")
    print(f"  {'-'*50}")
    for ecu in active_ecus:
        print(f"  {GREEN}0x{ecu['sa']:02X}{RESET}    {ecu['name']}")
    if not active_ecus:
        print(f"  {GRAY}(no ECUs broadcasting yet){RESET}")
    print()
    print(f"  {YELLOW}Check the 'J1939 Network Nodes' page in the web UI{RESET}")
    print(f"  {GRAY}(web UI polls /api/nodes every 5 s){RESET}")
    print()
    print(f"  Ctrl-C to stop")


# ── Main ──────────────────────────────────────────────────────────────────────

def run(ip, port, channel, ecus, join_mode, join_delay):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect((ip, port))

    def send_addr_claimed(ecu):
        can_id = addr_claimed_can_id(ecu["sa"])
        pkt = inject_packet(can_id, ecu["name_payload"], channel)
        sock.send(pkt)

    if join_mode:
        # Phase 1: ECUs appear one by one
        active = []
        for ecu in ecus:
            active.append(ecu)
            deadline = time.time() + join_delay
            while time.time() < deadline:
                print_status(active, f"Join mode — {ecu['name']} just joined, next in {deadline - time.time():.0f}s")
                for e in active:
                    send_addr_claimed(e)
                time.sleep(1.0)
    else:
        active = ecus

    # Phase 2: all active ECUs broadcast continuously
    while True:
        print_status(active, "Broadcasting all ECUs")
        for ecu in active:
            send_addr_claimed(ecu)
        time.sleep(1.0)


def main():
    ap = argparse.ArgumentParser(description="J1939 Address Claimed / Nodes page test tool")
    ap.add_argument("--ip",         default=config.GW_IP,   help="Gateway IP")
    ap.add_argument("--port",       default=config.GW_PORT, type=int, help="UDP inject port")
    ap.add_argument("--channel",    default=1,              type=int,
                    help="CAN channel: 1=FDCAN2 physical (default). Channel 255 does NOT work for "
                         "node discovery (bypasses the J1939 library).")
    ap.add_argument("--join",       action="store_true",
                    help="Introduce ECUs one-by-one instead of all at once")
    ap.add_argument("--join-delay", default=10, type=int,
                    help="Seconds between each new ECU joining (default 10, requires --join)")
    ap.add_argument("--count",      default=5,  type=int, choices=range(1, 6),
                    metavar="N",    help="Number of ECUs to simulate (1–5, default 5)")
    args = ap.parse_args()

    if args.channel == 255:
        print("[warn] Channel 255 (software sim) bypasses the J1939 library.")
        print("[warn] Node discovery only works via the physical CAN path (channel 1).")
        print("[warn] Use --channel 1 and ensure FDCAN1+FDCAN2 share the same CAN bus.")
        sys.exit(1)

    ecus = ECUS[:args.count]

    print(f"Sending Address Claimed to {args.ip}:{args.port}  channel={args.channel}")
    print(f"Simulating {len(ecus)} ECU(s):")
    for e in ecus:
        print(f"  SA=0x{e['sa']:02X}  {e['name']}")
    print()
    print("FDCAN1 and FDCAN2 must be on the same physical CAN bus with 120Ω termination.")
    print()

    try:
        run(args.ip, args.port, args.channel, ecus, args.join, args.join_delay)
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
