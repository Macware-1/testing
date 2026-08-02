#!/usr/bin/env python3
"""
dm1_sim.py — J1939 DM1 (Active Diagnostic Trouble Codes) test tool.

Sends DM1 frames to the gateway to exercise the Diagnostics page of the web UI.
Each DTC entry has:
  SPN  — Suspect Parameter Number  (which component is faulted)
  FMI  — Failure Mode Indicator    (how it failed)
  OC   — Occurrence count          (how many times since clear)

Lamp status (byte 0 of DM1):
  RSL — Red Stop Lamp    bits [5:4] = 0b01 → ON   (critical, stop immediately)
  AWL — Amber Warning Lamp bits [3:2] = 0b01 → ON (warning, monitor situation)

Severity mapping (matches web UI colour coding):
  sev-high  FMI 3,4,5,6   — electrical faults (voltage high/low, open, short)
  sev-med   FMI 0,1,2,7   — range / mechanical faults
  sev-low   FMI 8-15      — data quality / calibration issues

Scenarios (cycle automatically, or hold one with --scenario N):
  0  Clear        — all lamps off, no active DTCs
  1  AWL only     — SPN 110 (Coolant Temp)  FMI 1  below normal      sev-med
  2  AWL sev-high — SPN 190 (Engine RPM)    FMI 3  voltage high       sev-high
  3  RSL + AWL    — SPN 100 (Oil Pressure)  FMI 6  short to ground    sev-high  (critical)
  4  AWL sev-low  — SPN 247 (Engine Hours)  FMI 11 root cause unknown sev-low
  5  AWL from ECU2— SPN 168 (Battery V)     FMI 4  voltage low        sev-high  SA=0x27
  6  AWL sev-med  — SPN 96  (Fuel Level)    FMI 7  mechanical fault   sev-med
  7  Clear        — recovery, all clear

Usage:
  python3 dm1_sim.py                        # cycle all scenarios automatically
  python3 dm1_sim.py --scenario 3           # hold "critical fault" indefinitely
  python3 dm1_sim.py --ip 192.168.1.x       # custom gateway IP
  python3 dm1_sim.py --channel 255          # software path, no CAN hardware needed
  python3 dm1_sim.py --channel 1            # physical CAN via FDCAN2 (realistic)
"""

import argparse
import socket
import struct
import sys
import time

import config

# ── Inject protocol ───────────────────────────────────────────────────────────
INJECT_MAGIC    = 0xCA
INJECT_FLAG_EXT = 0x01
INJECT_FLAG_J1939 = 0x02

# ── J1939 lamp status bit values (2-bit field per lamp) ──────────────────────
LAMP_OFF = 0b00
LAMP_ON  = 0b01
LAMP_NA  = 0b11

# ── Common SPNs for realistic fault scenarios ─────────────────────────────────
SPN_ENGINE_SPEED   = 190
SPN_COOLANT_TEMP   = 110
SPN_OIL_PRESSURE   = 100
SPN_FUEL_LEVEL     = 96
SPN_BATTERY_V      = 168
SPN_ENGINE_HOURS   = 247
SPN_THROTTLE       = 91

# ── FMI codes ─────────────────────────────────────────────────────────────────
FMI_ABOVE_NORMAL    = 0
FMI_BELOW_NORMAL    = 1
FMI_ERRATIC         = 2
FMI_VOLTAGE_HIGH    = 3
FMI_VOLTAGE_LOW     = 4
FMI_OPEN_CIRCUIT    = 5
FMI_SHORT_GROUND    = 6
FMI_MECHANICAL      = 7
FMI_FREQ_ABNORMAL   = 8
FMI_UPDATE_RATE     = 9
FMI_RATE_OF_CHANGE  = 10
FMI_ROOT_UNKNOWN    = 11
FMI_BAD_DEVICE      = 12
FMI_CALIBRATION     = 13

FMI_NAMES = {
    0: "Above normal",       1: "Below normal",      2: "Erratic/incorrect",
    3: "Voltage high",       4: "Voltage low",        5: "Open circuit",
    6: "Short to ground",    7: "Mechanical fault",   8: "Abnormal frequency",
    9: "Abnormal update",   10: "Abnormal rate",     11: "Root cause unknown",
   12: "Bad device",        13: "Out of calibration",14: "Special instructions",
   15: "Above normal (mod)",
}

SPN_NAMES = {
    SPN_ENGINE_SPEED:  "Engine Speed",
    SPN_COOLANT_TEMP:  "Coolant Temp",
    SPN_OIL_PRESSURE:  "Oil Pressure",
    SPN_FUEL_LEVEL:    "Fuel Level",
    SPN_BATTERY_V:     "Battery Voltage",
    SPN_ENGINE_HOURS:  "Engine Hours",
    SPN_THROTTLE:      "Throttle Position",
}

SEVERITY = {
    3: "HIGH", 4: "HIGH", 5: "HIGH", 6: "HIGH",
    0: "MED",  1: "MED",  2: "MED",  7: "MED",
}

def severity(fmi):
    return SEVERITY.get(fmi, "LOW")


# ── Frame builders ─────────────────────────────────────────────────────────────

def lamp_byte(rsl=False, awl=False, mil=False):
    """Build DM1 lamp status byte (byte 0). Bits: [7:6]=MIL, [5:4]=RSL, [3:2]=AWL, [1:0]=PL"""
    m = LAMP_ON if mil else LAMP_OFF
    r = LAMP_ON if rsl else LAMP_OFF
    a = LAMP_ON if awl else LAMP_OFF
    return (m << 6) | (r << 4) | (a << 2) | LAMP_OFF  # protect lamp always off


def dtc_bytes(spn, fmi, oc=1):
    """Pack one DTC into 4 bytes per J1939-73."""
    b0 = spn & 0xFF
    b1 = (spn >> 8) & 0xFF
    b2 = (((spn >> 16) & 0x07) << 5) | (fmi & 0x1F)
    b3 = oc & 0x7F   # CM=0 (linear)
    return bytes([b0, b1, b2, b3])


def dm1_payload(rsl=False, awl=False, mil=False, spn=None, fmi=0, oc=1):
    """
    Build an 8-byte DM1 payload.
    Pass spn=None for a "no active DTC" clear frame (lamps still reflect state).
    """
    lb = lamp_byte(rsl=rsl, awl=awl, mil=mil)
    if spn is None:
        return bytes([lb, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
    return bytes([lb, 0xFF]) + dtc_bytes(spn, fmi, oc) + bytes([0xFF, 0xFF])


def make_j1939_id(pgn, sa, priority=6):
    """Build 29-bit J1939 CAN ID."""
    dp = (pgn >> 16) & 0x01
    pf = (pgn >>  8) & 0xFF
    ps =  pgn        & 0xFF
    return ((priority & 0x7) << 26) | (dp << 24) | (pf << 16) | (ps << 8) | (sa & 0xFF)


def inject_packet(pgn, payload, sa, channel):
    """Build UDP inject packet."""
    can_id = make_j1939_id(pgn, sa)
    flags  = INJECT_FLAG_EXT | INJECT_FLAG_J1939
    hdr = struct.pack('<BBBBI', INJECT_MAGIC, channel & 0xFF, flags, len(payload), can_id)
    return hdr + payload


PGN_DM1 = 0xFECA  # 65226 — Active Diagnostic Trouble Codes
PGN_DM2 = 0xFECB  # 65227 — Previously Active Diagnostic Trouble Codes


# ── Scenarios ─────────────────────────────────────────────────────────────────

SCENARIOS = [
    {
        "name": "Clear — no active faults",
        "sa":   config.SIM_SA_1,
        "rsl":  False, "awl": False,
        "spn":  None,
        "duration": 5,
    },
    {
        "name": "AWL — SPN 110 Coolant Temp below normal (sev-med)",
        "sa":   config.SIM_SA_1,
        "rsl":  False, "awl": True,
        "spn":  SPN_COOLANT_TEMP, "fmi": FMI_BELOW_NORMAL, "oc": 3,
        "duration": 10,
    },
    {
        "name": "AWL — SPN 190 Engine Speed voltage high (sev-high)",
        "sa":   config.SIM_SA_1,
        "rsl":  False, "awl": True,
        "spn":  SPN_ENGINE_SPEED, "fmi": FMI_VOLTAGE_HIGH, "oc": 7,
        "duration": 10,
    },
    {
        "name": "RSL + AWL — SPN 100 Oil Pressure short to ground (CRITICAL, sev-high)",
        "sa":   config.SIM_SA_1,
        "rsl":  True,  "awl": True,
        "spn":  SPN_OIL_PRESSURE, "fmi": FMI_SHORT_GROUND, "oc": 12,
        "duration": 10,
    },
    {
        "name": "AWL — SPN 247 Engine Hours root cause unknown (sev-low)",
        "sa":   config.SIM_SA_1,
        "rsl":  False, "awl": True,
        "spn":  SPN_ENGINE_HOURS, "fmi": FMI_ROOT_UNKNOWN, "oc": 1,
        "duration": 10,
    },
    {
        "name": "AWL — SPN 168 Battery Voltage low from ECU2 SA=0x27 (sev-high)",
        "sa":   config.SIM_SA_2,
        "rsl":  False, "awl": True,
        "spn":  SPN_BATTERY_V, "fmi": FMI_VOLTAGE_LOW, "oc": 2,
        "duration": 10,
    },
    {
        "name": "AWL — SPN 96 Fuel Level mechanical fault (sev-med)",
        "sa":   config.SIM_SA_1,
        "rsl":  False, "awl": True,
        "spn":  SPN_FUEL_LEVEL, "fmi": FMI_MECHANICAL, "oc": 5,
        "duration": 10,
    },
    {
        "name": "Clear — fault recovery, all lamps off",
        "sa":   config.SIM_SA_1,
        "rsl":  False, "awl": False,
        "spn":  None,
        "duration": 5,
    },
]

# DM2 scenarios run alongside DM1 — represents what the ECU remembers from the past
DM2_SCENARIOS = [
    # Phase 0-1: no history yet
    {"spn": None,            "rsl": False, "awl": False},
    {"spn": None,            "rsl": False, "awl": False},
    # Phase 2+: history accumulates from previous faults
    {"spn": SPN_COOLANT_TEMP, "fmi": FMI_BELOW_NORMAL, "oc": 3, "rsl": False, "awl": True},
    {"spn": SPN_COOLANT_TEMP, "fmi": FMI_BELOW_NORMAL, "oc": 3, "rsl": False, "awl": True},
    {"spn": SPN_ENGINE_SPEED, "fmi": FMI_VOLTAGE_HIGH,  "oc": 7, "rsl": False, "awl": True},
    {"spn": SPN_ENGINE_SPEED, "fmi": FMI_VOLTAGE_HIGH,  "oc": 7, "rsl": False, "awl": True},
    {"spn": SPN_OIL_PRESSURE, "fmi": FMI_SHORT_GROUND,  "oc":12, "rsl": True,  "awl": True},
    # After clear: history wipes
    {"spn": None,            "rsl": False, "awl": False},
]


# ── Terminal output ────────────────────────────────────────────────────────────

RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
GRAY   = "\033[90m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def colour_sev(sev):
    return {
        "HIGH": RED,
        "MED":  YELLOW,
        "LOW":  GRAY,
    }.get(sev, RESET)


def print_scenario(sc, t_remaining):
    sys.stdout.write("\033[2J\033[H")  # clear screen
    print(f"{BOLD}=== DM1 Diagnostics Simulator ==={RESET}")
    print()
    print(f"  Scenario: {CYAN}{sc['name']}{RESET}")
    print(f"  ECU SA  : 0x{sc['sa']:02X}")
    print()

    if sc["spn"] is not None:
        spn  = sc["spn"]
        fmi  = sc.get("fmi", 0)
        oc   = sc.get("oc", 1)
        sev  = severity(fmi)
        col  = colour_sev(sev)
        print(f"  {'SPN':<10} {'Name':<22} {'FMI':<5} {'Failure Mode':<28} {'OC':<4} {'SEV'}")
        print(f"  {'-'*80}")
        print(f"  {col}{spn:<10} {SPN_NAMES.get(spn, '?'):<22} {fmi:<5} "
              f"{FMI_NAMES.get(fmi, '?'):<28} {oc:<4} {sev}{RESET}")
    else:
        print(f"  {GREEN}No active DTCs{RESET}")
    print()

    rsl = sc.get("rsl", False)
    awl = sc.get("awl", False)
    rsl_str = f"{RED}● ON{RESET}"  if rsl else f"{GRAY}○ off{RESET}"
    awl_str = f"{YELLOW}● ON{RESET}" if awl else f"{GRAY}○ off{RESET}"
    print(f"  Lamps:  RSL {rsl_str}   AWL {awl_str}")
    print()
    if t_remaining is not None:
        print(f"  Next scenario in {t_remaining:.0f}s  (Ctrl-C to exit)")
    else:
        print(f"  Holding scenario (Ctrl-C to exit)")


# ── Main ──────────────────────────────────────────────────────────────────────

def run(ip, port, channel, hold_scenario):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect((ip, port))
    print(f"Sending DM1 to {ip}:{port}  channel={channel}")

    def send_scenario(sc, sc2=None):
        payload = dm1_payload(
            rsl=sc.get("rsl", False),
            awl=sc.get("awl", False),
            spn=sc.get("spn"),
            fmi=sc.get("fmi", 0),
            oc=sc.get("oc",  1),
        )
        sock.send(inject_packet(PGN_DM1, payload, sc["sa"], channel))

        if sc2 is not None:
            payload2 = dm1_payload(
                rsl=sc2.get("rsl", False),
                awl=sc2.get("awl", False),
                spn=sc2.get("spn"),
                fmi=sc2.get("fmi", 0),
                oc=sc2.get("oc",  1),
            )
            sock.send(inject_packet(PGN_DM2, payload2, sc["sa"], channel))

    if hold_scenario is not None:
        idx = hold_scenario % len(SCENARIOS)
        sc  = SCENARIOS[idx]
        sc2 = DM2_SCENARIOS[idx] if idx < len(DM2_SCENARIOS) else None
        while True:
            print_scenario(sc, None)
            send_scenario(sc, sc2)
            time.sleep(1.0)
        return

    while True:
        for idx, sc in enumerate(SCENARIOS):
            sc2 = DM2_SCENARIOS[idx] if idx < len(DM2_SCENARIOS) else None
            duration = sc.get("duration", 8)
            deadline = time.time() + duration
            while time.time() < deadline:
                remaining = deadline - time.time()
                print_scenario(sc, remaining)
                send_scenario(sc, sc2)
                time.sleep(1.0)


def main():
    ap = argparse.ArgumentParser(description="J1939 DM1 diagnostics page test tool")
    ap.add_argument("--ip",       default=config.GW_IP,   help="Gateway IP")
    ap.add_argument("--port",     default=config.GW_PORT, type=int, help="UDP inject port")
    ap.add_argument("--channel",  default=255, type=int,
                    help="CAN channel: 255=software sim (default), 1=physical FDCAN2")
    ap.add_argument("--scenario", default=None, type=int,
                    help="Hold one scenario index (0-7) instead of cycling")
    args = ap.parse_args()

    if args.channel == 255:
        print("[info] Using software sim path (channel 0xFF) — no physical CAN required.")
        print("[info] Ensure firmware is built with DM1 decoding in j1939_data_update_pgn().")
    else:
        print(f"[info] Using physical CAN path (channel {args.channel}).")
        print("[info] FDCAN1 and FDCAN2 must be on the same bus with 120Ω termination.")

    try:
        run(args.ip, args.port, args.channel, args.scenario)
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
