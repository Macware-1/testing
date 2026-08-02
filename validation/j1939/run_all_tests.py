#!/usr/bin/env python3
"""
run_all_tests.py — CAN-ETH Gateway UI simulator suite.

Runs all three simulators simultaneously in background threads so you can
verify every page of the web UI in one shot:

  Thread 1  J1939 Telemetry    Two ECUs, live drive-cycle data    → Gauges page
  Thread 2  DM1 / DM2          Fault scenarios cycling            → Diagnostics page
  Thread 3  Address Claimed    ECU node discovery                 → Network Nodes page

Channel notes:
  --channel 1   (default)  Physical CAN.  Frames go OUT on FDCAN2; FDCAN1
                           receives them on the shared bus.  All three threads
                           work.  FDCAN1 + FDCAN2 must share a physical bus
                           with 120Ω termination.
  --channel 255            Software sim.  Telemetry and DM work via the
                           firmware's direct data-store path.  Node discovery
                           is disabled (the J1939 library is bypassed).

Usage:
  python3 run_all_tests.py                        # physical, all features
  python3 run_all_tests.py --channel 255          # software sim (no nodes)
  python3 run_all_tests.py --ip 192.168.1.x       # custom gateway IP
  python3 run_all_tests.py --dm-scenario 3        # hold DM scenario 3 only
  python3 run_all_tests.py --no-nodes             # skip address-claim thread
"""

import argparse
import math
import socket
import struct
import sys
import threading
import time

import config

# ─────────────────────────────────────────────────────────────────────────────
# Shared: inject protocol
# ─────────────────────────────────────────────────────────────────────────────

INJECT_MAGIC      = 0xCA
INJECT_FLAG_EXT   = 0x01
INJECT_FLAG_J1939 = 0x02


def _make_socket(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect((ip, port))
    return s


def _inject(sock, can_id, payload, channel):
    flags = INJECT_FLAG_EXT | INJECT_FLAG_J1939
    hdr = struct.pack('<BBBBI', INJECT_MAGIC, channel & 0xFF, flags, len(payload), can_id)
    sock.send(hdr + payload)


def _j1939_can_id(pgn, sa, priority=6):
    """Build 29-bit J1939 CAN ID for PDU2 (broadcast) PGNs."""
    dp = (pgn >> 16) & 0x01
    pf = (pgn >>  8) & 0xFF
    ps =  pgn        & 0xFF
    return ((priority & 0x7) << 26) | (dp << 24) | (pf << 16) | (ps << 8) | (sa & 0xFF)


# ─────────────────────────────────────────────────────────────────────────────
# Shared display state (written by workers, read by main display loop)
# ─────────────────────────────────────────────────────────────────────────────

class _State:
    def __init__(self):
        self.lock = threading.Lock()
        self.ecu1_line    = 'starting...'
        self.ecu2_line    = 'starting...'
        self.dm_name      = 'starting...'
        self.dm_rsl       = False
        self.dm_awl       = False
        self.dm_spn       = None
        self.dm_fmi       = 0
        self.dm_oc        = 0
        self.dm_remaining = 0.0
        self.dm_idx       = 0
        self.dm_total     = 0
        self.nodes        = []    # list of {"sa": int, "name": str}
        self.nodes_ok     = True  # False when channel=255 (nodes disabled)


STATE = _State()


# ─────────────────────────────────────────────────────────────────────────────
# Thread 1: J1939 Telemetry (Gauges page)
# ─────────────────────────────────────────────────────────────────────────────

class _DriveCycle:
    IDLE = 'idle'; ACCEL = 'accel'; CRUISE = 'cruise'; DECEL = 'decel'

    def __init__(self, offset=0.0, fuel=65.0, max_rpm=2500.0, max_spd=80.0):
        self.max_rpm = max_rpm; self.max_spd = max_spd
        self.phase = self.IDLE; self.phase_t = 0.0
        self.rpm = 700.0; self.spd = 0.0; self.thr = 5.0; self.load = 10.0
        self.cool = 75.0; self.fuel = fuel; self.volt = 13.8
        self.brake = False; self.cruise = False
        if offset: self._skip(offset)

    def _skip(self, secs):
        cy = config.PHASE_IDLE + config.PHASE_ACCEL + config.PHASE_CRUISE + config.PHASE_DECEL
        secs %= cy
        for ph, dur in [(self.IDLE,  config.PHASE_IDLE),  (self.ACCEL,  config.PHASE_ACCEL),
                        (self.CRUISE,config.PHASE_CRUISE), (self.DECEL,  config.PHASE_DECEL)]:
            if secs < dur: self.phase = ph; self.phase_t = secs; return
            secs -= dur

    def update(self, dt):
        self.phase_t += dt
        if self.phase == self.IDLE:
            self.rpm = 700; self.spd = 0; self.thr = 5; self.load = 10
            self.brake = False; self.cruise = False
            if self.phase_t >= config.PHASE_IDLE: self.phase = self.ACCEL; self.phase_t = 0
        elif self.phase == self.ACCEL:
            p = min(1.0, self.phase_t / config.PHASE_ACCEL)
            self.rpm = 700 + p*(self.max_rpm-700); self.spd = p*self.max_spd
            self.thr = 5+p*65; self.load = 10+p*70; self.brake = False; self.cruise = False
            if self.phase_t >= config.PHASE_ACCEL: self.phase = self.CRUISE; self.phase_t = 0
        elif self.phase == self.CRUISE:
            self.rpm = self.max_rpm; self.spd = self.max_spd
            self.thr = 40; self.load = 60; self.brake = False; self.cruise = True
            if self.phase_t >= config.PHASE_CRUISE: self.phase = self.DECEL; self.phase_t = 0
        elif self.phase == self.DECEL:
            p = min(1.0, self.phase_t / config.PHASE_DECEL)
            self.rpm = self.max_rpm - p*(self.max_rpm-700)
            self.spd = self.max_spd - p*self.max_spd
            self.thr = 40-p*35; self.load = 60-p*50; self.brake = p > 0.5; self.cruise = False
            if self.phase_t >= config.PHASE_DECEL: self.phase = self.IDLE; self.phase_t = 0
        target = 92.0 if self.phase != self.IDLE else 88.0
        self.cool += (target - self.cool) * dt * 0.05
        self.fuel  = max(0, self.fuel - 0.001*dt)
        self.volt  = 13.8 + 0.3*math.sin(time.time()*0.2)

    def status(self, label):
        b = 'BRK' if self.brake  else '   '
        c = 'CRZ' if self.cruise else '   '
        return (f"{label} [{self.phase:6s}] {b} {c}"
                f"  RPM={self.rpm:6.0f}  spd={self.spd:5.1f} km/h"
                f"  thr={self.thr:4.1f}%  cool={self.cool:4.1f}°C"
                f"  fuel={self.fuel:4.1f}%  V={self.volt:.2f}V")


def _eec1(rpm):
    r = max(0, min(0xFAFF, round(rpm / 0.125)))
    return bytes([0xFF, 0xFF, 0xFF, r & 0xFF, (r >> 8) & 0xFF, 0xFF, 0xFF, 0xFF])

def _eec2(thr, load):
    d = bytearray(8); d[0] = 0xFF
    d[1] = max(0, min(250, round(thr / 0.4)))
    d[2] = max(0, min(250, round(load)))
    d[3:] = b'\xFF' * 5
    return bytes(d)

def _ccvs(spd, brake=False, cruise=False):
    r = max(0, min(0xFAFF, round(spd * 256))); d = bytearray(8)
    d[0] = 0xFF; d[1] = r & 0xFF; d[2] = (r >> 8) & 0xFF
    ctrl = 0
    if cruise: ctrl |= 0x01
    if brake:  ctrl |= (0x01 << 4)
    d[3] = ctrl; d[4] = 0xFF; d[5] = 0x00; d[6] = 0xFF; d[7] = 0xFF
    return bytes(d)

def _et1(c):
    d = bytearray(8); d[0] = max(0, min(250, round(c + 40))); d[1:] = b'\xFF' * 7; return bytes(d)

def _dd1(f):
    d = bytearray(8); d[0] = 0xFF; d[1] = max(0, min(250, round(f / 0.4))); d[2:] = b'\xFF' * 6; return bytes(d)

def _vep1(v):
    r = max(0, min(0xFAFF, round(v / 0.05))); d = bytearray(8)
    d[0:4] = b'\xFF' * 4; d[4] = r & 0xFF; d[5] = (r >> 8) & 0xFF; d[6] = 0xFF; d[7] = 0xFF
    return bytes(d)


def telemetry_worker(ip, port, channel, stop_evt):
    sock = _make_socket(ip, port)
    sa1  = config.SIM_SA_1
    sa2  = config.SIM_SA_2
    ecu1 = _DriveCycle(offset=0.0,                        fuel=65.0, max_rpm=2500.0, max_spd=80.0)
    # ECU2 starts 4 s into its ACCEL phase so both ECUs show visible movement from launch.
    # (offset=total*0.48 put ECU2 in CRUISE at constant max values — gauges appeared frozen)
    ecu2 = _DriveCycle(offset=config.PHASE_IDLE + 4.0,  fuel=82.0, max_rpm=3200.0, max_spd=120.0)
    t_last = time.monotonic()
    t_slow = 0.0

    def tx(pgn, payload, sa):
        _inject(sock, _j1939_can_id(pgn, sa), payload, channel)

    while not stop_evt.is_set():
        now = time.monotonic(); dt = now - t_last; t_last = now
        ecu1.update(dt); ecu2.update(dt)

        tx(0xF004, _eec1(ecu1.rpm),                      sa1)
        tx(0xF003, _eec2(ecu1.thr, ecu1.load),           sa1)
        tx(0xFEF1, _ccvs(ecu1.spd, ecu1.brake, ecu1.cruise), sa1)
        tx(0xF004, _eec1(ecu2.rpm),                      sa2)
        tx(0xF003, _eec2(ecu2.thr, ecu2.load),           sa2)
        tx(0xFEF1, _ccvs(ecu2.spd, ecu2.brake, ecu2.cruise), sa2)

        t_slow += dt
        if t_slow >= config.INTERVAL_SLOW:
            t_slow = 0.0
            tx(0xFEEE, _et1(ecu1.cool), sa1);  tx(0xFEFC, _dd1(ecu1.fuel), sa1);  tx(0xFEF7, _vep1(ecu1.volt), sa1)
            tx(0xFEEE, _et1(ecu2.cool), sa2);  tx(0xFEFC, _dd1(ecu2.fuel), sa2);  tx(0xFEF7, _vep1(ecu2.volt), sa2)

        with STATE.lock:
            STATE.ecu1_line = ecu1.status(f"ECU1 SA=0x{sa1:02X}")
            STATE.ecu2_line = ecu2.status(f"ECU2 SA=0x{sa2:02X}")

        time.sleep(config.INTERVAL_FAST)
    sock.close()


# ─────────────────────────────────────────────────────────────────────────────
# Thread 2: DM1 / DM2 Diagnostics (Diagnostics page)
# ─────────────────────────────────────────────────────────────────────────────

_LAMP_OFF = 0b00; _LAMP_ON = 0b01

def _lamp_byte(rsl=False, awl=False):
    r = _LAMP_ON if rsl else _LAMP_OFF
    a = _LAMP_ON if awl else _LAMP_OFF
    return (r << 4) | (a << 2)

def _dtc_bytes(spn, fmi, oc=1):
    return bytes([spn & 0xFF, (spn >> 8) & 0xFF,
                  (((spn >> 16) & 0x07) << 5) | (fmi & 0x1F),
                  oc & 0x7F])

def _dm_payload(rsl=False, awl=False, spn=None, fmi=0, oc=1):
    lb = _lamp_byte(rsl, awl)
    if spn is None:
        return bytes([lb, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
    return bytes([lb, 0xFF]) + _dtc_bytes(spn, fmi, oc) + b'\xFF\xFF'

PGN_DM1 = 0xFECA
PGN_DM2 = 0xFECB

_FMI_NAMES = {
    0: "Above normal",    1: "Below normal",     2: "Erratic/incorrect",
    3: "Voltage high",    4: "Voltage low",       5: "Open circuit",
    6: "Short to ground", 7: "Mechanical fault",  8: "Abnormal frequency",
    9: "Abnormal update", 10: "Abnormal rate",    11: "Root cause unknown",
    12: "Bad device",     13: "Out of calibration",
}
_SPN_NAMES = {
    190: "Engine Speed",   110: "Coolant Temp",  100: "Oil Pressure",
     96: "Fuel Level",     168: "Battery Voltage", 247: "Engine Hours",
}
_SEV = {3:"HIGH",4:"HIGH",5:"HIGH",6:"HIGH", 0:"MED",1:"MED",2:"MED",7:"MED"}

def _sev(fmi): return _SEV.get(fmi, "LOW")

DM_SCENARIOS = [
    {"name": "Clear — no active faults",
     "sa": config.SIM_SA_1, "rsl": False, "awl": False, "spn": None, "duration": 5},
    {"name": "AWL — Coolant Temp below normal",
     "sa": config.SIM_SA_1, "rsl": False, "awl": True,  "spn": 110, "fmi": 1,  "oc": 3,  "duration": 10},
    {"name": "AWL — Engine Speed voltage high",
     "sa": config.SIM_SA_1, "rsl": False, "awl": True,  "spn": 190, "fmi": 3,  "oc": 7,  "duration": 10},
    {"name": "RSL + AWL — Oil Pressure short to ground  [CRITICAL]",
     "sa": config.SIM_SA_1, "rsl": True,  "awl": True,  "spn": 100, "fmi": 6,  "oc": 12, "duration": 10},
    {"name": "AWL — Engine Hours root cause unknown",
     "sa": config.SIM_SA_1, "rsl": False, "awl": True,  "spn": 247, "fmi": 11, "oc": 1,  "duration": 10},
    {"name": "AWL — Battery Voltage low  (ECU2)",
     "sa": config.SIM_SA_2, "rsl": False, "awl": True,  "spn": 168, "fmi": 4,  "oc": 2,  "duration": 10},
    {"name": "AWL — Fuel Level mechanical fault",
     "sa": config.SIM_SA_1, "rsl": False, "awl": True,  "spn": 96,  "fmi": 7,  "oc": 5,  "duration": 10},
    {"name": "Clear — fault recovery",
     "sa": config.SIM_SA_1, "rsl": False, "awl": False, "spn": None, "duration": 5},
]

DM2_SCENARIOS = [
    {"spn": None,  "rsl": False, "awl": False},
    {"spn": None,  "rsl": False, "awl": False},
    {"spn": 110,   "fmi": 1,  "oc": 3,  "rsl": False, "awl": True},
    {"spn": 110,   "fmi": 1,  "oc": 3,  "rsl": False, "awl": True},
    {"spn": 190,   "fmi": 3,  "oc": 7,  "rsl": False, "awl": True},
    {"spn": 190,   "fmi": 3,  "oc": 7,  "rsl": False, "awl": True},
    {"spn": 100,   "fmi": 6,  "oc": 12, "rsl": True,  "awl": True},
    {"spn": None,  "rsl": False, "awl": False},
]


def diagnostics_worker(ip, port, channel, hold_idx, stop_evt):
    sock = _make_socket(ip, port)

    def send_dm(sc, sc2=None):
        pay1 = _dm_payload(sc.get("rsl",False), sc.get("awl",False),
                           sc.get("spn"), sc.get("fmi",0), sc.get("oc",1))
        _inject(sock, _j1939_can_id(PGN_DM1, sc["sa"]), pay1, channel)
        if sc2 is not None:
            pay2 = _dm_payload(sc2.get("rsl",False), sc2.get("awl",False),
                               sc2.get("spn"), sc2.get("fmi",0), sc2.get("oc",1))
            _inject(sock, _j1939_can_id(PGN_DM2, sc["sa"]), pay2, channel)

    with STATE.lock:
        STATE.dm_total = len(DM_SCENARIOS)

    if hold_idx is not None:
        idx = hold_idx % len(DM_SCENARIOS)
        sc  = DM_SCENARIOS[idx]
        sc2 = DM2_SCENARIOS[idx] if idx < len(DM2_SCENARIOS) else None
        while not stop_evt.is_set():
            send_dm(sc, sc2)
            with STATE.lock:
                STATE.dm_name = sc["name"]; STATE.dm_idx = idx + 1
                STATE.dm_rsl  = sc.get("rsl",False); STATE.dm_awl = sc.get("awl",False)
                STATE.dm_spn  = sc.get("spn"); STATE.dm_fmi = sc.get("fmi",0)
                STATE.dm_oc   = sc.get("oc",1); STATE.dm_remaining = 0
            time.sleep(1.0)
        sock.close(); return

    while not stop_evt.is_set():
        for idx, sc in enumerate(DM_SCENARIOS):
            sc2      = DM2_SCENARIOS[idx] if idx < len(DM2_SCENARIOS) else None
            duration = sc.get("duration", 8)
            deadline = time.time() + duration
            while time.time() < deadline and not stop_evt.is_set():
                send_dm(sc, sc2)
                with STATE.lock:
                    STATE.dm_name = sc["name"]; STATE.dm_idx = idx + 1
                    STATE.dm_rsl  = sc.get("rsl",False); STATE.dm_awl = sc.get("awl",False)
                    STATE.dm_spn  = sc.get("spn"); STATE.dm_fmi = sc.get("fmi",0)
                    STATE.dm_oc   = sc.get("oc",1); STATE.dm_remaining = deadline - time.time()
                time.sleep(1.0)
    sock.close()


# ─────────────────────────────────────────────────────────────────────────────
# Thread 3: Address Claimed / Network Nodes (Nodes page)
# ─────────────────────────────────────────────────────────────────────────────

def _j1939_name(identity=0, manufacturer=0x717, ecu_inst=0, func_inst=0,
                function=0, vehicle_system=0, vehicle_sys_inst=0,
                industry_group=0, arb_capable=1):
    b0 = identity & 0xFF
    b1 = (identity >> 8) & 0xFF
    b2 = ((identity >> 16) & 0x1F) | ((manufacturer & 0x07) << 5)
    b3 = (manufacturer >> 3) & 0xFF
    b4 = (ecu_inst & 0x07) | ((func_inst & 0x1F) << 3)
    b5 = function & 0xFF
    b6 = 0 | ((vehicle_system & 0x7F) << 1)
    b7 = ((vehicle_sys_inst & 0x0F)
          | ((industry_group & 0x07) << 4)
          | ((arb_capable & 0x01) << 7))
    return bytes([b0, b1, b2, b3, b4, b5, b6, b7])

def _addr_claimed_id(sa, priority=6):
    """PGN 0xEE00 to global (DA=0xFF), PDU1."""
    return ((priority & 0x7) << 26) | (0 << 24) | (0xEE << 16) | (0xFF << 8) | (sa & 0xFF)

NODES = [
    {"sa": 0x00, "name": "Engine Controller (EEC)",
     "payload": _j1939_name(identity=0x001, manufacturer=0x717, function=0)},
    {"sa": 0x03, "name": "Transmission Controller",
     "payload": _j1939_name(identity=0x002, manufacturer=0x717, function=3)},
    {"sa": 0x17, "name": "ABS / Brake Controller",
     "payload": _j1939_name(identity=0x010, manufacturer=0x33F, function=23)},
    {"sa": 0x23, "name": "Instrument Cluster",
     "payload": _j1939_name(identity=0x020, manufacturer=0x33F, function=40)},
    {"sa": 0x27, "name": "Battery / Power Management ECU",
     "payload": _j1939_name(identity=0x030, manufacturer=0x717, function=14)},
]


def nodes_worker(ip, port, channel, stop_evt):
    if channel == 255:
        with STATE.lock:
            STATE.nodes_ok = False
        return  # node discovery requires physical CAN

    sock = _make_socket(ip, port)
    with STATE.lock:
        STATE.nodes_ok = True
        STATE.nodes    = [{"sa": n["sa"], "name": n["name"]} for n in NODES]

    while not stop_evt.is_set():
        for node in NODES:
            _inject(sock, _addr_claimed_id(node["sa"]), node["payload"], channel)
        time.sleep(1.0)
    sock.close()


# ─────────────────────────────────────────────────────────────────────────────
# Display
# ─────────────────────────────────────────────────────────────────────────────

R  = "\033[91m"; Y = "\033[93m"; G = "\033[92m"
C  = "\033[96m"; D = "\033[90m"; B = "\033[1m";  X = "\033[0m"

def _sev_colour(sev):
    return {" HIGH": R, "MED": Y}.get(sev, D)

def _lamp(on, colour):
    return f"{colour}● ON{X}" if on else f"{D}○ off{X}"

def _render():
    with STATE.lock:
        e1 = STATE.ecu1_line
        e2 = STATE.ecu2_line
        dm_name = STATE.dm_name; dm_idx = STATE.dm_idx; dm_total = STATE.dm_total
        dm_rsl = STATE.dm_rsl;   dm_awl = STATE.dm_awl
        dm_spn = STATE.dm_spn;   dm_fmi = STATE.dm_fmi
        dm_oc  = STATE.dm_oc;    dm_rem = STATE.dm_remaining
        nodes    = list(STATE.nodes)
        nodes_ok = STATE.nodes_ok

    print("\033[2J\033[H", end='')
    print(f"{B}╔══════════════════════════════════════════════════════════════╗{X}")
    print(f"{B}║   CAN-ETH Gateway  —  UI Simulator Suite                    ║{X}")
    print(f"{B}╚══════════════════════════════════════════════════════════════╝{X}")
    print()

    print(f"{B}─── J1939 Telemetry  (Gauges page) {'─'*27}{X}")
    print(f"  {e1}")
    print(f"  {e2}")
    print()

    sev  = _sev(dm_fmi)
    scol = _sev_colour(sev)
    print(f"{B}─── DM Diagnostics  (Diagnostics page) {'─'*24}{X}")
    if dm_total:
        print(f"  Scenario [{dm_idx}/{dm_total}]: {C}{dm_name}{X}")
    else:
        print(f"  Scenario: {C}{dm_name}{X}")
    print(f"  Lamps:  RSL {_lamp(dm_rsl, R)}    AWL {_lamp(dm_awl, Y)}")
    if dm_spn is not None:
        spn_name = _SPN_NAMES.get(dm_spn, "Unknown")
        fmi_name = _FMI_NAMES.get(dm_fmi, "?")
        print(f"  DTC:    SPN={dm_spn} ({spn_name})  "
              f"FMI={dm_fmi} ({fmi_name})  OC={dm_oc}  "
              f"{scol}{sev}{X}")
    else:
        print(f"  DTC:    {G}No active fault codes{X}")
    if dm_rem > 0:
        print(f"  Next scenario in {dm_rem:.0f}s")
    print()

    print(f"{B}─── Network Nodes  (J1939 Network Nodes page) {'─'*17}{X}")
    if not nodes_ok:
        print(f"  {Y}Disabled — channel 255 bypasses the J1939 library.{X}")
        print(f"  {D}Use --channel 1 with a physical CAN bus to enable node discovery.{X}")
    elif nodes:
        for n in nodes:
            print(f"  {G}0x{n['sa']:02X}{X}  {n['name']}")
    else:
        print(f"  {D}(waiting for address claims...){X}")
    print()
    print(f"  {D}Ctrl-C to stop{X}")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description="CAN-ETH Gateway UI simulator suite — all pages at once")
    ap.add_argument("--ip",          default=config.GW_IP,   help="Gateway IP")
    ap.add_argument("--port",        default=config.GW_PORT, type=int, help="UDP inject port")
    ap.add_argument("--channel",     default=1,              type=int,
                    help="CAN channel: 1=FDCAN2 physical (default), 255=software sim")
    ap.add_argument("--dm-scenario", default=None,           type=int, metavar="N",
                    help="Hold one DM scenario index 0-7 instead of cycling")
    ap.add_argument("--no-nodes",    action="store_true",    help="Skip the address-claim thread")
    args = ap.parse_args()

    ch = args.channel
    ch_label = f"{ch} (FDCAN2 → physical CAN)" if ch != 255 else "255 (software sim)"
    print(f"Starting all simulators → {args.ip}:{args.port}  channel={ch_label}")
    if ch != 255:
        print("  Make sure FDCAN1 and FDCAN2 share the same physical CAN bus (120Ω termination).")
    if ch == 255:
        print("  [info] Software sim: J1939 telemetry and DM diagnostics work.")
        print("  [info] Node discovery disabled on channel 255.")
    print()

    stop_evt = threading.Event()

    threads = [
        threading.Thread(target=telemetry_worker,
                         args=(args.ip, args.port, ch, stop_evt),
                         daemon=True, name="telemetry"),
        threading.Thread(target=diagnostics_worker,
                         args=(args.ip, args.port, ch, args.dm_scenario, stop_evt),
                         daemon=True, name="diagnostics"),
    ]
    if not args.no_nodes:
        threads.append(threading.Thread(target=nodes_worker,
                                        args=(args.ip, args.port, ch, stop_evt),
                                        daemon=True, name="nodes"))

    for t in threads:
        t.start()

    try:
        time.sleep(0.5)  # let workers send their first frames
        while True:
            _render()
            time.sleep(1.0)
    except KeyboardInterrupt:
        pass
    finally:
        stop_evt.set()
        print("\n\nStopped.")


if __name__ == "__main__":
    main()
