#!/usr/bin/env python3
"""
j1939_sim.py — Simulate TWO J1939 engine ECUs and feed data to the web UI.

Simulates two ECUs with different source addresses (SA) so the web UI shows
two separate gauge panels (ECU 1 and ECU 2):
  ECU 1  SA=0x00  Primary engine   — idle → accel → cruise → decel cycle
  ECU 2  SA=0x27  Secondary engine — same cycle but starts mid-accel (phase offset)

Two modes:
  --channel 1    Physical CAN mode (DEFAULT for realistic testing)
                 Sends J1939 frames OUT on FDCAN2 (CAN channel 2) via UDP inject.
                 FDCAN1 (CAN channel 1) must be on the same physical CAN bus so it
                 receives the frames, decodes them via the J1939 library, and populates
                 the telemetry data store → web UI gauges update.

  --channel 255  Software sim mode (no CAN hardware needed)
                 Sends to special channel 0xFF which directly calls
                 j1939_data_update_from_canid() in firmware — skips all CAN hardware.
                 Use this when you just want to see the web UI working on a bench.

Why J1939 only works on FDCAN1 (channel 0/1):
  The Open-SAE-J1939 library is wired to FDCAN1 only.  FDCAN2 is raw CAN.
  So frames must arrive on FDCAN1 to be decoded into PGNs and appear as gauges.

PGNs simulated (per ECU):
  61444 (0xF004)  EEC1  — engine speed (RPM), engine running flag
  61443 (0xF003)  EEC2  — throttle %, engine load %
  65265 (0xFEF1)  CCVS  — vehicle speed, brake, cruise, PTO flags
  65262 (0xFEEE)  ET1   — coolant temperature
  65276 (0xFEFC)  DD1   — fuel level
  65271 (0xFEF7)  VEP1  — battery voltage

Usage:
  python3 j1939_sim.py                  # physical mode, channel 1 (FDCAN2)
  python3 j1939_sim.py --channel 255    # software sim, no CAN hardware
  python3 j1939_sim.py --ip 121.145.35.64 --channel 1
"""

import argparse
import math
import socket
import struct
import time

import config

# ── Inject protocol constants (matches can_inject.h) ─────────────────────────
INJECT_MAGIC      = 0xCA
INJECT_FLAG_EXT   = 0x01   # 29-bit extended frame
INJECT_FLAG_J1939 = 0x02   # J1939 frame / sim path indicator

# Channel values
CH_FDCAN1    = 0   # inject OUT on FDCAN1 (unusual — normally receive-only for J1939)
CH_FDCAN2    = 1   # inject OUT on FDCAN2, FDCAN1 picks it up on the shared bus
CH_SIM       = 255 # 0xFF: direct data-store update, no physical CAN TX

# ── J1939 CAN ID builder ──────────────────────────────────────────────────────

def make_j1939_id(pgn: int, sa: int, priority: int = 3) -> int:
    """Build a 29-bit J1939 CAN ID for a PDU2 (broadcast) PGN."""
    dp = (pgn >> 16) & 0x01
    pf = (pgn >>  8) & 0xFF
    ge =  pgn        & 0xFF
    # PDU2 (PF >= 0xF0): GE is group extension
    # PDU1 (PF  < 0xF0): GE would be destination — our sim PGNs are all PDU2
    ps = ge if pf >= 0xF0 else ge
    return ((priority & 0x7) << 26) | (dp << 24) | (pf << 16) | (ps << 8) | (sa & 0xFF)


def build_inject_packet(pgn: int, payload: bytes,
                        channel: int, sa: int = config.SIM_SA) -> bytes:
    """Build a UDP inject packet: 8-byte header + CAN payload."""
    can_id = make_j1939_id(pgn, sa)
    flags  = INJECT_FLAG_EXT | INJECT_FLAG_J1939
    hdr = struct.pack('<BBBBI',
                      INJECT_MAGIC,
                      channel & 0xFF,
                      flags,
                      len(payload),
                      can_id)
    return hdr + payload


# ── PGN payload encoders (match j1939_data.cpp decoders exactly) ─────────────

def eec1(rpm: float) -> bytes:
    # PGN 61444 — EEC1: SPN 190 bytes 3-4, 0.125 rpm/bit
    raw = max(0, min(0xFAFF, round(rpm / 0.125)))
    d = bytearray([0xFF, 0xFF, 0xFF, raw & 0xFF, (raw >> 8) & 0xFF, 0xFF, 0xFF, 0xFF])
    return bytes(d)


def eec2(throttle_pct: float, load_pct: float) -> bytes:
    # PGN 61443 — EEC2: SPN 91 byte 1 (0.4%/bit), SPN 92 byte 2
    d = bytearray(8)
    d[0] = 0xFF
    d[1] = max(0, min(250, round(throttle_pct / 0.4)))
    d[2] = max(0, min(250, round(load_pct)))
    d[3:] = [0xFF] * 5
    return bytes(d)


def ccvs(speed_kmh: float, brake=False, cruise=False, pto=False) -> bytes:
    # PGN 65265 — CCVS: SPN 84 bytes 1-2 (/256 km/h), brake/cruise/pto flags
    raw = max(0, min(0xFAFF, round(speed_kmh * 256)))
    d = bytearray(8)
    d[0] = 0xFF
    d[1] = raw & 0xFF
    d[2] = (raw >> 8) & 0xFF
    ctrl = 0
    if cruise: ctrl |= 0x01         # SPN 595 bits [1:0] = 01
    if brake:  ctrl |= (0x01 << 4)  # SPN 597 bits [5:4] = 01
    d[3] = ctrl
    d[4] = 0xFF
    d[5] = 0x0F if pto else 0x00   # SPN 976 != 0 → PTO active
    d[6] = 0xFF; d[7] = 0xFF
    return bytes(d)


def et1(coolant_c: float) -> bytes:
    # PGN 65262 — ET1: SPN 110 byte 0, -40°C offset
    d = bytearray(8)
    d[0] = max(0, min(250, round(coolant_c + 40)))
    d[1:] = [0xFF] * 7
    return bytes(d)


def dd1(fuel_pct: float) -> bytes:
    # PGN 65276 — DD1: SPN 96 byte 1, 0.4%/bit
    d = bytearray(8)
    d[0] = 0xFF
    d[1] = max(0, min(250, round(fuel_pct / 0.4)))
    d[2:] = [0xFF] * 6
    return bytes(d)


def vep1(voltage_v: float) -> bytes:
    # PGN 65271 — VEP1: SPN 168 bytes 4-5, 0.05V/bit
    raw = max(0, min(0xFAFF, round(voltage_v / 0.05)))
    d = bytearray(8)
    d[0:4] = [0xFF, 0xFF, 0xFF, 0xFF]
    d[4] = raw & 0xFF
    d[5] = (raw >> 8) & 0xFF
    d[6] = 0xFF; d[7] = 0xFF
    return bytes(d)


# ── Drive-cycle state machine ─────────────────────────────────────────────────

class DriveCycle:
    """idle → accel → cruise → decel → repeat.
    phase_offset skips ahead into the cycle so two instances stay out of sync.
    fuel_start lets each ECU have a different initial fuel level.
    """
    IDLE = 'idle'; ACCEL = 'accel'; CRUISE = 'cruise'; DECEL = 'decel'
    PHASES = [IDLE, ACCEL, CRUISE, DECEL]

    def __init__(self, phase_offset: float = 0.0, fuel_start: float = 65.0,
                 max_rpm: float = 2500.0, max_speed: float = 80.0):
        self.max_rpm   = max_rpm
        self.max_speed = max_speed
        self.phase     = self.IDLE
        self.phase_t   = 0.0
        self.rpm       = 700.0
        self.speed     = 0.0
        self.throttle  = 5.0
        self.load      = 10.0
        self.coolant   = 75.0
        self.fuel      = fuel_start
        self.voltage   = 13.8
        self.brake     = False
        self.cruise    = False
        # Fast-forward into the cycle by phase_offset seconds
        if phase_offset > 0.0:
            self._skip(phase_offset)

    def _skip(self, secs: float):
        """Advance the cycle by secs without updating slow-varying signals."""
        cycle = config.PHASE_IDLE + config.PHASE_ACCEL + config.PHASE_CRUISE + config.PHASE_DECEL
        secs  = secs % cycle
        for phase, dur in [(self.IDLE,   config.PHASE_IDLE),
                           (self.ACCEL,  config.PHASE_ACCEL),
                           (self.CRUISE, config.PHASE_CRUISE),
                           (self.DECEL,  config.PHASE_DECEL)]:
            if secs < dur:
                self.phase   = phase
                self.phase_t = secs
                return
            secs -= dur

    def update(self, dt: float):
        self.phase_t += dt

        if self.phase == self.IDLE:
            self.rpm = 700; self.speed = 0; self.throttle = 5; self.load = 10
            self.brake = False; self.cruise = False
            if self.phase_t >= config.PHASE_IDLE:
                self.phase = self.ACCEL; self.phase_t = 0

        elif self.phase == self.ACCEL:
            p = min(1.0, self.phase_t / config.PHASE_ACCEL)
            self.rpm = 700 + p * (self.max_rpm - 700); self.speed = p * self.max_speed
            self.throttle = 5 + p * 65; self.load = 10 + p * 70
            self.brake = False; self.cruise = False
            if self.phase_t >= config.PHASE_ACCEL:
                self.phase = self.CRUISE; self.phase_t = 0

        elif self.phase == self.CRUISE:
            self.rpm = self.max_rpm; self.speed = self.max_speed
            self.throttle = 40; self.load = 60
            self.brake = False; self.cruise = True
            if self.phase_t >= config.PHASE_CRUISE:
                self.phase = self.DECEL; self.phase_t = 0

        elif self.phase == self.DECEL:
            p = min(1.0, self.phase_t / config.PHASE_DECEL)
            self.rpm = self.max_rpm - p * (self.max_rpm - 700)
            self.speed = self.max_speed - p * self.max_speed
            self.throttle = 40 - p * 35; self.load = 60 - p * 50
            self.brake = p > 0.5; self.cruise = False
            if self.phase_t >= config.PHASE_DECEL:
                self.phase = self.IDLE; self.phase_t = 0

        # Slowly varying signals
        target = 92.0 if self.phase != self.IDLE else 88.0
        self.coolant += (target - self.coolant) * dt * 0.05
        self.fuel     = max(0, self.fuel - 0.001 * dt)
        self.voltage  = 13.8 + 0.3 * math.sin(time.time() * 0.2)

    def status_line(self, label: str) -> str:
        b = 'BRK ' if self.brake  else '    '
        c = 'CRZ ' if self.cruise else '    '
        return (f"{label} [{self.phase:6s}] {b}{c}"
                f"RPM={self.rpm:6.0f}  spd={self.speed:5.1f}km/h  "
                f"thr={self.throttle:4.1f}%  load={self.load:4.1f}%  "
                f"cool={self.coolant:4.1f}°C  fuel={self.fuel:4.1f}%  "
                f"V={self.voltage:.2f}V")


# ── Main loop ─────────────────────────────────────────────────────────────────

def run(gw_ip: str, gw_port: int, channel: int):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    addr = (gw_ip, gw_port)

    mode_str = {
        CH_FDCAN2: "PHYSICAL — sending OUT on FDCAN2, FDCAN1 must be on same CAN bus",
        CH_SIM:    "SOFTWARE SIM — direct data-store inject, no physical CAN",
        CH_FDCAN1: "FDCAN1 TX (loopback only makes sense in test mode)",
    }.get(channel, f"channel {channel}")

    print(f"J1939 sim → {gw_ip}:{gw_port}  |  Mode: {mode_str}")
    if channel == CH_FDCAN2:
        print("      Make sure FDCAN1 and FDCAN2 share the same physical CAN bus!")
    print(f"  ECU 1  SA=0x{config.SIM_SA_1:02X}  primary engine   (max {2500:.0f} rpm, 80 km/h)")
    print(f"  ECU 2  SA=0x{config.SIM_SA_2:02X}  secondary engine (max {3200:.0f} rpm, 120 km/h, phase offset)")
    print("Ctrl-C to stop\n")

    # Two independent drive cycles:
    # ECU 1 — primary engine, starts at idle, 2500 rpm max, 80 km/h max, 65% fuel
    # ECU 2 — secondary engine, starts mid-accel (13s offset), 3200 rpm max, 120 km/h max, 82% fuel
    ecu1 = DriveCycle(phase_offset=0.0,                        fuel_start=65.0, max_rpm=2500.0, max_speed=80.0)
    # ECU2 starts 4 s into ACCEL so both ECUs show movement immediately.
    ecu2 = DriveCycle(phase_offset=config.PHASE_IDLE + 4.0,   fuel_start=82.0, max_rpm=3200.0, max_speed=120.0)

    t_last = time.monotonic()
    t_slow = 0.0

    def tx(pgn, payload, sa):
        pkt = build_inject_packet(pgn, payload, channel, sa)
        sock.sendto(pkt, addr)

    def tx_ecu(c: DriveCycle, sa: int):
        tx(0xF004, eec1(c.rpm),                             sa)  # EEC1
        tx(0xF003, eec2(c.throttle, c.load),                sa)  # EEC2
        tx(0xFEF1, ccvs(c.speed, c.brake, c.cruise),        sa)  # CCVS

    def tx_ecu_slow(c: DriveCycle, sa: int):
        tx(0xFEEE, et1(c.coolant),  sa)  # ET1
        tx(0xFEFC, dd1(c.fuel),     sa)  # DD1
        tx(0xFEF7, vep1(c.voltage), sa)  # VEP1

    try:
        while True:
            now = time.monotonic()
            dt  = now - t_last
            t_last = now

            ecu1.update(dt)
            ecu2.update(dt)

            # Fast PGNs — both ECUs every 100 ms
            tx_ecu(ecu1, config.SIM_SA_1)
            tx_ecu(ecu2, config.SIM_SA_2)

            # Slow PGNs — both ECUs every 1 s
            t_slow += dt
            if t_slow >= config.INTERVAL_SLOW:
                t_slow = 0.0
                tx_ecu_slow(ecu1, config.SIM_SA_1)
                tx_ecu_slow(ecu2, config.SIM_SA_2)

            line1 = ecu1.status_line(f"ECU1 0x{config.SIM_SA_1:02X}")
            line2 = ecu2.status_line(f"ECU2 0x{config.SIM_SA_2:02X}")
            print(f"\r{line1}\n{line2}", end='\033[F', flush=True)
            time.sleep(config.INTERVAL_FAST)

    except KeyboardInterrupt:
        print("\n\nStopped.")
    finally:
        sock.close()


if __name__ == '__main__':
    p = argparse.ArgumentParser(description='J1939 ECU simulator for CAN-ETH gateway')
    p.add_argument('--ip',      default=config.GW_IP,   help='Gateway IP')
    p.add_argument('--port',    default=config.GW_PORT,  type=int, help='UDP inject port')
    p.add_argument('--channel', default=CH_FDCAN2,       type=int,
                   help='Inject channel: 1=FDCAN2 physical (default), 255=software sim')
    args = p.parse_args()
    run(args.ip, args.port, args.channel)
