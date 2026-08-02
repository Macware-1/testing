#!/usr/bin/env python3
"""
diagnose.py — layer-by-layer diagnostic for the CAN-ETH gateway J1939 setup.

Run with sudo:
    sudo python3 diagnose.py

Checks four layers independently:
  LAYER 1 — Raw Ethernet: are ANY frames arriving on the TECMP interface?
  LAYER 2 — TECMP frames: are EtherType 0x99FE / 0x2090 frames arriving?
  LAYER 3 — TECMP CAN frames: do any of them contain CAN data (type 0x0002)?
  LAYER 4 — CLOG UDP: are any CLOG frames arriving on USB ECM?

Each layer prints what it finds or a clear FAIL message.
Press Ctrl-C to stop any layer early and move to the next.
"""

import socket
import struct
import time
import threading
import sys

from config import (TECMP_INTERFACE, TECMP_CM_ID, TECMP_CHANNEL_ID,
                    CLOG_LISTEN_IP, CLOG_LISTEN_PORT)
from tecmp_bus import (decode_tecmp_frame, TECMP_ETHERTYPE, TECMP_ETHERTYPE_ALT,
                        TECMP_DATA_CAN, TECMP_DATA_CANFD, TECMP_MSG_LOGGING,
                        TECMP_HDR_LEN, ETH_HDR_LEN, _HDR_FMT, dlc_to_len)
from j1939_utils import decode_j1939_id, pgn_name

LISTEN_SECS = 10   # seconds per layer


# ── helpers ───────────────────────────────────────────────────────────────────

def open_raw_sock(interface: str):
    _ETH_P_ALL = 0x0003
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                          socket.htons(_ETH_P_ALL))
    sock.bind((interface, 0))
    sock.settimeout(0.5)
    return sock


def open_clog_sock():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.settimeout(0.5)
    sock.bind((CLOG_LISTEN_IP, CLOG_LISTEN_PORT))
    return sock


def section(title: str):
    print()
    print('─' * 60)
    print(f'  {title}')
    print('─' * 60)


def wait_or_skip():
    print(f"  (listening {LISTEN_SECS}s — Ctrl-C to skip to next layer)")


# ── Layer 1: Raw Ethernet ─────────────────────────────────────────────────────

def layer1_raw_ethernet():
    section("LAYER 1 — Raw Ethernet on " + TECMP_INTERFACE)
    print("  Counts ALL Ethernet frames received — any source, any type.")
    print("  If count stays 0 the interface name is wrong or nothing is connected.")
    wait_or_skip()

    sock = open_raw_sock(TECMP_INTERFACE)
    counts: dict[int, int] = {}
    total = 0
    deadline = time.monotonic() + LISTEN_SECS
    try:
        while time.monotonic() < deadline:
            try:
                raw, _ = sock.recvfrom(65536)
            except socket.timeout:
                continue
            total += 1
            if len(raw) >= 14:
                etype = struct.unpack_from('>H', raw, 12)[0]
                counts[etype] = counts.get(etype, 0) + 1
            if total % 10 == 0:
                print(f"\r  received {total} frames …", end='', flush=True)
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()

    print(f"\r  Total frames received: {total}")
    if total == 0:
        print("  ✗ FAIL — no Ethernet frames at all")
        print("    → Check TECMP_INTERFACE in config.py ('ip link' to list interfaces)")
        print("    → Check cable between PC and Capture Module")
        return False

    print("  EtherType breakdown:")
    for etype, cnt in sorted(counts.items(), key=lambda x: -x[1])[:10]:
        marker = ' ◄── TECMP' if etype in (TECMP_ETHERTYPE, TECMP_ETHERTYPE_ALT) else ''
        print(f"    0x{etype:04X}  {cnt} frames{marker}")

    has_tecmp = any(e in counts for e in (TECMP_ETHERTYPE, TECMP_ETHERTYPE_ALT))
    if not has_tecmp:
        print("  ✗ FAIL — no TECMP EtherType (0x99FE / 0x2090) frames seen")
        print("    → Capture Module may not be streaming to this PC")
        print("    → Check Capture Module's 'log destination' setting")
    else:
        print(f"  ✓ PASS — TECMP frames are arriving")
    return has_tecmp


# ── Layer 2: TECMP frame decode ───────────────────────────────────────────────

def layer2_tecmp_decode():
    section("LAYER 2 — TECMP frame decode")
    print("  Shows every TECMP frame: message type, data type, channel, CM_ID.")
    print("  We expect msg_type=0x03 (LOGGING), data_type=0x0002 (CAN).")
    wait_or_skip()

    sock = open_raw_sock(TECMP_INTERFACE)
    seen: dict[tuple, int] = {}   # (msg_type, data_type) → count
    deadline = time.monotonic() + LISTEN_SECS
    try:
        while time.monotonic() < deadline:
            try:
                raw, _ = sock.recvfrom(65536)
            except socket.timeout:
                continue
            if len(raw) < ETH_HDR_LEN + TECMP_HDR_LEN:
                continue
            etype = struct.unpack_from('>H', raw, 12)[0]
            if etype not in (TECMP_ETHERTYPE, TECMP_ETHERTYPE_ALT):
                continue

            hdr_raw = raw[ETH_HDR_LEN:]
            (cm_id, counter, version, msg_type, data_type,
             _res, cm_flags, channel_id, timestamp, length, data_flags) = \
                struct.unpack_from(_HDR_FMT, hdr_raw, 0)

            key = (msg_type, data_type)
            if key not in seen:
                seen[key] = 0
                mtypes = {0x00:'CONTROL', 0x01:'CM_STATUS', 0x02:'BUS_STATUS',
                           0x03:'LOGGING_STREAM', 0x04:'CONFIG_STATUS', 0x0A:'REPLAY_DATA'}
                dtypes = {0x0002:'CAN', 0x0003:'CAN_FD', 0x0004:'LIN',
                           0x0080:'Ethernet', 0x0000:'(none)'}
                mt = mtypes.get(msg_type, f'0x{msg_type:02X}')
                dt = dtypes.get(data_type, f'0x{data_type:04X}')
                print(f"  New frame type: msg={mt}  data={dt}  "
                      f"cm_id=0x{cm_id:04X}  ch=0x{channel_id:08X}  len={length}")
            seen[key] += 1
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()

    if not seen:
        print("  ✗ FAIL — no TECMP frames decoded (run Layer 1 first)")
        return False

    has_can = any(dt == TECMP_DATA_CAN for _, dt in seen)
    has_logging = any(mt == TECMP_MSG_LOGGING for mt, _ in seen)

    if not has_logging:
        print("  ✗ FAIL — no LOGGING_STREAM (0x03) frames seen")
        print("    → Capture Module is not sending logged data to this PC")
    elif not has_can:
        print("  ✗ FAIL — LOGGING_STREAM frames seen but none contain CAN data (0x0002)")
        print("    → Is the CAN channel connected? Is the gateway sending anything?")
        print("    → Check that the Capture Module CAN port is wired to the gateway")
    else:
        print(f"  ✓ PASS — CAN LOGGING_STREAM frames are arriving")

    return has_can and has_logging


# ── Layer 3: CAN frame content ────────────────────────────────────────────────

def layer3_can_frames():
    section("LAYER 3 — CAN frame content (live bus monitor)")
    print("  Decodes and prints every CAN frame captured from the bus.")
    print("  Reboot the gateway now and watch for 0x18EEFF80 (address claim).")
    wait_or_skip()

    sock = open_raw_sock(TECMP_INTERFACE)
    count = 0
    deadline = time.monotonic() + LISTEN_SECS
    try:
        while time.monotonic() < deadline:
            try:
                raw, _ = sock.recvfrom(65536)
            except socket.timeout:
                continue
            frames = decode_tecmp_frame(raw)
            for f in frames:
                count += 1
                ts   = f.timestamp / 1e9
                id_s = f"0x{f.can_id:08X}" if f.extended else f"0x{f.can_id:03X}"
                fd_s = ' FD' if f.fd else ''
                ext_s= ' EXT' if f.extended else ''
                print(f"  [{ts % 1000:10.3f}]  ID={id_s}{ext_s}{fd_s}  "
                      f"DLC={f.dlc}  data={f.data.hex()}  ch=0x{f.channel_id:08X}")
                if f.extended:
                    d = decode_j1939_id(f.can_id)
                    pgn = d['pgn']
                    print(f"             J1939: SA=0x{d['sa']:02X}  "
                          f"DA=0x{d['da']:02X}  "
                          f"PGN=0x{pgn:05X} ({pgn_name(pgn)})")
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()

    if count == 0:
        print("  ✗ FAIL — no CAN frames decoded from TECMP")
        print("    Possible causes:")
        print("    1. Gateway not sending — check UART: 'J1939 gateway started at address 0x80'")
        print("    2. Bit timing mismatch — gateway nbrp must be 4 for 250 kbps")
        print("    3. CAN transceiver missing — Nucleo H755ZI has no onboard transceiver")
        print("    4. No bus termination — need 120Ω at each end")
        return False

    print(f"  ✓ PASS — {count} CAN frames decoded")
    return True


# ── Layer 4: CLOG on USB ECM ──────────────────────────────────────────────────

def layer4_clog():
    section("LAYER 4 — CLOG UDP on USB ECM (port 47808)")
    print("  Listens for CLOG frames from the gateway over USB ECM.")
    print("  Requires:")
    print("    - USB cable between PC and Nucleo USB port")
    print("    - PC has an IP on 10.10.10.x/24  (gateway USB IP = 10.10.10.15)")
    print("    - Gateway config: ch1.enabled=1, ch1.target=1 (USB)")
    wait_or_skip()

    # Show PC's current IPs for reference
    try:
        import subprocess
        result = subprocess.run(['ip', 'addr'], capture_output=True, text=True)
        lines = [l.strip() for l in result.stdout.splitlines()
                 if 'inet ' in l and '10.10.10.' in l]
        if lines:
            print(f"  PC USB ECM IP: {lines[0]}")
        else:
            print("  ✗ WARNING — no 10.10.10.x IP found on PC")
            print("    Run: sudo ip addr add 10.10.10.100/24 dev <usb_interface>")
    except Exception:
        pass

    sock = open_clog_sock()
    count = 0
    deadline = time.monotonic() + LISTEN_SECS
    try:
        while time.monotonic() < deadline:
            try:
                data, addr = sock.recvfrom(256)
            except socket.timeout:
                continue
            if data[:4] != b'CLOG':
                continue
            count += 1
            msg_type = data[5]
            types = {0: 'STATUS', 1: 'RAW_CAN', 2: 'J1939'}
            t = types.get(msg_type, f'0x{msg_type:02X}')
            seq = struct.unpack_from('>I', data, 8)[0]
            print(f"  CLOG frame from {addr[0]}  type={t}  seq={seq}  len={len(data)}")
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()

    if count == 0:
        print("  ✗ FAIL — no CLOG frames received on USB ECM")
        print("    Check: USB cable plugged in?")
        print("    Check: PC IP on 10.10.10.x/24?  (sudo ip addr add 10.10.10.100/24 dev <if>)")
        print("    Check: web UI ch1.enabled=1 ch1.target=1")
        return False

    print(f"  ✓ PASS — {count} CLOG frames received")
    return True


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    print("╔══════════════════════════════════════════════════════════╗")
    print("║         CAN-ETH Gateway — Diagnostic Tool               ║")
    print("╠══════════════════════════════════════════════════════════╣")
    print(f"║  TECMP interface : {TECMP_INTERFACE:<38}║")
    print(f"║  CM_ID           : 0x{TECMP_CM_ID:04X}  Channel: 0x{TECMP_CHANNEL_ID:02X}              ║")
    print(f"║  CLOG port       : UDP {CLOG_LISTEN_PORT:<34}║")
    print("╚══════════════════════════════════════════════════════════╝")
    print("\nRunning all 4 layers in sequence. Ctrl-C skips to the next layer.")

    results = []

    r1 = layer1_raw_ethernet()
    results.append(('L1 Raw Ethernet',  r1))

    r2 = layer2_tecmp_decode()
    results.append(('L2 TECMP decode',  r2))

    r3 = layer3_can_frames()
    results.append(('L3 CAN frames',    r3))

    r4 = layer4_clog()
    results.append(('L4 CLOG USB ECM',  r4))

    # Summary
    section("Summary")
    for name, ok in results:
        status = '✓ PASS' if ok else '✗ FAIL'
        print(f"  {status}  {name}")

    first_fail = next((n for n, ok in results if not ok), None)
    if first_fail:
        print(f"\n  → Fix {first_fail} first, then re-run.")
    else:
        print("\n  All layers OK — pipeline is working end-to-end.")


if __name__ == '__main__':
    main()
