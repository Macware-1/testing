#!/usr/bin/env python3
"""
clog_receiver.py — live CLOG UDP listener.

Prints every CLOG frame (Status, Raw CAN, J1939) received from the gateway
over the USB ECM interface (10.10.10.255 broadcast, port 47808).

Usage:
    python clog_receiver.py
    python clog_receiver.py --port 47808 --iface 10.10.10.100

Press Ctrl-C to stop.
"""

import argparse
import socket
import struct
import sys
import time
from j1939_utils import (decode_clog, pgn_name,
                          CLOG_TYPE_STATUS, CLOG_TYPE_RAW_CAN, CLOG_TYPE_J1939,
                          CLOG_UDP_PORT)


def flag_str(flags: int) -> str:
    parts = []
    if flags & 0x08: parts.append('EXT')
    if flags & 0x01: parts.append('FD')
    if flags & 0x02: parts.append('BRS')
    if flags & 0x04: parts.append('ESI')
    if flags & 0x10: parts.append('RTR')
    return '+'.join(parts) if parts else 'STD'


def print_frame(f: dict, addr: tuple) -> None:
    t = f['ts_sec'] % 1000 + f['ts_nsec'] * 1e-9   # rolling display timestamp
    seq = f['seq']

    if f['type'] == CLOG_TYPE_J1939:
        data_hex = f.get('data', b'').hex()
        pgn = f.get('pgn', 0)
        print(f"  [{t:>10.6f}] J1939  seq={seq:<6}  "
              f"SA=0x{f.get('sa',0):02X}  DA=0x{f.get('da',0):02X}  "
              f"PGN=0x{pgn:05X} ({pgn_name(pgn)})  "
              f"DLC={f['dlc']}  data={data_hex}  "
              f"pri={f.get('priority',0)}  {flag_str(f['flags'])}")

    elif f['type'] == CLOG_TYPE_RAW_CAN:
        data_hex = f.get('data', b'').hex()
        print(f"  [{t:>10.6f}] RAW    seq={seq:<6}  "
              f"ID=0x{f['can_id']:08X}  DLC={f['dlc']}  data={data_hex}  "
              f"{flag_str(f['flags'])}")

    elif f['type'] == CLOG_TYPE_STATUS:
        print(f"  [{t:>10.6f}] STATUS seq={seq:<6}  "
              f"fw={f.get('fw','?')}  uptime={f.get('uptime_sec',0)}s  "
              f"CAN1={f.get('can1_state','?')}  "
              f"ch1_rx={f.get('ch1_rx',0)}  dropped={f.get('dropped',0)}")
    else:
        print(f"  [{t:>10.6f}] UNKNOWN type=0x{f['type']:02X}  src={addr}")


def main():
    parser = argparse.ArgumentParser(description='CLOG UDP receiver')
    parser.add_argument('--port',  type=int,   default=CLOG_UDP_PORT)
    parser.add_argument('--iface', type=str,   default='',
                        help='Bind to specific IP (default: all interfaces)')
    args = parser.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.iface, args.port))

    print(f"Listening for CLOG on UDP port {args.port} …  (Ctrl-C to stop)")
    print(f"{'─'*80}")

    frame_count = 0
    start = time.monotonic()
    try:
        while True:
            try:
                raw, addr = sock.recvfrom(1500)
            except socket.timeout:
                continue
            f = decode_clog(raw)
            if f is None:
                print(f"  [?] Received {len(raw)} bytes from {addr} — not a CLOG frame")
                continue
            frame_count += 1
            print_frame(f, addr)
    except KeyboardInterrupt:
        elapsed = time.monotonic() - start
        rate = frame_count / elapsed if elapsed > 0 else 0
        print(f"\n{'─'*80}")
        print(f"Received {frame_count} frames in {elapsed:.1f}s  ({rate:.1f} fps)")


if __name__ == '__main__':
    main()
