#!/usr/bin/env python3
"""
can_tx.py — CAN frame injector for CAN-ETH Gateway

Sends CAN frames to the gateway's UDP inject port (4000) or via HTTP POST.
The gateway transmits the frame on the specified CAN channel.

UDP Packet Format (port 4000)
------------------------------
  Byte  0     Magic      = 0xCA
  Byte  1     Channel    = 0 (FDCAN1)  |  1 (FDCAN2, future)
  Byte  2     Flags      = EXT(0x01) | J1939(0x02) | FD(0x04) | BRS(0x08)
  Byte  3     DataLen    = payload length in bytes (0–64)
  Byte  4–7   CAN ID     = little-endian uint32, raw identifier (no flag bits)
  Byte  8+    Payload    = DataLen bytes of CAN data

Examples
--------
  # 11-bit standard frame, ID 0x123, 4-byte payload
  python3 can_tx.py --id 0x123 --data DEADBEEF

  # 29-bit extended frame (J1939), PGN 0xFF00, SA 0x80
  python3 can_tx.py --id 0x18FF0080 --ext --j1939 --data 0102030405060708

  # Burst of 100 frames at 10 ms intervals
  python3 can_tx.py --id 0x123 --data AABBCCDD --count 100 --interval 0.01

  # CAN FD with bit-rate switch, 32-byte payload
  python3 can_tx.py --id 0x123 --fd --brs --data $(python3 -c "print('AA'*32)")

  # Zero-byte frame
  python3 can_tx.py --id 0x123

  # Via HTTP POST instead of UDP
  python3 can_tx.py --mode http --id 0x123 --data DEADBEEF
"""

import struct
import socket
import argparse
import sys
import time
import json

# ── Gateway defaults ──────────────────────────────────────────────────────────
DEFAULT_GW_IP   = '121.145.35.64'
UDP_INJECT_PORT = 4000
HTTP_PORT       = 80

# ── Protocol constants ────────────────────────────────────────────────────────
INJECT_MAGIC      = 0xCA
INJECT_FLAG_EXT   = 0x01   # 29-bit extended ID
INJECT_FLAG_J1939 = 0x02   # J1939 frame (informational tag)
INJECT_FLAG_FD    = 0x04   # CAN FD frame
INJECT_FLAG_BRS   = 0x08   # bit-rate switch (FD only)
INJECT_HDR_SIZE   = 8

DLC_TABLE = [0, 1, 2, 3, 4, 5, 6, 7, 8, 12, 16, 20, 24, 32, 48, 64]

# ── Helpers ───────────────────────────────────────────────────────────────────

def bytes_to_dlc(n: int) -> int:
    for i, length in enumerate(DLC_TABLE):
        if length >= n:
            return i
    return 15

def dlc_to_len(dlc: int) -> int:
    return DLC_TABLE[dlc] if 0 <= dlc <= 15 else 64

def parse_id(id_str: str) -> int:
    return int(id_str, 0) & 0x1FFFFFFF   # strip any accidental flag bits

def parse_data(hex_str: str) -> bytes:
    hex_str = hex_str.replace(' ', '').replace(':', '')
    if not hex_str:
        return b''
    if len(hex_str) % 2:
        hex_str = '0' + hex_str
    return bytes.fromhex(hex_str)

def build_udp_packet(can_id: int, data: bytes, flags: int,
                     channel: int = 0) -> bytes:
    """
    Build the 8-byte header + payload UDP inject packet.

      [0]     0xCA magic
      [1]     channel (0 = FDCAN1)
      [2]     flags
      [3]     data_len
      [4–7]   CAN ID (LE uint32, raw identifier — no flag embedding)
      [8+]    payload
    """
    data_len = len(data)
    if data_len > 64:
        raise ValueError(f'Payload too long: {data_len} > 64 bytes')
    return struct.pack('<BBBBl',
                       INJECT_MAGIC, channel, flags, data_len, can_id
                       ) + data

def send_udp(ip: str, can_id: int, data: bytes, flags: int,
             channel: int = 0) -> None:
    pkt  = build_udp_packet(can_id, data, flags, channel)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(pkt, (ip, UDP_INJECT_PORT))
    finally:
        sock.close()

def send_http(ip: str, can_id: int, data: bytes, flags: int) -> dict:
    """POST JSON to /api/send/can (stdlib only, no requests dependency)."""
    # HTTP handler uses the EXT_FLAG convention in the ID field
    full_id = can_id
    if flags & INJECT_FLAG_EXT:
        full_id |= (1 << 30)

    body = json.dumps({
        'id':   f'0x{full_id:08X}',
        'data': data.hex().upper(),
        'fd':   bool(flags & INJECT_FLAG_FD),
        'brs':  bool(flags & INJECT_FLAG_BRS),
    }).encode()

    req = (
        f'POST /api/send/can HTTP/1.1\r\n'
        f'Host: {ip}\r\n'
        f'Content-Type: application/json\r\n'
        f'Content-Length: {len(body)}\r\n'
        f'Connection: close\r\n\r\n'
    ).encode() + body

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3.0)
    try:
        sock.connect((ip, HTTP_PORT))
        sock.sendall(req)
        resp = b''
        while True:
            chunk = sock.recv(1024)
            if not chunk:
                break
            resp += chunk
    finally:
        sock.close()

    try:
        _, _, body_raw = resp.partition(b'\r\n\r\n')
        return json.loads(body_raw)
    except Exception:
        return {'raw': resp.decode(errors='replace')}

# ── Formatting ────────────────────────────────────────────────────────────────

def frame_summary(can_id: int, data: bytes, flags: int, channel: int) -> str:
    is_ext  = bool(flags & INJECT_FLAG_EXT)
    is_j1939= bool(flags & INJECT_FLAG_J1939)
    id_str  = f'0x{can_id:08X}' if is_ext else f'0x{can_id:03X}'
    kind    = []
    if is_ext:   kind.append('EXT')
    if is_j1939: kind.append('J1939')
    if flags & INJECT_FLAG_FD:  kind.append('FD')
    if flags & INJECT_FLAG_BRS: kind.append('BRS')
    kind_str = '|'.join(kind) if kind else 'STD'
    data_str = data.hex().upper() if data else '(none)'
    ch_str   = f'FDCAN{channel + 1}'
    return f'CH={ch_str}  ID={id_str} [{kind_str}]  len={len(data)}  data={data_str}'

def hex_dump(packet: bytes) -> str:
    return ' '.join(f'{b:02X}' for b in packet)

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(
        description='Inject CAN frames into CAN-ETH Gateway',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument('--ip',       default=DEFAULT_GW_IP,
                   help=f'Gateway IP (default: {DEFAULT_GW_IP})')
    p.add_argument('--mode',     choices=['udp', 'http'], default='udp',
                   help='Transport: udp (default) or http')
    p.add_argument('--channel',  type=int, default=0, choices=[0, 1],
                   help='CAN channel: 0 = FDCAN1 (default), 1 = FDCAN2')

    p.add_argument('--id',       required=True,
                   help='CAN identifier (hex or decimal). '
                        '11-bit: 0x000–0x7FF. 29-bit: use --ext.')
    p.add_argument('--ext',      action='store_true',
                   help='29-bit extended frame (sets EXT flag).')
    p.add_argument('--j1939',    action='store_true',
                   help='Tag frame as J1939 (informational; implies --ext).')
    p.add_argument('--fd',       action='store_true',
                   help='CAN FD frame (payload up to 64 bytes).')
    p.add_argument('--brs',      action='store_true',
                   help='Bit-rate switch — CAN FD only.')
    p.add_argument('--data',     default='',
                   help='Payload as hex string, e.g. DEADBEEF. '
                        'Omit for 0-byte frame.')

    p.add_argument('--count',    type=int,   default=1,
                   help='Frames to send (default: 1).')
    p.add_argument('--interval', type=float, default=0.010,
                   help='Delay between frames in seconds (default: 0.010).')
    p.add_argument('--dump',     action='store_true',
                   help='Print raw packet hex before sending.')
    p.add_argument('--quiet',    action='store_true',
                   help='Suppress per-frame output.')

    args = p.parse_args()

    # Build flag byte
    flags = 0
    if args.ext   or args.j1939: flags |= INJECT_FLAG_EXT
    if args.j1939:               flags |= INJECT_FLAG_J1939
    if args.fd:                  flags |= INJECT_FLAG_FD
    if args.brs:                 flags |= INJECT_FLAG_BRS

    if args.brs and not args.fd:
        print('Warning: --brs has no effect without --fd', file=sys.stderr)

    can_id = parse_id(args.id)
    data   = parse_data(args.data)

    if len(data) > 8 and not args.fd:
        print('Warning: payload > 8 bytes requires --fd for CAN FD', file=sys.stderr)

    print(f'Gateway : {args.ip}')
    print(f'Mode    : {args.mode.upper()}')
    print(f'Frame   : {frame_summary(can_id, data, flags, args.channel)}')
    print(f'Count   : {args.count}  interval: {args.interval*1000:.1f} ms')

    if args.dump and args.mode == 'udp':
        pkt = build_udp_packet(can_id, data, flags, args.channel)
        print(f'Packet  : {hex_dump(pkt)}')

    print()

    ok = 0
    fail = 0

    for i in range(args.count):
        try:
            if args.mode == 'udp':
                send_udp(args.ip, can_id, data, flags, args.channel)
                success = True
            else:
                resp = send_http(args.ip, can_id, data, flags)
                success = resp.get('status') == 'ok'
                if not success and not args.quiet:
                    print(f'  [{i+1:>5}/{args.count}]  HTTP error: {resp}')

            if success:
                ok += 1
                if not args.quiet:
                    print(f'  [{i+1:>5}/{args.count}]  sent')
            else:
                fail += 1

        except Exception as e:
            fail += 1
            print(f'  [{i+1:>5}/{args.count}]  ERROR: {e}', file=sys.stderr)

        if i < args.count - 1:
            time.sleep(args.interval)

    print()
    print(f'Done — {ok} sent, {fail} failed.')
    if fail:
        sys.exit(1)


if __name__ == '__main__':
    main()
