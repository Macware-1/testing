#!/usr/bin/env python3
"""Minimal UDP sniffer for port 47808 — prints every packet received."""
import socket, struct, sys

PORT = 47808

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
except AttributeError:
    pass
sock.bind(('', PORT))
sock.settimeout(30.0)

print(f'Listening on 0.0.0.0:{PORT} — waiting for packets (30 s timeout) …\n')

count = 0
try:
    while True:
        data, addr = sock.recvfrom(4096)
        count += 1
        tag = data[:4]
        hdr = ''
        if tag == b'CLOG' and len(data) >= 28:
            ver, mtype, ch, flags = data[4], data[5], data[6], data[7]
            seq, = struct.unpack_from('>I', data, 8)
            can_id, = struct.unpack_from('>I', data, 20)
            dlc = data[24]
            hdr = (f'  CLOG v{ver} type=0x{mtype:02x} ch={ch} seq={seq} '
                   f'can_id=0x{can_id:08x} dlc={dlc}')
        print(f'[{count:4}] from {addr[0]}:{addr[1]}  len={len(data)} bytes')
        print(f'       raw: {data[:32].hex()}')
        if hdr:
            print(hdr)
        print()
except socket.timeout:
    print(f'Timeout — {count} packet(s) received total.')
except KeyboardInterrupt:
    print(f'\nStopped — {count} packet(s) received total.')
