#!/usr/bin/env python3
"""
can_loopback.py — CAN bus loopback / frame-loss test for CAN-ETH Gateway

Physical setup
--------------
  Connect FDCAN1 transceiver  ──  CAN-H to CAN-H, CAN-L to CAN-L  ──  FDCAN2 transceiver
  Add a 120 Ω termination resistor at each transceiver end.

  FDCAN1 pins: PD0 (RX), PD1 (TX)
  FDCAN2 pins: PB12 (RX), PB6 (TX)

Data flow
---------
  PC  ──► UDP inject port 4000 (channel 0, FDCAN1 TX)
         │
         ▼  CAN bus wire
  FDCAN2 RX  ──► CLOG UDP port 47808 (channel_id = ch2.logging_id from gateway config)
         │
         ▼
  PC listens and correlates frames by sequence number

Frame identification
--------------------
  All test frames share a fixed CAN ID (default 0x7FF).
  Payload format (8 bytes):
    [0–3]  little-endian sequence number (uint32)
    [4–7]  magic pattern 0xDEADBEEF

Configuration note
------------------
  The gateway sends CLOG to the subnet broadcast address (e.g. 10.104.3.255),
  never to a specific PC IP. Enable SO_BROADCAST is required on the RX socket.

  In the gateway web UI, set ch2 logging: enabled=1, target=ETH (0).
  There is no "destination IP" field — the gateway always broadcasts.

  By default both ch1 and ch2 logging_id = 0.
  To distinguish ch2 RX frames, set ch2.logging_id to 1 in the gateway web UI
  and pass --rx-logging-id 1 to this script.
  Without that filter (-1 = accept any) the script matches by CAN ID + magic only.

Examples
--------
  # Burst of 1000 frames, accept any CLOG channel
  python3 can_loopback.py --ip 121.145.35.64 --count 1000

  # 500 frames at 5 ms interval with extended 29-bit CAN ID
  python3 can_loopback.py --ip 121.145.35.64 --count 500 --interval 0.005 --ext --can-id 0x1FFAB123

  # Unlimited until Ctrl+C, strict ch2 CLOG filter
  python3 can_loopback.py --ip 121.145.35.64 --count 0 --rx-logging-id 1

  # Reverse: inject on FDCAN2, receive on FDCAN1
  python3 can_loopback.py --ip 121.145.35.64 --tx-channel 1 --rx-logging-id 0
"""

import argparse
import socket
import struct
import sys
import threading
import time

# ── Protocol constants ────────────────────────────────────────────────────────
INJECT_MAGIC      = 0xCA
INJECT_FLAG_EXT   = 0x01
INJECT_FLAG_FD    = 0x04
INJECT_FLAG_BRS   = 0x08
INJECT_HDR_SIZE   = 8
UDP_INJECT_PORT   = 4000
CLOG_UDP_PORT     = 47808
CLOG_MAGIC        = b'CLOG'
CLOG_HDR_SIZE     = 28
CLOG_TYPE_RAW_CAN = 0x01
TEST_MAGIC_BYTES  = 0xDEADBEEF
DLC_TABLE         = [0, 1, 2, 3, 4, 5, 6, 7, 8, 12, 16, 20, 24, 32, 48, 64]


def dlc_to_len(dlc: int) -> int:
    return DLC_TABLE[dlc] if 0 <= dlc <= 15 else 64


def build_inject_packet(can_id: int, payload: bytes, flags: int, channel: int) -> bytes:
    """8-byte inject header + payload."""
    return struct.pack('<BBBBl',
                       INJECT_MAGIC, channel, flags, len(payload), can_id) + payload


def make_payload(seq: int) -> bytes:
    """8-byte test payload: 4-byte seq (LE) + 4-byte magic."""
    return struct.pack('<II', seq, TEST_MAGIC_BYTES)


# ── Loopback test ─────────────────────────────────────────────────────────────

class LoopbackTest:
    def __init__(self, args):
        self.args = args
        self.lock = threading.Lock()

        # seq → monotonic send time
        self.sent: dict[int, float] = {}
        # seq → monotonic receive time
        self.recv: dict[int, float] = {}
        self.dupe_count = 0
        self.running = True

        # TX socket (plain UDP)
        self.sock_tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # RX socket — must have SO_BROADCAST to receive directed subnet broadcasts.
        # Gateway sends CLOG to the subnet broadcast address (e.g. 10.104.3.255),
        # not a specific PC IP.
        self.sock_rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock_rx.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.sock_rx.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.sock_rx.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except AttributeError:
            pass
        self.sock_rx.settimeout(0.1)
        self.sock_rx.bind((args.iface, CLOG_UDP_PORT))

    # ── TX ────────────────────────────────────────────────────────────────────

    def _tx_flags(self) -> int:
        f = 0
        if self.args.ext:  f |= INJECT_FLAG_EXT
        if self.args.fd:   f |= INJECT_FLAG_FD
        if self.args.brs:  f |= INJECT_FLAG_BRS
        return f

    def tx_thread(self):
        flags    = self._tx_flags()
        can_id   = self.args.can_id
        channel  = self.args.tx_channel
        interval = self.args.interval
        total    = self.args.count
        seq      = 0

        while self.running:
            if total and seq >= total:
                break
            payload = make_payload(seq)
            pkt     = build_inject_packet(can_id, payload, flags, channel)
            t       = time.monotonic()
            try:
                self.sock_tx.sendto(pkt, (self.args.ip, UDP_INJECT_PORT))
            except OSError as e:
                print(f'\n  TX error at seq {seq}: {e}', file=sys.stderr)
            with self.lock:
                self.sent[seq] = t
            seq += 1
            if interval > 0:
                time.sleep(interval)

        # Keep RX thread alive for late arrivals
        time.sleep(self.args.timeout)
        self.running = False

    # ── RX ────────────────────────────────────────────────────────────────────

    def rx_thread(self):
        target_id_be   = struct.pack('>I', self.args.can_id & 0x1FFFFFFF)
        rx_logging_id  = self.args.rx_logging_id

        while self.running:
            try:
                data, _src = self.sock_rx.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                break

            if len(data) < CLOG_HDR_SIZE:
                continue
            if data[:4] != CLOG_MAGIC:
                continue
            if data[5] != CLOG_TYPE_RAW_CAN:
                continue
            if rx_logging_id >= 0 and data[6] != rx_logging_id:
                continue
            if data[20:24] != target_id_be:
                continue

            dlc       = data[24]
            dlen      = dlc_to_len(dlc)
            pay_start = CLOG_HDR_SIZE
            if len(data) < pay_start + 8 or dlen < 8:
                continue

            seq_val, magic = struct.unpack_from('<II', data, pay_start)
            if magic != TEST_MAGIC_BYTES:
                continue

            t = time.monotonic()
            with self.lock:
                if seq_val in self.recv:
                    self.dupe_count += 1
                    continue
                self.recv[seq_val] = t

    # ── Stats ─────────────────────────────────────────────────────────────────

    def stats_thread(self):
        prev_sent = 0
        prev_recv = 0
        prev_t    = time.monotonic()

        while self.running:
            time.sleep(1.0)
            now = time.monotonic()
            dt  = now - prev_t
            with self.lock:
                s = len(self.sent)
                r = len(self.recv)
            rate_tx = (s - prev_sent) / dt
            rate_rx = (r - prev_recv) / dt
            in_flight = s - r
            print(f'  TX {s:>6}  ({rate_tx:>6.0f}/s)    '
                  f'RX {r:>6}  ({rate_rx:>6.0f}/s)    '
                  f'in-flight {in_flight:>4}', flush=True)
            prev_sent = s
            prev_recv = r
            prev_t    = now

    # ── Run ───────────────────────────────────────────────────────────────────

    def run(self) -> int:
        a = self.args
        id_str = f'0x{a.can_id:08X}' if a.ext else f'0x{a.can_id:03X}'
        kind   = []
        if a.ext: kind.append('EXT')
        if a.fd:  kind.append('FD')
        if a.brs: kind.append('BRS')
        kind_str = '|'.join(kind) if kind else 'STD'

        print(f'Gateway     : {a.ip}')
        print(f'TX channel  : {a.tx_channel}  (FDCAN{a.tx_channel + 1}  →  UDP inject port {UDP_INJECT_PORT})')
        print(f'RX filter   : CLOG port {CLOG_UDP_PORT}'
              + (f'  channel_id = {a.rx_logging_id}' if a.rx_logging_id >= 0 else '  (any channel_id)'))
        print(f'CAN ID      : {id_str}  [{kind_str}]')
        if a.count:
            rate_str = 'burst' if a.interval == 0 else f'{a.interval * 1000:.1f} ms interval'
            print(f'Frames      : {a.count}  ({rate_str})')
        else:
            print('Frames      : unlimited  (Ctrl+C to stop)')
        print()
        print(f'  {"TX":>6}  (rate/s)    {"RX":>6}  (rate/s)    in-flight')
        print(f'  {"─"*6}  {"─"*8}    {"─"*6}  {"─"*8}    {"─"*9}')

        t_rx    = threading.Thread(target=self.rx_thread,    daemon=True)
        t_stats = threading.Thread(target=self.stats_thread, daemon=True)
        t_tx    = threading.Thread(target=self.tx_thread,    daemon=True)

        t_rx.start()
        t_stats.start()
        t_tx.start()

        try:
            t_tx.join()
        except KeyboardInterrupt:
            self.running = False
            print('\nInterrupted.')

        self.running = False
        self.sock_rx.close()
        self.sock_tx.close()

        # ── Final report ──────────────────────────────────────────────────────
        with self.lock:
            sent_seqs = set(self.sent)
            recv_seqs = set(self.recv)

        matched = sent_seqs & recv_seqs
        lost    = sent_seqs - recv_seqs
        extra   = recv_seqs - sent_seqs

        latencies_ms: list[float] = []
        for s in matched:
            latencies_ms.append((self.recv[s] - self.sent[s]) * 1000.0)
        latencies_ms.sort()

        n_sent  = len(sent_seqs)
        n_recv  = len(recv_seqs)
        n_match = len(matched)
        n_lost  = len(lost)

        print()
        print('─' * 60)
        print(f'  Sent       : {n_sent}')
        print(f'  Received   : {n_recv}')
        print(f'  Matched    : {n_match}')
        loss_pct = 100.0 * n_lost / max(1, n_sent)
        print(f'  Lost       : {n_lost}  ({loss_pct:.2f}%)')
        if self.dupe_count:
            print(f'  Duplicates : {self.dupe_count}')
        if extra:
            print(f'  Unexpected : {len(extra)}  (RX frames with test CAN ID but seq not in TX set)')
        if latencies_ms:
            avg = sum(latencies_ms) / len(latencies_ms)
            p50 = latencies_ms[int(0.50 * len(latencies_ms))]
            p95 = latencies_ms[int(0.95 * len(latencies_ms))]
            p99 = latencies_ms[int(0.99 * len(latencies_ms))]
            print(f'  Latency    : min={latencies_ms[0]:.1f}  avg={avg:.1f}'
                  f'  p50={p50:.1f}  p95={p95:.1f}  p99={p99:.1f}'
                  f'  max={latencies_ms[-1]:.1f}  ms')
        print('─' * 60)

        if n_lost == 0 and n_match > 0:
            print(f'  PASS — all {n_match} frames received.')
        elif n_match == 0:
            print('  FAIL — no frames received. Check wiring, termination, and gateway config.')
        else:
            print(f'  FAIL — {n_lost} frames lost ({loss_pct:.2f}%).')

        return 0 if n_lost == 0 and n_match > 0 else 1


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(
        description='CAN loopback / frame-loss test for CAN-ETH Gateway',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument('--ip',            default='121.145.35.64',
                   help='Gateway IP address (default: 121.145.35.64)')
    p.add_argument('--iface',         default='',
                   help='Local interface IP to bind CLOG RX socket (default: all interfaces). '
                        'Set to your PC\'s IP on the gateway subnet, e.g. 10.104.3.100')
    p.add_argument('--tx-channel',    type=int, default=0, choices=[0, 1],
                   help='Inject channel: 0 = FDCAN1 TX (default), 1 = FDCAN2 TX')
    p.add_argument('--rx-logging-id', type=int, default=-1,
                   help='CLOG channel_id to accept. -1 = any (default). '
                        'Set to the ch2.logging_id value from the gateway web UI '
                        'to filter strictly to the receiving CAN channel.')
    p.add_argument('--can-id',        default='0x7FF',
                   help='CAN identifier for test frames (default: 0x7FF for STD, '
                        'use --ext for 29-bit)')
    p.add_argument('--ext',           action='store_true',
                   help='Use 29-bit extended CAN ID')
    p.add_argument('--fd',            action='store_true',
                   help='Use CAN FD framing (payload still 8 bytes)')
    p.add_argument('--brs',           action='store_true',
                   help='Bit-rate switch (FD only)')
    p.add_argument('--count',         type=int, default=1000,
                   help='Number of frames to send (0 = unlimited, default: 1000)')
    p.add_argument('--interval',      type=float, default=0.0,
                   help='Seconds between TX frames (0 = burst, default: 0 = burst)')
    p.add_argument('--timeout',       type=float, default=1.0,
                   help='Seconds to wait for late frames after TX completes (default: 1.0)')

    args = p.parse_args()
    args.can_id = int(args.can_id, 0) & 0x1FFFFFFF

    if not args.ext and args.can_id > 0x7FF:
        print(f'Warning: CAN ID 0x{args.can_id:X} > 0x7FF — add --ext for 29-bit extended frame.',
              file=sys.stderr)

    if args.brs and not args.fd:
        print('Warning: --brs has no effect without --fd.', file=sys.stderr)

    test = LoopbackTest(args)
    sys.exit(test.run())


if __name__ == '__main__':
    main()
