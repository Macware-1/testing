#!/usr/bin/env python3
"""
CLOG Viewer — portable CAN Logger Protocol v2 viewer.

No external dependencies — requires only Python 3.8+ with tkinter.

To build a standalone executable (no Python or installation needed):
    pip install pyinstaller
    # Linux:
    pyinstaller --onefile --windowed clog_viewer.py
    # Windows (run in cmd):
    pyinstaller --onefile --windowed --name "CLOG Viewer" clog_viewer.py
    # Output: dist/clog_viewer  (Linux)  or  dist/CLOG Viewer.exe  (Windows)

Protocol: UDP port 47808, CLOG v2, 28-byte header.
"""

import csv
import queue
import socket
import struct
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

# Optional: scapy for Npcap capture (bypasses Windows Firewall).
# Install with:  pip install scapy
# Requires Npcap (https://npcap.com) — already installed if Wireshark is present.
try:
    from scapy.all import AsyncSniffer, IP, UDP   # type: ignore
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# ── Protocol constants ──────────────────────────────────────────────────────────

CLOG_MAGIC  = b'CLOG'
CLOG_PORT   = 47808
HDR_SIZE    = 28

DLC_TO_LEN  = [0, 1, 2, 3, 4, 5, 6, 7, 8, 12, 16, 20, 24, 32, 48, 64]

MSG_TYPES   = {0: 'STATUS', 1: 'RAW CAN', 2: 'J1939'}
BUS_STATES  = {0: 'OK', 1: 'Warning', 2: 'Passive', 3: 'Bus-Off'}

J1939_PGNS = {
    0x00000: 'TSC1',            0x00100: 'TC1',
    0x0EE00: 'Address Claimed', 0x0EF00: 'Cannot Claim',
    0x0F001: 'ETC2',            0x0F003: 'EEC2',
    0x0F004: 'EEC1',            0x0F005: 'EEC3',
    0x0F009: 'EBC2',            0x0FEC1: 'HOURS',
    0x0FECA: 'DM1',             0x0FECB: 'DM2',
    0x0FECC: 'DM3',             0x0FED5: 'DM11',
    0x0FEE0: 'VD',              0x0FEE3: 'AIR1',
    0x0FEE9: 'LFC',             0x0FEEA: 'VW',
    0x0FEEC: 'EI',              0x0FEEE: 'ET1',
    0x0FEF0: 'LFC2',            0x0FEF1: 'CCVS',
    0x0FEF2: 'LFE',             0x0FEF5: 'AMBC',
    0x0FEF6: 'IC1',             0x0FEF7: 'VEP1',
    0x0FEF8: 'TF',              0x0FEF9: 'EI2',
    0x0FEFC: 'DD',              0x0FEFD: 'A1',
}

J1939_ADDRS = {
    0x00: 'Engine #1',        0x01: 'Engine #2',
    0x03: 'Transmission #1',  0x04: 'Transmission #2',
    0x0B: 'Brakes',           0x17: 'Instrument Cluster',
    0x21: 'Body Controller',  0x27: 'Cab Controller',
    0x80: 'Gateway',          0xFE: 'Null',
    0xFF: 'Global/Broadcast',
}

FLAG_FD  = 0x01
FLAG_BRS = 0x02
FLAG_ESI = 0x04
FLAG_EXT = 0x08
FLAG_RTR = 0x10

# ── Row colours (bg, fg) — empty string = default ──────────────────────────────

ROW_COLORS = {
    'STATUS': ('#dbeafe', '#1e3a8a'),
    'J1939':  ('#dcfce7', '#14532d'),
    'FD+BRS': ('#fef9c3', '#713f12'),
    'FD':     ('#e0f2fe', '#0c4a6e'),
    'RTR':    ('#fce7f3', '#831843'),
    'BUS-OFF':('#fee2e2', '#7f1d1d'),
    'CAN':    ('',        ''),
}

# ── Protocol parsing ────────────────────────────────────────────────────────────

def _dlc_len(dlc):
    return DLC_TO_LEN[dlc] if 0 <= dlc <= 15 else 0


def parse_packet(raw):
    if len(raw) < HDR_SIZE or raw[:4] != CLOG_MAGIC or raw[4] != 2:
        return None

    msg_type = raw[5]
    chan_id  = raw[6]
    flags    = raw[7]
    seq,     = struct.unpack_from('>I', raw,  8)
    ts_sec,  = struct.unpack_from('>I', raw, 12)
    ts_nsec, = struct.unpack_from('>I', raw, 16)
    can_id,  = struct.unpack_from('>I', raw, 20)
    dlc      = raw[24]
    dlen     = _dlc_len(dlc)

    pkt = {
        'msg_type': msg_type,
        'chan_id':  chan_id,
        'flags':    flags,
        'seq':      seq,
        'ts_sec':   ts_sec,
        'ts_nsec':  ts_nsec,
        'can_id':   can_id,
        'dlc':      dlc,
        'dlen':     dlen,
        'is_fd':    bool(flags & FLAG_FD),
        'is_brs':   bool(flags & FLAG_BRS),
        'is_esi':   bool(flags & FLAG_ESI),
        'is_ext':   bool(flags & FLAG_EXT),
        'is_rtr':   bool(flags & FLAG_RTR),
        'data':     b'',
        'extra':    {},
    }

    pl = raw[HDR_SIZE:]

    if msg_type == 0 and len(pl) >= 40:
        pkt['extra'] = {
            'flags':    pl[0],
            'eth_up':   bool(pl[0] & 0x01),
            'c1_act':   bool(pl[0] & 0x02),
            'c2_act':   bool(pl[0] & 0x04),
            'ptp_ok':   bool(pl[0] & 0x08),
            'c1_state': pl[1],
            'c2_state': pl[2],
            'fw_major': pl[3],
            'fw_minor': pl[4],
            'uptime':   struct.unpack_from('>I', pl,  8)[0],
            'c1_rx':    struct.unpack_from('>I', pl, 12)[0],
            'c2_rx':    struct.unpack_from('>I', pl, 16)[0],
            'c1_tx':    struct.unpack_from('>I', pl, 20)[0],
            'c2_tx':    struct.unpack_from('>I', pl, 24)[0],
            'c1_err':   struct.unpack_from('>I', pl, 28)[0],
            'c2_err':   struct.unpack_from('>I', pl, 32)[0],
            'dropped':  struct.unpack_from('>I', pl, 36)[0],
        }
    elif msg_type == 1 and dlen > 0 and len(pl) >= dlen:
        pkt['data'] = pl[:dlen]
    elif msg_type == 2 and len(pl) >= 8:
        pkt['extra'] = {
            'priority': pl[0],
            'sa':       pl[1],
            'da':       pl[2],
            'pgn':      struct.unpack_from('>I', pl, 4)[0],
        }
        if dlen > 0 and len(pl) >= 8 + dlen:
            pkt['data'] = pl[8:8 + dlen]

    return pkt

# ── Display formatters ──────────────────────────────────────────────────────────

def fmt_type(pkt):
    t = pkt['msg_type']
    if t == 0: return 'STATUS'
    if t == 2: return 'J1939'
    if pkt['is_brs']: return 'FD+BRS'
    if pkt['is_fd']:  return 'FD'
    if pkt['is_rtr']: return 'RTR'
    return 'CAN'


def fmt_can_id(pkt):
    if pkt['msg_type'] == 0:
        return '—'
    if pkt['is_ext']:
        return f'{pkt["can_id"]:08X}h'
    return f'{pkt["can_id"]:03X}h'


def fmt_info(pkt):
    t = pkt['msg_type']
    if t == 0:
        st = pkt['extra']
        if st:
            c1 = BUS_STATES.get(st['c1_state'], '?')
            c2 = BUS_STATES.get(st['c2_state'], '?')
            return (f'FW {st["fw_major"]}.{st["fw_minor"]}  '
                    f'up={st["uptime"]}s  '
                    f'ETH={"UP" if st["eth_up"] else "DOWN"}  '
                    f'PTP={"OK" if st["ptp_ok"] else "--"}  '
                    f'C1:{c1}  C2:{c2}')
        return ''
    if t == 2:
        j = pkt['extra']
        if j:
            pgn_name = J1939_PGNS.get(j['pgn'], '')
            pgn_str  = f'0x{j["pgn"]:05X}' + (f' {pgn_name}' if pgn_name else '')
            sa_name  = J1939_ADDRS.get(j['sa'], '')
            sa_str   = f'SA=0x{j["sa"]:02X}' + (f' ({sa_name})' if sa_name else '')
            data_hex = pkt['data'].hex(' ').upper() if pkt['data'] else ''
            return f'PGN={pgn_str}  {sa_str}  [{data_hex}]'
        return ''
    # RAW CAN
    if pkt['is_rtr']:
        return f'RTR request ({pkt["dlen"]}B)'
    if pkt['data']:
        return pkt['data'].hex(' ').upper()
    return '(no data)'


def row_tag(pkt):
    t = pkt['msg_type']
    if t == 0:
        st = pkt['extra']
        if st and (st.get('c1_state') == 3 or st.get('c2_state') == 3):
            return 'BUS-OFF'
        return 'STATUS'
    if t == 2: return 'J1939'
    if pkt['is_brs']: return 'FD+BRS'
    if pkt['is_fd']:  return 'FD'
    if pkt['is_rtr']: return 'RTR'
    return 'CAN'


def build_detail(pkt, pkt_num, src):
    lines = [
        f'=== Packet #{pkt_num}  from {src} ===',
        f'Type      : {MSG_TYPES.get(pkt["msg_type"], str(pkt["msg_type"]))}',
        f'Channel   : {pkt["chan_id"]}',
        f'Sequence  : {pkt["seq"]}',
        f'Timestamp : {pkt["ts_sec"]}.{pkt["ts_nsec"]:09d} s  (PTP TAI)',
    ]
    if pkt['msg_type'] != 0:
        id_str = (f'0x{pkt["can_id"]:08X}  (29-bit extended)' if pkt['is_ext']
                  else f'0x{pkt["can_id"]:03X}  (11-bit standard)')
        lines += [
            f'CAN ID    : {id_str}',
            f'DLC       : {pkt["dlc"]}  →  {pkt["dlen"]} byte(s)',
        ]
        flag_parts = []
        if pkt['is_fd']:  flag_parts.append('FD')
        if pkt['is_brs']: flag_parts.append('BRS')
        if pkt['is_esi']: flag_parts.append('ESI')
        if pkt['is_ext']: flag_parts.append('EXT')
        if pkt['is_rtr']: flag_parts.append('RTR')
        lines.append(f'Flags     : 0x{pkt["flags"]:02X}  [{" | ".join(flag_parts) or "none"}]')

    if pkt['msg_type'] == 0:
        st = pkt['extra']
        if st:
            lines += [
                '',
                '--- Gateway Status ---',
                f'Firmware  : v{st["fw_major"]}.{st["fw_minor"]}',
                f'Uptime    : {st["uptime"]} seconds',
                f'Ethernet  : {"UP" if st["eth_up"] else "DOWN"}',
                f'PTP       : {"LOCKED" if st["ptp_ok"] else "unlocked"}',
                f'CAN ch1   : active={st["c1_act"]}  '
                f'state={BUS_STATES.get(st["c1_state"], "?")}',
                f'CAN ch2   : active={st["c2_act"]}  '
                f'state={BUS_STATES.get(st["c2_state"], "?")}',
                '',
                '--- Counters ---',
                f'ch1 RX/TX : {st["c1_rx"]} / {st["c1_tx"]}',
                f'ch2 RX/TX : {st["c2_rx"]} / {st["c2_tx"]}',
                f'ch1 errors: {st["c1_err"]}',
                f'ch2 errors: {st["c2_err"]}',
                f'Dropped   : {st["dropped"]}',
            ]

    elif pkt['msg_type'] == 2:
        j = pkt['extra']
        if j:
            pgn_name = J1939_PGNS.get(j['pgn'], 'unknown PGN')
            da_name  = J1939_ADDRS.get(j['da'], 'specific ECU')
            sa_name  = J1939_ADDRS.get(j['sa'], 'unknown ECU')
            lines += [
                '',
                '--- J1939 Fields ---',
                f'Priority  : {j["priority"]}',
                f'PGN       : 0x{j["pgn"]:05X}  ({pgn_name})',
                f'SA        : 0x{j["sa"]:02X}  ({sa_name})',
                f'DA        : 0x{j["da"]:02X}  ({da_name})',
            ]
        _append_hexdump(lines, pkt['data'])

    elif pkt['msg_type'] == 1:
        _append_hexdump(lines, pkt['data'])

    return '\n'.join(lines)


def _append_hexdump(lines, data):
    if not data:
        return
    lines += ['', f'Data ({len(data)} bytes):']
    for i in range(0, len(data), 16):
        chunk    = data[i:i + 16]
        hex_part = ' '.join(f'{b:02X}' for b in chunk)
        asc_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f'  {i:04X}  {hex_part:<47}  {asc_part}')

# ── GUI ─────────────────────────────────────────────────────────────────────────

class ClogViewer(tk.Tk):
    MAX_ROWS = 5000

    def __init__(self):
        super().__init__()
        self.title('CLOG Viewer — CAN Logger Protocol')
        self.geometry('1280x720')
        self.minsize(800, 480)

        self._q           = queue.Queue()
        self._sock        = None
        self._sniffer     = None   # scapy AsyncSniffer instance
        self._thread      = None
        self._running     = False
        self._pkt_count   = 0
        self._count_by_type = {'STATUS': 0, 'J1939': 0, 'CAN/FD': 0}
        self._all_pkts    = []   # list of (num, pkt, src)

        self._filter_var = tk.StringVar()
        self._port_var   = tk.StringVar(value=str(CLOG_PORT))
        self._bind_var   = tk.StringVar(value='0.0.0.0')
        self._mode_var   = tk.StringVar(value='Npcap' if SCAPY_AVAILABLE else 'UDP')
        self._status_var = tk.StringVar(value='Ready')

        self._build_ui()
        self.after(100, self._poll)
        self.protocol('WM_DELETE_WINDOW', self._on_close)

    # ── UI construction ─────────────────────────────────────────────────────────

    def _build_ui(self):
        self._build_toolbar()
        self._build_paned()
        self._build_statusbar()
        self._configure_tags()

    def _build_toolbar(self):
        bar = ttk.Frame(self, padding=(4, 3))
        bar.pack(fill=tk.X, side=tk.TOP)

        self._btn_start = ttk.Button(bar, text='Start', width=8, command=self._start)
        self._btn_start.pack(side=tk.LEFT, padx=2)

        self._btn_stop = ttk.Button(bar, text='Stop', width=8,
                                    command=self._stop, state=tk.DISABLED)
        self._btn_stop.pack(side=tk.LEFT, padx=2)

        ttk.Button(bar, text='Clear', width=8, command=self._clear).pack(side=tk.LEFT, padx=2)
        ttk.Button(bar, text='Save CSV', command=self._save_csv).pack(side=tk.LEFT, padx=2)

        ttk.Separator(bar, orient=tk.VERTICAL).pack(side=tk.LEFT, padx=8, fill=tk.Y)

        ttk.Label(bar, text='Mode:').pack(side=tk.LEFT)
        mode_values = ['Npcap (bypass firewall)', 'UDP Socket'] if SCAPY_AVAILABLE else ['UDP Socket']
        self._mode_cb = ttk.Combobox(bar, textvariable=self._mode_var,
                                     values=mode_values, width=22, state='readonly')
        self._mode_cb.pack(side=tk.LEFT, padx=2)
        if SCAPY_AVAILABLE:
            self._mode_var.set('Npcap (bypass firewall)')
        else:
            self._mode_var.set('UDP Socket')

        ttk.Separator(bar, orient=tk.VERTICAL).pack(side=tk.LEFT, padx=8, fill=tk.Y)

        self._lbl_bind = ttk.Label(bar, text='Bind IP:')
        self._lbl_bind.pack(side=tk.LEFT)
        self._ent_bind = ttk.Entry(bar, textvariable=self._bind_var, width=14)
        self._ent_bind.pack(side=tk.LEFT, padx=2)
        ttk.Label(bar, text='Port:').pack(side=tk.LEFT, padx=(6, 0))
        ttk.Entry(bar, textvariable=self._port_var, width=7).pack(side=tk.LEFT, padx=2)

        self._mode_var.trace_add('write', lambda *_: self._on_mode_change())
        self._on_mode_change()

        ttk.Separator(bar, orient=tk.VERTICAL).pack(side=tk.LEFT, padx=8, fill=tk.Y)

        ttk.Label(bar, text='Filter:').pack(side=tk.LEFT)
        e = ttk.Entry(bar, textvariable=self._filter_var, width=22)
        e.pack(side=tk.LEFT, padx=2)
        self._filter_var.trace_add('write', lambda *_: self._refilter())
        ttk.Button(bar, text='X', width=2,
                   command=lambda: self._filter_var.set('')).pack(side=tk.LEFT)

    def _build_paned(self):
        paned = ttk.PanedWindow(self, orient=tk.VERTICAL)
        paned.pack(fill=tk.BOTH, expand=True)

        # ── Packet list ──
        top = ttk.Frame(paned)
        paned.add(top, weight=3)

        cols   = ('#', 'Timestamp (s)', 'Ch', 'Type', 'CAN ID', 'DLC', 'Info', 'Seq')
        widths = (50,   160,             40,   75,      110,      45,    560,     65)
        center = {'#', 'Ch', 'DLC', 'Seq'}

        self._tree = ttk.Treeview(top, columns=cols, show='headings', selectmode='browse')
        for col, w in zip(cols, widths):
            self._tree.heading(col, text=col)
            self._tree.column(col, width=w, minwidth=30,
                              anchor=tk.CENTER if col in center else tk.W)

        vsb = ttk.Scrollbar(top, orient=tk.VERTICAL,   command=self._tree.yview)
        hsb = ttk.Scrollbar(top, orient=tk.HORIZONTAL, command=self._tree.xview)
        self._tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        vsb.pack(side=tk.RIGHT,  fill=tk.Y)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)
        self._tree.pack(fill=tk.BOTH, expand=True)
        self._tree.bind('<<TreeviewSelect>>', self._on_select)

        # ── Detail pane ──
        bot = ttk.Frame(paned)
        paned.add(bot, weight=1)

        self._detail = tk.Text(
            bot, font=('Courier New', 10), wrap=tk.NONE,
            state=tk.DISABLED, bg='#1e1e1e', fg='#d4d4d4',
        )
        dvsb = ttk.Scrollbar(bot, orient=tk.VERTICAL,   command=self._detail.yview)
        dhsb = ttk.Scrollbar(bot, orient=tk.HORIZONTAL, command=self._detail.xview)
        self._detail.configure(yscrollcommand=dvsb.set, xscrollcommand=dhsb.set)
        dvsb.pack(side=tk.RIGHT,  fill=tk.Y)
        dhsb.pack(side=tk.BOTTOM, fill=tk.X)
        self._detail.pack(fill=tk.BOTH, expand=True)

    def _build_statusbar(self):
        sb = ttk.Frame(self, relief=tk.SUNKEN, padding=(4, 2))
        sb.pack(fill=tk.X, side=tk.BOTTOM)
        ttk.Label(sb, textvariable=self._status_var, anchor=tk.W).pack(fill=tk.X)

    def _configure_tags(self):
        style = ttk.Style()
        style.theme_use('clam')
        for tag, (bg, fg) in ROW_COLORS.items():
            kw = {}
            if bg: kw['background'] = bg
            if fg: kw['foreground'] = fg
            if kw:
                self._tree.tag_configure(tag, **kw)

    # ── Socket / receive loop ────────────────────────────────────────────────────

    def _on_mode_change(self, *_):
        npcap = 'Npcap' in self._mode_var.get()
        state = tk.DISABLED if npcap else tk.NORMAL
        try:
            self._lbl_bind.config(state=state)
            self._ent_bind.config(state=state)
        except AttributeError:
            pass

    def _start(self):
        try:
            port = int(self._port_var.get())
        except ValueError:
            messagebox.showerror('Error', 'Invalid port number')
            return

        use_npcap = 'Npcap' in self._mode_var.get()

        if use_npcap:
            if not SCAPY_AVAILABLE:
                messagebox.showerror('Npcap not available',
                    'scapy is not installed.\n\n'
                    'Install it with:\n    pip install scapy\n\n'
                    'Also requires Npcap from https://npcap.com\n'
                    '(already present if Wireshark is installed).')
                return
            self._start_npcap(port)
        else:
            self._start_udp(port)

    def _start_udp(self, port):
        bind = self._bind_var.get().strip() or '0.0.0.0'
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except AttributeError:
                pass
            sock.bind((bind, port))
            sock.settimeout(0.5)
        except OSError as e:
            messagebox.showerror('Socket Error',
                f'Cannot bind to {bind}:{port}\n\n{e}')
            return

        self._sock    = sock
        self._running = True
        self._thread  = threading.Thread(target=self._recv_loop_udp, daemon=True)
        self._thread.start()
        self._on_started()

    def _start_npcap(self, port):
        self._running = True
        try:
            self._sniffer = AsyncSniffer(
                filter=f'udp dst port {port}',
                prn=self._on_scapy_pkt,
                store=False,
            )
            self._sniffer.start()
        except Exception as e:
            self._running = False
            messagebox.showerror('Npcap Error',
                f'Could not start Npcap capture:\n\n{e}\n\n'
                'Make sure Npcap is installed (https://npcap.com).\n'
                'Try running as Administrator.')
            return
        self._on_started()

    def _on_started(self):
        self._btn_start.config(state=tk.DISABLED)
        self._btn_stop.config(state=tk.NORMAL)
        self._mode_cb.config(state=tk.DISABLED)
        self._port_var_lock()

    def _stop(self):
        self._running = False
        if self._sock:
            try:    self._sock.close()
            except: pass
            self._sock = None
        if self._sniffer:
            try:    self._sniffer.stop()
            except: pass
            self._sniffer = None
        self._btn_start.config(state=tk.NORMAL)
        self._btn_stop.config(state=tk.DISABLED)
        self._mode_cb.config(state='readonly')
        self._port_var_unlock()

    def _port_var_lock(self):
        for w in self.winfo_children():
            if isinstance(w, ttk.Frame):
                for child in w.winfo_children():
                    if isinstance(child, ttk.Entry):
                        try:
                            child.config(state='readonly')
                        except tk.TclError:
                            pass

    def _port_var_unlock(self):
        for w in self.winfo_children():
            if isinstance(w, ttk.Frame):
                for child in w.winfo_children():
                    if isinstance(child, ttk.Entry):
                        try:
                            child.config(state='normal')
                        except tk.TclError:
                            pass

    def _recv_loop_udp(self):
        while self._running:
            try:
                data, addr = self._sock.recvfrom(8192)
            except socket.timeout:
                continue
            except OSError:
                break
            pkt = parse_packet(data)
            if pkt is None:
                continue
            self._pkt_count += 1
            self._q.put((self._pkt_count, pkt, f'{addr[0]}:{addr[1]}'))

    def _on_scapy_pkt(self, spkt):
        if not self._running:
            return
        if UDP not in spkt or IP not in spkt:
            return
        raw = bytes(spkt[UDP].payload)
        pkt = parse_packet(raw)
        if pkt is None:
            return
        self._pkt_count += 1
        src = f'{spkt[IP].src}:{spkt[UDP].sport}'
        self._q.put((self._pkt_count, pkt, src))

    # ── Queue drain / UI update ──────────────────────────────────────────────────

    def _poll(self):
        batch = 0
        try:
            while batch < 100:
                num, pkt, src = self._q.get_nowait()
                self._all_pkts.append((num, pkt, src))
                if len(self._all_pkts) > self.MAX_ROWS * 2:
                    self._all_pkts = self._all_pkts[-self.MAX_ROWS:]
                t = pkt['msg_type']
                if t == 0:   self._count_by_type['STATUS'] += 1
                elif t == 2: self._count_by_type['J1939']  += 1
                else:        self._count_by_type['CAN/FD'] += 1
                if self._matches_filter(pkt):
                    self._insert_row(num, pkt)
                batch += 1
        except queue.Empty:
            pass

        state = 'Running' if self._running else 'Stopped'
        c     = self._count_by_type
        rows  = len(self._tree.get_children())
        self._status_var.set(
            f'{state}  |  Total: {self._pkt_count}  '
            f'(STATUS: {c["STATUS"]}  J1939: {c["J1939"]}  CAN/FD: {c["CAN/FD"]})  '
            f'|  Showing {rows} rows'
        )
        self.after(100, self._poll)

    def _insert_row(self, num, pkt):
        tag    = row_tag(pkt)
        no_can = pkt['msg_type'] == 0
        values = (
            num,
            f'{pkt["ts_sec"]}.{pkt["ts_nsec"]:09d}',
            pkt['chan_id'],
            fmt_type(pkt),
            fmt_can_id(pkt),
            '—' if no_can else pkt['dlc'],
            fmt_info(pkt),
            '—' if no_can else pkt['seq'],
        )
        self._tree.insert('', tk.END, iid=str(num), values=values, tags=(tag,))

        if self._tree.yview()[1] > 0.95:
            self._tree.yview_moveto(1.0)

        rows = self._tree.get_children()
        if len(rows) > self.MAX_ROWS:
            self._tree.delete(rows[0])

    # ── Detail pane ─────────────────────────────────────────────────────────────

    def _on_select(self, _event=None):
        sel = self._tree.selection()
        if not sel:
            return
        try:
            num = int(sel[0])
        except ValueError:
            return
        for n, pkt, src in reversed(self._all_pkts):
            if n == num:
                text = build_detail(pkt, n, src)
                self._detail.config(state=tk.NORMAL)
                self._detail.delete('1.0', tk.END)
                self._detail.insert(tk.END, text)
                self._detail.config(state=tk.DISABLED)
                return

    # ── Filter ───────────────────────────────────────────────────────────────────

    def _matches_filter(self, pkt):
        f = self._filter_var.get().strip().lower()
        if not f:
            return True
        haystack = (
            fmt_type(pkt) + ' ' +
            fmt_can_id(pkt) + ' ' +
            fmt_info(pkt) + ' ' +
            str(pkt['chan_id'])
        ).lower()
        return f in haystack

    def _refilter(self):
        self._tree.delete(*self._tree.get_children())
        for num, pkt, _ in self._all_pkts:
            if self._matches_filter(pkt):
                self._insert_row(num, pkt)

    # ── Clear / Save ─────────────────────────────────────────────────────────────

    def _clear(self):
        self._tree.delete(*self._tree.get_children())
        self._all_pkts.clear()
        self._pkt_count = 0
        self._count_by_type = {'STATUS': 0, 'J1939': 0, 'CAN/FD': 0}
        self._detail.config(state=tk.NORMAL)
        self._detail.delete('1.0', tk.END)
        self._detail.config(state=tk.DISABLED)

    def _save_csv(self):
        if not self._all_pkts:
            messagebox.showinfo('Save CSV', 'No packets to save.')
            return
        path = filedialog.asksaveasfilename(
            defaultextension='.csv',
            filetypes=[('CSV files', '*.csv'), ('All files', '*.*')],
            title='Save CLOG packets as CSV',
        )
        if not path:
            return
        with open(path, 'w', newline='') as f:
            w = csv.writer(f)
            w.writerow(['#', 'ts_sec', 'ts_nsec', 'channel', 'type', 'can_id_hex',
                        'dlc', 'dlen', 'flags_hex', 'seq', 'data_hex', 'info'])
            for num, pkt, src in self._all_pkts:
                t = pkt['msg_type']
                w.writerow([
                    num,
                    pkt['ts_sec'],
                    pkt['ts_nsec'],
                    pkt['chan_id'],
                    MSG_TYPES.get(t, str(t)),
                    f'0x{pkt["can_id"]:08X}' if t != 0 else '',
                    pkt['dlc']  if t != 0 else '',
                    pkt['dlen'] if t != 0 else '',
                    f'0x{pkt["flags"]:02X}',
                    pkt['seq'],
                    pkt['data'].hex() if pkt['data'] else '',
                    fmt_info(pkt),
                ])
        messagebox.showinfo('Saved',
            f'Saved {len(self._all_pkts)} packets to:\n{path}')

    # ── Lifecycle ────────────────────────────────────────────────────────────────

    def _on_close(self):
        self._stop()
        self.destroy()


if __name__ == '__main__':
    app = ClogViewer()
    app.mainloop()
