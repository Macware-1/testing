"""Gateway status heartbeat — UDP multicast 239.1.2.3:7898, 20-byte payload.

Wire format (mixed endianness):
  0     msg_type  (0x01 = heartbeat)
  1     dev_id
  2     proto_ver
  3     flags
  4-7   uptime_s  (uint32, little-endian)
  8-11  ip_addr   (IPv4, network byte order / big-endian)
 12-15  free_heap (uint32, little-endian)
 16-17  task_count (uint16, little-endian)
 18-19  reserved
"""

import socket
import struct
import threading
from dataclasses import dataclass
from typing import Callable, List, Optional

STATUS_UDP_PORT  = 7898
STATUS_MCAST_IP  = "239.1.2.3"
STATUS_MSG_TYPE  = 0x01

# Mixed endian: '<BBBB' then '<I' uptime, then 4B BE ip, then '<IH2s'
_FMT = struct.Struct("<BBBBII2H2s")  # 20 bytes


def _parse_ip(addr_ne: int) -> str:
    return socket.inet_ntoa(struct.pack("!I", addr_ne))


@dataclass
class StatusFrame:
    msg_type:   int
    dev_id:     int
    proto_ver:  int
    flags:      int
    uptime_s:   int
    ip_addr:    str
    free_heap:  int
    task_count: int

    def __repr__(self) -> str:
        return (f"StatusFrame(ip={self.ip_addr} uptime={self.uptime_s}s "
                f"heap={self.free_heap}B tasks={self.task_count})")


def _parse(raw: bytes) -> Optional[StatusFrame]:
    if len(raw) < 20:
        return None
    msg_type, dev_id, proto_ver, flags = struct.unpack_from("<BBBB", raw, 0)
    uptime_s  = struct.unpack_from("<I", raw, 4)[0]
    ip_ne     = struct.unpack_from("!I", raw, 8)[0]
    free_heap = struct.unpack_from("<I", raw, 12)[0]
    task_count= struct.unpack_from("<H", raw, 16)[0]
    return StatusFrame(
        msg_type=msg_type,
        dev_id=dev_id,
        proto_ver=proto_ver,
        flags=flags,
        uptime_s=uptime_s,
        ip_addr=_parse_ip(ip_ne),
        free_heap=free_heap,
        task_count=task_count,
    )


class StatusReceiver:
    """Receive gateway heartbeat packets from UDP multicast 239.1.2.3:7898.

    Usage::

        rx = StatusReceiver()
        rx.on_frame = lambda f: print(f)
        rx.start()
        ...
        rx.stop()
    """

    def __init__(self, listen_ip: str = "0.0.0.0", port: int = STATUS_UDP_PORT,
                 mcast_group: str = STATUS_MCAST_IP):
        self._listen_ip = listen_ip
        self._port = port
        self._mcast_group = mcast_group
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._last: Optional[StatusFrame] = None
        self._lock = threading.Lock()

        self.on_frame: Optional[Callable[[StatusFrame], None]] = None

    def start(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("", self._port))
        mreq = socket.inet_aton(self._mcast_group) + socket.inet_aton(self._listen_ip)
        self._sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        self._sock.settimeout(0.5)
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        if self._sock:
            self._sock.close()
        if self._thread:
            self._thread.join(timeout=2.0)

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *_):
        self.stop()

    @property
    def last(self) -> Optional[StatusFrame]:
        with self._lock:
            return self._last

    def _loop(self) -> None:
        while self._running:
            try:
                raw, _ = self._sock.recvfrom(64)
            except socket.timeout:
                continue
            except OSError:
                break
            frame = _parse(raw)
            if frame is None:
                continue
            with self._lock:
                self._last = frame
            if self.on_frame:
                try:
                    self.on_frame(frame)
                except Exception:
                    pass
