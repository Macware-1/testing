"""GatewayClient — unified entry point for all gateway protocols.

Combines:
  - CANInject: send CAN / J1939 frames via UDP (port 4000)
  - CLOGReceiver: receive CAN / J1939 frames via CLOG UDP (port 47808)
  - StatusReceiver: receive heartbeat via UDP multicast (239.1.2.3:7898)
  - GatewayAPI: HTTP REST API (port 80)

Usage::

    from sdk import GatewayClient

    with GatewayClient("192.168.1.100") as gw:
        # Subscribe to incoming CAN frames
        gw.clog.on_frame = lambda f: print(f)

        # Send a raw CAN frame
        gw.send_can(0x123, b"\\x01\\x02\\x03")

        # Send a J1939 frame
        gw.send_j1939(pgn=0xFEF1, sa=0x00, data=b"\\xFF\\xFF\\x00\\x00\\xFF\\xFF\\xFF\\xFF")

        # Query device info via HTTP
        print(gw.api.get_info())
"""

from .protocols.can_inject import CANInject, CANFrame
from .protocols.clog import CLOGReceiver, CLOGFrame
from .protocols.status import StatusReceiver, StatusFrame
from .protocols.j1939 import J1939Frame, can_id_from_j1939, j1939_from_clog
from .http.api import GatewayAPI


class GatewayClient:
    """All-in-one gateway client.

    Args:
        host: IP address of the gateway (e.g. "192.168.1.100")
        inject_port: UDP port for CAN inject (default 4000)
        clog_port: UDP port for CLOG receiver (default 47808)
        status_port: UDP port for status heartbeat (default 7898)
        http_port: TCP port for HTTP API (default 80)
        listen_ip: Local IP to bind receivers (default "0.0.0.0")
    """

    def __init__(self, host: str,
                 inject_port: int = 4000,
                 clog_port: int = 47808,
                 status_port: int = 7898,
                 http_port: int = 80,
                 listen_ip: str = "0.0.0.0"):
        self._host = host
        self.inject = CANInject(host=host, port=inject_port)
        self.clog   = CLOGReceiver(listen_ip=listen_ip, port=clog_port)
        self.status = StatusReceiver(listen_ip=listen_ip, port=status_port)
        self.api    = GatewayAPI(host=host, port=http_port)

    # ── Lifecycle ────────────────────────────────────────────────────────────────

    def open(self) -> None:
        """Open all transports and start receiver threads."""
        self.inject.open()
        self.clog.start()
        self.status.start()

    def close(self) -> None:
        """Stop receivers and close all sockets."""
        self.clog.stop()
        self.status.stop()
        self.inject.close()
        self.api.close()

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, *_):
        self.close()

    # ── CAN TX shortcuts ─────────────────────────────────────────────────────────

    def send_can(self, can_id: int, data: bytes, channel: int = 0,
                 extended: bool = False) -> None:
        """Send a raw CAN frame via UDP inject.

        Args:
            can_id: CAN identifier (11-bit standard or 29-bit extended)
            data:   Payload bytes (up to 8 for classic, 64 for FD)
            channel: 0=FDCAN1, 1=FDCAN2
            extended: True for 29-bit extended ID
        """
        self.inject.send_raw(can_id=can_id, data=data, channel=channel,
                             extended=extended)

    def send_j1939(self, pgn: int, sa: int, data: bytes,
                   da: int = 0xFF, priority: int = 6,
                   channel: int = 0) -> None:
        """Send a J1939 frame via UDP inject.

        Args:
            pgn:      Parameter Group Number (18-bit)
            sa:       Source Address (0x00–0xFE)
            data:     J1939 payload bytes (0–8)
            da:       Destination Address (0xFF = broadcast)
            priority: J1939 priority 0–7 (default 6)
            channel:  0=FDCAN1, 1=FDCAN2
        """
        self.inject.send_j1939(pgn=pgn, sa=sa, data=data, da=da,
                               priority=priority, channel=channel)

    def send_j1939_frame(self, frame: J1939Frame, channel: int = 0) -> None:
        """Send a J1939Frame object via UDP inject."""
        self.inject.send_j1939(
            pgn=frame.pgn, sa=frame.sa, data=frame.data,
            da=frame.da, priority=frame.priority, channel=channel,
        )

    # ── Status shortcuts ─────────────────────────────────────────────────────────

    @property
    def last_status(self) -> StatusFrame | None:
        """Most recently received gateway status heartbeat."""
        return self.status.last

    @property
    def host(self) -> str:
        return self._host
