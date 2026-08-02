"""HTTP REST API wrapper for the CAN-ETH Gateway.

All endpoints are on port 80. GET requests return JSON; POST requests
accept JSON bodies. Binary config download uses application/octet-stream.

Available endpoints:
  GET  /api/info              — firmware version, device info
  GET  /api/telemetry         — J1939 telemetry data
  GET  /api/dtc               — active diagnostic trouble codes (DM1)
  GET  /api/nodes             — discovered J1939 nodes
  GET  /api/can/filters       — active CAN receive filters
  GET  /api/can/mode          — current CAN mode (normal / listen-only)
  GET  /api/can/config        — CAN bit-rate, FD config
  GET  /api/config/values     — full config blob (binary, octet-stream)
  GET  /api/radxa             — Radxa co-processor status
  POST /api/send/can          — inject a CAN frame via HTTP
  POST /api/sendconfig        — write new config blob
  POST /api/radxa/wifi        — configure Radxa WiFi credentials
  POST /api/radxa/reboot      — reboot Radxa co-processor
"""

import struct
from typing import Any, Dict, List, Optional

import requests


class GatewayAPI:
    """HTTP client for the CAN-ETH Gateway REST API."""

    def __init__(self, host: str, port: int = 80, timeout: float = 5.0):
        self._base = f"http://{host}:{port}"
        self._timeout = timeout
        self._session = requests.Session()

    def close(self) -> None:
        self._session.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    # ── GET helpers ──────────────────────────────────────────────────────────────

    def _get(self, path: str, **params) -> Any:
        r = self._session.get(
            self._base + path, params=params or None, timeout=self._timeout
        )
        r.raise_for_status()
        return r.json()

    def _get_binary(self, path: str) -> bytes:
        r = self._session.get(self._base + path, timeout=self._timeout)
        r.raise_for_status()
        return r.content

    def _post(self, path: str, body: Any) -> Any:
        r = self._session.post(
            self._base + path, json=body, timeout=self._timeout
        )
        r.raise_for_status()
        return r.json()

    # ── Device info ──────────────────────────────────────────────────────────────

    def get_info(self) -> Dict:
        """Return firmware version and board info."""
        return self._get("/api/info")

    # ── Telemetry & J1939 ────────────────────────────────────────────────────────

    def get_telemetry(self) -> Dict:
        """Return live J1939 telemetry (speed, engine temp, etc.)."""
        return self._get("/api/telemetry")

    def get_dtc(self) -> Dict:
        """Return DM1 active diagnostic trouble codes."""
        return self._get("/api/dtc")

    def get_nodes(self) -> Dict:
        """Return list of discovered J1939 nodes."""
        return self._get("/api/nodes")

    # ── CAN configuration ────────────────────────────────────────────────────────

    def get_can_filters(self) -> Dict:
        """Return active CAN receive filters."""
        return self._get("/api/can/filters")

    def get_can_mode(self) -> Dict:
        """Return current CAN operating mode."""
        return self._get("/api/can/mode")

    def get_can_config(self) -> Dict:
        """Return CAN bit-rate and FD configuration."""
        return self._get("/api/can/config")

    def set_can_filter(self, filter_id: int, mask: int, id_: int,
                       extended: bool = False) -> Dict:
        """Set a CAN acceptance filter."""
        return self._get(
            "/api/can/filter/set",
            id=filter_id, mask=mask, can_id=id_, ext=int(extended)
        )

    def clear_can_filter(self, filter_id: int) -> Dict:
        """Clear a specific CAN acceptance filter."""
        return self._get("/api/can/filter/clear", id=filter_id)

    def clear_all_can_filters(self) -> Dict:
        """Clear all CAN acceptance filters (accept everything)."""
        return self._get("/api/can/filter/clear_all")

    # ── CAN send via HTTP ────────────────────────────────────────────────────────

    def send_can(self, can_id: int, data: bytes, extended: bool = False,
                 channel: int = 0) -> Dict:
        """Inject a CAN frame via HTTP POST /api/send/can.

        Args:
            can_id: CAN identifier (11 or 29 bit)
            data:   Payload bytes (up to 8 for classic CAN)
            extended: True for 29-bit extended ID
            channel: 0=FDCAN1, 1=FDCAN2
        """
        return self._post("/api/send/can", {
            "id":       can_id,
            "data":     list(data),
            "extended": extended,
            "channel":  channel,
        })

    def send_j1939(self, pgn: int, sa: int, data: bytes,
                   da: int = 0xFF, priority: int = 6,
                   channel: int = 0) -> Dict:
        """Inject a J1939 frame via HTTP (builds CAN ID internally).

        Args:
            pgn:      Parameter Group Number (18-bit)
            sa:       Source Address
            data:     J1939 payload bytes (0-8)
            da:       Destination Address (0xFF = broadcast)
            priority: J1939 priority 0-7
            channel:  0=FDCAN1, 1=FDCAN2
        """
        from ..protocols.j1939 import can_id_from_j1939
        can_id = can_id_from_j1939(pgn, sa, da, priority)
        return self._post("/api/send/can", {
            "id":       can_id,
            "data":     list(data),
            "extended": True,
            "channel":  channel,
            "j1939":    True,
        })

    # ── Configuration ────────────────────────────────────────────────────────────

    def get_config_blob(self) -> bytes:
        """Download the full binary configuration blob."""
        return self._get_binary("/api/config/values")

    def send_config_blob(self, blob: bytes) -> Dict:
        """Upload a binary configuration blob."""
        r = self._session.post(
            self._base + "/api/sendconfig",
            data=blob,
            headers={"Content-Type": "application/octet-stream"},
            timeout=self._timeout,
        )
        r.raise_for_status()
        return r.json()

    # ── Radxa co-processor ───────────────────────────────────────────────────────

    def get_radxa_status(self) -> Dict:
        """Return Radxa co-processor status (alive, wifi, forwarding)."""
        return self._get("/api/radxa")

    def set_radxa_wifi(self, ssid: str, password: str) -> Dict:
        """Configure Radxa WiFi credentials."""
        return self._post("/api/radxa/wifi", {"ssid": ssid, "password": password})

    def reboot_radxa(self) -> Dict:
        """Reboot the Radxa co-processor."""
        return self._post("/api/radxa/reboot", {})

    # ── Bootloader ───────────────────────────────────────────────────────────────

    def enter_bootloader(self) -> Dict:
        """Trigger firmware update via bootloader jump."""
        return self._get("/api/bootloader")
