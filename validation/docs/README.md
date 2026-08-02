# CAN-ETH Gateway Python SDK

Python SDK for the STM32H755 CAN-to-Ethernet gateway.  Supports all four
transport paths: UDP CAN inject (TX), CLOG v2 stream (RX), status heartbeat,
and the HTTP REST API.

---

## Quick Start

```bash
cd validation/
pip install -r requirements.txt

# Run the GUI demo
python demo/main.py

# Or use the SDK directly from a script
python - <<'EOF'
from sdk import GatewayClient

with GatewayClient("192.168.1.100") as gw:
    gw.clog.on_frame = lambda f: print(f)

    # Send a raw CAN frame on FDCAN1
    gw.send_can(0x123, b"\x01\x02\x03\x04", extended=False)

    # Send a J1939 broadcast
    gw.send_j1939(pgn=0xFEF1, sa=0x00,
                  data=b"\xFF\xFF\x00\x00\xFF\xFF\xFF\xFF")

    import time; time.sleep(5)   # let CLOG frames arrive
EOF
```

---

## Package Layout

```
validation/
├── requirements.txt          # Python dependencies
├── sdk/
│   ├── __init__.py           # exports GatewayClient
│   ├── client.py             # GatewayClient — unified entry point
│   ├── protocols/
│   │   ├── can_inject.py     # CAN TX  (UDP port 4000)
│   │   ├── clog.py           # CAN RX  (UDP port 47808, CLOG v2)
│   │   ├── status.py         # Heartbeat (UDP multicast 239.1.2.3:7898)
│   │   └── j1939.py          # J1939 PGN utilities
│   └── http/
│       └── api.py            # HTTP REST API wrapper (port 80)
├── demo/
│   └── main.py               # PyQt5 GUI application
└── docs/
    └── README.md             # this file
```

---

## GatewayClient

`GatewayClient` is the single object that owns all transports.

```python
from sdk import GatewayClient

gw = GatewayClient(
    host="192.168.1.100",    # gateway IP
    inject_port=4000,        # UDP CAN inject port (default)
    clog_port=47808,         # CLOG receive port (default)
    status_port=7898,        # status heartbeat port (default)
    http_port=80,            # HTTP API port (default)
    listen_ip="0.0.0.0",     # local bind address
)
gw.open()   # or use as context manager: with GatewayClient(...) as gw:
...
gw.close()
```

### CAN TX

```python
# Standard 11-bit frame
gw.send_can(0x123, b"\xDE\xAD\xBE\xEF")

# Extended 29-bit frame on FDCAN2
gw.send_can(0x18FF0000, b"\x01\x02", extended=True, channel=1)
```

### J1939 TX

```python
# Broadcast engine speed PGN on FDCAN1
gw.send_j1939(
    pgn=0xFEF1,          # Cruise Control / Vehicle Speed
    sa=0x00,             # Source Address
    data=b"\xFF\xFF\x00\x00\xFF\xFF\xFF\xFF",
    da=0xFF,             # 0xFF = global broadcast
    priority=6,
    channel=0,
)

# Or build a J1939Frame and pass it directly
from sdk.protocols.j1939 import J1939Frame
frame = J1939Frame(pgn=0xFECA, sa=0x01, data=b"\x00" * 8)
gw.send_j1939_frame(frame)
```

### CAN RX (CLOG)

CLOG frames arrive asynchronously on a background thread.

```python
from sdk.protocols.clog import CLOGType

def on_frame(f):
    if f.msg_type == CLOGType.RAW_CAN:
        print(f"CAN  id=0x{f.can_id:08X} data={f.data.hex()}")
    elif f.msg_type == CLOGType.J1939:
        print(f"J1939 PGN=0x{f.pgn:05X} SA=0x{f.sa:02X} data={f.data.hex()}")
    elif f.msg_type == CLOGType.STATUS:
        print(f"Gateway uptime={f.uptime_sec}s ch1_rx={f.ch1_rx}")

gw.clog.on_frame = on_frame

# Or poll the internal buffer
import time; time.sleep(1)
frames = gw.clog.get_frames(clear=True)
```

### Status Heartbeat

Sent by the gateway every 1 second to UDP multicast 239.1.2.3:7898.

```python
gw.status.on_frame = lambda s: print(f"IP={s.ip_addr} uptime={s.uptime_s}s")

# Or read the most recent frame directly
s = gw.last_status
if s:
    print(f"Free heap: {s.free_heap} bytes")
```

### HTTP REST API

```python
# Device info
info = gw.api.get_info()

# J1939 telemetry
tel = gw.api.get_telemetry()

# Active diagnostic trouble codes (DM1)
dtc = gw.api.get_dtc()

# Send a CAN frame via HTTP (alternative to UDP inject)
gw.api.send_can(0x123, b"\x01\x02\x03", extended=False)

# Configure Radxa WiFi
gw.api.set_radxa_wifi("MySSID", "MyPassword")

# Download configuration blob
blob = gw.api.get_config_blob()
```

---

## Protocol Reference

### CAN Inject (UDP port 4000)

| Offset | Size | Field       | Description                        |
|--------|------|-------------|------------------------------------|
| 0      | 1    | Magic       | 0xCA                               |
| 1      | 1    | Channel     | 0 = FDCAN1, 1 = FDCAN2             |
| 2      | 1    | Flags       | see flags table below              |
| 3      | 1    | DataLen     | payload length 0–64                |
| 4–7    | 4    | CAN ID      | uint32 little-endian               |
| 8+     | 0–64 | Payload     | CAN data bytes                     |

**Flags:**

| Bit | Name   | Meaning                          |
|-----|--------|----------------------------------|
| 0   | EXT    | 29-bit extended identifier       |
| 1   | J1939  | J1939 routing (informational)    |
| 2   | FD     | CAN FD frame                     |
| 3   | BRS    | Bit-rate switch (FD only)        |

### CLOG v2 (UDP port 47808, big-endian)

**Common Header (28 bytes):**

| Offset | Size | Field       | Description                         |
|--------|------|-------------|-------------------------------------|
| 0–3    | 4    | Magic       | "CLOG" (0x43 0x4C 0x4F 0x47)        |
| 4      | 1    | Version     | 2                                   |
| 5      | 1    | Msg type    | 0=STATUS, 1=RAW_CAN, 2=J1939        |
| 6      | 1    | Channel ID  | logging channel 0–255               |
| 7      | 1    | Flags       | FD/BRS/ESI/EXT/RTR                  |
| 8–11   | 4    | Sequence    | per-channel counter (BE)            |
| 12–15  | 4    | TS seconds  | PTP TAI (BE)                        |
| 16–19  | 4    | TS nanosec  | PTP nanoseconds (BE)                |
| 20–23  | 4    | CAN ID      | 29-bit ID (BE); 0 for STATUS        |
| 24     | 1    | DLC         | CAN DLC 0–15                        |
| 25–27  | 3    | Reserved    | 0                                   |

**Type 0 STATUS payload (40 bytes @ offset 28):**

| Offset | Field         | Description                              |
|--------|---------------|------------------------------------------|
| 28     | status_flags  | ETH_UP / CAN1_ACTIVE / CAN2_ACTIVE / PTP_LOCKED |
| 29     | can1_state    | OK/WARNING/PASSIVE/BUS_OFF               |
| 30     | can2_state    | same                                     |
| 31     | fw_major      |                                          |
| 32     | fw_minor      |                                          |
| 36–39  | uptime_sec    | BE uint32                                |
| 40–67  | counters      | ch1/ch2 rx/tx/error, dropped (BE uint32) |

**Type 2 J1939 payload (8-byte routing header @ offset 28 + data):**

| Offset | Field     | Description                                |
|--------|-----------|--------------------------------------------|
| 28     | priority  | J1939 priority 0–7                         |
| 29     | sa        | Source Address                             |
| 30     | da        | Destination Address (0xFF = broadcast)     |
| 31     | reserved  | 0                                          |
| 32–35  | pgn       | 18-bit PGN in lower bits (BE uint32)       |
| 36+    | data      | CAN payload, length = DLC_to_len(dlc)      |

### Status Heartbeat (UDP multicast 239.1.2.3:7898, 20 bytes)

| Offset | Size | Endian | Field      |
|--------|------|--------|------------|
| 0      | 1    | —      | msg_type (0x01) |
| 1      | 1    | —      | dev_id    |
| 2      | 1    | —      | proto_ver |
| 3      | 1    | —      | flags     |
| 4–7    | 4    | LE     | uptime_s  |
| 8–11   | 4    | BE/NBO | ip_addr   |
| 12–15  | 4    | LE     | free_heap |
| 16–17  | 2    | LE     | task_count|
| 18–19  | 2    | —      | reserved  |

---

## Running Tests

```bash
cd validation/
# Install deps
pip install -r requirements.txt

# Quick smoke test (no hardware needed)
python -c "
from sdk.protocols.j1939 import pgn_from_can_id, can_id_from_j1939

# Round-trip J1939 ID encode/decode
pgn, sa, da, prio = pgn_from_can_id(0x18FEF100)
assert pgn == 0xFEF1, f'got {pgn:#07x}'
assert sa == 0x00
print('J1939 codec OK')

# CLOG parse
from sdk.protocols.clog import _parse
import struct
hdr = struct.pack('>4sBBBBIIIIB3s',
    b'CLOG', 2, 1, 0, 0x08, 1, 0, 0, 0x123, 3, b'\\x00\\x00\\x00')
frame = _parse(hdr + b'\\xDE\\xAD\\xBE')
assert frame.can_id == 0x123
assert frame.data == b'\\xDE\\xAD\\xBE'
print('CLOG parse OK')
"
```
