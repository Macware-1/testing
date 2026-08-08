# Windows Port — CAN-ETH Gateway Tools

All PC-side tools communicate with the gateway **over Ethernet only**:

- **Inject CAN frames** → UDP port 4000 on the gateway
- **Receive CAN data** → CLOG UDP port 47808 from the gateway
- **Web UI / config** → HTTP on port 80

No USB-CAN adapter, no special drivers, no Linux-specific code.
Python + a network cable is all that's needed.

---

## What's here

| File | Purpose |
|---|---|
| `requirements.txt` | Python dependencies (PyQt5, requests, pyqtgraph) |
| `run_tests.bat` | Double-click to run the J1939 UDP loopback test suite |
| `run_validation.bat` | Double-click to launch the PyQt5 validation GUI |
| `build_exe.bat` | Build standalone `.exe` files (no Python needed on target) |
| `dist/` | Output folder created by `build_exe.bat` |

---

## Quick start

### 1 — Prerequisites

1. **Python 3.10+** — <https://www.python.org/> → tick **"Add to PATH"**
2. **Connect PC to the gateway** over an Ethernet cable (same subnet)
3. Check / update the gateway IP in the config file that matches what you're running:

| Tool | Config file |
|---|---|
| J1939 tests | `Tests\J1939\udp_loopback\config.py` → `GW_IP` |
| Validation GUI | `validation\j1939\config.py` → `GW_IP` |

Default gateway IP is `121.145.35.64` — change if yours differs.

---

### 2 — J1939 hardware tests (UDP loopback)

```
Double-click:  windows\run_tests.bat
```

Or from a command prompt:
```cmd
cd Tests\J1939\udp_loopback
python run_all.py
```

Runs all 5 J1939 protocol tests (address claim, PGN request, broadcast PGN,
transport protocol, DM1 diagnostics) entirely over UDP — no CAN adapter on the PC.

Hardware required on the **gateway side** only:
- FDCAN1 ↔ FDCAN2 loopback cable with 120 Ω termination at each end

---

### 3 — Validation GUI (PyQt5)

```
Double-click:  windows\run_validation.bat
```

The script auto-installs PyQt5, pyqtgraph, and requests on first run.

---

### 4 — Individual tools (no install needed)

All scripts in `Tests\testing\` work directly on Windows:

```cmd
:: Send a CAN frame to the gateway
python Tests\testing\can_tx.py --ip 121.145.35.64 --id 0x18FF0080 --ext --j1939 --data DEADBEEF

:: Listen for CLOG frames from the gateway
python Tests\testing\clog_sniff.py

:: Run a CAN loopback test (inject on FDCAN2, receive echo on FDCAN1)
python Tests\testing\can_loopback.py
```

---

## Build standalone `.exe` files

To distribute to a Windows PC that does **not** have Python installed:

```
Double-click:  windows\build_exe.bat
```

Produces:

| File | Description |
|---|---|
| `windows\dist\run_j1939_tests.exe` | J1939 test suite (console) |
| `windows\dist\gateway_demo.exe` | Validation GUI (windowed) |

The `.exe` files bundle Python and all dependencies. Only a network connection
to the gateway is required on the target machine.
