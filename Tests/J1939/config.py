# config.py — edit this before running any test
#
# Set TRANSPORT = 'tecmp'   to use your Technica Engineering TECMP device.
# Set TRANSPORT = 'can'     to use a USB-CAN adapter with python-can.

TRANSPORT = 'tecmp'   # 'can' | 'tecmp'

# ── CAN adapter ───────────────────────────────────────────────────────────────
# Uncomment the block that matches your hardware.

# Linux SocketCAN (e.g. PCAN, Kvaser or CAN-hat after  ip link set can0 up type can bitrate 250000)
CAN_INTERFACE = 'socketcan'
CAN_CHANNEL   = 'can0'
CAN_BITRATE   = 250_000   # J1939 standard

# Windows / PCAN USB
# CAN_INTERFACE = 'pcan'
# CAN_CHANNEL   = 'PCAN_USBBUS1'
# CAN_BITRATE   = 250_000

# Kvaser
# CAN_INTERFACE = 'kvaser'
# CAN_CHANNEL   = 0
# CAN_BITRATE   = 250_000

# Virtual bus (loopback, no hardware — useful for smoke-testing the scripts)
# CAN_INTERFACE = 'virtual'
# CAN_CHANNEL   = 'vcan0'
# CAN_BITRATE   = 250_000

# ── Gateway ───────────────────────────────────────────────────────────────────
GW_ADDRESS  = 0x80   # gateway ECU source address (set in can_task.cpp)

# ── Tester node ───────────────────────────────────────────────────────────────
# Use 0xFE = "null address" (no address claim needed for simple send/receive)
MY_ADDRESS  = 0xFE

# ── CLOG UDP listener (USB ECM interface on your PC) ─────────────────────────
CLOG_LISTEN_IP   = ''          # '' = all interfaces
CLOG_LISTEN_PORT = 47808       # CLOG_UDP_PORT from clog.h
CLOG_TIMEOUT_S   = 5.0         # seconds to wait for a CLOG frame per test

# ── TECMP device settings (used when TRANSPORT = 'tecmp') ────────────────────
#
# TECMP uses raw Ethernet (EtherType 0x99FE), NOT UDP.
# Requires root / sudo on Linux (raw socket needs CAP_NET_RAW).
#
# Network layout:
#   PC eth0 ──raw Ethernet──  TECMP device  ──CAN bus──  Gateway (Nucleo)
#
# TECMP_INTERFACE  : PC network interface connected to the TECMP device.
#                    Run  ip link  to find the right name.
#
# TECMP_DEVICE_MAC : MAC address printed on the TECMP device label, or visible in
#                    `arp -n` / Wireshark after the device sends its first frame.
#
# TECMP_CM_ID      : Capture Module ID — shown on the device label or web UI.
#
# TECMP_CHANNEL_ID : CAN channel number on the device (the interface ID).
#
TECMP_INTERFACE    = 'enx00e04c13538c'               # ← PC interface facing the TECMP device
TECMP_DEVICE_MAC   = '38:2A:19:80:BA:4F'  # ← TECMP device MAC (fill this in!)
TECMP_CM_ID        = 0x0040               # device CM ID (your device: 0x0040)
TECMP_CHANNEL_ID   = 0x1A                 # CAN channel / interface ID (your device: 0x1a)

# ── Test timeouts ─────────────────────────────────────────────────────────────
BUS_TIMEOUT_S    = 3.0   # seconds to wait for a CAN reply
BOOT_WAIT_S      = 5.0   # seconds to wait after asking user to reboot


# ── Bus factory — used by all test scripts ────────────────────────────────────
def make_bus():
    """Return a CAN bus object matching the configured TRANSPORT."""
    if TRANSPORT == 'tecmp':
        from tecmp_bus import TecmpBusCompat
        return TecmpBusCompat(
            interface  = TECMP_INTERFACE,
            device_mac = TECMP_DEVICE_MAC,
            cm_id      = TECMP_CM_ID,
            channel_id = TECMP_CHANNEL_ID,
        )
    else:
        import can
        return can.Bus(interface=CAN_INTERFACE, channel=CAN_CHANNEL,
                       bitrate=CAN_BITRATE)
