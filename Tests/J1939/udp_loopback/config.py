# config.py — edit before running udp_loopback tests
#
# Physical setup
# ──────────────
# Connect FDCAN1 transceiver ↔ FDCAN2 transceiver (H-to-H, L-to-L).
# Add a 120 Ω termination resistor at each transceiver end.
#
# FDCAN1 pins: PD0 (RX), PD1 (TX)   — J1939 mode, processes received frames
# FDCAN2 pins: PB12 (RX), PB6 (TX)  — raw mode, used as loopback RX channel
#
# Data flow
# ─────────
# TX (inject):
#   udp_inject.py → UDP port 4000, channel=1 (FDCAN2 TX)
#   → physical bus → FDCAN1 RX → J1939 library → CLOG ch1 (TYPE_J1939)
#
# Gateway responses (address claim, PGN replies):
#   Gateway FDCAN1 TX → physical bus → FDCAN2 RX → CLOG ch2 (TYPE_RAW_CAN)
#
# Gateway firmware settings (via web UI):
#   can.j1939          = 1        J1939 mode on FDCAN1
#   can.fd_mode        = 0        classic CAN (J1939 standard)
#   logging.ch1.enabled = 1
#   logging.ch1.target  = 0       0=ETH or 1=USB ECM (use whichever is connected)
#   logging.ch2.enabled = 1
#   logging.ch2.target  = 0       same interface as ch1

GW_IP = '121.145.35.64'   # gateway Ethernet IP  (adjust if different)

# J1939 ECU source addresses
GW_ADDRESS   = 0x80   # gateway address (from can_task.cpp, GW_ECU_ADDRESS)
MY_ADDRESS   = 0xFE   # tester null address (no address claim needed)
TP_SENDER_SA = 0x01   # SA used for transport-protocol and DM1 tests

# UDP inject channel
#   0 = FDCAN1 TX  (frame goes straight out; FDCAN1 will NOT receive its own TX)
#   1 = FDCAN2 TX  (frame → bus → FDCAN1 RX → J1939 lib)  ← correct for J1939 tests
INJECT_CHANNEL = 1

# CLOG reception
CLOG_PORT      = 47808
CLOG_TIMEOUT_S = 5.0    # seconds to wait for a CLOG frame per test

# Boot wait used by test_01 (address claim)
BOOT_WAIT_S = 6.0
