# config.py — j1939_sim settings

# Gateway Ethernet address
GW_IP   = '121.145.35.64'
GW_PORT = 4000          # UDP inject port

# Source addresses for the two simulated ECUs
SIM_SA_1 = 0x00   # Primary   ECU — engine management (address 0x00 is typical engine controller)
SIM_SA_2 = 0x27   # Secondary ECU — transmission/drivetrain (0x27 is a common secondary address)

# Legacy alias kept for backwards compatibility
SIM_SA = SIM_SA_1

# How often to update each PGN (seconds)
INTERVAL_FAST  = 0.10   # EEC1, EEC2, CCVS  — 100 ms
INTERVAL_SLOW  = 1.00   # ET1, DD1, VEP1    — 1 s

# Engine drive cycle timing (seconds per phase)
PHASE_IDLE   = 3.0
PHASE_ACCEL  = 8.0
PHASE_CRUISE = 10.0
PHASE_DECEL  = 6.0
