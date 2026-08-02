"""J1939 frame utilities — encode/decode PGN ↔ 29-bit CAN ID."""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class J1939Frame:
    """Decoded J1939 frame."""
    pgn:      int          # 18-bit Parameter Group Number
    sa:       int          # Source Address (0x00–0xFE)
    da:       int = 0xFF   # Destination Address (0xFF = broadcast/global)
    priority: int = 6      # Priority 0 (highest) – 7 (lowest)
    data:     bytes = b""  # Payload (0–8 bytes classic, up to 64 FD)

    @property
    def pf(self) -> int:
        return (self.pgn >> 8) & 0xFF

    @property
    def is_pdu2(self) -> bool:
        return self.pf >= 0xF0

    @property
    def can_id(self) -> int:
        return can_id_from_j1939(self.pgn, self.sa, self.da, self.priority)

    def __repr__(self) -> str:
        pgn_name = WELL_KNOWN_PGNS.get(self.pgn, "")
        tag = f" ({pgn_name})" if pgn_name else ""
        return (f"J1939[PGN=0x{self.pgn:05X}{tag} SA=0x{self.sa:02X} "
                f"DA=0x{self.da:02X} prio={self.priority} "
                f"data={self.data.hex()}]")


def pgn_from_can_id(can_id: int) -> tuple:
    """Decode a 29-bit J1939 CAN ID.

    Returns:
        (pgn, sa, da, priority) tuple
    """
    priority = (can_id >> 26) & 0x07
    dp       = (can_id >> 24) & 0x01
    pf       = (can_id >> 16) & 0xFF
    ps       = (can_id >>  8) & 0xFF
    sa       =  can_id        & 0xFF

    if pf >= 0xF0:
        # PDU2: PS is Group Extension, DA is always broadcast
        pgn = (dp << 17) | (pf << 8) | ps
        da  = 0xFF
    else:
        # PDU1: PS is Destination Address
        pgn = (dp << 17) | (pf << 8)
        da  = ps

    return pgn, sa, da, priority


def can_id_from_j1939(pgn: int, sa: int, da: int = 0xFF,
                      priority: int = 6) -> int:
    """Build a 29-bit J1939 CAN ID."""
    dp = (pgn >> 17) & 0x01
    pf = (pgn >>  8) & 0xFF
    if pf < 0xF0:
        ps = da & 0xFF          # PDU1: PS = DA
    else:
        ps = pgn & 0xFF         # PDU2: PS = GE (embedded in PGN)
    return ((priority & 0x7) << 26) | (dp << 24) | (pf << 16) | (ps << 8) | (sa & 0xFF)


def j1939_from_clog(clog_frame) -> Optional[J1939Frame]:
    """Convert a CLOGFrame with msg_type=J1939 into a J1939Frame."""
    from .clog import CLOGType
    if clog_frame.msg_type != CLOGType.J1939:
        return None
    return J1939Frame(
        pgn=clog_frame.pgn,
        sa=clog_frame.sa,
        da=clog_frame.da,
        priority=clog_frame.priority,
        data=clog_frame.data,
    )


WELL_KNOWN_PGNS = {
    0x00FEE0: "Vehicle Distance",
    0x00FEE5: "Electronic Engine Controller 1",
    0x00FEF1: "Cruise Control/Vehicle Speed",
    0x00FEF2: "Fuel Economy",
    0x00FEF7: "Engine Temperature 1",
    0x00FECA: "DM1 - Active Diagnostics",
    0x00FECB: "DM2 - Previously Active Diagnostics",
    0x00FEEB: "Vehicle Electrical Power",
    0x00FF00: "Proprietary B",
    0x00EF00: "Proprietary A",
    0x00EA00: "Request PGN",
    0x00E800: "Acknowledgement",
    0x00EC00: "TP.CM (Transport Protocol Control)",
    0x00EB00: "TP.DT (Transport Protocol Data)",
}
