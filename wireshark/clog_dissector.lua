-- ═══════════════════════════════════════════════════════════════════════════
-- clog_dissector.lua  —  Wireshark dissector for CAN Logger Protocol (CLOG)
-- Protocol version 2  (also decodes legacy v1 frames)
-- ═══════════════════════════════════════════════════════════════════════════
--
-- ── INSTALLATION ────────────────────────────────────────────────────────────
--
--   1. Copy this file to your Wireshark plugins directory:
--        Linux   : ~/.config/wireshark/plugins/
--        macOS   : ~/.config/wireshark/plugins/   (or ~/Library/Application Support/Wireshark/plugins/)
--        Windows : %APPDATA%\Wireshark\plugins\
--
--   2. Load the plugin (no restart required):
--        Wireshark menu → Analyze → Reload Lua Plugins   (Ctrl+Shift+L)
--      — OR —
--        Restart Wireshark.
--
--   3. Verify: Help → About Wireshark → Plugins tab → look for "clog_dissector"
--
-- ── CAPTURE ─────────────────────────────────────────────────────────────────
--
--   Capture filter (BPF — set before starting capture):
--     udp port 47808
--
--   To capture alongside J1939 EtherType traffic:
--     udp port 47808 or ether proto 0x88b5
--
-- ── DISPLAY FILTERS ─────────────────────────────────────────────────────────
--
--   clog                            all CLOG frames (any version/type)
--   clog.type == 0                  Status / heartbeat frames
--   clog.type == 1                  Raw CAN frames
--   clog.type == 2                  J1939 frames
--   clog.channel == 1               Channel 1 only
--   clog.flags.ext == 1             29-bit extended ID frames
--   clog.flags.fd  == 1             CAN FD frames
--   clog.flags.brs == 1             CAN FD with Bit-Rate Switch
--   clog.can_id == 0x18feef00       Specific 29-bit CAN ID
--   clog.can_id == 0x7df             Specific 11-bit CAN ID
--   clog.j1939.pgn == 0xf004        J1939 EEC1 (Engine Speed)
--   clog.j1939.sa  == 0             J1939 Engine ECU (SA=0)
--   clog.j1939.pgn == 0xfeca        J1939 DM1 (Active DTCs)
--   clog.status.can1_state == 3     Gateway reporting CAN ch1 bus-off
--   clog.status.eth_up == 1         Ethernet link is up
--   clog.seq > 1000                 Later in a session
--   !clog.flags.fd                  Classic CAN frames only
--
-- ── SUGGESTED COLOR RULES ───────────────────────────────────────────────────
--   Go to View → Coloring Rules → + (add each rule):
--
--   Name              Filter                   Fg      Bg
--   ──────────────    ─────────────────────    ──────  ───────
--   CLOG Status       clog.type == 0           #e2e8f0 #0f4c81
--   CLOG J1939        clog.type == 2           #000000 #d4edda
--   CLOG FD+BRS       clog.flags.brs == 1      #000000 #fff3cd
--   CLOG FD           clog.flags.fd == 1       #000000 #cce5ff
--   CLOG Bus-off      clog.status.can1_state==3 or clog.status.can2_state==3
--                                              #ffffff #dc3545
--   CLOG Malformed    clog.expert               #ffffff #990000
--
-- ── PROTOCOL SUMMARY ────────────────────────────────────────────────────────
--
-- Common header (28 bytes, all versions ≥2):
--  [0]  4  Magic "CLOG" (0x43 4C 4F 47)
--  [4]  1  Version
--  [5]  1  Message Type  0=Status  1=RawCAN  2=J1939
--  [6]  1  Channel ID    (logging_id from gateway config)
--  [7]  1  Flags         bit0=FD  bit1=BRS  bit2=ESI  bit3=EXT  bit4=RTR
--  [8]  4  Sequence      (big-endian, per-channel monotonic)
-- [12]  4  Timestamp sec  (big-endian, PTP TAI)
-- [16]  4  Timestamp nsec (big-endian)
-- [20]  4  CAN ID         (big-endian, raw 11- or 29-bit)
-- [24]  1  DLC            (0-15)
-- [25]  3  Reserved
--
-- Status payload  [28]:
--  [28]  1  Status flags   bit0=ETH_UP  bit1=CAN1_ACTIVE  bit2=CAN2_ACTIVE  bit3=PTP_LOCKED
--  [29]  1  ch1 bus state  0=OK  1=Warn  2=Passive  3=Bus-off
--  [30]  1  ch2 bus state
--  [31]  1  FW major / [32] FW minor
--  [33]  3  Reserved
--  [36]  4  Uptime seconds
--  [40]  4  ch1 RX count  [44] ch2 RX count
--  [48]  4  ch1 TX count  [52] ch2 TX count
--  [56]  4  ch1 errors    [60] ch2 errors
--  [64]  4  Dropped frames
--
-- J1939 payload  [28]:
--  [28]  1  Priority (0-7)
--  [29]  1  SA  (Source Address)
--  [30]  1  DA  (Destination Address, 0xFF=broadcast)
--  [31]  1  Reserved
--  [32]  4  PGN (big-endian, 18-bit in lower 18 bits)
--  [36]  n  J1939 data  (n = dlc_to_len(DLC), max 64)
-- ═══════════════════════════════════════════════════════════════════════════

-- ── Protocol object ──────────────────────────────────────────────────────────
local clog = Proto("CLOG", "CAN Logger Protocol (CLOG)")

-- ── Preferences ──────────────────────────────────────────────────────────────
clog.prefs.udp_port = Pref.uint("UDP Port", 47808,
    "UDP destination port used by the CAN gateway. Reload plugins after changing.")

-- ── Lookup tables ─────────────────────────────────────────────────────────────
local MSG_TYPE_NAMES = {
    [0] = "Status",
    [1] = "Raw CAN",
    [2] = "J1939",
    [3] = "Event",
}

local BUS_STATE_NAMES = {
    [0] = "OK (Error Active)",
    [1] = "Warning",
    [2] = "Error Passive",
    [3] = "Bus-Off",
}

-- ISO 11898-1:2015 Table 5
local DLC_TO_LEN = {
    [0]=0,  [1]=1,  [2]=2,  [3]=3,
    [4]=4,  [5]=5,  [6]=6,  [7]=7,
    [8]=8,  [9]=12, [10]=16,[11]=20,
    [12]=24,[13]=32,[14]=48,[15]=64,
}

-- SAE J1939 well-known PGNs (PGN value in hex → description)
local J1939_PGNS = {
    [0x0000] = "TSC1 — Torque/Speed Control 1",
    [0x0100] = "TC1 — Transmission Control 1",
    [0xEE00] = "AC — Address Claimed",
    [0xEF00] = "CA — Cannot Claim Address",
    [0xF001] = "ETC2 — Electronic Transmission Controller 2",
    [0xF003] = "EEC2 — Electronic Engine Controller 2",
    [0xF004] = "EEC1 — Electronic Engine Controller 1",
    [0xF005] = "EEC3 — Electronic Engine Controller 3",
    [0xF009] = "EBC2 — Electronic Brake Controller 2",
    [0xFEC1] = "HOURS — Engine Hours / Revolutions",
    [0xFECA] = "DM1 — Active Diagnostic Trouble Codes",
    [0xFECB] = "DM2 — Previously Active DTCs",
    [0xFECC] = "DM3 — Diagnostic Data Clear / Reset",
    [0xFED5] = "DM11 — Diagnostic Data Clear / Reset",
    [0xFEE0] = "VD — Vehicle Distance",
    [0xFEE3] = "AIR1 — Aftertreatment 1 Air Control",
    [0xFEE9] = "LFC — Fuel Consumption (Liquid)",
    [0xFEEA] = "VW — Vehicle Weight",
    [0xFEEC] = "EI — Engine Information",
    [0xFEEE] = "ET1 — Engine Temperature 1",
    [0xFEF0] = "LFC2 — Fuel Economy (Liquid)",
    [0xFEF1] = "CCVS — Cruise Control / Vehicle Speed 1",
    [0xFEF2] = "LFE — Fuel Economy (Liquid)",
    [0xFEF5] = "AMBC — Ambient Conditions",
    [0xFEF6] = "IC1 — Inlet/Exhaust Conditions 1",
    [0xFEF7] = "VEP1 — Vehicle Electrical Power 1",
    [0xFEF8] = "TF — Transmission Fluids",
    [0xFEF9] = "EI2 — Engine Information 2",
    [0xFEFC] = "DD — Dash Display",
    [0xFEFD] = "A1 — Auxiliary Analog Information 1",
}

-- SAE J1939 well-known source addresses
local J1939_ADDRESSES = {
    [0x00] = "Engine #1",
    [0x01] = "Engine #2",
    [0x03] = "Transmission #1",
    [0x04] = "Transmission #2",
    [0x0B] = "Brakes — System Controller",
    [0x11] = "Brakes — Trailer #1",
    [0x17] = "Instrument Cluster #1",
    [0x21] = "Body Controller",
    [0x27] = "Cab Controller — Primary",
    [0x28] = "Cab Controller — Secondary",
    [0x33] = "Body-to-Vehicle Interface Control",
    [0x3D] = "Suspension — Steer Axle",
    [0x80] = "Gateway (this device)",
    [0xFE] = "Null Address",
    [0xFF] = "Global / Broadcast",
}

-- ── ProtoField declarations ───────────────────────────────────────────────────
local PF = ProtoField

-- Common header
local f_magic     = PF.string ("clog.magic",    "Magic",         base.ASCII)
local f_version   = PF.uint8  ("clog.version",  "Version",       base.DEC)
local f_msg_type  = PF.uint8  ("clog.type",     "Message Type",  base.DEC)
local f_chan_id   = PF.uint8  ("clog.channel",  "Channel ID",    base.DEC)
local f_flags     = PF.uint8  ("clog.flags",    "CAN Flags",     base.HEX)
local f_flag_fd   = PF.bool   ("clog.flags.fd",  "CAN FD Frame",         8, {"Yes","No"}, 0x01)
local f_flag_brs  = PF.bool   ("clog.flags.brs", "Bit-Rate Switching",   8, {"Yes","No"}, 0x02)
local f_flag_esi  = PF.bool   ("clog.flags.esi", "Error State Indicator",8, {"Yes","No"}, 0x04)
local f_flag_ext  = PF.bool   ("clog.flags.ext", "Extended ID (29-bit)", 8, {"Yes","No"}, 0x08)
local f_flag_rtr  = PF.bool   ("clog.flags.rtr", "Remote Frame (RTR)",   8, {"Yes","No"}, 0x10)
local f_seq       = PF.uint32 ("clog.seq",      "Sequence Number",  base.DEC)
local f_ts_sec    = PF.uint32 ("clog.ts_sec",   "Timestamp Sec",    base.DEC)
local f_ts_nsec   = PF.uint32 ("clog.ts_nsec",  "Timestamp NSec",   base.DEC)
local f_can_id    = PF.uint32 ("clog.can_id",   "CAN ID",           base.HEX)
local f_dlc       = PF.uint8  ("clog.dlc",      "DLC",              base.DEC)

-- Raw CAN payload
local f_raw_data  = PF.bytes  ("clog.raw.data", "CAN Data")

-- J1939 payload
local f_j1_prio   = PF.uint8  ("clog.j1939.priority", "J1939 Priority", base.DEC)
local f_j1_sa     = PF.uint8  ("clog.j1939.sa",       "Source Address", base.HEX)
local f_j1_da     = PF.uint8  ("clog.j1939.da",       "Destination Address", base.HEX)
local f_j1_pgn    = PF.uint32 ("clog.j1939.pgn",      "PGN",            base.HEX)
local f_j1_data   = PF.bytes  ("clog.j1939.data",     "J1939 Data")

-- Status payload
local f_st_flags  = PF.uint8  ("clog.status.flags",      "Status Flags",       base.HEX)
local f_st_eth    = PF.bool   ("clog.status.eth_up",     "Ethernet Link Up",   8, {"Yes","No"}, 0x01)
local f_st_c1act  = PF.bool   ("clog.status.can1_active","CAN ch1 Active",     8, {"Yes","No"}, 0x02)
local f_st_c2act  = PF.bool   ("clog.status.can2_active","CAN ch2 Active",     8, {"Yes","No"}, 0x04)
local f_st_ptp    = PF.bool   ("clog.status.ptp_locked", "PTP Synchronized",   8, {"Yes","No"}, 0x08)
local f_st_c1bus  = PF.uint8  ("clog.status.can1_state", "ch1 Bus State",      base.DEC)
local f_st_c2bus  = PF.uint8  ("clog.status.can2_state", "ch2 Bus State",      base.DEC)
local f_st_fwmaj  = PF.uint8  ("clog.status.fw_major",   "FW Major Version",   base.DEC)
local f_st_fwmin  = PF.uint8  ("clog.status.fw_minor",   "FW Minor Version",   base.DEC)
local f_st_upt    = PF.uint32 ("clog.status.uptime",     "Uptime (seconds)",   base.DEC)
local f_st_c1rx   = PF.uint32 ("clog.status.ch1_rx",     "ch1 RX Frames",      base.DEC)
local f_st_c2rx   = PF.uint32 ("clog.status.ch2_rx",     "ch2 RX Frames",      base.DEC)
local f_st_c1tx   = PF.uint32 ("clog.status.ch1_tx",     "ch1 TX Frames",      base.DEC)
local f_st_c2tx   = PF.uint32 ("clog.status.ch2_tx",     "ch2 TX Frames",      base.DEC)
local f_st_c1err  = PF.uint32 ("clog.status.ch1_errors", "ch1 Error Frames",   base.DEC)
local f_st_c2err  = PF.uint32 ("clog.status.ch2_errors", "ch2 Error Frames",   base.DEC)
local f_st_drop   = PF.uint32 ("clog.status.dropped",    "Dropped Frames",     base.DEC)

clog.fields = {
    -- common
    f_magic, f_version, f_msg_type, f_chan_id,
    f_flags, f_flag_fd, f_flag_brs, f_flag_esi, f_flag_ext, f_flag_rtr,
    f_seq, f_ts_sec, f_ts_nsec, f_can_id, f_dlc,
    -- raw CAN
    f_raw_data,
    -- J1939
    f_j1_prio, f_j1_sa, f_j1_da, f_j1_pgn, f_j1_data,
    -- status
    f_st_flags, f_st_eth, f_st_c1act, f_st_c2act, f_st_ptp,
    f_st_c1bus, f_st_c2bus, f_st_fwmaj, f_st_fwmin,
    f_st_upt, f_st_c1rx, f_st_c2rx, f_st_c1tx, f_st_c2tx,
    f_st_c1err, f_st_c2err, f_st_drop,
}

-- ── Expert info ───────────────────────────────────────────────────────────────
local EI = ProtoExpert.new
local ef_bad_magic   = EI("clog.bad_magic",    "Bad magic — not a CLOG frame",           expert.group.MALFORMED,  expert.severity.ERROR)
local ef_short_hdr   = EI("clog.short_header", "Header shorter than 28 bytes",           expert.group.MALFORMED,  expert.severity.ERROR)
local ef_truncated   = EI("clog.truncated",    "Payload shorter than DLC declares",      expert.group.MALFORMED,  expert.severity.ERROR)
local ef_bad_version = EI("clog.bad_version",  "Unknown version (expected 1 or 2)",      expert.group.ASSUMPTION, expert.severity.WARN)
local ef_bad_type    = EI("clog.bad_type",     "Unknown message type",                   expert.group.ASSUMPTION, expert.severity.WARN)
local ef_rsv_flags   = EI("clog.rsv_flags",    "Reserved flag bits are set (must be 0)", expert.group.ASSUMPTION, expert.severity.NOTE)
local ef_bus_off     = EI("clog.bus_off",      "CAN bus in Bus-Off state",               expert.group.SEQUENCE,   expert.severity.ERROR)
clog.experts = { ef_bad_magic, ef_short_hdr, ef_truncated, ef_bad_version,
                 ef_bad_type, ef_rsv_flags, ef_bus_off }

-- ── Constants ──────────────────────────────────────────────────────────────────
local MAGIC   = "\x43\x4C\x4F\x47"   -- "CLOG"
local HDR_V1  = 24
local HDR_V2  = 28
local FL_RSV  = 0xE0  -- flag bits [7:5]

-- ── Helpers ───────────────────────────────────────────────────────────────────
local function dlc_to_len(dlc)
    return DLC_TO_LEN[dlc] or 0
end

local function pgn_name(pgn)
    local n = J1939_PGNS[pgn]
    return n and string.format("0x%05X  [%s]", pgn, n)
              or string.format("0x%05X", pgn)
end

local function addr_name(addr)
    local n = J1939_ADDRESSES[addr]
    return n and string.format("0x%02X  (%s)", addr, n)
              or string.format("0x%02X", addr)
end

local function bus_state_str(v)
    return BUS_STATE_NAMES[v] or string.format("Unknown (%d)", v)
end

-- Format seconds + nanoseconds as a readable timestamp string
local function fmt_ts(sec, nsec)
    return string.format("%u.%09u s", sec, nsec)
end

-- ── Main dissector ────────────────────────────────────────────────────────────
function clog.dissector(tvb, pinfo, tree)
    local pkt_len = tvb:len()

    if pkt_len < 4 then return 0 end
    if tvb(0,4):string() ~= MAGIC then return 0 end

    pinfo.cols.protocol:set("CLOG")

    -- ── Minimum header check ──────────────────────────────────────────────────
    local version = (pkt_len >= 5) and tvb(4,1):uint() or 0
    local hdr_len = (version == 1) and HDR_V1 or HDR_V2

    if pkt_len < hdr_len then
        local t = tree:add(clog, tvb(), "CAN Logger Protocol  [TRUNCATED HEADER]")
        t:add_proto_expert_info(ef_short_hdr)
        pinfo.cols.info:set("[Truncated CLOG header]")
        return pkt_len
    end

    -- ── Parse common header fields ────────────────────────────────────────────
    -- v1: no msg_type field (treat all as RawCAN)
    local msg_type, chan_id, flags, dlc, seq, ts_sec, ts_nsec, can_id

    if version == 1 then
        -- Legacy v1 layout (24 bytes): magic version chan_id flags dlc seq ts_sec ts_nsec can_id
        msg_type = 1  -- always Raw CAN
        chan_id  = tvb(5,1):uint()
        flags    = tvb(6,1):uint()
        dlc      = tvb(7,1):uint()
        seq      = tvb(8,4):uint()
        ts_sec   = tvb(12,4):uint()
        ts_nsec  = tvb(16,4):uint()
        can_id   = tvb(20,4):uint()
    else
        -- v2 layout (28 bytes)
        msg_type = tvb(5,1):uint()
        chan_id  = tvb(6,1):uint()
        flags    = tvb(7,1):uint()
        seq      = tvb(8,4):uint()
        ts_sec   = tvb(12,4):uint()
        ts_nsec  = tvb(16,4):uint()
        can_id   = tvb(20,4):uint()
        dlc      = tvb(24,1):uint()
    end

    -- Flag decoding
    local is_fd  = bit.band(flags, 0x01) ~= 0
    local is_brs = bit.band(flags, 0x02) ~= 0
    local is_ext = bit.band(flags, 0x08) ~= 0
    local is_rtr = bit.band(flags, 0x10) ~= 0
    local has_rsv= bit.band(flags, FL_RSV) ~= 0
    local dlen   = dlc_to_len(dlc)

    -- ── Info column ───────────────────────────────────────────────────────────
    local id_str   = is_ext and string.format("%08X", can_id) or string.format("%03X", can_id)
    local type_str = MSG_TYPE_NAMES[msg_type] or string.format("Type%d", msg_type)
    local frm_str

    if msg_type == 0 then  -- Status
        frm_str = string.format("Ch%-3d  STATUS  seq=%d  uptime=?", chan_id, seq)
    elseif msg_type == 1 then  -- Raw CAN
        local kind = is_fd and (is_brs and "FD+BRS" or "FD") or (is_rtr and "RTR" or "CAN")
        frm_str = string.format("Ch%-3d  %-6s  [%s]  DLC=%d (%dB)  seq=%d",
                                chan_id, kind, id_str, dlc, dlen, seq)
    elseif msg_type == 3 then  -- Event (same wire layout as Raw CAN)
        local kind = is_fd and (is_brs and "FD+BRS" or "FD") or (is_rtr and "RTR" or "CAN")
        frm_str = string.format("Ch%-3d  EVENT/%-5s [%s]  DLC=%d (%dB)  seq=%d",
                                chan_id, kind, id_str, dlc, dlen, seq)
    elseif msg_type == 2 then  -- J1939
        frm_str = string.format("Ch%-3d  J1939   [%s]  DLC=%d (%dB)  seq=%d",
                                chan_id, id_str, dlc, dlen, seq)
    else
        frm_str = string.format("Ch%-3d  %s  seq=%d", chan_id, type_str, seq)
    end
    pinfo.cols.info:set(frm_str)

    -- ── Build protocol tree ───────────────────────────────────────────────────
    local root = tree:add(clog, tvb(), "CAN Logger Protocol  " .. frm_str)

    -- Magic
    root:add(f_magic, tvb(0,4), tvb(0,4):string())

    -- Version
    local vi = root:add(f_version, tvb(4,1), version)
    if version ~= 1 and version ~= 2 then
        vi:add_proto_expert_info(ef_bad_version,
            string.format("Dissector supports v1 and v2, got v%d", version))
    end

    -- v2-only fields in common header
    if version >= 2 then
        local mti = root:add(f_msg_type, tvb(5,1), msg_type)
        mti:append_text(string.format("  (%s)", type_str))
        if msg_type > 3 then mti:add_proto_expert_info(ef_bad_type) end
    end

    -- Channel ID
    root:add(f_chan_id, tvb(6 - (version == 1 and 1 or 0), 1), chan_id)
        :append_text(string.format("  (logging_id = %d)", chan_id))

    -- Flags
    if msg_type ~= 0 then  -- Status frames don't carry CAN flags
        local foff = (version == 1) and 6 or 7
        local ftree = root:add(f_flags, tvb(foff,1), flags)
        ftree:add(f_flag_fd,  tvb(foff,1))
        ftree:add(f_flag_brs, tvb(foff,1))
        ftree:add(f_flag_esi, tvb(foff,1))
        ftree:add(f_flag_ext, tvb(foff,1))
        ftree:add(f_flag_rtr, tvb(foff,1))
        if has_rsv then
            ftree:add_proto_expert_info(ef_rsv_flags)
        end
    end

    -- Sequence number
    root:add(f_seq, tvb(8,4), seq)

    -- Timestamp
    local ts_tree = root:add(clog, tvb(12,8),
        string.format("Timestamp: %s  (PTP TAI)", fmt_ts(ts_sec, ts_nsec)))
    ts_tree:add(f_ts_sec,  tvb(12,4), ts_sec)
    ts_tree:add(f_ts_nsec, tvb(16,4), ts_nsec)

    -- CAN ID and DLC (not shown for Status)
    if msg_type ~= 0 then
        local id_label = is_ext
            and string.format("CAN ID: 0x%08X  (29-bit extended)", can_id)
            or  string.format("CAN ID: 0x%03X  (11-bit standard)", can_id)
        root:add(f_can_id, tvb(20,4), can_id):set_text(id_label)

        local dlc_off = (version == 1) and 7 or 24
        root:add(f_dlc, tvb(dlc_off,1), dlc)
            :append_text(string.format("  →  %d byte%s", dlen, dlen ~= 1 and "s" or ""))
    end

    -- ── Type-specific payload ─────────────────────────────────────────────────
    local pl_off = hdr_len  -- payload starts after common header

    if msg_type == 0 then
        ---------------------------------------------------------------------------
        -- STATUS payload  (40 bytes at pl_off)
        ---------------------------------------------------------------------------
        if pkt_len < pl_off + 40 then
            root:add_proto_expert_info(ef_truncated,
                string.format("Status payload needs 40 bytes, got %d", pkt_len - pl_off))
            return pkt_len
        end

        local st_flags  = tvb(pl_off+0, 1):uint()
        local c1_state  = tvb(pl_off+1, 1):uint()
        local c2_state  = tvb(pl_off+2, 1):uint()
        local fw_maj    = tvb(pl_off+3, 1):uint()
        local fw_min    = tvb(pl_off+4, 1):uint()
        local uptime    = tvb(pl_off+8, 4):uint()
        local c1rx      = tvb(pl_off+12,4):uint()
        local c2rx      = tvb(pl_off+16,4):uint()
        local c1tx      = tvb(pl_off+20,4):uint()
        local c2tx      = tvb(pl_off+24,4):uint()
        local c1err     = tvb(pl_off+28,4):uint()
        local c2err     = tvb(pl_off+32,4):uint()
        local dropped   = tvb(pl_off+36,4):uint()

        -- Update info column now that we have uptime
        pinfo.cols.info:set(string.format(
            "Ch%-3d  STATUS  v%d.%d  up=%ds  c1:%s  c2:%s  seq=%d",
            chan_id, fw_maj, fw_min, uptime,
            bus_state_str(c1_state), bus_state_str(c2_state), seq))

        local st = root:add(clog, tvb(pl_off, 40),
            string.format("Gateway Status  FW v%d.%d  Uptime %ds", fw_maj, fw_min, uptime))

        local sf = st:add(f_st_flags, tvb(pl_off,1), st_flags)
        sf:add(f_st_eth,   tvb(pl_off,1))
        sf:add(f_st_c1act, tvb(pl_off,1))
        sf:add(f_st_c2act, tvb(pl_off,1))
        sf:add(f_st_ptp,   tvb(pl_off,1))

        st:add(f_st_c1bus, tvb(pl_off+1,1), c1_state)
            :append_text(string.format("  (%s)", bus_state_str(c1_state)))
        st:add(f_st_c2bus, tvb(pl_off+2,1), c2_state)
            :append_text(string.format("  (%s)", bus_state_str(c2_state)))

        if c1_state == 3 or c2_state == 3 then
            st:add_proto_expert_info(ef_bus_off,
                "One or both CAN channels are in Bus-Off state")
        end

        st:add(f_st_fwmaj, tvb(pl_off+3,1), fw_maj)
        st:add(f_st_fwmin, tvb(pl_off+4,1), fw_min)
        st:add(f_st_upt,   tvb(pl_off+8, 4), uptime)

        local ctr = st:add(clog, tvb(pl_off+12,24), "Frame Counters")
        ctr:add(f_st_c1rx,  tvb(pl_off+12,4), c1rx)
        ctr:add(f_st_c2rx,  tvb(pl_off+16,4), c2rx)
        ctr:add(f_st_c1tx,  tvb(pl_off+20,4), c1tx)
        ctr:add(f_st_c2tx,  tvb(pl_off+24,4), c2tx)

        local etr = st:add(clog, tvb(pl_off+28,12), "Error Counters")
        etr:add(f_st_c1err, tvb(pl_off+28,4), c1err)
        etr:add(f_st_c2err, tvb(pl_off+32,4), c2err)
        etr:add(f_st_drop,  tvb(pl_off+36,4), dropped)

    elseif msg_type == 1 or msg_type == 3 then
        ---------------------------------------------------------------------------
        -- RAW CAN / EVENT payload  (identical wire layout, 0-64 data bytes)
        ---------------------------------------------------------------------------
        if dlen > 0 then
            if pkt_len < pl_off + dlen then
                root:add_proto_expert_info(ef_truncated,
                    string.format("Expected %d data bytes, packet has %d",
                                  dlen, pkt_len - pl_off))
                if pkt_len > pl_off then
                    root:add(f_raw_data, tvb(pl_off, pkt_len - pl_off))
                        :append_text("  [truncated]")
                end
            else
                root:add(f_raw_data, tvb(pl_off, dlen))
            end
        elseif is_rtr then
            root:add(clog, tvb(pl_off, 0), "(RTR — no data payload)")
        end

    elseif msg_type == 2 then
        ---------------------------------------------------------------------------
        -- J1939 payload  (8-byte routing header + 0-64 data bytes)
        ---------------------------------------------------------------------------
        local j1_hdr = 8
        if pkt_len < pl_off + j1_hdr then
            root:add_proto_expert_info(ef_truncated, "J1939 routing header truncated")
            return pkt_len
        end

        local prio = tvb(pl_off+0, 1):uint()
        local sa   = tvb(pl_off+1, 1):uint()
        local da   = tvb(pl_off+2, 1):uint()
        local pgn  = tvb(pl_off+4, 4):uint()

        -- Update info column with J1939-specific info
        pinfo.cols.info:set(string.format(
            "Ch%-3d  J1939  PGN=%s  SA=%s  DA=%s  seq=%d",
            chan_id, pgn_name(pgn), addr_name(sa), addr_name(da), seq))

        local j1 = root:add(clog, tvb(pl_off, j1_hdr + dlen),
            string.format("J1939  PGN=%s", pgn_name(pgn)))

        j1:add(f_j1_prio, tvb(pl_off+0,1), prio)
            :append_text(string.format("  (priority %d)", prio))
        j1:add(f_j1_sa,   tvb(pl_off+1,1), sa)
            :append_text(string.format("  — %s", J1939_ADDRESSES[sa] or "unknown ECU"))
        j1:add(f_j1_da,   tvb(pl_off+2,1), da)
            :append_text(string.format("  — %s", J1939_ADDRESSES[da] or "specific ECU"))
        j1:add(f_j1_pgn,  tvb(pl_off+4,4), pgn)
            :set_text(string.format("PGN: %s", pgn_name(pgn)))

        -- J1939 data
        local data_off = pl_off + j1_hdr
        if dlen > 0 then
            if pkt_len < data_off + dlen then
                j1:add_proto_expert_info(ef_truncated,
                    string.format("Expected %d J1939 data bytes, got %d",
                                  dlen, pkt_len - data_off))
                if pkt_len > data_off then
                    j1:add(f_j1_data, tvb(data_off, pkt_len - data_off))
                        :append_text("  [truncated]")
                end
            else
                j1:add(f_j1_data, tvb(data_off, dlen))
            end
        end

    else
        ---------------------------------------------------------------------------
        -- Unknown type
        ---------------------------------------------------------------------------
        root:add_proto_expert_info(ef_bad_type,
            string.format("Unknown message type 0x%02X", msg_type))
    end

    return pkt_len
end

-- ── Port registration with live preference update ─────────────────────────────
local udp_table  = DissectorTable.get("udp.port")
local bound_port = clog.prefs.udp_port

udp_table:add(bound_port, clog)

function clog.prefs_changed()
    local new_port = clog.prefs.udp_port
    if new_port ~= bound_port then
        udp_table:remove(bound_port, clog)
        udp_table:add(new_port, clog)
        bound_port = new_port
    end
end
