-- gw_status_dissector.lua  —  Wireshark dissector for CAN-ETH Gateway Status heartbeat
--
-- Protocol : UDP port 7898, 20-byte payload, sent every 1 second by status_task.cpp
--
-- Wire layout (all multi-byte fields little-endian EXCEPT ip_addr which lwIP
-- stores in network byte order):
--
--   Offset  Size  Field
--     0      1    msg_type   0x01 = heartbeat
--     1      1    dev_id
--     2      1    proto_ver
--     3      1    flags      (reserved, always 0)
--     4      4    uptime_s   seconds since boot          (little-endian)
--     8      4    ip_addr    device IPv4                 (network byte order)
--    12      4    free_heap  FreeRTOS heap free bytes    (little-endian)
--    16      2    task_count number of running tasks     (little-endian)
--    18      2    reserved
--
-- ── INSTALLATION ──────────────────────────────────────────────────────────────
--   Copy to ~/.config/wireshark/plugins/
--   Then press Ctrl+Shift+L in Wireshark to reload (no restart needed).
--
-- ── DISPLAY FILTERS ──────────────────────────────────────────────────────────
--   gwstat                     all gateway status frames
--   gwstat.msg_type == 0x01    heartbeat frames
--   gwstat.uptime > 60         device has been up more than 1 minute
--   gwstat.free_heap < 10000   low heap warning
--   gwstat.task_count > 8      more tasks than expected
-- ─────────────────────────────────────────────────────────────────────────────

local gwstat = Proto("gwstat", "CAN-ETH Gateway Status")

-- ── Field declarations ────────────────────────────────────────────────────────
local PF = ProtoField

local f_msg_type   = PF.uint8 ("gwstat.msg_type",   "Message Type",    base.HEX)
local f_dev_id     = PF.uint8 ("gwstat.dev_id",     "Device ID",       base.HEX)
local f_proto_ver  = PF.uint8 ("gwstat.proto_ver",  "Protocol Version",base.DEC)
local f_flags      = PF.uint8 ("gwstat.flags",      "Flags",           base.HEX)
local f_uptime     = PF.uint32("gwstat.uptime",     "Uptime (s)",      base.DEC)
local f_ip_addr    = PF.ipv4  ("gwstat.ip_addr",    "Device IP")
local f_free_heap  = PF.uint32("gwstat.free_heap",  "Free Heap (bytes)",base.DEC)
local f_task_count = PF.uint16("gwstat.task_count", "Task Count",      base.DEC)

gwstat.fields = {
    f_msg_type, f_dev_id, f_proto_ver, f_flags,
    f_uptime, f_ip_addr, f_free_heap, f_task_count,
}

-- ── Expert info ───────────────────────────────────────────────────────────────
local ef_short = ProtoExpert.new("gwstat.short", "Packet shorter than 20 bytes",
                                 expert.group.MALFORMED, expert.severity.ERROR)
local ef_heap  = ProtoExpert.new("gwstat.low_heap", "Free heap below 8 KB — possible OOM risk",
                                 expert.group.SEQUENCE, expert.severity.WARN)

gwstat.experts = { ef_short, ef_heap }

-- ── Helpers ───────────────────────────────────────────────────────────────────
local MSG_TYPE_NAMES = { [0x01] = "Heartbeat" }

local function fmt_uptime(s)
    local d = math.floor(s / 86400)
    local h = math.floor((s % 86400) / 3600)
    local m = math.floor((s % 3600) / 60)
    local sc = s % 60
    if d > 0 then
        return string.format("%dd %02dh %02dm %02ds", d, h, m, sc)
    elseif h > 0 then
        return string.format("%dh %02dm %02ds", h, m, sc)
    else
        return string.format("%dm %02ds", m, sc)
    end
end

-- ── Dissector ─────────────────────────────────────────────────────────────────
function gwstat.dissector(tvb, pinfo, tree)
    local pkt_len = tvb:len()

    if pkt_len < 20 then
        pinfo.cols.protocol:set("GW-STAT")
        local t = tree:add(gwstat, tvb(), "CAN-ETH Gateway Status [TRUNCATED]")
        t:add_proto_expert_info(ef_short,
            string.format("Expected 20 bytes, got %d", pkt_len))
        return pkt_len
    end

    pinfo.cols.protocol:set("GW-STAT")

    -- Read fields (uptime/heap/tasks are little-endian on Cortex-M7)
    local msg_type  = tvb(0,1):uint()
    local dev_id    = tvb(1,1):uint()
    local proto_ver = tvb(2,1):uint()
    local uptime    = tvb(4,4):le_uint()   -- little-endian
    local free_heap = tvb(12,4):le_uint()  -- little-endian
    local task_cnt  = tvb(16,2):le_uint()  -- little-endian
    -- ip_addr at tvb(8,4) is network byte order — handled directly by PF.ipv4

    local type_str = MSG_TYPE_NAMES[msg_type] or string.format("0x%02X", msg_type)

    -- Info column
    pinfo.cols.info:set(string.format(
        "%s  up=%s  heap=%d B  tasks=%d",
        type_str, fmt_uptime(uptime), free_heap, task_cnt))

    -- Protocol tree root
    local root = tree:add(gwstat, tvb(),
        string.format("CAN-ETH Gateway Status  [%s  up=%s]", type_str, fmt_uptime(uptime)))

    root:add(f_msg_type,  tvb(0,1)):append_text(string.format("  (%s)", type_str))
    root:add(f_dev_id,    tvb(1,1))
    root:add(f_proto_ver, tvb(2,1)):append_text(string.format("  (v%d)", proto_ver))
    root:add(f_flags,     tvb(3,1))

    -- Pass decoded value explicitly so Wireshark renders little-endian correctly
    root:add(f_uptime,    tvb(4,4),  uptime)
        :append_text(string.format("  (%s)", fmt_uptime(uptime)))

    -- ip_addr: lwIP stores in network byte order → PF.ipv4 reads it directly
    root:add(f_ip_addr,   tvb(8,4))

    local heap_item = root:add(f_free_heap, tvb(12,4), free_heap)
    if free_heap < 8192 then
        heap_item:add_proto_expert_info(ef_heap,
            string.format("Only %d bytes free", free_heap))
    end

    root:add(f_task_count, tvb(16,2), task_cnt)

    return 20
end

-- ── Register on UDP port 7898 ─────────────────────────────────────────────────
DissectorTable.get("udp.port"):add(7898, gwstat)
