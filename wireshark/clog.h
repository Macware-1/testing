// clog.h — CAN Logger Protocol (CLOG) v2  wire-format definition
//
// Transport : UDP unicast or broadcast, default port 47808.
// Byte order : all multi-byte fields big-endian on the wire.
//
// ═══════════════════════════════════════════════════════════════════════════════
//  COMMON HEADER  (28 bytes, every message type)
// ═══════════════════════════════════════════════════════════════════════════════
//
//  Offset  Size  Field
//    0      4    Magic  0x43 0x4C 0x4F 0x47  ("CLOG")
//    4      1    Version  = 2
//    5      1    Message Type  (CLOG_TYPE_*)
//    6      1    Channel ID    (logging_id from gateway config, 0–255)
//    7      1    Flags         (CLOG_FLAG_*  — CAN frame flags, 0 for Status)
//    8      4    Sequence      per-channel monotonic counter, wraps at 2³²
//   12      4    Timestamp sec   PTP TAI hardware clock, big-endian
//   16      4    Timestamp nsec  PTP nanoseconds, big-endian
//   20      4    CAN ID          raw 11- or 29-bit ID, big-endian; 0 for Status
//   24      1    DLC             CAN data-length code 0–15; 0 for Status
//   25      3    Reserved        must be 0
//   28            ↓  type-specific payload starts here
//
// ═══════════════════════════════════════════════════════════════════════════════
//  TYPE 0x00  STATUS  (gateway heartbeat, 40-byte payload → 68-byte frame)
// ═══════════════════════════════════════════════════════════════════════════════
//
//  Offset  Size  Field
//   28      1    Status flags  (CLOG_ST_*)
//   29      1    CAN ch1 bus state  (CLOG_BUS_*)
//   30      1    CAN ch2 bus state
//   31      1    FW version major
//   32      1    FW version minor
//   33      3    Reserved
//   36      4    Uptime seconds                (big-endian)
//   40      4    ch1 RX frame count since boot (big-endian)
//   44      4    ch2 RX frame count since boot
//   48      4    ch1 TX frame count
//   52      4    ch2 TX frame count
//   56      4    ch1 error frame count
//   60      4    ch2 error frame count
//   64      4    Dropped frames  (TX ring full / pbuf alloc failures)
//   Total payload: 40 bytes  →  total frame: 68 bytes
//
// ═══════════════════════════════════════════════════════════════════════════════
//  TYPE 0x01  RAW CAN  (pass-through CAN frame, 0–64 byte payload)
// ═══════════════════════════════════════════════════════════════════════════════
//
//  Offset  Size  Field
//   28    0–64   CAN data  (length = clog_dlc_to_len(DLC))
//   Total frame: 28–92 bytes
//
// ═══════════════════════════════════════════════════════════════════════════════
//  TYPE 0x02  J1939   (decoded J1939 routing + data, 8-byte payload header)
// ═══════════════════════════════════════════════════════════════════════════════
//
//  Offset  Size  Field
//   28      1    Priority        bits [2:0], upper bits 0 (range 0–7)
//   29      1    Source Address  (SA, 0x00–0xFF)
//   30      1    Destination Address  (DA; 0xFF = broadcast / PDU2 global)
//   31      1    Reserved
//   32      4    PGN  big-endian, 18-bit value in lower 18 bits
//                     PDU2 (PF≥240): PGN = (DP<<17)|(PF<<8)|GE
//                     PDU1 (PF<240): PGN = (DP<<17)|(PF<<8)  (DA in header above)
//   36    0–8    J1939 data  (standard CAN payload, length from DLC)
//                For CAN FD J1939-22 frames DLC may indicate >8 bytes.
//   Total frame: 36–100 bytes (J1939 classic is always ≤44 bytes)
//
// ═══════════════════════════════════════════════════════════════════════════════
//  TYPE 0x03  EVENT   (filter-rule-triggered event frame)
// ═══════════════════════════════════════════════════════════════════════════════
//
//  Generated when a received CAN frame matches a filter rule with ACTION_EVENT.
//  The channel_id field carries the event_logging_id configured for that rule,
//  allowing the host to distinguish different event sources by channel_id.
//
//  Payload layout is identical to TYPE 0x01 (RAW CAN):
//   28    0–64   CAN data  (length = clog_dlc_to_len(DLC))
//   Total frame: 28–92 bytes
//
// ═══════════════════════════════════════════════════════════════════════════════
//  VERSION HISTORY
//    v1 (24-byte header): version=1, no msg_type, raw CAN only (deprecated)
//    v2 (28-byte header): version=2, msg_type discriminator, status + J1939 + event
// ═══════════════════════════════════════════════════════════════════════════════

#pragma once
#include <cstdint>
#include <cstddef>

// ── Protocol constants ────────────────────────────────────────────────────────
static constexpr uint8_t  CLOG_MAGIC[4]   = { 0x43u, 0x4Cu, 0x4Fu, 0x47u }; // "CLOG"
static constexpr uint8_t  CLOG_VERSION    = 2u;
static constexpr uint16_t CLOG_UDP_PORT   = 47808u;
static constexpr size_t   CLOG_HDR_LEN    = 28u;
static constexpr size_t   CLOG_MAX_DATA   = 64u;

// ── Message types (byte 5) ────────────────────────────────────────────────────
static constexpr uint8_t CLOG_TYPE_STATUS  = 0x00u;  // gateway heartbeat
static constexpr uint8_t CLOG_TYPE_RAW_CAN = 0x01u;  // pass-through CAN frame
static constexpr uint8_t CLOG_TYPE_J1939   = 0x02u;  // J1939 decoded frame
static constexpr uint8_t CLOG_TYPE_EVENT   = 0x03u;  // filter-triggered event frame

// ── Flags byte (byte 7) — CAN frame attributes; 0 for Status messages ─────────
static constexpr uint8_t CLOG_FLAG_FD  = (1u << 0);  // CAN FD frame
static constexpr uint8_t CLOG_FLAG_BRS = (1u << 1);  // Bit-Rate Switching active
static constexpr uint8_t CLOG_FLAG_ESI = (1u << 2);  // Error State Indicator
static constexpr uint8_t CLOG_FLAG_EXT = (1u << 3);  // Extended 29-bit CAN ID
static constexpr uint8_t CLOG_FLAG_RTR = (1u << 4);  // Remote Transmission Request
// bits [7:5] reserved, must be 0

// ── Status payload flags (byte 28) ───────────────────────────────────────────
static constexpr uint8_t CLOG_ST_ETH_UP     = (1u << 0);  // Ethernet link up
static constexpr uint8_t CLOG_ST_CAN1_ACTIVE= (1u << 1);  // CAN ch1 logging enabled
static constexpr uint8_t CLOG_ST_CAN2_ACTIVE= (1u << 2);  // CAN ch2 logging enabled
static constexpr uint8_t CLOG_ST_PTP_LOCKED = (1u << 3);  // PTP clock synchronized
// bits [7:4] reserved

// ── CAN bus state values (bytes 29, 30) ──────────────────────────────────────
static constexpr uint8_t CLOG_BUS_OK      = 0u;  // error-active, normal operation
static constexpr uint8_t CLOG_BUS_WARNING = 1u;  // one error counter ≥ 96
static constexpr uint8_t CLOG_BUS_PASSIVE = 2u;  // one error counter ≥ 128
static constexpr uint8_t CLOG_BUS_OFF     = 3u;  // TEC ≥ 256, bus-off state

// ── Wire structures (all packed, big-endian uint32_t fields) ─────────────────
#pragma pack(push, 1)

// Common 28-byte header — present in every CLOG frame
struct ClogHeader {
    uint8_t  magic[4];    // CLOG_MAGIC
    uint8_t  version;     // CLOG_VERSION (2)
    uint8_t  msg_type;    // CLOG_TYPE_*
    uint8_t  channel_id;  // logging_id from LoggingChanCfg (0–255)
    uint8_t  flags;       // CLOG_FLAG_* bitmask; 0 for status frames
    uint32_t sequence;    // big-endian per-channel counter
    uint32_t ts_sec;      // big-endian PTP TAI seconds
    uint32_t ts_nsec;     // big-endian PTP nanoseconds
    uint32_t can_id;      // big-endian raw CAN ID; 0 for status
    uint8_t  dlc;         // CAN DLC 0–15; 0 for status
    uint8_t  reserved[3]; // must be 0
};
static_assert(sizeof(ClogHeader) == CLOG_HDR_LEN, "ClogHeader must be 28 bytes");

// Type 0x01 — Raw CAN frame
// Payload is just the CAN data bytes; length = clog_dlc_to_len(hdr.dlc)
// Total frame = sizeof(ClogHeader) + clog_dlc_to_len(dlc)

// Type 0x02 — J1939 frame payload (8-byte header before data)
struct ClogJ1939Payload {
    uint8_t  priority;   // J1939 priority 0–7 (3 bits, upper 5 bits = 0)
    uint8_t  sa;         // Source Address
    uint8_t  da;         // Destination Address (0xFF = broadcast/global)
    uint8_t  reserved;   // must be 0
    uint32_t pgn;        // big-endian, 18-bit PGN in lower 18 bits
    // data follows: clog_dlc_to_len(hdr.dlc) bytes
};
static_assert(sizeof(ClogJ1939Payload) == 8u, "ClogJ1939Payload must be 8 bytes");

// Type 0x00 — Status / heartbeat payload (40 bytes)
struct ClogStatusPayload {
    uint8_t  status_flags;  // CLOG_ST_* bitmask
    uint8_t  can1_state;    // CLOG_BUS_*
    uint8_t  can2_state;    // CLOG_BUS_*
    uint8_t  fw_major;      // firmware version major
    uint8_t  fw_minor;      // firmware version minor
    uint8_t  reserved[3];
    uint32_t uptime_sec;    // big-endian, seconds since boot
    uint32_t ch1_rx;        // big-endian, ch1 RX frames since boot
    uint32_t ch2_rx;        // big-endian, ch2 RX frames
    uint32_t ch1_tx;        // big-endian, ch1 TX frames
    uint32_t ch2_tx;        // big-endian, ch2 TX frames
    uint32_t ch1_errors;    // big-endian, ch1 CAN error frames
    uint32_t ch2_errors;    // big-endian, ch2 CAN error frames
    uint32_t dropped;       // big-endian, frames dropped (ring full / OOM)
};
static_assert(sizeof(ClogStatusPayload) == 40u, "ClogStatusPayload must be 40 bytes");

// Convenience: complete status frame (68 bytes)
struct ClogStatusFrame {
    ClogHeader       hdr;
    ClogStatusPayload st;
};
static_assert(sizeof(ClogStatusFrame) == 68u, "ClogStatusFrame must be 68 bytes");

// Convenience: maximum-size J1939 FD frame
struct ClogJ1939Frame {
    ClogHeader       hdr;
    ClogJ1939Payload j1;
    uint8_t          data[CLOG_MAX_DATA];
};

// Convenience: maximum-size raw CAN frame
struct ClogRawFrame {
    ClogHeader hdr;
    uint8_t    data[CLOG_MAX_DATA];
};

#pragma pack(pop)

// ── Helpers ───────────────────────────────────────────────────────────────────
inline constexpr uint8_t clog_dlc_to_len(uint8_t dlc) {
    constexpr uint8_t tab[16] = { 0,1,2,3,4,5,6,7,8,12,16,20,24,32,48,64 };
    return (dlc < 16u) ? tab[dlc] : 64u;
}

// Big-endian write helpers for Cortex-M (little-endian)
inline constexpr uint32_t clog_hton32(uint32_t v) { return __builtin_bswap32(v); }
inline constexpr uint16_t clog_hton16(uint16_t v) { return __builtin_bswap16(v); }

// Fill the common header fields (caller still needs to set msg_type, can_id, dlc, flags)
inline void clog_fill_header(ClogHeader& h, uint8_t channel_id,
                             uint32_t seq, uint32_t ts_sec, uint32_t ts_nsec) {
    h.magic[0] = CLOG_MAGIC[0]; h.magic[1] = CLOG_MAGIC[1];
    h.magic[2] = CLOG_MAGIC[2]; h.magic[3] = CLOG_MAGIC[3];
    h.version    = CLOG_VERSION;
    h.channel_id = channel_id;
    h.sequence   = clog_hton32(seq);
    h.ts_sec     = clog_hton32(ts_sec);
    h.ts_nsec    = clog_hton32(ts_nsec);
    h.reserved[0] = h.reserved[1] = h.reserved[2] = 0u;
}
