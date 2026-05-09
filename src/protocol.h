#pragma once

#include "types.h"
#include <cstdint>
#include <deque>
#include <functional>
#include <optional>

namespace msg {

constexpr uint16_t MAGIC = 0xABCD;
constexpr uint8_t  PROTO_VERSION = 1;
constexpr size_t   HEADER_SIZE = 14; // magic(2)+len(4)+ver(1)+type(1)+reqid(4)+flags(2)
constexpr size_t   CHECKSUM_SIZE = 4;

enum class Cmd : uint8_t {
    AUTH_REQ        = 0x01, AUTH_RESP       = 0x02,
    REG_REQ         = 0x03, REG_RESP        = 0x04,
    MSG_SEND        = 0x10, MSG_DELIVER     = 0x11,
    MSG_ACK         = 0x12, MSG_STATUS      = 0x13,
    SYNC_REQ        = 0x20, SYNC_RESP       = 0x21,
    SYNC_P2P        = 0x22,
    PING            = 0x30, PONG            = 0x31,
    USER_BLOCK      = 0x40, USER_UNBLOCK    = 0x41,
    CERT_REVOKE     = 0x42,
    // Chat management
    CHAT_CREATE     = 0x50, CHAT_RESP       = 0x51,
    CHAT_JOIN       = 0x52, CHAT_LEAVE      = 0x53,
    // Contacts
    CONTACT_ADD     = 0x60, CONTACT_RESP    = 0x61,
    CONTACT_ACCEPT  = 0x62, CONTACT_LIST    = 0x63,
    // Profiles
    PROFILE_GET     = 0x70, PROFILE_RESP    = 0x71,
    PROFILE_UPDATE  = 0x72,
    // User list
    USER_LIST       = 0x73, USER_LIST_RESP  = 0x74,
    // Admin panel
    LOG_QUERY       = 0x80, LOG_RESP        = 0x81,
    ADMIN_STATS     = 0x82, ADMIN_STATS_RESP = 0x83,
    ERR             = 0xFF,
};

enum class ErrCode : uint16_t {
    OK = 0, INVALID_PACKET = 1, CRC_MISMATCH = 2, BAD_VERSION = 3,
    AUTH_FAIL = 4, NOT_FOUND = 5, BLOCKED = 6, DENIED = 7,
    INTERNAL = 8, SESSION_EXPIRED = 9,
};

namespace Flags {
    constexpr uint16_t NONE       = 0x0000;
    constexpr uint16_t COMPRESSED = 0x0001;
    constexpr uint16_t ENCRYPTED  = 0x0002;
    constexpr uint16_t IS_REPLY   = 0x0004;
}

struct Packet {
    uint16_t magic      = MAGIC;
    uint32_t total_len  = 0;
    uint8_t  version    = PROTO_VERSION;
    Cmd      type       = Cmd::ERR;
    uint32_t request_id = 0;
    uint16_t flags      = Flags::NONE;
    Bytes    payload;
    uint32_t checksum   = 0;

    std::string payloadStr() const { return {payload.begin(), payload.end()}; }
    void setPayload(const std::string& s) { payload.assign(s.begin(), s.end()); }
};

// ── CRC32 ──────────────────────────────────────────────────
uint32_t crc32(const uint8_t* data, size_t len);
inline uint32_t crc32(const Bytes& d) { return crc32(d.data(), d.size()); }

// ── Serialization ──────────────────────────────────────────
Bytes    serialize(const Packet& pkt);
std::optional<Packet> deserialize(const Bytes& data);

// ── Packet builder ─────────────────────────────────────────
Packet makePacket(Cmd type, uint32_t reqId, const std::string& payload,
                  uint16_t flags = Flags::NONE);
Packet makePacket(Cmd type, uint32_t reqId, const Bytes& payload = {},
                  uint16_t flags = Flags::NONE);

// ── Stream parser ──────────────────────────────────────────
class StreamParser {
public:
    using PacketCb = std::function<void(Packet)>;
    using ErrorCb  = std::function<void(ErrCode, const std::string&)>;

    void onPacket(PacketCb cb) { packet_cb_ = std::move(cb); }
    void onError(ErrorCb cb)   { error_cb_ = std::move(cb); }

    void feed(const uint8_t* data, size_t len);
    void feed(const Bytes& data) { feed(data.data(), data.size()); }
    void reset() { buf_.clear(); }

private:
    Bytes buf_;
    PacketCb packet_cb_;
    ErrorCb  error_cb_;
    void tryParse();
};

} // namespace msg