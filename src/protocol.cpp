#include "protocol.h"
#include <cstring>
#include <array>
#include <mutex>

namespace msg {

// ── CRC32 (thread-safe table-based) ───────────────────────
static std::array<uint32_t, 256> makeCrcTable() {
    std::array<uint32_t, 256> table{};
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int j = 0; j < 8; j++)
            c = (c & 1) ? (0xEDB88320 ^ (c >> 1)) : (c >> 1);
        table[i] = c;
    }
    return table;
}

static const std::array<uint32_t, 256> crc_table = makeCrcTable();

uint32_t crc32(const uint8_t* data, size_t len) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; i++)
        crc = crc_table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
    return crc ^ 0xFFFFFFFF;
}

// ── Helpers for network byte order (big-endian) ────────────
// Manual big-endian layout — NO htons/htonl needed
static void put16(Bytes& b, uint16_t v) {
    b.push_back((v >> 8) & 0xFF);
    b.push_back(v & 0xFF);
}

static void put32(Bytes& b, uint32_t v) {
    b.push_back((v >> 24) & 0xFF);
    b.push_back((v >> 16) & 0xFF);
    b.push_back((v >> 8) & 0xFF);
    b.push_back(v & 0xFF);
}

static uint16_t get16(const uint8_t* p) {
    return (uint16_t(p[0]) << 8) | p[1];
}

static uint32_t get32(const uint8_t* p) {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) |
           (uint32_t(p[2]) << 8) | p[3];
}

// ── Serialization ──────────────────────────────────────────
Bytes serialize(const Packet& pkt) {
    uint32_t total = HEADER_SIZE + pkt.payload.size() + CHECKSUM_SIZE;
    Bytes out;
    out.reserve(total);

    put16(out, pkt.magic);
    put32(out, total);
    out.push_back(pkt.version);
    out.push_back(static_cast<uint8_t>(pkt.type));
    put32(out, pkt.request_id);
    put16(out, pkt.flags);
    out.insert(out.end(), pkt.payload.begin(), pkt.payload.end());

    uint32_t chk = crc32(out);
    put32(out, chk);

    return out;
}

std::optional<Packet> deserialize(const Bytes& data) {
    if (data.size() < HEADER_SIZE + CHECKSUM_SIZE) return std::nullopt;

    const uint8_t* p = data.data();
    Packet pkt;
    pkt.magic      = get16(p);       p += 2;
    pkt.total_len  = get32(p);       p += 4;
    pkt.version    = *p++;
    pkt.type       = static_cast<Cmd>(*p++);
    pkt.request_id = get32(p);       p += 4;
    pkt.flags      = get16(p);       p += 2;

    if (pkt.magic != MAGIC) return std::nullopt;
    if (pkt.total_len != data.size()) return std::nullopt;
    if (pkt.version != PROTO_VERSION) return std::nullopt;

    size_t payload_len = pkt.total_len - HEADER_SIZE - CHECKSUM_SIZE;
    pkt.payload.assign(p, p + payload_len);
    p += payload_len;

    pkt.checksum = get32(p);

    // Verify CRC
    uint32_t computed = crc32(data.data(), data.size() - CHECKSUM_SIZE);
    if (computed != pkt.checksum) return std::nullopt;

    return pkt;
}

// ── Convenience builders ───────────────────────────────────
Packet makePacket(Cmd type, uint32_t reqId, const std::string& payload, uint16_t flags) {
    Packet p;
    p.type = type;
    p.request_id = reqId;
    p.flags = flags;
    p.setPayload(payload);
    return p;
}

Packet makePacket(Cmd type, uint32_t reqId, const Bytes& payload, uint16_t flags) {
    Packet p;
    p.type = type;
    p.request_id = reqId;
    p.flags = flags;
    p.payload = payload;
    return p;
}

// ── Stream parser ──────────────────────────────────────────
void StreamParser::feed(const uint8_t* data, size_t len) {
    buf_.insert(buf_.end(), data, data + len);
    tryParse();
}

void StreamParser::tryParse() {
    while (buf_.size() >= HEADER_SIZE + CHECKSUM_SIZE) {
        // Find magic
        size_t start = 0;
        bool found = false;
        for (size_t i = 0; i + 1 < buf_.size(); i++) {
            if (get16(&buf_[i]) == MAGIC) {
                start = i;
                found = true;
                break;
            }
        }
        if (!found) {
            buf_.clear();
            return;
        }
        if (start > 0) buf_.erase(buf_.begin(), buf_.begin() + start);

        if (buf_.size() < HEADER_SIZE) return; // need more data

        uint32_t total = get32(&buf_[2]);
        if (total < HEADER_SIZE + CHECKSUM_SIZE || total > 1024 * 1024) {
            // Invalid length — skip this magic
            if (error_cb_) error_cb_(ErrCode::INVALID_PACKET, "bad total_len");
            buf_.erase(buf_.begin(), buf_.begin() + 2);
            continue;
        }

        if (buf_.size() < total) return; // need more data

        Bytes pkt_data(buf_.begin(), buf_.begin() + total);
        buf_.erase(buf_.begin(), buf_.begin() + total);

        auto pkt = deserialize(pkt_data);
        if (pkt && packet_cb_) {
            packet_cb_(*pkt);
        } else if (!pkt && error_cb_) {
            error_cb_(ErrCode::CRC_MISMATCH, "deserialization failed");
        }
    }
}

} // namespace msg
