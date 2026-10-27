#include "dns_protocol.hpp"
#include <algorithm>
#include <limits>
#include <stdexcept>

namespace net_accel {
uint16_t read16(View data, size_t offset) {
    if (offset > data.size() || data.size() - offset < 2) throw std::out_of_range("short DNS field");
    return uint16_t(data[offset]) << 8 | data[offset + 1];
}
uint32_t read32(View data, size_t offset) {
    return uint32_t(read16(data, offset)) << 16 | read16(data, offset + 2);
}
void write16(Bytes& data, size_t offset, uint16_t value) {
    if (offset > data.size() || data.size() - offset < 2) throw std::out_of_range("short DNS field");
    data[offset] = value >> 8;
    data[offset + 1] = value & 255;
}
void write32(Bytes& data, size_t offset, uint32_t value) {
    write16(data, offset, value >> 16);
    write16(data, offset + 2, value & 65535);
}
namespace {
uint8_t lower(uint8_t c) { return c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c; }
bool name(View wire, size_t& offset, Bytes& canonical, Bytes& original) {
    size_t cursor = offset;
    bool jumped = false;
    size_t steps = 0;
    while (cursor < wire.size() && ++steps <= 256) {
        uint8_t len = wire[cursor++];
        if ((len & 0xc0) == 0xc0) {
            if (cursor >= wire.size()) return false;
            size_t pointer = (size_t(len & 0x3f) << 8) | wire[cursor++];
            if (pointer < 12 || pointer >= cursor - 2) return false;
            if (!jumped) offset = cursor;
            jumped = true;
            cursor = pointer;
            continue;
        }
        if (len > 63 || cursor + len > wire.size() || canonical.size() + 1 + len > 255) return false;
        canonical.push_back(len);
        original.push_back(len);
        if (!len) {
            if (!jumped) offset = cursor;
            return true;
        }
        for (size_t i = 0; i < len; ++i) {
            canonical.push_back(lower(wire[cursor + i]));
            original.push_back(wire[cursor + i]);
        }
        cursor += len;
    }
    return false;
}
bool question(View wire, Question& q) {
    if (wire.size() < 12 || read16(wire, 4) != 1) return false;
    size_t offset = 12;
    if (!name(wire, offset, q.name, q.wire_name) || offset + 4 > wire.size()) return false;
    q.type = read16(wire, offset);
    q.klass = read16(wire, offset + 2);
    q.end = offset + 4;
    return true;
}
struct Record {
    uint16_t type;
    uint16_t klass;
    size_t ttl_offset;
    uint32_t ttl;
    uint16_t length;
    bool root;
};
std::optional<std::vector<Record>> records(View wire, size_t offset) {
    std::vector<Record> result;
    uint32_t count = uint32_t(read16(wire, 6)) + read16(wire, 8) + read16(wire, 10);
    if (count > wire.size() / 11) return std::nullopt;
    for (uint32_t i = 0; i < count; ++i) {
        Bytes key, original;
        if (!name(wire, offset, key, original) || offset + 10 > wire.size()) return std::nullopt;
        Record record{read16(wire, offset), read16(wire, offset + 2), offset + 4,
                      read32(wire, offset + 4), read16(wire, offset + 8), key.size() == 1};
        offset += 10;
        if (record.length > wire.size() - offset) return std::nullopt;
        offset += record.length;
        result.push_back(record);
    }
    if (offset != wire.size()) return std::nullopt;
    return result;
}
Bytes response_header(const Query& query, uint16_t flags) {
    Bytes result(12, 0);
    write16(result, 0, read16(query.wire, 0));
    write16(result, 2, flags);
    write16(result, 4, 1);
    result.insert(result.end(), query.question.wire_name.begin(), query.question.wire_name.end());
    result.resize(result.size() + 4);
    write16(result, result.size() - 4, query.question.type);
    write16(result, result.size() - 2, query.question.klass);
    return result;
}
uint32_t checksum_sum(View wire, uint32_t sum = 0) {
    size_t i = 0;
    for (; i + 1 < wire.size(); i += 2) sum += uint32_t(wire[i]) << 8 | wire[i + 1];
    if (i < wire.size()) sum += uint32_t(wire[i]) << 8;
    while (sum >> 16) sum = (sum & 65535) + (sum >> 16);
    return sum;
}
} // namespace

std::optional<Query> parse_query(View wire) {
    Query result;
    if (wire.size() < 12 || wire.size() > 65507 || (read16(wire, 2) & 0x8000) ||
        !question(wire, result.question)) return std::nullopt;
    auto rr = records(wire, result.question.end);
    if (!rr) return std::nullopt;
    result.wire.assign(wire.begin(), wire.end());
    bool cacheable = (read16(wire, 2) & 0x7800) == 0 && result.question.klass == 1 &&
                     read16(wire, 6) == 0 && read16(wire, 8) == 0 && read16(wire, 10) <= 1 &&
                     result.question.end == 16 + result.question.name.size();
    bool opt_seen = false;
    for (const auto& record : *rr) {
        if (record.type == 41) {
            if (opt_seen || !record.root) return std::nullopt;
            opt_seen = true;
            result.udp_limit = std::max<size_t>(512, record.klass);
            // Unknown EDNS versions and stateful options are forwarded, not cached.
            cacheable &= (record.ttl & 0xffff0000U) == 0 && record.length == 0;
        } else cacheable = false;
    }
    if (cacheable) {
        result.cache_key = result.wire;
        write16(result.cache_key, 0, 0);
        std::copy(result.question.name.begin(), result.question.name.end(), result.cache_key.begin() + 12);
    }
    return result;
}
bool valid_response(const Query& query, View response) {
    Question q;
    if (response.size() < 12 || read16(response, 0) != read16(query.wire, 0) ||
        !(read16(response, 2) & 0x8000) ||
        (read16(response, 2) & 0x7800) != (read16(query.wire, 2) & 0x7800) ||
        !question(response, q) || q.name != query.question.name || q.type != query.question.type ||
        q.klass != query.question.klass) return false;
    // A truncated UDP response may end inside an RR. Its matched question is
    // sufficient to request the complete response over the connected TCP peer.
    return (read16(response, 2) & 0x0200) || records(response, q.end).has_value();
}
uint32_t cache_ttl(const Query& query, View response) {
    if (query.cache_key.empty() || !valid_response(query, response) ||
        (read16(response, 2) & 0x020f) || read16(response, 6) == 0) return 0;
    Question q;
    if (!question(response, q) || q.end != query.question.end || q.wire_name != query.question.wire_name) return 0;
    auto rr = records(response, q.end);
    uint32_t ttl = std::numeric_limits<uint32_t>::max();
    bool opt_seen = false;
    for (const auto& record : *rr) {
        if (record.type == 41) {
            if (opt_seen || !record.root || record.ttl >> 16 || record.length) return 0;
            opt_seen = true;
        } else {
            if (record.type == 250 || record.type == 249 || record.type == 24) return 0;
            if (record.ttl == 0 || record.ttl > 0x7fffffffU) return 0;
            ttl = std::min(ttl, record.ttl);
        }
    }
    return ttl == std::numeric_limits<uint32_t>::max() ? 0 : ttl;
}
bool age_response(Bytes& response, uint32_t seconds) {
    Question q;
    if (!question(response, q)) return false;
    auto rr = records(response, q.end);
    if (!rr) return false;
    for (const auto& record : *rr) {
        if (record.type != 41) write32(response, record.ttl_offset, record.ttl > seconds ? record.ttl - seconds : 0);
    }
    return true;
}
void restore_question(const Query& query, Bytes& response) {
    write16(response, 0, read16(query.wire, 0));
    std::copy(query.question.wire_name.begin(), query.question.wire_name.end(), response.begin() + 12);
}
Bytes error_response(const Query& query, uint16_t rcode) {
    return response_header(query, 0x8080 | (read16(query.wire, 2) & 0x7910) | (rcode & 15));
}
Bytes fit_response(const Query& query, View response, size_t maximum) {
    if (response.size() <= std::min(query.udp_limit, maximum)) return Bytes(response.begin(), response.end());
    // Return a complete TC packet, never an answer cut in the middle of an RR.
    Bytes result = response_header(query, (read16(response, 2) | 0x8200) & ~0x0020);
    Question q;
    if (question(response, q)) {
        auto rr = records(response, q.end);
        if (rr) for (const auto& record : *rr) {
            if (record.type != 41 || !record.root) continue;
            // Keep EDNS version/extended RCODE even when dropping oversized data.
            // Options are omitted from the synthesized truncated response.
            size_t offset = result.size();
            result.resize(offset + 11, 0);
            write16(result, offset + 1, 41);
            write16(result, offset + 3, static_cast<uint16_t>(std::min<size_t>(query.udp_limit, 1232)));
            write32(result, offset + 5, record.ttl);
            write16(result, 10, 1);
            break;
        }
    }
    return result;
}
std::optional<UdpPacket> parse_ipv4_udp(View packet, PacketError* error) {
    if (error) *error = PacketError::malformed;
    if (packet.size() < 42 || read16(packet, 12) != 0x0800 || (packet[14] >> 4) != 4 || packet[23] != 17) return std::nullopt;
    size_t ihl = size_t(packet[14] & 15) * 4;
    size_t total = read16(packet, 16);
    if (ihl < 20 || total < ihl + 8 || total > packet.size() - 14 ||
        (read16(packet, 20) & 0x3fff)) return std::nullopt;
    if (checksum_sum(packet.subspan(14, ihl)) != 65535) {
        if (error) *error = PacketError::ipv4_checksum;
        return std::nullopt;
    }
    size_t udp = 14 + ihl;
    size_t length = read16(packet, udp + 4);
    if (read16(packet, udp + 2) != 53 || length < 20 || length > total - ihl) return std::nullopt;
    if (read16(packet, udp + 6)) {
        uint32_t pseudo = checksum_sum(packet.subspan(26, 8), 17 + length);
        if (checksum_sum(packet.subspan(udp, length), pseudo) != 65535) {
            if (error) *error = PacketError::udp_checksum;
            return std::nullopt;
        }
    }
    if (error) *error = PacketError::none;
    return UdpPacket{Bytes(packet.begin(), packet.begin() + udp + 8),
                     Bytes(packet.begin() + udp + 8, packet.begin() + udp + length)};
}
Bytes build_ipv4_reply(const UdpPacket& request, View response) {
    if (request.headers.size() < 42 || response.size() > 65507) throw std::invalid_argument("invalid packet reply");
    size_t udp = request.headers.size() - 8;
    Bytes result(42 + response.size(), 0);
    std::copy_n(request.headers.begin() + 6, 6, result.begin());
    std::copy_n(request.headers.begin(), 6, result.begin() + 6);
    write16(result, 12, 0x0800);
    result[14] = 0x45;
    result[15] = request.headers[15];
    write16(result, 16, 28 + response.size());
    write16(result, 20, 0x4000);
    result[22] = 64;
    result[23] = 17;
    std::copy_n(request.headers.begin() + 30, 4, result.begin() + 26);
    std::copy_n(request.headers.begin() + 26, 4, result.begin() + 30);
    write16(result, 24, static_cast<uint16_t>(~checksum_sum(View(result).subspan(14, 20))));
    write16(result, 34, read16(request.headers, udp + 2));
    write16(result, 36, read16(request.headers, udp));
    write16(result, 38, 8 + response.size());
    std::copy(response.begin(), response.end(), result.begin() + 42);
    uint32_t pseudo = checksum_sum(View(result).subspan(26, 8), 17 + 8 + response.size());
    uint16_t checksum = static_cast<uint16_t>(~checksum_sum(View(result).subspan(34), pseudo));
    write16(result, 40, checksum ? checksum : 65535);
    return result;
}
} // namespace net_accel
