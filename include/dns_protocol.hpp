#pragma once
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace net_accel {
using Bytes = std::vector<uint8_t>;
using View = std::span<const uint8_t>;
uint16_t read16(View data, size_t offset);
uint32_t read32(View data, size_t offset);
void write16(Bytes& data, size_t offset, uint16_t value);
void write32(Bytes& data, size_t offset, uint32_t value);
struct Question {
    Bytes name;      // Canonical, length-prefixed labels; no dotted-name ambiguity.
    Bytes wire_name; // Expanded labels with the client's capitalization.
    uint16_t type = 0;
    uint16_t klass = 0;
    size_t end = 0;
};
struct Query {
    Bytes wire;
    Bytes cache_key;
    Question question;
    size_t udp_limit = 512;
};
std::optional<Query> parse_query(View wire);
bool valid_response(const Query& query, View response);
uint32_t cache_ttl(const Query& query, View response);
bool age_response(Bytes& response, uint32_t seconds);
void restore_question(const Query& query, Bytes& response);
Bytes error_response(const Query& query, uint16_t rcode);
Bytes fit_response(const Query& query, View response, size_t maximum);
struct UdpPacket { Bytes headers; Bytes dns; };
enum class PacketError { none, malformed, ipv4_checksum, udp_checksum };
std::optional<UdpPacket> parse_ipv4_udp(View packet, PacketError* error = nullptr);
Bytes build_ipv4_reply(const UdpPacket& request, View response);
} // namespace net_accel
