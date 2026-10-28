#include "dns_protocol.hpp"
using namespace net_accel;
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size > 65535) return 0;
    auto exercise = [](View input) {
    PacketError error;
    if (auto packet = parse_ipv4_udp(input, &error)) {
        if (auto q = parse_query(packet->dns)) {
            auto response = error_response(*q, 2);
            (void)build_ipv4_reply(*packet, response);
        }
    }
    };
    exercise(View(data, size));
    // Also explore deeper paths with valid lengths/checksums; keep the raw path
    // above so malformed metadata and bad checksums remain covered.
    if (size >= 42 && data[12] == 8 && data[13] == 0 && (data[14] >> 4) == 4) {
        size_t ihl = (data[14] & 15) * 4;
        if (ihl >= 20 && ihl <= 60 && size >= 14 + ihl + 8) {
            Bytes normalized(data, data + size);
            write16(normalized, 16, size - 14);
            write16(normalized, 24, 0);
            uint32_t sum = 0;
            for (size_t i = 14; i < 14 + ihl; i += 2) sum += read16(normalized, i);
            while (sum >> 16) sum = (sum & 65535) + (sum >> 16);
            write16(normalized, 24, static_cast<uint16_t>(~sum));
            write16(normalized, 14 + ihl + 4, size - 14 - ihl);
            write16(normalized, 14 + ihl + 6, 0);
            exercise(normalized);
        }
    }
    return 0;
}
