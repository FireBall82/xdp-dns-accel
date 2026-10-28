#pragma once
#include "dns_protocol.hpp"
#include <netinet/in.h>
#include <optional>
#include <string_view>

namespace net_accel {
enum class UpstreamTransport { automatic, udp, tcp };
struct ForwardZone { Bytes suffix; sockaddr_in address; };
sockaddr_in upstream_address(std::string_view text);
// domain=IPv4[:port], canonical DNS label encoding. The root zone is not accepted.
ForwardZone forward_zone(std::string_view text);
// One deadline covers UDP, rejected packets and any TCP fallback.
std::optional<Bytes> resolve_upstream(const Query& query, const sockaddr_in& address, int timeout_ms = 1500, bool* timed_out = nullptr,
                                      UpstreamTransport transport = UpstreamTransport::automatic);
} // namespace net_accel
