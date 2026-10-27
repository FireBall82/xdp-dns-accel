#pragma once
#include "dns_protocol.hpp"
#include <netinet/in.h>
#include <optional>
#include <string_view>

namespace net_accel {
sockaddr_in upstream_address(std::string_view text);
// One deadline covers UDP, rejected packets and any TCP fallback.
std::optional<Bytes> resolve_upstream(const Query& query, const sockaddr_in& address, int timeout_ms = 1500);
} // namespace net_accel
