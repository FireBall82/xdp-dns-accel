#pragma once
#include <array>
#include <cstdint>
#include <span>

namespace net_accel {
using HashKey = std::array<uint64_t, 2>;
HashKey random_hash_key();
// SipHash-2-4; keyed cache placement, not a wire protocol authenticator.
uint64_t keyed_hash(std::span<const uint8_t> input, const HashKey& key) noexcept;
}
