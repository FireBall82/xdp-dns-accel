#include "keyed_hash.hpp"
#include <bit>
#include <cerrno>
#include <stdexcept>
#include <sys/random.h>

namespace net_accel {
HashKey random_hash_key() {
    HashKey key{};
    auto* data = reinterpret_cast<uint8_t*>(key.data());
    size_t done = 0;
    while (done < sizeof(key)) {
        ssize_t count = getrandom(data + done, sizeof(key) - done, 0);
        if (count > 0) done += static_cast<size_t>(count);
        else if (count < 0 && errno == EINTR) continue;
        else throw std::runtime_error("secure hash key generation failed");
    }
    return key;
}
uint64_t keyed_hash(std::span<const uint8_t> input, const HashKey& key) noexcept {
    uint64_t v0 = 0x736f6d6570736575ULL ^ key[0], v1 = 0x646f72616e646f6dULL ^ key[1];
    uint64_t v2 = 0x6c7967656e657261ULL ^ key[0], v3 = 0x7465646279746573ULL ^ key[1];
    auto round = [&] {
        v0 += v1; v1 = std::rotl(v1, 13); v1 ^= v0; v0 = std::rotl(v0, 32);
        v2 += v3; v3 = std::rotl(v3, 16); v3 ^= v2;
        v0 += v3; v3 = std::rotl(v3, 21); v3 ^= v0;
        v2 += v1; v1 = std::rotl(v1, 17); v1 ^= v2; v2 = std::rotl(v2, 32);
    };
    size_t offset = 0;
    while (input.size() - offset >= 8) {
        uint64_t word = 0;
        for (unsigned i = 0; i < 8; ++i) word |= uint64_t(input[offset + i]) << (8 * i);
        v3 ^= word; round(); round(); v0 ^= word;
        offset += 8;
    }
    uint64_t tail = uint64_t(input.size() & 255) << 56;
    for (size_t i = 0; i < input.size() - offset; ++i) tail |= uint64_t(input[offset + i]) << (8 * i);
    v3 ^= tail; round(); round(); v0 ^= tail;
    v2 ^= 255; round(); round(); round(); round();
    return v0 ^ v1 ^ v2 ^ v3;
}
}
