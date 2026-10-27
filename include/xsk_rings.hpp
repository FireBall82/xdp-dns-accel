#pragma once
#include <algorithm>
#include <cstdint>
#include <deque>
#include <xdp/xsk.h>

namespace net_accel {
struct PendingTx { uint64_t addr; uint32_t len; };
// Reserve as much as fits. Unsubmitted entries remain owned by the caller.
inline uint32_t refill_frames(xsk_ring_prod& ring, std::deque<uint64_t>& frames) {
    uint32_t count = static_cast<uint32_t>(std::min<size_t>(frames.size(), ring.size));
    count = std::min(count, xsk_prod_nb_free(&ring, count));
    uint32_t index = 0;
    if (!count || xsk_ring_prod__reserve(&ring, count, &index) != count) return 0;
    for (uint32_t i = 0; i < count; ++i) {
        *xsk_ring_prod__fill_addr(&ring, index + i) = frames.front();
        frames.pop_front();
    }
    xsk_ring_prod__submit(&ring, count);
    return count;
}
inline uint32_t submit_frames(xsk_ring_prod& ring, std::deque<PendingTx>& frames) {
    uint32_t count = static_cast<uint32_t>(std::min<size_t>(frames.size(), ring.size));
    count = std::min(count, xsk_prod_nb_free(&ring, count));
    uint32_t index = 0;
    if (!count || xsk_ring_prod__reserve(&ring, count, &index) != count) return 0;
    for (uint32_t i = 0; i < count; ++i) {
        auto* desc = xsk_ring_prod__tx_desc(&ring, index + i);
        *desc = {frames.front().addr, frames.front().len, 0};
        frames.pop_front();
    }
    xsk_ring_prod__submit(&ring, count);
    return count;
}
} // namespace net_accel
