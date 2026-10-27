#include "resolver_service.hpp"
#include <stdexcept>

namespace net_accel {
ResolverService::ResolverService(SharedDnsTable<>* cache, sockaddr_in upstream, size_t maximum_dns,
                                 size_t worker_count, std::function<void()> wake)
    : cache_(cache), upstream_(upstream), maximum_dns_(maximum_dns), wake_(std::move(wake)) {
    if (!cache || !wake_ || !worker_count || worker_count > 64 || maximum_dns < 512)
        throw std::invalid_argument("invalid resolver configuration");
    try {
        for (size_t i = 0; i < worker_count; ++i) workers_.emplace_back([this] { worker(); });
    } catch (...) {
        jobs_.close();
        replies_.close();
        workers_.clear();
        throw;
    }
}
ResolverService::~ResolverService() {
    jobs_.close();
    replies_.close();
    workers_.clear(); // Join before queues, callback or cache can be destroyed.
}
Bytes ResolverService::scoped_key(const Query& query) const {
    if (query.cache_key.empty()) return {};
    Bytes key(6);
    const auto* address = reinterpret_cast<const uint8_t*>(&upstream_.sin_addr.s_addr);
    const auto* port = reinterpret_cast<const uint8_t*>(&upstream_.sin_port);
    std::copy_n(address, 4, key.begin());
    std::copy_n(port, 2, key.begin() + 4);
    key.insert(key.end(), query.cache_key.begin(), query.cache_key.end());
    return key;
}
void ResolverService::reply(const Job& job, View response, bool wait) {
    Bytes packet = build_ipv4_reply(job.packet, fit_response(job.query, response, maximum_dns_));
    bool pushed = wait ? replies_.push_wait(std::move(packet)) : replies_.try_push(std::move(packet));
    if (pushed) wake_();
    else metrics.overloaded.fetch_add(1, std::memory_order_relaxed);
}
void ResolverService::submit(UdpPacket packet) {
    metrics.received.fetch_add(1, std::memory_order_relaxed);
    auto query = parse_query(packet.dns);
    if (!query) { metrics.malformed.fetch_add(1, std::memory_order_relaxed); return; }
    Job job{std::move(packet), std::move(*query)};
    if (read16(job.query.wire, 2) & 0x7800) {
        reply(job, error_response(job.query, 4), false);
        return;
    }
    Bytes response;
    uint32_t age = 0;
    try {
        if (cache_->lookup(scoped_key(job.query), response, monotonic_ns(), age) && age_response(response, age)) {
            restore_question(job.query, response);
            metrics.hits.fetch_add(1, std::memory_order_relaxed);
            reply(job, response, false);
            return;
        }
    } catch (const std::runtime_error&) {
        // An unavailable cache must not disable upstream resolution.
        metrics.failures.fetch_add(1, std::memory_order_relaxed);
    }
    // Keep the packet available for SERVFAIL when the bounded queue is full.
    if (!jobs_.try_push(job)) {
        metrics.overloaded.fetch_add(1, std::memory_order_relaxed);
        reply(job, error_response(job.query, 2), false);
    }
}
void ResolverService::worker() {
    Job job;
    while (jobs_.pop_wait(job)) {
        try {
            metrics.forwarded.fetch_add(1, std::memory_order_relaxed);
            auto response = resolve_upstream(job.query, upstream_);
            if (!response) {
                metrics.failures.fetch_add(1, std::memory_order_relaxed);
                reply(job, error_response(job.query, 2), true);
                continue;
            }
            uint32_t ttl = cache_ttl(job.query, *response);
            if (ttl) {
                try { cache_->insert(scoped_key(job.query), *response, ttl, monotonic_ns()); }
                catch (const std::runtime_error&) { metrics.failures.fetch_add(1, std::memory_order_relaxed); }
            }
            reply(job, *response, true);
        } catch (const std::exception&) {
            metrics.failures.fetch_add(1, std::memory_order_relaxed);
            try { reply(job, error_response(job.query, 2), true); } catch (...) {}
        }
    }
}
} // namespace net_accel
