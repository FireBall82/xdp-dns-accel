#include "resolver_service.hpp"
#include <stdexcept>

namespace net_accel {
ResolverService::ResolverService(SharedDnsTable<>* cache, sockaddr_in upstream, size_t maximum_dns,
                                 size_t worker_count, std::function<void()> wake, RequestPolicyConfig policy,
                                 UpstreamTransport transport, std::vector<ForwardZone> forward_zones)
    : policy_(std::move(policy)), cache_(cache), upstream_(upstream), forward_zones_(std::move(forward_zones)),
      transport_(transport), maximum_dns_(maximum_dns), wake_(std::move(wake)) {
    if (!cache || !wake_ || !worker_count || worker_count > 64 || maximum_dns < 512)
        throw std::invalid_argument("invalid resolver configuration");
    if (forward_zones_.size() > 128) throw std::invalid_argument("at most 128 forward zones");
    std::sort(forward_zones_.begin(), forward_zones_.end(), [](const auto& a, const auto& b) {
        return a.suffix.size() == b.suffix.size() ? a.suffix < b.suffix : a.suffix.size() > b.suffix.size();
    });
    for (size_t i = 0; i < forward_zones_.size(); ++i) {
        const auto& zone = forward_zones_[i];
        if (zone.suffix.size() < 3 || zone.suffix.size() > 255 || zone.suffix.back() != 0 ||
            zone.address.sin_family != AF_INET || !zone.address.sin_port ||
            (i && zone.suffix == forward_zones_[i - 1].suffix))
            throw std::invalid_argument("invalid or duplicate forward zone");
    }
    try {
        for (size_t i = 0; i < worker_count; ++i) workers_.emplace_back([this] { worker(); });
    } catch (...) {
        jobs_.close();
        replies_.close();
        workers_.clear();
        throw;
    }
}
ResolverService::~ResolverService() { stop(); }
void ResolverService::stop() {
    jobs_.close();
    replies_.close();
    workers_.clear(); // Join before queues, callback or cache can be destroyed.
}
const sockaddr_in& ResolverService::upstream_for(const Query& query) const {
    for (const auto& zone : forward_zones_) {
        if (zone.suffix.size() > query.question.name.size()) continue;
        for (size_t offset = 0; offset < query.question.name.size();) {
            if (query.question.name.size() - offset == zone.suffix.size() &&
                std::equal(zone.suffix.begin(), zone.suffix.end(), query.question.name.begin() + offset))
                return zone.address;
            offset += static_cast<size_t>(query.question.name[offset]) + 1;
        }
    }
    return upstream_;
}
Bytes ResolverService::scoped_key(const Query& query) const {
    if (query.cache_key.empty()) return {};
    Bytes key(7);
    const auto& upstream = upstream_for(query);
    const auto* address = reinterpret_cast<const uint8_t*>(&upstream.sin_addr.s_addr);
    const auto* port = reinterpret_cast<const uint8_t*>(&upstream.sin_port);
    std::copy_n(address, 4, key.begin());
    std::copy_n(port, 2, key.begin() + 4);
    key[6] = static_cast<uint8_t>(transport_);
    key.insert(key.end(), query.cache_key.begin(), query.cache_key.end());
    return key;
}
void ResolverService::reply(const Job& job, View response, bool wait) {
    DnsResponse result{fit_response(job.query, response, maximum_dns_), job.request.route};
    bool pushed = wait ? replies_.push_wait(std::move(result)) : replies_.try_push(std::move(result));
    if (pushed) {
        uint64_t elapsed = monotonic_ns() - job.started_ns;
        ++metrics.latency_count;
        metrics.latency_sum_ns.fetch_add(elapsed, std::memory_order_relaxed);
        for (size_t i = 0; i < Metrics::latency_bounds_ns.size(); ++i)
            if (elapsed <= Metrics::latency_bounds_ns[i]) ++metrics.latency_buckets[i];
        wake_();
    }
    else metrics.overloaded.fetch_add(1, std::memory_order_relaxed);
}
void ResolverService::submit(UdpPacket packet) {
    if (packet.headers.size() < 42) {
        ++metrics.received;
        metrics.malformed.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    auto source = read32(packet.headers, 26), destination = read32(packet.headers, 30);
    submit_dns(DnsRequest{std::move(packet.dns), source, destination, std::move(packet.headers)});
}
bool ResolverService::try_response(Bytes& packet) {
    DnsResponse response;
    if (!replies_.try_pop(response)) return false;
    const auto* headers = std::get_if<Bytes>(&response.route);
    if (!headers) throw std::logic_error("socket response used with packet adapter");
    packet = build_ipv4_reply(UdpPacket{*headers, {}}, response.dns);
    return true;
}
void ResolverService::submit_dns(DnsRequest request) {
    uint64_t started = monotonic_ns();
    metrics.received.fetch_add(1, std::memory_order_relaxed);
    if (!policy_.accepts_destination(request.destination)) {
        ++metrics.wrong_destination;
        return;
    }
    auto admission = policy_.admit(request.source, monotonic_ns());
    metrics.tracked_clients.store(policy_.tracked_clients(), std::memory_order_relaxed);
    switch (admission) {
    case Admission::unauthorized: metrics.unauthorized.fetch_add(1, std::memory_order_relaxed); return;
    case Admission::global_limit: metrics.global_limited.fetch_add(1, std::memory_order_relaxed); return;
    case Admission::client_limit: metrics.client_limited.fetch_add(1, std::memory_order_relaxed); return;
    case Admission::client_capacity: metrics.client_table_full.fetch_add(1, std::memory_order_relaxed); return;
    case Admission::network_limit: ++metrics.network_limited; return;
    case Admission::reserved_limit: ++metrics.reserved_limited; return;
    case Admission::allow: break;
    }
    auto query = parse_query(request.dns);
    if (!query) { metrics.malformed.fetch_add(1, std::memory_order_relaxed); return; }
    // Query owns the DNS bytes from here; do not retain a second payload per waiter.
    Bytes{}.swap(request.dns);
    Job job{std::move(request), std::move(*query), started};
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
    Bytes key = scoped_key(job.query);
    std::unique_lock lock(flights_mutex_);
    if (!key.empty()) {
        auto found = flights_.find(key);
        if (found != flights_.end()) {
            if (found->second->followers.size() < 32) {
                found->second->followers.push_back(std::move(job));
                ++metrics.coalesced;
                ++metrics.inflight_waiters;
                return;
            }
            lock.unlock();
            ++metrics.overloaded;
            reply(job, error_response(job.query, 2), false);
            return;
        }
    }
    auto flight = std::make_shared<Flight>(Flight{std::move(job), {}, key});
    if (!key.empty()) flights_.emplace(key, flight);
    if (jobs_.try_push(flight)) {
        ++metrics.inflight_groups;
        return;
    }
    if (!key.empty()) flights_.erase(key);
    lock.unlock();
    ++metrics.overloaded;
    reply(flight->leader, error_response(flight->leader.query, 2), false);
}
void ResolverService::complete(const std::shared_ptr<Flight>& flight, const std::optional<Bytes>& response) {
    std::vector<Job> followers;
    {
        std::lock_guard lock(flights_mutex_);
        if (!flight->key.empty()) flights_.erase(flight->key);
        followers = std::move(flight->followers);
        --metrics.inflight_groups;
        metrics.inflight_waiters.fetch_sub(followers.size(), std::memory_order_relaxed);
    }
    auto deliver = [&](const Job& job) {
        Bytes wire = response ? *response : error_response(job.query, 2);
        // Preserve client IDs even when an upstream uses a different question layout.
        restore_question(job.query, wire);
        reply(job, wire, true);
    };
    deliver(flight->leader);
    for (const auto& job : followers) deliver(job);
}
void ResolverService::worker() {
    std::shared_ptr<Flight> flight;
    while (jobs_.pop_wait(flight)) {
        std::optional<Bytes> response;
        try {
            ++metrics.forwarded;
            bool timed_out = false;
            response = resolve_upstream(flight->leader.query, upstream_for(flight->leader.query), 1500, &timed_out, transport_);
            if (timed_out) ++metrics.upstream_timeouts;
            if (!response) ++metrics.failures;
            else {
                uint32_t ttl = cache_ttl(flight->leader.query, *response);
                if (ttl) {
                    try { cache_->insert(flight->key, *response, ttl, monotonic_ns()); }
                    catch (const std::runtime_error&) { ++metrics.failures; }
                }
            }
        } catch (const std::exception&) { ++metrics.failures; }
        try { complete(flight, response); }
        catch (const std::exception&) { ++metrics.failures; }
    }
}
} // namespace net_accel
