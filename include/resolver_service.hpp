#pragma once
#include "bounded_queue.hpp"
#include "dns_protocol.hpp"
#include "request_policy.hpp"
#include "shared_dns_table.hpp"
#include "upstream.hpp"
#include <atomic>
#include <functional>
#include <thread>
#include <map>
#include <memory>
#include <mutex>
#include <array>
#include <variant>

namespace net_accel {
// Adapters own reply routing. The resolver only carries it through its bounded queues.
using ReplyRoute = std::variant<Bytes, sockaddr_in>;
struct DnsRequest {
    Bytes dns;
    uint32_t source, destination; // Host-order IPv4 addresses.
    ReplyRoute route;
};
struct DnsResponse { Bytes dns; ReplyRoute route; };
class ResolverService {
public:
    struct Metrics {
        std::atomic<uint64_t> received{0}, hits{0}, forwarded{0}, failures{0}, overloaded{0}, malformed{0};
        std::atomic<uint64_t> bad_ip_checksums{0}, bad_udp_checksums{0};
        std::atomic<uint64_t> unauthorized{0}, global_limited{0}, client_limited{0}, client_table_full{0};
        std::atomic<uint64_t> wrong_destination{0}, network_limited{0}, reserved_limited{0}, tracked_clients{0};
        std::atomic<uint64_t> coalesced{0}, inflight_groups{0}, inflight_waiters{0}, upstream_timeouts{0};
        std::atomic<uint64_t> latency_count{0}, latency_sum_ns{0};
        static constexpr std::array<uint64_t, 7> latency_bounds_ns{1000000, 5000000, 10000000, 50000000, 100000000, 500000000, 1500000000};
        std::array<std::atomic<uint64_t>, 7> latency_buckets{};
    } metrics;
    ResolverService(SharedDnsTable<>* cache, sockaddr_in upstream, size_t maximum_dns,
                    size_t worker_count, std::function<void()> wake, RequestPolicyConfig policy = {},
                    UpstreamTransport transport = UpstreamTransport::automatic,
                    std::vector<ForwardZone> forward_zones = {});
    ~ResolverService();
    void stop();
    size_t job_queue_depth() const { return jobs_.size(); }
    size_t reply_queue_depth() const { return replies_.size(); }
    void submit(UdpPacket packet);
    void submit_dns(DnsRequest request);
    bool try_response(DnsResponse& response) { return replies_.try_pop(response); }
    bool try_response(Bytes& packet); // Compatibility adapter for the XDP packet path.
private:
    struct Job { DnsRequest request; Query query; uint64_t started_ns; };
    struct Flight { Job leader; std::vector<Job> followers; Bytes key; };
    std::mutex flights_mutex_;
    std::map<Bytes, std::shared_ptr<Flight>> flights_;
    RequestPolicy policy_;
    SharedDnsTable<>* cache_;
    sockaddr_in upstream_;
    std::vector<ForwardZone> forward_zones_;
    UpstreamTransport transport_;
    size_t maximum_dns_;
    std::function<void()> wake_;
    BoundedQueue<std::shared_ptr<Flight>> jobs_{256};
    BoundedQueue<DnsResponse> replies_{512};
    std::vector<std::jthread> workers_;
    Bytes scoped_key(const Query& query) const;
    const sockaddr_in& upstream_for(const Query& query) const;
    void reply(const Job& job, View response, bool wait);
    void worker();
    void complete(const std::shared_ptr<Flight>& flight, const std::optional<Bytes>& response);
};
} // namespace net_accel
