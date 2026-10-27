#pragma once
#include "bounded_queue.hpp"
#include "dns_protocol.hpp"
#include "shared_dns_table.hpp"
#include "upstream.hpp"
#include <atomic>
#include <functional>
#include <thread>

namespace net_accel {
class ResolverService {
public:
    struct Metrics {
        std::atomic<uint64_t> received{0}, hits{0}, forwarded{0}, failures{0}, overloaded{0}, malformed{0};
        std::atomic<uint64_t> bad_ip_checksums{0}, bad_udp_checksums{0};
    } metrics;
    ResolverService(SharedDnsTable<>* cache, sockaddr_in upstream, size_t maximum_dns,
                    size_t worker_count, std::function<void()> wake);
    ~ResolverService();
    void submit(UdpPacket packet);
    bool try_response(Bytes& packet) { return replies_.try_pop(packet); }
private:
    struct Job { UdpPacket packet; Query query; };
    SharedDnsTable<>* cache_;
    sockaddr_in upstream_;
    size_t maximum_dns_;
    std::function<void()> wake_;
    BoundedQueue<Job> jobs_{256};
    BoundedQueue<Bytes> replies_{512};
    std::vector<std::jthread> workers_;
    Bytes scoped_key(const Query& query) const;
    void reply(const Job& job, View response, bool wait);
    void worker();
};
} // namespace net_accel
