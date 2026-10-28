#pragma once
#include "resolver_service.hpp"
#include <atomic>
#include <string>
#include <thread>

namespace net_accel {
// Shared supervisor -> worker counters. No query names, addresses or hash keys.
struct KernelMetrics {
    std::atomic<uint64_t> xdp_packets{0}, xdp_dropped{0}, xdp_redirected{0}, xdp_unauthorized{0}, destination_passed{0};
    std::atomic<uint64_t> rx_dropped{0}, rx_invalid{0}, tx_invalid{0}, collection_errors{0};
};
std::string render_metrics(const ResolverService& service, const KernelMetrics& kernel);
class MetricsServer {
public:
    MetricsServer(const ResolverService& service, const KernelMetrics& kernel, uint16_t port);
    ~MetricsServer();
    uint16_t port() const { return port_; }
private:
    int fd_ = -1;
    uint16_t port_ = 0;
    std::jthread thread_;
};
}
