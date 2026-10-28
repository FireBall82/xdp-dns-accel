#include "runtime_metrics.hpp"
#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <poll.h>
#include <sstream>
#include <stdexcept>
#include <sys/socket.h>
#include <unistd.h>

namespace net_accel {
std::string render_metrics(const ResolverService& service, const KernelMetrics& kernel) {
    std::ostringstream out;
    auto metric = [&](const char* name, uint64_t value, bool gauge = false) {
        out << "# TYPE net_accel_dns_" << name << (gauge ? " gauge\n" : " counter\n")
            << "net_accel_dns_" << name << ' ' << value << '\n';
    };
    const auto& m = service.metrics;
#define COUNTER(field) metric(#field "_total", m.field.load(std::memory_order_relaxed))
    COUNTER(received); COUNTER(hits); COUNTER(forwarded); COUNTER(failures); COUNTER(overloaded); COUNTER(malformed);
    COUNTER(bad_ip_checksums); COUNTER(bad_udp_checksums); COUNTER(unauthorized); COUNTER(wrong_destination);
    COUNTER(global_limited); COUNTER(client_limited); COUNTER(client_table_full); COUNTER(network_limited);
    COUNTER(reserved_limited); COUNTER(coalesced); COUNTER(upstream_timeouts);
#undef COUNTER
#define GAUGE(field) metric(#field, m.field.load(std::memory_order_relaxed), true)
    GAUGE(tracked_clients); GAUGE(inflight_groups); GAUGE(inflight_waiters);
#undef GAUGE
    metric("job_queue_depth", service.job_queue_depth(), true);
    metric("reply_queue_depth", service.reply_queue_depth(), true);
#define KERNEL(field) metric(#field "_total", kernel.field.load(std::memory_order_relaxed))
    KERNEL(xdp_packets); KERNEL(xdp_dropped); KERNEL(xdp_redirected); KERNEL(xdp_unauthorized);
    KERNEL(destination_passed); KERNEL(rx_dropped); KERNEL(rx_invalid); KERNEL(tx_invalid); KERNEL(collection_errors);
#undef KERNEL
    out << "# TYPE net_accel_dns_processing_seconds histogram\n";
    for (size_t i = 0; i < ResolverService::Metrics::latency_bounds_ns.size(); ++i)
        out << "net_accel_dns_processing_seconds_bucket{le=\"" << double(ResolverService::Metrics::latency_bounds_ns[i]) / 1e9
            << "\"} " << m.latency_buckets[i].load() << '\n';
    out << "net_accel_dns_processing_seconds_bucket{le=\"+Inf\"} " << m.latency_count.load() << '\n'
        << "net_accel_dns_processing_seconds_count " << m.latency_count.load() << '\n'
        << "net_accel_dns_processing_seconds_sum " << double(m.latency_sum_ns.load()) / 1e9 << '\n';
    return out.str();
}
MetricsServer::MetricsServer(const ResolverService& service, const KernelMetrics& kernel, uint16_t port) {
    fd_ = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd_ < 0) throw std::runtime_error("metrics socket failed");
    try {
        int reuse = 1;
        if (setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)))
            throw std::runtime_error("metrics socket reuse failed");
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        address.sin_port = htons(port);
        if (bind(fd_, reinterpret_cast<sockaddr*>(&address), sizeof(address)) || listen(fd_, 16))
            throw std::runtime_error("metrics bind/listen failed: " + std::string(std::strerror(errno)));
        socklen_t length = sizeof(address);
        if (getsockname(fd_, reinterpret_cast<sockaddr*>(&address), &length)) throw std::runtime_error("metrics getsockname failed");
        port_ = ntohs(address.sin_port);
        thread_ = std::jthread([this, &service, &kernel](std::stop_token stop) {
            while (!stop.stop_requested()) {
                pollfd item{fd_, POLLIN, 0};
                if (poll(&item, 1, 100) <= 0 || !(item.revents & POLLIN)) continue;
                int client = accept4(fd_, nullptr, nullptr, SOCK_CLOEXEC | SOCK_NONBLOCK);
                if (client < 0) continue;
                // A stalled scraper cannot block DNS or hold this thread indefinitely.
                auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(250);
                std::string request;
                char buffer[1024];
                while (!stop.stop_requested() && request.size() < 4096 && request.find("\r\n\r\n") == std::string::npos &&
                       std::chrono::steady_clock::now() < deadline) {
                    pollfd input{client, POLLIN, 0};
                    if (poll(&input, 1, 20) <= 0) continue;
                    ssize_t count = recv(client, buffer, sizeof(buffer), 0);
                    if (count > 0) request.append(buffer, static_cast<size_t>(count));
                    else if (count == 0 || (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)) break;
                }
                bool valid = request.size() <= 4096 && request.find("\r\n\r\n") != std::string::npos &&
                    (request.starts_with("GET /metrics HTTP/1.0\r\n") || request.starts_with("GET /metrics HTTP/1.1\r\n"));
                std::string body = valid ? render_metrics(service, kernel) : "bad request\n";
                std::string response = std::string(valid ? "HTTP/1.1 200 OK\r\n" : "HTTP/1.1 400 Bad Request\r\n") +
                    "Content-Type: text/plain; version=0.0.4\r\nConnection: close\r\nContent-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
                size_t sent = 0;
                while (!stop.stop_requested() && sent < response.size() && std::chrono::steady_clock::now() < deadline) {
                    ssize_t count = send(client, response.data() + sent, response.size() - sent, MSG_NOSIGNAL);
                    if (count > 0) sent += static_cast<size_t>(count);
                    else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) break;
                    else { pollfd output{client, POLLOUT, 0}; poll(&output, 1, 20); }
                }
                close(client);
            }
        });
    } catch (...) { close(fd_); throw; }
}
MetricsServer::~MetricsServer() {
    thread_.request_stop();
    shutdown(fd_, SHUT_RDWR);
    thread_.join();
    close(fd_);
}
}
