#include "request_policy.hpp"
#include <algorithm>
#include <arpa/inet.h>
#include <charconv>
#include <stdexcept>
#include <string>
#include <utility>

namespace net_accel {
namespace {
constexpr uint64_t second = 1000000000ULL;
constexpr uint64_t idle_expiry = 60 * second;
}
Ipv4Cidr Ipv4Cidr::parse(std::string_view text) {
    auto slash = text.find('/');
    unsigned prefix = 32;
    if (slash != std::string_view::npos) {
        auto value = text.substr(slash + 1);
        auto [end, error] = std::from_chars(value.data(), value.data() + value.size(), prefix);
        if (error != std::errc{} || end != value.data() + value.size() || prefix > 32)
            throw std::invalid_argument("allowed client must be IPv4[/0..32]");
    }
    std::string host(text.substr(0, slash));
    in_addr address{};
    if (host.find('\0') != std::string::npos || inet_pton(AF_INET, host.c_str(), &address) != 1)
        throw std::invalid_argument("allowed client must be IPv4[/0..32]");
    uint32_t mask = prefix ? 0xffffffffU << (32 - prefix) : 0;
    return {ntohl(address.s_addr) & mask, mask};
}
RequestPolicy::RequestPolicy(RequestPolicyConfig config) : config_(std::move(config)) {
    if (config_.allowed_clients.size() > 64 || config_.network_budgets.size() > 64 || config_.reserved_clients.size() > 64 || config_.global_qps > max_qps || config_.client_qps > max_qps)
        throw std::invalid_argument("invalid request policy limits");
    uint64_t reserved_total = 0;
    for (const auto& client : config_.reserved_clients) {
        if (!client.qps || client.qps > max_qps || reserved_.contains(client.address))
            throw std::invalid_argument("reserved clients need unique IPv4 addresses and positive rates");
        if (!config_.allowed_clients.empty() && std::none_of(config_.allowed_clients.begin(), config_.allowed_clients.end(),
                [&](const auto& cidr) { return cidr.contains(client.address); }))
            throw std::invalid_argument("reserved client must be included in the allowlist");
        reserved_.emplace(client.address, ReservedBucket{client.qps, {uint64_t(client.qps) * second, 0, 0}});
        reserved_total += client.qps;
    }
    if (config_.global_qps && reserved_total > config_.global_qps)
        throw std::invalid_argument("reserved rates exceed global rate limit");
    shared_qps_ = config_.global_qps ? config_.global_qps - static_cast<uint32_t>(reserved_total) : 0;
    for (const auto& rule : config_.network_budgets) {
        if (!rule.qps || rule.qps > max_qps) throw std::invalid_argument("network rates must be 1..1000000");
        networks_.push_back({uint64_t(rule.qps) * second, 0, 0});
    }
}
void RequestPolicy::refill(Bucket& bucket, uint32_t rate, uint64_t now) {
    if (now > bucket.updated) {
        bucket.credit = std::min(uint64_t(rate) * second,
                                 bucket.credit + std::min(now - bucket.updated, second) * rate);
        bucket.updated = now;
    }
    bucket.last_seen = std::max(bucket.last_seen, now);
}
Admission RequestPolicy::admit(uint32_t source, uint64_t now) {
    if (!config_.allowed_clients.empty() &&
        std::none_of(config_.allowed_clients.begin(), config_.allowed_clients.end(),
                     [source](const auto& cidr) { return cidr.contains(source); }))
        return Admission::unauthorized;
    if (auto reserved = reserved_.find(source); reserved != reserved_.end()) {
        auto& item = reserved->second;
        refill(item.bucket, item.rate, now);
        if (item.bucket.credit < second) return Admission::reserved_limit;
        item.bucket.credit -= second;
        return Admission::allow;
    }
    if (config_.global_qps) {
        if (!shared_qps_) return Admission::global_limit;
        if (!global_started_) {
            global_ = {uint64_t(shared_qps_) * second, now, now};
            global_started_ = true;
        }
        refill(global_, shared_qps_, now);
        if (global_.credit < second) return Admission::global_limit;
    }
    for (size_t i = 0; i < networks_.size(); ++i) {
        if (!config_.network_budgets[i].network.contains(source)) continue;
        refill(networks_[i], config_.network_budgets[i].qps, now);
        if (networks_[i].credit < second) return Admission::network_limit;
    }
    if (config_.client_qps) {
        // Sweep at most once per second, even under a stream of new source IPs.
        if (now >= last_sweep_ && now - last_sweep_ >= second) {
            for (auto it = clients_.begin(); it != clients_.end();) {
                if (now >= it->second.last_seen && now - it->second.last_seen >= idle_expiry)
                    it = clients_.erase(it);
                else ++it;
            }
            last_sweep_ = now;
        }
        auto it = clients_.find(source);
        if (it == clients_.end()) {
            // Never evict an active bucket to give rotating sources fresh credits.
            if (clients_.size() == max_clients) return Admission::client_capacity;
            it = clients_.emplace(source, Bucket{uint64_t(config_.client_qps) * second, now, now}).first;
        }
        refill(it->second, config_.client_qps, now);
        if (it->second.credit < second) return Admission::client_limit;
        it->second.credit -= second;
    }
    for (size_t i = 0; i < networks_.size(); ++i)
        if (config_.network_budgets[i].network.contains(source)) networks_[i].credit -= second;
    if (config_.global_qps) global_.credit -= second;
    return Admission::allow;
}
} // namespace net_accel
