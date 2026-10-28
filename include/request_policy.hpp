#pragma once
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string_view>
#include <vector>

namespace net_accel {
// Addresses use host-order numeric IPv4 values (as returned by read32).
struct Ipv4Cidr {
    uint32_t network;
    uint32_t mask;
    static Ipv4Cidr parse(std::string_view text);
    bool contains(uint32_t address) const { return (address & mask) == network; }
};
struct NetworkBudget { Ipv4Cidr network; uint32_t qps; };
struct ReservedClient { uint32_t address; uint32_t qps; };
struct RequestPolicyConfig {
    std::vector<Ipv4Cidr> allowed_clients; // Empty preserves unrestricted access.
    uint32_t global_qps = 0;              // Zero disables the corresponding limit.
    uint32_t client_qps = 0;
    std::vector<NetworkBudget> network_budgets{};
    std::vector<ReservedClient> reserved_clients{};
    std::optional<uint32_t> listen_address{};
};
enum class Admission { allow, unauthorized, global_limit, client_limit, client_capacity, network_limit, reserved_limit };
// Used only by the receive thread. A bucket holds one second's burst allowance.
class RequestPolicy {
public:
    static constexpr size_t max_clients = 4096;
    static constexpr uint32_t max_qps = 1000000;
    explicit RequestPolicy(RequestPolicyConfig config = {});
    Admission admit(uint32_t source, uint64_t now_ns);
    size_t tracked_clients() const { return clients_.size(); }
    size_t reserved_clients() const { return reserved_.size(); }
    bool accepts_destination(uint32_t address) const { return !config_.listen_address || address == *config_.listen_address; }
private:
    struct Bucket { uint64_t credit, updated, last_seen; };
    RequestPolicyConfig config_;
    Bucket global_{};
    uint32_t shared_qps_ = 0;
    std::vector<Bucket> networks_;
    struct ReservedBucket { uint32_t rate; Bucket bucket; };
    std::map<uint32_t, ReservedBucket> reserved_;
    bool global_started_ = false;
    std::map<uint32_t, Bucket> clients_; // Bounded; avoids attacker-controlled hash collisions.
    uint64_t last_sweep_ = 0;
    static void refill(Bucket& bucket, uint32_t rate, uint64_t now);
};
} // namespace net_accel
