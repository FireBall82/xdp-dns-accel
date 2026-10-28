#include "process_security.hpp"
#include "keyed_hash.hpp"
#include "request_policy.hpp"
#include "resolver_service.hpp"
#include <iostream>
#include <memory>
#include <stdexcept>
#include <sys/prctl.h>
#include <linux/capability.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

using namespace net_accel;
#define REQUIRE(condition) do { if (!(condition)) throw std::runtime_error(std::string(__func__) + ": " #condition); } while (false)
namespace {
constexpr uint64_t second = 1000000000ULL;
void cidrs() {
    auto network = Ipv4Cidr::parse("192.0.2.37/24");
    REQUIRE(network.contains(0xc0000200) && network.contains(0xc00002ff));
    REQUIRE(!network.contains(0xc0000300));
    REQUIRE(Ipv4Cidr::parse("0.0.0.0/0").contains(0xffffffff));
    REQUIRE(Ipv4Cidr::parse("192.0.2.1").contains(0xc0000201));
    REQUIRE(!Ipv4Cidr::parse("192.0.2.1/32").contains(0xc0000202));
    for (auto text : {"", "example.com", "::1", "127.1", "256.0.0.1", "1.2.3.4/", "1.2.3.4/-1",
                      "1.2.3.4/33", "1.2.3.4/24/8", "1.2.3.4/24x", " 1.2.3.4"}) {
        bool rejected = false;
        try { Ipv4Cidr::parse(text); } catch (const std::invalid_argument&) { rejected = true; }
        REQUIRE(rejected);
    }
    RequestPolicyConfig config;
    config.allowed_clients = {network, Ipv4Cidr::parse("198.51.100.7")};
    config.global_qps = 1;
    RequestPolicy policy(config);
    REQUIRE(policy.admit(0x01020304, 0) == Admission::unauthorized);
    REQUIRE(policy.admit(0xc0000201, 0) == Admission::allow); // Denials do not consume global credits.
    REQUIRE(policy.admit(0xc6336407, second) == Admission::allow);
    RequestPolicy defaults;
    for (unsigned i = 0; i < 10000; ++i) REQUIRE(defaults.admit(i, 0) == Admission::allow);
    REQUIRE(defaults.tracked_clients() == 0);
}
void limits() {
    RequestPolicy policy({{}, 4, 2});
    REQUIRE(policy.admit(1, 0) == Admission::allow);
    REQUIRE(policy.admit(1, 0) == Admission::allow);
    REQUIRE(policy.admit(1, 0) == Admission::client_limit);
    REQUIRE(policy.admit(2, 0) == Admission::allow);
    REQUIRE(policy.admit(2, 0) == Admission::allow);
    REQUIRE(policy.admit(3, 0) == Admission::global_limit);
    REQUIRE(policy.tracked_clients() == 2); // Global exhaustion cannot allocate new client state.
    REQUIRE(policy.admit(1, second / 2 - 1) == Admission::client_limit);
    REQUIRE(policy.admit(1, second / 2) == Admission::allow); // Fractional refill is retained.
    REQUIRE(policy.admit(1, second / 2) == Admission::client_limit);
    REQUIRE(policy.admit(1, 0) == Admission::client_limit); // No credit from a backwards clock.
    REQUIRE(policy.admit(1, 100 * second) == Admission::allow);
    REQUIRE(policy.admit(1, 100 * second) == Admission::allow);
    REQUIRE(policy.admit(1, 100 * second) == Admission::client_limit); // Idle credit is capped.
    RequestPolicy bounded({{}, 0, 1});
    for (unsigned i = 0; i < RequestPolicy::max_clients; ++i) REQUIRE(bounded.admit(i, 0) == Admission::allow);
    REQUIRE(bounded.admit(5000, 0) == Admission::client_capacity);
    REQUIRE(bounded.admit(0, 0) == Admission::client_limit); // Capacity pressure never resets active buckets.
    REQUIRE(bounded.tracked_clients() == RequestPolicy::max_clients);
    REQUIRE(bounded.admit(5000, 60 * second) == Admission::allow);
    REQUIRE(bounded.tracked_clients() == 1);
    bool rejected = false;
    try { RequestPolicy bad({{}, RequestPolicy::max_qps + 1, 0}); }
    catch (const std::invalid_argument&) { rejected = true; }
    REQUIRE(rejected);
}
void keyed_hash_vectors() {
    const HashKey key{0x0706050403020100ULL, 0x0f0e0d0c0b0a0908ULL};
    const uint64_t vectors[]{0x726fdb47dd0e0e31ULL, 0x74f839c593dc67fdULL, 0x0d6c8009d9a94f5aULL,
        0x85676696d7fb7e2dULL, 0xcf2794e0277187b7ULL, 0x18765564cd99a68dULL, 0xcbc9466e58fee3ceULL,
        0xab0200f58b01d137ULL, 0x93f5f5799a932462ULL, 0x9e0082df0ba9e4b0ULL, 0x7a5dbbc594ddb9f3ULL,
        0xf4b32f46226bada7ULL, 0x751e8fbc860ee5fbULL, 0x14ea5627c0843d90ULL, 0xf723ca908e7af2eeULL,
        0xa129ca6149be45e5ULL};
    Bytes input;
    for (unsigned i = 0; i < 16; ++i) {
        REQUIRE(keyed_hash(input, key) == vectors[i]);
        input.push_back(static_cast<uint8_t>(i));
    }
    REQUIRE(random_hash_key() != random_hash_key());
}
void network_fairness() {
    RequestPolicyConfig config;
    config.client_qps = 1;
    config.network_budgets = {{Ipv4Cidr::parse("192.0.2.0/24"), 2}};
    config.reserved_clients = {{0xc0000207, 1}};
    RequestPolicy policy(config);
    REQUIRE(policy.admit(0xc0000201, 0) == Admission::allow);
    REQUIRE(policy.admit(0xc0000202, 0) == Admission::allow);
    REQUIRE(policy.admit(0xc0000203, 0) == Admission::network_limit);
    REQUIRE(policy.admit(0xc0000207, 0) == Admission::allow); // Dedicated budget survives a network flood.
    REQUIRE(policy.admit(0xc0000207, 0) == Admission::reserved_limit);
    REQUIRE(policy.admit(0xc6336401, 0) == Admission::allow);
    REQUIRE(policy.admit(0xc0000203, second / 2) == Admission::allow);
    RequestPolicyConfig reserved;
    reserved.global_qps = 3;
    reserved.reserved_clients = {{9999, 1}};
    RequestPolicy carved(reserved);
    REQUIRE(carved.admit(1, 0) == Admission::allow && carved.admit(2, 0) == Admission::allow);
    REQUIRE(carved.admit(3, 0) == Admission::global_limit);
    REQUIRE(carved.admit(9999, 0) == Admission::allow);
    reserved.global_qps = 0;
    reserved.client_qps = 1;
    RequestPolicy bounded(reserved);
    for (unsigned i = 0; i < RequestPolicy::max_clients; ++i) REQUIRE(bounded.admit(i, 0) == Admission::allow);
    REQUIRE(bounded.admit(5000, 0) == Admission::client_capacity);
    REQUIRE(bounded.admit(9999, 0) == Admission::allow); // Reserved state is independent of the dynamic table.
    for (int variant = 0; variant < 3; ++variant) {
        RequestPolicyConfig bad;
        bad.reserved_clients = {{1, 2}};
        if (variant == 0) bad.global_qps = 1;
        if (variant == 1) bad.reserved_clients.push_back({1, 2});
        if (variant == 2) bad.allowed_clients = {Ipv4Cidr::parse("192.0.2.0/24")};
        bool rejected = false;
        try { RequestPolicy invalid(bad); } catch (const std::invalid_argument&) { rejected = true; }
        REQUIRE(rejected);
    }
}
void service_policy() {
    auto cache = std::make_unique<SharedDnsTable<>>();
    auto upstream = upstream_address("127.0.0.1:53");
    Bytes wire{0,1,1,0,0,1,0,0,0,0,0,0,1,'a',0,0,1,0,1};
    auto query = parse_query(wire); REQUIRE(query);
    auto answer = error_response(*query, 0);
    Bytes key{127,0,0,1,0,53,0};
    key.insert(key.end(), query->cache_key.begin(), query->cache_key.end());
    REQUIRE(cache->insert(key, answer, 60, monotonic_ns()));
    UdpPacket packet{Bytes(42), wire};
    write32(packet.headers, 26, 0xc000020a);
    write16(packet.headers, 34, 53000);
    write16(packet.headers, 36, 53);
    ResolverService denied(cache.get(), upstream, 1232, 1, [] {},
                           {{Ipv4Cidr::parse("198.51.100.0/24")}, 0, 0});
    denied.submit(packet);
    Bytes reply;
    REQUIRE(denied.metrics.unauthorized == 1 && denied.metrics.forwarded == 0 && denied.metrics.hits == 0);
    REQUIRE(!denied.try_response(reply) && cache->header()->total_queries == 0);
    ResolverService limited(cache.get(), upstream, 1232, 1, [] {}, {{}, 0, 1});
    limited.submit(packet);
    REQUIRE(limited.try_response(reply) && limited.metrics.hits == 1);
    write16(packet.headers, 34, 54000); // Changing source port cannot bypass a per-IP limit.
    limited.submit(packet);
    REQUIRE(!limited.try_response(reply) && limited.metrics.client_limited == 1);
    REQUIRE(limited.metrics.forwarded == 0 && cache->header()->total_queries == 1);
    ResolverService global(cache.get(), upstream, 1232, 1, [] {}, {{}, 1, 0});
    global.submit(packet);
    REQUIRE(global.try_response(reply));
    write32(packet.headers, 26, 0xc000020b);
    global.submit(packet);
    REQUIRE(!global.try_response(reply) && global.metrics.global_limited == 1);
    RequestPolicyConfig endpoint;
    endpoint.listen_address = 0xc0000235;
    ResolverService addressed(cache.get(), upstream, 1232, 1, [] {}, endpoint);
    addressed.submit(packet);
    REQUIRE(addressed.metrics.wrong_destination == 1 && !addressed.try_response(reply));
    write32(packet.headers, 30, 0xc0000235);
    addressed.submit(packet);
    REQUIRE(addressed.try_response(reply));
    global.submit({{}, {}});
    REQUIRE(global.metrics.malformed == 1);
}
void process_hardening() {
    pid_t child = fork(); REQUIRE(child >= 0);
    if (child == 0) {
        try {
            harden_process();
            rlimit core{};
            if (getrlimit(RLIMIT_CORE, &core) || core.rlim_cur || core.rlim_max ||
                prctl(PR_GET_DUMPABLE) != 0 || prctl(PR_GET_NO_NEW_PRIVS, 0L, 0L, 0L, 0L) != 1) _exit(1);
            drop_worker_privileges(worker_identity());
            __user_cap_header_struct header{};
            header.version = _LINUX_CAPABILITY_VERSION_3;
            __user_cap_data_struct caps[2]{};
            if (!geteuid() || syscall(SYS_capget, &header, caps) ||
                caps[0].effective || caps[1].effective || caps[0].permitted || caps[1].permitted ||
                caps[0].inheritable || caps[1].inheritable || prctl(PR_GET_DUMPABLE) != 0) _exit(1);
            _exit(0);
        } catch (...) { _exit(1); }
    }
    int status = 0;
    REQUIRE(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
}
}
int main() {
    try {
        cidrs(); limits(); keyed_hash_vectors(); network_fairness(); process_hardening(); service_policy();
        std::cout << "Client access, rate limits, bounded state, silent drops and process hardening passed\n";
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
