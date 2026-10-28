#include "bounded_queue.hpp"
#include "dns_protocol.hpp"
#include "resolver_service.hpp"
#include "runtime_metrics.hpp"
#include "shared_dns_table.hpp"
#include "upstream.hpp"
#ifdef NET_ACCEL_XDP
#include "xsk_rings.hpp"
#endif
#include <algorithm>
#include <array>
#include <atomic>
#include <arpa/inet.h>
#include <chrono>
#include <cstring>
#include <future>
#include <iostream>
#include <memory>
#include <poll.h>
#include <random>
#include <stdexcept>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

using namespace net_accel;
#define REQUIRE(condition) do { if (!(condition)) throw std::runtime_error(std::string(__func__) + ": " #condition); } while (false)
namespace {
Bytes query_wire(uint16_t type = 1, bool edns = false) {
    Bytes wire{0x12,0x34,1,0,0,1,0,0,0,0,0,0, 7,'e','x','a','m','p','l','e',3,'c','o','m',0,0,0,0,1};
    write16(wire, wire.size() - 4, type);
    if (edns) {
        write16(wire, 10, 1);
        const Bytes opt{0,0,41,4,208,0,0,128,0,0,0};
        wire.insert(wire.end(), opt.begin(), opt.end());
    }
    return wire;
}
Query query(uint16_t type = 1, bool edns = false) {
    auto parsed = parse_query(query_wire(type, edns));
    REQUIRE(parsed);
    return *parsed;
}
void append_rr(Bytes& wire, uint16_t type, uint32_t ttl, View data) {
    size_t offset = wire.size();
    wire.resize(offset + 12 + data.size());
    write16(wire, offset, 0xc00c);
    write16(wire, offset + 2, type);
    write16(wire, offset + 4, 1);
    write32(wire, offset + 6, ttl);
    write16(wire, offset + 10, static_cast<uint16_t>(data.size()));
    std::copy(data.begin(), data.end(), wire.begin() + offset + 12);
    write16(wire, 6, read16(wire, 6) + 1);
}
Bytes answer(const Query& q, uint32_t ttl = 60) {
    auto wire = error_response(q, 0);
    Bytes address(q.question.type == 28 ? 16 : 4, 1);
    append_rr(wire, q.question.type, ttl, address);
    return wire;
}
uint16_t checksum(View wire, uint32_t sum = 0) {
    for (size_t i = 0; i < wire.size(); ++i) sum += uint32_t(wire[i]) << (i % 2 ? 0 : 8);
    while (sum >> 16) sum = (sum & 65535) + (sum >> 16);
    return static_cast<uint16_t>(~sum);
}
Bytes ethernet_query(View dns, bool options = false) {
    size_t ihl = options ? 24 : 20;
    size_t udp = 14 + ihl;
    Bytes wire(udp + 8 + dns.size(), 0);
    for (size_t i = 0; i < 12; ++i) wire[i] = static_cast<uint8_t>(i + 1);
    write16(wire, 12, 0x0800);
    wire[14] = 0x40 | static_cast<uint8_t>(ihl / 4);
    write16(wire, 16, wire.size() - 14);
    wire[22] = 64; wire[23] = 17;
    wire[26] = 192; wire[27] = 0; wire[28] = 2; wire[29] = 10;
    wire[30] = 192; wire[31] = 0; wire[32] = 2; wire[33] = 53;
    write16(wire, 24, checksum(View(wire).subspan(14, ihl)));
    write16(wire, udp, 53000); write16(wire, udp + 2, 53);
    write16(wire, udp + 4, 8 + dns.size());
    std::copy(dns.begin(), dns.end(), wire.begin() + udp + 8);
    return wire;
}
void fix_ip_checksum(Bytes& packet) {
    write16(packet, 24, 0);
    write16(packet, 24, checksum(View(packet).subspan(14, (packet[14] & 15) * 4)));
}
void queries_and_answers() {
    auto a = query();
    auto aaaa = query(28);
    auto txt = query(16);
    REQUIRE(!a.cache_key.empty());
    REQUIRE(a.cache_key != aaaa.cache_key && a.cache_key != txt.cache_key);
    auto mixed_wire = a.wire;
    mixed_wire[13] = 'E';
    write16(mixed_wire, 0, 999);
    auto mixed = parse_query(mixed_wire);
    REQUIRE(mixed && mixed->cache_key == a.cache_key);
    auto wire = answer(a);
    REQUIRE(valid_response(a, wire));
    REQUIRE(cache_ttl(a, wire) == 60);
    restore_question(*mixed, wire);
    REQUIRE(read16(wire, 0) == 999 && wire[13] == 'E');
    REQUIRE(valid_response(*mixed, wire));
    REQUIRE(!valid_response(a, wire));
    auto nx = error_response(a, 3);
    REQUIRE(valid_response(a, nx) && (read16(nx, 2) & 15) == 3 && read16(nx, 6) == 0);
    REQUIRE(cache_ttl(a, nx) == 0);
    auto empty = error_response(aaaa, 0);
    REQUIRE(valid_response(aaaa, empty) && read16(empty, 6) == 0);
    REQUIRE(cache_ttl(aaaa, empty) == 0);
    REQUIRE(cache_ttl(a, answer(a, 0)) == 0);
    REQUIRE(cache_ttl(a, answer(a, 0x80000001U)) == 0);
    auto wrong = answer(a);
    wrong[13] = 'z';
    REQUIRE(!valid_response(a, wrong));
    wrong = answer(a); write16(wrong, a.question.end - 2, 3);
    REQUIRE(!valid_response(a, wrong));
    wrong = answer(a); write16(wrong, a.question.end - 4, 28);
    REQUIRE(!valid_response(a, wrong));
    auto root_wire = Bytes{1,2,1,0,0,1,0,0,0,0,0,0,0,0,2,0,1};
    REQUIRE(parse_query(root_wire));
}
void edns_and_ttl() {
    auto q = query(1, true);
    REQUIRE(q.udp_limit == 1232 && !q.cache_key.empty());
    auto other = q.wire;
    write16(other, other.size() - 4, 0); // Clear DO; this must change the cache key.
    REQUIRE(parse_query(other)->cache_key != q.cache_key);
    other = q.wire; write16(other, 2, read16(other, 2) | 0x10);
    REQUIRE(parse_query(other)->cache_key != q.cache_key);
    other = q.wire; other.back() = 4;
    other.insert(other.end(), {0,10,0,0}); // EDNS cookie option; valid but not cacheable.
    REQUIRE(parse_query(other) && parse_query(other)->cache_key.empty());
    auto wire = answer(q, 5);
    size_t first_ttl = q.question.end + 6;
    append_rr(wire, 1, 90, Bytes{2,3,4,5});
    size_t second_ttl = q.question.end + 16 + 6;
    write16(wire, 10, 1);
    wire.insert(wire.end(), q.wire.end() - 11, q.wire.end());
    REQUIRE(cache_ttl(q, wire) == 5);
    uint32_t opt_ttl = read32(wire, wire.size() - 6);
    REQUIRE(age_response(wire, 3));
    REQUIRE(read32(wire, first_ttl) == 2 && read32(wire, second_ttl) == 87);
    REQUIRE(read32(wire, wire.size() - 6) == opt_ttl);
    REQUIRE(age_response(wire, 100) && read32(wire, first_ttl) == 0);
    auto chain = error_response(q, 0);
    const Bytes target{5,'a','l','i','a','s',7,'e','x','a','m','p','l','e',3,'c','o','m',0};
    append_rr(chain, 5, 10, target);
    append_rr(chain, 1, 60, Bytes{1,2,3,4});
    append_rr(chain, 1, 30, Bytes{5,6,7,8});
    REQUIRE(cache_ttl(q, chain) == 10 && read16(chain, 6) == 3);
    REQUIRE(fit_response(q, chain, 1232) == chain);
    auto large = answer(query(16), 60);
    large.resize(large.size() + 600, 0);
    auto truncated = fit_response(query(16), large, 1232);
    REQUIRE(truncated.size() <= 512 && (read16(truncated, 2) & 0x200));
    REQUIRE(read16(truncated, 6) == 0 && read16(truncated, 8) == 0 && read16(truncated, 10) == 0);
    REQUIRE(valid_response(query(16), truncated));
    auto edns_error = error_response(q, 0);
    append_rr(edns_error, 16, 60, Bytes(800, 0));
    write16(edns_error, 10, 1);
    edns_error.insert(edns_error.end(), q.wire.end() - 11, q.wire.end());
    write32(edns_error, edns_error.size() - 6, 0x01008000); // Extended RCODE plus DO.
    auto edns_truncated = fit_response(q, edns_error, 512);
    REQUIRE(valid_response(q, edns_truncated) && (read16(edns_truncated, 2) & 0x200));
    REQUIRE(read16(edns_truncated, 6) == 0 && read16(edns_truncated, 10) == 1);
    REQUIRE(read32(edns_truncated, edns_truncated.size() - 6) == 0x01008000);
}
void malformed_dns() {
    // A backward pointer can target a name embedded in binary label data.
    // Its expanded name is longer than the encoded question and must never
    // be copied over that question in place.
    Bytes compressed(12, 0);
    write16(compressed, 2, 0x0100);
    write16(compressed, 4, 1);
    compressed.insert(compressed.end(), {20, 18});
    compressed.insert(compressed.end(), 18, 'a');
    compressed.insert(compressed.end(), {0, 0xc0, 13, 0, 1, 0, 1});
    auto compressed_query = parse_query(compressed);
    REQUIRE(compressed_query && compressed_query->cache_key.empty());
    auto compressed_response = compressed;
    write16(compressed_response, 2, 0x8180);
    REQUIRE(valid_response(*compressed_query, compressed_response));
    auto preserved = compressed_response;
    REQUIRE(!restore_question(*compressed_query, compressed_response));
    REQUIRE(compressed_response == preserved);

    auto wire = query_wire();
    for (size_t length = 0; length < wire.size(); ++length) REQUIRE(!parse_query(View(wire).first(length)));
    auto bad = wire; write16(bad, 4, 2); REQUIRE(!parse_query(bad));
    bad = wire; bad[12] = 64; REQUIRE(!parse_query(bad));
    bad = wire; bad[12] = 0xc0; bad[13] = 12; REQUIRE(!parse_query(bad));
    bad = wire; bad[12] = 0xc0; bad[13] = 255; REQUIRE(!parse_query(bad));
    bad = wire; bad.push_back(0); REQUIRE(!parse_query(bad));
    bad = wire; write16(bad, 2, 0x8100); REQUIRE(!parse_query(bad));
    bad = Bytes(wire.begin(), wire.begin() + 12);
    for (int i = 0; i < 4; ++i) { bad.push_back(63); bad.insert(bad.end(), 63, 'a'); }
    bad.insert(bad.end(), {0,0,1,0,1}); REQUIRE(!parse_query(bad));
    auto q = query();
    auto response = answer(q);
    for (size_t length = 0; length < response.size(); ++length) REQUIRE(!valid_response(q, View(response).first(length)));
    response.back() = 5; REQUIRE(valid_response(q, response));
    write16(response, q.question.end + 10, 1000); REQUIRE(!valid_response(q, response));
    std::mt19937 generator(12345);
    for (size_t trial = 0; trial < 4000; ++trial) {
        Bytes random(generator() % 600);
        for (auto& c : random) c = static_cast<uint8_t>(generator());
        (void)parse_query(random);
        (void)valid_response(q, random);
        (void)parse_ipv4_udp(random);
    }
}
void cache_regressions() {
    auto table = std::make_unique<SharedDnsTable<16>>();
    auto a = query(), aaaa = query(28);
    auto ra = answer(a, 3), raaaa = answer(aaaa, 9);
    constexpr uint64_t now = 1000000000ULL;
    REQUIRE(table->insert(a.cache_key, ra, 3, now));
    REQUIRE(table->insert(aaaa.cache_key, raaaa, 9, now));
    Bytes out; uint32_t age = 0;
    REQUIRE(table->lookup(a.cache_key, out, now + 2000000000ULL, age) && out == ra && age == 2);
    REQUIRE(table->lookup(aaaa.cache_key, out, now + 2000000000ULL, age) && out == raaaa);
    REQUIRE(!table->lookup(a.cache_key, out, now + 3000000000ULL, age));
    REQUIRE(table->sweep_expired(now + 3000000000ULL) == 1);
    REQUIRE(table->lookup(aaaa.cache_key, out, now + 3000000000ULL, age));
    // Repeated updates must not consume additional ways in the same set.
    for (int i = 0; i < 100; ++i) REQUIRE(table->insert(aaaa.cache_key, raaaa, 9, now));
    for (uint8_t i = 0; i < 15; ++i) REQUIRE(table->insert(Bytes{i}, Bytes(12, i), 10, now));
    REQUIRE(table->lookup(aaaa.cache_key, out, now, age));
    for (uint8_t i = 0; i < 15; ++i) REQUIRE(table->lookup(Bytes{i}, out, now, age));
    REQUIRE(!table->insert(a.cache_key, ra, 0, now));
    REQUIRE(!table->insert(Bytes(513), ra, 2, now));
    REQUIRE(!table->insert(a.cache_key, Bytes(4097), 2, now));
    REQUIRE(reinterpret_cast<uintptr_t>(table.get()) % 64 == 0);
    REQUIRE(reinterpret_cast<uintptr_t>(table->header()) % 64 == 0);
    std::atomic<bool> failed{false};
    std::vector<std::jthread> threads;
    for (uint8_t t = 0; t < 4; ++t) threads.emplace_back([&, t] {
        for (unsigned i = 0; i < 500; ++i) {
            Bytes value(256, static_cast<uint8_t>(i + t));
            table->insert(Bytes{99}, value, 10, now);
            Bytes snapshot; uint32_t seconds = 0;
            if (!table->lookup(Bytes{99}, snapshot, now, seconds) || snapshot.size() != 256 ||
                !std::all_of(snapshot.begin(), snapshot.end(), [&](uint8_t c) { return c == snapshot.front(); })) failed = true;
        }
    });
    threads.clear();
    REQUIRE(!failed);
}
void shared_process_cache() {
    using Table = SharedDnsTable<16>;
    void* region = mmap(nullptr, sizeof(Table), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    REQUIRE(region != MAP_FAILED);
    auto* table = new(region) Table;
    pid_t pid = fork();
    REQUIRE(pid >= 0);
    if (pid == 0) {
        bool ok = table->insert(Bytes{1,2,3}, Bytes(12, 7), 10, 100);
        _exit(ok ? 0 : 1);
    }
    int status = 0;
    REQUIRE(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    Bytes value; uint32_t age = 0;
    REQUIRE(table->lookup(Bytes{1,2,3}, value, 101, age) && value == Bytes(12, 7));
    REQUIRE(munmap(region, sizeof(Table)) == 0);
}
void packet_regressions() {
    for (bool options : {false, true}) {
        auto request = ethernet_query(query_wire(), options);
        auto parsed = parse_ipv4_udp(request);
        REQUIRE(parsed && parsed->dns == query_wire());
        auto response = answer(query());
        auto reply = build_ipv4_reply(*parsed, response);
        REQUIRE(reply.size() == 42 + response.size() && reply[14] == 0x45);
        REQUIRE(std::equal(reply.begin(), reply.begin() + 6, request.begin() + 6));
        REQUIRE(read16(reply, 34) == 53 && read16(reply, 36) == 53000);
        REQUIRE(checksum(View(reply).subspan(14, 20)) == 0);
        uint32_t pseudo = 17 + read16(reply, 38);
        for (size_t i = 26; i < 34; i += 2) pseudo += read16(reply, i);
        REQUIRE(checksum(View(reply).subspan(34), pseudo) == 0);
        REQUIRE(std::equal(response.begin(), response.end(), reply.begin() + 42));
        // Reverse ports to test validation of the nonzero UDP checksum we generated.
        std::swap(reply[34], reply[36]); std::swap(reply[35], reply[37]);
        REQUIRE(parse_ipv4_udp(reply));
        reply.back() ^= 1; REQUIRE(!parse_ipv4_udp(reply));
    }
    auto wire = ethernet_query(query_wire());
    for (size_t length = 0; length < wire.size(); ++length) REQUIRE(!parse_ipv4_udp(View(wire).first(length)));
    auto bad = wire; write16(bad, 20, 0x2000); fix_ip_checksum(bad); REQUIRE(!parse_ipv4_udp(bad));
    bad = wire; write16(bad, 20, 1); fix_ip_checksum(bad); REQUIRE(!parse_ipv4_udp(bad));
    bad = wire; write16(bad, 38, 65535); REQUIRE(!parse_ipv4_udp(bad));
    bad = wire; write16(bad, 16, 27); fix_ip_checksum(bad); REQUIRE(!parse_ipv4_udp(bad));
    bad = wire; bad[14] = 0x44; REQUIRE(!parse_ipv4_udp(bad));
    bad = wire; bad[24] ^= 1; REQUIRE(!parse_ipv4_udp(bad));
    PacketError error = PacketError::none;
    REQUIRE(!parse_ipv4_udp(bad, &error) && error == PacketError::ipv4_checksum);
    // A virtual sender can leave only the pseudo-header seed in the checksum
    // field. AF_XDP loses CHECKSUM_PARTIAL metadata, so strict parsing must
    // reject it until sender TX offload is disabled and the checksum completed.
    auto partial = ethernet_query(query_wire());
    uint32_t pseudo = 17 + read16(partial, 38);
    uint16_t seed = static_cast<uint16_t>(~checksum(View(partial).subspan(26, 8), pseudo));
    write16(partial, 40, seed);
    REQUIRE(!parse_ipv4_udp(partial, &error) && error == PacketError::udp_checksum);
    for (size_t i = 26; i < 34; i += 2) pseudo += read16(partial, i);
    write16(partial, 40, 0);
    uint16_t completed = checksum(View(partial).subspan(34), pseudo);
    write16(partial, 40, completed ? completed : 65535);
    REQUIRE(parse_ipv4_udp(partial, &error) && error == PacketError::none);
    REQUIRE(!parse_ipv4_udp(View{}, &error) && error == PacketError::malformed);
    wire.insert(wire.end(), 10, 0xaa); // Ethernet padding must not be forwarded as DNS.
    REQUIRE(parse_ipv4_udp(wire)->dns == query_wire());
}
void queue_and_rings() {
    BoundedQueue<int> queue(1);
    REQUIRE(queue.try_push(1) && !queue.try_push(2));
    int item = 0; REQUIRE(queue.try_pop(item) && item == 1);
    REQUIRE(queue.try_push(3));
    auto blocked = std::async(std::launch::async, [&] { return queue.push_wait(4); });
    queue.close();
    REQUIRE(!blocked.get() && !queue.pop_wait(item) && !queue.try_push(5));
#ifdef NET_ACCEL_XDP
    uint32_t producer = 0, consumer = 0, flags = 0;
    // Match libxdp's __u64 type; uint64_t can have a different aliasing type.
    std::array<__u64, 4> storage{};
    xsk_ring_prod ring{};
    ring.cached_cons = 4; ring.mask = 3; ring.size = 4;
    ring.producer = &producer; ring.consumer = &consumer; ring.flags = &flags; ring.ring = storage.data();
    std::deque<uint64_t> frames{0,4096,8192,12288,16384,20480};
    REQUIRE(refill_frames(ring, frames) == 4 && frames.size() == 2 && producer == 4);
    REQUIRE(refill_frames(ring, frames) == 0 && frames.size() == 2);
    consumer = 2;
    REQUIRE(refill_frames(ring, frames) == 2 && frames.empty() && producer == 6);
    REQUIRE(storage[0] == 16384 && storage[1] == 20480);
    std::array<xdp_desc, 4> descriptors{};
    ring.ring = descriptors.data();
    std::deque<PendingTx> pending{{123,45},{678,90},{1000,100}};
    REQUIRE(submit_frames(ring, pending) == 0 && pending.size() == 3);
    consumer = 4;
    REQUIRE(submit_frames(ring, pending) == 2 && pending.size() == 1);
    REQUIRE(descriptors[2].addr == 123 && descriptors[2].len == 45 && descriptors[3].addr == 678);
    consumer = 5;
    REQUIRE(submit_frames(ring, pending) == 1 && pending.empty());
#endif
}

class Socket {
public:
    explicit Socket(int type) : fd(socket(AF_INET, type | SOCK_CLOEXEC, 0)) {
        if (fd < 0) throw std::runtime_error("local test socket: " + std::string(std::strerror(errno)));
        timeval timeout{2, 0};
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    }
    ~Socket() { close(fd); }
    sockaddr_in bind_local(uint16_t port = 0) {
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        address.sin_port = port;
        REQUIRE(bind(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0);
        socklen_t length = sizeof(address);
        REQUIRE(getsockname(fd, reinterpret_cast<sockaddr*>(&address), &length) == 0);
        return address;
    }
    int fd;
};
std::pair<Bytes, sockaddr_in> receive_query(int fd) {
    Bytes wire(65535);
    sockaddr_in peer{};
    socklen_t length = sizeof(peer);
    ssize_t count = recvfrom(fd, wire.data(), wire.size(), 0, reinterpret_cast<sockaddr*>(&peer), &length);
    REQUIRE(count >= 12);
    wire.resize(static_cast<size_t>(count));
    return {wire, peer};
}
void send_reply(int fd, View wire, const sockaddr_in& peer) {
    REQUIRE(sendto(fd, wire.data(), wire.size(), 0, reinterpret_cast<const sockaddr*>(&peer), sizeof(peer)) ==
            static_cast<ssize_t>(wire.size()));
}
void upstream_validation() {
    Socket server(SOCK_DGRAM);
    auto address = server.bind_local();
    auto responder = std::async(std::launch::async, [&] {
        auto [wire, peer] = receive_query(server.fd);
        auto q = parse_query(wire); REQUIRE(q);
        auto valid = answer(*q);
        auto wrong = valid;
        write16(wrong, 0, read16(valid, 0) + 1);
        send_reply(server.fd, wrong, peer);
        wrong = valid; wrong[13] = 'z';
        send_reply(server.fd, wrong, peer);
        Socket impostor(SOCK_DGRAM);
        auto spoofed = answer(*q, 999);
        send_reply(impostor.fd, spoofed, peer);
        send_reply(server.fd, valid, peer);
    });
    auto q = query();
    auto result = resolve_upstream(q, address, 1500);
    responder.get();
    REQUIRE(result && *result == answer(q));
    // A silent peer must terminate at the configured deadline.
    auto start = std::chrono::steady_clock::now();
    REQUIRE(!resolve_upstream(q, address, 30));
    REQUIRE(std::chrono::steady_clock::now() - start < std::chrono::seconds(1));
}
void named_cache_attachment() {
    using Table = SharedDnsTable<16>;
    const std::string path = "/net_accel_dns_test_" + std::to_string(getpid()) + "_" + std::to_string(monotonic_ns());
    struct Cleanup {
        std::string path;
        ~Cleanup() { shm_unlink(path.c_str()); }
    } cleanup{path};
    using Mapping = std::unique_ptr<Table, decltype(&Table::unmap)>;
    Mapping first(Table::create_or_attach(true, path.c_str()), &Table::unmap);
    auto q = query();
    auto response = answer(q);
    REQUIRE(first->insert(q.cache_key, response, 60, 100));
    Mapping second(Table::create_or_attach(false, path.c_str()), &Table::unmap);
    Bytes out; uint32_t age = 0;
    REQUIRE(second->lookup(q.cache_key, out, 101, age) && out == response);
    Mapping third(Table::create_or_attach(true, path.c_str()), &Table::unmap);
    REQUIRE(third->lookup(q.cache_key, out, 102, age) && out == response);
    REQUIRE(first->header()->cache_hits == 2); // Attach must not reset metrics or entries.
    bool rejected = false;
    try { auto* wrong = SharedDnsTable<32>::create_or_attach(false, path.c_str()); SharedDnsTable<32>::unmap(wrong); }
    catch (const std::runtime_error&) { rejected = true; }
    REQUIRE(rejected);
    first->header()->magic_identifier ^= 1;
    rejected = false;
    try { auto* wrong = Table::create_or_attach(false, path.c_str()); Table::unmap(wrong); }
    catch (const std::runtime_error&) { rejected = true; }
    REQUIRE(rejected);
    first->header()->magic_identifier = Table::SHM_MAGIC;
    int fd = shm_open(path.c_str(), O_RDWR | O_CLOEXEC, 0);
    REQUIRE(fd >= 0 && fchmod(fd, 0666) == 0);
    rejected = false;
    try { auto* wrong = Table::create_or_attach(false, path.c_str()); Table::unmap(wrong); }
    catch (const std::runtime_error&) { rejected = true; }
    int restored = fchmod(fd, 0600);
    close(fd);
    REQUIRE(rejected && restored == 0);
}
void tcp_fallback() {
    Socket udp(SOCK_DGRAM), tcp(SOCK_STREAM);
    auto address = udp.bind_local();
    tcp.bind_local(address.sin_port);
    REQUIRE(listen(tcp.fd, 1) == 0);
    auto responder = std::async(std::launch::async, [&] {
        auto [wire, peer] = receive_query(udp.fd);
        auto q = parse_query(wire); REQUIRE(q);
        auto truncated = error_response(*q, 0);
        write16(truncated, 2, read16(truncated, 2) | 0x0200);
        write16(truncated, 6, 1); // Deliberately incomplete RR: still triggers TCP.
        truncated.push_back(0xc0);
        send_reply(udp.fd, truncated, peer);
        pollfd item{tcp.fd, POLLIN, 0};
        REQUIRE(poll(&item, 1, 2000) == 1);
        int client = accept4(tcp.fd, nullptr, nullptr, SOCK_CLOEXEC);
        REQUIRE(client >= 0);
        timeval timeout{2, 0};
        setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        Bytes prefix(2);
        if (recv(client, prefix.data(), 2, MSG_WAITALL) != 2) { close(client); throw std::runtime_error("TCP length missing"); }
        Bytes request(read16(prefix, 0));
        if (recv(client, request.data(), request.size(), MSG_WAITALL) != static_cast<ssize_t>(request.size())) {
            close(client); throw std::runtime_error("TCP query missing");
        }
        auto parsed = parse_query(request);
        if (!parsed) { close(client); throw std::runtime_error("bad TCP query"); }
        auto full = answer(*parsed, 90);
        Bytes payload(full.size() + 2);
        write16(payload, 0, full.size());
        std::copy(full.begin(), full.end(), payload.begin() + 2);
        ssize_t sent = send(client, payload.data(), payload.size(), MSG_NOSIGNAL);
        close(client);
        REQUIRE(sent == static_cast<ssize_t>(payload.size()));
    });
    auto q = query(28, true);
    auto result = resolve_upstream(q, address, 1500);
    responder.get();
    REQUIRE(result && *result == answer(q, 90) && !(read16(*result, 2) & 0x0200));
    // With no TCP listener, return a clean TC response instead of partial data.
    Socket udp_only(SOCK_DGRAM);
    address = udp_only.bind_local();
    auto fallback = std::async(std::launch::async, [&] {
        auto [wire, peer] = receive_query(udp_only.fd);
        auto parsed = parse_query(wire); REQUIRE(parsed);
        auto partial = error_response(*parsed, 0);
        write16(partial, 2, read16(partial, 2) | 0x200);
        write16(partial, 6, 100);
        partial.push_back(0xc0);
        send_reply(udp_only.fd, partial, peer);
    });
    result = resolve_upstream(q, address, 200);
    fallback.get();
    REQUIRE(result && valid_response(q, *result) && (read16(*result, 2) & 0x200) && read16(*result, 6) == 0);
}
void upstream_transport_fallback() {
    for (auto transport : {UpstreamTransport::automatic, UpstreamTransport::tcp}) {
        Socket udp(SOCK_DGRAM), tcp(SOCK_STREAM);
        auto address = udp.bind_local();
        tcp.bind_local(address.sin_port);
        REQUIRE(listen(tcp.fd, 1) == 0);
        auto responder = std::async(std::launch::async, [&] {
            pollfd item{tcp.fd, POLLIN, 0};
            REQUIRE(poll(&item, 1, 2000) == 1);
            int client = accept4(tcp.fd, nullptr, nullptr, SOCK_CLOEXEC);
            REQUIRE(client >= 0);
            struct Close { int fd; ~Close() { close(fd); } } cleanup{client};
            timeval timeout{2, 0};
            REQUIRE(setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
            Bytes prefix(2);
            REQUIRE(recv(client, prefix.data(), 2, MSG_WAITALL) == 2);
            Bytes request(read16(prefix, 0));
            REQUIRE(recv(client, request.data(), request.size(), MSG_WAITALL) == static_cast<ssize_t>(request.size()));
            auto parsed = parse_query(request); REQUIRE(parsed);
            auto full = answer(*parsed);
            Bytes payload(full.size() + 2);
            write16(payload, 0, full.size());
            std::copy(full.begin(), full.end(), payload.begin() + 2);
            REQUIRE(send(client, payload.data(), payload.size(), MSG_NOSIGNAL) == static_cast<ssize_t>(payload.size()));
        });
        auto original = query();
        bool timed_out = true;
        auto started = std::chrono::steady_clock::now();
        auto response = resolve_upstream(original, address, 1000, &timed_out, transport);
        responder.get();
        REQUIRE(response && *response == answer(original) && !timed_out);
        REQUIRE(std::chrono::steady_clock::now() - started < std::chrono::seconds(2));
        pollfd input{udp.fd, POLLIN, 0};
        REQUIRE(poll(&input, 1, 0) == (transport == UpstreamTransport::automatic ? 1 : 0));
    }
    // Explicit UDP mode waits for UDP without probing a TCP listener.
    Socket silent(SOCK_DGRAM);
    bool timed_out = false;
    REQUIRE(!resolve_upstream(query(), silent.bind_local(), 30, &timed_out, UpstreamTransport::udp));
    REQUIRE(timed_out);
}
void coalescing() {
    Socket server(SOCK_DGRAM);
    auto address = server.bind_local();
    std::promise<void> seen, release;
    auto gate = release.get_future();
    auto responder = std::async(std::launch::async, [&] {
        auto [wire, peer] = receive_query(server.fd);
        auto parsed = parse_query(wire); REQUIRE(parsed);
        seen.set_value();
        REQUIRE(gate.wait_for(std::chrono::seconds(3)) == std::future_status::ready);
        send_reply(server.fd, answer(*parsed), peer);
    });
    auto cache = std::make_unique<SharedDnsTable<>>();
    ResolverService service(cache.get(), address, 1232, 2, [] {});
    std::vector<Bytes> requests;
    for (unsigned i = 0; i < 34; ++i) {
        auto wire = query_wire();
        write16(wire, 0, i);
        if (i & 1) wire[13] = 'E';
        requests.push_back(wire);
        auto packet = parse_ipv4_udp(ethernet_query(wire)); REQUIRE(packet);
        service.submit(std::move(*packet));
        if (i == 0) REQUIRE(seen.get_future().wait_for(std::chrono::seconds(2)) == std::future_status::ready);
    }
    REQUIRE(service.metrics.coalesced == 32 && service.metrics.overloaded == 1);
    release.set_value();
    responder.get();
    unsigned replies = 0, failures = 0;
    std::array<bool, 34> ids{};
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    while (replies < 34 && std::chrono::steady_clock::now() < deadline) {
        Bytes frame;
        if (!service.try_response(frame)) { std::this_thread::yield(); continue; }
        View wire = View(frame).subspan(42);
        auto id = read16(wire, 0);
        REQUIRE(id < requests.size() && !ids[id]);
        ids[id] = true;
        REQUIRE(std::equal(requests[id].begin() + 12, requests[id].end(), wire.begin() + 12));
        if ((read16(wire, 2) & 15) == 2) ++failures;
        ++replies;
    }
    REQUIRE(replies == 34 && failures == 1 && service.metrics.forwarded == 1);
    REQUIRE(service.metrics.inflight_groups == 0 && service.metrics.inflight_waiters == 0);
    // A later request gets the shared cached answer with its own ID/case.
    service.submit(*parse_ipv4_udp(ethernet_query(requests[1])));
    Bytes frame;
    REQUIRE(service.try_response(frame) && service.metrics.hits == 1);
    REQUIRE(read16(View(frame).subspan(42), 0) == 1);
    service.stop();
}
void metrics_http() {
    auto cache = std::make_unique<SharedDnsTable<>>();
    ResolverService service(cache.get(), upstream_address("127.0.0.1"), 1232, 1, [] {});
    KernelMetrics kernel;
    kernel.xdp_unauthorized = 7;
    auto metrics = std::make_unique<MetricsServer>(service, kernel, 0);
    auto scrape = [&](const char* request) {
        Socket client(SOCK_STREAM);
        sockaddr_in address = upstream_address("127.0.0.1:" + std::to_string(metrics->port()));
        REQUIRE(connect(client.fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0);
        timeval timeout{2, 0};
        REQUIRE(setsockopt(client.fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
        REQUIRE(send(client.fd, request, std::strlen(request), MSG_NOSIGNAL) == static_cast<ssize_t>(std::strlen(request)));
        std::string result;
        char buffer[2048];
        ssize_t count;
        while ((count = recv(client.fd, buffer, sizeof(buffer), 0)) > 0) result.append(buffer, count);
        REQUIRE(count == 0);
        return result;
    };
    auto response = scrape("GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n");
    REQUIRE(response.starts_with("HTTP/1.1 200 OK"));
    REQUIRE(response.find("net_accel_dns_xdp_unauthorized_total 7\n") != std::string::npos);
    REQUIRE(response.find("net_accel_dns_job_queue_depth 0\n") != std::string::npos);
    REQUIRE(response.find("net_accel_dns_processing_seconds_bucket{le=\"+Inf\"}") != std::string::npos);
    REQUIRE(scrape("POST /metrics HTTP/1.1\r\n\r\n").starts_with("HTTP/1.1 400 Bad Request"));
    auto port = metrics->port();
    metrics.reset();
    metrics = std::make_unique<MetricsServer>(service, kernel, port);
    REQUIRE(scrape("GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n").starts_with("HTTP/1.1 200 OK"));
}
void service_integration() {
    Socket server(SOCK_DGRAM);
    auto address = server.bind_local();
    auto responder = std::async(std::launch::async, [&] {
        for (int i = 0; i < 6; ++i) {
            auto [wire, peer] = receive_query(server.fd);
            auto q = parse_query(wire); REQUIRE(q);
            Bytes response;
            if (q->wire[13] == 'z') response = error_response(*q, 3);
            else if (q->wire[13] == 'n') response = error_response(*q, 0);
            else if (q->question.type == 16) {
                response = error_response(*q, 0);
                append_rr(response, 16, 60, Bytes{4,'t','e','s','t'});
            } else response = answer(*q, 60);
            send_reply(server.fd, response, peer);
        }
    });
    auto cache = std::make_unique<SharedDnsTable<>>();
    std::mutex mutex;
    std::condition_variable ready;
    ResolverService service(cache.get(), address, 1232, 2, [&] { std::lock_guard lock(mutex); ready.notify_one(); });
    auto resolve = [&](const Bytes& wire) {
        auto packet = parse_ipv4_udp(ethernet_query(wire)); REQUIRE(packet);
        service.submit(std::move(*packet));
        Bytes result;
        std::unique_lock lock(mutex);
        REQUIRE(ready.wait_for(lock, std::chrono::seconds(3), [&] { return service.try_response(result); }));
        REQUIRE(result.size() >= 54);
        return Bytes(result.begin() + 42, result.end());
    };
    auto a = query();
    REQUIRE(resolve(a.wire) == answer(a));
    auto changed = a.wire;
    write16(changed, 0, 999); changed[13] = 'E';
    auto case_query = parse_query(changed); REQUIRE(case_query);
    auto expected = answer(a); restore_question(*case_query, expected);
    REQUIRE(resolve(changed) == expected);
    REQUIRE(service.metrics.hits == 1 && service.metrics.forwarded == 1);
    auto aaaa = query(28);
    REQUIRE(resolve(aaaa.wire) == answer(aaaa));
    auto txt = query(16);
    auto text_response = resolve(txt.wire);
    REQUIRE(valid_response(txt, text_response) && read16(text_response, 6) == 1 && text_response.back() == 't');
    auto missing = a.wire; missing[13] = 'z';
    REQUIRE((read16(resolve(missing), 2) & 15) == 3);
    REQUIRE((read16(resolve(missing), 2) & 15) == 3); // Negative answers are forwarded, not fabricated or cached.
    auto nodata = a.wire; nodata[13] = 'n';
    auto empty = resolve(nodata);
    REQUIRE(read16(empty, 6) == 0 && (read16(empty, 2) & 15) == 0);
    responder.get();
    // Refused upstream connections produce SERVFAIL, and destruction joins workers.
    Socket absent(SOCK_DGRAM);
    auto refused = absent.bind_local();
    close(absent.fd); absent.fd = -1;
    ResolverService failed(cache.get(), refused, 1232, 1, [] {});
    auto packet = parse_ipv4_udp(ethernet_query(a.wire)); REQUIRE(packet);
    failed.submit(std::move(*packet));
    Bytes failure;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (!failed.try_response(failure) && std::chrono::steady_clock::now() < deadline) std::this_thread::yield();
    REQUIRE(!failure.empty() && (read16(View(failure).subspan(42), 2) & 15) == 2);
}
} // namespace
int main(int argc, char**) {
    try {
        if (argc > 1) {
            named_cache_attachment();
            upstream_validation();
            tcp_fallback();
            service_integration();
            upstream_transport_fallback();
            coalescing();
            metrics_http();
            std::cout << "Upstream validation, TCP fallback and resolver integration passed\n";
            return 0;
        }
        queries_and_answers();
        edns_and_ttl();
        malformed_dns();
        cache_regressions();
        shared_process_cache();
        packet_regressions();
        queue_and_rings();
        std::cout << "DNS, cache, process sharing, packet, queue and ring regressions passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
