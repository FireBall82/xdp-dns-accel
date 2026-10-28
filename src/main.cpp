#include "resolver_service.hpp"
#include "process_security.hpp"
#include "runtime_metrics.hpp"
#ifdef NET_ACCEL_XDP
#include "common_structs.h"
#include "xsk_rings.hpp"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#endif
#include <algorithm>
#include <arpa/inet.h>
#include <charconv>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <memory>
#include <net/if.h>
#include <poll.h>
#include <stdexcept>
#include <string>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <fcntl.h>
#include <set>
#include <bit>
#include <unistd.h>

namespace {
using namespace net_accel;
volatile sig_atomic_t exiting = 0;
void signal_handler(int) { exiting = 1; }
#ifdef NET_ACCEL_XDP
constexpr uint32_t num_frames = 4096;
constexpr uint32_t frame_size = XSK_UMEM__DEFAULT_FRAME_SIZE;
constexpr uint32_t rx_frames = 2048;
constexpr uint32_t batch_size = 64;
static_assert(rx_frames < num_frames);

void check(int result, const char* operation) {
    if (result) throw std::runtime_error(std::string(operation) + ": " + std::strerror(result < 0 ? -result : result));
}
#endif
unsigned number(std::string_view text, unsigned maximum) {
    unsigned result = 0;
    auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), result);
    if (error != std::errc{} || end != text.data() + text.size() || result > maximum)
        throw std::invalid_argument("invalid numeric option");
    return result;
}
std::filesystem::path default_bpf_path() {
    auto executable = std::filesystem::canonical("/proc/self/exe").parent_path();
    auto adjacent = executable / "xdp_filter.bpf.o";
    if (std::filesystem::exists(adjacent)) return adjacent;
    return executable / "../libexec/net_accel_dns/xdp_filter.bpf.o";
}
struct Options {
    bool socket_mode = false;
    bool check_config = false;
    std::string bind = "127.0.0.1:53";
    std::vector<ForwardZone> forward_zones;
    std::string interface;
    std::string upstream = "1.1.1.1:53";
    std::string cache_name = SharedDnsTable<>::SHM_PATH;
    std::filesystem::path bpf;
    unsigned workers = 4;
    unsigned queue = 0;
    bool native = false;
    bool zero_copy = false;
    RequestPolicyConfig policy;
    std::string run_as;
    unsigned metrics_port = 0;
    UpstreamTransport transport = UpstreamTransport::automatic;
    std::string transport_name = "auto";
};
void usage(const char* executable) {
    std::cout << "Usage: " << executable << " <interface> [--upstream IPv4[:port]] [--workers 1..64]\n"
                 "       [--queue 0..63] [--bpf-object path] [--cache-name /name]\n"
                 "       [--xdp-mode generic|native] [--xsk-mode copy|zero-copy]\n"
                 "       [--allow-client IPv4[/prefix]]... [--rate-limit 0..1000000]\n"
                 "       [--upstream-transport auto|udp|tcp]\n"
                 "       [--client-rate-limit 0..1000000]\n"
                 "       [--listen-address IPv4] [--network-rate-limit IPv4/prefix:qps]...\n"
                 "       [--reserve-client IPv4:qps]... [--run-as user] [--metrics-port 1024..65535]\n"
                 "       or: dns_daemon --mode socket [--bind 127.0.0.1:port] [options]\n"
                 "       --check-config validates options without opening sockets or loading BPF.\n"
                 "       [--forward-zone domain=IPv4[:port]]... (longest matching domain wins)\n"
                 "Defaults to generic XDP and AF_XDP copy; zero-copy requires native XDP.\n";
}
Options options(int argc, char** argv) {
    if (argc < 2) throw std::invalid_argument("an interface or --mode socket is required (see --help)");
    Options result;
    int first = 1;
    if (!std::string_view(argv[1]).starts_with("--")) { result.interface = argv[1]; first = 2; }
    bool xdp_option = false;
    bool bind_option = false;
    for (int i = first; i < argc; i += 2) {
        if (std::string_view(argv[i]) == "--check-config") { result.check_config = true; --i; continue; }
        if (i + 1 >= argc) throw std::invalid_argument("missing option value");
        std::string_view option = argv[i];
        if (option == "--mode") {
            std::string_view mode = argv[i + 1];
            if (mode != "socket" && mode != "xdp") throw std::invalid_argument("mode must be socket or xdp");
            result.socket_mode = mode == "socket";
        } else if (option == "--bind") { result.bind = argv[i + 1]; bind_option = true; }
        else if (option == "--upstream") result.upstream = argv[i + 1];
        else if (option == "--forward-zone") {
            if (result.forward_zones.size() == 128) throw std::invalid_argument("at most 128 forward zones");
            result.forward_zones.push_back(forward_zone(argv[i + 1]));
        }
        else if (option == "--upstream-transport") {
            result.transport_name = argv[i + 1];
            if (result.transport_name == "auto") result.transport = UpstreamTransport::automatic;
            else if (result.transport_name == "udp") result.transport = UpstreamTransport::udp;
            else if (result.transport_name == "tcp") result.transport = UpstreamTransport::tcp;
            else throw std::invalid_argument("upstream transport must be auto, udp or tcp");
        }
        else if (option == "--workers") {
            result.workers = number(argv[i + 1], 64);
            if (!result.workers) throw std::invalid_argument("at least one worker is required");
        } else if (option == "--queue") { result.queue = number(argv[i + 1], 63); xdp_option = true; }
        else if (option == "--xdp-mode") {
            std::string_view mode = argv[i + 1];
            if (mode != "generic" && mode != "native") throw std::invalid_argument("XDP mode must be generic or native");
            result.native = mode == "native";
            xdp_option = true;
        } else if (option == "--xsk-mode") {
            std::string_view mode = argv[i + 1];
            if (mode != "copy" && mode != "zero-copy") throw std::invalid_argument("XSK mode must be copy or zero-copy");
            result.zero_copy = mode == "zero-copy";
            xdp_option = true;
        } else if (option == "--bpf-object") { result.bpf = argv[i + 1]; xdp_option = true; }
        else if (option == "--allow-client") {
            if (result.policy.allowed_clients.size() == 64) throw std::invalid_argument("at most 64 allowed client networks");
            result.policy.allowed_clients.push_back(Ipv4Cidr::parse(argv[i + 1]));
        } else if (option == "--rate-limit") result.policy.global_qps = number(argv[i + 1], RequestPolicy::max_qps);
        else if (option == "--client-rate-limit") result.policy.client_qps = number(argv[i + 1], RequestPolicy::max_qps);
        else if (option == "--listen-address") {
            std::string_view value = argv[i + 1];
            if (value.find('/') != std::string_view::npos) throw std::invalid_argument("listen address must be an IPv4 host");
            auto address = Ipv4Cidr::parse(value).network;
            if (!address || (address >> 24) >= 224) throw std::invalid_argument("listen address must be unicast IPv4");
            result.policy.listen_address = address;
        } else if (option == "--network-rate-limit" || option == "--reserve-client") {
            std::string_view value = argv[i + 1];
            auto colon = value.find(':');
            if (colon == std::string_view::npos) throw std::invalid_argument("budget must be IPv4[/prefix]:qps");
            auto network = Ipv4Cidr::parse(value.substr(0, colon));
            unsigned rate = number(value.substr(colon + 1), RequestPolicy::max_qps);
            if (!rate) throw std::invalid_argument("budget rate must be positive");
            if (option == "--reserve-client") {
                if (network.mask != 0xffffffffU) throw std::invalid_argument("reserved client must be a single IPv4 host");
                if (result.policy.reserved_clients.size() == 64) throw std::invalid_argument("at most 64 reserved clients");
                result.policy.reserved_clients.push_back({network.network, rate});
            } else {
                if (result.policy.network_budgets.size() == 64) throw std::invalid_argument("at most 64 network budgets");
                result.policy.network_budgets.push_back({network, rate});
            }
        } else if (option == "--run-as") result.run_as = argv[i + 1];
        else if (option == "--metrics-port") {
            result.metrics_port = number(argv[i + 1], 65535);
            if (result.metrics_port < 1024) throw std::invalid_argument("metrics port must be 1024..65535");
        }
        else if (option == "--cache-name") {
            result.cache_name = argv[i + 1];
            if (result.cache_name.size() < 2 || result.cache_name.size() > 240 || result.cache_name[0] != '/' ||
                result.cache_name.find('/', 1) != std::string::npos)
                throw std::invalid_argument("cache name must be /name without additional slashes");
        }
        else throw std::invalid_argument("unknown option: " + std::string(option));
    }
    if (result.zero_copy && !result.native) throw std::invalid_argument("zero-copy requires --xdp-mode native");
    std::set<Bytes> zones;
    for (const auto& zone : result.forward_zones)
        if (!zones.insert(zone.suffix).second) throw std::invalid_argument("duplicate forward zone");
    if (result.socket_mode) {
        auto address = upstream_address(result.bind);
        if (ntohl(address.sin_addr.s_addr) != INADDR_LOOPBACK)
            throw std::invalid_argument("socket mode binds only to 127.0.0.1");
        if (!result.interface.empty() || xdp_option) throw std::invalid_argument("socket mode does not accept XDP options or an interface");
        if (result.policy.listen_address && *result.policy.listen_address != INADDR_LOOPBACK)
            throw std::invalid_argument("socket listen address must be 127.0.0.1");
        auto upstream = upstream_address(result.upstream);
        if (upstream.sin_addr.s_addr == address.sin_addr.s_addr && upstream.sin_port == address.sin_port)
            throw std::invalid_argument("upstream cannot be the socket listener");
        for (const auto& zone : result.forward_zones)
            if (zone.address.sin_addr.s_addr == address.sin_addr.s_addr && zone.address.sin_port == address.sin_port)
                throw std::invalid_argument("forward zone cannot target the socket listener");
    } else {
        if (result.interface.empty()) throw std::invalid_argument("an interface is required for XDP mode");
        if (bind_option) throw std::invalid_argument("--bind requires --mode socket");
    }
    RequestPolicy validate(result.policy);
    if (result.bpf.empty()) result.bpf = default_bpf_path();
    return result;
}

class Runtime {
public:
    bool socket_mode = false;
    int udp_fd = -1;
#ifdef NET_ACCEL_XDP
    bpf_object* object = nullptr;
    xsk_umem* umem = nullptr;
    xsk_socket* socket = nullptr;
    void* buffer = nullptr;
    xsk_ring_prod fill{}, tx{};
    xsk_ring_cons completion{}, rx{};
    int ifindex = 0;
    int program_fd = -1;
    int map_fd = -1;
    uint32_t queue = 0;
    bool mapped = false;
    bool attached = false;
    uint32_t xdp_flags = XDP_FLAGS_SKB_MODE;
    bool zero_copy = false;
#endif
    int notify = -1;
    size_t maximum_dns = 1232;

    ~Runtime() {
#ifdef NET_ACCEL_XDP
        if (mapped) bpf_map_delete_elem(map_fd, &queue);
        if (attached) {
            bpf_xdp_attach_opts opts{};
            opts.sz = sizeof(opts);
            opts.old_prog_fd = program_fd;
            int result = bpf_xdp_detach(ifindex, xdp_flags, &opts);
            if (result) std::cerr << "Could not detach owned XDP hook: " << std::strerror(-result) << '\n';
        }
        if (socket) xsk_socket__delete(socket);
        if (umem) xsk_umem__delete(umem);
        if (buffer) munmap(buffer, num_frames * frame_size);
        if (object) bpf_object__close(object);
#endif
        if (udp_fd >= 0) close(udp_fd);
        if (notify >= 0) close(notify);
    }
    void initialize(const Options& opts) {
        socket_mode = opts.socket_mode;
        notify = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
        if (notify < 0) throw std::runtime_error("eventfd failed");
        if (socket_mode) {
            auto address = upstream_address(opts.bind);
            udp_fd = ::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
            if (udp_fd < 0 || bind(udp_fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)))
                throw std::runtime_error("bind localhost UDP: " + std::string(std::strerror(errno)));
            return;
        }
#ifdef NET_ACCEL_XDP
        queue = opts.queue;
        xdp_flags = opts.native ? XDP_FLAGS_DRV_MODE : XDP_FLAGS_SKB_MODE;
        ifindex = static_cast<int>(if_nametoindex(opts.interface.c_str()));
        if (!ifindex) throw std::invalid_argument("interface not found: " + opts.interface);
        int control = ::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        if (control < 0) throw std::runtime_error("MTU socket failed");
        ifreq request{};
        if (opts.interface.size() >= sizeof(request.ifr_name)) { close(control); throw std::invalid_argument("interface name too long"); }
        std::copy(opts.interface.begin(), opts.interface.end(), request.ifr_name);
        int result = ioctl(control, SIOCGIFMTU, &request);
        close(control);
        if (result || request.ifr_mtu < 540) throw std::runtime_error("interface MTU must accommodate 512-byte DNS messages");
        maximum_dns = std::min({size_t(1232), size_t(request.ifr_mtu - 28), size_t(frame_size - 42)});
        object = bpf_object__open_file(opts.bpf.c_str(), nullptr);
        long error = libbpf_get_error(object);
        if (error || !object) { object = nullptr; throw std::runtime_error("failed to open BPF object: " + opts.bpf.string()); }
        check(bpf_object__load(object), "load BPF object");
        auto* program = bpf_object__find_program_by_name(object, "xdp_dns_accelerator");
        if (!program) throw std::runtime_error("DNS XDP program missing");
        program_fd = bpf_program__fd(program);
        map_fd = bpf_object__find_map_fd_by_name(object, "xsks_map");
        if (program_fd < 0 || map_fd < 0) throw std::runtime_error("BPF program or socket map missing");
        configure_filter(opts.policy);
        // Shared across fork: kernel-pinned pages and child TX writes must be identical.
        buffer = mmap(nullptr, num_frames * frame_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        if (buffer == MAP_FAILED) { buffer = nullptr; throw std::runtime_error("allocate shared UMEM failed"); }
        xsk_umem_config umem_config{};
        umem_config.fill_size = rx_frames;
        umem_config.comp_size = num_frames - rx_frames;
        umem_config.frame_size = frame_size;
        check(xsk_umem__create(&umem, buffer, num_frames * frame_size, &fill, &completion, &umem_config), "create UMEM");
        xsk_socket_config socket_config{};
        socket_config.rx_size = rx_frames;
        socket_config.tx_size = num_frames - rx_frames;
        socket_config.libxdp_flags = XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD;
        socket_config.xdp_flags = xdp_flags;
        socket_config.bind_flags = opts.zero_copy ? XDP_ZEROCOPY : XDP_COPY;
        check(xsk_socket__create(&socket, opts.interface.c_str(), queue, umem, &rx, &tx, &socket_config), "create AF_XDP socket");
        int fd = xsk_socket__fd(socket);
        xdp_options actual{};
        socklen_t length = sizeof(actual);
        if (getsockopt(fd, SOL_XDP, XDP_OPTIONS, &actual, &length) || length != sizeof(actual))
            throw std::runtime_error("cannot verify AF_XDP socket mode");
        zero_copy = actual.flags & XDP_OPTIONS_ZEROCOPY;
        if (zero_copy != opts.zero_copy) throw std::runtime_error("AF_XDP socket mode differs from requested mode");
        if (bpf_map_update_elem(map_fd, &queue, &fd, BPF_ANY)) throw std::runtime_error("populate XSK map failed");
        mapped = true;
#else
        throw std::runtime_error("XDP support is disabled in this build; use --mode socket");
#endif
    }
#ifdef NET_ACCEL_XDP
    void configure_filter(const RequestPolicyConfig& policy) {
        int allowed = bpf_object__find_map_fd_by_name(object, "allowed_clients");
        int config = bpf_object__find_map_fd_by_name(object, "filter_config");
        if (allowed < 0 || config < 0) throw std::runtime_error("BPF policy maps missing; rebuild the BPF object");
        uint32_t value = 1;
        for (const auto& cidr : policy.allowed_clients) {
            ipv4_prefix_key key{static_cast<uint32_t>(std::popcount(cidr.mask)), htonl(cidr.network)};
            if (bpf_map_update_elem(allowed, &key, &value, BPF_ANY)) throw std::runtime_error("populate BPF allowlist failed");
        }
        dns_filter_config settings{!policy.allowed_clients.empty(), policy.listen_address.has_value(),
                                   htonl(policy.listen_address.value_or(0))};
        uint32_t zero = 0;
        if (bpf_map_update_elem(config, &zero, &settings, BPF_ANY) || bpf_map_freeze(allowed) || bpf_map_freeze(config))
            throw std::runtime_error("populate/freeze BPF policy failed");
    }
    void release_supervisor_handles() {
        if (socket_mode) return;
        attached = mapped = false;
        bpf_object__close(object);
        object = nullptr;
        program_fd = map_fd = -1;
    }
    void sample(KernelMetrics& metrics) {
        if (socket_mode) return;
        int cpus = libbpf_num_possible_cpus();
        int fd = bpf_object__find_map_fd_by_name(object, "stats_map");
        uint32_t key = 0;
        if (cpus > 0 && fd >= 0) {
            std::vector<packet_stats> values(static_cast<size_t>(cpus));
            if (!bpf_map_lookup_elem(fd, &key, values.data())) {
                packet_stats total{};
                for (const auto& item : values) {
                    total.rx_packets += item.rx_packets; total.dropped_packets += item.dropped_packets;
                    total.dns_redirected += item.dns_redirected; total.unauthorized += item.unauthorized;
                    total.destination_passed += item.destination_passed;
                }
                metrics.xdp_packets = total.rx_packets; metrics.xdp_dropped = total.dropped_packets;
                metrics.xdp_redirected = total.dns_redirected; metrics.xdp_unauthorized = total.unauthorized;
                metrics.destination_passed = total.destination_passed;
            } else ++metrics.collection_errors;
        } else ++metrics.collection_errors;
        xdp_statistics stats{};
        socklen_t length = sizeof(stats);
        if (!getsockopt(xsk_socket__fd(socket), SOL_XDP, XDP_STATISTICS, &stats, &length)) {
            metrics.rx_dropped = stats.rx_dropped; metrics.rx_invalid = stats.rx_invalid_descs;
            metrics.tx_invalid = stats.tx_invalid_descs;
        } else ++metrics.collection_errors;
    }
    void attach() {
        if (socket_mode) return;
        // Refuse to replace another program, including a second daemon instance.
        check(bpf_xdp_attach(ifindex, program_fd, xdp_flags | XDP_FLAGS_UPDATE_IF_NOEXIST, nullptr), "attach XDP program");
        attached = true;
    }
#else
    void release_supervisor_handles() {}
    void sample(KernelMetrics&) {}
    void attach() {}
#endif
};

void worker_ready(int fd) {
    char value = 'R';
    if (write(fd, &value, 1) != 1) throw std::runtime_error("readiness pipe failed");
    close(fd);
}
void notify_systemd() {
    const char* path = std::getenv("NOTIFY_SOCKET");
    if (!path || !*path) return;
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    size_t length = std::strlen(path);
    if (length >= sizeof(address.sun_path)) throw std::runtime_error("NOTIFY_SOCKET path too long");
    std::memcpy(address.sun_path, path, length + 1);
    if (address.sun_path[0] == '@') address.sun_path[0] = '\0';
    int fd = ::socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) throw std::runtime_error("systemd notify socket failed");
    constexpr char message[] = "READY=1\nSTATUS=Local DNS worker ready";
    auto count = sendto(fd, message, sizeof(message) - 1, MSG_NOSIGNAL,
                        reinterpret_cast<sockaddr*>(&address), offsetof(sockaddr_un, sun_path) + length + 1);
    close(fd);
    if (count != sizeof(message) - 1) throw std::runtime_error("systemd readiness notification failed");
}
#ifdef NET_ACCEL_XDP
void event_loop(Runtime& runtime, ResolverService& service, SharedDnsTable<>& cache, int ready_fd) {
    std::deque<uint64_t> recycle;
    std::vector<uint64_t> tx_pool;
    std::deque<PendingTx> pending;
    for (uint64_t i = rx_frames; i < num_frames; ++i) tx_pool.push_back(i * frame_size);
    std::cout << "DNS accelerator ready: XDP attached, AF_XDP queue " << runtime.queue
              << ", RX fill ring populated; XDP=" << (runtime.xdp_flags == XDP_FLAGS_DRV_MODE ? "native" : "generic")
              << " AF_XDP=" << (runtime.zero_copy ? "zero-copy" : "copy") << "\n" << std::flush;
    worker_ready(ready_fd);
    uint64_t next_sweep = monotonic_ns() + 60000000000ULL;
    size_t inflight = 0;
    bool active = true;
    while (!exiting) {
        pollfd descriptors[2]{{xsk_socket__fd(runtime.socket), POLLIN, 0}, {runtime.notify, POLLIN, 0}};
        int result = poll(descriptors, 2, active ? 0 : (inflight || !pending.empty() ? 1 : 100));
        if (result < 0 && errno != EINTR) throw std::runtime_error("AF_XDP poll failed");
        if (descriptors[0].revents & (POLLERR | POLLHUP | POLLNVAL)) throw std::runtime_error("AF_XDP socket became unavailable");
        if (descriptors[1].revents & POLLIN) {
            uint64_t value;
            while (read(runtime.notify, &value, sizeof(value)) < 0 && errno == EINTR) {}
        }
        active = false;
        uint32_t index = 0;
        uint32_t count = xsk_ring_cons__peek(&runtime.completion, batch_size, &index);
        for (uint32_t i = 0; i < count; ++i) {
            uint64_t addr = *xsk_ring_cons__comp_addr(&runtime.completion, index + i);
            if (addr < uint64_t(rx_frames) * frame_size || addr >= uint64_t(num_frames) * frame_size || addr % frame_size)
                throw std::runtime_error("invalid TX completion address");
            tx_pool.push_back(addr);
        }
        if (count > inflight) throw std::runtime_error("invalid TX completion count");
        inflight -= count;
        xsk_ring_cons__release(&runtime.completion, count);
        active |= count != 0;

        count = xsk_ring_cons__peek(&runtime.rx, batch_size, &index);
        for (uint32_t i = 0; i < count; ++i) {
            const auto* desc = xsk_ring_cons__rx_desc(&runtime.rx, index + i);
            uint64_t base = desc->addr & ~(uint64_t(frame_size) - 1);
            if (base >= uint64_t(rx_frames) * frame_size || desc->len > frame_size - (desc->addr - base))
                throw std::runtime_error("invalid RX descriptor");
            auto* data = static_cast<uint8_t*>(xsk_umem__get_data(runtime.buffer, desc->addr));
            PacketError error;
            auto packet = parse_ipv4_udp(View(data, desc->len), &error);
            if (packet) service.submit(std::move(*packet));
            else {
                service.metrics.malformed.fetch_add(1, std::memory_order_relaxed);
                if (error == PacketError::ipv4_checksum)
                    service.metrics.bad_ip_checksums.fetch_add(1, std::memory_order_relaxed);
                if (error == PacketError::udp_checksum &&
                    service.metrics.bad_udp_checksums.fetch_add(1, std::memory_order_relaxed) == 0) {
                    std::cerr << "Rejected UDP checksum. For veth testing, disable TX checksum offload on the sending peer; "
                                 "generic AF_XDP cannot distinguish an unfinished checksum from a corrupt packet.\n";
                }
            }
            recycle.push_back(base);
        }
        xsk_ring_cons__release(&runtime.rx, count);
        active |= count == batch_size;
        refill_frames(runtime.fill, recycle); // Keep every unreserved frame for retry.

        Bytes packet;
        while (!tx_pool.empty() && service.try_response(packet)) {
            if (packet.size() > frame_size) throw std::runtime_error("response exceeds UMEM frame");
            uint64_t addr = tx_pool.back();
            tx_pool.pop_back();
            std::memcpy(xsk_umem__get_data(runtime.buffer, addr), packet.data(), packet.size());
            pending.push_back({addr, static_cast<uint32_t>(packet.size())});
        }
        auto submitted = submit_frames(runtime.tx, pending);
        inflight += submitted;
        active |= submitted != 0;
        if (inflight) {
            int kicked = sendto(xsk_socket__fd(runtime.socket), nullptr, 0, MSG_DONTWAIT, nullptr, 0);
            if (kicked < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != ENOBUFS && errno != EBUSY && errno != EINTR)
                throw std::runtime_error("AF_XDP transmit failed: " + std::string(std::strerror(errno)));
        }
        uint64_t now = monotonic_ns();
        if (now >= next_sweep) { cache.sweep_expired(now); next_sweep = now + 60000000000ULL; }
    }
}
#endif
void socket_event_loop(Runtime& runtime, ResolverService& service, SharedDnsTable<>& cache, int ready_fd) {
    worker_ready(ready_fd);
    std::cout << "Local DNS ready: UDP socket on 127.0.0.1; no BPF loaded\n" << std::flush;
    uint64_t next_sweep = monotonic_ns() + 60000000000ULL;
    std::array<uint8_t, 65535> buffer{};
    while (!exiting) {
        pollfd fds[2]{{runtime.udp_fd, POLLIN, 0}, {runtime.notify, POLLIN, 0}};
        if (poll(fds, 2, service.reply_queue_depth() ? 0 : 100) < 0 && errno != EINTR) throw std::runtime_error("UDP poll failed");
        if (fds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) throw std::runtime_error("UDP listener unavailable");
        if (fds[1].revents & POLLIN) { uint64_t value; while (read(runtime.notify, &value, sizeof(value)) < 0 && errno == EINTR) {} }
        for (unsigned i = 0; i < 64 && (fds[0].revents & POLLIN); ++i) {
            sockaddr_in peer{};
            socklen_t length = sizeof(peer);
            ssize_t count = recvfrom(runtime.udp_fd, buffer.data(), buffer.size(), 0, reinterpret_cast<sockaddr*>(&peer), &length);
            if (count < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                if (errno == EINTR) continue;
                throw std::runtime_error("UDP receive failed");
            }
            if (length != sizeof(peer) || ntohl(peer.sin_addr.s_addr) != INADDR_LOOPBACK) continue;
            Bytes wire(buffer.begin(), buffer.begin() + count);
            service.submit_dns(DnsRequest{std::move(wire), INADDR_LOOPBACK, INADDR_LOOPBACK, peer});
        }
        DnsResponse response;
        for (unsigned i = 0; i < 64 && service.try_response(response); ++i) {
            const auto& peer = std::get<sockaddr_in>(response.route);
            ssize_t sent = sendto(runtime.udp_fd, response.dns.data(), response.dns.size(), MSG_NOSIGNAL,
                                  reinterpret_cast<const sockaddr*>(&peer), sizeof(peer));
            if (sent != static_cast<ssize_t>(response.dns.size())) ++service.metrics.overloaded;
        }
        uint64_t now = monotonic_ns();
        if (now >= next_sweep) { cache.sweep_expired(now); next_sweep = now + 60000000000ULL; }
    }
}
} // namespace

int main(int argc, char** argv) {
    if (argc == 2 && std::string_view(argv[1]) == "--help") { usage(argv[0]); return 0; }
    try {
        auto opts = options(argc, argv);
        auto upstream = upstream_address(opts.upstream);
        auto identity = worker_identity(opts.run_as);
        if (opts.check_config) { std::cout << "Configuration valid\n"; return 0; }
        struct sigaction action{};
        action.sa_handler = signal_handler;
        sigemptyset(&action.sa_mask);
        if (sigaction(SIGINT, &action, nullptr) || sigaction(SIGTERM, &action, nullptr))
            throw std::runtime_error("signal handler installation failed");
        harden_process();
        Runtime runtime;
        runtime.initialize(opts);
        void* region = mmap(nullptr, sizeof(KernelMetrics), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        if (region == MAP_FAILED) throw std::runtime_error("allocate supervisor telemetry failed");
        struct RegionCleanup { void* region; ~RegionCleanup() { munmap(region, sizeof(KernelMetrics)); } } cleanup{region};
        auto* kernel = new(region) KernelMetrics;
#ifdef NET_ACCEL_XDP
        if (!opts.socket_mode) {
        std::deque<uint64_t> initial_frames;
        for (uint64_t i = 0; i < rx_frames; ++i) initial_frames.push_back(i * frame_size);
        if (refill_frames(runtime.fill, initial_frames) != rx_frames) throw std::runtime_error("initial fill ring reservation failed");
        }
#endif
        runtime.attach();
        int ready_pipe[2];
        if (pipe2(ready_pipe, O_CLOEXEC | O_NONBLOCK)) throw std::runtime_error("create readiness pipe failed");
        pid_t parent = getpid();
        std::cout << std::flush;
        std::cerr << std::flush;
        pid_t child = fork();
        if (child < 0) throw std::runtime_error("fork DNS worker failed");
        if (child != 0) {
            close(ready_pipe[1]);
            struct ReadyGuard { int fd; ~ReadyGuard() { close(fd); } } ready_guard{ready_pipe[0]};
            struct ChildGuard {
                pid_t pid;
                ~ChildGuard() {
                    if (pid > 0) {
                        kill(pid, SIGKILL);
                        while (waitpid(pid, nullptr, 0) < 0 && errno == EINTR) {}
                    }
                }
            } child_guard{child};
            bool stopping = false;
            uint64_t stop_time = 0, next_sample = 0, startup = monotonic_ns();
            bool ready = false;
            int status = 0;
            for (;;) {
                pid_t result = waitpid(child, &status, WNOHANG);
                if (result == child) break;
                if (result < 0 && errno != EINTR) throw std::runtime_error("wait for DNS worker failed");
                uint64_t now = monotonic_ns();
                if (!ready) {
                    char value;
                    if (read(ready_pipe[0], &value, 1) == 1 && value == 'R') { notify_systemd(); ready = true; }
                    if (now - startup > 15000000000ULL) throw std::runtime_error("DNS worker startup timed out");
                }
                if (now >= next_sample) { runtime.sample(*kernel); next_sample = now + 1000000000ULL; }
                if (exiting && !stopping) { kill(child, SIGTERM); stopping = true; stop_time = now; }
                if (stopping && now - stop_time > 5000000000ULL) kill(child, SIGKILL);
                poll(nullptr, 0, 50);
            }
            child_guard.pid = 0;
            return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
        }
        // No privileged DNS parser or upstream threads are created in the supervisor.
        close(ready_pipe[0]);
        try {
            runtime.release_supervisor_handles();
            drop_worker_privileges(identity);
            if (prctl(PR_SET_PDEATHSIG, SIGTERM) || getppid() != parent)
                throw std::runtime_error("supervisor disappeared during worker startup");
            if (mprotect(region, sizeof(KernelMetrics), PROT_READ)) throw std::runtime_error("protect supervisor telemetry failed");
            using Cache = SharedDnsTable<>;
            std::unique_ptr<Cache, decltype(&Cache::unmap)> cache(Cache::create_or_attach(true, opts.cache_name.c_str()), &Cache::unmap);
            ResolverService service(cache.get(), upstream, runtime.maximum_dns, opts.workers, [&] {
                uint64_t value = 1;
                while (write(runtime.notify, &value, sizeof(value)) < 0 && errno == EINTR) {}
            }, opts.policy, opts.transport, opts.forward_zones);
            std::unique_ptr<MetricsServer> metrics;
            if (opts.metrics_port) metrics = std::make_unique<MetricsServer>(service, *kernel, opts.metrics_port);
            std::cout << "Worker PID=" << getpid() << " uid=" << geteuid() << " gid=" << getegid()
                      << " user=" << identity.name << " capabilities=none\n"
                      << "Security: no_new_privs=1 core_dumps=disabled allowed_networks=" << opts.policy.allowed_clients.size()
                      << " rate_limit=" << opts.policy.global_qps << " client_rate_limit=" << opts.policy.client_qps << '\n'
                      << "Interface=" << opts.interface << " upstream=" << opts.upstream << " transport=" << opts.transport_name << " workers=" << opts.workers
                      << " mode=" << (opts.socket_mode ? "socket" : "xdp") << '\n';
            if (metrics) std::cout << "Metrics: http://127.0.0.1:" << metrics->port() << "/metrics\n";
            if (opts.socket_mode) socket_event_loop(runtime, service, *cache, ready_pipe[1]);
#ifdef NET_ACCEL_XDP
            else event_loop(runtime, service, *cache, ready_pipe[1]);
#endif
            metrics.reset();
            service.stop();
            std::cout << "Queries=" << service.metrics.received << " hits=" << service.metrics.hits
                      << " forwarded=" << service.metrics.forwarded << " failures=" << service.metrics.failures
                      << " overloaded=" << service.metrics.overloaded << " malformed=" << service.metrics.malformed
                      << " bad_ip_checksums=" << service.metrics.bad_ip_checksums << " bad_udp_checksums=" << service.metrics.bad_udp_checksums
                      << " unauthorized=" << service.metrics.unauthorized << " global_limited=" << service.metrics.global_limited
                      << " client_limited=" << service.metrics.client_limited << " client_table_full=" << service.metrics.client_table_full
                      << " network_limited=" << service.metrics.network_limited << " reserved_limited=" << service.metrics.reserved_limited
                      << " coalesced=" << service.metrics.coalesced << '\n' << std::flush;
            // The supervisor owns all resource teardown. Avoid running its inherited destructors here.
            _exit(0);
        } catch (const std::exception& error) {
            std::cerr << "dns_daemon worker: " << error.what() << '\n' << std::flush;
            _exit(1);
        }
    } catch (const std::exception& error) {
        std::cerr << "dns_daemon: " << error.what() << '\n';
        return 1;
    }
}
