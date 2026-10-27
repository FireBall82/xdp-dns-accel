#include "resolver_service.hpp"
#include "xsk_rings.hpp"
#include <algorithm>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <charconv>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <linux/if_link.h>
#include <memory>
#include <net/if.h>
#include <poll.h>
#include <stdexcept>
#include <string>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

namespace {
using namespace net_accel;
volatile sig_atomic_t exiting = 0;
void signal_handler(int) { exiting = 1; }
constexpr uint32_t num_frames = 4096;
constexpr uint32_t frame_size = XSK_UMEM__DEFAULT_FRAME_SIZE;
constexpr uint32_t rx_frames = 2048;
constexpr uint32_t batch_size = 64;
static_assert(rx_frames < num_frames);

void check(int result, const char* operation) {
    if (result) throw std::runtime_error(std::string(operation) + ": " + std::strerror(result < 0 ? -result : result));
}
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
    std::string interface;
    std::string upstream = "1.1.1.1:53";
    std::string cache_name = SharedDnsTable<>::SHM_PATH;
    std::filesystem::path bpf;
    unsigned workers = 4;
    unsigned queue = 0;
};
void usage(const char* executable) {
    std::cout << "Usage: " << executable << " <interface> [--upstream IPv4[:port]] [--workers 1..64]\n"
                 "       [--queue 0..63] [--bpf-object path] [--cache-name /name]\n"
                 "Runs generic XDP with AF_XDP copy mode on the selected receive queue.\n";
}
Options options(int argc, char** argv) {
    if (argc < 2) throw std::invalid_argument("an interface is required (see --help)");
    Options result;
    result.interface = argv[1];
    for (int i = 2; i < argc; i += 2) {
        if (i + 1 >= argc) throw std::invalid_argument("missing option value");
        std::string_view option = argv[i];
        if (option == "--upstream") result.upstream = argv[i + 1];
        else if (option == "--workers") {
            result.workers = number(argv[i + 1], 64);
            if (!result.workers) throw std::invalid_argument("at least one worker is required");
        } else if (option == "--queue") result.queue = number(argv[i + 1], 63);
        else if (option == "--bpf-object") result.bpf = argv[i + 1];
        else if (option == "--cache-name") {
            result.cache_name = argv[i + 1];
            if (result.cache_name.size() < 2 || result.cache_name.size() > 240 || result.cache_name[0] != '/' ||
                result.cache_name.find('/', 1) != std::string::npos)
                throw std::invalid_argument("cache name must be /name without additional slashes");
        }
        else throw std::invalid_argument("unknown option: " + std::string(option));
    }
    if (result.bpf.empty()) result.bpf = default_bpf_path();
    return result;
}

class Runtime {
public:
    bpf_object* object = nullptr;
    xsk_umem* umem = nullptr;
    xsk_socket* socket = nullptr;
    void* buffer = nullptr;
    xsk_ring_prod fill{}, tx{};
    xsk_ring_cons completion{}, rx{};
    int notify = -1;
    int ifindex = 0;
    int program_fd = -1;
    int map_fd = -1;
    uint32_t queue = 0;
    bool mapped = false;
    bool attached = false;
    size_t maximum_dns = 1232;

    ~Runtime() {
        if (mapped) bpf_map_delete_elem(map_fd, &queue);
        if (attached) {
            bpf_xdp_attach_opts opts{};
            opts.sz = sizeof(opts);
            opts.old_prog_fd = program_fd;
            int result = bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, &opts);
            if (result) std::cerr << "Could not detach owned XDP hook: " << std::strerror(-result) << '\n';
        }
        if (socket) xsk_socket__delete(socket);
        if (umem) xsk_umem__delete(umem);
        std::free(buffer);
        if (object) bpf_object__close(object);
        if (notify >= 0) close(notify);
    }
    void initialize(const Options& opts) {
        queue = opts.queue;
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
        notify = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
        if (notify < 0) throw std::runtime_error("eventfd failed");
        object = bpf_object__open_file(opts.bpf.c_str(), nullptr);
        long error = libbpf_get_error(object);
        if (error || !object) { object = nullptr; throw std::runtime_error("failed to open BPF object: " + opts.bpf.string()); }
        check(bpf_object__load(object), "load BPF object");
        auto* program = bpf_object__find_program_by_name(object, "xdp_dns_accelerator");
        if (!program) throw std::runtime_error("DNS XDP program missing");
        program_fd = bpf_program__fd(program);
        map_fd = bpf_object__find_map_fd_by_name(object, "xsks_map");
        if (program_fd < 0 || map_fd < 0) throw std::runtime_error("BPF program or socket map missing");
        check(posix_memalign(&buffer, static_cast<size_t>(getpagesize()), num_frames * frame_size), "allocate UMEM");
        xsk_umem_config umem_config{};
        umem_config.fill_size = rx_frames;
        umem_config.comp_size = num_frames - rx_frames;
        umem_config.frame_size = frame_size;
        check(xsk_umem__create(&umem, buffer, num_frames * frame_size, &fill, &completion, &umem_config), "create UMEM");
        xsk_socket_config socket_config{};
        socket_config.rx_size = rx_frames;
        socket_config.tx_size = num_frames - rx_frames;
        socket_config.libxdp_flags = XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD;
        socket_config.xdp_flags = XDP_FLAGS_SKB_MODE;
        socket_config.bind_flags = XDP_COPY;
        check(xsk_socket__create(&socket, opts.interface.c_str(), queue, umem, &rx, &tx, &socket_config), "create AF_XDP socket");
        int fd = xsk_socket__fd(socket);
        if (bpf_map_update_elem(map_fd, &queue, &fd, BPF_ANY)) throw std::runtime_error("populate XSK map failed");
        mapped = true;
    }
    void attach() {
        // Refuse to replace another program, including a second daemon instance.
        check(bpf_xdp_attach(ifindex, program_fd, XDP_FLAGS_SKB_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST, nullptr), "attach XDP program");
        attached = true;
    }
};

void event_loop(Runtime& runtime, ResolverService& service, SharedDnsTable<>& cache) {
    std::deque<uint64_t> recycle;
    std::vector<uint64_t> tx_pool;
    std::deque<PendingTx> pending;
    for (uint64_t i = 0; i < rx_frames; ++i) recycle.push_back(i * frame_size);
    for (uint64_t i = rx_frames; i < num_frames; ++i) tx_pool.push_back(i * frame_size);
    if (refill_frames(runtime.fill, recycle) != rx_frames) throw std::runtime_error("initial fill ring reservation failed");
    runtime.attach();
    std::cout << "DNS accelerator ready: XDP attached, AF_XDP queue " << runtime.queue
              << ", RX fill ring populated\n" << std::flush;
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
} // namespace

int main(int argc, char** argv) {
    if (argc == 2 && std::string_view(argv[1]) == "--help") { usage(argv[0]); return 0; }
    try {
        auto opts = options(argc, argv);
        auto upstream = net_accel::upstream_address(opts.upstream);
        struct sigaction action{};
        action.sa_handler = signal_handler;
        sigemptyset(&action.sa_mask);
        if (sigaction(SIGINT, &action, nullptr) || sigaction(SIGTERM, &action, nullptr))
            throw std::runtime_error("signal handler installation failed");
        Runtime runtime;
        runtime.initialize(opts);
        using Cache = net_accel::SharedDnsTable<>;
        std::unique_ptr<Cache, decltype(&Cache::unmap)> cache(Cache::create_or_attach(true, opts.cache_name.c_str()), &Cache::unmap);
        net_accel::ResolverService service(cache.get(), upstream, runtime.maximum_dns, opts.workers, [&] {
            uint64_t value = 1;
            while (write(runtime.notify, &value, sizeof(value)) < 0 && errno == EINTR) {}
        });
        std::cout << "Interface=" << opts.interface << " upstream=" << opts.upstream
                  << " workers=" << opts.workers << " (XDP copy mode)\n";
        event_loop(runtime, service, *cache);
        std::cout << "Queries=" << service.metrics.received << " hits=" << service.metrics.hits
                  << " forwarded=" << service.metrics.forwarded << " failures=" << service.metrics.failures
                  << " overloaded=" << service.metrics.overloaded << " malformed=" << service.metrics.malformed
                  << " bad_ip_checksums=" << service.metrics.bad_ip_checksums
                  << " bad_udp_checksums=" << service.metrics.bad_udp_checksums << '\n';
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "dns_daemon: " << error.what() << '\n';
        return 1;
    }
}
