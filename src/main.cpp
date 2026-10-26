#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <csignal>
#include <iostream>
#include <linux/if_link.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <poll.h>
#include <string>
#include <sys/resource.h>
#include <unistd.h>
#include <utility>
#include <vector>
#include <xdp/libxdp.h>
#include <xdp/xsk.h>
#include <thread>
#include <atomic>
#include <chrono>
#include <cstring>
#include "shared_dns_table.hpp"

using namespace net_accel;

volatile sig_atomic_t global_exit_flag = 0;

void sigint_handler(int) { global_exit_flag = 1; }

constexpr size_t NUM_FRAMES = 4096;
constexpr size_t FRAME_SIZE = XSK_UMEM__DEFAULT_FRAME_SIZE;
constexpr size_t BATCH_SIZE = 64;

struct xsk_umem_info {
    struct xsk_ring_prod fq;
    struct xsk_ring_cons cq;
    struct xsk_umem *umem;
    void *buffer;
};

struct xsk_socket_info {
    struct xsk_ring_cons rx;
    struct xsk_ring_prod tx;
    struct xsk_umem_info *umem;
    struct xsk_socket *xsk;
};

struct dns_header {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} __attribute__((packed));

inline uint16_t calculate_ip_checksum(const uint8_t* ip_header) {
    uint32_t sum = 0;
    for (int i = 0; i < 20; i += 2) {
        if (i == 10) continue; // Skip existing checksum field
        uint16_t word = (ip_header[i] << 8) | ip_header[i + 1];
        sum += word;
    }
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return htons(static_cast<uint16_t>(~sum));
}

inline void swap_headers_ipv4(uint8_t* pkt, uint16_t total_ip_len, uint16_t total_udp_len) {
    // 1. Swap MAC addresses (Ethernet header 0..13)
    uint8_t tmp_mac[6];
    std::memcpy(tmp_mac, pkt, 6);
    std::memcpy(pkt, pkt + 6, 6);
    std::memcpy(pkt + 6, tmp_mac, 6);

    // 2. Swap IPv4 addresses (IP header 14..33, src @ 26, dst @ 30)
    uint32_t src_ip, dst_ip;
    std::memcpy(&src_ip, pkt + 26, 4);
    std::memcpy(&dst_ip, pkt + 30, 4);
    std::memcpy(pkt + 26, &dst_ip, 4);
    std::memcpy(pkt + 30, &src_ip, 4);

    // 3. Update IP Total Length (offset 16)
    *reinterpret_cast<uint16_t*>(pkt + 16) = htons(total_ip_len);

    // 4. Recalculate IPv4 Checksum (offset 24)
    pkt[24] = 0;
    pkt[25] = 0;
    uint16_t ip_csum = calculate_ip_checksum(pkt + 14);
    std::memcpy(pkt + 24, &ip_csum, 2);

    // 5. Swap UDP Ports (UDP header 34..41, src @ 34, dst @ 36)
    uint16_t src_port, dst_port;
    std::memcpy(&src_port, pkt + 34, 2);
    std::memcpy(&dst_port, pkt + 36, 2);
    std::memcpy(pkt + 34, &dst_port, 2);
    std::memcpy(pkt + 36, &src_port, 2);

    // 6. Update UDP Length (offset 38) and Clear UDP Checksum (offset 40)
    *reinterpret_cast<uint16_t*>(pkt + 38) = htons(total_udp_len);
    pkt[40] = 0;
    pkt[41] = 0;
}

// Returns parsed domain string & outputs total DNS payload length (Header + Question)
inline std::string parse_dns_name(const uint8_t* pkt, size_t dns_payload_offset, size_t& query_len_out) {
    std::string domain;
    size_t offset = dns_payload_offset + 12; // Skip 12-byte DNS header
    size_t start_offset = offset;

    while (pkt[offset] != 0) {
        uint8_t len = pkt[offset];
        if ((len & 0xC0) == 0xC0) {
            offset += 2;
            break;
        }
        offset++;
        if (!domain.empty()) domain += ".";
        domain.append(reinterpret_cast<const char*>(pkt + offset), len);
        offset += len;
    }
    if (pkt[start_offset] != 0 && (pkt[offset] & 0xC0) != 0xC0) offset++;

    // Total length from start of DNS Header (42) to end of Question (QTYPE + QCLASS)
    query_len_out = (offset - dns_payload_offset) + 4;
    return domain;
}

xsk_umem_info *configure_umem() {
    auto *ui = new xsk_umem_info();
    if (posix_memalign(&ui->buffer, getpagesize(), NUM_FRAMES * FRAME_SIZE)) {
        std::cerr << "Failed to allocate UMEM buffer\n";
        exit(EXIT_FAILURE);
    }

    struct xsk_umem_config cfg = {
        .fill_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
        .comp_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
        .frame_size = FRAME_SIZE,
        .frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
        .flags = 0
    };

    if (xsk_umem__create(&ui->umem, ui->buffer, NUM_FRAMES * FRAME_SIZE, &ui->fq, &ui->cq, &cfg)) {
        std::cerr << "Failed to create UMEM\n";
        exit(EXIT_FAILURE);
    }
    return ui;
}

xsk_socket_info *setup_socket(const char *ifname, uint32_t queue_id, xsk_umem_info *umem_info) {
    auto *si = new xsk_socket_info();
    si->umem = umem_info;

    struct xsk_socket_config cfg = {
        .rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
        .tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
        .libxdp_flags = XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD,
        .xdp_flags = XDP_FLAGS_SKB_MODE,
        .bind_flags = XDP_COPY
    };

    if (xsk_socket__create(&si->xsk, ifname, queue_id, umem_info->umem, &si->rx, &si->tx, &cfg)) {
        std::cerr << "Failed to create AF_XDP socket on " << ifname << "\n";
        exit(EXIT_FAILURE);
    }
    return si;
}

bool resolve_upstream_ipv4(const uint8_t* query_payload, size_t query_len, uint32_t &out_ipv4, uint32_t &out_ttl) {
    out_ttl = 60;
    out_ipv4 = 0;

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return false;

    struct timeval tv{1, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in upstream_addr{};
    upstream_addr.sin_family = AF_INET;
    upstream_addr.sin_port = htons(53);
    inet_pton(AF_INET, "1.1.1.1", &upstream_addr.sin_addr);

    if (sendto(sock, query_payload, query_len, 0, (struct sockaddr*)&upstream_addr, sizeof(upstream_addr)) < 0) {
        close(sock);
        return false;
    }

    uint8_t resp_buf[512];
    ssize_t resp_len = recv(sock, resp_buf, sizeof(resp_buf), 0);
    close(sock);

    if (resp_len < 12) return false;

    uint16_t flags   = ntohs(*reinterpret_cast<uint16_t*>(resp_buf + 2));
    uint16_t qdcount = ntohs(*reinterpret_cast<uint16_t*>(resp_buf + 4));
    uint16_t ancount = ntohs(*reinterpret_cast<uint16_t*>(resp_buf + 6));
    if ((flags & 0x0F) != 0) return false;

    if (ancount == 0) return true;

    size_t offset = 12;
    for (uint16_t i = 0; i < qdcount; ++i) {
        while (offset < (size_t)resp_len) {
            uint8_t len = resp_buf[offset];
            if (len == 0) { offset += 1; break; }
            if ((len & 0xC0) == 0xC0) { offset += 2; break; }
            offset += 1 + len;
        }
        offset += 4;
    }

    for (uint16_t i = 0; i < ancount && offset < (size_t)resp_len; ++i) {
        while (offset < (size_t)resp_len) {
            uint8_t len = resp_buf[offset];
            if (len == 0) { offset += 1; break; }
            if ((len & 0xC0) == 0xC0) { offset += 2; break; }
            offset += 1 + len;
        }
        if (offset + 10 > (size_t)resp_len) break;

        uint16_t rtype    = ntohs(*reinterpret_cast<uint16_t*>(resp_buf + offset));
        uint32_t ttl      = ntohl(*reinterpret_cast<uint32_t*>(resp_buf + offset + 4));
        uint16_t rdlength = ntohs(*reinterpret_cast<uint16_t*>(resp_buf + offset + 8));
        offset += 10;

        if (rtype == 1 && rdlength == 4 && offset + 4 <= (size_t)resp_len) {
            out_ipv4 = *reinterpret_cast<const uint32_t*>(resp_buf + offset);
            out_ttl = (ttl > 0) ? ttl : 60;
            return true;
        }
        offset += rdlength;
    }
    return true;
}

bool resolve_upstream_ipv6(const uint8_t* query_payload, size_t query_len, uint8_t* out_ipv6, uint32_t &out_ttl) {
    out_ttl = 60;
    std::memset(out_ipv6, 0, 16);

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return false;

    struct timeval tv{1, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in upstream_addr{};
    upstream_addr.sin_family = AF_INET;
    upstream_addr.sin_port = htons(53);
    inet_pton(AF_INET, "1.1.1.1", &upstream_addr.sin_addr);

    if (sendto(sock, query_payload, query_len, 0, (struct sockaddr*)&upstream_addr, sizeof(upstream_addr)) < 0) {
        close(sock);
        return false;
    }

    uint8_t resp_buf[512];
    ssize_t resp_len = recv(sock, resp_buf, sizeof(resp_buf), 0);
    close(sock);

    if (resp_len < 12) return false;

    uint16_t flags   = ntohs(*reinterpret_cast<uint16_t*>(resp_buf + 2));
    uint16_t qdcount = ntohs(*reinterpret_cast<uint16_t*>(resp_buf + 4));
    uint16_t ancount = ntohs(*reinterpret_cast<uint16_t*>(resp_buf + 6));
    if ((flags & 0x0F) != 0) return false;

    if (ancount == 0) return true;

    size_t offset = 12;
    for (uint16_t i = 0; i < qdcount; ++i) {
        while (offset < (size_t)resp_len) {
            uint8_t len = resp_buf[offset];
            if (len == 0) { offset += 1; break; }
            if ((len & 0xC0) == 0xC0) { offset += 2; break; }
            offset += 1 + len;
        }
        offset += 4;
    }

    for (uint16_t i = 0; i < ancount && offset < (size_t)resp_len; ++i) {
        while (offset < (size_t)resp_len) {
            uint8_t len = resp_buf[offset];
            if (len == 0) { offset += 1; break; }
            if ((len & 0xC0) == 0xC0) { offset += 2; break; }
            offset += 1 + len;
        }

        if (offset + 10 > (size_t)resp_len) break;

        uint16_t rtype    = ntohs(*reinterpret_cast<uint16_t*>(resp_buf + offset));
        uint32_t ttl      = ntohl(*reinterpret_cast<uint32_t*>(resp_buf + offset + 4));
        uint16_t rdlength = ntohs(*reinterpret_cast<uint16_t*>(resp_buf + offset + 8));
        offset += 10;

        if (rtype == 28 && rdlength == 16 && offset + 16 <= (size_t)resp_len) {
            std::memcpy(out_ipv6, resp_buf + offset, 16);
            out_ttl = (ttl > 0) ? ttl : 60;
            return true;
        }
        offset += rdlength;
    }
    return true;
}

std::atomic<bool> running{true};

void start_gc_thread(SharedDnsTable<131072>* table) {
    std::thread([table]() {
        std::cout << "[+] DNS Cache GC thread started.\n";
        while (running.load(std::memory_order_relaxed)) {
            std::this_thread::sleep_for(std::chrono::minutes(5));
            if (!running.load(std::memory_order_relaxed)) break;

            size_t evicted = table->sweep_expired();
            if (evicted > 0) {
                std::cout << "[GC] Swept cache: Evicted " << evicted << " expired DNS records.\n";
            }
        }
    }).detach();
}

int main(int argc, char **argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <interface>\n";
        return EXIT_FAILURE;
    }
    const char *ifname = argv[1];
    uint32_t queue_id = 0;
    int ifindex = if_nametoindex(ifname);

    if (ifindex == 0) {
        std::cerr << "Invalid interface: " << ifname << "\n";
        return EXIT_FAILURE;
    }

    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);

    struct bpf_object *obj = bpf_object__open_file("xdp_filter.bpf.o", NULL);
    if (!obj || bpf_object__load(obj)) {
        std::cerr << "[!] Failed to load xdp_filter.bpf.o\n";
        return EXIT_FAILURE;
    }

    int prog_fd = bpf_program__fd(bpf_object__find_program_by_name(obj, "xdp_dns_accelerator"));

    if (bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE, NULL) < 0) {
        std::cerr << "[!] Failed to attach eBPF program to interface\n";
        return EXIT_FAILURE;
    }
    std::cout << "[+] eBPF program injected into kernel driver for " << ifname << "\n";

    auto *dns_cache = SharedDnsTable<>::create_or_attach(true);
    std::cout << "[+] Shared memory cache initialized at " << SharedDnsTable<>::SHM_PATH << "\n";

    dns_cache->insert("google.com", inet_addr("1.2.3.4"), 0xFFFFFFFFFFFFFFFFULL);
    start_gc_thread(dns_cache);
    std::cout << "[+] Test record inserted: google.com -> 1.2.3.4\n";

    xsk_umem_info *umem = configure_umem();
    xsk_socket_info *xsk = setup_socket(ifname, queue_id, umem);

    int map_fd = bpf_object__find_map_fd_by_name(obj, "xsks_map");
    int xsk_fd = xsk_socket__fd(xsk->xsk);
    if (bpf_map_update_elem(map_fd, &queue_id, &xsk_fd, BPF_ANY) != 0) {
        std::cerr << "[!] Failed to link AF_XDP socket into eBPF map\n";
        return EXIT_FAILURE;
    }

    uint32_t fq_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
    uint32_t idx;
    if (xsk_ring_prod__reserve(&umem->fq, fq_size, &idx) != fq_size)
        return EXIT_FAILURE;
    for (size_t i = 0; i < fq_size; i++) {
        *xsk_ring_prod__fill_addr(&umem->fq, idx++) = i * FRAME_SIZE;
    }
    xsk_ring_prod__submit(&umem->fq, fq_size);

    std::cout << "[+] AF_XDP socket bound to " << ifname << " queue " << queue_id << "\n";
    std::cout << "[+] Entering fast-path poll loop...\n";

    while (!global_exit_flag) {
        struct pollfd fds[1] = {};
        fds[0].fd = xsk_socket__fd(xsk->xsk);
        fds[0].events = POLLIN;

        int ret = poll(fds, 1, 100);

        // Reap completed TX buffers back into Fill Queue (fq) to prevent UMEM buffer exhaustion
        uint32_t cq_idx = 0;
        uint32_t completed = xsk_ring_cons__peek(&xsk->umem->cq, BATCH_SIZE, &cq_idx);
        if (completed > 0) {
            uint32_t fill_idx = 0;
            uint32_t fill_reserved = xsk_ring_prod__reserve(&xsk->umem->fq, completed, &fill_idx);
            for (uint32_t k = 0; k < fill_reserved; ++k) {
                uint64_t addr = *xsk_ring_cons__comp_addr(&xsk->umem->cq, cq_idx + k);
                *xsk_ring_prod__fill_addr(&xsk->umem->fq, fill_idx + k) = addr;
            }
            xsk_ring_prod__submit(&xsk->umem->fq, fill_reserved);
            xsk_ring_cons__release(&xsk->umem->cq, completed);
        }

        if (ret <= 0) continue;

        uint32_t idx_rx = 0;
        uint32_t rcvd = xsk_ring_cons__peek(&xsk->rx, BATCH_SIZE, &idx_rx);
        if (!rcvd) continue;

        std::vector<uint64_t> recycle_queue;
        std::vector<std::pair<uint64_t, uint32_t>> tx_queue;

        recycle_queue.reserve(rcvd);
        tx_queue.reserve(rcvd);

        uint64_t now_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();

        for (uint32_t i = 0; i < rcvd; ++i) {
            uint64_t addr = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx + i)->addr;
            uint32_t pkt_len = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx + i)->len;
            uint8_t* pkt = (uint8_t*)xsk_umem__get_data(xsk->umem->buffer, addr);

            // Framing check: Ethernet (14) + IP (20) + UDP (8) = 42
            if (pkt_len < 42 || pkt[12] != 0x08 || pkt[13] != 0x00 || pkt[23] != 17) {
                recycle_queue.push_back(addr);
                continue;
            }

            uint16_t dst_port = ntohs(*reinterpret_cast<uint16_t*>(pkt + 36));
            size_t dns_payload_offset = 42;

            if (dst_port != 53 || pkt_len < dns_payload_offset + 12) {
                recycle_queue.push_back(addr);
                continue;
            }

            size_t query_section_len = 0;
            std::string query_domain = parse_dns_name(pkt, dns_payload_offset, query_section_len);
            
            // Correct QTYPE offset calculation (Offset 42 + total Question section length - 4)
            size_t qtype_offset = dns_payload_offset + query_section_len - 4;
            uint16_t qtype = ntohs(*reinterpret_cast<uint16_t*>(pkt + qtype_offset));

            bool handled = false;

            // --------------------------------------------------------------------
            // TYPE A (IPv4 Resolution)
            // --------------------------------------------------------------------
            if (qtype == 1) {
                uint32_t cached_ipv4 = 0;

                if (dns_cache->lookup(query_domain, cached_ipv4, now_ns)) {
                    std::cout << "[HIT]  A " << query_domain << " (0 msec)\n";
                } else {
                    std::cout << "[MISS] A " << query_domain << " -> Cloudflare...\n";
                    uint32_t resolved_ip = 0;
                    uint32_t dynamic_ttl = 60;
                    
                    if (resolve_upstream_ipv4(pkt + dns_payload_offset, pkt_len - dns_payload_offset, resolved_ip, dynamic_ttl)) {
                        uint64_t expiry_ns = now_ns + (static_cast<uint64_t>(dynamic_ttl) * 1000000000ULL);
                        dns_cache->insert(query_domain, resolved_ip, expiry_ns);
                        cached_ipv4 = resolved_ip;
                    }
                }

                // Header Flags: Standard Response (0x8180)
                *reinterpret_cast<uint16_t*>(pkt + dns_payload_offset + 2) = htons(0x8180);
                *reinterpret_cast<uint16_t*>(pkt + dns_payload_offset + 6) = htons(cached_ipv4 ? 1 : 0); // ANCOUNT
                *reinterpret_cast<uint16_t*>(pkt + dns_payload_offset + 8) = 0; // NSCOUNT = 0
                *reinterpret_cast<uint16_t*>(pkt + dns_payload_offset + 10) = 0; // ARCOUNT = 0

                size_t resp_dns_len = query_section_len;

                if (cached_ipv4 != 0) {
                    uint8_t* ans_ptr = pkt + dns_payload_offset + resp_dns_len;
                    *reinterpret_cast<uint16_t*>(ans_ptr) = htons(0xC00C);     // Compression Pointer to Name
                    *reinterpret_cast<uint16_t*>(ans_ptr + 2) = htons(1);       // TYPE A
                    *reinterpret_cast<uint16_t*>(ans_ptr + 4) = htons(1);       // CLASS IN
                    *reinterpret_cast<uint32_t*>(ans_ptr + 6) = htonl(60);      // TTL
                    *reinterpret_cast<uint16_t*>(ans_ptr + 10) = htons(4);      // RDLEN
                    *reinterpret_cast<uint32_t*>(ans_ptr + 12) = cached_ipv4;   // RDATA
                    resp_dns_len += 16;
                }

                uint16_t total_udp_len = 8 + resp_dns_len;
                uint16_t total_ip_len = 20 + total_udp_len;

                swap_headers_ipv4(pkt, total_ip_len, total_udp_len);
                tx_queue.push_back({addr, static_cast<uint32_t>(14 + total_ip_len)});
                handled = true;
            }
            // --------------------------------------------------------------------
            // TYPE AAAA (IPv6 Resolution)
            // --------------------------------------------------------------------
            else if (qtype == 28) {
                uint8_t cached_ipv6[16]{0};
                bool hit = dns_cache->lookup_ipv6(query_domain, cached_ipv6, now_ns);

                if (hit) {
                    std::cout << "[HIT]  AAAA " << query_domain << " (0 msec)\n";
                } else {
                    std::cout << "[MISS] AAAA " << query_domain << " -> Cloudflare...\n";
                    uint8_t ipv6_res[16]{0};
                    uint32_t dynamic_ttl = 60;
                    
                    if (resolve_upstream_ipv6(pkt + dns_payload_offset, pkt_len - dns_payload_offset, ipv6_res, dynamic_ttl)) {
                        uint64_t expiry_ns = now_ns + (static_cast<uint64_t>(dynamic_ttl) * 1000000000ULL);
                        dns_cache->insert_ipv6(query_domain, ipv6_res, expiry_ns);
                        std::memcpy(cached_ipv6, ipv6_res, 16);
                    }
                }

                static const uint8_t zero_ip[16]{0};
                bool has_ip = std::memcmp(cached_ipv6, zero_ip, 16) != 0;

                *reinterpret_cast<uint16_t*>(pkt + dns_payload_offset + 2) = htons(0x8180);
                *reinterpret_cast<uint16_t*>(pkt + dns_payload_offset + 6) = htons(has_ip ? 1 : 0);
                *reinterpret_cast<uint16_t*>(pkt + dns_payload_offset + 8) = 0;
                *reinterpret_cast<uint16_t*>(pkt + dns_payload_offset + 10) = 0;

                size_t resp_dns_len = query_section_len;

                if (has_ip) {
                    uint8_t* ans_ptr = pkt + dns_payload_offset + resp_dns_len;
                    *reinterpret_cast<uint16_t*>(ans_ptr) = htons(0xC00C);
                    *reinterpret_cast<uint16_t*>(ans_ptr + 2) = htons(28); // TYPE AAAA
                    *reinterpret_cast<uint16_t*>(ans_ptr + 4) = htons(1);
                    *reinterpret_cast<uint32_t*>(ans_ptr + 6) = htonl(60);
                    *reinterpret_cast<uint16_t*>(ans_ptr + 10) = htons(16);
                    std::memcpy(ans_ptr + 12, cached_ipv6, 16);
                    resp_dns_len += 28;
                }

                uint16_t total_udp_len = 8 + resp_dns_len;
                uint16_t total_ip_len = 20 + total_udp_len;

                swap_headers_ipv4(pkt, total_ip_len, total_udp_len);
                tx_queue.push_back({addr, static_cast<uint32_t>(14 + total_ip_len)});
                handled = true;
            }

            if (!handled) {
                recycle_queue.push_back(addr);
            }
        }

        xsk_ring_cons__release(&xsk->rx, rcvd);

        if (!tx_queue.empty()) {
            uint32_t tx_idx = 0;
            uint32_t tx_reserved = xsk_ring_prod__reserve(&xsk->tx, tx_queue.size(), &tx_idx);
            for (size_t k = 0; k < tx_reserved; ++k) {
                struct xdp_desc* tx_desc = xsk_ring_prod__tx_desc(&xsk->tx, tx_idx + k);
                tx_desc->addr = tx_queue[k].first;
                tx_desc->len = tx_queue[k].second;
            }
            xsk_ring_prod__submit(&xsk->tx, tx_reserved);
            sendto(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
        }

        if (!recycle_queue.empty()) {
            uint32_t fill_idx = 0;
            uint32_t fill_reserved = xsk_ring_prod__reserve(&xsk->umem->fq, recycle_queue.size(), &fill_idx);
            for (size_t k = 0; k < fill_reserved; ++k) {
                *xsk_ring_prod__fill_addr(&xsk->umem->fq, fill_idx + k) = recycle_queue[k];
            }
            xsk_ring_prod__submit(&xsk->umem->fq, fill_reserved);
        }
    }

    running.store(false);
    std::cout << "\n[!] Detaching kernel hooks and shutting down...\n";
    bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);
    xsk_socket__delete(xsk->xsk);
    xsk_umem__delete(umem->umem);
    return 0;
}
