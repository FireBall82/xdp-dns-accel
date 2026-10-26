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

#include "shared_dns_table.hpp"

using namespace net_accel;

volatile sig_atomic_t global_exit_flag = 0;

void sigint_handler(int) { global_exit_flag = 1; }

constexpr size_t NUM_FRAMES = 4096;
constexpr size_t FRAME_SIZE = XSK_UMEM__DEFAULT_FRAME_SIZE;
constexpr size_t BATCH_SIZE = 64;

// 1. Define the shared UMEM pool struct
struct xsk_umem_info {
    struct xsk_ring_prod fq;
    struct xsk_ring_cons cq;
    struct xsk_umem *umem;
    void *buffer;
};

// 2. Update your socket struct to hold a pointer to the shared UMEM
struct xsk_socket_info {
    struct xsk_ring_cons rx;
    struct xsk_ring_prod tx;
    struct xsk_umem_info *umem; // Pointer to shared UMEM pool
    struct xsk_socket *xsk;
    
    // ... keep any other existing fields like queue_id, umem_frame_addr, etc.
};
struct dns_header {
  uint16_t id;
  uint16_t flags;
  uint16_t qdcount;
  uint16_t ancount;
  uint16_t nscount;
  uint16_t arcount;
} __attribute__((packed));

// --- STRICT RFC 1071 CHECKSUM CALCULATORS ---
uint16_t calc_checksum(const void *b, int len) {
  uint32_t sum = 0;
  const uint16_t *buf = (const uint16_t *)b;
  while (len > 1) {
    sum += *buf++;
    len -= 2;
  }
  if (len == 1) {
    sum += *(const uint8_t *)buf;
  }
  sum = (sum >> 16) + (sum & 0xFFFF);
  sum += (sum >> 16);
  return ~sum;
}

uint16_t calc_udp_csum(struct iphdr *ip, struct udphdr *udp) {
  uint32_t sum = 0;
  uint16_t *s = (uint16_t *)&ip->saddr;
  uint16_t *d = (uint16_t *)&ip->daddr;
  // UDP Pseudo-header
  sum += s[0] + s[1] + d[0] + d[1];
  sum += htons(IPPROTO_UDP);
  sum += udp->len;

  // UDP Payload
  uint16_t csum = calc_checksum(udp, ntohs(udp->len));
  sum += (~csum & 0xFFFF);
  sum = (sum >> 16) + (sum & 0xFFFF);
  sum += (sum >> 16);

  uint16_t res = ~sum;
  return res == 0 ? 0xFFFF : res;
}
size_t parse_dns_qname(const uint8_t *payload, size_t max_len,
                       std::string &domain) {
  size_t offset = 0;
  domain.clear();
  while (offset < max_len) {
    uint8_t len = payload[offset++];
    if (len == 0)
      return offset;
    if ((len & 0xC0) == 0xC0)
      return 0;
    if (offset + len > max_len)
      return 0;

    if (!domain.empty())
      domain += ".";
    domain.append(reinterpret_cast<const char *>(payload + offset), len);
    offset += len;
  }
  return 0;
}

xsk_umem_info *configure_umem() {
  auto *ui = new xsk_umem_info();
  if (posix_memalign(&ui->buffer, getpagesize(), NUM_FRAMES * FRAME_SIZE)) {
    std::cerr << "Failed to allocate UMEM buffer\n";
    exit(EXIT_FAILURE);
  }

  struct xsk_umem_config cfg = {.fill_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
                                .comp_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
                                .frame_size = FRAME_SIZE,
                                .frame_headroom =
                                    XSK_UMEM__DEFAULT_FRAME_HEADROOM,
                                .flags = 0};

  if (xsk_umem__create(&ui->umem, ui->buffer, NUM_FRAMES * FRAME_SIZE, &ui->fq,
                       &ui->cq, &cfg)) {
    std::cerr << "Failed to create UMEM\n";
    exit(EXIT_FAILURE);
  }
  return ui;
}

xsk_socket_info *setup_socket(const char *ifname, uint32_t queue_id,
                              xsk_umem_info *umem_info) {
  auto *si = new xsk_socket_info();
  si->umem = umem_info;

  struct xsk_socket_config cfg = {.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
                                  .tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
                                  .libxdp_flags =
                                      XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD,
                                  .xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST,
                                  .bind_flags = XDP_USE_NEED_WAKEUP};

  if (xsk_socket__create(&si->xsk, ifname, queue_id, umem_info->umem, &si->rx,
                         &si->tx, &cfg)) {
    std::cerr << "Failed to create AF_XDP socket on " << ifname << "\n";
    exit(EXIT_FAILURE);
  }
  return si;
}
// --- SLOW PATH: Upstream IPv4 (A) Resolution with Dynamic TTL ---
uint32_t resolve_upstream_ipv4(const uint8_t *query_payload, size_t query_len, uint32_t &out_ttl) {
    out_ttl = 60; // Default fallback TTL

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return 0;

    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in up_addr;
    memset(&up_addr, 0, sizeof(up_addr));
    up_addr.sin_family = AF_INET;
    up_addr.sin_port = htons(53);
    inet_pton(AF_INET, "1.1.1.1", &up_addr.sin_addr);

    if (sendto(sock, query_payload, query_len, 0, (struct sockaddr *)&up_addr, sizeof(up_addr)) < 0) {
        close(sock);
        return 0;
    }

    uint8_t resp[512];
    ssize_t res = recvfrom(sock, resp, sizeof(resp), 0, NULL, NULL);
    close(sock);

    if (res < 12) return 0;
    size_t res_len = static_cast<size_t>(res);

    uint16_t ancount = ntohs(*(uint16_t *)(resp + 6));
    if (ancount == 0) return 0;

    size_t offset = 12;
    while (offset < res_len && resp[offset] != 0) {
        offset += resp[offset] + 1;
    }
    offset += 5; // Skip QNAME null byte + QTYPE(2) + QCLASS(2)

    for (int i = 0; i < ancount && offset < res_len; i++) {
        if ((resp[offset] & 0xC0) == 0xC0) {
            offset += 2;
        } else {
            while (offset < res_len && resp[offset] != 0) {
                if ((resp[offset] & 0xC0) == 0xC0) { offset += 2; break; }
                offset += resp[offset] + 1;
            }
            if (offset < res_len && resp[offset] == 0) offset += 1;
        }

        if (offset + 10 > res_len) return 0;
        
        uint16_t type  = ntohs(*(uint16_t *)(resp + offset));
        uint32_t ttl   = ntohl(*(uint32_t *)(resp + offset + 4)); // Extract 4-byte TTL
        uint16_t rdlen = ntohs(*(uint16_t *)(resp + offset + 8));
        offset += 10;

        if (type == 1 && rdlen == 4 && offset + 4 <= res_len) {
            uint32_t resolved_ip;
            memcpy(&resolved_ip, resp + offset, 4);
            out_ttl = (ttl > 0) ? ttl : 60;
            return resolved_ip;
        }
        offset += rdlen;
    }
    return 0;
}

// --- SLOW PATH: Upstream IPv6 (AAAA) Resolution with Dynamic TTL ---
bool resolve_upstream_ipv6(const uint8_t* query_payload, size_t query_len, uint8_t* out_ipv6, uint32_t &out_ttl) {
    out_ttl = 60; // Default fallback TTL

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return false;

    struct timeval tv;
    tv.tv_sec = 1; tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in up_addr;
    memset(&up_addr, 0, sizeof(up_addr));
    up_addr.sin_family = AF_INET;
    up_addr.sin_port = htons(53);
    inet_pton(AF_INET, "1.1.1.1", &up_addr.sin_addr);

    if (sendto(sock, query_payload, query_len, 0, (struct sockaddr*)&up_addr, sizeof(up_addr)) < 0) {
        close(sock);
        return false;
    }

    uint8_t resp[512];
    ssize_t res = recvfrom(sock, resp, sizeof(resp), 0, NULL, NULL);
    close(sock);

    if (res < 12) return false;
    size_t res_len = static_cast<size_t>(res);

    uint16_t ancount = ntohs(*(uint16_t*)(resp + 6));
    if (ancount == 0) return false;

    size_t offset = 12;
    while (offset < res_len && resp[offset] != 0) { offset += resp[offset] + 1; }
    offset += 5; // null terminator + QTYPE(2) + QCLASS(2)

    for (int i = 0; i < ancount && offset < res_len; i++) {
        if ((resp[offset] & 0xC0) == 0xC0) {
            offset += 2;
        } else {
            while (offset < res_len && resp[offset] != 0) {
                if ((resp[offset] & 0xC0) == 0xC0) { offset += 2; break; }
                offset += resp[offset] + 1;
            }
            if (offset < res_len && resp[offset] == 0) offset += 1;
        }

        if (offset + 10 > res_len) return false;
        
        uint16_t type  = ntohs(*(uint16_t*)(resp + offset));
        uint32_t ttl   = ntohl(*(uint32_t*)(resp + offset + 4)); // Extract 4-byte TTL
        uint16_t rdlen = ntohs(*(uint16_t*)(resp + offset + 8));
        offset += 10;

        if (type == 28 && rdlen == 16 && offset + 16 <= res_len) {
            memcpy(out_ipv6, resp + offset, 16);
            out_ttl = (ttl > 0) ? ttl : 60;
            return true;
        }
        offset += rdlen;
    }
    return false;
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

  // 1. Manually Load & Attach the eBPF Kernel program
  struct bpf_object *obj = bpf_object__open_file("xdp_filter.bpf.o", NULL);
  if (!obj || bpf_object__load(obj)) {
    std::cerr << "[!] Failed to load xdp_filter.bpf.o (Are you running from "
                 "the build directory?)\n";
    return EXIT_FAILURE;
  }

  int prog_fd = bpf_program__fd(
      bpf_object__find_program_by_name(obj, "xdp_dns_accelerator"));

  if (bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE, NULL) < 0) {
    std::cerr << "[!] Failed to attach eBPF program to interface\n";
    return EXIT_FAILURE;
  }
  std::cout << "[+] eBPF program injected into kernel driver for " << ifname
            << "\n";
// 2. Init Cache & Inject Test Record
 auto *dns_cache = SharedDnsTable<>::create_or_attach(true);
  std::cout << "[+] Shared memory cache initialized at "
            << SharedDnsTable<>::SHM_PATH << "\n";

  dns_cache->insert("google.com", inet_addr("1.2.3.4"), 0xFFFFFFFFFFFFFFFFULL);
  std::cout << "[+] Test record inserted: google.com -> 1.2.3.4\n";

  xsk_umem_info *umem = configure_umem();
  xsk_socket_info *xsk = setup_socket(ifname, queue_id, umem);
  
  xsk->umem = umem; // <-- ADD THIS LINE HERE
  // 3. Link Socket to eBPF Map
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

  std::cout << "[+] AF_XDP socket bound to " << ifname << " queue " << queue_id
            << "\n";
  std::cout << "[+] Entering fast-path poll loop...\n";

  struct pollfd fds[1];
  fds[0].fd = xsk_socket__fd(xsk->xsk);
  fds[0].events = POLLIN;

  while (!global_exit_flag) {
        struct pollfd fds[1] = {};
        fds[0].fd = xsk_socket__fd(xsk->xsk);
        fds[0].events = POLLIN;

        int ret = poll(fds, 1, 100);
        if (ret <= 0) continue;

        uint32_t idx_rx = 0;
        uint32_t rcvd = xsk_ring_cons__peek(&xsk->rx, BATCH_SIZE, &idx_rx);
        if (!rcvd) continue;

        std::vector<uint64_t> tx_addrs;
        std::vector<uint32_t> tx_lens;
        std::vector<uint64_t> recycle_queue;

        for (uint32_t i = 0; i < rcvd; i++) {
            uint64_t addr = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx + i)->addr;
            uint32_t len  = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx + i)->len;
            uint8_t* pkt = (uint8_t*)xsk_umem__get_data(xsk->umem->buffer, addr);
            if (len < sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dns_header)) {
                recycle_queue.push_back(addr);
                continue;
            }

            struct ether_header *eth = (struct ether_header *)pkt;
            struct iphdr *ip = (struct iphdr *)(pkt + sizeof(struct ether_header));
            size_t ip_hlen = ip->ihl * 4;
            struct udphdr *udp = (struct udphdr *)((uint8_t*)ip + ip_hlen);
            uint8_t *dns_raw = (uint8_t *)udp + sizeof(struct udphdr);
            struct dns_header *dns = (struct dns_header *)dns_raw;

            size_t dns_payload_len = ntohs(udp->len) - sizeof(struct udphdr);
            const uint8_t *qname = dns_raw + sizeof(struct dns_header);
            size_t max_qname_len = dns_payload_len - sizeof(struct dns_header);

            std::string query_domain;
            size_t consumed_bytes = parse_dns_qname(qname, max_qname_len, query_domain);

            if (consumed_bytes > 0 && (consumed_bytes + 4) <= max_qname_len) {
                uint16_t qtype = ntohs(*(uint16_t*)(qname + consumed_bytes));

                struct timespec ts;
                clock_gettime(CLOCK_MONOTONIC, &ts);
                uint64_t now_ns = (ts.tv_sec * 1000000000ULL) + ts.tv_nsec;

                if (qtype == 1) {
                    // --- IPv4 (A-RECORD) ---
                    uint32_t resolved_ip = 0;
                    uint32_t ttl_sec = 60;

                    if (dns_cache->lookup(query_domain, resolved_ip, now_ns)) {
                        std::cout << "[HIT]  A " << query_domain << " (0 msec)\n";
                    } else {
                        std::cout << "[MISS] A " << query_domain << " -> Cloudflare...\n";
                        resolved_ip = resolve_upstream_ipv4(dns_raw, dns_payload_len, ttl_sec);

                        if (resolved_ip != 0) {
                            uint64_t expiry_ns = now_ns + (static_cast<uint64_t>(ttl_sec) * 1000000000ULL);
                            dns_cache->insert(query_domain, resolved_ip, expiry_ns);
                            struct in_addr print_ip; print_ip.s_addr = resolved_ip;
                            std::cout << "[CACHE] A " << query_domain << " -> " << inet_ntoa(print_ip) 
                                      << " (TTL: " << ttl_sec << "s)\n";
                        }
                    }

                    if (resolved_ip != 0) {
                        dns->flags = htons(0x8180);
                        dns->ancount = htons(1);
                        dns->nscount = 0;
                        dns->arcount = 0;

                        size_t query_size = sizeof(struct dns_header) + consumed_bytes + 4;
                        uint8_t* answer_ptr = dns_raw + query_size;

                        answer_ptr[0] = 0xc0; answer_ptr[1] = 0x0c; // Pointer to QNAME
                        answer_ptr[2] = 0x00; answer_ptr[3] = 0x01; // Type A
                        answer_ptr[4] = 0x00; answer_ptr[5] = 0x01; // Class IN
                        uint32_t ttl_net = htonl(ttl_sec);
                        memcpy(&answer_ptr[6], &ttl_net, 4);        // Dynamic TTL
                        answer_ptr[10] = 0x00; answer_ptr[11] = 0x04; // RDLENGTH 4
                        memcpy(&answer_ptr[12], &resolved_ip, 4);   // RDATA IP

                        size_t new_dns_len = query_size + 16;
                        size_t new_udp_len = sizeof(struct udphdr) + new_dns_len;
                        size_t new_ip_len = ip_hlen + new_udp_len;
                        size_t new_frame_len = sizeof(struct ether_header) + new_ip_len;

                        for (int j = 0; j < ETH_ALEN; j++) {
                            std::swap(eth->ether_shost[j], eth->ether_dhost[j]);
                        }

                        std::swap(ip->saddr, ip->daddr);
                        ip->tot_len = htons(new_ip_len);
                        ip->check = 0;
                        ip->check = calc_checksum(ip, ip_hlen);

                        std::swap(udp->source, udp->dest);
                        udp->len = htons(new_udp_len);
                        udp->check = 0;
                        udp->check = calc_udp_csum(ip, udp);

                        tx_addrs.push_back(addr);
                        tx_lens.push_back(new_frame_len);
                    } else {
                        recycle_queue.push_back(addr);
                    }

                } else if (qtype == 28) {
                    // --- IPv6 (AAAA-RECORD) ---
                    uint8_t ipv6_buf[16];
                    uint32_t ttl_sec_v6 = 60;
                    std::cout << "[MISS] AAAA " << query_domain << " -> Cloudflare...\n";

                    if (resolve_upstream_ipv6(dns_raw, dns_payload_len, ipv6_buf, ttl_sec_v6)) {
                        char ip_str[INET6_ADDRSTRLEN];
                        inet_ntop(AF_INET6, ipv6_buf, ip_str, sizeof(ip_str));
                        std::cout << "[CACHE] AAAA " << query_domain << " -> " << ip_str 
                                  << " (TTL: " << ttl_sec_v6 << "s)\n";

                        dns->flags = htons(0x8180);
                        dns->ancount = htons(1);
                        dns->nscount = 0;
                        dns->arcount = 0;

                        size_t query_size = sizeof(struct dns_header) + consumed_bytes + 4;
                        uint8_t* answer_ptr = dns_raw + query_size;

                        answer_ptr[0] = 0xc0; answer_ptr[1] = 0x0c; // Pointer to QNAME
                        answer_ptr[2] = 0x00; answer_ptr[3] = 0x1c; // Type AAAA (28)
                        answer_ptr[4] = 0x00; answer_ptr[5] = 0x01; // Class IN
                        uint32_t ttl_net = htonl(ttl_sec_v6);
                        memcpy(&answer_ptr[6], &ttl_net, 4);        // Dynamic TTL
                        answer_ptr[10] = 0x00; answer_ptr[11] = 0x10; // RDLENGTH 16
                        memcpy(&answer_ptr[12], ipv6_buf, 16);      // RDATA IPv6

                        size_t new_dns_len = query_size + 28;
                        size_t new_udp_len = sizeof(struct udphdr) + new_dns_len;
                        size_t new_ip_len = ip_hlen + new_udp_len;
                        size_t new_frame_len = sizeof(struct ether_header) + new_ip_len;

                        for (int j = 0; j < ETH_ALEN; j++) {
                            std::swap(eth->ether_shost[j], eth->ether_dhost[j]);
                        }

                        std::swap(ip->saddr, ip->daddr);
                        ip->tot_len = htons(new_ip_len);
                        ip->check = 0;
                        ip->check = calc_checksum(ip, ip_hlen);

                        std::swap(udp->source, udp->dest);
                        udp->len = htons(new_udp_len);
                        udp->check = 0;
                        udp->check = calc_udp_csum(ip, udp);

                        tx_addrs.push_back(addr);
                        tx_lens.push_back(new_frame_len);
                    } else {
                        // Empty response synthesis for missing IPv6 records
                        dns->flags = htons(0x8180);
                        dns->ancount = htons(0);
                        dns->nscount = 0;
                        dns->arcount = 0;

                        size_t query_size = sizeof(struct dns_header) + consumed_bytes + 4;
                        size_t new_dns_len = query_size;
                        size_t new_udp_len = sizeof(struct udphdr) + new_dns_len;
                        size_t new_ip_len = ip_hlen + new_udp_len;
                        size_t new_frame_len = sizeof(struct ether_header) + new_ip_len;

                        for (int j = 0; j < ETH_ALEN; j++) {
                            std::swap(eth->ether_shost[j], eth->ether_dhost[j]);
                        }

                        std::swap(ip->saddr, ip->daddr);
                        ip->tot_len = htons(new_ip_len);
                        ip->check = 0;
                        ip->check = calc_checksum(ip, ip_hlen);

                        std::swap(udp->source, udp->dest);
                        udp->len = htons(new_udp_len);
                        udp->check = 0;
                        udp->check = calc_udp_csum(ip, udp);

                        tx_addrs.push_back(addr);
                        tx_lens.push_back(new_frame_len);
                    }
                } else {
                    recycle_queue.push_back(addr);
                }
            } else {
                recycle_queue.push_back(addr);
            }
        }

        // --- RX RELEASE & TX BOUNCE ---
        xsk_ring_cons__release(&xsk->rx, rcvd);

        if (!tx_addrs.empty()) {
            uint32_t tx_idx = 0;
            uint32_t reserved = xsk_ring_prod__reserve(&xsk->tx, tx_addrs.size(), &tx_idx);
            if (reserved > 0) {
                for (uint32_t k = 0; k < reserved; k++) {
                    xsk_ring_prod__tx_desc(&xsk->tx, tx_idx + k)->addr = tx_addrs[k];
                    xsk_ring_prod__tx_desc(&xsk->tx, tx_idx + k)->len  = tx_lens[k];
                }
                xsk_ring_prod__submit(&xsk->tx, reserved);
                sendto(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
            } else {
                for (uint64_t a : tx_addrs) recycle_queue.push_back(a);
            }
        }

       // --- UMEM FILL RING RECYCLING ---
        if (!recycle_queue.empty()) {
            uint32_t fill_idx = 0;
            uint32_t fill_reserved = xsk_ring_prod__reserve(&xsk->umem->fq, recycle_queue.size(), &fill_idx);
            if (fill_reserved > 0) {
                for (uint32_t k = 0; k < fill_reserved; k++) {
                    *xsk_ring_prod__fill_addr(&xsk->umem->fq, fill_idx + k) = recycle_queue[k];
                }
                xsk_ring_prod__submit(&xsk->umem->fq, fill_reserved);
            }
        }
    }
  std::cout << "\n[!] Detaching kernel hooks and shutting down...\n";
  bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);
  xsk_socket__delete(xsk->xsk);
  xsk_umem__delete(umem->umem);
  return 0;
}
