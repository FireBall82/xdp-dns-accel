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

struct xsk_umem_info {
  struct xsk_ring_prod fq;
  struct xsk_ring_cons cq;
  struct xsk_umem *umem;
  void *buffer;
};

struct xsk_socket_info {
  struct xsk_ring_cons rx;
  struct xsk_ring_prod tx;
  struct xsk_socket *xsk;
  xsk_umem_info *umem_info;
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
  si->umem_info = umem_info;

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
// --- SLOW PATH: Upstream Resolution ---
uint32_t resolve_upstream_ipv4(const uint8_t *query_payload, size_t query_len) {
  int sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock < 0)
    return 0;

  // Set a 1-second timeout so the engine doesn't lock up if the internet drops
  struct timeval tv;
  tv.tv_sec = 1;
  tv.tv_usec = 0;
  setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

  struct sockaddr_in up_addr;
  memset(&up_addr, 0, sizeof(up_addr));
  up_addr.sin_family = AF_INET;
  up_addr.sin_port = htons(53);
  inet_pton(AF_INET, "1.1.1.1", &up_addr.sin_addr); // Cloudflare DNS

  // Forward the raw XDP query to Cloudflare
  sendto(sock, query_payload, query_len, 0, (struct sockaddr *)&up_addr,
         sizeof(up_addr));

  uint8_t resp[512];
  ssize_t res = recvfrom(sock, resp, sizeof(resp), 0, NULL, NULL);
  close(sock);

  if (res < 12)
    return 0; // Timeout or malformed
  size_t res_len =
      static_cast<size_t>(res); // Cast to unsigned for safe comparison

  uint16_t ancount = ntohs(*(uint16_t *)(resp + 6));
  if (ancount == 0)
    return 0; // NXDOMAIN

  size_t offset = 12;
  while (offset < res_len && resp[offset] != 0) {
    offset += resp[offset] + 1;
  }
  offset += 5;

  for (int i = 0; i < ancount && offset < res_len; i++) {
    if ((resp[offset] & 0xC0) == 0xC0) {
      offset += 2;
    } else {
      while (offset < res_len && resp[offset] != 0) {
        if ((resp[offset] & 0xC0) == 0xC0) {
          offset += 2;
          break;
        }
        offset += resp[offset] + 1;
      }
      if (offset < res_len && resp[offset] == 0)
        offset += 1;
    }

    if (offset + 10 > res_len)
      return 0;
    uint16_t type = ntohs(*(uint16_t *)(resp + offset));
    uint16_t rdlen = ntohs(*(uint16_t *)(resp + offset + 8));
    offset += 10;

    if (type == 1 && rdlen == 4 && offset + 4 <= res_len) {
      uint32_t resolved_ip;
      memcpy(&resolved_ip, resp + offset, 4);
      return resolved_ip;
    }
    offset += rdlen;
  }
  return 0;
}

// --- SLOW PATH: Upstream IPv6 (AAAA) Resolution ---
bool resolve_upstream_ipv6(const uint8_t* query_payload, size_t query_len, uint8_t* out_ipv6) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return false;

    // Set a 1-second timeout so the engine doesn't lock up if the internet drops
    struct timeval tv;
    tv.tv_sec = 1; tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in up_addr;
    memset(&up_addr, 0, sizeof(up_addr));
    up_addr.sin_family = AF_INET;
    up_addr.sin_port = htons(53);
    inet_pton(AF_INET, "1.1.1.1", &up_addr.sin_addr); // Cloudflare DNS

    // Forward the raw AAAA query to Cloudflare
    sendto(sock, query_payload, query_len, 0, (struct sockaddr*)&up_addr, sizeof(up_addr));

    uint8_t resp[512];
    ssize_t res = recvfrom(sock, resp, sizeof(resp), 0, NULL, NULL);
    close(sock);

    if (res < 12) return false; // Timeout or malformed
    size_t res_len = static_cast<size_t>(res);

    uint16_t ancount = ntohs(*(uint16_t*)(resp + 6));
    if (ancount == 0) return false; // No AAAA records

    // Skip question section
    size_t offset = 12;
    while (offset < res_len && resp[offset] != 0) { offset += resp[offset] + 1; }
    offset += 5; // null terminator + QTYPE(2) + QCLASS(2)

    // Walk answer records looking for Type 28 (AAAA) with rdlen 16
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
        uint16_t rdlen = ntohs(*(uint16_t*)(resp + offset + 8));
        offset += 10;

        if (type == 28 && rdlen == 16 && offset + 16 <= res_len) {
            memcpy(out_ipv6, resp + offset, 16);
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
    int ret = poll(fds, 1, 1000);
    if (ret <= 0)
      continue;

    uint32_t rx_idx = 0;
    uint32_t rcvd = xsk_ring_cons__peek(&xsk->rx, BATCH_SIZE, &rx_idx);
    if (!rcvd)
      continue;

    std::vector<uint64_t> tx_addrs;
    std::vector<uint32_t> tx_lens;
    std::vector<uint64_t> drop_addrs;

    for (uint32_t i = 0; i < rcvd; i++) {
      const struct xdp_desc *desc = xsk_ring_cons__rx_desc(&xsk->rx, rx_idx++);
      uint64_t addr = desc->addr;
      uint32_t len = desc->len;

      uint8_t *pkt = static_cast<uint8_t *>(umem->buffer) + addr;

      struct ether_header *eth = reinterpret_cast<struct ether_header *>(pkt);
      if (ntohs(eth->ether_type) != ETHERTYPE_IP) {
        drop_addrs.push_back(addr);
        continue;
      }

      struct iphdr *ip =
          reinterpret_cast<struct iphdr *>(pkt + sizeof(struct ether_header));
      if (ip->protocol != IPPROTO_UDP) {
        drop_addrs.push_back(addr);
        continue;
      }

      size_t ip_hlen = ip->ihl * 4;
      struct udphdr *udp = reinterpret_cast<struct udphdr *>(
          reinterpret_cast<uint8_t *>(ip) + ip_hlen);

      uint8_t *dns_raw =
          reinterpret_cast<uint8_t *>(udp) + sizeof(struct udphdr);
      struct dns_header *dns = reinterpret_cast<struct dns_header *>(dns_raw);

      uint16_t flags = ntohs(dns->flags);

      // Only process standard queries (QR=0) with 1 question
      if ((flags & 0x8000) == 0 && ntohs(dns->qdcount) == 1) {
        uint8_t *qname = dns_raw + sizeof(struct dns_header);
        size_t max_qname_len = len - (qname - pkt);

        std::string query_domain;
        size_t consumed_bytes =
            parse_dns_qname(qname, max_qname_len, query_domain);

        if (consumed_bytes > 0) {
          // --- Read QTYPE from the 2 bytes immediately after the QNAME ---
          uint8_t *qtype_ptr = qname + consumed_bytes;
          if (qtype_ptr + 4 > pkt + len) {
            drop_addrs.push_back(addr);
            continue;
          }
          uint16_t qtype = ntohs(*(uint16_t *)qtype_ptr);

          if (qtype == 28) {
            // --- IPv6 (AAAA) RECORD PROCESSING ---
            uint8_t resolved_ipv6[16] = {};
            bool have_ipv6 = false;
            struct timespec ts;
            clock_gettime(CLOCK_MONOTONIC, &ts);
            uint64_t now_ns = (ts.tv_sec * 1000000000ULL) + ts.tv_nsec;

            // --- CACHE LOOKUP ---
            if (dns_cache->lookup_ipv6(query_domain, resolved_ipv6, now_ns)) {
              char ipv6_str[INET6_ADDRSTRLEN];
              inet_ntop(AF_INET6, resolved_ipv6, ipv6_str, sizeof(ipv6_str));
              std::cout << "[HIT6] " << query_domain << " -> " << ipv6_str
                        << "\n";
              have_ipv6 = true;
            } else {
              // --- CACHE MISS: QUERY UPSTREAM ---
              std::cout << "[MISS6] " << query_domain
                        << " -> Querying Upstream (AAAA)...\n";
              size_t dns_payload_len = ntohs(udp->len) - sizeof(struct udphdr);

              have_ipv6 = resolve_upstream_ipv6(dns_raw, dns_payload_len,
                                                resolved_ipv6);

              if (have_ipv6) {
                // Expire 60 seconds from now
                dns_cache->insert_ipv6(query_domain, resolved_ipv6,
                                       now_ns + (60ULL * 1000000000ULL));

                char ipv6_str[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, resolved_ipv6, ipv6_str, sizeof(ipv6_str));
                std::cout << "[CACHE6] Saved " << query_domain << " -> "
                          << ipv6_str << "\n";
              }
            }

            if (have_ipv6) {
              // --- CRAFT AAAA RESPONSE ---
              dns->flags = htons(0x8180); // QR=1, RD=1, RA=1
              dns->ancount = htons(1);    // 1 Answer
              dns->nscount = 0;
              dns->arcount = 0; // Strip EDNS

              size_t query_size =
                  sizeof(struct dns_header) + consumed_bytes + 4;

              // Inject 28-byte AAAA Answer Block
              uint8_t *answer_ptr = dns_raw + query_size;
              answer_ptr[0] = 0xc0;
              answer_ptr[1] = 0x0c; // Pointer to name
              answer_ptr[2] = 0x00;
              answer_ptr[3] = 0x1c; // Type AAAA (28)
              answer_ptr[4] = 0x00;
              answer_ptr[5] = 0x01; // Class IN
              answer_ptr[6] = 0x00;
              answer_ptr[7] = 0x00; // TTL 60
              answer_ptr[8] = 0x00;
              answer_ptr[9] = 0x3c;
              answer_ptr[10] = 0x00;
              answer_ptr[11] = 0x10;                      // RDLENGTH 16
              memcpy(&answer_ptr[12], resolved_ipv6, 16); // IPv6 Address

              // Calculate new lengths (answer = 12-byte header + 16-byte addr =
              // 28)
              size_t new_dns_len = query_size + 28;
              size_t new_udp_len = sizeof(struct udphdr) + new_dns_len;
              size_t new_ip_len = ip_hlen + new_udp_len;
              size_t new_frame_len = sizeof(struct ether_header) + new_ip_len;

              // L2 MAC Swap
              for (int j = 0; j < ETH_ALEN; j++) {
                std::swap(eth->ether_shost[j], eth->ether_dhost[j]);
              }

              // L3 IP Swap & Checksum
              std::swap(ip->saddr, ip->daddr);
              ip->tot_len = htons(new_ip_len);
              ip->check = 0;
              ip->check = calc_checksum(ip, ip_hlen);

              // L4 UDP Swap & Checksum
              std::swap(udp->source, udp->dest);
              udp->len = htons(new_udp_len);
              udp->check = 0;
              udp->check = calc_udp_csum(ip, udp);

              tx_addrs.push_back(addr);
              tx_lens.push_back(new_frame_len);
            } else {
              // No AAAA record exists — synthesize empty NOERROR so
              // the browser instantly falls back to IPv4 without timeout
              std::cout << "[AAAA] " << query_domain
                        << " -> No AAAA, empty NOERROR\n";

              dns->flags = htons(0x8180);
              dns->ancount = 0;
              dns->nscount = 0;
              dns->arcount = 0;

              size_t query_size =
                  sizeof(struct dns_header) + consumed_bytes + 4;
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

          } else if (qtype == 1) {
            // --- IPv4 (A) RECORD PROCESSING ---
            uint32_t resolved_ip = 0;
            struct timespec ts;
            clock_gettime(CLOCK_MONOTONIC, &ts);
            uint64_t now_ns = (ts.tv_sec * 1000000000ULL) + ts.tv_nsec;

            // --- CACHE LOOKUP ---
            if (dns_cache->lookup(query_domain, resolved_ip, now_ns)) {
              std::cout << "[HIT]  " << query_domain
                        << " -> Bouncing Response!\n";
            } else {
              // --- CACHE MISS: QUERY UPSTREAM ---
              std::cout << "[MISS] " << query_domain
                        << " -> Querying Upstream...\n";
              size_t dns_payload_len = ntohs(udp->len) - sizeof(struct udphdr);

              resolved_ip = resolve_upstream_ipv4(dns_raw, dns_payload_len);

              if (resolved_ip != 0) {
                // Expire 60 seconds from now (60 billion nanoseconds)
                dns_cache->insert(query_domain, resolved_ip,
                                  now_ns + (60ULL * 1000000000ULL));

                struct in_addr print_ip;
                print_ip.s_addr = resolved_ip;
                std::cout << "[CACHE] Saved " << query_domain << " -> "
                          << inet_ntoa(print_ip) << "\n";
              }
            }

            // --- CONVERGENCE: CRAFT PACKET ---
            if (resolved_ip != 0) {
              dns->flags = htons(0x8180); // Pure response, clear AD bits
              dns->ancount = htons(1);    // 1 Answer
              dns->nscount = 0;
              dns->arcount = 0; // Strip EDNS

              // Calculate original query bounds (Header + QNAME + QTYPE +
              // QCLASS)
              size_t query_size =
                  sizeof(struct dns_header) + consumed_bytes + 4;

              // Inject 16-byte Answer Block at the end of the query
              uint8_t *answer_ptr = dns_raw + query_size;
              answer_ptr[0] = 0xc0;
              answer_ptr[1] = 0x0c; // Pointer to name
              answer_ptr[2] = 0x00;
              answer_ptr[3] = 0x01; // Type A
              answer_ptr[4] = 0x00;
              answer_ptr[5] = 0x01; // Class IN
              answer_ptr[6] = 0x00;
              answer_ptr[7] = 0x00; // TTL 60
              answer_ptr[8] = 0x00;
              answer_ptr[9] = 0x3c;
              answer_ptr[10] = 0x00;
              answer_ptr[11] = 0x04;                    // Data Len 4
              memcpy(&answer_ptr[12], &resolved_ip, 4); // IP Address

              // Calculate new lengths
              size_t new_dns_len = query_size + 16;
              size_t new_udp_len = sizeof(struct udphdr) + new_dns_len;
              size_t new_ip_len = ip_hlen + new_udp_len;
              size_t new_frame_len = sizeof(struct ether_header) + new_ip_len;

              // L2 MAC Swap
              for (int j = 0; j < ETH_ALEN; j++) {
                std::swap(eth->ether_shost[j], eth->ether_dhost[j]);
              }

              // L3 IP Swap & Checksum
              std::swap(ip->saddr, ip->daddr);
              ip->tot_len = htons(new_ip_len);
              ip->check = 0;
              ip->check = calc_checksum(ip, ip_hlen);

              // L4 UDP Swap & Checksum
              std::swap(udp->source, udp->dest);
              udp->len = htons(new_udp_len);
              udp->check = 0;
              udp->check = calc_udp_csum(ip, udp);

              tx_addrs.push_back(addr);
              tx_lens.push_back(new_frame_len);
            } else {
              // Upstream failed or returned NXDOMAIN, safely drop
              drop_addrs.push_back(addr);
            }

          } else {
            // Unsupported QTYPE (e.g. SRV, MX, TXT), drop and let kernel handle
            drop_addrs.push_back(addr);
          }
        } else {
          drop_addrs.push_back(addr); // Failed QNAME parsing
        }
      } else {
        drop_addrs.push_back(addr); // Not a standard query
      }
    }

    xsk_ring_cons__release(&xsk->rx, rcvd);

    // --- TX ENGINE (Push Zero-Copy Responses) ---
    if (!tx_addrs.empty()) {
      uint32_t tx_idx = 0;
      if (xsk_ring_prod__reserve(&xsk->tx, tx_addrs.size(), &tx_idx) ==
          tx_addrs.size()) {
        for (size_t i = 0; i < tx_addrs.size(); i++) {
          struct xdp_desc *tx_desc = xsk_ring_prod__tx_desc(&xsk->tx, tx_idx++);
          tx_desc->addr = tx_addrs[i];
          tx_desc->len = tx_lens[i];
        }
        xsk_ring_prod__submit(&xsk->tx, tx_addrs.size());
        sendto(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL,
               0); // Wake up kernel TX
      } else {
        // Ring full: Fallback to dropping to prevent memory leak
        for (auto a : tx_addrs)
          drop_addrs.push_back(a);
      }
    }

    // --- FILL QUEUE (Recycle Dropped Memory) ---
    if (!drop_addrs.empty()) {
      uint32_t fq_idx = 0;
      if (xsk_ring_prod__reserve(&umem->fq, drop_addrs.size(), &fq_idx) ==
          drop_addrs.size()) {
        for (size_t i = 0; i < drop_addrs.size(); i++) {
          *xsk_ring_prod__fill_addr(&umem->fq, fq_idx++) = drop_addrs[i];
        }
        xsk_ring_prod__submit(&umem->fq, drop_addrs.size());
      }
    }
  }

  std::cout << "\n[!] Detaching kernel hooks and shutting down...\n";
  bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);
  xsk_socket__delete(xsk->xsk);
  xsk_umem__delete(umem->umem);
  return 0;
}
