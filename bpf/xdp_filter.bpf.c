#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "common_structs.h"

#define ETH_P_IP 0x0800
#define IPPROTO_UDP 17
#define DNS_PORT 53

char LICENSE[] SEC("license") = "GPL";

// BPF Map: Blocked IPv4 addresses
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, IP_BLOCKLIST_MAX_ENTRIES);
    __type(key, __u32);   // IPv4 address
    __type(value, __u8);  // Status flag (1 = blocked)
} ip_blocklist SEC(".maps");

// BPF Map: AF_XDP Socket Ring Map for zero-copy redirection
struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __type(key, __u32);   // Queue ID
    __type(value, __u32); // AF_XDP socket fd
} xsks_map SEC(".maps");

// BPF Map: Global per-CPU packet counter stats
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct packet_stats);
} stats_map SEC(".maps");

SEC("xdp")
int xdp_dns_accelerator(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    __u32 key_zero = 0;
    struct packet_stats *stats = bpf_map_lookup_elem(&stats_map, &key_zero);
    if (stats) {
        stats->rx_packets++;
    }

    // 1. Parse Ethernet Header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    // 2. Parse IPv4 Header
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) {
        return XDP_PASS;
    }

    // Direct IPv4 lookup against IP Blocklist
    __u32 src_ip = iph->saddr;
    __u8 *blocked = bpf_map_lookup_elem(&ip_blocklist, &src_ip);
    if (blocked && *blocked == 1) {
        if (stats) {
            stats->dropped_packets++;
        }
        return XDP_DROP;
    }

    if (iph->protocol != IPPROTO_UDP) {
        return XDP_PASS;
    }

// 3. Parse UDP Header
    struct udphdr *udph = (void *)((__u8 *)iph + (iph->ihl * 4));
    if ((void *)(udph + 1) > data_end) {
        return XDP_PASS;
    }

    // ONLY intercept incoming UDP queries (Destination Port 53)
    // DO NOT intercept outgoing responses (Source Port 53)
    if (udph->dest == bpf_htons(DNS_PORT)) {
        __u32 rx_queue_id = ctx->rx_queue_index;

        if (bpf_map_lookup_elem(&xsks_map, &rx_queue_id)) {
            if (stats) {
                stats->dns_redirected++;
            }
            return bpf_redirect_map(&xsks_map, rx_queue_id, XDP_PASS);
        }
    }

    // Let responses bypass XDP so they can reach the kernel and `dig`
    return XDP_PASS;
}
