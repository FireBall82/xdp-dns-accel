#ifndef COMMON_STRUCTS_H
#define COMMON_STRUCTS_H

#if defined(__cplusplus)
#include <linux/types.h>
extern "C" {
#endif

#define IP_BLOCKLIST_MAX_ENTRIES 65536
// Leave room for kernel headroom in the daemon's 4096-byte UMEM chunks.
// Larger packets continue through the kernel instead of being lost in AF_XDP.
#define DNS_MAX_PACKET_SIZE 2048

struct ipv4_prefix_key { __u32 prefixlen; __u32 address; };
struct dns_filter_config {
    __u32 restrict_clients;
    __u32 restrict_destination;
    __u32 destination; // network byte order
};

struct packet_stats {
    __u64 rx_packets;
    __u64 dropped_packets;
    __u64 dns_redirected;
    __u64 unauthorized;
    __u64 destination_passed;
};

#if defined(__cplusplus)
}
#endif

#endif // COMMON_STRUCTS_H
