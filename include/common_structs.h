#ifndef COMMON_STRUCTS_H
#define COMMON_STRUCTS_H

#if defined(__cplusplus)
#include <cstdint>
typedef uint8_t  __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;
extern "C" {
#endif

#define IP_BLOCKLIST_MAX_ENTRIES 65536

struct packet_stats {
    __u64 rx_packets;
    __u64 dropped_packets;
    __u64 dns_redirected;
};

struct dns_cache_entry {
    __u32 domain_hash;
    __u32 ipv4_addr;
    __u64 ttl_expiration;
    __u32 hit_count;
    __u8  ipv6_addr[16];
    __u64 ipv6_ttl_expiration;
} __attribute__((packed, aligned(8)));

#if defined(__cplusplus)
}
#endif

#endif // COMMON_STRUCTS_H
