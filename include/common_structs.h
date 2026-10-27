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
// Leave room for kernel headroom in the daemon's 4096-byte UMEM chunks.
// Larger packets continue through the kernel instead of being lost in AF_XDP.
#define DNS_MAX_PACKET_SIZE 2048

struct packet_stats {
    __u64 rx_packets;
    __u64 dropped_packets;
    __u64 dns_redirected;
};

#if defined(__cplusplus)
}
#endif

#endif // COMMON_STRUCTS_H
