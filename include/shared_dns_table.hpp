#pragma once

#include <cstdint>
#include <chrono>
#include <atomic>
#include <string_view>
#include <cstring>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdexcept>
#include <new>

namespace net_accel {

// 64-bit FNV-1a hash algorithm evaluated at compile-time or run-time
constexpr uint32_t fnv1a_32(std::string_view str) noexcept {
    uint32_t hash = 2166136261u;
    for (char c : str) {
        hash ^= static_cast<uint8_t>(c);
        hash *= 16777619u;
    }
    return hash;
}
struct alignas(64) AtomicCacheBucket {
    std::atomic<uint32_t> domain_hash{0};
    std::atomic<uint32_t> ipv4_addr{0};
    uint8_t ipv6_addr[16]{0};
    std::atomic<uint64_t> ttl_expiration{0}; // Standardized TTL expiration field
    std::atomic<uint64_t> hit_count{0};      // Added for lookup metrics
};
inline uint32_t calculate_hash(std::string_view domain) {
    uint32_t hash = 2166136261u; // FNV-1a
    for (char c : domain) {
        hash ^= static_cast<uint8_t>(c);
        hash *= 16777619u;
    }
    return hash;
}
template<size_t Capacity = 131072> // Must be a power of two
class SharedDnsTable {
    static_assert((Capacity & (Capacity - 1)) == 0, "Capacity must be a power of 2");

public:
    struct TableHeader {
        uint64_t magic_identifier;
        uint32_t capacity;
        std::atomic<uint64_t> total_queries;
        std::atomic<uint64_t> cache_hits;
    };

    static constexpr uint64_t SHM_MAGIC = 0x444E535F41434345ULL; // "DNS_ACCE"
    static constexpr const char* SHM_PATH = "/net_accel_dns";

    SharedDnsTable() = default;

    // Create or attach to POSIX Shared Memory
    static SharedDnsTable* create_or_attach(bool is_master = true) {
        int shm_fd = ::shm_open(SHM_PATH, O_CREAT | O_RDWR, 0666);
        if (shm_fd < 0) {
            throw std::runtime_error("Failed to open POSIX Shared Memory");
        }

        size_t total_size = sizeof(TableHeader) + (sizeof(AtomicCacheBucket) * Capacity);

        if (is_master) {
            if (::ftruncate(shm_fd, total_size) < 0) {
                ::close(shm_fd);
                throw std::runtime_error("Failed to set Shared Memory size");
            }
        }

        void* addr = ::mmap(nullptr, total_size, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
        ::close(shm_fd);

        if (addr == MAP_FAILED) {
            throw std::runtime_error("mmap failed for Shared Memory");
        }

        auto* table = new (addr) SharedDnsTable();
        if (is_master) {
            table->header()->magic_identifier = SHM_MAGIC;
            table->header()->capacity = Capacity;
            table->header()->total_queries.store(0, std::memory_order_relaxed);
            table->header()->cache_hits.store(0, std::memory_order_relaxed);
        }

        return table;
    }
    // inside include/shared_dns_table.hpp (under public methods of SharedDnsTable)

size_t sweep_expired() {
    uint64_t now_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now().time_since_epoch()
    ).count();

    size_t evicted_count = 0;
    auto* bucket_array = buckets();

    for (size_t i = 0; i < Capacity; ++i) {
        uint32_t current_hash = bucket_array[i].domain_hash.load(std::memory_order_relaxed);
        if (current_hash == 0) continue;

        uint64_t expiry = bucket_array[i].ttl_expiration.load(std::memory_order_relaxed);

        if (expiry != 0 && expiry < now_ns) {
            uint32_t expected = current_hash;
            if (bucket_array[i].domain_hash.compare_exchange_strong(
                    expected, 0, std::memory_order_acq_rel)) {
                bucket_array[i].ttl_expiration.store(0, std::memory_order_relaxed);
                bucket_array[i].ipv4_addr.store(0, std::memory_order_relaxed);
                evicted_count++;
            }
        }
    }
    return evicted_count;
}
    TableHeader* header() noexcept {
        return reinterpret_cast<TableHeader*>(this);
    }

    AtomicCacheBucket* buckets() noexcept {
        return reinterpret_cast<AtomicCacheBucket*>(
            reinterpret_cast<uint8_t*>(this) + sizeof(TableHeader)
        );
    }

    // Sub-50ns Lock-free lookup implementation
    [[nodiscard]] bool lookup(std::string_view domain, uint32_t& out_ip, uint64_t current_time_ns) noexcept {
        header()->total_queries.fetch_add(1, std::memory_order_relaxed);
        uint32_t hash = fnv1a_32(domain);
        if (hash == 0) hash = 1; // 0 reserved for empty bucket

        uint32_t mask = Capacity - 1;
        uint32_t idx = hash & mask;

        for (size_t probe = 0; probe < 16; ++probe) {
            uint32_t bucket_hash = buckets()[idx].domain_hash.load(std::memory_order_acquire);

            if (bucket_hash == 0) {
                return false; // Empty slot, cache miss
            }

            if (bucket_hash == hash) {
                uint64_t exp = buckets()[idx].ttl_expiration.load(std::memory_order_relaxed);
                if (current_time_ns > exp) {
                    return false; // Record expired
                }

                out_ip = buckets()[idx].ipv4_addr.load(std::memory_order_relaxed);
                buckets()[idx].hit_count.fetch_add(1, std::memory_order_relaxed);
                header()->cache_hits.fetch_add(1, std::memory_order_relaxed);
                return true;
            }

            idx = (idx + 1) & mask;
        }

        return false;
    }

    // Sub-50ns Lock-free IPv6 lookup implementation
    [[nodiscard]] bool lookup_ipv6(std::string_view domain, uint8_t* out_ipv6, uint64_t current_time_ns) noexcept {
        header()->total_queries.fetch_add(1, std::memory_order_relaxed);
        uint32_t hash = fnv1a_32(domain);
        if (hash == 0) hash = 1;

        uint32_t mask = Capacity - 1;
        uint32_t idx = hash & mask;

        for (size_t probe = 0; probe < 16; ++probe) {
            uint32_t bucket_hash = buckets()[idx].domain_hash.load(std::memory_order_acquire);

            if (bucket_hash == 0) {
                return false; // Empty slot, cache miss
            }

            if (bucket_hash == hash) {
                    uint64_t exp = buckets()[idx].ttl_expiration.load(std::memory_order_relaxed);
                    if (exp == 0 || current_time_ns > exp) {
                    return false; // Never populated or expired
                }

                std::memcpy(out_ipv6, buckets()[idx].ipv6_addr, 16);
                buckets()[idx].hit_count.fetch_add(1, std::memory_order_relaxed);
                header()->cache_hits.fetch_add(1, std::memory_order_relaxed);
                return true;
            }

            idx = (idx + 1) & mask;
        }

        return false;
    }

    // Atomic IPv4 Insertion / Update
void insert(std::string_view domain, uint32_t ipv4_addr, uint64_t ttl_expiration_ns) {
    uint32_t hash = calculate_hash(domain); // Removed 'this->'
    if (hash == 0) hash = 1;

    size_t base_idx = hash % Capacity;
    size_t oldest_idx = base_idx;
    uint64_t oldest_ttl = UINT64_MAX;

    for (size_t probe = 0; probe < 16; ++probe) {
        size_t idx = (base_idx + probe) % Capacity;
        uint32_t slot_hash = buckets()[idx].domain_hash.load(std::memory_order_acquire);

        if (slot_hash == 0 || slot_hash == hash) {
            buckets()[idx].ipv4_addr.store(ipv4_addr, std::memory_order_relaxed);
            buckets()[idx].ttl_expiration.store(ttl_expiration_ns, std::memory_order_relaxed);
            buckets()[idx].domain_hash.store(hash, std::memory_order_release);
            return;
        }

        uint64_t slot_ttl = buckets()[idx].ttl_expiration.load(std::memory_order_relaxed);
        if (slot_ttl < oldest_ttl) {
            oldest_ttl = slot_ttl;
            oldest_idx = idx;
        }
    }

    // Fallback eviction
    buckets()[oldest_idx].domain_hash.store(0, std::memory_order_release);
    buckets()[oldest_idx].ipv4_addr.store(ipv4_addr, std::memory_order_relaxed);
    buckets()[oldest_idx].ttl_expiration.store(ttl_expiration_ns, std::memory_order_relaxed);
    buckets()[oldest_idx].domain_hash.store(hash, std::memory_order_release);
}

    // Atomic IPv6 Insertion / Update
    void insert_ipv6(std::string_view domain, const uint8_t ipv6_addr_in[16], uint64_t ttl_expiration_ns) {
    uint32_t hash = calculate_hash(domain); // Removed 'this->'
    if (hash == 0) hash = 1;

    size_t base_idx = hash % Capacity;
    size_t oldest_idx = base_idx;
    uint64_t oldest_ttl = UINT64_MAX;

    for (size_t probe = 0; probe < 16; ++probe) {
        size_t idx = (base_idx + probe) % Capacity;
        uint32_t slot_hash = buckets()[idx].domain_hash.load(std::memory_order_acquire);

        if (slot_hash == 0 || slot_hash == hash) {
            if (slot_hash == hash) {
                buckets()[idx].domain_hash.store(0, std::memory_order_release);
            }
            std::memcpy(buckets()[idx].ipv6_addr, ipv6_addr_in, 16);
            buckets()[idx].ttl_expiration.store(ttl_expiration_ns, std::memory_order_relaxed);
            buckets()[idx].domain_hash.store(hash, std::memory_order_release);
            return;
        }

        uint64_t slot_ttl = buckets()[idx].ttl_expiration.load(std::memory_order_relaxed);
        if (slot_ttl < oldest_ttl) {
            oldest_ttl = slot_ttl;
            oldest_idx = idx;
        }
    }

    // Fallback eviction
    buckets()[oldest_idx].domain_hash.store(0, std::memory_order_release);
    std::memcpy(buckets()[oldest_idx].ipv6_addr, ipv6_addr_in, 16);
    buckets()[oldest_idx].ttl_expiration.store(ttl_expiration_ns, std::memory_order_relaxed);
    buckets()[oldest_idx].domain_hash.store(hash, std::memory_order_release);
}
    
   };

} // namespace net_accel
