#pragma once
#include "keyed_hash.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <new>
#include <pthread.h>
#include <span>
#include <stdexcept>
#include <string>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace net_accel {
inline uint64_t monotonic_ns() noexcept {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}
// Set associative storage avoids deletion holes. Each set has one robust,
// process-shared lock; readers copy a complete response while holding that lock.
template<size_t Capacity = 4096>
class alignas(64) SharedDnsTable {
    static_assert(Capacity >= 16 && (Capacity & (Capacity - 1)) == 0);
    static_assert(std::atomic<uint64_t>::is_always_lock_free, "shared metrics require lock-free atomics");
    static constexpr size_t ways = 16;
    static constexpr size_t max_key = 512;
    static constexpr size_t max_response = 4096;
    struct Entry {
        uint64_t hash = 0;
        uint64_t inserted_ns = 0;
        uint64_t expires_ns = 0;
        uint32_t key_size = 0;
        uint32_t response_size = 0;
        std::array<uint8_t, max_key> key{};
        std::array<uint8_t, max_response> response{};
    };
    struct alignas(64) Set {
        pthread_mutex_t mutex{};
        std::array<Entry, ways> entries{};
    };
public:
    static constexpr uint64_t SHM_MAGIC = 0x444e534143433033ULL;
    static constexpr const char* SHM_PATH = "/net_accel_dns_v3";
    struct alignas(64) TableHeader {
        uint64_t magic_identifier = 0;
        uint64_t capacity = Capacity;
        uint64_t layout_size = sizeof(SharedDnsTable);
        std::atomic<uint64_t> total_queries{0};
        std::atomic<uint64_t> cache_hits{0};
    };
    SharedDnsTable() : hash_key_(random_hash_key()) {
        pthread_mutexattr_t attr;
        if (pthread_mutexattr_init(&attr)) throw std::runtime_error("mutex attributes failed");
        int err = pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
        if (!err) err = pthread_mutexattr_setrobust(&attr, PTHREAD_MUTEX_ROBUST);
        size_t initialized = 0;
        if (!err) {
            for (; initialized < sets_.size(); ++initialized) {
                err = pthread_mutex_init(&sets_[initialized].mutex, &attr);
                if (err) break;
            }
        }
        pthread_mutexattr_destroy(&attr);
        if (err) {
            while (initialized) pthread_mutex_destroy(&sets_[--initialized].mutex);
            throw std::runtime_error("process-shared mutex initialization failed");
        }
        header_.magic_identifier = SHM_MAGIC;
    }
    ~SharedDnsTable() {
        for (auto& set : sets_) pthread_mutex_destroy(&set.mutex);
    }
    SharedDnsTable(const SharedDnsTable&) = delete;
    SharedDnsTable& operator=(const SharedDnsTable&) = delete;

    static SharedDnsTable* create_or_attach(bool is_master = true, const char* path = SHM_PATH) {
        int fd = ::shm_open(path, O_RDWR | O_CLOEXEC | (is_master ? O_CREAT : 0), 0600);
        if (fd < 0) throw std::runtime_error("shm_open failed: " + std::string(std::strerror(errno)));
        void* addr = MAP_FAILED;
        try {
            if (flock(fd, LOCK_EX)) throw std::runtime_error("shared cache initialization lock failed");
            struct stat st{};
            if (fstat(fd, &st)) throw std::runtime_error("shared cache fstat failed");
            if (st.st_uid != geteuid() || (st.st_mode & 0077))
                throw std::runtime_error("shared cache must be owned by this user and private (0600)");
            bool fresh = st.st_size == 0 && is_master;
            if (fresh && ftruncate(fd, sizeof(SharedDnsTable))) throw std::runtime_error("shared cache resize failed");
            if (fresh) {
                int error = posix_fallocate(fd, 0, sizeof(SharedDnsTable));
                if (error) {
                    std::string message = "shared cache allocation failed: " + std::string(std::strerror(error));
                    if (ftruncate(fd, 0)) message += "; could not reset the incomplete cache size";
                    throw std::runtime_error(message);
                }
            }
            if (!fresh && st.st_size != static_cast<off_t>(sizeof(SharedDnsTable)))
                throw std::runtime_error("incompatible shared cache size");
            addr = mmap(nullptr, sizeof(SharedDnsTable), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
            if (addr == MAP_FAILED) throw std::runtime_error("shared cache mmap failed");
            auto* table = static_cast<SharedDnsTable*>(addr);
            if (fresh) table = new (addr) SharedDnsTable;
            else if (table->header_.magic_identifier != SHM_MAGIC || table->header_.capacity != Capacity ||
                     table->header_.layout_size != sizeof(SharedDnsTable))
                throw std::runtime_error("incompatible shared cache version");
            flock(fd, LOCK_UN);
            close(fd);
            return table;
        } catch (...) {
            if (addr != MAP_FAILED) munmap(addr, sizeof(SharedDnsTable));
            close(fd);
            throw;
        }
    }
    static void unmap(SharedDnsTable* table) noexcept { if (table) munmap(table, sizeof(SharedDnsTable)); }
    TableHeader* header() noexcept { return &header_; }

    bool lookup(std::span<const uint8_t> key, std::vector<uint8_t>& response,
                uint64_t now_ns, uint32_t& age_seconds) {
        header_.total_queries.fetch_add(1, std::memory_order_relaxed);
        if (key.empty() || key.size() > max_key) return false;
        uint64_t hash = keyed_hash(key, hash_key_);
        auto& set = sets_[hash & (sets_.size() - 1)];
        Guard lock(set);
        for (auto& entry : set.entries) {
            if (matches(entry, key, hash) && entry.response_size >= 12 && entry.response_size <= max_response &&
                now_ns >= entry.inserted_ns && now_ns < entry.expires_ns) {
                response.assign(entry.response.begin(), entry.response.begin() + entry.response_size);
                age_seconds = static_cast<uint32_t>((now_ns - entry.inserted_ns) / 1000000000ULL);
                header_.cache_hits.fetch_add(1, std::memory_order_relaxed);
                return true;
            }
        }
        return false;
    }
    bool insert(std::span<const uint8_t> key, std::span<const uint8_t> response,
                uint32_t ttl_seconds, uint64_t now_ns) {
        if (key.empty() || key.size() > max_key || response.size() < 12 ||
            response.size() > max_response || ttl_seconds == 0 || ttl_seconds > 0x7fffffffU) return false;
        uint64_t hash = keyed_hash(key, hash_key_);
        auto& set = sets_[hash & (sets_.size() - 1)];
        Guard lock(set);
        Entry* selected = nullptr;
        for (auto& entry : set.entries) {
            if (matches(entry, key, hash)) { selected = &entry; break; }
            if (!selected || entry.expires_ns < selected->expires_ns) selected = &entry;
        }
        selected->key_size = 0;
        selected->hash = hash;
        selected->inserted_ns = now_ns;
        uint64_t duration = uint64_t(ttl_seconds) * 1000000000ULL;
        selected->expires_ns = now_ns > UINT64_MAX - duration ? UINT64_MAX : now_ns + duration;
        selected->response_size = static_cast<uint32_t>(response.size());
        std::copy(key.begin(), key.end(), selected->key.begin());
        std::copy(response.begin(), response.end(), selected->response.begin());
        selected->key_size = static_cast<uint32_t>(key.size());
        return true;
    }
    size_t sweep_expired(uint64_t now_ns = monotonic_ns()) {
        size_t count = 0;
        for (auto& set : sets_) {
            Guard lock(set);
            for (auto& entry : set.entries) {
                if (entry.key_size && entry.expires_ns <= now_ns) {
                    entry.key_size = 0;
                    entry.expires_ns = 0;
                    ++count;
                }
            }
        }
        return count;
    }
private:
    struct Guard {
        Set& set;
        explicit Guard(Set& value) : set(value) {
            int err = pthread_mutex_lock(&set.mutex);
            if (err == EOWNERDEAD) {
                for (auto& entry : set.entries) { entry.key_size = 0; entry.expires_ns = 0; }
                err = pthread_mutex_consistent(&set.mutex);
                if (err) pthread_mutex_unlock(&set.mutex);
            }
            if (err) throw std::runtime_error("shared cache lock failed");
        }
        ~Guard() { pthread_mutex_unlock(&set.mutex); }
    };
    static bool matches(const Entry& entry, std::span<const uint8_t> key, uint64_t hash) {
        return entry.key_size == key.size() && entry.hash == hash &&
               std::equal(key.begin(), key.end(), entry.key.begin());
    }
    TableHeader header_{};
    HashKey hash_key_;
    std::array<Set, Capacity / ways> sets_{};
};
} // namespace net_accel
