#pragma once
#include <condition_variable>
#include <cstddef>
#include <deque>
#include <mutex>
#include <utility>

namespace net_accel {
template<class T>
class BoundedQueue {
public:
    explicit BoundedQueue(size_t capacity) : capacity_(capacity) {}
    bool try_push(T item) {
        std::lock_guard lock(mutex_);
        if (closed_ || queue_.size() >= capacity_) return false;
        queue_.push_back(std::move(item));
        ready_.notify_one();
        return true;
    }
    bool push_wait(T item) {
        std::unique_lock lock(mutex_);
        space_.wait(lock, [&] { return closed_ || queue_.size() < capacity_; });
        if (closed_) return false;
        queue_.push_back(std::move(item));
        ready_.notify_one();
        return true;
    }
    bool pop_wait(T& item) {
        std::unique_lock lock(mutex_);
        ready_.wait(lock, [&] { return closed_ || !queue_.empty(); });
        if (closed_) return false;
        item = std::move(queue_.front());
        queue_.pop_front();
        space_.notify_one();
        return true;
    }
    bool try_pop(T& item) {
        std::lock_guard lock(mutex_);
        if (closed_ || queue_.empty()) return false;
        item = std::move(queue_.front());
        queue_.pop_front();
        space_.notify_one();
        return true;
    }
    void close() {
        std::lock_guard lock(mutex_);
        closed_ = true;
        ready_.notify_all();
        space_.notify_all();
    }
private:
    const size_t capacity_;
    bool closed_ = false;
    std::deque<T> queue_;
    std::mutex mutex_;
    std::condition_variable ready_, space_;
};
} // namespace net_accel
