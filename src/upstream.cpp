#include "upstream.hpp"
#include <arpa/inet.h>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <climits>
#include <cstring>
#include <poll.h>
#include <stdexcept>
#include <string>
#include <sys/random.h>
#include <sys/socket.h>
#include <unistd.h>

namespace net_accel {
namespace {
class Fd {
public:
    explicit Fd(int value) : value_(value) {}
    ~Fd() { if (value_ >= 0) close(value_); }
    operator int() const { return value_; }
private:
    int value_;
};
using Clock = std::chrono::steady_clock;
using Deadline = Clock::time_point;
bool wait_fd(int fd, short events, Deadline deadline) {
    while (Clock::now() < deadline) {
        auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now()).count();
        pollfd item{fd, events, 0};
        int result = poll(&item, 1, static_cast<int>(std::min<int64_t>(INT_MAX, remaining + 1)));
        if (result > 0) return (item.revents & events) != 0;
        if (result == 0 || errno != EINTR) return false;
    }
    return false;
}
bool transfer(int fd, uint8_t* data, size_t size, bool writing, Deadline deadline) {
    size_t done = 0;
    while (done < size) {
        if (!wait_fd(fd, writing ? POLLOUT : POLLIN, deadline)) return false;
        ssize_t count = writing ? send(fd, data + done, size - done, MSG_NOSIGNAL) : recv(fd, data + done, size - done, 0);
        if (count > 0) done += static_cast<size_t>(count);
        else if (count == 0 || (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)) return false;
    }
    return true;
}
std::optional<Bytes> tcp_query(const Query& query, const sockaddr_in& address, Deadline deadline) {
    Fd fd(socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0));
    if (fd < 0) return std::nullopt;
    if (connect(fd, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) < 0 && errno != EINPROGRESS) return std::nullopt;
    if (!wait_fd(fd, POLLOUT, deadline)) return std::nullopt;
    int error = 0;
    socklen_t size = sizeof(error);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &size) || error) return std::nullopt;
    Bytes request(2 + query.wire.size());
    write16(request, 0, static_cast<uint16_t>(query.wire.size()));
    std::copy(query.wire.begin(), query.wire.end(), request.begin() + 2);
    if (!transfer(fd, request.data(), request.size(), true, deadline)) return std::nullopt;
    Bytes prefix(2);
    if (!transfer(fd, prefix.data(), prefix.size(), false, deadline)) return std::nullopt;
    size_t length = read16(prefix, 0);
    if (length < 12) return std::nullopt;
    Bytes reply(length);
    if (!transfer(fd, reply.data(), reply.size(), false, deadline) || !valid_response(query, reply)) return std::nullopt;
    return reply;
}
} // namespace
sockaddr_in upstream_address(std::string_view text) {
    auto colon = text.find(':');
    std::string host(text.substr(0, colon));
    unsigned port = 53;
    if (colon != std::string_view::npos) {
        auto value = text.substr(colon + 1);
        auto [end, error] = std::from_chars(value.data(), value.data() + value.size(), port);
        if (error != std::errc{} || end != value.data() + value.size() || !port || port > 65535)
            throw std::invalid_argument("upstream must be IPv4[:port]");
    }
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(static_cast<uint16_t>(port));
    if (inet_pton(AF_INET, host.c_str(), &address.sin_addr) != 1)
        throw std::invalid_argument("upstream must be IPv4[:port]");
    return address;
}
std::optional<Bytes> resolve_upstream(const Query& original, const sockaddr_in& address, int timeout_ms) {
    if (timeout_ms <= 0) return std::nullopt;
    Query query = original;
    uint16_t id = 0;
    ssize_t random_count;
    do { random_count = getrandom(&id, sizeof(id), 0); } while (random_count < 0 && errno == EINTR);
    if (random_count != sizeof(id)) return std::nullopt;
    write16(query.wire, 0, id);
    auto deadline = Clock::now() + std::chrono::milliseconds(timeout_ms);
    Fd fd(socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0));
    if (fd < 0 || connect(fd, reinterpret_cast<const sockaddr*>(&address), sizeof(address))) return std::nullopt;
    if (send(fd, query.wire.data(), query.wire.size(), MSG_NOSIGNAL) != static_cast<ssize_t>(query.wire.size())) return std::nullopt;
    while (wait_fd(fd, POLLIN, deadline)) {
        Bytes reply(65535);
        ssize_t count = recv(fd, reply.data(), reply.size(), MSG_TRUNC);
        if (count < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            return std::nullopt;
        }
        if (static_cast<size_t>(count) > reply.size()) continue;
        reply.resize(static_cast<size_t>(count));
        if (!valid_response(query, reply)) continue;
        if (read16(reply, 2) & 0x0200) {
            auto full = tcp_query(query, address, deadline);
            if (full) reply = std::move(*full);
            else reply = fit_response(query, reply, 0);
        }
        write16(reply, 0, read16(original.wire, 0));
        return reply;
    }
    return std::nullopt;
}
} // namespace net_accel
