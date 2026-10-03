// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco

#include "lux/node/mesh.hpp"

#include "lux/zap/wire.hpp"  // Writer/Reader (the one BE codec) + read_exact/write_exact

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <chrono>
#include <optional>
#include <set>
#include <span>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>  // TCP_NODELAY
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

namespace lux::node {

namespace {

using Clock    = std::chrono::steady_clock;
using Deadline = Clock::time_point;

int ms_until(Deadline t) {
    const auto now  = Clock::now();
    const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(t - now).count();
    if (left <= 0) return 0;
    return static_cast<int>(std::min<long long>(left, 60'000));
}

// Bound every blocking operation on a peer socket. A peer that never sends its
// handshake, and a peer that stops reading while we broadcast, both fail within
// kPeerIoTimeoutMs instead of holding this node forever. Set once, on both ends
// of every link, immediately after the connection exists.
void bound_peer_io(int fd) {
    int one = 1;
    ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    timeval tv{};
    tv.tv_sec  = kPeerIoTimeoutMs / 1000;
    tv.tv_usec = (kPeerIoTimeoutMs % 1000) * 1000;
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
}

// Wait until `fd` is ready for `events`, or the deadline passes.
bool ready_by(int fd, short events, Deadline deadline) {
    for (;;) {
        const int ms = ms_until(deadline);
        if (ms == 0) return false;
        pollfd pf{fd, events, 0};
        const int r = ::poll(&pf, 1, ms);
        if (r > 0) return true;
        if (r < 0 && errno == EINTR) continue;
        return false;
    }
}

bool read_by(int fd, std::uint8_t* p, std::size_t n, Deadline deadline) {
    while (n > 0) {
        if (!ready_by(fd, POLLIN, deadline)) return false;
        const ssize_t r = ::recv(fd, p, n, MSG_DONTWAIT);
        if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) continue;
        if (r <= 0) return false;
        p += r;
        n -= std::size_t(r);
    }
    return true;
}

bool write_by(int fd, const std::uint8_t* p, std::size_t n, Deadline deadline) {
    while (n > 0) {
        if (!ready_by(fd, POLLOUT, deadline)) return false;
        const ssize_t w = ::send(fd, p, n, MSG_DONTWAIT | MSG_NOSIGNAL);
        if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) continue;
        if (w <= 0) return false;
        p += w;
        n -= std::size_t(w);
    }
    return true;
}

// THE GREETING, and it is the only one on this wire. A handshake message is a
// 4-byte big-endian length and that many bytes — LP-10602's framing, which is
// the same shape the vote frames that follow use and a different rule (this one
// counts no tag byte and caps at 16 KiB). The stream is clean afterwards
// because both ends read exactly the frames the handshake defines. Every read
// and write of it answers to ONE deadline, the greeting's.
bool greet_write(int fd, std::span<const std::uint8_t> body, Deadline deadline) {
    const auto framed = pq::frame(body);
    return write_by(fd, framed.data(), framed.size(), deadline);
}

std::vector<std::uint8_t> greet_read(int fd, Deadline deadline) {
    std::array<std::uint8_t, 4> head{};
    if (!read_by(fd, head.data(), head.size(), deadline)) return {};
    std::uint32_t n = 0;
    try {
        n = pq::body_size(head);
    } catch (const std::exception&) {
        return {};  // a stranger announcing more than the cap, refused before the malloc
    }
    std::vector<std::uint8_t> body(n);
    if (!read_by(fd, body.data(), body.size(), deadline)) return {};
    return body;
}

}  // namespace

Mesh::~Mesh() {
    // Wake the acceptor out of accept(), then every greeting out of its poll;
    // each is bounded anyway, so the joins below are too. Peer fds the
    // transport holds are the transport's.
    stopping_.store(true);
    if (listen_fd_ >= 0) ::shutdown(listen_fd_, SHUT_RDWR);
    if (acceptor_.joinable()) acceptor_.join();
    std::vector<Worker> workers;
    {
        const std::lock_guard<std::mutex> lock(mu_);
        for (const int fd : inflight_) ::shutdown(fd, SHUT_RDWR);
        workers.swap(workers_);
    }
    for (auto& w : workers)
        if (w.thread.joinable()) w.thread.join();
    if (listen_fd_ >= 0) ::close(listen_fd_);
    for (const auto& [fd, seat] : arrived_) ::close(fd);
}

std::uint16_t Mesh::listen_bind(const std::string& host, std::uint16_t port) {
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    // Refused before a socket exists: a mesh host that is not an address would
    // otherwise bind somewhere nobody asked for, or nowhere, and look up.
    if (::inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1)
        throw std::runtime_error("node: the mesh listens on an IPv4 address, and '" + host +
                                 "' is not one");

    listen_fd_ = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (listen_fd_ < 0) throw std::runtime_error("node: socket() failed");

    int one = 1;
    ::setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);

    if (::bind(listen_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof addr) != 0)
        throw std::runtime_error("node: bind() failed on " + host + ":" + std::to_string(port));

    // Backlog must hold inbound dialers until accept() drains it.
    if (::listen(listen_fd_, 128) != 0)
        throw std::runtime_error("node: listen() failed");

    socklen_t len = sizeof addr;
    if (::getsockname(listen_fd_, reinterpret_cast<sockaddr*>(&addr), &len) != 0)
        throw std::runtime_error("node: getsockname() failed");
    bound_port_ = ntohs(addr.sin_port);
    acceptor_ = std::thread([this] { accepting(); });
    return bound_port_;
}

std::size_t Mesh::greeting() const {
    const std::lock_guard<std::mutex> lock(mu_);
    return inflight_.size();
}

void Mesh::spawn(std::function<void()> work) {
    auto done = std::make_shared<std::atomic<bool>>(false);
    workers_.push_back(Worker{std::thread([work = std::move(work), done] {
                                  work();
                                  done->store(true);
                              }),
                              done});
}

void Mesh::reap() {
    for (auto it = workers_.begin(); it != workers_.end();) {
        if (!it->done->load()) {
            ++it;
            continue;
        }
        it->thread.join();
        it = workers_.erase(it);
    }
}

// THE DOOR ONLY TAKES AND HANDS ON. It never reads a byte: a greeting runs on a
// thread of its own under one deadline, at most kHandshakesMax at once and
// kHandshakesPerSource from one address. Past either bound a connection is
// closed at once — the slots in use free themselves within kHandshakeMs, and a
// validator's dial is tried again on its next sweep.
void Mesh::accepting() {
    while (!stopping_.load()) {
        sockaddr_in from{};
        socklen_t   len = sizeof from;
        const int   fd  = ::accept4(listen_fd_, reinterpret_cast<sockaddr*>(&from), &len, SOCK_CLOEXEC);
        if (fd < 0) {
            if (stopping_.load()) return;
            if (errno == EINTR || errno == ECONNABORTED) continue;
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
            continue;
        }
        char text[INET_ADDRSTRLEN] = {};
        ::inet_ntop(AF_INET, &from.sin_addr, text, sizeof text);
        std::string source = text;

        const std::lock_guard<std::mutex> lock(mu_);
        reap();
        if (stopping_.load() || inbound_ >= kHandshakesMax || sources_[source] >= kHandshakesPerSource) {
            ::close(fd);
            continue;
        }
        ++inbound_;
        ++sources_[source];
        inflight_.insert(fd);
        spawn([this, fd, source] { greet_in(fd, source); });
    }
}

void Mesh::greet_in(int fd, std::string source) {
    bound_peer_io(fd);
    const Deadline deadline = Clock::now() + std::chrono::milliseconds(kHandshakeMs);
    // Answer the greeting as the responder. What comes back is a name this peer
    // SIGNED for, on this chain — so the seat below is proven rather than
    // claimed, and a stranger gets no seat at all because it cannot sign for
    // one.
    const auto out = pq::run_responder(
        link_.me, [fd, deadline](std::span<const std::uint8_t> b) { greet_write(fd, b, deadline); },
        [fd, deadline] { return greet_read(fd, deadline); }, link_.chain);
    const auto seat = out.ok && link_.seat ? link_.seat(out.peer_node_id) : std::nullopt;

    const std::lock_guard<std::mutex> lock(mu_);
    inflight_.erase(fd);
    --inbound_;
    if (--sources_[source] == 0) sources_.erase(source);
    // Proved who it is, and it is nobody here; or a seat above this one, which
    // is the end of the pair that accepts, not the one that dials.
    if (!seat || *seat >= index_ || stopping_.load()) {
        ::close(fd);
        return;
    }
    arrived_.emplace_back(fd, *seat);
}

void Mesh::greet_out(std::uint32_t expect, PeerAddr to) {
    const auto finish = [this, expect](int fd) {
        const std::lock_guard<std::mutex> lock(mu_);
        dialing_.erase(expect);
        if (fd < 0) return;
        inflight_.erase(fd);
        if (stopping_.load()) {
            ::close(fd);
            return;
        }
        arrived_.emplace_back(fd, expect);
    };

    // A name is resolved at every attempt: in a cluster a peer that restarted
    // can come back at another address under the same name.
    addrinfo hints{};
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* found   = nullptr;
    if (::getaddrinfo(to.host.c_str(), std::to_string(to.port).c_str(), &hints, &found) != 0 || !found)
        return finish(-1);
    sockaddr_in addr{};
    std::memcpy(&addr, found->ai_addr, sizeof addr);
    ::freeaddrinfo(found);

    const int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return finish(-1);
    {
        const std::lock_guard<std::mutex> lock(mu_);
        if (stopping_.load()) {
            ::close(fd);
            dialing_.erase(expect);
            return;
        }
        inflight_.insert(fd);
    }
    const auto fail = [&] {
        {
            const std::lock_guard<std::mutex> lock(mu_);
            inflight_.erase(fd);
        }
        ::close(fd);
        finish(-1);
    };

    // Non-blocking connect so a black-holed address costs kDialAttemptMs.
    const int flags = ::fcntl(fd, F_GETFL, 0);
    ::fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof addr) != 0) {
        if (errno != EINPROGRESS) return fail();
        pollfd pf{fd, POLLOUT, 0};
        if (::poll(&pf, 1, kDialAttemptMs) <= 0) return fail();
        int       err  = 0;
        socklen_t elen = sizeof err;
        if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen) != 0 || err != 0) return fail();
    }
    ::fcntl(fd, F_SETFL, flags);  // back to blocking; every wait below has its deadline
    bound_peer_io(fd);

    // The greeting, as the initiator. AN ADDRESS IS NOT A NAME: this list said
    // seat `expect` answers here, and the handshake says who actually did. When
    // the two disagree the link is dropped — believing the address would seat a
    // validator behind a socket that belongs to somebody else.
    const Deadline deadline = Clock::now() + std::chrono::milliseconds(kHandshakeMs);
    const auto     out      = pq::run_initiator(
        link_.me, [fd, deadline](std::span<const std::uint8_t> b) { greet_write(fd, b, deadline); },
        [fd, deadline] { return greet_read(fd, deadline); }, link_.chain);
    if (!out.ok) return fail();
    const auto seat = link_.seat ? link_.seat(out.peer_node_id) : std::nullopt;
    if (!seat || *seat != expect) return fail();
    finish(fd);
}

void Mesh::take_arrivals() {
    std::vector<std::pair<int, std::uint32_t>> took;
    {
        const std::lock_guard<std::mutex> lock(mu_);
        took.swap(arrived_);
        reap();
    }
    // One connection per seat: a later link from a seat replaces the one before
    // it (the transport's rule), so a retrying dialer ends up holding one link.
    for (const auto& [fd, seat] : took) tx_.add_peer(fd, seat);
}

void Mesh::sweep(const std::map<std::uint32_t, PeerAddr>& peers) {
    take_arrivals();
    const auto held = tx_.members();
    const auto now  = Clock::now();
    const std::lock_guard<std::mutex> lock(mu_);
    if (stopping_.load()) return;
    for (const auto& [idx, addr] : peers) {
        if (idx <= index_ || std::find(held.begin(), held.end(), idx) != held.end() || dialing_.count(idx))
            continue;
        if (const auto last = dialed_.find(idx);
            last != dialed_.end() && now - last->second < std::chrono::milliseconds(kDialAttemptMs))
            continue;
        dialed_[idx] = now;
        dialing_.insert(idx);
        spawn([this, idx, addr] { greet_out(idx, addr); });
    }
}

std::size_t Mesh::connect(const std::map<std::uint32_t, PeerAddr>& peers, int deadline_ms) {
    // ONE deadline for the whole phase. The seats below this one dial here and
    // arrive through the acceptor; the seats above are dialed, each attempt on a
    // thread of its own, so a peer that never shows up delays nothing else.
    const Deadline deadline = Clock::now() + std::chrono::milliseconds(deadline_ms);
    for (;;) {
        sweep(peers);
        const auto held     = tx_.members();
        bool       complete = true;
        for (const auto& [idx, addr] : peers)
            if (idx != index_ && std::find(held.begin(), held.end(), idx) == held.end()) complete = false;
        if (complete || ms_until(deadline) == 0) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    return tx_.peer_count();
}

}  // namespace lux::node
