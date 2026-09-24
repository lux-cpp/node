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

// THE GREETING, and it is the only one on this wire. A handshake message is a
// 4-byte big-endian length and that many bytes — LP-10602's framing, which is
// the same shape the vote frames that follow use and a different rule (this one
// counts no tag byte and caps at 16 KiB). The stream is clean afterwards
// because both ends read exactly the frames the handshake defines.
bool greet_write(int fd, std::span<const std::uint8_t> body) {
    const auto framed = pq::frame(body);
    return lux::zap::write_exact(fd, framed.data(), framed.size());
}

std::vector<std::uint8_t> greet_read(int fd) {
    std::array<std::uint8_t, 4> head{};
    if (!lux::zap::read_exact(fd, head.data(), head.size())) return {};
    std::uint32_t n = 0;
    try {
        n = pq::body_size(head);
    } catch (const std::exception&) {
        return {};  // a stranger announcing more than the cap, refused before the malloc
    }
    std::vector<std::uint8_t> body(n);
    if (!lux::zap::read_exact(fd, body.data(), body.size())) return {};
    return body;
}


}  // namespace

Mesh::~Mesh() {
    // Wake the acceptor out of accept() and wait for it; then close what it
    // proved and nobody took. Peer fds the transport holds are the transport's.
    stopping_.store(true);
    if (listen_fd_ >= 0) ::shutdown(listen_fd_, SHUT_RDWR);
    if (acceptor_.joinable()) acceptor_.join();
    if (listen_fd_ >= 0) ::close(listen_fd_);
    for (const auto& [fd, seat] : arrived_) ::close(fd);
}

std::uint16_t Mesh::listen_bind(const std::string& host, std::uint16_t port) {
    listen_fd_ = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (listen_fd_ < 0) throw std::runtime_error("node: socket() failed");

    int one = 1;
    ::setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (::inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1)
        throw std::runtime_error("node: the mesh binds an IPv4 address, and " + host + " is not one");
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

void Mesh::accepting() {
    while (!stopping_.load()) {
        const int fd = ::accept4(listen_fd_, nullptr, nullptr, SOCK_CLOEXEC);
        if (fd < 0) {
            if (stopping_.load()) return;
            if (errno == EINTR || errno == ECONNABORTED) continue;
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
            continue;
        }
        bound_peer_io(fd);  // before the greeting: a silent dialer times out

        // Answer the greeting as the responder. What comes back is a name this
        // peer SIGNED for, on this chain — so the seat below is proven rather
        // than claimed, and a stranger gets no seat at all because it cannot
        // sign for one.
        const auto out = pq::run_responder(
            link_.me, [fd](std::span<const std::uint8_t> b) { greet_write(fd, b); },
            [fd] { return greet_read(fd); }, link_.chain);
        const auto seat = out.ok && link_.seat ? link_.seat(out.peer_node_id) : std::nullopt;
        // Proved who it is, and it is nobody here; or a seat above this one,
        // which is the end of the pair that accepts, not the one that dials.
        if (!seat || *seat >= index_) {
            ::close(fd);
            continue;
        }
        const std::lock_guard<std::mutex> lock(arrived_mu_);
        arrived_.emplace_back(fd, *seat);
    }
}

void Mesh::take_arrivals() {
    std::vector<std::pair<int, std::uint32_t>> took;
    {
        const std::lock_guard<std::mutex> lock(arrived_mu_);
        took.swap(arrived_);
    }
    // One connection per seat: a later link from a seat replaces the one before
    // it (the transport's rule), so a retrying dialer ends up holding one link.
    for (const auto& [fd, seat] : took) tx_.add_peer(fd, seat);
}

int Mesh::dial_once(const PeerAddr& a, std::uint32_t expect, int wait_ms) {
    // A name is resolved at every attempt: in a cluster a peer that restarted
    // can come back at another address under the same name.
    addrinfo hints{};
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* found   = nullptr;
    if (::getaddrinfo(a.host.c_str(), std::to_string(a.port).c_str(), &hints, &found) != 0 || !found)
        return -1;
    sockaddr_in addr{};
    std::memcpy(&addr, found->ai_addr, sizeof addr);
    ::freeaddrinfo(found);

    const int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;

    // Non-blocking connect so a black-holed address costs `wait_ms`, not forever.
    const int flags = ::fcntl(fd, F_GETFL, 0);
    ::fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof addr) != 0) {
        if (errno != EINPROGRESS) { ::close(fd); return -1; }
        pollfd pf{fd, POLLOUT, 0};
        if (::poll(&pf, 1, wait_ms) <= 0) { ::close(fd); return -1; }
        int err = 0;
        socklen_t elen = sizeof err;
        if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen) != 0 || err != 0) {
            ::close(fd);
            return -1;
        }
    }
    ::fcntl(fd, F_SETFL, flags);  // back to blocking; the timeouts below bound it
    bound_peer_io(fd);

    // The greeting, as the initiator. AN ADDRESS IS NOT A NAME: this list said
    // seat `expect` answers here, and the handshake says who actually did. When
    // the two disagree the link is dropped — believing the address would seat a
    // validator behind a socket that belongs to somebody else.
    const auto out = pq::run_initiator(
        link_.me, [fd](std::span<const std::uint8_t> b) { greet_write(fd, b); },
        [fd] { return greet_read(fd); }, link_.chain);
    if (!out.ok) { ::close(fd); return -1; }
    const auto seat = link_.seat ? link_.seat(out.peer_node_id) : std::nullopt;
    if (!seat || *seat != expect) { ::close(fd); return -1; }
    return fd;
}

std::size_t Mesh::connect(const std::map<std::uint32_t, PeerAddr>& peers, int deadline_ms) {
    // ONE deadline for the whole phase. The acceptor fills the seats below this
    // one on its own thread; the seats above are dialed here, each attempt
    // bounded, so a peer that never shows up delays nothing else.
    const Deadline deadline = Clock::now() + std::chrono::milliseconds(deadline_ms);
    for (;;) {
        take_arrivals();
        const auto held = tx_.members();
        const auto has  = [&](std::uint32_t s) { return std::find(held.begin(), held.end(), s) != held.end(); };
        bool complete = true;
        for (const auto& [idx, addr] : peers) {
            if (idx == index_ || has(idx)) continue;
            if (idx < index_) { complete = false; continue; }  // theirs to dial
            const int fd = dial_once(addr, idx, std::min({ms_until(deadline), kPeerIoTimeoutMs, kDialAttemptMs}));
            if (fd < 0) { complete = false; continue; }  // not listening yet (or gone) — swept again next round
            tx_.add_peer(fd, idx);
        }
        if (complete) break;
        if (ms_until(deadline) == 0) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    return tx_.peer_count();
}

void Mesh::sweep(const std::map<std::uint32_t, PeerAddr>& peers) {
    take_arrivals();
    const auto held = tx_.members();
    for (const auto& [idx, addr] : peers) {
        if (idx <= index_ || std::find(held.begin(), held.end(), idx) != held.end()) continue;
        const int fd = dial_once(addr, idx, kDialAttemptMs);
        if (fd >= 0) tx_.add_peer(fd, idx);
    }
}

}  // namespace lux::node
