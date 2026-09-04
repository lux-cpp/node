// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco

#include "lux/node/mesh.hpp"

#include "lux/zap/wire.hpp"  // Writer/Reader (the one BE codec) + read_exact/write_exact

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <set>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include <arpa/inet.h>
#include <fcntl.h>
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

// The one-shot peer-index handshake a dialer sends on connect, so each end agrees
// which validator index owns the link AND the frame stream that follows starts
// clean (the acceptor consumes exactly these 4 bytes before any ZAP frame). It is
// written and read with the ZAP codec — the same big-endian encoder the frames
// use, so node has one integer encoding and not three.
constexpr std::size_t kHandshakeSize = 4;

bool write_index(int fd, std::uint32_t index) {
    lux::zap::Writer w;
    w.write_u32(index);
    const std::vector<std::uint8_t> b = w.take();
    return lux::zap::write_exact(fd, b.data(), b.size());
}

bool read_index(int fd, std::uint32_t& index) {
    std::uint8_t b[kHandshakeSize];
    if (!lux::zap::read_exact(fd, b, sizeof b)) return false;
    lux::zap::Reader r(b, sizeof b);
    return r.read_u32(index);
}

bool readable(int fd, int wait_ms) {
    pollfd pf{fd, POLLIN, 0};
    return ::poll(&pf, 1, wait_ms) > 0 && (pf.revents & POLLIN) != 0;
}

}  // namespace

Mesh::~Mesh() {
    if (listen_fd_ >= 0) ::close(listen_fd_);
    // Peer fds are owned and closed by the transport.
}

std::uint16_t Mesh::listen_bind(std::uint16_t port) {
    listen_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd_ < 0) throw std::runtime_error("node: socket() failed");

    int one = 1;
    ::setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);
    if (::bind(listen_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof addr) != 0)
        throw std::runtime_error("node: bind() failed on port " + std::to_string(port));

    // Backlog must hold inbound dialers until accept() drains it.
    if (::listen(listen_fd_, 128) != 0)
        throw std::runtime_error("node: listen() failed");

    socklen_t len = sizeof addr;
    if (::getsockname(listen_fd_, reinterpret_cast<sockaddr*>(&addr), &len) != 0)
        throw std::runtime_error("node: getsockname() failed");
    bound_port_ = ntohs(addr.sin_port);
    return bound_port_;
}

int Mesh::accept_one(std::uint32_t& peer_index) {
    const int fd = ::accept(listen_fd_, nullptr, nullptr);
    if (fd < 0) return -1;
    bound_peer_io(fd);  // before the handshake read: a silent dialer times out

    // Consume the dialer's index handshake so the ZAP frame stream that follows is
    // clean, and hand the caller the index it claimed. The claim is not proof —
    // the handshake is four plaintext bytes and node has no peer authentication
    // yet — but the caller checks it against the slots it is actually waiting on,
    // so one connection can occupy at most the one slot it names, and never two.
    // Safety never rests on it: votes self-identify by voter pubkey and the gate
    // verifies BLS + set membership.
    peer_index = 0;
    if (!read_index(fd, peer_index)) { ::close(fd); return -1; }
    return fd;
}

int Mesh::dial_once(const PeerAddr& a, int wait_ms) {
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(a.port);
    if (::inet_pton(AF_INET, a.host.c_str(), &addr.sin_addr) != 1) return -1;

    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
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

    if (!write_index(fd, index_)) { ::close(fd); return -1; }
    return fd;
}

std::size_t Mesh::connect(const std::map<std::uint32_t, PeerAddr>& peers, int deadline_ms) {
    // Per-pair direction: lower index dials, higher index accepts. So this node
    // accepts from every peer with a smaller index and dials every larger one.
    std::set<std::uint32_t> awaited;   // inbound slots still open, by validator index
    std::vector<PeerAddr> pending;     // peers still to dial
    for (const auto& [idx, addr] : peers) {
        if (idx == index_) continue;
        if (idx < index_) awaited.insert(idx);
        else              pending.push_back(addr);
    }

    // ONE deadline for the whole phase. Accepts and dials are swept together each
    // round, so a low-indexed peer that never shows up delays nothing else, and
    // the retry policy for a dial lives here — in one place — rather than inside
    // the dial.
    const Deadline deadline = Clock::now() + std::chrono::milliseconds(deadline_ms);
    for (;;) {
        while (!awaited.empty() && readable(listen_fd_, 0)) {
            std::uint32_t claimed = 0;
            const int fd = accept_one(claimed);
            if (fd < 0) continue;  // a connection that failed its handshake costs only itself
            // One connection fills at most the one slot it named. A second claim
            // on a slot already filled — a retrying dialer, or a stranger — is
            // dropped rather than counted as another peer, which is how the mesh
            // used to believe it was complete while a validator was still missing.
            if (awaited.erase(claimed) == 0) { ::close(fd); continue; }
            tx_.add_peer(fd);
        }
        for (std::size_t k = 0; k < pending.size();) {
            const int fd = dial_once(pending[k], std::min(ms_until(deadline), kPeerIoTimeoutMs));
            if (fd < 0) { ++k; continue; }  // not listening yet (or gone) — swept again next round
            tx_.add_peer(fd);
            pending.erase(pending.begin() + static_cast<std::ptrdiff_t>(k));
        }
        if (awaited.empty() && pending.empty()) break;
        if (ms_until(deadline) == 0) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }

    return tx_.peer_count();
}

}  // namespace lux::node
