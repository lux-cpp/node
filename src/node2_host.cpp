// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco

#include "lux/node2/node2_host.hpp"

#include "lux/zap/wire.hpp"  // read_exact / write_exact (blocking handshake I/O)

#include <chrono>
#include <stdexcept>
#include <string>
#include <thread>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>  // TCP_NODELAY
#include <sys/socket.h>
#include <unistd.h>

namespace lux::node2 {

namespace {

// 4-byte big-endian framing for the one-shot peer-index handshake a dialer sends
// on connect, so each end agrees which validator index owns the link AND the
// frame stream that follows starts clean (the acceptor consumes exactly these 4
// bytes before any ZAP frame).
void put_u32_be(std::uint8_t out[4], std::uint32_t v) {
    out[0] = static_cast<std::uint8_t>(v >> 24);
    out[1] = static_cast<std::uint8_t>(v >> 16);
    out[2] = static_cast<std::uint8_t>(v >> 8);
    out[3] = static_cast<std::uint8_t>(v);
}
std::uint32_t get_u32_be(const std::uint8_t in[4]) {
    return static_cast<std::uint32_t>(in[0]) << 24 |
           static_cast<std::uint32_t>(in[1]) << 16 |
           static_cast<std::uint32_t>(in[2]) << 8  |
           static_cast<std::uint32_t>(in[3]);
}

void set_nodelay(int fd) {
    int one = 1;
    ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
}

}  // namespace

Node2Host::Node2Host(HostConfig cfg) : cfg_(std::move(cfg)) {
    // Build the mesh first with a sink that hands inbound/self votes to the Node;
    // the sink is only invoked during poll/pump (after node_ exists), so capturing
    // a member that is set just below is safe.
    mesh_ = std::make_unique<MeshVoteTransport>(
        [this](const lux::consensus2::SignedVote& v) { node_->onVote(v); });

    node_ = std::make_unique<lux::consensus2::Node>(
        cfg_.index, cfg_.sk, cfg_.pk, cfg_.validators,
        cfg_.alpha, cfg_.wave, cfg_.epoch, *mesh_);
}

Node2Host::~Node2Host() {
    if (listen_fd_ >= 0) ::close(listen_fd_);
    // Peer fds are owned and closed by mesh_.
}

std::uint16_t Node2Host::listen_bind() {
    listen_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd_ < 0) throw std::runtime_error("node2: socket() failed");

    int one = 1;
    ::setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(cfg_.port);
    if (::bind(listen_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof addr) != 0)
        throw std::runtime_error("node2: bind() failed on port " + std::to_string(cfg_.port));

    // Backlog must hold every inbound dialer until accept() drains it.
    if (::listen(listen_fd_, 16) != 0)
        throw std::runtime_error("node2: listen() failed");

    socklen_t len = sizeof addr;
    if (::getsockname(listen_fd_, reinterpret_cast<sockaddr*>(&addr), &len) != 0)
        throw std::runtime_error("node2: getsockname() failed");
    cfg_.port = ntohs(addr.sin_port);
    return cfg_.port;
}

int Node2Host::accept_one() {
    const int fd = ::accept(listen_fd_, nullptr, nullptr);
    if (fd < 0) return -1;

    // Consume the dialer's 4-byte index handshake so the ZAP frame stream that
    // follows is clean. (We accept the value for symmetry/observability; routing
    // does not depend on it — votes self-identify by voter pubkey.)
    std::uint8_t hdr[4];
    if (!lux::zap::read_exact(fd, hdr, sizeof hdr)) { ::close(fd); return -1; }
    (void)get_u32_be(hdr);

    set_nodelay(fd);
    return fd;
}

int Node2Host::dial_one(const PeerAddr& a, int deadline_ms) {
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(a.port);
    if (::inet_pton(AF_INET, a.host.c_str(), &addr.sin_addr) != 1) return -1;

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(deadline_ms);
    for (;;) {
        const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) return -1;
        if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof addr) == 0) {
            // Announce our index, then hand the clean stream to the mesh.
            std::uint8_t hdr[4];
            put_u32_be(hdr, cfg_.index);
            if (!lux::zap::write_exact(fd, hdr, sizeof hdr)) { ::close(fd); return -1; }
            set_nodelay(fd);
            return fd;
        }
        ::close(fd);  // target not listening yet (cluster still booting) — retry
        if (std::chrono::steady_clock::now() >= deadline) return -1;
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
}

bool Node2Host::connect_mesh(const std::map<std::uint32_t, PeerAddr>& peers, int deadline_ms) {
    // Per-pair direction: lower index dials, higher index accepts. So this node
    // accepts from every peer with a smaller index and dials every larger one.
    std::size_t inbound = 0;
    std::vector<const PeerAddr*> outbound;
    for (const auto& [idx, addr] : peers) {
        if (idx == cfg_.index) continue;
        if (idx < cfg_.index) ++inbound;
        else                  outbound.push_back(&addr);
    }

    // Accept inbound first: the dialers' connects sit in the listen backlog (every
    // node listens before any dial), so accept() drains them as the dial chain
    // (rooted at index 0, which only dials) progresses. No deadlock — the wait-for
    // relation (i waits on j<i) is a DAG.
    for (std::size_t k = 0; k < inbound; ++k) {
        const int fd = accept_one();
        if (fd < 0) return false;
        mesh_->add_peer(fd);
    }
    for (const PeerAddr* a : outbound) {
        const int fd = dial_one(*a, deadline_ms);
        if (fd < 0) return false;
        mesh_->add_peer(fd);
    }

    return mesh_->peer_count() == (inbound + outbound.size());
}

}  // namespace lux::node2
