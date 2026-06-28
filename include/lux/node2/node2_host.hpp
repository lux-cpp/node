// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// node2_host.hpp — a running consensus2 node. Node2Host binds a TCP listener,
// forms a full mesh with its configured peers (one connection per pair), and
// drives one local consensus2::Node over that mesh.
//
// Identity (index + BLS key + validator set) is fixed at construction; the peer
// ADDRESSES are supplied later to connect_mesh(), because in a real cluster the
// listen port may be ephemeral and is only known after bind. That split keeps
// "who am I" orthogonal from "who do I dial".
//
// Concurrency: a Node2Host is driven by ONE thread. Mesh setup (accept + dial)
// and consensus driving (submit/poll/pump/isFinal) all run on the caller's
// thread; the cluster proof runs each host on its own thread for setup, then
// drives consensus round-robin on a single thread. No shared mutable consensus
// state, hence no locks.

#pragma once

#include "lux/consensus2/node.hpp"
#include "lux/node2/mesh_vote_transport.hpp"

#include <array>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace lux::node2 {

struct PeerAddr {
    std::string   host;
    std::uint16_t port;
};

// Fixed identity + consensus parameters for one node2 instance. Peer discovery is
// out of scope: the peer set is supplied to connect_mesh, fixed for the run.
struct HostConfig {
    std::uint32_t                              index;       // this node's validator index
    std::uint16_t                              port;        // listen port (0 = OS-assigned)
    std::array<std::uint8_t, 32>               sk;          // this node's BLS secret key
    lux::consensus2::PubKey                    pk;          // this node's BLS public key
    std::vector<lux::consensus2::Validator>    validators;  // the full, agreed validator set
    std::uint32_t                              alpha;       // distinct-voter floor (gate)
    lux::consensus2::WaveConfig                wave;        // liveness/voting committee config
    std::uint64_t                              epoch;       // bound into each vote's message
};

class Node2Host {
public:
    explicit Node2Host(HostConfig cfg);
    ~Node2Host();

    Node2Host(const Node2Host&) = delete;
    Node2Host& operator=(const Node2Host&) = delete;

    // Bind 127.0.0.1:cfg.port and listen. Returns the actual bound port (resolves
    // an ephemeral 0). Throws std::runtime_error at the boundary on failure.
    std::uint16_t listen_bind();

    // Form the full mesh against `peers` (index -> address, excluding self). The
    // lower-indexed end of each pair dials; the higher-indexed end accepts — so a
    // pair has exactly one connection. Dials retry until `deadline_ms` (covers
    // staggered process start); accepts block until the expected count arrives.
    // Returns true iff every peer is connected. Must be preceded by listen_bind.
    bool connect_mesh(const std::map<std::uint32_t, PeerAddr>& peers, int deadline_ms = 10000);

    // ── consensus driving (single-threaded) ─────────────────────────────────
    void submit(const lux::consensus2::VotePosition& pos) { node_->submit(pos); }

    lux::consensus2::Decision poll(const lux::consensus2::VotePosition& pos,
                                   std::uint32_t yes, std::uint32_t total) {
        return node_->poll(pos, yes, total);
    }

    // Drain inbound votes from every peer into the gate. Returns votes delivered.
    std::size_t pump() { return mesh_->pump(); }

    bool isFinal(const lux::consensus2::BlockId& b) const { return node_->isFinal(b); }
    std::optional<lux::consensus2::QuorumCert> cert(const lux::consensus2::BlockId& b) const {
        return node_->cert(b);
    }
    bool verifyCert(const lux::consensus2::QuorumCert& c) const { return node_->verifyCert(c); }

    std::uint32_t index()      const noexcept { return cfg_.index; }
    std::uint16_t port()       const noexcept { return cfg_.port; }
    std::size_t   peer_count() const noexcept { return mesh_->peer_count(); }

private:
    // accept one inbound peer: accept() + read its 4-byte BE index handshake +
    // TCP_NODELAY. Returns the connected fd, or -1 on error.
    int accept_one();
    // dial one peer: connect() with retry to `deadline_ms` + write our 4-byte BE
    // index handshake + TCP_NODELAY. Returns the connected fd, or -1 on failure.
    int dial_one(const PeerAddr& a, int deadline_ms);

    HostConfig                          cfg_;
    int                                 listen_fd_ = -1;
    std::unique_ptr<MeshVoteTransport>  mesh_;
    std::unique_ptr<lux::consensus2::Node> node_;
};

}  // namespace lux::node2
