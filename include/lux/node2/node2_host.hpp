// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// node2_host.hpp — a running consensus2 node. Node2Host binds a TCP listener,
// forms a mesh with its configured peers (one connection per pair), and drives
// one local consensus2::Node over that mesh.
//
// Identity (index + BLS key + validator set) is fixed at construction; the peer
// ADDRESSES are supplied later to connect_mesh(), because in a real cluster the
// listen port may be ephemeral and is only known after bind. That split keeps
// "who am I" orthogonal from "who do I dial".
//
// THE MESH IS NOT THE QUORUM. connect_mesh returns how many peers it reached
// within one deadline; it never demands all of them. The finality rule already
// says how many votes are enough, and stating it a second time as "every peer
// must connect" would only be a way to disagree with it — one absent validator
// would take down a cluster that the ⅔ rule says is healthy. The caller reads
// the returned count against the rule it already has.
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
#include <chrono>
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

// Every blocking operation on a peer socket is bounded by this window, so no
// single peer can hold the node: a handshake that never arrives times out, and a
// peer that stops reading makes broadcast fail (and be evicted) rather than hang.
inline constexpr int kPeerIoTimeoutMs = 2000;

// Fixed identity + consensus parameters for one node2 instance. Peer discovery is
// out of scope: the peer set is supplied to connect_mesh, fixed for the run.
struct HostConfig {
    std::uint32_t                              index;       // this node's validator index
    std::uint16_t                              port;        // requested listen port (0 = OS-assigned)
    std::array<std::uint8_t, 32>               sk;          // this node's BLS secret key
    lux::consensus2::PubKey                    pk;          // this node's BLS public key
    std::vector<lux::consensus2::Validator>    validators;  // the full, agreed validator set
    std::uint32_t                              alpha;       // distinct-voter floor (gate)
    lux::consensus2::WaveConfig                wave;        // liveness/voting committee config
};

class Node2Host {
public:
    explicit Node2Host(HostConfig cfg);
    ~Node2Host();

    Node2Host(const Node2Host&) = delete;
    Node2Host& operator=(const Node2Host&) = delete;

    // Bind 127.0.0.1:cfg.port and listen. Returns the port actually bound (which
    // resolves a requested 0). Throws std::runtime_error at the boundary on
    // failure. The config keeps the request; port() reports the result.
    std::uint16_t listen_bind();

    // Reach as many of `peers` as possible within ONE deadline that covers the
    // whole phase — accepting, dialing, and the index handshake alike. The lower-
    // indexed end of each pair dials and the higher-indexed end accepts, so a pair
    // has exactly one connection; accepts and dials are swept together, so an
    // absent low-indexed peer cannot starve the dials. Returns the number of peers
    // connected (== peer_count()). Must be preceded by listen_bind.
    std::size_t connect_mesh(const std::map<std::uint32_t, PeerAddr>& peers, int deadline_ms = 10000);

    // ── consensus driving (single-threaded) ─────────────────────────────────
    void submit(const lux::consensus2::VotePosition& pos) { node_->submit(pos); }

    // One liveness round for `block`, driven by the committee this node can reach
    // RIGHT NOW — itself plus its live peers. Say plainly what this is: node2 has
    // no sampling layer, so this is a connectivity measure, not a poll of anyone's
    // opinion. A node keeps confirming only while it can still see a supermajority
    // of the set, and stops the moment it cannot; it never votes on a set it
    // cannot reach. When photon sampling lands it replaces exactly this one
    // expression, and nothing above it changes.
    lux::consensus2::Decision round(const lux::consensus2::BlockId& block) {
        const auto reachable = static_cast<std::uint32_t>(mesh_->peer_count() + 1);
        return node_->poll(block, reachable, reachable);
    }

    // Drain inbound votes from every peer into the gate. Returns votes delivered.
    std::size_t pump() { return mesh_->pump(); }

    bool isFinal(const lux::consensus2::BlockId& b) const { return node_->isFinal(b); }
    std::optional<lux::consensus2::QuorumCert> cert(const lux::consensus2::BlockId& b) const {
        return node_->cert(b);
    }
    bool verifyCert(const lux::consensus2::QuorumCert& c) const { return node_->verifyCert(c); }

    // The finalization observer's step, and the reason node2 embeds the Node: a
    // height that carries a VERIFYING quorum cert is decided, so advance the
    // decided-height frontier. From then on the Node refuses to sign at that
    // height at all, which is what stops a late sibling from ever collecting this
    // validator's second signature (consensus2 node.hpp mark_finalized_through
    // names the embedder as the caller — this is that call). Returns the cert, or
    // nullopt if the block is not final or its cert does not verify.
    std::optional<lux::consensus2::QuorumCert> accept(const lux::consensus2::VotePosition& pos);

    std::uint32_t index()      const noexcept { return cfg_.index; }
    std::uint16_t port()       const noexcept { return bound_port_; }
    std::size_t   peer_count() const noexcept { return mesh_->peer_count(); }

private:
    using Clock    = std::chrono::steady_clock;
    using Deadline = Clock::time_point;

    // Take one inbound peer off the listen backlog: accept() + its 4-byte BE index
    // handshake, both bounded. Returns the connected fd, or -1.
    int accept_one();
    // One dial attempt (no retry — the sweep in connect_mesh owns the retry policy):
    // non-blocking connect bounded by `wait_ms`, then our 4-byte BE index handshake.
    // Returns the connected fd, or -1.
    int dial_once(const PeerAddr& a, int wait_ms);

    HostConfig                          cfg_;
    int                                 listen_fd_  = -1;
    std::uint16_t                       bound_port_ = 0;
    std::unique_ptr<MeshVoteTransport>  mesh_;
    std::unique_ptr<lux::consensus2::Node> node_;
};

}  // namespace lux::node2
