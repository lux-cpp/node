// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// node_host.hpp — a running consensus node. Node2Host binds a TCP listener,
// forms a mesh with its configured peers (one connection per pair), and drives
// one local consensus::Party over that mesh.
//
// It is a COMPOSITION, and the three parts it composes are each usable without
// it: Mesh forms the links (lux/node/mesh.hpp), MeshVoteTransport frames votes
// over them, and consensus::Party decides. A chain that wants its own driver —
// lux-cpp/sdk builds one that also owns blocks and execution — takes the first
// two and supplies the third, rather than reimplementing the socket dance.
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

#include "lux/consensus/node.hpp"
#include "lux/node/mesh.hpp"
#include "lux/node/mesh_vote_transport.hpp"

#include <array>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <vector>

namespace lux::node {

// Fixed identity + consensus parameters for one node instance. Peer discovery is
// out of scope: the peer set is supplied to connect_mesh, fixed for the run.
struct HostConfig {
    std::uint32_t                              index;       // this node's validator index
    std::uint16_t                              port;        // requested listen port (0 = OS-assigned)
    std::array<std::uint8_t, 32>               sk;          // this node's BLS secret key
    lux::consensus::PubKey                    pk;          // this node's BLS public key
    std::vector<lux::consensus::Validator>    validators;  // the full, agreed validator set
    lux::consensus::WaveConfig                wave;        // liveness/voting committee config

    // The height this node has already DECIDED, read from its own durable store
    // before it starts. consensus::Party::mark_finalized_through names the embedder
    // as the only one that can supply this, because the Party keeps the frontier
    // in memory and has no persistence layer: leave it at 0 after a restart and a
    // height whose slot was pruned becomes re-signable, which is the cross-restart
    // prune-then-resign fork (proofs/no_double_finalize.tex §Durability across a
    // restart). 0 is correct for a node that has decided nothing — the frontier is
    // engaged at 0 and only height 0, which is never voted on, is closed.
    //
    // Go seeds the same floor from vm.LastAccepted at Start, so a chain reads it
    // from its last accepted block's height.
    std::uint64_t                              accepted = 0;
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
    std::uint16_t listen_bind() { return mesh_.listen_bind(cfg_.port); }

    // Reach as many of `peers` as possible within ONE deadline. Returns the number
    // of peers connected (== peer_count()). Must be preceded by listen_bind.
    std::size_t connect_mesh(const std::map<std::uint32_t, PeerAddr>& peers, int deadline_ms = 10000) {
        return mesh_.connect(peers, deadline_ms);
    }

    // ── consensus driving (single-threaded) ─────────────────────────────────
    void submit(const lux::consensus::VotePosition& pos) { node_->submit(pos); }

    // One liveness round for `block`, driven by the committee this node can reach
    // RIGHT NOW — itself plus its live peers. Say plainly what this is: node has
    // no sampling layer, so this is a connectivity measure, not a poll of anyone's
    // opinion. A node keeps confirming only while it can still see a supermajority
    // of the set, and stops the moment it cannot; it never votes on a set it
    // cannot reach. When photon sampling lands it replaces exactly this one
    // expression, and nothing above it changes.
    lux::consensus::Decision round(const lux::consensus::BlockId& block) {
        const auto reachable = static_cast<std::uint32_t>(tx_->peer_count() + 1);
        return node_->poll(block, reachable, reachable);
    }

    // Drain inbound votes from every peer into the gate. Returns votes delivered.
    std::size_t pump() { return tx_->pump(); }

    bool isFinal(const lux::consensus::BlockId& b) const { return node_->isFinal(b); }
    std::optional<lux::consensus::QuorumCert> cert(const lux::consensus::BlockId& b) const {
        return node_->cert(b);
    }
    bool verifyCert(const lux::consensus::QuorumCert& c) const { return node_->verifyCert(c); }

    // The finalization observer's step, and the reason node embeds the Party: a
    // height that carries a VERIFYING quorum cert is decided, so advance the
    // decided-height frontier. From then on the Party refuses to sign at that
    // height at all, which is what stops a late sibling from ever collecting this
    // validator's second signature (consensus node.hpp mark_finalized_through
    // names the embedder as the caller — this is that call). Returns the cert, or
    // nullopt if the block is not final or its cert does not verify.
    //
    // The caller must make the height durable, so that the next boot can supply it
    // as HostConfig::accepted. This call moves the IN-MEMORY frontier only.
    std::optional<lux::consensus::QuorumCert> accept(const lux::consensus::VotePosition& pos);

    std::uint32_t index()      const noexcept { return cfg_.index; }
    std::uint16_t port()       const noexcept { return mesh_.port(); }
    std::size_t   peer_count() const noexcept { return tx_->peer_count(); }

private:
    HostConfig                             cfg_;
    // Declaration order is the construction order, and it is load-bearing: the
    // transport must outlive the Mesh that hands it sockets, and both must outlive
    // the Party that votes over them.
    std::unique_ptr<MeshVoteTransport>     tx_;
    Mesh                                   mesh_;
    std::unique_ptr<lux::consensus::Node>  node_;
};

}  // namespace lux::node
