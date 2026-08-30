// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// mesh.hpp — forming the mesh: bind a listener, reach the configured peers, and
// hand each connected socket to a transport.
//
// This is the SOCKET half of a node, and it is only that. It knows who it is
// (an index), where to listen, whom to dial, and where to put an fd once the
// link exists. It has no Node, no gate, no vote, no finality rule — the same
// line MeshVoteTransport already draws between framing and consensus, drawn
// once more between connecting and framing.
//
// Drawing it here is what lets one mesh serve two drivers: Node2Host, which
// runs a bare consensus::Node, and a chain built on lux-cpp/sdk, which runs its
// own validator over the same wire. Neither has to reimplement the dance, and
// neither can drift from the other about who dials whom.
//
// THE MESH IS NOT THE QUORUM. connect() returns how many peers it reached
// within one deadline; it never demands all of them. The finality rule already
// says how many votes are enough, and stating it a second time as "every peer
// must connect" would only be a way to disagree with it — one absent validator
// would take down a cluster the ⅔ rule calls healthy. The caller reads the
// returned count against the rule it already has.
//
// Concurrency: one Mesh is driven by ONE thread. It holds no consensus state,
// so there is nothing here to lock.

#pragma once

#include "lux/node/mesh_vote_transport.hpp"

#include <cstdint>
#include <map>
#include <string>

namespace lux::node {

struct PeerAddr {
    std::string   host;
    std::uint16_t port;
};

// Every blocking operation on a peer socket is bounded by this window, so no
// single peer can hold the node: a handshake that never arrives times out, and a
// peer that stops reading makes broadcast fail (and be evicted) rather than hang.
inline constexpr int kPeerIoTimeoutMs = 2000;

class Mesh {
public:
    // `index` is this node's validator index — it decides dial direction and is
    // what the handshake claims. `tx` receives every connected socket and outlives
    // this Mesh.
    Mesh(std::uint32_t index, MeshVoteTransport& tx) noexcept : index_(index), tx_(tx) {}
    ~Mesh();

    Mesh(const Mesh&) = delete;
    Mesh& operator=(const Mesh&) = delete;

    // Bind 127.0.0.1:port and listen. Returns the port actually bound (which
    // resolves a requested 0). Throws std::runtime_error at the boundary on
    // failure. Must precede connect().
    std::uint16_t listen_bind(std::uint16_t port);

    // Reach as many of `peers` as possible within ONE deadline that covers the
    // whole phase — accepting, dialing, and the index handshake alike. The lower-
    // indexed end of each pair dials and the higher-indexed end accepts, so a pair
    // has exactly one connection; accepts and dials are swept together, so an
    // absent low-indexed peer cannot starve the dials. Returns the number of peers
    // connected (== the transport's peer_count()).
    std::size_t connect(const std::map<std::uint32_t, PeerAddr>& peers, int deadline_ms = 10000);

    std::uint32_t index() const noexcept { return index_; }
    std::uint16_t port()  const noexcept { return bound_port_; }

private:
    // Take one inbound peer off the listen backlog: accept() + its 4-byte BE index
    // handshake, both bounded. Sets `peer_index` to the index the dialer claimed —
    // a claim, not a proof, which connect() checks against the slots it is waiting
    // on. Returns the connected fd, or -1.
    int accept_one(std::uint32_t& peer_index);
    // One dial attempt (no retry — the sweep in connect() owns the retry policy):
    // non-blocking connect bounded by `wait_ms`, then our 4-byte BE index
    // handshake. Returns the connected fd, or -1.
    int dial_once(const PeerAddr& a, int wait_ms);

    std::uint32_t      index_;
    MeshVoteTransport& tx_;
    int                listen_fd_  = -1;
    std::uint16_t      bound_port_ = 0;
};

}  // namespace lux::node
