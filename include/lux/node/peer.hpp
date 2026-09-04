// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// peer.hpp — one live link to a luxd validator: the p2p Handshake/PeerList
// exchange that makes it count, and the PushQuery -> Position -> BLS vote ->
// Gossip path that co-certifies a C-chain block with it.
//
// This is a NEW peer, not a mode of `Node2Host`/`MeshVoteTransport` — those
// speak node.cpp's own internal, self-referential wire to node.cpp's own
// mesh. This speaks Go's `luxfi/proto node/zap/p2p` to an external luxd
// process, over `peer_tls::Connection` (mutual TLS 1.3, X25519MLKEM768). See
// `peer_wire.hpp` for the codec and `LLM.md` for why the two are kept apart.

#pragma once

#include "lux/consensus/quorum_cert_engine.hpp"  // Id
#include "lux/node/peer_tls.hpp"
#include "lux/node/staking.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <optional>
#include <string>

namespace lux::node::peer {

using lux::consensus::Id;

// What this validator votes AS, once it knows the network: which chain, and
// the commitment to the validator set the P-chain currently enforces. Held
// once per `Peer::connect` because node.rs's own proof reads it fresh on
// every dial — a stale root would sign for a set no longer in force.
struct Ballot {
    Id chain_id{};
    Id validator_set_root{};
};

// One height this peer has told luxd it prefers/accepts, for Chits replies.
struct Frontier {
    Id            outer_id{};
    std::uint64_t height = 0;
};

class Peer {
public:
    // Dial `host:port` (luxd's staking port), complete the TLS layer, and
    // return a peer that has not yet exchanged the p2p Handshake — call
    // `join()` next.
    static Peer connect(const std::string& host, std::uint16_t port, const staking::Identity& id,
                        std::uint32_t network_id, std::uint16_t advertise_port,
                        std::chrono::milliseconds tls_timeout);

    // Send this side's Handshake, then service frames until `finishedHandshake`
    // is true on BOTH sides: luxd's Handshake answered with our PeerList
    // (what flips ITS flag) and luxd's own PeerList received (what flips
    // OURS — not merely completing the Handshake exchange itself). Throws on
    // `deadline`.
    void join(std::chrono::milliseconds deadline);

    [[nodiscard]] bool ready() const noexcept { return accepted_; }
    [[nodiscard]] const std::array<std::uint8_t, 20>& node_id() const noexcept { return id_->node_id(); }

    // Tell luxd which chain/tip this validator is caught up to — what this
    // node answers a `GetAcceptedFrontier` poll with. Call before `step()`s
    // that matter for a specific chain.
    void track(const Ballot& ballot, const Frontier& initial);

    // One receive-and-dispatch cycle: read one frame (propagating
    // `peer_tls::Quiet` — the caller should simply call again — and
    // `peer_tls::Desync`, which means the connection is gone), and act on it:
    //   Ping         -> Pong
    //   GetPeerList  -> (empty) PeerList
    //   Handshake    -> (empty) PeerList   (answers a LATE inbound handshake)
    //   PeerList     -> accepted_ = true
    //   PushQuery    -> Chits, THEN a signed vote gossiped back (see below)
    // Anything else is read and dropped — this peer answers what it must to
    // stay counted; it does not yet implement the rest of the p2p surface.
    void step(std::chrono::milliseconds deadline);

    // How many votes this peer has cast (informational, for the daemon's log).
    [[nodiscard]] std::uint64_t votes_cast() const noexcept { return votes_cast_; }

private:
    Peer(peer_tls::Connection conn, const staking::Identity& id, std::uint32_t network_id,
        std::uint16_t advertise_port)
        : conn_(std::move(conn)), id_(&id), network_id_(network_id), advertise_port_(advertise_port) {}

    void send_handshake();
    void send_peer_list();
    void send_pong();
    void read_frame_dispatch(std::chrono::milliseconds deadline);
    void handle_push_query(std::span<const std::uint8_t> body);
    void cast_vote(const Id& outer_id, const Id& canonical_id, const Id& parent_canonical_id,
                  std::uint64_t height);

    peer_tls::Connection      conn_;
    const staking::Identity*  id_;
    std::uint32_t             network_id_;
    std::uint16_t             advertise_port_;
    bool                      accepted_          = false;  // OUR finishedHandshake
    bool                      sent_peer_list_    = false;  // answered luxd's Handshake yet
    std::optional<Ballot>     ballot_;
    std::optional<Frontier>   frontier_;
    std::uint64_t             votes_cast_        = 0;
};

}  // namespace lux::node::peer
