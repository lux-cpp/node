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
//
// Three layers, in this order, and the middle one is conditional: TLS 1.3
// with the hybrid group, then — on a strict-PQ chain — the ML-KEM-768 +
// ML-DSA-65 handshake of `pq_handshake.hpp`, then the p2p Handshake below.
// This is the one place the middle layer is bound, and it is bound inside
// `connect` rather than offered as a step a caller could forget.

#pragma once

#include "lux/consensus/quorum_cert_engine.hpp"  // Id
#include "lux/node/peer_tls.hpp"
#include "lux/node/pq_handshake.hpp"
#include "lux/node/staking.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <optional>
#include <string>

namespace lux::node::peer {

using lux::consensus::Id;

// The chain-wide security profile, `peer.ProfileID` in Go and the byte the
// PQ handshake commits to. It is a genesis fact, not a negotiation: luxd
// reads it from its `securityProfile.json` pin and a peer that guesses wrong
// is closed on the first frame, in either direction. The shipped pins are
// StrictPQ for mainnet, testnet and local/localnet, and Permissive for
// devnet; a chain with no pin at all behaves as Permissive.
enum class Profile : std::uint8_t {
    None       = 0x00,
    StrictPQ   = 0x01,
    Permissive = 0x02,
    Fips       = 0x03,
};

// Go's `profileRequiresPQHandshake`: the same two profiles that build the
// SchemeGate also run the handshake, decided in one place so the two cannot
// drift apart.
[[nodiscard]] constexpr bool requires_pq(Profile p) noexcept {
    return p == Profile::StrictPQ || p == Profile::Fips;
}

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
    // Dial `host:port` (luxd's staking port), complete the TLS layer and, on
    // a profile that requires it, the PQ handshake — and return a peer that
    // has not yet exchanged the p2p Handshake. Call `join()` next.
    //
    // `timeout` bounds the PQ exchange as well as the dial: it is one
    // connection being established, and luxd bounds its own side the same
    // way (`MaxClockDifference + 30s` on the whole INIT/RESP round trip).
    // Throws if the PQ handshake fails — there is no degraded link to
    // return, and returning one would be the downgrade the profile exists
    // to forbid.
    static Peer connect(const std::string& host, std::uint16_t port, const staking::Identity& id,
                        Profile profile, std::uint32_t network_id, std::uint16_t advertise_port,
                        std::chrono::milliseconds timeout);

    // Send this side's Handshake, then service frames until `finishedHandshake`
    // is true on BOTH sides: luxd's Handshake answered with our PeerList
    // (what flips ITS flag) and luxd's own PeerList received (what flips
    // OURS — not merely completing the Handshake exchange itself). Throws on
    // `deadline`.
    void join(std::chrono::milliseconds deadline);

    [[nodiscard]] bool ready() const noexcept { return accepted_; }

    // The name luxd knows THIS side by on THIS link. It is the TLS
    // certificate's hash160 on a permissive chain and the ML-DSA-derived one
    // once the PQ handshake has run, because that is when luxd replaces it
    // (`verifyPQIdentityBinding`). Answered from one field so a caller
    // cannot ask the question twice and get two answers.
    [[nodiscard]] const std::array<std::uint8_t, 20>& node_id() const noexcept { return node_id_; }

    // The peer's own key-bound NodeID, present only when the PQ handshake
    // ran. Its absence is not a weaker form of presence: on a permissive
    // chain nothing on the wire binds a NodeID to a key at all.
    [[nodiscard]] const std::optional<std::array<std::uint8_t, 20>>& peer_node_id() const noexcept {
        return peer_node_id_;
    }

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
        : conn_(std::move(conn)), id_(&id), network_id_(network_id), advertise_port_(advertise_port),
          node_id_(id.node_id()) {}

    // The PQ handshake over this link, and the identity adoption that
    // follows it. Called by `connect` alone.
    void secure(std::chrono::milliseconds deadline);

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
    std::array<std::uint8_t, 20>                node_id_{};
    std::optional<std::array<std::uint8_t, 20>> peer_node_id_;
};

}  // namespace lux::node::peer
