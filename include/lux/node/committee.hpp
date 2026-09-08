// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// committee.hpp — the network, written down: who the validators are, in the
// order the operator declared them.
//
// THIS FILE IS THE POINT OF THE FLAG. A daemon that derives its validator set
// from `--index I --n N` can only ever agree with copies of itself that were
// handed the same three numbers, because the set is a private convention rather
// than a description. A committee file is the description — and it is the SAME
// description the Rust node reads (`lux-rs/node src/engine.rs impl Committee`)
// and the same commitment the Go node computes (`luxfi/validators SetRoot`), so
// one file drives all three.
//
// ONE LINE PER VALIDATOR, three fields, hex:
//
//     <identity> <key> <proof>
//
//   identity  the ML-DSA-65 public key this validator is NAMED by. Its name —
//             its node id — is keccak256(identity) truncated to 20 bytes, so a
//             validator cannot claim a name it cannot sign for.
//   key       the 48-byte COMPRESSED BLS public key it votes with.
//   proof     its proof of possession over node ‖ key, which is CHECKED when
//             the set is built and not taken on trust.
//
// `#` starts a comment and runs to the end of the line; blank lines are
// ignored. Every validator carries weight 1: this file says who may vote, and
// the stake a P-chain computed is a different fact from a different source.
//
// FILE ORDER IS KEPT, and that is load-bearing rather than incidental: a peer
// list is POSITIONS (`--peers a:p,b:p,...`), so the third address belongs to
// the third line. The commitment sorts its own copy, so the root does not
// depend on the order — but who dials whom does.

#pragma once

#include "lux/consensus/cert.hpp"                // Node — the 20-byte identity
#include "lux/consensus/quorum_cert_engine.hpp"  // Id, Validator

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace lux::node {

using lux::consensus::Id;
using lux::consensus::Node;

// The name a validator is known by: keccak256(identity), first 20 bytes.
//
// NOT `pq::derive_node_id`, which answers the same question for a different
// wire — SHAKE256 under "NODE_ID_V1", the scheme luxd's peer handshake binds a
// TLS link to. The committee's naming is the Rust node's `pq::name`, and the
// two disagree for the same key. Which one is right is a question about which
// network is being joined, so this states its own and does not guess.
[[nodiscard]] Node name(std::span<const std::uint8_t> identity);

// One validator, exactly as it published itself.
struct Member {
    Node                      node{};      // keccak256(identity)[..20]
    std::uint64_t             weight = 1;  // one line, one vote
    std::vector<std::uint8_t> identity;    // ML-DSA-65 public key
    std::vector<std::uint8_t> key;         // compressed G1 BLS public key
    std::vector<std::uint8_t> proof;       // possession over node ‖ key
};

class Committee {
public:
    // Read what the validators published. Throws std::runtime_error naming the
    // line and the clause that refused: a malformed committee is not a smaller
    // committee, it is a network this node has not been told about.
    //
    // Refused: no validators at all, a line that is not three fields, a field
    // that is not hex, and a validator listed twice — two seats behind one key
    // is a quorum smaller than it looks.
    [[nodiscard]] static Committee read(std::string_view text);

    // What one validator publishes so others can put it in their committee.
    [[nodiscard]] static std::string line(std::span<const std::uint8_t> identity,
                                          std::span<const std::uint8_t> key,
                                          std::span<const std::uint8_t> proof);

    // Where `who` sits, if it sits here at all. This is how a node learns its
    // own index: from the file, not from a flag.
    [[nodiscard]] std::optional<std::size_t> seat(const Node& who) const;

    [[nodiscard]] const std::vector<Member>& members() const noexcept { return members_; }
    [[nodiscard]] std::size_t                size() const noexcept { return members_.size(); }

    // The commitment every vote binds — Go's encoding, over the UNCOMPRESSED
    // key. Computed by the one implementation this repo has of it
    // (`validator_set_root`), so the file and the vote cannot drift.
    [[nodiscard]] Id root() const;

    // The weighted set the finality gate is built over, with every member's
    // possession PROVEN — the same door, in the same order, that Rust's
    // `ValidatorSet::insert` and Go's registration hold: no key, zero weight,
    // possession, duplicate key, duplicate node, weight overflow. Throws
    // std::runtime_error naming the clause and the validator it fell on.
    //
    // Ordered by compressed key rather than by file: the gate keys on the key,
    // this is the order the door canonicalises to, and `seat()` above is the
    // one place that answers a positional question.
    [[nodiscard]] std::vector<lux::consensus::Validator> validators() const;

private:
    std::vector<Member> members_;
};

}  // namespace lux::node
