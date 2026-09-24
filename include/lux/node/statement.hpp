// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// statement.hpp — what a validator signs with its voting key, and what α of the
// same signature make.
//
// A validator signs 226-byte MESSAGES, and there are two kinds:
//
//   vote    Go's canonical vote message (engine/chain canonicalVoteMessageFor):
//           "LUX/chain/vote/v2\0" ‖ version ‖ role ‖ chain ‖ height ‖ round ‖
//           block ‖ parent ‖ state root ‖ payload root ‖ set root ‖ accept.
//           "This block, at this height, on this parent."
//   anchor  the same layout under the tag "LUX/chain/anchor\0\0", naming an
//           imported tip: chain ‖ height T ‖ tip id H ‖ set root, every other
//           axis zero. "The history I read off an export ends at (T, H)."
//
// The tag is the domain separation. Both are signed under the one consensus
// BLS ciphersuite, and the two tags differ at byte 10, so no signature over one
// kind verifies as the other. Keeping the layout is what lets both go through
// ONE journal: the slot a message falls in — (chain, height, round) — sits at
// the same offsets in both, so an anchor at height T and a vote at height T are
// the same slot, and a validator makes at most one of them.
//
// A CERTIFICATE is α distinct committee signatures over one message, aggregated.
// One rule verifies both kinds, and it is consensus's rule, called rather than
// restated: signer_floor(Quasar, n) distinct signers, their stake past
// two_thirds_stake_floor(total), n at least the Quasar committee floor, and one
// aggregate pairing over the message.
//
// On the mesh a statement is ZAP msg type 62 — the id lux-rs/node sends a vote
// under (lux_consensus::vote::VOTE) — and the same payload: the message, the
// signer's 20-byte node id and the signature, each ZAP length-prefixed. A Rust
// validator reads a C++ vote as its own.

#pragma once

#include "lux/consensus/quorum_cert_engine.hpp"  // VotePosition, Signature, PubKey
#include "lux/node/committee.hpp"                // Committee, Node, Id

#include <array>
#include <cstdint>
#include <map>
#include <optional>
#include <span>
#include <vector>

namespace lux::node {

using lux::consensus::PubKey;
using lux::consensus::Signature;

inline constexpr std::size_t kMessageLen = 226;
using Message                            = std::array<std::uint8_t, kMessageLen>;

// Go's vote tag, 17 characters and a NUL.
inline constexpr std::array<std::uint8_t, 18> kVoteTag = {
    'L', 'U', 'X', '/', 'c', 'h', 'a', 'i', 'n', '/', 'v', 'o', 't', 'e', '/', 'v', '2', 0};
// The anchor's, 16 characters and two NULs: the same width, so every field
// after it sits where a vote's does.
inline constexpr std::array<std::uint8_t, 18> kAnchorTag = {
    'L', 'U', 'X', '/', 'c', 'h', 'a', 'i', 'n', '/', 'a', 'n', 'c', 'h', 'o', 'r', 0, 0};

// The ZAP msg type a statement travels under on the mesh.
inline constexpr std::uint8_t kStatementMsgType = 62;

enum class Kind : std::uint8_t { Vote, Anchor };

// Where a validator may make one statement: a chain, a height, a round. Read out
// of the signed bytes, never the envelope.
struct Slot {
    Id            chain{};
    std::uint64_t height = 0;
    std::uint32_t round  = 0;
    auto operator<=>(const Slot&) const = default;
};

// What a message says.
struct Claim {
    Kind          kind = Kind::Vote;
    Slot          slot;
    Id            block{};     // the block a vote names; the tip an anchor names
    Id            parent{};    // a vote's parent; zero in an anchor
    Id            set_root{};
};

// Read a message, or refuse it: the tag must be one of the two, the version
// and role Go's, the accept byte 1, and an anchor's unused axes zero — so one
// (chain, T, H, set) has exactly one anchor message.
[[nodiscard]] std::optional<Claim> read(const Message& m);

// A block vote: canonical_vote_message(pos, accept).
[[nodiscard]] Message vote_message(const lux::consensus::VotePosition& pos);
// An anchor on the imported tip (height, tip).
[[nodiscard]] Message anchor_message(const Id& chain, std::uint64_t height, const Id& tip,
                                     const Id& set_root);

// One validator's signed statement.
struct Statement {
    Message   message{};
    Node      node{};
    Signature sig{};
};

[[nodiscard]] std::vector<std::uint8_t> encode(const Statement& s);
[[nodiscard]] std::optional<Statement>  decode_statement(std::span<const std::uint8_t> payload);

// Sign `m` as `self` with the BLS secret `sk`, in the consensus vote domain.
// Deterministic: the same message signs to the same bytes, which is what makes a
// re-sent statement the same statement.
[[nodiscard]] Statement sign(const Message& m, const Node& self, const std::array<std::uint8_t, 32>& sk);

// The voting key the committee holds for `who`.
[[nodiscard]] std::optional<PubKey> key_of(const Committee& c, const Node& who);

// Whether `s` is signed by the committee member it names.
[[nodiscard]] bool verify(const Statement& s, const Committee& c);

// The distinct signers a certificate needs from this committee.
[[nodiscard]] std::uint32_t quorum(const Committee& c);

// α signatures over one message.
struct Certificate {
    Message           message{};
    std::vector<Node> signers;  // ascending, distinct
    Signature         aggregate{};
};

// message(226) ‖ count(u32 BE) ‖ count × node(20) ‖ aggregate(96).
[[nodiscard]] std::vector<std::uint8_t>   encode(const Certificate& c);
[[nodiscard]] std::optional<Certificate>  decode_certificate(std::span<const std::uint8_t> bytes);

// A certificate from signatures already verified over `m`, when they clear the
// floors; nullopt when they do not.
[[nodiscard]] std::optional<Certificate> certify(const Message& m, const std::map<Node, Signature>& sigs,
                                                 const Committee& c);

// The one rule a certificate of either kind is held to: it names this
// committee's chain and set root, and carries the floors' worth of its signers.
[[nodiscard]] bool verify(const Certificate& cert, const Committee& c);

}  // namespace lux::node
