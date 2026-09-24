// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco

#include "lux/node/statement.hpp"

#include "lux/consensus/bls.hpp"
#include "lux/consensus/threshold.hpp"
#include "lux/zap/wire.hpp"

#include <algorithm>
#include <cstring>
#include <stdexcept>

namespace lux::node {

namespace {

using lux::consensus::kQCFinality;
using lux::consensus::kQuorumCertVersion;
using lux::consensus::Tier;

// Offsets of the layout both kinds share (canonicalVoteMessageFor's order).
constexpr std::size_t kVersionAt = 18;
constexpr std::size_t kRoleAt    = 20;
constexpr std::size_t kChainAt   = 21;
constexpr std::size_t kHeightAt  = 53;
constexpr std::size_t kRoundAt   = 61;
constexpr std::size_t kBlockAt   = 65;
constexpr std::size_t kParentAt  = 97;
constexpr std::size_t kRootAt    = 129;
constexpr std::size_t kPayloadAt = 161;
constexpr std::size_t kSetAt     = 193;
constexpr std::size_t kAcceptAt  = 225;

Id id_at(const Message& m, std::size_t at) {
    Id out{};
    std::memcpy(out.data(), m.data() + at, 32);
    return out;
}

std::uint64_t be64_at(const Message& m, std::size_t at) {
    std::uint64_t v = 0;
    for (std::size_t i = 0; i < 8; ++i) v = (v << 8) | m[at + i];
    return v;
}

void put_id(Message& m, std::size_t at, const Id& id) { std::memcpy(m.data() + at, id.data(), 32); }

void put_be(Message& m, std::size_t at, std::uint64_t v, std::size_t width) {
    for (std::size_t i = 0; i < width; ++i) m[at + i] = std::uint8_t(v >> (8 * (width - 1 - i)));
}

bool zero(const Id& id) { return id == Id{}; }

}  // namespace

std::optional<Claim> read(const Message& m) {
    Claim c;
    if (std::equal(kVoteTag.begin(), kVoteTag.end(), m.begin())) c.kind = Kind::Vote;
    else if (std::equal(kAnchorTag.begin(), kAnchorTag.end(), m.begin())) c.kind = Kind::Anchor;
    else return std::nullopt;
    const std::uint16_t version = std::uint16_t((m[kVersionAt] << 8) | m[kVersionAt + 1]);
    if (version != kQuorumCertVersion || m[kRoleAt] != kQCFinality) return std::nullopt;
    // The accept byte is signed, so a third value is a message no signer made;
    // and this node states only accepts.
    if (m[kAcceptAt] != 0x01) return std::nullopt;
    c.slot.chain  = id_at(m, kChainAt);
    c.slot.height = be64_at(m, kHeightAt);
    c.slot.round  = (std::uint32_t(m[kRoundAt]) << 24) | (std::uint32_t(m[kRoundAt + 1]) << 16) |
                    (std::uint32_t(m[kRoundAt + 2]) << 8) | std::uint32_t(m[kRoundAt + 3]);
    c.block    = id_at(m, kBlockAt);
    c.parent   = id_at(m, kParentAt);
    c.set_root = id_at(m, kSetAt);
    if (c.kind == Kind::Anchor &&
        (c.slot.round != 0 || !zero(c.parent) || !zero(id_at(m, kRootAt)) || !zero(id_at(m, kPayloadAt))))
        return std::nullopt;
    return c;
}

Message vote_message(const lux::consensus::VotePosition& pos) {
    const auto bytes = lux::consensus::canonical_vote_message(pos, true);
    Message    m{};
    std::copy_n(bytes.begin(), std::min(bytes.size(), m.size()), m.begin());
    return m;
}

Message anchor_message(const Id& chain, std::uint64_t height, const Id& tip, const Id& set_root) {
    Message m{};
    std::copy(kAnchorTag.begin(), kAnchorTag.end(), m.begin());
    put_be(m, kVersionAt, kQuorumCertVersion, 2);
    m[kRoleAt] = kQCFinality;
    put_id(m, kChainAt, chain);
    put_be(m, kHeightAt, height, 8);
    put_be(m, kRoundAt, 0, 4);
    put_id(m, kBlockAt, tip);
    put_id(m, kSetAt, set_root);
    m[kAcceptAt] = 0x01;
    return m;
}

std::vector<std::uint8_t> encode(const Statement& s) {
    lux::zap::Writer w;
    w.write_bytes(s.message.data(), s.message.size());
    w.write_bytes(s.node.data(), s.node.size());
    w.write_bytes(s.sig.data(), s.sig.size());
    return w.take();
}

std::optional<Statement> decode_statement(std::span<const std::uint8_t> payload) {
    lux::zap::Reader          r(payload.data(), payload.size());
    std::vector<std::uint8_t> message, node, sig;
    if (!r.read_bytes(message) || !r.read_bytes(node) || !r.read_bytes(sig)) return std::nullopt;
    if (r.remaining() != 0 || message.size() != kMessageLen || node.size() != 20 || sig.size() != 96)
        return std::nullopt;
    Statement s;
    std::copy(message.begin(), message.end(), s.message.begin());
    std::copy(node.begin(), node.end(), s.node.begin());
    std::copy(sig.begin(), sig.end(), s.sig.begin());
    return s;
}

Statement sign(const Message& m, const Node& self, const std::array<std::uint8_t, 32>& sk) {
    Statement s;
    s.message = m;
    s.node    = self;
    if (lux::consensus::bls::sign(sk.data(), m.data(), m.size(), s.sig.data()) != 0)
        throw std::runtime_error("statement: the voting key did not sign");
    return s;
}

std::optional<PubKey> key_of(const Committee& c, const Node& who) {
    for (const auto& m : c.members())
        if (m.node == who && m.key.size() == 48) {
            PubKey k{};
            std::copy(m.key.begin(), m.key.end(), k.begin());
            return k;
        }
    return std::nullopt;
}

bool verify(const Statement& s, const Committee& c) {
    const auto key = key_of(c, s.node);
    if (!key) return false;
    return lux::consensus::bls::verify(key->data(), s.message.data(), s.message.size(), s.sig.data()) == 0;
}

std::uint32_t quorum(const Committee& c) {
    return lux::consensus::signer_floor(Tier::Quasar, static_cast<std::uint32_t>(c.size()));
}

std::vector<std::uint8_t> encode(const Certificate& cert) {
    std::vector<std::uint8_t> out(cert.message.begin(), cert.message.end());
    const auto                n = static_cast<std::uint32_t>(cert.signers.size());
    for (int s = 24; s >= 0; s -= 8) out.push_back(std::uint8_t(n >> s));
    for (const auto& who : cert.signers) out.insert(out.end(), who.begin(), who.end());
    out.insert(out.end(), cert.aggregate.begin(), cert.aggregate.end());
    return out;
}

std::optional<Certificate> decode_certificate(std::span<const std::uint8_t> bytes) {
    if (bytes.size() < kMessageLen + 4 + 96) return std::nullopt;
    Certificate c;
    std::copy_n(bytes.begin(), kMessageLen, c.message.begin());
    std::uint32_t n = 0;
    for (std::size_t i = 0; i < 4; ++i) n = (n << 8) | bytes[kMessageLen + i];
    // Exact: no count the bytes do not hold, no byte past the aggregate.
    if (bytes.size() != kMessageLen + 4 + std::size_t(n) * 20 + 96) return std::nullopt;
    std::size_t at = kMessageLen + 4;
    for (std::uint32_t i = 0; i < n; ++i, at += 20) {
        Node who{};
        std::copy_n(bytes.begin() + std::ptrdiff_t(at), 20, who.begin());
        c.signers.push_back(who);
    }
    std::copy_n(bytes.begin() + std::ptrdiff_t(at), 96, c.aggregate.begin());
    return c;
}

std::optional<Certificate> certify(const Message& m, const std::map<Node, Signature>& sigs,
                                   const Committee& c) {
    Certificate cert;
    cert.message = m;
    std::vector<std::uint8_t> flat;
    for (const auto& [who, sig] : sigs) {  // a std::map iterates ascending
        cert.signers.push_back(who);
        flat.insert(flat.end(), sig.begin(), sig.end());
    }
    if (cert.signers.size() < quorum(c)) return std::nullopt;
    if (lux::consensus::bls::aggregate_sigs(flat.data(), cert.signers.size(), cert.aggregate.data()) != 0)
        return std::nullopt;
    if (!verify(cert, c)) return std::nullopt;
    return cert;
}

bool verify(const Certificate& cert, const Committee& c) {
    // A certificate is this committee's only when it speaks of this committee:
    // the chain its members are entitled on, and the set they are. The same keys
    // entitled on another chain are another committee.
    const auto claim = read(cert.message);
    if (!claim || claim->slot.chain != c.chain() || claim->set_root != c.root()) return false;
    const auto n = static_cast<std::uint32_t>(c.size());
    if (n < lux::consensus::QuorumCertEngine::committee_floor(Tier::Quasar)) return false;
    std::uint64_t             total = 0, voted = 0;
    std::vector<std::uint8_t> keys;
    for (const auto& m : c.members()) total += m.weight;
    for (std::size_t i = 0; i < cert.signers.size(); ++i) {
        if (i > 0 && !(cert.signers[i - 1] < cert.signers[i])) return false;  // ascending, distinct
        const auto key = key_of(c, cert.signers[i]);
        if (!key) return false;
        for (const auto& m : c.members())
            if (m.node == cert.signers[i]) voted += m.weight;
        keys.insert(keys.end(), key->begin(), key->end());
    }
    if (cert.signers.size() < quorum(c)) return false;
    if (voted <= lux::consensus::two_thirds_stake_floor(total)) return false;
    return lux::consensus::bls::fast_aggregate_verify(keys.data(), cert.signers.size(), cert.message.data(),
                                                     cert.message.size(), cert.aggregate.data()) == 0;
}

}  // namespace lux::node
