// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco

#include "lux/node/committee.hpp"

#include "lux/consensus/bls.hpp"           // key_validate, and the proof's domain tag
#include "lux/node/pq_handshake.hpp"       // derive_node_id — the one naming rule
#include "lux/node/validators.hpp"         // validator_set_root — the one commitment

#include <blst.h>

#include <algorithm>
#include <cstdio>
#include <stdexcept>
#include <tuple>

namespace lux::node {
namespace {

constexpr char kHexDigits[] = "0123456789abcdef";

std::string encode(std::span<const std::uint8_t> b) {
    std::string s;
    s.reserve(b.size() * 2);
    for (const auto c : b) {
        s.push_back(kHexDigits[c >> 4]);
        s.push_back(kHexDigits[c & 0x0f]);
    }
    return s;
}

int nibble(char c) noexcept {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// Hex as the other two read it: mixed case, an optional `0x`, and nothing else.
// Odd length and a stray character are the two refusals, told apart because an
// operator fixing a committee file wants to know which.
std::vector<std::uint8_t> decode(std::string_view s, std::size_t line, const char* what) {
    const auto fail = [&](const std::string& why) -> std::vector<std::uint8_t> {
        throw std::runtime_error("line " + std::to_string(line) + ": " + what +
                                 " is not hex: " + why);
    };
    if (s.size() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s.remove_prefix(2);
    if (s.size() % 2 != 0) return fail("odd number of digits");
    std::vector<std::uint8_t> out;
    out.reserve(s.size() / 2);
    for (std::size_t i = 0; i < s.size(); i += 2) {
        const int hi = nibble(s[i]), lo = nibble(s[i + 1]);
        if (hi < 0 || lo < 0) {
            const std::size_t at = hi < 0 ? i : i + 1;
            return fail(std::string("invalid character '") + s[at] + "' at position " +
                        std::to_string(at));
        }
        out.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
    }
    return out;
}

// A BLS public key as Go hashes it: blst's 96-byte uncompressed form.
//
// A key that will not decompress is written through UNCHANGED rather than
// dropped. It cannot be a valid member — `validators()` refuses it at the door
// — and hashing nothing in its place would make two different committees commit
// to one value. Rust does exactly this, for exactly this reason.
std::vector<std::uint8_t> uncompressed(const std::vector<std::uint8_t>& key) {
    blst_p1_affine point;
    if (key.size() != 48 || blst_p1_uncompress(&point, key.data()) != BLST_SUCCESS)
        return key;
    std::vector<std::uint8_t> out(96);
    blst_p1_affine_serialize(out.data(), &point);
    return out;
}

// Whether `proof` is `key`'s signature over `message` under the
// proof-of-possession domain.
//
// NOT `bls::pop_verify`, and the difference is the message: that one builds
// `node ‖ key` itself, which is the REGISTRATION proof and is pinned across
// three languages by a frozen corpus. A committee proof covers the chain as
// well, so the message is the caller's — which is exactly what `bls::pop_sign`
// already assumes ("the CALLER decides what message a proof binds"). The
// consensus surface exposes that general SIGN and only the specialised VERIFY;
// until it exposes the pair, the pairing is here, under the tag that surface
// publishes.
bool proves(std::span<const std::uint8_t> message, const std::vector<std::uint8_t>& key,
            const std::vector<std::uint8_t>& proof) {
    blst_p1_affine pk;
    blst_p2_affine sig;
    if (key.size() != 48 || blst_p1_uncompress(&pk, key.data()) != BLST_SUCCESS) return false;
    if (proof.size() != 96 || blst_p2_uncompress(&sig, proof.data()) != BLST_SUCCESS) return false;
    // The identity and an off-subgroup point are refused as the encoding they
    // are, not later as a pairing that happens to fail.
    if (blst_p1_affine_is_inf(&pk) || !blst_p1_affine_in_g1(&pk)) return false;
    if (blst_p2_affine_is_inf(&sig) || !blst_p2_affine_in_g2(&sig)) return false;
    return blst_core_verify_pk_in_g1(
               &pk, &sig, /*hash_or_encode=*/true, message.data(), message.size(),
               reinterpret_cast<const byte*>(lux::consensus::bls::kPopDST),
               lux::consensus::bls::kPopDSTLen, nullptr, 0) == BLST_SUCCESS;
}

}  // namespace

std::vector<std::uint8_t> Committee::claim(const std::array<std::uint8_t, 32>& chain,
                                           const Node& node, std::span<const std::uint8_t> key) {
    std::vector<std::uint8_t> m;
    m.reserve(chain.size() + node.size() + key.size());
    m.insert(m.end(), chain.begin(), chain.end());
    m.insert(m.end(), node.begin(), node.end());
    m.insert(m.end(), key.begin(), key.end());
    return m;
}

Committee Committee::read(std::string_view text, const std::array<std::uint8_t, 32>& chain) {
    Committee   c;
    c.chain_ = chain;
    std::size_t number = 0;
    while (!text.empty()) {
        const std::size_t cut  = text.find('\n');
        std::string_view  line = text.substr(0, cut);
        text = (cut == std::string_view::npos) ? std::string_view{} : text.substr(cut + 1);
        ++number;

        line = line.substr(0, line.find('#'));
        while (!line.empty() && (line.front() == ' ' || line.front() == '\t' || line.front() == '\r'))
            line.remove_prefix(1);
        while (!line.empty() && (line.back() == ' ' || line.back() == '\t' || line.back() == '\r'))
            line.remove_suffix(1);
        if (line.empty()) continue;

        std::vector<std::string_view> parts;
        for (std::size_t i = 0; i < line.size();) {
            while (i < line.size() && (line[i] == ' ' || line[i] == '\t')) ++i;
            const std::size_t start = i;
            while (i < line.size() && line[i] != ' ' && line[i] != '\t') ++i;
            if (i > start) parts.push_back(line.substr(start, i - start));
        }
        if (parts.size() != 3)
            throw std::runtime_error("line " + std::to_string(number) +
                                     ": expected <identity> <key> <proof>");

        Member m;
        m.identity = decode(parts[0], number, "identity");
        // THE ONE NAMING RULE, and it is the handshake's: a validator's name is
        // what its ML-DSA key derives, at chain zero, so the name in the file
        // and the name the link proves are the same 20 bytes — on every chain
        // it serves.
        m.node     = pq::derive_node_id(m.identity);
        m.weight   = 1;
        m.key      = decode(parts[1], number, "key");
        m.proof    = decode(parts[2], number, "proof");
        c.members_.push_back(std::move(m));
    }
    if (c.members_.empty())
        throw std::runtime_error("a committee with no validators is not a committee");

    // A validator listed twice would be counted twice — two seats, one key, and
    // a quorum that is smaller than it looks.
    for (std::size_t i = 0; i < c.members_.size(); ++i)
        for (std::size_t j = 0; j < i; ++j)
            if (c.members_[j].node == c.members_[i].node)
                throw std::runtime_error(encode(c.members_[i].node) + " is listed twice");

    return c;
}

std::string Committee::line(std::span<const std::uint8_t> identity,
                            std::span<const std::uint8_t> key,
                            std::span<const std::uint8_t> proof) {
    return encode(identity) + " " + encode(key) + " " + encode(proof);
}

std::optional<std::size_t> Committee::seat(const Node& who) const {
    for (std::size_t i = 0; i < members_.size(); ++i)
        if (members_[i].node == who) return i;
    return std::nullopt;
}

Id Committee::root() const {
    std::vector<SetMember> set;
    set.reserve(members_.size());
    for (const auto& m : members_)
        set.push_back(SetMember{m.node, m.weight, uncompressed(m.key)});
    return validator_set_root(std::move(set));
}

std::vector<lux::consensus::Validator> Committee::validators() const {
    std::vector<lux::consensus::Validator> set;
    set.reserve(members_.size());

    for (const auto& m : members_) {
        const auto refuse = [&m](const char* why) {
            throw std::runtime_error(std::string(why) + ": " + encode(m.node));
        };

        // ENCODING, then POSSESSION — the order a registration door holds them
        // in, and for its reason: a member that is not a key at all should not
        // reach the pairing. `key_validate` is the BLS spec's own clause plus
        // Lux's fourth (one point, one encoding), so a second spelling of a key
        // is refused here rather than admitted as a key no proof was made for.
        if (m.key.size() != std::tuple_size_v<lux::consensus::PubKey>) refuse("no key");
        if (!lux::consensus::bls::key_validate(m.key.data())) refuse("key encoding");
        if (m.weight == 0) refuse("zero weight");
        if (!proves(claim(chain_, m.node, m.key), m.key, m.proof)) refuse("possession");

        lux::consensus::PubKey key{};
        std::copy(m.key.begin(), m.key.end(), key.begin());

        // ONE KEY PER NODE, ONE NODE PER KEY. Two seats behind one key is a
        // quorum smaller than it looks; two keys behind one node is a node that
        // can sign twice. `read` already refused a repeated name, so this is the
        // key half — and it is checked over the CANONICAL spelling, which
        // key_validate has just established.
        for (const auto& seated : set)
            if (seated.pubkey == key) refuse("duplicate key");

        set.push_back(lux::consensus::Validator{key, m.weight});
    }

    // Canonical order: ascending by compressed key, which is what decides
    // signature bit indices, so every node that admits the same file holds the
    // same set in the same order.
    std::sort(set.begin(), set.end(),
              [](const lux::consensus::Validator& a, const lux::consensus::Validator& b) {
                  return a.pubkey < b.pubkey;
              });
    return set;
}

}  // namespace lux::node
