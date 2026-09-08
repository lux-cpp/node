// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco

#include "lux/node/committee.hpp"

#include "lux/consensus/registration.hpp"  // admit — the one door a member enters by
#include "lux/node/validators.hpp"         // validator_set_root — the one commitment

#include <blst.h>
#include <test/state/hash_utils.hpp>  // cevm::keccak256

#include <cstdio>
#include <stdexcept>

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

}  // namespace

Node name(std::span<const std::uint8_t> identity) {
    const auto h = cevm::keccak256({identity.data(), identity.size()});
    Node       id{};
    for (std::size_t i = 0; i < id.size(); ++i) id[i] = static_cast<std::uint8_t>(h.bytes[i]);
    return id;
}

Committee Committee::read(std::string_view text) {
    Committee   c;
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
        m.node     = name(m.identity);
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
    std::vector<lux::consensus::Registration> asking;
    asking.reserve(members_.size());
    for (const auto& m : members_)
        asking.push_back(lux::consensus::Registration{m.node, m.key, m.proof, m.weight});

    lux::consensus::CanonicalSet   admitted;
    const lux::consensus::Admission said = lux::consensus::admit(std::move(asking), admitted);
    if (!said)
        throw std::runtime_error(std::string(lux::consensus::admission_name(said.why)) + ": " +
                                 encode(said.node));
    return admitted.weights();
}

}  // namespace lux::node
