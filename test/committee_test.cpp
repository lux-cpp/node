// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// committee_test.cpp — the network description, held to the one every other
// implementation reads.
//
// THE FIXTURES ARE REAL FILES, and half of them were not written by this code:
// `test/committee/four.txt` is a network of four whose seats 0 and 2 are lines
// the RUST node published (`lux-node --data nN --publish`) and whose seats 1
// and 3 are lines this one did — real ML-DSA-65 identities, real BLS keys, real
// proofs of possession, interleaved so that a reader which only understood its
// own daemon's lines would fail on the very first seat it did not write. The
// Rust node reads this same file and admits all four; the refusal fixtures are
// files a reader can hand to either daemon and watch both say no.
//
// THE EXPECTED ROOT IS GO'S. It was computed by `github.com/luxfi/validators
// SetRoot` over this exact committee, by a Go program that imports that package
// unmodified — not by this encoder, which would only prove the encoder is
// deterministic. The Rust node's `Committee::root()` agrees with it for the
// same file. Three implementations, one number.

#include "lux/node/committee.hpp"

#include <cstdio>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>

using namespace lux::node;

namespace {

int  g_fail = 0;
void check(bool ok, const std::string& what) {
    std::printf("  %s  %s\n", ok ? "ok  " : "FAIL", what.c_str());
    if (!ok) ++g_fail;
}

std::string hex(std::span<const std::uint8_t> b) {
    static const char* d = "0123456789abcdef";
    std::string        s;
    for (const auto c : b) {
        s.push_back(d[c >> 4]);
        s.push_back(d[c & 0x0f]);
    }
    return s;
}

std::string hex(const Id& id) { return hex(std::span<const std::uint8_t>(id.data(), id.size())); }
std::string hex(const Node& n) { return hex(std::span<const std::uint8_t>(n.data(), n.size())); }

std::string slurp(const std::string& fixture) {
    const std::string path = std::string(COMMITTEE_FIXTURES) + "/" + fixture;
    std::ifstream     f(path, std::ios::binary);
    if (!f) {
        std::printf("  FAIL  cannot read the fixture %s\n", path.c_str());
        ++g_fail;
        return {};
    }
    std::ostringstream out;
    out << f.rdbuf();
    return out.str();
}

// What a refusal looks like: read() threw, and it said which clause.
void refuses(const std::string& fixture, const std::string& because) {
    try {
        Committee::read(slurp(fixture));
        check(false, fixture + " is refused (" + because + ")");
    } catch (const std::exception& e) {
        const std::string said = e.what();
        check(said.find(because) != std::string::npos,
              fixture + " is refused: " + said);
    }
}

// The four validators of test/committee/four.txt, named by keccak256 of the
// ML-DSA public key each published. Independently computed: Go's
// x/crypto/sha3.NewLegacyKeccak256 over the same file.
const char* const kNames[] = {
    "5e8e5ad8382a21edae8974fd0b76d3e9aa9f13ca",
    "8d38e307c511268d69aebed7ec942e1bdfe948c6",
    "6ec1033ac692b4a418698d0a9df7ce02b4d23137",
    "5d427d60f64d0e194da96f7076295e521ec346cd",
};

// github.com/luxfi/validators SetRoot over that committee, weight 1 each, keys
// uncompressed — the number a Go validator would fold into every vote.
const char* const kRoot = "cd75055e9fe042eb3064cb2d13a189067ac3fa87ba227586166a75d1f40ba23f";

}  // namespace

int main() {
    std::printf("node — the committee file, and the network it describes\n\n");

    // ── the naming rule ─────────────────────────────────────────────────────
    // A validator's name is keccak256 of the key it is published under, first
    // 20 bytes. Pinned against the published Keccak-256 value for the empty
    // input, so the hash itself is held to the standard and not to this build.
    {
        const std::vector<std::uint8_t> nothing;
        check(hex(name(nothing)) == "c5d2460186f7233c927e7db2dcc703c0e500b653",
              "a name is keccak256 of the identity, truncated to 20 bytes");
    }

    // ── the parse ───────────────────────────────────────────────────────────
    const Committee four = Committee::read(slurp("four.txt"));
    check(four.size() == 4, "four published lines are four validators");
    {
        bool named = four.size() == 4;
        for (std::size_t i = 0; i < four.size() && named; ++i)
            named = hex(four.members()[i].node) == kNames[i];
        check(named, "and they are named, in file order, as Go names them");
        for (std::size_t i = 0; i < four.size(); ++i)
            std::printf("        %zu %s\n", i, hex(four.members()[i].node).c_str());
    }
    {
        bool shaped = true;
        for (const auto& m : four.members())
            shaped &= m.identity.size() == 1952 && m.key.size() == 48 &&
                      m.proof.size() == 96 && m.weight == 1;
        check(shaped, "each carries an ML-DSA-65 identity, a compressed key, a proof, weight 1");
    }

    // ── the commitment ──────────────────────────────────────────────────────
    {
        const Id root = four.root();
        check(hex(root) == kRoot, "the root is the one Go computes for this set");
        std::printf("        %s\n", hex(root).c_str());
    }

    // ── comments, blank lines and indentation are not validators ────────────
    {
        const Committee noisy = Committee::read(slurp("noisy.txt"));
        bool            same  = noisy.size() == four.size();
        for (std::size_t i = 0; i < noisy.size() && same; ++i)
            same = noisy.members()[i].node == four.members()[i].node;
        check(same, "a commented, indented, blank-line-strewn file is the same committee");
        check(hex(noisy.root()) == kRoot, "and commits to the same root");
    }

    // ── an 0x in front of a field is the same field ─────────────────────────
    // Not a liberty taken here: the Rust reader decodes through a hex decoder
    // that strips the prefix, so a file written with one is a file it accepts.
    // A reader that refused it would refuse a committee its peer runs on.
    {
        std::string text;
        for (std::size_t i = 0; i < four.size(); ++i) {
            const auto& m = four.members()[i];
            text += i == 0 ? "0x" + hex(m.identity) + " 0x" + hex(m.key) + " 0x" + hex(m.proof)
                           : Committee::line(m.identity, m.key, m.proof);
            text += "\n";
        }
        const Committee same = Committee::read(text);
        check(same.members()[0].node == four.members()[0].node,
              "a field written 0x-first names the same validator");
        check(hex(same.root()) == kRoot, "and the committee commits to the same root");
    }

    // ── what a validator publishes is what a reader reads ───────────────────
    {
        std::string written;
        for (const auto& m : four.members())
            written += Committee::line(m.identity, m.key, m.proof) + "\n";
        const Committee again = Committee::read(written);
        bool            same  = again.size() == four.size();
        for (std::size_t i = 0; i < again.size() && same; ++i)
            same = again.members()[i].node == four.members()[i].node;
        check(same, "line() and read() are inverses, in order");
        check(hex(again.root()) == kRoot, "and round-tripping does not move the root");
    }

    // ── a node finds itself by its name, not by a flag ──────────────────────
    {
        bool seated = true;
        for (std::size_t i = 0; i < four.size(); ++i) {
            const auto at = four.seat(four.members()[i].node);
            seated &= at.has_value() && *at == i;
        }
        check(seated, "every validator sits where the file put it");
        Node stranger{};
        stranger.fill(0x5a);
        check(!four.seat(stranger).has_value(), "and a stranger sits nowhere");
    }

    // ── the refusals, each from a file ──────────────────────────────────────
    refuses("empty.txt", "a committee with no validators is not a committee");
    refuses("short.txt", "line 3: expected <identity> <key> <proof>");
    refuses("badhex.txt", "line 2: proof is not hex");
    refuses("twice.txt", "is listed twice");

    // ── possession is CHECKED, not taken on trust ───────────────────────────
    {
        const auto set = four.validators();
        check(set.size() == 4, "four proven validators make a set of four");
    }
    {
        // forged.txt is four.txt with the FIRST validator carrying the SECOND's
        // proof: a real proof, made by a real key, that does not bind this node
        // to this key. It parses — nothing about a line's shape is wrong — and
        // the door refuses it.
        const Committee forged = Committee::read(slurp("forged.txt"));
        check(forged.size() == 4, "a forged line still parses: the shape is not the proof");
        try {
            (void)forged.validators();
            check(false, "a proof that binds another validator is refused");
        } catch (const std::exception& e) {
            const std::string said = e.what();
            check(said.find("possession") != std::string::npos ||
                      said.find("Possession") != std::string::npos,
                  std::string("a proof that binds another validator is refused: ") + said);
        }
    }
    {
        // And a proof that is merely WRONG — one bit moved — is refused too.
        std::string text;
        for (std::size_t i = 0; i < four.size(); ++i) {
            const auto& m     = four.members()[i];
            auto        proof = m.proof;
            if (i == 0) proof.back() ^= 0x01;
            text += Committee::line(m.identity, m.key, proof) + "\n";
        }
        try {
            (void)Committee::read(text).validators();
            check(false, "a proof with one bit moved is refused");
        } catch (const std::exception& e) {
            check(true, std::string("a proof with one bit moved is refused: ") + e.what());
        }
    }

    std::printf("\n%s\n", g_fail == 0 ? "all good" : "FAILURES");
    return g_fail == 0 ? 0 : 1;
}
