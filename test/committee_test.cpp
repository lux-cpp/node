// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// committee_test.cpp — the network description, held to the one every other
// implementation reads.
//
// THE FIXTURES ARE REAL FILES: `test/committee/four.txt` is four lines the
// daemon published (`zood --data vN --publish`), with real ML-DSA-65
// identities, real BLS keys and real proofs of possession. The refusal fixtures
// are files a reader can hand to any implementation and watch it say no.
//
// THE EXPECTED NAMES AND ROOT ARE GO'S. The names were computed by
// `ids.NodeIDScheme.DeriveMLDSA` and the root by `validators.SetRoot`, in a Go
// program that imports both packages unmodified — not by this code, which would
// only prove this code is deterministic.
//
// AND THE NAMES ARE NAMES ON A CHAIN. Read the same file under a different
// chain and it names four different validators with a different root, which is
// the property that stops a published line from being a credential on every
// network at once (LP-10603). `unbound.txt` is a file from before that was
// true — lines whose proofs are over a name derived from the key alone — and it
// is refused rather than half-read.

#include "lux/node/committee.hpp"

#include "lux/node/evm.hpp"  // chain_id — the network the names are bound to

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

// The chain those four are validators OF: the local C-Chain, whose 32-byte id
// is `evm::chain_id(31337)`. It is not decoration — every name above is a
// function of it.
const std::array<std::uint8_t, 32> kChain = [] {
    std::array<std::uint8_t, 32> c{};
    const char*                  hex = "c066f0c6c80088c742bf27c7e3f8d5ad18a903a4162ba17dba4168e1c51ede87";
    for (std::size_t i = 0; i < c.size(); ++i) {
        const auto nib = [](char x) { return x <= '9' ? x - '0' : x - 'a' + 10; };
        c[i] = static_cast<std::uint8_t>((nib(hex[2 * i]) << 4) | nib(hex[2 * i + 1]));
    }
    return c;
}();

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
        Committee::read(slurp(fixture), kChain);
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
    "42eebf978769a20c42aa5e1c703fcbadcddf8806",
    "9c7383ad3ca9820641e0babbca11862679f63cdd",
    "38f6dbe13314653c4af4598a79f7e0f375a1c9a1",
    "ccf17d93d74b9e7ce3c6b207f57dcd92a69ff10c",
};

// github.com/luxfi/validators SetRoot over that committee, weight 1 each, keys
// uncompressed — the number a Go validator would fold into every vote.
const char* const kRoot = "33fb8fd25c96ed64ee11952cf49fb6bc8f522b510fe4aca2044792e53b12e5a2";


}  // namespace

int main() {
    std::printf("node — the committee file, and the network it describes\n\n");

    // ── the parse ───────────────────────────────────────────────────────────
    const Committee four = Committee::read(slurp("four.txt"), kChain);
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

    // ── the chain is not decoration ─────────────────────────────────────────
    {
        check(kChain == lux::node::evm::chain_id(31337),
              "the fixture chain is the local C-Chain's own id, not a constant");
        // The SAME file, read as a committee of a different network. Every name
        // moves, so the root moves: a line published for one chain names nobody
        // on another, which is the whole of a committee file's scope.
        std::array<std::uint8_t, 32> elsewhere{};
        elsewhere.fill(0x11);
        const Committee other = Committee::read(slurp("four.txt"), elsewhere);
        bool             moved = other.size() == four.size();
        for (std::size_t i = 0; i < other.size() && moved; ++i)
            moved = other.members()[i].node != four.members()[i].node;
        check(moved, "the same file under another chain names four other validators");
        check(hex(other.root()) != kRoot, "and commits to another root");
        std::printf("        %s\n", hex(other.root()).c_str());
        // ...and those four cannot vote: their proofs are over names nobody
        // derives here, so the door refuses the set rather than admitting it.
        try {
            (void)other.validators();
            check(false, "a committee read under the wrong chain is refused");
        } catch (const std::exception& e) {
            check(true, std::string("a committee read under the wrong chain is refused: ") + e.what());
        }
    }

    // ── a line from before the chain was in the name ────────────────────────
    // unbound.txt was published when a validator's name was the hash of its key
    // alone. The lines are well formed and the proofs are real; they are proofs
    // over a different name, and this is what that looks like from here.
    {
        const Committee unbound = Committee::read(slurp("unbound.txt"), kChain);
        check(unbound.size() == 4, "an unbound file still parses: the shape did not change");
        try {
            (void)unbound.validators();
            check(false, "a proof over an unbound name is refused");
        } catch (const std::exception& e) {
            check(true, std::string("a proof over an unbound name is refused: ") + e.what());
        }
    }

    // ── comments, blank lines and indentation are not validators ────────────
    {
        const Committee noisy = Committee::read(slurp("noisy.txt"), kChain);
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
        const Committee same = Committee::read(text, kChain);
        check(same.members()[0].node == four.members()[0].node,
              "a field written 0x-first names the same validator");
        check(hex(same.root()) == kRoot, "and the committee commits to the same root");
    }

    // ── what a validator publishes is what a reader reads ───────────────────
    {
        std::string written;
        for (const auto& m : four.members())
            written += Committee::line(m.identity, m.key, m.proof) + "\n";
        const Committee again = Committee::read(written, kChain);
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
        const Committee forged = Committee::read(slurp("forged.txt"), kChain);
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
            (void)Committee::read(text, kChain).validators();
            check(false, "a proof with one bit moved is refused");
        } catch (const std::exception& e) {
            check(true, std::string("a proof with one bit moved is refused: ") + e.what());
        }
    }

    std::printf("\n%s\n", g_fail == 0 ? "all good" : "FAILURES");
    return g_fail == 0 ? 0 : 1;
}
