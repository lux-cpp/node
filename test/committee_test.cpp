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
// AND THE NAME IS THE SAME EVERYWHERE. A node answers to one name on every
// chain it serves; what is scoped is the PROOF, which is signed over
// `chain ‖ node ‖ key`. So the same file read as a committee of another network
// names the same four validators — and admits none of them, because their
// proofs authorise them here and nowhere else. `elsewhere.txt` is the mirror of
// that: the same four, publishing for a different chain (LP-10603).

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

// The chain those four are ENTITLED on: the local C-Chain, whose 32-byte id is
// `evm::chain_id(31337)`. It is not in any name above — it is in every proof.
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
    "bafa8bdb0612e1c07161b50c705270b835a19b03",
    "dbe40be3fb369a4a21bdbc92ffd15983f4904374",
    "d34f2b65e4d42df87011e4b61dc669cf1a8df4da",
    "21e1c5fb625cec5450231e6d922a42d734ea7329",
};

// github.com/luxfi/validators SetRoot over that committee, weight 1 each, keys
// uncompressed — the number a Go validator would fold into every vote.
const char* const kRoot = "de34e8d1948f90d09610c8737c6487d494e093ba01680f1a54095a1cdfa696e7";


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

    // ── the name is not scoped; the proof is ────────────────────────────────
    {
        check(kChain == lux::node::evm::chain_id(31337),
              "the fixture chain is the local C-Chain's own id, not a constant");

        // THE SAME FILE, read as a committee of another network. The four names
        // do not move — a node does not change its name when it joins a second
        // chain — and neither does the root, which commits to names and keys.
        // What moves is the entitlement: not one of them can vote there.
        std::array<std::uint8_t, 32> another{};
        another.fill(0x11);
        const Committee there = Committee::read(slurp("four.txt"), another);
        bool            same  = there.size() == four.size();
        for (std::size_t i = 0; i < there.size() && same; ++i)
            same = there.members()[i].node == four.members()[i].node;
        check(same, "the same file on another chain names the same four validators");
        check(hex(there.root()) == kRoot, "and commits to the same root");
        try {
            (void)there.validators();
            check(false, "and admits none of them");
        } catch (const std::exception& e) {
            check(true, std::string("and admits none of them: ") + e.what());
        }
    }

    // ── a line published for somewhere else ─────────────────────────────────
    // elsewhere.txt is these same four validators, publishing for a different
    // chain. Same identities, same voting keys, same names — and proofs that
    // authorise them there. Here they authorise nothing, which is the whole of
    // what a committee file's scope is.
    {
        const Committee elsewhere = Committee::read(slurp("elsewhere.txt"), kChain);
        bool            same      = elsewhere.size() == four.size();
        for (std::size_t i = 0; i < elsewhere.size() && same; ++i)
            same = elsewhere.members()[i].node == four.members()[i].node;
        check(same, "a line published elsewhere names the same validator");
        try {
            (void)elsewhere.validators();
            check(false, "and is refused here");
        } catch (const std::exception& e) {
            check(true, std::string("and is refused here: ") + e.what());
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
