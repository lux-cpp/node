// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// set_root_test.cpp — the validator-set commitment, held to Go's encoding.
//
// `validator_set_root` has to produce the SAME 32 bytes as luxd's
// `hashValidatorSet` for the same set, because the root goes into the signed
// vote message: a node whose root differs signs a different message, and luxd
// drops its votes rather than disputing them. "Nearly compatible" is not a
// state this value has.
//
// The expected roots below are computed by an INDEPENDENT implementation of the
// spec (a Python script over hashlib), not by this code — the same discipline
// Go's own golden test uses, and for the same reason: comparing an encoder to
// itself proves only that it is deterministic.

#include "lux/node/validators.hpp"

#include <cstdio>
#include <string>

using namespace lux::node;

namespace {

int g_fail = 0;
void check(bool ok, const std::string& what) {
    std::printf("  %s  %s\n", ok ? "ok  " : "FAIL", what.c_str());
    if (!ok) ++g_fail;
}

std::string hex(const Id& id) {
    std::string s = "0x";
    char b[3];
    for (auto c : id) { std::snprintf(b, sizeof(b), "%02x", c); s += b; }
    return s;
}

// A deterministic member: node id all `tag`, uncompressed key all `tag ^ 0x5a`.
SetMember member(std::uint8_t tag, std::uint64_t weight, std::size_t key_len = 96) {
    SetMember m;
    m.node_id.fill(tag);
    m.weight = weight;
    m.pubkey.assign(key_len, static_cast<std::uint8_t>(tag ^ 0x5a));
    return m;
}

}  // namespace

int main() {
    std::printf("node — the validator-set root, against Go's encoding\n\n");

    // An empty set is the explicit "unbound" answer, and it is the ZERO id —
    // not sha256 of nothing, which is a perfectly good hash of the wrong thing.
    check(validator_set_root({}) == Id{}, "an empty set commits to the zero id");

    // One validator. Expected value from the independent implementation.
    {
        const auto r = validator_set_root({member(0x01, 1)});
        check(hex(r) == "0xc52e0890b71b5b0afb37d5c65ed54896f2463cb3fd344fc97e13603b5b6551ee",
              "one validator matches the independent implementation");
        std::printf("        %s\n", hex(r).c_str());
    }

    // SORTING IS BY RAW NODE ID, and the caller must not have to know that.
    // The same three validators handed over in three different orders are one
    // set and must commit to one root.
    {
        const auto a = validator_set_root({member(0x03, 30), member(0x01, 10), member(0x02, 20)});
        const auto b = validator_set_root({member(0x01, 10), member(0x02, 20), member(0x03, 30)});
        const auto c = validator_set_root({member(0x02, 20), member(0x03, 30), member(0x01, 10)});
        check(a == b && b == c, "input order does not change the root");
        check(hex(a) == "0x79fd717045de8b2321fd9a7203463e897063c176ed4bd445d70ecea02014747f",
              "and three validators match the independent implementation");
        std::printf("        %s\n", hex(a).c_str());
    }

    // The weight is COMMITTED TO, so a set that differs only in weight is a
    // different set. This is the whole point of binding the root: a stake change
    // must invalidate an old certificate rather than silently re-weight it.
    {
        const auto declared  = validator_set_root({member(0x01, 1'000'000'000'000ull)});
        const auto effective = validator_set_root({member(0x01, 3'750'000'000ull)});
        check(declared != effective,
              "the declared weight and the effective weight give different roots");
    }

    // The key length is length-prefixed, so a 48-byte compressed key and a
    // 96-byte uncompressed one are different sets. Using the compressed key —
    // which is what the proof of possession signs — produces a root that
    // verifies against nothing.
    {
        const auto uncompressed = validator_set_root({member(0x01, 1, 96)});
        const auto compressed   = validator_set_root({member(0x01, 1, 48)});
        check(uncompressed != compressed,
              "a compressed key gives a different root than an uncompressed one");
    }

    std::printf("\n%s\n", g_fail ? "FAIL" : "PASS");
    return g_fail ? 1 : 0;
}
