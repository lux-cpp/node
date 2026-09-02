// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// boot_floor_test.cpp — a validator that restarts must not sign a height it has
// already decided, and HostConfig::accepted is how it is told which one that is.
//
// consensus::Party keeps the decided-height frontier IN MEMORY and says so: it
// names the embedder as the only party that can restore it, because only the
// embedder has a durable store. Node2Host is that embedder. Before this, it had
// no way to be told — the frontier could only be advanced by accept(), which
// needs a live in-memory cert that a freshly booted process does not have — so
// every restart came up with an empty frontier, and a height whose slot had been
// pruned was signable a second time. That is the cross-restart prune-then-resign
// fork (proofs/no_double_finalize.tex §Durability across a restart).
//
// THE OBSERVABLE IS THE SIGNATURE, AND IT IS READ OFF THE WIRE. round() reports
// the wave's decision either way — the gate simply declines to sign (node.cpp
// poll, guard 2) — so a Decision proves nothing here. Instead two hosts are
// meshed over real loopback TCP with α = 2, so a certificate exists only if BOTH
// signed. The witness host is identical in both runs; the ONE thing that changes
// is the floor the other host booted with.
//
//   floor below the height  →  it signs   →  2 votes cross the wire  →  cert
//   floor at the height     →  it is mute →  1 vote                  →  no cert
//
// A control that did not distinguish these would be a test of nothing, so the
// run that must produce a cert is asserted just as hard as the run that must not.

#include "lux/node/node_host.hpp"
#include "bls_signature.hpp"

#include <array>
#include <cstdint>
#include <cstdio>
#include <map>
#include <memory>
#include <string>
#include <thread>
#include <vector>

using namespace lux::node;
using namespace lux::consensus;

namespace {

constexpr std::uint32_t kN      = 2;    // validators
constexpr std::uint64_t kStake  = 50;   // each → 100 total
constexpr std::uint64_t kHeight = 7;    // the height under test
constexpr int           kBeta   = 2;

int g_fail = 0;
void check(bool ok, const std::string& what) {
    std::printf("  %s  %s\n", ok ? "ok  " : "FAIL", what.c_str());
    if (!ok) ++g_fail;
}

struct Key { std::array<std::uint8_t, 32> sk{}; PubKey pk{}; };

Key make_key(std::uint8_t tag) {
    std::array<std::uint8_t, 32> seed{};
    seed[0] = tag;
    for (int i = 1; i < 32; ++i) seed[i] = std::uint8_t(0xA5 ^ (tag + i));
    Key k;
    if (cevm::crypto::bls::keygen(seed.data(), k.sk.data()) != 0) { std::puts("keygen"); std::exit(2); }
    if (cevm::crypto::bls::sk_to_pk(k.sk.data(), k.pk.data()) != 0) { std::puts("sk_to_pk"); std::exit(2); }
    return k;
}

VotePosition make_pos(std::uint8_t tag, std::uint64_t h) {
    VotePosition p{};
    p.block_id.fill(tag);
    p.height = h;
    p.round  = 1;
    return p;
}

std::vector<Key>       g_keys;
std::vector<Validator> g_set;

// Run one height on a real two-host mesh. `booted_at` is the durable decided
// height host 0 comes up with; host 1 is always fresh. Returns how many voters
// the witness (host 1) could assemble into a certificate — 2 if both signed,
// 0 if it could not reach α at all.
std::size_t voters_at_height(std::uint64_t booted_at) {
    std::vector<std::unique_ptr<Node2Host>> hosts;
    std::vector<std::uint16_t> ports(kN);
    for (std::uint32_t i = 0; i < kN; ++i) {
        HostConfig cfg;
        cfg.index      = i;
        cfg.port       = 0;  // ephemeral
        cfg.sk         = g_keys[i].sk;
        cfg.pk         = g_keys[i].pk;
        cfg.validators = g_set;
        cfg.wave       = WaveConfig{kN, kN, kBeta};  // both reachable → the round counts
        cfg.accepted   = (i == 0) ? booted_at : 0;   // THE ONE VARIABLE
        hosts.push_back(std::make_unique<Node2Host>(std::move(cfg)));
        ports[i] = hosts[i]->listen_bind();
    }

    std::vector<char> ok(kN, 0);
    {
        std::vector<std::thread> setup;
        for (std::uint32_t i = 0; i < kN; ++i)
            setup.emplace_back([&, i] {
                std::map<std::uint32_t, PeerAddr> peers;
                for (std::uint32_t j = 0; j < kN; ++j)
                    if (j != i) peers[j] = PeerAddr{"127.0.0.1", ports[j]};
                ok[i] = hosts[i]->connect_mesh(peers, /*deadline_ms=*/10000) == kN - 1 ? 1 : 0;
            });
        for (auto& t : setup) t.join();
    }
    for (std::uint32_t i = 0; i < kN; ++i)
        if (!ok[i]) { std::puts("    mesh did not form"); std::exit(2); }

    const VotePosition pos = make_pos(0x42, kHeight);
    for (auto& h : hosts) h->submit(pos);
    for (int r = 0; r < kBeta; ++r)
        for (auto& h : hosts) h->round(pos.block_id);

    // Drain the wire. Bounded: whatever was signed has crossed by now, and a
    // vote that was never signed will not appear however long we wait.
    for (int r = 0; r < 50; ++r)
        for (auto& h : hosts) h->pump();

    const auto c = hosts[1]->cert(pos.block_id);
    if (!c) return 0;
    if (!hosts[1]->verifyCert(*c)) { std::puts("    a cert that does not verify"); std::exit(2); }
    return c->voters.size();
}

}  // namespace

int main() {
    std::printf("node — the boot floor: a restarted validator does not re-sign a decided height\n\n");

    for (std::uint8_t i = 0; i < kN; ++i) {
        g_keys.push_back(make_key(std::uint8_t(0xB0 + i)));
        g_set.push_back({g_keys.back().pk, kStake});
    }

    // The control. Host 0 booted having decided only up to the height BELOW the
    // one on offer, so that height is still open to it: it signs, both votes
    // cross the wire, and the witness assembles a full certificate. Without this
    // run passing, the run below would prove only that something was broken.
    const auto open = voters_at_height(kHeight - 1);
    check(open == kN, "a validator booted below the height signs there (the control)");

    // The property. Same keys, same set, same block, same wire — host 0 booted
    // having ALREADY decided this height. It must stay mute, so the witness is
    // left holding its own vote alone and no certificate can form.
    const auto closed = voters_at_height(kHeight);
    check(closed == 0, "a validator booted at the height signs nothing there");

    check(open != closed, "the floor is what changed the outcome, and nothing else");

    std::printf("\n  voters assembled: booted below = %zu, booted at = %zu\n", open, closed);
    std::printf("\n%s\n", g_fail ? "FAIL" : "PASS — HostConfig::accepted closes the height across a restart");
    return g_fail ? 1 : 0;
}
