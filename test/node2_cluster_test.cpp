// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// node2_cluster_test.cpp — the live-mesh proof. Five Node2Host instances bind
// real loopback TCP listeners on distinct (ephemeral) ports, dial each other into
// a full mesh (listen/accept/connect — no socketpair), and each runs a real
// consensus2::Node with its own BLS key. We propose one block, let every node
// sign + broadcast its ACCEPT vote over the wire, then drive the pump loop and
// assert ALL FIVE independently reach finality with a verifying >2/3-stake quorum
// certificate.
//
// The decisive assertion: immediately after voting, every node holds ONLY its own
// vote and is NOT final (1 < α). Finality appears strictly after pump() — i.e.
// only once the other four votes have crossed real sockets. That is the live-mesh
// property the socketpair test could not show.
//
// Determinism: connection setup is the only concurrent phase (each host's mesh is
// formed on its own thread, joined at a barrier). The consensus phase then runs
// single-threaded, round-robin over the five hosts — no data races — so the
// outcome is fixed: all five finalize within a generous deadline, or the test
// fails hard. Never flaky.

#include "lux/node2/node2_host.hpp"
#include "bls_signature.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <string>
#include <thread>
#include <vector>

using namespace lux::node2;
using namespace lux::consensus2;

namespace {

constexpr std::uint32_t kN     = 5;    // validators
constexpr std::uint64_t kStake = 20;   // per validator → total 100
constexpr std::uint32_t kAlpha = 4;    // distinct-voter floor; 2/3 stake floor of 100 is 66

int g_fail = 0;
void check(bool ok, const std::string& what) {
    if (!ok) { std::printf("    ASSERT FAILED: %s\n", what.c_str()); ++g_fail; }
}

struct Key {
    std::array<std::uint8_t, 32> sk{};
    PubKey pk{};
};

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
    return p;
}

}  // namespace

int main() {
    std::printf("====================== node2 — five-node finality over real TCP ======================\n");
    std::printf("5 validators, full loopback mesh (listen/accept/connect), ZAP-framed votes, BLS quorum cert\n\n");

    // ── identities + the agreed validator set (every node holds the same set) ──
    std::vector<Key> keys;
    for (std::uint32_t i = 0; i < kN; ++i) keys.push_back(make_key(std::uint8_t(0x80 + i)));
    std::vector<Validator> set;
    for (const auto& k : keys) set.push_back({k.pk, kStake});

    // ── construct hosts; bind ephemeral loopback listeners (all up before any dial) ──
    std::vector<std::unique_ptr<Node2Host>> hosts;
    std::vector<std::uint16_t> ports(kN);
    for (std::uint32_t i = 0; i < kN; ++i) {
        HostConfig cfg;
        cfg.index      = i;
        cfg.port       = 0;  // ephemeral
        cfg.sk         = keys[i].sk;
        cfg.pk         = keys[i].pk;
        cfg.validators = set;
        cfg.alpha      = kAlpha;
        cfg.wave       = WaveConfig{5, 0.8, 4};  // threshold int(5*0.8)=4: poll(5,5) triggers a vote
        hosts.push_back(std::make_unique<Node2Host>(std::move(cfg)));
        ports[i] = hosts[i]->listen_bind();
        std::printf("  node %u  listening on 127.0.0.1:%u\n", i, ports[i]);
    }

    // ── form the full mesh: each host on its own thread (the one concurrent phase) ──
    std::vector<char> ok(kN, 0);
    {
        std::vector<std::thread> setup;
        for (std::uint32_t i = 0; i < kN; ++i) {
            setup.emplace_back([&, i] {
                std::map<std::uint32_t, PeerAddr> peers;
                for (std::uint32_t j = 0; j < kN; ++j)
                    if (j != i) peers[j] = PeerAddr{"127.0.0.1", ports[j]};
                ok[i] = hosts[i]->connect_mesh(peers, /*deadline_ms=*/10000) ? 1 : 0;
            });
        }
        for (auto& t : setup) t.join();
    }
    for (std::uint32_t i = 0; i < kN; ++i) {
        check(ok[i] == 1, "node " + std::to_string(i) + " formed its mesh");
        check(hosts[i]->peer_count() == kN - 1,
              "node " + std::to_string(i) + " has " + std::to_string(kN - 1) + " peers");
    }
    std::printf("  mesh: full %u-node loopback TCP mesh up (%u connections, each node %u peers)\n\n",
                kN, kN * (kN - 1) / 2, kN - 1);

    // ── propose one block; every node signs + broadcasts its ACCEPT vote ───────
    const VotePosition pos = make_pos(0x42, 1);
    for (auto& h : hosts) h->submit(pos);
    for (int r = 0; r < 4; ++r) for (auto& h : hosts) h->poll(pos, 5, 5);  // beta confirmation rounds

    // Decisive: each node now holds ONLY its own vote (self-echo) → NOT final.
    for (std::uint32_t i = 0; i < kN; ++i)
        check(!hosts[i]->isFinal(pos.block_id),
              "node " + std::to_string(i) + " NOT final before pump (only its own vote)");
    std::printf("  voted: all 5 broadcast ACCEPT; none final yet (each has 1/5 votes, needs the wire)\n");

    // ── drive the pump loop until all five finalize (or fail on deadline) ──────
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    std::size_t total_delivered = 0;
    int rounds = 0;
    for (;;) {
        std::size_t still = 0;
        for (auto& h : hosts) {
            total_delivered += h->pump();           // drain inbound votes off the sockets
            if (!h->isFinal(pos.block_id)) ++still;
        }
        ++rounds;
        if (still == 0) break;
        if (std::chrono::steady_clock::now() >= deadline) {
            check(false, "all nodes final within deadline");
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    std::printf("  pumped: %zu votes delivered across the mesh in %d round(s)\n\n",
                total_delivered, rounds);

    // ── assert finality + an independently-verifying quorum cert on every node ──
    for (std::uint32_t i = 0; i < kN; ++i) {
        const bool fin = hosts[i]->isFinal(pos.block_id);
        check(fin, "node " + std::to_string(i) + " FINAL after wire-delivered votes");
        auto c = hosts[i]->cert(pos.block_id);
        const bool cert_ok = c.has_value() && hosts[i]->verifyCert(*c);
        check(cert_ok, "node " + std::to_string(i) + " cert verifies");
        const bool stake_ok = c && c->voted_stake == kN * kStake && c->voters.size() == kN;
        check(stake_ok, "node " + std::to_string(i) + " cert: 5 voters, full 100 stake");
        std::printf("  node %u: FINAL  voters=%zu/5  stake=%llu/%llu  cert=%s\n",
                    i,
                    c ? c->voters.size() : 0,
                    static_cast<unsigned long long>(c ? c->voted_stake : 0),
                    static_cast<unsigned long long>(kN * kStake),
                    cert_ok ? "VERIFIED" : "INVALID");
    }

    // Cross-check: independently-assembled certs agree on the same finality witness.
    {
        auto c0 = hosts[0]->cert(pos.block_id);
        bool all_match = c0.has_value();
        for (std::uint32_t i = 1; i < kN && all_match; ++i) {
            auto ci = hosts[i]->cert(pos.block_id);
            all_match = ci && ci->voters == c0->voters && ci->position.block_id == c0->position.block_id;
        }
        check(all_match, "all five nodes assembled the identical voter set (leaderless convergence)");
    }

    std::printf("--------------------------------------------------------------------------------------\n");
    if (g_fail) { std::printf("==== node2 CLUSTER: FAIL (%d) ====\n", g_fail); return 1; }
    std::printf("==== node2 CLUSTER: PASS — 5 nodes finalized over real TCP with a verifying BLS quorum cert ====\n");
    return 0;
}
