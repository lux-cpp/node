// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// node_liveness_test.cpp — the PRODUCTION liveness proof OVER REAL TCP: a faulty
// validator does not stall finality on the wire. consensus is leaderless, so the
// "proposer-fallback" property is realized as "any >2/3-stake quorum finalizes
// without waiting for the faulty node". Two faults, each over real loopback sockets
// with real BLS keys (the in-process companion is consensus's liveness_test):
//
//   [A] DOWN validator — validator 4 of 5 is in every host's CONFIGURED set and
//       never runs. The four live hosts dial it, get nothing, form the 4-node
//       mesh anyway and finalize the block (80 stake > 66) over the wire with a
//       verifying cert. Asking each host only for the peers that happened to be
//       up would have proved nothing: nobody would ever have waited on the absent
//       validator, which is exactly how a mesh that refused to form without it
//       passed this test while five real processes deadlocked.
//
//   [B] WEDGED-but-PRESENT validator — validator 4 joins the full 5-node mesh and
//       gossips, but its only vote is for a CONFLICTING forged block (it never
//       casts a valid vote for the real block). The four honest hosts finalize the
//       real block over the wire; the forged block finalizes NOWHERE (1 vote, 20
//       stake). A present, actively-misbehaving node cannot stall or fork finality.
//
// Determinism: mesh setup is the only concurrent phase (per-host thread, joined at
// a barrier); the consensus phase is single-threaded round-robin over the hosts —
// never flaky. Either every required host finalizes within a generous deadline or
// the test fails hard.

#include "lux/node/node_host.hpp"
#include "bls_signature.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <map>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

using namespace lux::node;
using namespace lux::consensus;

namespace {

constexpr std::uint32_t kN     = 5;
constexpr std::uint64_t kStake = 20;   // total 100, floor 66
constexpr std::uint32_t kAlpha = 4;    // 4 voters = 80 > 66; 1 fault tolerated

int g_fail = 0;
void check(bool ok, const std::string& what) {
    if (!ok) { std::printf("    ASSERT FAILED: %s\n", what.c_str()); ++g_fail; }
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
    VotePosition p{}; p.block_id.fill(tag); p.height = h; p.round = 1; return p;
}

// The shared validator set (all 5 validators, whether or not their host runs).
std::vector<Validator> g_set;
std::vector<Key> g_keys;

std::unique_ptr<Node2Host> make_host(std::uint32_t index) {
    HostConfig cfg;
    cfg.index      = index;
    cfg.port       = 0;  // ephemeral
    cfg.sk         = g_keys[index].sk;
    cfg.pk         = g_keys[index].pk;
    cfg.validators = g_set;
    cfg.alpha      = kAlpha;
    cfg.wave       = WaveConfig{kN, 4, 4};
    return std::make_unique<Node2Host>(std::move(cfg));
}

// A loopback port that is BOUND but never listening: a validator that is in the
// configured set and is not running. Connects to it are refused immediately, and
// no other process can take the port while this object lives.
struct DownPeer {
    int fd = -1;
    std::uint16_t port = 0;
    DownPeer() {
        fd = ::socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        a.sin_port = 0;
        if (::bind(fd, reinterpret_cast<sockaddr*>(&a), sizeof a) != 0) { std::puts("bind"); std::exit(2); }
        socklen_t len = sizeof a;
        ::getsockname(fd, reinterpret_cast<sockaddr*>(&a), &len);
        port = ntohs(a.sin_port);
    }
    ~DownPeer() { if (fd >= 0) ::close(fd); }
};

// Form the mesh. Every host is asked to reach the WHOLE configured set — the set
// a real daemon gets from genesis, including validators that are not running —
// so a down validator is actually dialled and actually has to be routed around.
// Asking each host only for the peers that happen to be up would prove nothing:
// nobody would ever wait on the absent one. Returns each host's reached count.
std::vector<std::size_t> form_mesh(std::vector<std::unique_ptr<Node2Host>>& hosts,
                                   const std::map<std::uint32_t, PeerAddr>& configured,
                                   int deadline_ms = 3000) {
    std::vector<std::size_t> reached(hosts.size(), 0);
    std::vector<std::thread> setup;
    for (std::size_t s = 0; s < hosts.size(); ++s)
        setup.emplace_back([&, s] { reached[s] = hosts[s]->connect_mesh(configured, deadline_ms); });
    for (auto& t : setup) t.join();
    return reached;
}

// Drive poll(real)+pump on `drivers` until all `expectFinal` hosts finalize `pos`,
// or the deadline elapses. Wedged behavior is injected by the caller before this.
bool drive_until_final(std::vector<Node2Host*>& drivers,
                       std::vector<Node2Host*>& expectFinal,
                       const VotePosition& pos, int seconds) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(seconds);
    for (;;) {
        for (auto* h : drivers) { h->round(pos.block_id); h->pump(); }
        std::size_t still = 0;
        for (auto* h : expectFinal) if (!h->isFinal(pos.block_id)) ++still;
        if (still == 0) return true;
        if (std::chrono::steady_clock::now() >= deadline) return false;
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
}

}  // namespace

int main() {
    std::printf("================== node — LIVENESS over real TCP (route around faults) ==================\n");
    std::printf("a down or wedged-but-present validator never stalls the >2/3-stake quorum on the wire\n\n");

    for (std::uint32_t i = 0; i < kN; ++i) g_keys.push_back(make_key(std::uint8_t(0xA0 + i)));
    for (const auto& k : g_keys) g_set.push_back({k.pk, kStake});

    // ── [A] DOWN validator: 4 of 5 run, mesh among themselves, finalize on the wire ─
    {
        const std::vector<std::uint32_t> live = {0, 1, 2, 3};  // validator 4 is DOWN
        std::vector<std::unique_ptr<Node2Host>> hosts;
        std::map<std::uint32_t, PeerAddr> configured;
        for (std::uint32_t i : live) {
            hosts.push_back(make_host(i));
            configured[i] = PeerAddr{"127.0.0.1", hosts.back()->listen_bind()};
        }
        // Validator 4 IS in the configured set and IS dialled — it just is not there.
        DownPeer down;
        configured[4] = PeerAddr{"127.0.0.1", down.port};

        const std::vector<std::size_t> reached = form_mesh(hosts, configured);
        bool reached_ok = true;
        for (std::size_t r : reached) reached_ok &= (r == live.size() - 1);
        check(reached_ok, "A: each live host reached the 3 running peers and routed around validator 4");
        for (auto& h : hosts) check(h->peer_count() == live.size() - 1, "A: each live host has 3 peers");

        const VotePosition pos = make_pos(0x42, 1);
        for (auto& h : hosts) h->submit(pos);
        std::vector<Node2Host*> drivers, expect;
        for (auto& h : hosts) { drivers.push_back(h.get()); expect.push_back(h.get()); }
        const bool fin = drive_until_final(drivers, expect, pos, /*seconds=*/5);
        check(fin, "A: all 4 live hosts finalized over the wire within the deadline");

        bool cert_ok = true;
        for (auto& h : hosts) {
            auto c = h->cert(pos.block_id);
            cert_ok &= (c && h->verifyCert(*c) && c->voters.size() == 4 && c->voted_stake == 80);
        }
        check(cert_ok, "A: every live host holds a verifying 4-of-5 cert (80 stake, the down node routed around)");
        std::printf("[A] down validator (4/5 over real TCP): live quorum finalizes            => %s\n",
                    g_fail == 0 ? "PASS" : "FAIL");
    }

    // ── [B] WEDGED-but-PRESENT validator: votes a forged sibling; honest 4 finalize ─
    {
        const int b = g_fail;
        const std::vector<std::uint32_t> all = {0, 1, 2, 3, 4};  // validator 4 present but wedged
        std::vector<std::unique_ptr<Node2Host>> hosts;
        std::map<std::uint32_t, PeerAddr> configured;
        for (std::uint32_t i : all) {
            hosts.push_back(make_host(i));
            configured[i] = PeerAddr{"127.0.0.1", hosts.back()->listen_bind()};
        }
        const std::vector<std::size_t> reached = form_mesh(hosts, configured);
        bool full = true;
        for (std::size_t r : reached) full &= (r == all.size() - 1);
        check(full, "B: full 5-node mesh up (wedged validator present)");

        const VotePosition real   = make_pos(0x42, 2);
        const VotePosition forged = make_pos(0x99, 2);  // conflicting sibling: same height
        // Every host is aware of both proposals; honest 0..3 will only vote real,
        // the wedged host 4 will only vote forged.
        for (auto& h : hosts) { h->submit(real); h->submit(forged); }

        // Wedged host 4 commits + broadcasts its forged vote over the wire first.
        for (int r = 0; r < 4; ++r) { hosts[4]->round(forged.block_id); hosts[4]->pump(); }

        std::vector<Node2Host*> honest;        // drivers + expected-final for `real`
        for (std::uint32_t i = 0; i < 4; ++i) honest.push_back(hosts[i].get());
        // Pump the wedged host throughout so its forged frame is delivered (present/gossiping),
        // but it never drives `real`.
        std::vector<Node2Host*> drivers = honest; drivers.push_back(hosts[4].get());
        const bool fin = drive_until_final(drivers, honest, real, /*seconds=*/5);
        check(fin, "B: the 4 honest hosts finalize the REAL block over the wire");

        bool real_ok = true, forged_dead = true;
        for (std::uint32_t i = 0; i < 4; ++i) {
            auto c = hosts[i]->cert(real.block_id);
            real_ok &= (c && hosts[i]->verifyCert(*c) && c->voted_stake == 80 && c->voters.size() == 4);
            forged_dead &= !hosts[i]->isFinal(forged.block_id);  // forged never reaches quorum
        }
        check(real_ok, "B: honest cert carries exactly the 4 real voters (80 stake)");
        check(forged_dead, "B: the wedged node's forged block finalizes NOWHERE (1 vote, 20 stake)");
        std::printf("[B] wedged-but-present (forged vote on the wire): honest quorum routes around => %s\n",
                    g_fail == b ? "PASS" : "FAIL");
    }

    std::printf("----------------------------------------------------------------------------------------\n");
    if (g_fail) { std::printf("==== node LIVENESS: FAIL (%d) ====\n", g_fail); return 1; }
    std::printf("==== node LIVENESS: PASS — down + wedged validators routed around over real TCP ====\n");
    return 0;
}
