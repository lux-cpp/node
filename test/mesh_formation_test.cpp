// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// mesh_formation_test.cpp — forming the mesh is bounded, and a missing validator
// is not a dead cluster.
//
// Two properties, both about what a node does when the set it was configured with
// is not the set that showed up:
//
//   BOUNDED. One deadline covers the whole phase. It used to cover dialing only:
//   accept() blocked forever waiting for a validator that was never started, and
//   a peer that connected and then said nothing held the acceptor for as long as
//   it liked. A node whose start-up can be held open by a stranger is a node an
//   unauthenticated peer can keep out of its own cluster.
//
//   PARTIAL. connect_mesh reports how many peers it reached and lets the caller
//   read that against the finality rule. Requiring every peer contradicted the
//   quorum rule the whole engine is built on: four validators holding 80 of 100
//   stake — comfortably over the ⅔ floor of 66 — all refused to start because the
//   fifth was down.

#include "lux/node2/node2_host.hpp"
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

using namespace lux::node2;
using namespace lux::consensus2;

namespace {

constexpr std::uint32_t kN     = 3;
constexpr std::uint64_t kStake = 20;
constexpr std::uint32_t kAlpha = 2;
constexpr int kDeadlineMs = 1500;

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

std::vector<Key> g_keys;
std::vector<Validator> g_set;

std::unique_ptr<Node2Host> make_host(std::uint32_t index) {
    HostConfig cfg;
    cfg.index      = index;
    cfg.port       = 0;
    cfg.sk         = g_keys[index].sk;
    cfg.pk         = g_keys[index].pk;
    cfg.validators = g_set;
    cfg.alpha      = kAlpha;
    cfg.wave       = WaveConfig{kN, 0.8, 4};
    return std::make_unique<Node2Host>(std::move(cfg));
}

// A loopback port that is BOUND but never listening: connects to it are refused
// immediately and deterministically, and no other process can take it while this
// object lives. That is a validator that is configured and not running.
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
        port = ntohs(a.sin_port);  // bound, not listening → ECONNREFUSED
    }
    ~DownPeer() { if (fd >= 0) ::close(fd); }
};

long elapsed_ms(std::chrono::steady_clock::time_point t0) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now() - t0).count();
}

}  // namespace

int main() {
    std::printf("============ node2 — mesh formation is bounded, and partial ============\n");
    std::printf("a validator that never starts costs a deadline, not the cluster\n\n");

    for (std::uint32_t i = 0; i < kN; ++i) g_keys.push_back(make_key(std::uint8_t(0xC0 + i)));
    for (const auto& k : g_keys) g_set.push_back({k.pk, kStake});

    // [A] the inbound half of the phase is bounded. Host 1 waits on an inbound
    //     connection from host 0, which never runs.
    {
        auto h = make_host(1);
        const std::uint16_t port = h->listen_bind();
        DownPeer absent;
        std::map<std::uint32_t, PeerAddr> peers{{0, {"127.0.0.1", absent.port}}};
        const auto t0 = std::chrono::steady_clock::now();
        const std::size_t reached = h->connect_mesh(peers, kDeadlineMs);
        const long took = elapsed_ms(t0);
        check(reached == 0, "[A] no peer reached (the only configured peer is down)");
        check(took < kDeadlineMs + 2 * kPeerIoTimeoutMs,
              "[A] accept returned by the deadline, not never (took " + std::to_string(took) + " ms)");
        std::printf("  [A] host 1 on :%u waited %ld ms for an absent host 0 (deadline %d ms)\n",
                    port, took, kDeadlineMs);
    }

    // [B] a stranger that connects and then says nothing does not hold the node.
    {
        auto h = make_host(1);
        const std::uint16_t port = h->listen_bind();
        DownPeer absent;

        // Connect to the host's listener and send no handshake, ever.
        const int mute = ::socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        a.sin_port = htons(port);
        check(::connect(mute, reinterpret_cast<sockaddr*>(&a), sizeof a) == 0,
              "[B] the mute stranger connected");

        std::map<std::uint32_t, PeerAddr> peers{{0, {"127.0.0.1", absent.port}}};
        const auto t0 = std::chrono::steady_clock::now();
        const std::size_t reached = h->connect_mesh(peers, kDeadlineMs);
        const long took = elapsed_ms(t0);
        ::close(mute);
        check(reached == 0, "[B] a connection with no handshake never becomes a peer");
        check(took < kDeadlineMs + 2 * kPeerIoTimeoutMs,
              "[B] the mute stranger did not hold the acceptor (took " + std::to_string(took) + " ms)");
        std::printf("  [B] a socket that connected and stayed silent cost %ld ms, then was dropped\n", took);
    }

    // [C] two of three validators run: each reaches the other and says so.
    {
        auto h0 = make_host(0);
        auto h2 = make_host(2);
        const std::uint16_t p0 = h0->listen_bind();
        const std::uint16_t p2 = h2->listen_bind();
        DownPeer absent;  // validator 1 is configured but not running

        std::map<std::uint32_t, PeerAddr> configured{
            {0, {"127.0.0.1", p0}},
            {1, {"127.0.0.1", absent.port}},
            {2, {"127.0.0.1", p2}},
        };

        std::size_t r0 = 0, r2 = 0;
        const auto t0 = std::chrono::steady_clock::now();
        {
            std::thread a([&] { r0 = h0->connect_mesh(configured, kDeadlineMs); });
            std::thread b([&] { r2 = h2->connect_mesh(configured, kDeadlineMs); });
            a.join();
            b.join();
        }
        const long took = elapsed_ms(t0);
        check(r0 == 1, "[C] host 0 reached exactly the one running peer");
        check(r2 == 1, "[C] host 2 reached exactly the one running peer");
        check(h0->peer_count() == 1 && h2->peer_count() == 1, "[C] both hold one peer");
        check(took < kDeadlineMs + 2 * kPeerIoTimeoutMs,
              "[C] the absent validator cost a deadline, not a hang (took " + std::to_string(took) + " ms)");
        std::printf("  [C] 2 of 3 up: host 0 reached %zu, host 2 reached %zu, in %ld ms\n", r0, r2, took);
    }

    // [E] a connection fills at most the slot it names. The handshake index is a
    //     claim, not a proof — node2 has no peer authentication — but checking it
    //     against the slots actually being waited on means one socket cannot take
    //     two, and a claim on a validator that is not expected is refused rather
    //     than counted. Without the check, two connections from a retrying dialer
    //     left the mesh believing it was complete while a validator was missing.
    {
        auto h = make_host(2);  // awaits inbound from validators 0 and 1
        const std::uint16_t port = h->listen_bind();
        DownPeer d0, d1;
        std::map<std::uint32_t, PeerAddr> peers{
            {0, {"127.0.0.1", d0.port}},
            {1, {"127.0.0.1", d1.port}},
        };

        std::size_t reached = 0;
        std::thread forming([&] { reached = h->connect_mesh(peers, kDeadlineMs); });

        // Claim validator 0 twice, and a validator that is not in the set at all.
        std::vector<int> conns;
        for (std::uint32_t claim : {0u, 0u, 9u}) {
            const int c = ::socket(AF_INET, SOCK_STREAM, 0);
            sockaddr_in a{};
            a.sin_family = AF_INET;
            a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            a.sin_port = htons(port);
            if (::connect(c, reinterpret_cast<sockaddr*>(&a), sizeof a) == 0) {
                const std::uint8_t hs[4] = {std::uint8_t(claim >> 24), std::uint8_t(claim >> 16),
                                            std::uint8_t(claim >> 8), std::uint8_t(claim)};
                (void)::send(c, hs, sizeof hs, 0);
                conns.push_back(c);
            } else {
                ::close(c);
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(60));
        }
        forming.join();
        for (int c : conns) ::close(c);

        check(reached == 1, "[E] three connections claiming {0, 0, 9} filled exactly one slot");
        std::printf("  [E] claims {0,0,9} against slots {0,1}: %zu peer(s) admitted\n", reached);
    }

    // [D] regression: a complete set still forms a complete mesh, fast.
    {
        std::vector<std::unique_ptr<Node2Host>> hosts;
        std::map<std::uint32_t, PeerAddr> configured;
        for (std::uint32_t i = 0; i < kN; ++i) {
            hosts.push_back(make_host(i));
            configured[i] = PeerAddr{"127.0.0.1", hosts.back()->listen_bind()};
        }
        std::vector<std::size_t> reached(kN, 0);
        const auto t0 = std::chrono::steady_clock::now();
        {
            std::vector<std::thread> ts;
            for (std::uint32_t i = 0; i < kN; ++i)
                ts.emplace_back([&, i] { reached[i] = hosts[i]->connect_mesh(configured, kDeadlineMs); });
            for (auto& t : ts) t.join();
        }
        const long took = elapsed_ms(t0);
        for (std::uint32_t i = 0; i < kN; ++i)
            check(reached[i] == kN - 1, "[D] host " + std::to_string(i) + " reached every peer");
        check(took < kDeadlineMs, "[D] a complete set forms without waiting out the deadline");
        std::printf("  [D] full %u-node mesh formed in %ld ms\n", kN, took);
    }

    std::printf("------------------------------------------------------------------------\n");
    if (g_fail) { std::printf("==== node2 MESH FORMATION: FAIL (%d) ====\n", g_fail); return 1; }
    std::printf("==== node2 MESH FORMATION: PASS — bounded, partial, and complete when it can be ====\n");
    return 0;
}
