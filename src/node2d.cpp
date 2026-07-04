// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// node2d — a standalone consensus2 node process. Booted N times (one OS process
// each) on distinct loopback ports, the processes form a real TCP mesh and each
// independently finalizes one proposed block, proving the host works across true
// process boundaries (not just threads in one test binary). scripts/cluster_5.sh
// launches five and checks every one prints FINAL.
//
//   node2d --index I --n N --base-port P [--alpha A] [--stake S] [--deadline-ms D]
//
// Node j listens on 127.0.0.1:(P+j). The validator set is derived deterministically
// from the index scheme below, so every process agrees on the same set; in
// production the set comes from genesis and keys from KMS (out of scope here).

#include "lux/node2/node2_host.hpp"
#include "bls_signature.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

using namespace lux::node2;
using namespace lux::consensus2;

namespace {

struct Key {
    std::array<std::uint8_t, 32> sk{};
    PubKey pk{};
};

Key make_key(std::uint8_t tag) {
    std::array<std::uint8_t, 32> seed{};
    seed[0] = tag;
    for (int i = 1; i < 32; ++i) seed[i] = std::uint8_t(0xA5 ^ (tag + i));
    Key k;
    if (cevm::crypto::bls::keygen(seed.data(), k.sk.data()) != 0) { std::puts("keygen failed"); std::exit(2); }
    if (cevm::crypto::bls::sk_to_pk(k.sk.data(), k.pk.data()) != 0) { std::puts("sk_to_pk failed"); std::exit(2); }
    return k;
}

long arg(int argc, char** argv, const char* flag, long dflt) {
    for (int i = 1; i + 1 < argc; ++i)
        if (std::strcmp(argv[i], flag) == 0) return std::strtol(argv[i + 1], nullptr, 10);
    return dflt;
}

}  // namespace

int main(int argc, char** argv) {
    const long index     = arg(argc, argv, "--index", -1);
    const long n         = arg(argc, argv, "--n", -1);
    const long base_port = arg(argc, argv, "--base-port", -1);
    if (index < 0 || n <= 0 || base_port <= 0 || index >= n) {
        std::fprintf(stderr, "usage: node2d --index I --n N --base-port P "
                             "[--alpha A] [--stake S] [--deadline-ms D]\n");
        return 2;
    }
    const long stake       = arg(argc, argv, "--stake", 20);
    const long alpha       = arg(argc, argv, "--alpha", (2 * n) / 3 + 1);  // >2/3 count default
    const long deadline_ms = arg(argc, argv, "--deadline-ms", 15000);

    // Deterministic validator set shared by every process; this node's own key.
    std::vector<Key> keys;
    for (long i = 0; i < n; ++i) keys.push_back(make_key(std::uint8_t(0x80 + i)));
    std::vector<Validator> set;
    for (const auto& k : keys) set.push_back({k.pk, std::uint64_t(stake)});

    HostConfig cfg;
    cfg.index      = std::uint32_t(index);
    cfg.port       = std::uint16_t(base_port + index);
    cfg.sk         = keys[index].sk;
    cfg.pk         = keys[index].pk;
    cfg.validators = set;
    cfg.alpha      = std::uint32_t(alpha);
    cfg.wave       = WaveConfig{5, 0.8, 4};

    Node2Host host(std::move(cfg));
    const std::uint16_t port = host.listen_bind();
    std::printf("node %ld: listening 127.0.0.1:%u, forming %ld-node mesh...\n", index, port, n - 1);
    std::fflush(stdout);

    std::map<std::uint32_t, PeerAddr> peers;
    for (long j = 0; j < n; ++j)
        if (j != index) peers[std::uint32_t(j)] = PeerAddr{"127.0.0.1", std::uint16_t(base_port + j)};

    if (!host.connect_mesh(peers, int(deadline_ms))) {
        std::printf("node %ld: MESH FAILED (peers=%zu/%ld)\n", index, host.peer_count(), n - 1);
        return 1;
    }
    std::printf("node %ld: mesh up (%zu peers)\n", index, host.peer_count());
    std::fflush(stdout);

    VotePosition pos{};
    pos.block_id.fill(0x42);
    pos.height = 1;

    host.submit(pos);

    // Drive the wave to its β-confirmed decision: WaveConfig.beta consecutive
    // α-supermajority rounds are required before the node signs (consensus2 red
    // C1 — a node never votes on a single transient round). poll() is idempotent
    // once the slot is committed, so calling it every loop iteration both reaches
    // β and is a no-op afterwards. The earlier single poll() left wave at
    // confidence 1 with beta=4 ⇒ the node never voted ⇒ the cluster never
    // finalized (caught only by scripts/cluster_5.sh, not the in-binary test).
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(deadline_ms);
    while (!host.isFinal(pos.block_id)) {
        host.poll(pos, /*yes=*/5, /*total=*/5);  // β-confirmation rounds → sign+broadcast once decided
        host.pump();                             // drain peers' votes into the gate
        if (std::chrono::steady_clock::now() >= deadline) {
            std::printf("node %ld: NOT FINAL before deadline\n", index);
            return 1;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }

    auto c = host.cert(pos.block_id);
    const bool cert_ok = c.has_value() && host.verifyCert(*c);
    std::printf("node %ld: FINAL  voters=%zu  stake=%llu  cert=%s\n",
                index,
                c ? c->voters.size() : 0,
                static_cast<unsigned long long>(c ? c->voted_stake : 0),
                cert_ok ? "VERIFIED" : "INVALID");
    return cert_ok ? 0 : 1;
}
