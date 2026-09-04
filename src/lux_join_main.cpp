// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// lux_join_main.cpp — `lux-join`: this node as a validator on a REAL luxd
// network. Dials luxd's staking port, completes the PQ-gated TLS 1.3
// handshake and the p2p Handshake/PeerList exchange, then answers PushQuery
// with a signed Quasar vote — the C++ mirror of lux-rs/node's `bin/lux-join.rs`,
// which already reached co-certification against a live luxd. See LLM.md.
//
//   lux-join <staking-host:port> <network-id> <chain-id-hex32> <tip-hex32>
//
// Environment:
//   LUX_STAKER_DIR       where this validator's keys live   (default .lux-staker)
//   LUX_ADVERTISE_PORT   the port this validator claims       (default 19999)
//   LUX_SET_ROOT         validator_set_root, hex32 — REQUIRED for now: the
//                        live HTTP fetch from /v1/chain/P/ops/validators/at
//                        is not wired into this binary yet (see LLM.md); this
//                        mirrors node.rs's own override escape hatch,
//                        promoted to the only path here rather than a silent
//                        zero default that would sign a message luxd rejects
//                        for a different, harder-to-diagnose reason.

#include "lux/node/peer.hpp"
#include "lux/node/staking.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <csignal>
#include <cstring>
#include <string>
#include <thread>

namespace {

std::atomic<bool> g_stop{false};
void on_signal(int) { g_stop.store(true, std::memory_order_relaxed); }

std::string hex(std::span<const std::uint8_t> b) {
    static constexpr char d[] = "0123456789abcdef";
    std::string out;
    out.reserve(b.size() * 2);
    for (auto c : b) { out.push_back(d[c >> 4]); out.push_back(d[c & 0xf]); }
    return out;
}

bool parse_hex32(std::string s, std::array<std::uint8_t, 32>& out) {
    if (s.size() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s = s.substr(2);
    if (s.size() != 64) return false;
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (std::size_t i = 0; i < 32; ++i) {
        const int hi = nib(s[2 * i]), lo = nib(s[2 * i + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = std::uint8_t((hi << 4) | lo);
    }
    return true;
}

bool split_host_port(const std::string& addr, std::string& host, std::uint16_t& port) {
    const auto pos = addr.rfind(':');
    if (pos == std::string::npos) return false;
    host = addr.substr(0, pos);
    port = std::uint16_t(std::strtoul(addr.substr(pos + 1).c_str(), nullptr, 10));
    return port != 0;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc != 5) {
        std::fprintf(stderr,
                     "lux-join — a Lux validator on a luxd network\n\n"
                     "  lux-join <staking-host:port> <network-id> <chain-id-hex32> <tip-hex32>\n\n"
                     "Environment:\n"
                     "  LUX_STAKER_DIR       where this validator's keys live (default .lux-staker)\n"
                     "  LUX_ADVERTISE_PORT   the port this validator claims   (default 19999)\n"
                     "  LUX_SET_ROOT         validator_set_root, hex32 (required)\n");
        return 2;
    }

    std::string host;
    std::uint16_t staking_port = 0;
    if (!split_host_port(argv[1], host, staking_port)) {
        std::fprintf(stderr, "lux-join: bad staking address %s\n", argv[1]);
        return 2;
    }
    const std::uint32_t network_id = std::uint32_t(std::strtoul(argv[2], nullptr, 10));

    std::array<std::uint8_t, 32> chain_id{}, tip{};
    if (!parse_hex32(argv[3], chain_id)) { std::fprintf(stderr, "lux-join: bad chain-id hex\n"); return 2; }
    if (!parse_hex32(argv[4], tip)) { std::fprintf(stderr, "lux-join: bad tip hex\n"); return 2; }

    const char* staker_dir_env = std::getenv("LUX_STAKER_DIR");
    const std::filesystem::path staker_dir = staker_dir_env ? staker_dir_env : ".lux-staker";
    const char* advertise_env = std::getenv("LUX_ADVERTISE_PORT");
    const std::uint16_t advertise_port =
        advertise_env ? std::uint16_t(std::strtoul(advertise_env, nullptr, 10)) : 19999;
    const char* set_root_env = std::getenv("LUX_SET_ROOT");
    std::array<std::uint8_t, 32> set_root{};
    if (!set_root_env || !parse_hex32(set_root_env, set_root)) {
        std::fprintf(stderr, "lux-join: LUX_SET_ROOT (hex32) is required\n");
        return 2;
    }

    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);

    auto id = lux::node::staking::Identity::open(staker_dir);
    std::printf("lux-join lux-join/v0.1.0 (C++)\n");
    std::printf("  identity      %s\n", id.node_id_string().c_str());
    std::printf("  bls pubkey    0x%s\n", hex(std::span<const std::uint8_t>(id.bls_pk().data(), 48)).c_str());
    std::printf("  network       %u\n", network_id);
    std::printf("  chain id      0x%s\n", hex(std::span<const std::uint8_t>(chain_id.data(), 32)).c_str());
    std::printf("  staking addr  %s:%u\n", host.c_str(), staking_port);
    std::printf("  advertise     %u\n", advertise_port);
    std::fflush(stdout);

    std::chrono::milliseconds backoff{500};
    constexpr std::chrono::milliseconds kBackoffCeiling{15000};

    while (!g_stop.load(std::memory_order_relaxed)) {
        try {
            std::printf("lux-join: dialing %s:%u ...\n", host.c_str(), staking_port);
            std::fflush(stdout);
            auto peer = lux::node::peer::Peer::connect(host, staking_port, id, network_id, advertise_port,
                                                        std::chrono::milliseconds(5000));
            std::printf("lux-join: TLS 1.3 (X25519MLKEM768) session established\n");
            std::fflush(stdout);

            peer.join(std::chrono::milliseconds(15000));
            std::printf("lux-join: HANDSHAKE ACCEPTED — %s is a peer of luxd at %s:%u\n",
                       id.node_id_string().c_str(), host.c_str(), staking_port);
            std::fflush(stdout);

            lux::node::peer::Ballot ballot;
            std::copy(chain_id.begin(), chain_id.end(), ballot.chain_id.begin());
            std::copy(set_root.begin(), set_root.end(), ballot.validator_set_root.begin());
            lux::node::peer::Frontier initial;
            std::copy(tip.begin(), tip.end(), initial.outer_id.begin());
            initial.height = 0;
            peer.track(ballot, initial);

            backoff = std::chrono::milliseconds(500);  // a successful join resets the backoff
            while (!g_stop.load(std::memory_order_relaxed)) {
                try {
                    peer.step(std::chrono::milliseconds(30000));
                } catch (const lux::node::peer_tls::Quiet&) {
                    continue;  // luxd pings ~22s; silence between frames is normal
                }
            }
        } catch (const std::exception& e) {
            if (g_stop.load(std::memory_order_relaxed)) break;
            std::fprintf(stderr, "lux-join: link error: %s — redialing in %lldms\n", e.what(),
                        static_cast<long long>(backoff.count()));
            std::fflush(stderr);
            std::this_thread::sleep_for(backoff);
            backoff = std::min(backoff * 2, kBackoffCeiling);
        }
    }
    std::printf("lux-join: SIGTERM/SIGINT — shutting down\n");
    return 0;
}
