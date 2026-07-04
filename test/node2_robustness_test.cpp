// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// node2_robustness_test.cpp — the mesh at its OWN fault boundary. node2 claims to
// "route around faults"; these three tests exercise the failure modes that claim
// implies but the happy-path cluster/liveness tests never trigger:
//
//   [1] SIGPIPE — a peer that has closed its read end must not KILL this process
//       when we next write to it. (Default SIGPIPE disposition terminates.)
//   [2] oversize frame — a peer that sends a bogus >MaxMessageSize length header
//       and keeps streaming must not grow our reassembly buffer without bound
//       (the MaxMessageSize guard is defeated if drain keeps appending after the
//       error latches). The peer is dropped instead.
//   [3] accept deadline — a lower-index peer that never dials must not hang this
//       node's accept() forever; connect_mesh fails gracefully within the deadline.

#include "lux/node2/frame_reader.hpp"
#include "lux/node2/mesh_vote_transport.hpp"
#include "lux/node2/node2_host.hpp"
#include "bls_signature.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <map>
#include <string>
#include <vector>

#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

using namespace lux::node2;
using namespace lux::consensus2;

namespace {
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
}  // namespace

int main() {
    std::printf("========================= node2 — robustness at the fault boundary =========================\n");

    // ── [1] broadcasting to a peer whose read end is closed must not kill us ────
    {
        int sp[2];
        if (::socketpair(AF_UNIX, SOCK_STREAM, 0, sp) != 0) { std::puts("socketpair"); return 2; }
        MeshVoteTransport mesh([](const SignedVote&) {});
        mesh.add_peer(sp[0]);   // transport owns sp[0]; arms SIGPIPE suppression
        ::close(sp[1]);         // the peer disappears — its read end is gone

        SignedVote v{};         // zero-filled is fine: encode never inspects contents
        mesh.broadcast(v);      // writes to a broken pipe → EPIPE, NOT a process kill
        mesh.broadcast(v);      // still alive: a second write also survives
        check(true, "broadcast to a closed peer did not raise SIGPIPE (process survived)");
    }

    // ── [2] an oversize length header must not let a peer grow our buffer ───────
    {
        int sp[2];
        if (::socketpair(AF_UNIX, SOCK_STREAM, 0, sp) != 0) { std::puts("socketpair"); return 2; }
        FrameReader r;

        const std::uint32_t huge = lux::zap::MaxMessageSize + 1;
        const std::uint8_t hdr[5] = {std::uint8_t(huge >> 24), std::uint8_t(huge >> 16),
                                     std::uint8_t(huge >> 8), std::uint8_t(huge), 0x11};
        check(::write(sp[1], hdr, sizeof hdr) == (ssize_t)sizeof hdr, "wrote oversize header");
        check(r.drain_fd(sp[0]) == Drain::Data, "first drain reads the header bytes");
        check(!r.next().has_value() && r.error(), "oversize header latches error(), yields nothing");
        const std::size_t buffered_after_latch = r.buffered();

        // The attacker keeps streaming. A pre-fix drain would recv these bytes into
        // buf_ (unbounded growth); the fix reports Closed and reads nothing further.
        // Send non-blocking so the writer never stalls on a full socketpair buffer
        // (the receiver deliberately never drains after the latch).
        ::fcntl(sp[1], F_SETFL, O_NONBLOCK);
        std::vector<std::uint8_t> flood(4096, 0xEE);
        (void)!::write(sp[1], flood.data(), flood.size());
        check(r.drain_fd(sp[0]) == Drain::Closed, "drain after latch reports Closed, does not read");
        check(r.buffered() == buffered_after_latch, "buffer did NOT grow past the latched header");

        ::close(sp[0]); ::close(sp[1]);
    }

    // ── [3] a lower-index peer that never dials must not hang accept() ──────────
    {
        // This host is index 1, so it must ACCEPT from index 0. Nobody dials it, so
        // a bare blocking accept() would hang forever; connect_mesh must instead
        // fail within the deadline.
        const Key k0 = make_key(0x90), k1 = make_key(0x91);
        std::vector<Validator> set{{k0.pk, 50}, {k1.pk, 50}};

        HostConfig cfg;
        cfg.index = 1; cfg.port = 0; cfg.sk = k1.sk; cfg.pk = k1.pk;
        cfg.validators = set; cfg.alpha = 2; cfg.wave = WaveConfig{5, 0.8, 4};
        Node2Host host(std::move(cfg));
        host.listen_bind();

        std::map<std::uint32_t, PeerAddr> peers;
        peers[0] = PeerAddr{"127.0.0.1", 1};  // index 0: a port nobody serves; it never dials us

        const int deadline_ms = 300;
        const auto t0 = std::chrono::steady_clock::now();
        const bool ok = host.connect_mesh(peers, deadline_ms);
        const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                                 std::chrono::steady_clock::now() - t0).count();

        check(!ok, "connect_mesh fails (the missing dialer never arrives)");
        check(elapsed < deadline_ms + 2000, "accept() returned within the deadline (no hang), took "
                                             + std::to_string(elapsed) + "ms");
    }

    std::printf("-------------------------------------------------------------------------------------------\n");
    if (g_fail) { std::printf("==== node2 robustness: FAIL (%d) ====\n", g_fail); return 1; }
    std::printf("==== node2 robustness: PASS — survives closed peers, bounds bad frames, deadlines accept ====\n");
    return 0;
}
