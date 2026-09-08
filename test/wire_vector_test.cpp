// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// wire_vector_test.cpp — the bytes node puts on the wire, written down by hand
// from the SPEC and compared against what the real send path actually emits.
//
// A round-trip test proves the encoder agrees with itself. Swap two same-width
// fields, or move the length to little-endian on both sides, and it still passes
// while every Go peer reads a different message. The Go reference pins its own
// formats this way (consensus engine/chain/cert_wire_vector_test.go); this is the
// same discipline for the two things node owns end to end:
//
//   the greeting's frame [4-byte BE length][that many bytes]  (LP-10602)
//   a vote frame         [4-byte BE length][1-byte msg_type][payload]
//                        payload = three ZAP length-framed fields:
//                          [4-byte BE 32][block_id  32]
//                          [4-byte BE 48][voter pk  48]
//                          [4-byte BE 96][signature 96]
//                        188 payload bytes, 193 on the wire, msg_type 0x11.
//
// Every byte below is a literal, and the bytes it is compared against come off a
// real socket written by the real transport — not from a re-encode. That layout
// is `github.com/luxfi/api/zap` verbatim (HeaderSize 5, big-endian length), which
// is what makes a C++ frame parse on a Go node.

#include "lux/node/mesh_vote_transport.hpp"
#include "lux/node/node_host.hpp"
#include "names.hpp"
#include "bls_signature.hpp"

#include <array>
#include <cstdint>
#include <cstdio>
#include <map>
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

int g_fail = 0;
void check(bool ok, const std::string& what) {
    if (!ok) { std::printf("    ASSERT FAILED: %s\n", what.c_str()); ++g_fail; }
}

std::string hex(const std::vector<std::uint8_t>& b, std::size_t upto) {
    static const char* d = "0123456789abcdef";
    std::string s;
    for (std::size_t i = 0; i < b.size() && i < upto; ++i) {
        s += d[b[i] >> 4];
        s += d[b[i] & 0xF];
    }
    return s;
}

void append(std::vector<std::uint8_t>& v, std::initializer_list<std::uint8_t> bytes) {
    v.insert(v.end(), bytes);
}
void repeat(std::vector<std::uint8_t>& v, std::uint8_t b, std::size_t n) {
    v.insert(v.end(), n, b);
}

// Read exactly n bytes, or as many as arrive before the socket goes quiet.
std::vector<std::uint8_t> read_n(int fd, std::size_t n) {
    std::vector<std::uint8_t> out;
    out.reserve(n);
    std::uint8_t tmp[512];
    while (out.size() < n) {
        const ssize_t r = ::recv(fd, tmp, std::min(sizeof tmp, n - out.size()), 0);
        if (r <= 0) break;
        out.insert(out.end(), tmp, tmp + r);
    }
    return out;
}

}  // namespace

int main() {
    std::printf("================ node — WIRE VECTOR (the bytes, from the spec) ================\n");
    std::printf("what a Go peer reads off this socket, pinned byte for byte\n\n");

    // ── the framing constants node depends on, as Go records them ────────────
    // github.com/luxfi/api/zap: header_size 5, max_message_size 16777216,
    // response_flag 0x80, error_flag 0x40, type_mask 0x3F. A service id must stay
    // under 0x40 or both ends read it as a flag and dispatch it somewhere else.
    {
        check(lux::zap::HeaderSize == 5, "ZAP header is 5 bytes (4 BE length + 1 type)");
        check(lux::zap::MaxMessageSize == 16u * 1024u * 1024u, "ZAP ceiling is 16 MiB");
        check(lux::zap::MsgResponseFlag == 0x80 && lux::zap::MsgErrorFlag == 0x40 &&
              lux::zap::MsgTypeMask == 0x3F, "the flag bits and the type mask are Go's");
        check(lux::consensus::zap::kVoteMsgType < 0x40,
              "the vote type fits the low six bits, so the flags OR in cleanly");
        check(kMaxVoteFrame <= lux::zap::MaxMessageSize,
              "the vote link's cap sits under the ZAP ceiling");
    }

    // ── the vote frame, as the real transport writes it ───────────────────────
    {
        int fds[2];
        if (::socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) { std::puts("socketpair"); return 2; }

        MeshVoteTransport tx([](const SignedVote&) {});
        tx.add_peer(fds[0]);

        SignedVote v;
        v.block_id.fill(0x11);
        v.voter.fill(0x22);
        v.sig.fill(0x33);
        tx.broadcast(v);

        // The golden frame, assembled from literal bytes.
        std::vector<std::uint8_t> want;
        append(want, {0x00, 0x00, 0x00, 0xBC});  // length 188, big-endian
        append(want, {0x11});                    // msg_type = kVoteMsgType
        append(want, {0x00, 0x00, 0x00, 0x20});  // field length 32
        repeat(want, 0x11, 32);                  // block_id
        append(want, {0x00, 0x00, 0x00, 0x30});  // field length 48
        repeat(want, 0x22, 48);                  // voter public key (compressed G1)
        append(want, {0x00, 0x00, 0x00, 0x60});  // field length 96
        repeat(want, 0x33, 96);                  // signature (compressed G2)
        check(want.size() == 193, "the documented frame is 193 bytes on the wire");

        const std::vector<std::uint8_t> got = read_n(fds[1], want.size());
        check(got == want, "the frame the transport wrote matches the documented layout");
        if (got != want) std::printf("     got %s\n    want %s\n", hex(got, 24).c_str(), hex(want, 24).c_str());
        check(got.size() == 193, "and is exactly 193 bytes, no padding, no trailer");
        std::printf("  frame: len=0x000000BC type=0x11 payload=188 total=%zu\n  %s...\n",
                    got.size(), hex(got, 20).c_str());
        ::close(fds[1]);
    }

    // ── the peer handshake, as the real host dials it ─────────────────────────
    {
        // Stand in for validator 7's listener; a host at index 5 dials it.
        const int srv = ::socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        a.sin_port = 0;
        ::bind(srv, reinterpret_cast<sockaddr*>(&a), sizeof a);
        ::listen(srv, 4);
        socklen_t len = sizeof a;
        ::getsockname(srv, reinterpret_cast<sockaddr*>(&a), &len);
        const std::uint16_t port = ntohs(a.sin_port);

        std::array<std::uint8_t, 32> sk{};
        PubKey pk{};
        std::array<std::uint8_t, 32> seed{};
        seed[0] = 0x5A;
        cevm::crypto::bls::keygen(seed.data(), sk.data());
        cevm::crypto::bls::sk_to_pk(sk.data(), pk.data());

        HostConfig cfg;
        cfg.index      = 5;
        cfg.port       = 0;
        cfg.sk         = sk;
        cfg.pk         = pk;
        cfg.validators = {{pk, 20}};
        cfg.wave       = WaveConfig{1, 1, 1};
        const test::Names names(1);
        cfg.link       = names.link(0);
        Node2Host host(std::move(cfg));
        host.listen_bind();

        std::thread dial([&] {
            std::map<std::uint32_t, PeerAddr> peers{{7, {"127.0.0.1", port}}};
            host.connect_mesh(peers, 2000);
        });

        // The dialer no longer announces an index. It greets: a 4-byte
        // big-endian length and that many bytes, and the bytes are a signed
        // INIT (LP-10602 — pq_vector_test holds their contents to a handshake
        // Go produced). What is pinned HERE is the framing: the length is big
        // endian, it counts the body and nothing else, and there is no tag byte
        // in front of it — the one difference from the vote frame below.
        const int conn = ::accept(srv, nullptr, nullptr);
        const std::vector<std::uint8_t> head = read_n(conn, 4);
        const std::uint32_t announced =
            (std::uint32_t(head[0]) << 24) | (std::uint32_t(head[1]) << 16) |
            (std::uint32_t(head[2]) << 8) | std::uint32_t(head[3]);
        const std::vector<std::uint8_t> body = read_n(conn, announced);
        check(body.size() == announced, "the greeting's length counts the body, big-endian");
        // 1 + 1 + 32 + 1 + 20 + (4+1952) + (4+1184) + (4+3309) = 6512.
        check(announced == 6512, "and an ML-KEM-768 INIT under ML-DSA-65 is 6512 bytes of it");
        check(body[0] == 0x01 && body[1] == 0x01,
              "which begins with the version and the profile, not a message tag");
        std::printf("  greeting:  %s... %u bytes\n", hex(head, 4).c_str(), announced);

        dial.join();
        ::close(conn);
        ::close(srv);
    }

    std::printf("--------------------------------------------------------------------------------\n");
    if (g_fail) { std::printf("==== node WIRE VECTOR: FAIL (%d) ====\n", g_fail); return 1; }
    std::printf("==== node WIRE VECTOR: PASS — the wire is what the spec says it is ====\n");
    return 0;
}
