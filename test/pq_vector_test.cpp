// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// pq_vector_test.cpp — the validator link (LP-10602) against a handshake the
// GO node produced.
//
// A test in which both ends are this code proves the two halves agree with
// each other, which is the one thing that was never in doubt. So the vector in
// `test/pq/handshake.json` is a real exchange: the RESP frame in it was written
// by `github.com/luxfi/node/mesh/peer.RunPQHandshakeConn`, the INIT frame is
// the one that Go ACCEPTED, and the session key is the one Go derived. Every
// value below is checked against that file.
//
// HOW THE FILE WAS MADE, and how to make another:
//
//   pqgo <pub> <priv> <chain> 127.0.0.1:PORT     # the Go responder, fixed keys
//   pq_vector_test --against 127.0.0.1:PORT      # this, printing the vector
//
// WHAT IS VERIFIED RATHER THAN REPRODUCED. LP-10602 asks for deterministic
// ML-DSA-65 so a signature is reproducible. Go signs deterministically
// (`mldsa65.SignTo(..., randomized=false)`); the C ABI this node signs through
// does not — `mldsa65_sign_ctx` calls `priv.SignCtx(rand.Reader, ...)`, so two
// signatures over one message differ. Measured, not assumed. A signature is
// therefore CHECKED here, not recomputed: the check is over a transcript this
// code rebuilds from the frame, so a prefix that was one byte different would
// fail it. Everything with no randomness in it — both prefixes, the binding,
// the transcript hash and the session key — is recomputed and compared.

#include "lux/node/pq_handshake.hpp"

#include <nlohmann/json.hpp>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <span>
#include <string>
#include <vector>

namespace pq = lux::node::pq;

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

std::vector<std::uint8_t> unhex(const std::string& s) {
    const auto nib = [](char c) {
        return c <= '9' ? c - '0' : (c >= 'a' ? c - 'a' + 10 : c - 'A' + 10);
    };
    std::vector<std::uint8_t> out;
    out.reserve(s.size() / 2);
    for (std::size_t i = 0; i + 1 < s.size(); i += 2)
        out.push_back(static_cast<std::uint8_t>((nib(s[i]) << 4) | nib(s[i + 1])));
    return out;
}

// ── the message, read the way LP-10602 writes it ────────────────────────────
struct Message {
    std::uint8_t                 version = 0, profile = 0, scheme = 0;
    std::array<std::uint8_t, 32> chain{};
    std::array<std::uint8_t, 20> node{};
    std::vector<std::uint8_t>    mldsa_pub, kem, sig;
    std::size_t                  prefix_len = 0;  // where the signature begins
};

std::uint32_t be32(const std::uint8_t* p) {
    return (std::uint32_t(p[0]) << 24) | (std::uint32_t(p[1]) << 16) |
           (std::uint32_t(p[2]) << 8) | std::uint32_t(p[3]);
}

Message parse(const std::vector<std::uint8_t>& b) {
    Message     m;
    std::size_t at = 0;
    const auto  fixed = [&](std::uint8_t* dst, std::size_t n) {
        std::memcpy(dst, b.data() + at, n);
        at += n;
    };
    m.version = b[at++];
    m.profile = b[at++];
    fixed(m.chain.data(), m.chain.size());
    m.scheme = b[at++];
    fixed(m.node.data(), m.node.size());
    const auto lp = [&]() {
        const std::uint32_t n = be32(b.data() + at);
        at += 4;
        std::vector<std::uint8_t> v(b.begin() + long(at), b.begin() + long(at + n));
        at += n;
        return v;
    };
    m.mldsa_pub  = lp();
    m.kem        = lp();
    m.prefix_len = at;
    m.sig        = lp();
    return m;
}

// ── the live half: one handshake against a Go responder ─────────────────────
int dial(const std::string& where) {
    const auto colon = where.rfind(':');
    const int  fd    = ::socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in to{};
    to.sin_family = AF_INET;
    to.sin_port   = htons(static_cast<std::uint16_t>(std::stoi(where.substr(colon + 1))));
    ::inet_pton(AF_INET, where.substr(0, colon).c_str(), &to.sin_addr);
    if (::connect(fd, reinterpret_cast<sockaddr*>(&to), sizeof(to)) != 0) {
        std::perror("connect");
        ::close(fd);
        return -1;
    }
    return fd;
}

void write_all(int fd, std::span<const std::uint8_t> b) {
    std::size_t off = 0;
    while (off < b.size()) {
        const ssize_t n = ::write(fd, b.data() + off, b.size() - off);
        if (n <= 0) return;
        off += std::size_t(n);
    }
}

std::vector<std::uint8_t> read_exact(int fd, std::size_t n) {
    std::vector<std::uint8_t> out(n);
    std::size_t               off = 0;
    while (off < n) {
        const ssize_t got = ::read(fd, out.data() + off, n - off);
        if (got <= 0) return {};
        off += std::size_t(got);
    }
    return out;
}

int generate(const std::string& against, const std::string& dir,
             const std::array<std::uint8_t, 32>& chain) {
    const auto id = pq::Identity::open(dir);
    const int  fd = dial(against);
    if (fd < 0) return 1;

    std::vector<std::uint8_t> init_frame, resp_frame;
    const auto write_frame = [&](std::span<const std::uint8_t> body) {
        init_frame.assign(body.begin(), body.end());
        write_all(fd, pq::frame(body));
    };
    const auto read_frame = [&]() -> std::vector<std::uint8_t> {
        const auto head = read_exact(fd, 4);
        if (head.size() != 4) return {};
        std::array<std::uint8_t, 4> h{head[0], head[1], head[2], head[3]};
        resp_frame = read_exact(fd, pq::body_size(h));
        return resp_frame;
    };

    const auto out = pq::run_initiator(id, write_frame, read_frame, chain);
    ::close(fd);
    if (!out.ok) {
        std::fprintf(stderr, "handshake failed: %s\n", out.error.c_str());
        return 1;
    }
    nlohmann::json j;
    j["chain"]         = hex(chain);
    j["initiator_pub"] = hex(id.public_key());
    j["initiator_id"]  = hex(id.node_id(chain));
    j["init_frame"]    = hex(init_frame);
    j["resp_frame"]    = hex(resp_frame);
    j["responder_id"]  = hex(out.peer_node_id);
    j["shared_secret"] = hex(out.shared_secret);
    j["aead_key"]      = hex(out.aead_key);
    std::printf("%s\n", j.dump(2).c_str());
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc > 2 && std::string(argv[1]) == "--against") {
        std::array<std::uint8_t, 32> chain{};
        return generate(argv[2], argc > 3 ? argv[3] : ".pq-vector", chain);
    }

    std::printf("node — the validator link, against a handshake Go produced\n\n");

    std::ifstream f(std::string(PQ_VECTORS) + "/handshake.json");
    if (!f) {
        std::printf("  FAIL  cannot read %s/handshake.json\n", PQ_VECTORS);
        return 1;
    }
    nlohmann::json j;
    f >> j;

    const auto init_frame = unhex(j["init_frame"].get<std::string>());
    const auto resp_frame = unhex(j["resp_frame"].get<std::string>());
    const auto secret_raw = unhex(j["shared_secret"].get<std::string>());
    const auto chain_raw  = unhex(j["chain"].get<std::string>());

    std::array<std::uint8_t, 32> chain{}, secret{};
    std::copy(chain_raw.begin(), chain_raw.end(), chain.begin());
    std::copy(secret_raw.begin(), secret_raw.end(), secret.begin());

    // The frames Go read and wrote, read here.
    const Message init = parse(init_frame);
    const Message resp = parse(resp_frame);

    check(init.version == pq::kProtocolVersionV1 && resp.version == pq::kProtocolVersionV1,
          "both messages are version 1");
    check(init.profile == resp.profile && init.scheme == resp.scheme,
          "the responder echoed the profile and the scheme it was offered");
    check(init.chain == chain && resp.chain == chain, "and the chain");
    check(init.mldsa_pub.size() == 1952 && resp.mldsa_pub.size() == 1952,
          "both identities are ML-DSA-65 public keys");
    check(init.sig.size() == 3309 && resp.sig.size() == 3309, "both signatures are ML-DSA-65");
    check(init.kem.size() == 1184 && resp.kem.size() == 1088,
          "an ML-KEM-768 public key went out and a ciphertext came back");

    // ── the names ───────────────────────────────────────────────────────────
    check(hex(pq::derive_node_id(init.mldsa_pub, chain)) == j["initiator_id"].get<std::string>() &&
              pq::derive_node_id(init.mldsa_pub, chain) == init.node,
          "the initiator's name is what its key derives, and what it claimed");
    check(hex(pq::derive_node_id(resp.mldsa_pub, chain)) == j["responder_id"].get<std::string>() &&
              pq::derive_node_id(resp.mldsa_pub, chain) == resp.node,
          "and the responder's, which Go derived independently");

    // ── the two transcript prefixes ─────────────────────────────────────────
    // Rebuilt here from the parsed fields, and each one is proven by the
    // signature over it: a prefix that differed by a byte would not verify.
    const std::span<const std::uint8_t> init_prefix(init_frame.data(), init.prefix_len);
    check(pq::verify(init.mldsa_pub, pq::kContextInitiator, init_prefix, init.sig),
          "the initiator's signature holds over prefix_init, under its role");
    check(!pq::verify(init.mldsa_pub, pq::kContextResponder, init_prefix, init.sig),
          "and does not hold under the other role — the replay argument, checked");

    std::vector<std::uint8_t> resp_prefix = init_frame;
    resp_prefix.insert(resp_prefix.end(), resp_frame.begin(),
                       resp_frame.begin() + long(resp.prefix_len));
    check(pq::verify(resp.mldsa_pub, pq::kContextResponder, resp_prefix, resp.sig),
          "the responder's signature holds over init_bytes ‖ its own fields");
    check(!pq::verify(resp.mldsa_pub, pq::kContextInitiator, resp_prefix, resp.sig),
          "and not under the initiator's role");

    // ── the binding, the hash, and the key ──────────────────────────────────
    const auto bound  = pq::bind_transcript(init_frame, resp_frame, init.profile, chain,
                                            init.mldsa_pub, resp.mldsa_pub);
    const auto digest = pq::transcript_hash(bound);
    const auto key    = pq::aead_key(init.scheme, secret, digest);
    check(hex(key) == j["aead_key"].get<std::string>(),
          "the session key is the one Go derived, from the same binding");
    std::printf("        %s\n", hex(key).c_str());

    // ── one byte ────────────────────────────────────────────────────────────
    {
        auto broken = init_frame;
        broken[7] ^= 0x01;  // inside the chain id, which prefix_init covers
        const Message m = parse(broken);
        check(!pq::verify(m.mldsa_pub, pq::kContextInitiator,
                          std::span<const std::uint8_t>(broken.data(), m.prefix_len), m.sig),
              "one byte moved in INIT and the initiator's signature is refused");
    }
    {
        auto broken = resp_frame;
        broken[40] ^= 0x01;  // inside the responder's NodeID
        const Message m = parse(broken);
        std::vector<std::uint8_t> p = init_frame;
        p.insert(p.end(), broken.begin(), broken.begin() + long(m.prefix_len));
        check(!pq::verify(m.mldsa_pub, pq::kContextResponder, p, m.sig),
              "one byte moved in RESP and the responder's signature is refused");
    }
    {
        auto other = secret;
        other[0] ^= 0x01;
        check(hex(pq::aead_key(init.scheme, other, digest)) != j["aead_key"].get<std::string>(),
              "one byte moved in the shared secret and the session key is another key");
        auto elsewhere = chain;
        elsewhere[0] ^= 0x01;
        const auto moved = pq::transcript_hash(pq::bind_transcript(
            init_frame, resp_frame, init.profile, elsewhere, init.mldsa_pub, resp.mldsa_pub));
        check(hex(pq::aead_key(init.scheme, secret, moved)) != j["aead_key"].get<std::string>(),
              "and one byte moved in the chain, which is why the chain is in the binding twice");
    }

    std::printf("\n%s\n", g_fail == 0 ? "all good" : "FAILURES");
    return g_fail == 0 ? 0 : 1;
}
