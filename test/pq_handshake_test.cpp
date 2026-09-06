// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// pq_handshake_test.cpp — the strict-PQ peer handshake, in two halves that
// check different things, because either alone would pass while the wire was
// wrong.
//
// The first half is known-answer. Three derivations decide every byte the
// handshake commits to, and all three are pure functions with no key material
// in them, so the Go implementation can be asked directly for the answer. The
// hexadecimal below was PRINTED BY GO — `ids.NodeIDSchemeMLDSA65.DeriveMLDSA`,
// `kem.HashTranscript` and `KEMSession.DeriveAEADKey`, called on these exact
// inputs — and pasted here unaltered. Nothing in this repository can produce
// those strings, which is the point: a round trip between two C++ ends proves
// only that this port agrees with itself, and a port that agrees with itself
// about the wrong domain string, the wrong left_encode, or the wrong output
// length is precisely the failure that reaches production.
//
// The second half is a real socket. `run_initiator` is driven over an
// AF_UNIX stream pair against a responder written from `RespondHandshake`,
// through the same `pq::frame` / `pq::body_size` the peer path uses, so the
// framing, the FIPS 204 context strings, the signature transcript and the
// NodeID binding are all exercised on bytes that crossed a file descriptor.
// The two ends then compare the AEAD key they each derived. That comparison
// is the one that catches an asymmetric transcript: the responder builds the
// RESPONSE ALONE from its own fields, while the initiator recovers it from a
// parse, so a side that folds the whole INIT back into the binding derives a
// different key and the handshake that "succeeded" is caught here.

#include "lux/node/pq_handshake.hpp"

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

// The responder half of the C ABI. `mlkem768_encapsulate` is deliberately
// absent from the node library: nothing in this node responds to a PQ
// handshake, and declaring a primitive the production path never calls is how
// a stub becomes permanent.
extern "C" {
int mlkem768_encapsulate(char* pkData, int pkLen, char* ct, int* ctLen, char* ss, int* ssLen);
int mldsa65_keypair(char* pk, int* pkLen, char* sk, int* skLen);
int mldsa65_sign_ctx(char* skData, int skLen, char* msgData, int msgLen, char* ctxData, int ctxLen,
                     char* sig, int* sigLen);
int mldsa65_verify_ctx(char* pkData, int pkLen, char* msgData, int msgLen, char* ctxData, int ctxLen,
                       char* sigData, int sigLen);
int mldsa65_pk_size();
int mldsa65_sk_size();
int mldsa65_sig_size();
int mlkem768_ct_size();
}

namespace pq = lux::node::pq;

namespace {

int g_fail = 0;
void check(bool ok, const std::string& what) {
    std::printf("  %s %s\n", ok ? "ok  " : "FAIL", what.c_str());
    if (!ok) ++g_fail;
}

std::string hex(std::span<const std::uint8_t> b) {
    static const char* d = "0123456789abcdef";
    std::string s;
    s.reserve(b.size() * 2);
    for (auto c : b) { s += d[c >> 4]; s += d[c & 0xF]; }
    return s;
}


void put_u32_be(std::vector<std::uint8_t>& b, std::uint32_t v) {
    b.push_back(std::uint8_t(v >> 24));
    b.push_back(std::uint8_t(v >> 16));
    b.push_back(std::uint8_t(v >> 8));
    b.push_back(std::uint8_t(v));
}
void append_lp(std::vector<std::uint8_t>& b, std::span<const std::uint8_t> d) {
    put_u32_be(b, std::uint32_t(d.size()));
    b.insert(b.end(), d.begin(), d.end());
}

// ── the socket, blocking with a bound ───────────────────────────────────
// Both ends are blocking, and both carry a receive timeout, so a side that
// stops talking fails the test in five seconds instead of hanging the suite
// forever. A non-blocking pair would need this file to reimplement the
// reassembly `FrameReader` already owns, and would test that instead of the
// handshake.
//
// Writing to a socket whose peer has gone raises SIGPIPE, and the default
// disposition of SIGPIPE kills the process — a test that dies that way looks
// like a failure with no failing assertion in its output, which is worse than
// the bug it was meant to find. The two platforms disarm it in two places:
// BSD and Darwin take a socket option, Linux takes a send flag. Both are set
// below, and each is a no-op where the other applies.
#ifdef MSG_NOSIGNAL
inline constexpr int kSendFlags = MSG_NOSIGNAL;
#else
inline constexpr int kSendFlags = 0;
#endif

void no_sigpipe(int fd) {
#ifdef SO_NOSIGPIPE
    int on = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof on);
#else
    (void)fd;
#endif
}

void write_all(int fd, std::span<const std::uint8_t> data) {
    std::size_t off = 0;
    while (off < data.size()) {
        const ssize_t n = ::send(fd, data.data() + off, data.size() - off, kSendFlags);
        if (n <= 0) throw std::runtime_error("send failed");
        off += std::size_t(n);
    }
}

std::vector<std::uint8_t> read_exact(int fd, std::size_t want) {
    std::vector<std::uint8_t> out(want);
    std::size_t got = 0;
    while (got < want) {
        const ssize_t n = ::recv(fd, out.data() + got, want - got, 0);
        if (n <= 0) throw std::runtime_error("recv failed or peer hung up");
        got += std::size_t(n);
    }
    return out;
}

void write_frame(int fd, std::span<const std::uint8_t> body) { write_all(fd, pq::frame(body)); }

std::vector<std::uint8_t> read_frame(int fd) {
    const auto header = read_exact(fd, 4);
    return read_exact(fd, pq::body_size(std::span<const std::uint8_t, 4>(header.data(), 4)));
}

// ── the responder ───────────────────────────────────────────────────────
// `RespondHandshake` plus `RunPQHandshakeConn`'s ingress branch, transcribed:
// parse INIT, verify it under the initiator context, encapsulate, sign
// init.canonicalBytes() ++ its own fields under the responder context, and
// bind the transcript from the RESPONSE ALONE.

struct Responder {
    std::vector<std::uint8_t>    pk, sk;
    std::array<std::uint8_t, 32> aead{};
    bool                          init_signature_ok = false;

    // Knobs for the refusal cases. Each one changes exactly one byte of what
    // a correct responder would say.
    std::uint8_t                 profile = pq::kProfileStrictPQ;
    std::array<std::uint8_t, 32> chain{};
    bool                         lie_about_node_id = false;
    bool                         corrupt_signature = false;

    Responder() {
        pk.resize(std::size_t(mldsa65_pk_size()));
        sk.resize(std::size_t(mldsa65_sk_size()));
        int pkl = int(pk.size()), skl = int(sk.size());
        if (mldsa65_keypair(reinterpret_cast<char*>(pk.data()), &pkl,
                            reinterpret_cast<char*>(sk.data()), &skl) != 0)
            throw std::runtime_error("mldsa65_keypair failed");
        pk.resize(std::size_t(pkl));
        sk.resize(std::size_t(skl));
    }

    void serve(int fd) {
        const auto init = read_frame(fd);

        // Parse INIT. Positions are fixed by the field widths above the two
        // length-prefixed keys: 1 + 1 + 32 + 1 + 20.
        std::size_t at = 1 + 1 + 32 + 1 + 20;
        auto take = [&] {
            const std::uint32_t n = (std::uint32_t(init[at]) << 24) | (std::uint32_t(init[at + 1]) << 16) |
                                    (std::uint32_t(init[at + 2]) << 8) | std::uint32_t(init[at + 3]);
            at += 4;
            std::vector<std::uint8_t> v(init.begin() + std::ptrdiff_t(at),
                                        init.begin() + std::ptrdiff_t(at + n));
            at += n;
            return v;
        };
        const auto init_mldsa_pub = take();
        const auto init_kem_pub   = take();
        const std::size_t prefix_len = at;  // transcriptPrefix ends where Sig begins
        const auto init_sig = take();

        {
            static constexpr std::string_view kCtx = "NODE_PQ_HANDSHAKE_V1/initiator";
            init_signature_ok =
                mldsa65_verify_ctx(reinterpret_cast<char*>(const_cast<std::uint8_t*>(init_mldsa_pub.data())),
                                   int(init_mldsa_pub.size()),
                                   reinterpret_cast<char*>(const_cast<std::uint8_t*>(init.data())),
                                   int(prefix_len), const_cast<char*>(kCtx.data()), int(kCtx.size()),
                                   reinterpret_cast<char*>(const_cast<std::uint8_t*>(init_sig.data())),
                                   int(init_sig.size())) == 0;
        }

        // static_cast, not a functional cast: `vector<T> v(size_t(f()))`
        // declares a function. The production file carried three of these
        // for as long as nothing compiled it.
        std::vector<std::uint8_t>    ct(static_cast<std::size_t>(mlkem768_ct_size()));
        std::array<std::uint8_t, 32> shared{};
        {
            int ctl = int(ct.size()), ssl = int(shared.size());
            if (mlkem768_encapsulate(reinterpret_cast<char*>(const_cast<std::uint8_t*>(init_kem_pub.data())),
                                     int(init_kem_pub.size()), reinterpret_cast<char*>(ct.data()), &ctl,
                                     reinterpret_cast<char*>(shared.data()), &ssl) != 0)
                throw std::runtime_error("mlkem768_encapsulate failed");
            ct.resize(std::size_t(ctl));
        }

        auto node_id = pq::derive_node_id(pk);
        if (lie_about_node_id) node_id[0] ^= 0xFF;

        std::vector<std::uint8_t> fields;
        fields.push_back(pq::kProtocolVersionV1);
        fields.push_back(profile);
        fields.insert(fields.end(), chain.begin(), chain.end());
        fields.push_back(pq::kKEMSchemeMLKEM768);
        fields.insert(fields.end(), node_id.begin(), node_id.end());
        append_lp(fields, pk);
        append_lp(fields, ct);

        std::vector<std::uint8_t> signed_over = init;
        signed_over.insert(signed_over.end(), fields.begin(), fields.end());

        std::vector<std::uint8_t> sig(static_cast<std::size_t>(mldsa65_sig_size()));
        {
            static constexpr std::string_view kCtx = "NODE_PQ_HANDSHAKE_V1/responder";
            int sig_len = int(sig.size());
            if (mldsa65_sign_ctx(reinterpret_cast<char*>(sk.data()), int(sk.size()),
                                 reinterpret_cast<char*>(signed_over.data()), int(signed_over.size()),
                                 const_cast<char*>(kCtx.data()), int(kCtx.size()),
                                 reinterpret_cast<char*>(sig.data()), &sig_len) != 0)
                throw std::runtime_error("mldsa65_sign_ctx failed");
            sig.resize(std::size_t(sig_len));
        }
        if (corrupt_signature) sig[0] ^= 0x01;

        std::vector<std::uint8_t> resp = fields;
        append_lp(resp, sig);

        // The binding takes the RESPONSE, not the response prefixed by the
        // INIT it answers. Getting this wrong on one side and not the other
        // is what the key comparison below detects.
        aead = pq::aead_key(
            pq::kKEMSchemeMLKEM768, shared,
            pq::transcript_hash(pq::bind_transcript(init, resp, pq::kProfileStrictPQ,
                                                    std::array<std::uint8_t, 32>{}, init_mldsa_pub, pk)));

        write_frame(fd, resp);
    }
};

// A pair of connected stream sockets, each with a receive timeout.
struct Pair {
    int a = -1, b = -1;
    Pair() {
        int fds[2];
        if (::socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) throw std::runtime_error("socketpair failed");
        a = fds[0];
        b = fds[1];
        // Thirty seconds is not a latency budget — a handshake here costs
        // tens of milliseconds. It is only there so a side that stops talking
        // ends the test instead of wedging the suite, and it is set far above
        // anything a loaded machine can produce so that scheduling delay can
        // never be read as a protocol failure.
        timeval tv{30, 0};
        for (int fd : {a, b}) {
            ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
            no_sigpipe(fd);
        }
    }
    ~Pair() {
        if (a >= 0) ::close(a);
        if (b >= 0) ::close(b);
    }
};

// A thread that is joined however this scope ends. A `std::thread` still
// joinable when it is destroyed calls `std::terminate`, so a path that leaves
// one behind turns a readable assertion failure into a process that dies with
// no failing line in its output.
struct Join {
    std::thread t;
    ~Join() {
        if (t.joinable()) t.join();
    }
};

// One handshake against `r`, initiator on one end and `r.serve` on a thread
// at the other. A responder that throws closes its end, so the initiator sees
// end-of-stream at once rather than waiting out its receive timeout.
pq::Outcome exchange(const pq::Identity& id, Responder& r) {
    Pair p;
    Join responder{std::thread([&] {
        try {
            r.serve(p.b);
        } catch (...) {
            ::shutdown(p.b, SHUT_RDWR);
        }
    })};
    pq::Outcome out;
    try {
        out = pq::run_initiator(
            id, [&](std::span<const std::uint8_t> body) { write_frame(p.a, body); },
            [&] { return read_frame(p.a); });
    } catch (const std::exception& e) {
        out.ok    = false;
        out.error = e.what();
    }
    return out;
}

}  // namespace

int main() {
    std::printf("================================================================================\n");
    std::printf("node PQ HANDSHAKE — the strict-PQ peer handshake, against Go's own answers\n");
    std::printf("================================================================================\n");

    // ── 1. Known-answer: the NodeID derivation ──────────────────────────
    // ids.NodeIDSchemeMLDSA65.DeriveMLDSA(chainID, pubKey), first 20 bytes of
    // SHAKE256-384 over left_encode-framed "NODE_ID_V1", chain, scheme, key.
    std::printf("\nDeriveMLDSA (luxfi/ids), answers printed by Go:\n");
    {
        std::vector<std::uint8_t> pub(1952);
        for (std::size_t i = 0; i < pub.size(); ++i) pub[i] = std::uint8_t(i * 7 % 251);

        const auto id = pq::derive_node_id(pub);
        check(hex(id) == "94d642e344455e1edf479aece51d5c139c0e42a7",
              "a 1952-byte ML-DSA-65 key under ids.Empty derives Go's NodeID");

        // The chain id is a real field, not padding: the same key on another
        // chain is another validator, which is what stops a cross-chain
        // replay of a registration.
        std::array<std::uint8_t, 32> chain{};
        for (std::size_t i = 0; i < chain.size(); ++i) chain[i] = std::uint8_t(0xA0 + i);
        check(hex(pq::derive_node_id(pub, chain)) == "1c9b9987eb447b3eec1e261376f1f953a6f77d6e",
              "the same key under a non-zero chain id derives a different NodeID, Go's");

        // A three-byte key exercises a left_encode of a length that is not a
        // round number of bytes, where an off-by-one in the SP 800-185
        // framing would otherwise stay hidden.
        const std::vector<std::uint8_t> lux{'l', 'u', 'x'};
        check(hex(pq::derive_node_id(lux)) == "98c9bde92f13f06742421278e07bcdd85ece992f",
              "a 3-byte key derives Go's NodeID, so left_encode agrees on short lengths");
    }

    // ── 2. Known-answer: the transcript hash and the session key ────────
    std::printf("\nkem.HashTranscript and KEMSession.DeriveAEADKey, answers printed by Go:\n");
    {
        const std::string_view msg = "NODE_TRANSCRIPT vector 0123456789";
        const auto             th  = pq::transcript_hash(
            std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(msg.data()), msg.size()));
        check(hex(th) == "dc54f333215b2e5d6c07e9e7801e7596f49ca467165e7b0acaed560b67ea2346"
                         "9a96796197aba596bcae9335effc0545",
              "TupleHash256 over one element, customization NODE_TRANSCRIPT_V1, matches Go");

        check(hex(pq::transcript_hash({})) == "82738f39b7ee3bb80a5e7f04dcd169b0f3982e443dbd6fcdce9aa312"
                                              "694ab3dcb39a454c0cc8972097d838963d63024c",
              "the empty transcript hashes to Go's value, pinning the right_encode tail");

        std::array<std::uint8_t, 32> ss{};
        for (std::size_t i = 0; i < ss.size(); ++i) ss[i] = std::uint8_t(i);
        std::array<std::uint8_t, 48> th_fixed{};
        for (std::size_t i = 0; i < th_fixed.size(); ++i) th_fixed[i] = std::uint8_t(255 - i);

        check(hex(pq::aead_key(pq::kKEMSchemeMLKEM768, ss, th_fixed)) ==
                  "0c688297d061d730faec2b16982d5cad583197d783fbfc7fb2df9379e054cc81",
              "cSHAKE256(KEMDerive, NODE_AEAD_V1) over scheme+secret+transcript matches Go");

        // The scheme byte is inside the key derivation, so ML-KEM-1024 over
        // the identical secret and transcript is a different session key.
        check(hex(pq::aead_key(0x02, ss, th_fixed)) ==
                  "ab6365fd40f3c399d3ac73dd425ff80b4c887774435c65d196463e953eca91a9",
              "the scheme byte reaches the key: 0x02 gives Go's ML-KEM-1024 answer");
    }

    // ── 3. Framing ──────────────────────────────────────────────────────
    std::printf("\nFraming (network/peer/pq_frame.go), 4-byte big-endian, 16 KiB:\n");
    {
        const std::vector<std::uint8_t> body{0xDE, 0xAD, 0xBE, 0xEF};
        const auto                      f = pq::frame(body);
        check(f.size() == 8 && f[0] == 0 && f[1] == 0 && f[2] == 0 && f[3] == 4,
              "a frame is a 4-byte big-endian length and the payload, with no tag byte");
        check(pq::body_size(std::span<const std::uint8_t, 4>(f.data(), 4)) == 4,
              "the header reads back as the payload length");

        bool refused = false;
        try {
            const std::array<std::uint8_t, 4> over{0x00, 0x00, 0x40, 0x01};  // 16385
            (void)pq::body_size(over);
        } catch (const std::exception&) { refused = true; }
        check(refused, "one byte over the 16 KiB cap is refused before any buffer is allocated");

        const std::array<std::uint8_t, 4> at_cap{0x00, 0x00, 0x40, 0x00};  // 16384
        check(pq::body_size(at_cap) == pq::kFrameMax, "the cap itself is admissible, not off by one");
    }

    // ── 4. bindAEADTranscript ───────────────────────────────────────────
    std::printf("\nbindAEADTranscript, by length:\n");
    {
        const std::vector<std::uint8_t> init(100, 0x11), resp(50, 0x22), ipub(8, 0x33), rpub(9, 0x44);
        const auto bound = pq::bind_transcript(init, resp, 0x01, {}, ipub, rpub);
        check(bound.size() == 100 + 50 + 1 + 32 + 8 + 9,
              "the binding is each input exactly once — a duplicated message shows up here");
        check(bound[100 + 50] == 0x01 && bound.back() == 0x44,
              "profile follows the two messages, and the responder's key is last");
    }

    // ── 5. The handshake, over a socket ─────────────────────────────────
    std::printf("\nOver an AF_UNIX stream pair, against a responder built from RespondHandshake:\n");
    const auto dir = std::filesystem::temp_directory_path() / "node-pq-handshake-test";
    std::filesystem::remove_all(dir);
    const auto id = pq::Identity::open(dir);

    {
        Responder  r;
        const auto out = exchange(id, r);
        check(out.ok, std::string("the handshake completes") + (out.ok ? "" : ": " + out.error));
        check(r.init_signature_ok,
              "the responder verifies this node's INIT under NODE_PQ_HANDSHAKE_V1/initiator");
        check(out.peer_node_id == pq::derive_node_id(r.pk),
              "the peer NodeID returned is the one its ML-DSA key derives");
        check(out.peer_mldsa_pub == r.pk, "the peer's ML-DSA key survives the round trip intact");
        check(out.aead_key == r.aead,
              "both ends derive the SAME session key — the transcripts agree byte for byte");
        std::printf("       session key %s\n", hex(out.aead_key).c_str());
        std::printf("       peer NodeID %s\n", hex(out.peer_node_id).c_str());
    }

    // Each refusal below is a byte a hostile or misconfigured peer controls.
    {
        Responder r;
        r.profile      = 0x02;  // peer.ProfilePermissive
        const auto out = exchange(id, r);
        check(!out.ok, "a responder answering with another profile is refused: " + out.error);
    }
    {
        Responder r;
        r.chain[0]     = 0x01;
        const auto out = exchange(id, r);
        check(!out.ok, "a responder answering for another chain is refused: " + out.error);
    }
    {
        Responder r;
        r.lie_about_node_id = true;
        const auto out      = exchange(id, r);
        check(!out.ok, "a NodeID its own key does not derive is refused: " + out.error);
    }
    {
        Responder r;
        r.corrupt_signature = true;
        const auto out      = exchange(id, r);
        check(!out.ok, "one flipped signature bit is refused: " + out.error);
    }

    // A truncated RESP is a stranger's bytes, not a transport failure: the
    // handshake reports it rather than letting an exception out of a decoder.
    {
        Pair p;
        Join responder{std::thread([&] {
            try {
                (void)read_frame(p.b);
                const std::vector<std::uint8_t> stub{pq::kProtocolVersionV1, pq::kProfileStrictPQ};
                write_frame(p.b, stub);
            } catch (...) {
                ::shutdown(p.b, SHUT_RDWR);
            }
        })};
        pq::Outcome out;
        try {
            out = pq::run_initiator(
                id, [&](std::span<const std::uint8_t> body) { write_frame(p.a, body); },
                [&] { return read_frame(p.a); });
        } catch (const std::exception& e) {
            out.ok    = false;
            out.error = "escaped: " + std::string(e.what());
        }
        check(!out.ok && out.error.rfind("escaped:", 0) != 0,
              "a truncated RESP is an outcome, not an exception: " + out.error);
    }

    // The identity is the node's, not the session's: a second open of the
    // same directory is the same validator.
    {
        const auto again = pq::Identity::open(dir);
        check(again.node_id() == id.node_id() && again.public_key() == id.public_key(),
              "reopening the key directory yields the same validator, not a new one");
    }
    std::filesystem::remove_all(dir);

    std::printf("--------------------------------------------------------------------------------\n");
    if (g_fail) {
        std::printf("==== node PQ HANDSHAKE: FAIL (%d) ====\n", g_fail);
        return 1;
    }
    std::printf("==== node PQ HANDSHAKE: PASS — Go's answers, and one key from two ends ====\n");
    return 0;
}
