// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco

#include "lux/node/pq_handshake.hpp"

#include "lux/node/keccak.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <cstring>
#include <fstream>
#include <stdexcept>

// lux-crypto's C ABI (github.com/luxfi/crypto/bindings/cabi), transcribed
// from the `libluxcrypto.h` that cgo generates beside the archive. The
// transcription is the whole risk here: these have C linkage, so a
// declaration whose PARAMETER ORDER disagrees with the definition links
// cleanly and the arguments simply arrive in the wrong registers. The `_ctx`
// pair takes the message BEFORE the context; this file had them the other
// way round, which signed the context string under the transcript as
// context. Nothing caught it because nothing called it.
//
// The `_ctx` variants exist because the unqualified mldsa65_sign/verify
// hardcode an EMPTY FIPS 204 context, and the same bytes signed under a
// different context are a different signature.
extern "C" {
int mlkem768_keypair(char* pk, int* pkLen, char* sk, int* skLen);
int mlkem768_decapsulate(char* skData, int skLen, char* ctData, int ctLen, char* ss, int* ssLen);
int mlkem768_pk_size();
int mlkem768_sk_size();
int mlkem768_ct_size();
int mldsa65_keypair(char* pk, int* pkLen, char* sk, int* skLen);
int mldsa65_sign_ctx(char* skData, int skLen, char* msgData, int msgLen, char* ctxData, int ctxLen,
                     char* sig, int* sigLen);
int mldsa65_verify_ctx(char* pkData, int pkLen, char* msgData, int msgLen, char* ctxData, int ctxLen,
                       char* sigData, int sigLen);
int mldsa65_pk_size();
int mldsa65_sk_size();
int mldsa65_sig_size();
}

namespace lux::node::pq {

namespace {

void write_private(const std::filesystem::path& path, std::span<const std::uint8_t> data) {
    const int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) throw std::runtime_error("pq: cannot create " + path.string());
    std::size_t off = 0;
    while (off < data.size()) {
        const ssize_t n = ::write(fd, data.data() + off, data.size() - off);
        if (n < 0) { ::close(fd); throw std::runtime_error("pq: write failed: " + path.string()); }
        off += std::size_t(n);
    }
    ::close(fd);
}
std::vector<std::uint8_t> read_all(const std::filesystem::path& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("pq: cannot open " + path.string());
    return std::vector<std::uint8_t>(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
}

void put_u32_be(std::vector<std::uint8_t>& b, std::uint32_t v) {
    b.push_back(std::uint8_t(v >> 24));
    b.push_back(std::uint8_t(v >> 16));
    b.push_back(std::uint8_t(v >> 8));
    b.push_back(std::uint8_t(v));
}
void append_lp(std::vector<std::uint8_t>& b, std::span<const std::uint8_t> data) {
    put_u32_be(b, std::uint32_t(data.size()));
    b.insert(b.end(), data.begin(), data.end());
}
std::span<const std::uint8_t> bytes_of(std::string_view s) {
    return {reinterpret_cast<const std::uint8_t*>(s.data()), s.size()};
}

// A tiny bounds-checked cursor over an untrusted RESP frame — mirrors Go's
// pqReader in pq_frame.go: every accessor reports failure rather than
// reading past the end.
class Cursor {
public:
    explicit Cursor(std::span<const std::uint8_t> b) : d_(b) {}
    std::size_t remaining() const { return d_.size() - at_; }
    std::uint8_t u8() {
        if (remaining() < 1) throw std::runtime_error("pq: RESP truncated (u8)");
        return d_[at_++];
    }
    void fixed(std::span<std::uint8_t> out) {
        if (remaining() < out.size()) throw std::runtime_error("pq: RESP truncated (fixed)");
        std::memcpy(out.data(), d_.data() + at_, out.size());
        at_ += out.size();
    }
    std::vector<std::uint8_t> bytes() {
        if (remaining() < 4) throw std::runtime_error("pq: RESP truncated (len)");
        std::uint32_t n = (std::uint32_t(d_[at_]) << 24) | (std::uint32_t(d_[at_ + 1]) << 16) |
                          (std::uint32_t(d_[at_ + 2]) << 8) | std::uint32_t(d_[at_ + 3]);
        at_ += 4;
        if (std::uint64_t(n) > remaining()) throw std::runtime_error("pq: RESP truncated (body)");
        std::vector<std::uint8_t> out(d_.begin() + std::ptrdiff_t(at_), d_.begin() + std::ptrdiff_t(at_ + n));
        at_ += n;
        return out;
    }

private:
    std::span<const std::uint8_t> d_;
    std::size_t                   at_ = 0;
};

}  // namespace

std::vector<std::uint8_t> frame(std::span<const std::uint8_t> payload) {
    if (payload.size() > kFrameMax)
        throw std::runtime_error("pq: frame payload exceeds the 16 KiB cap");
    std::vector<std::uint8_t> out;
    out.reserve(4 + payload.size());
    put_u32_be(out, std::uint32_t(payload.size()));
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
}

std::uint32_t body_size(std::span<const std::uint8_t, 4> header) {
    const std::uint32_t n = (std::uint32_t(header[0]) << 24) | (std::uint32_t(header[1]) << 16) |
                            (std::uint32_t(header[2]) << 8) | std::uint32_t(header[3]);
    if (n > kFrameMax) throw std::runtime_error("pq: peer announced a frame over the 16 KiB cap");
    return n;
}

std::vector<std::uint8_t> bind_transcript(std::span<const std::uint8_t> init_canonical,
                                          std::span<const std::uint8_t> resp_canonical,
                                          std::uint8_t profile,
                                          const std::array<std::uint8_t, 32>& chain_id,
                                          std::span<const std::uint8_t> init_mldsa_pub,
                                          std::span<const std::uint8_t> resp_mldsa_pub) {
    std::vector<std::uint8_t> out;
    out.reserve(init_canonical.size() + resp_canonical.size() + 1 + chain_id.size() +
                init_mldsa_pub.size() + resp_mldsa_pub.size());
    out.insert(out.end(), init_canonical.begin(), init_canonical.end());
    out.insert(out.end(), resp_canonical.begin(), resp_canonical.end());
    out.push_back(profile);
    out.insert(out.end(), chain_id.begin(), chain_id.end());
    out.insert(out.end(), init_mldsa_pub.begin(), init_mldsa_pub.end());
    out.insert(out.end(), resp_mldsa_pub.begin(), resp_mldsa_pub.end());
    return out;
}

std::array<std::uint8_t, 48> transcript_hash(std::span<const std::uint8_t> transcript) {
    auto x  = keccak::encode_string(transcript);
    auto re = keccak::right_encode(48ull * 8);
    x.insert(x.end(), re.begin(), re.end());
    std::array<std::uint8_t, 48> out{};
    keccak::cshake256(x, out, "TupleHash", "NODE_TRANSCRIPT_V1");
    return out;
}

std::array<std::uint8_t, 32> aead_key(std::uint8_t scheme,
                                      const std::array<std::uint8_t, 32>& shared_secret,
                                      const std::array<std::uint8_t, 48>& transcript) {
    std::vector<std::uint8_t> in;
    in.reserve(1 + shared_secret.size() + transcript.size());
    in.push_back(scheme);
    in.insert(in.end(), shared_secret.begin(), shared_secret.end());
    in.insert(in.end(), transcript.begin(), transcript.end());
    std::array<std::uint8_t, 32> out{};
    keccak::cshake256(in, out, "KEMDerive", "NODE_AEAD_V1");
    return out;
}

std::array<std::uint8_t, 20> derive_node_id(std::span<const std::uint8_t> mldsa_pub,
                                            const std::array<std::uint8_t, 32>& chain_id) {
    std::vector<std::uint8_t> x;
    static constexpr std::string_view kDomain = "NODE_ID_V1";
    auto app = [&](std::span<const std::uint8_t> field, std::uint64_t bits) {
        auto le = keccak::left_encode(bits);
        x.insert(x.end(), le.begin(), le.end());
        x.insert(x.end(), field.begin(), field.end());
    };
    app(bytes_of(kDomain), kDomain.size() * 8);
    app(std::span<const std::uint8_t>(chain_id.data(), chain_id.size()), chain_id.size() * 8);
    const std::uint8_t scheme = 0x42;  // ids.NodeIDSchemeMLDSA65
    app(std::span<const std::uint8_t>(&scheme, 1), 8);
    app(mldsa_pub, std::uint64_t(mldsa_pub.size()) * 8);

    std::array<std::uint8_t, 48> full{};
    keccak::shake256(x, full);
    std::array<std::uint8_t, 20> id{};
    std::memcpy(id.data(), full.data(), 20);
    return id;
}

Identity Identity::open(const std::filesystem::path& dir) {
    std::filesystem::create_directories(dir);
    const auto pk_path = dir / "mldsa.pub.raw";
    const auto sk_path = dir / "mldsa.key.raw";

    Identity id;
    if (std::filesystem::exists(pk_path) && std::filesystem::exists(sk_path)) {
        id.pk_ = read_all(pk_path);
        id.sk_ = read_all(sk_path);
    } else {
        // Braces, not parentheses around a functional cast: `vector<T> v(size_t(f()))`
        // declares a FUNCTION taking a `size_t(*)()` and returning vector<T>. The
        // most vexing parse, and the reason this file had never been compiled.
        std::vector<std::uint8_t> pk(static_cast<std::size_t>(mldsa65_pk_size()));
        std::vector<std::uint8_t> sk(static_cast<std::size_t>(mldsa65_sk_size()));
        int pk_len = int(pk.size()), sk_len = int(sk.size());
        if (mldsa65_keypair(reinterpret_cast<char*>(pk.data()), &pk_len,
                            reinterpret_cast<char*>(sk.data()), &sk_len) != 0)
            throw std::runtime_error("pq: mldsa65_keypair failed");
        pk.resize(std::size_t(pk_len));
        sk.resize(std::size_t(sk_len));
        write_private(pk_path, pk);
        write_private(sk_path, sk);
        id.pk_ = std::move(pk);
        id.sk_ = std::move(sk);
    }
    id.node_id_ = derive_node_id(id.pk_);
    return id;
}

Outcome run_initiator(const Identity& id,
                      const std::function<void(std::span<const std::uint8_t>)>& write_frame,
                      const std::function<std::vector<std::uint8_t>()>& read_frame,
                      const std::array<std::uint8_t, 32>& chain_id) {
    Outcome out;

    // 1. Fresh ML-KEM-768 keypair for this session only (never persisted —
    //    matches Go's InitiateHandshake, which calls GenerateKEMKeypair anew
    //    on every dial).
    std::vector<std::uint8_t> kem_pk(static_cast<std::size_t>(mlkem768_pk_size()));
    std::vector<std::uint8_t> kem_sk(static_cast<std::size_t>(mlkem768_sk_size()));
    {
        int pkl = int(kem_pk.size()), skl = int(kem_sk.size());
        if (mlkem768_keypair(reinterpret_cast<char*>(kem_pk.data()), &pkl,
                             reinterpret_cast<char*>(kem_sk.data()), &skl) != 0) {
            out.error = "mlkem768_keypair failed";
            return out;
        }
        kem_pk.resize(std::size_t(pkl));
        kem_sk.resize(std::size_t(skl));
    }

    // 2. INIT transcriptPrefix: ProtocolVersion, Profile, ChainID, KEMScheme,
    //    NodeID, MLDSAPub, KEMPub — HandshakeInit.transcriptPrefix, field for
    //    field.
    std::vector<std::uint8_t> init_prefix;
    init_prefix.push_back(kProtocolVersionV1);
    init_prefix.push_back(kProfileStrictPQ);
    init_prefix.insert(init_prefix.end(), chain_id.begin(), chain_id.end());
    init_prefix.push_back(kKEMSchemeMLKEM768);
    init_prefix.insert(init_prefix.end(), id.node_id().begin(), id.node_id().end());
    append_lp(init_prefix, id.public_key());
    append_lp(init_prefix, kem_pk);

    // 3. Sign the prefix under the initiator context, then append the
    //    length-prefixed signature to get canonicalBytes.
    std::vector<std::uint8_t> sig(static_cast<std::size_t>(mldsa65_sig_size()));
    {
        static constexpr std::string_view kCtx = "NODE_PQ_HANDSHAKE_V1/initiator";
        int sig_len = int(sig.size());
        if (mldsa65_sign_ctx(reinterpret_cast<char*>(const_cast<std::uint8_t*>(id.secret_key().data())),
                             int(id.secret_key().size()),
                             reinterpret_cast<char*>(init_prefix.data()), int(init_prefix.size()),
                             const_cast<char*>(kCtx.data()), int(kCtx.size()),
                             reinterpret_cast<char*>(sig.data()), &sig_len) != 0) {
            out.error = "mldsa65_sign_ctx (INIT) failed";
            return out;
        }
        sig.resize(std::size_t(sig_len));
    }
    std::vector<std::uint8_t> init_bytes = init_prefix;
    append_lp(init_bytes, sig);

    write_frame(init_bytes);

    // 4. Read and parse RESP. The transport call is the caller's to fail —
    //    a Quiet or a closed link belongs to peer_tls and propagates — but
    //    the bytes it returns are a stranger's, so a truncated or overlong
    //    field is this function's `ok == false`, not an exception escaping
    //    into a caller that has no better answer for it.
    const auto resp_bytes = read_frame();

    std::uint8_t                 resp_version = 0, resp_profile = 0, resp_kem_scheme = 0;
    std::array<std::uint8_t, 32> resp_chain{};
    std::array<std::uint8_t, 20> resp_node_id{};
    std::vector<std::uint8_t>    resp_mldsa_pub, resp_kem_ct, resp_sig;
    try {
        Cursor r(resp_bytes);
        resp_version = r.u8();
        resp_profile = r.u8();
        r.fixed(resp_chain);
        resp_kem_scheme = r.u8();
        r.fixed(resp_node_id);
        resp_mldsa_pub = r.bytes();
        resp_kem_ct    = r.bytes();
        resp_sig       = r.bytes();
        if (r.remaining() != 0) { out.error = "RESP has trailing bytes"; return out; }
    } catch (const std::exception& e) {
        out.error = e.what();
        return out;
    }

    // 5. Every cross-axis check, and every length, BEFORE any signature work
    //    — Go's validateRemoteResp, in its order and for its stated reason:
    //    a peer that sends garbage should not be able to spend this node's
    //    ML-DSA verifier on it. The lengths are not a formality either;
    //    these buffers cross into a cgo boundary that trusts them.
    if (resp_version != kProtocolVersionV1) { out.error = "RESP: unexpected ProtocolVersion"; return out; }
    if (resp_profile != kProfileStrictPQ) { out.error = "RESP: unexpected Profile"; return out; }
    if (resp_chain != chain_id) { out.error = "RESP: ChainID mismatch"; return out; }
    if (resp_kem_scheme != kKEMSchemeMLKEM768) { out.error = "RESP: unexpected KEMScheme"; return out; }
    if (resp_node_id == std::array<std::uint8_t, 20>{}) { out.error = "RESP: NodeID is zero"; return out; }
    if (resp_mldsa_pub.size() != std::size_t(mldsa65_pk_size())) {
        out.error = "RESP: ML-DSA public key is the wrong size";
        return out;
    }
    if (resp_kem_ct.size() != std::size_t(mlkem768_ct_size())) {
        out.error = "RESP: KEM ciphertext is the wrong size";
        return out;
    }
    if (resp_sig.size() != std::size_t(mldsa65_sig_size())) {
        out.error = "RESP: signature is the wrong size";
        return out;
    }

    // 6. What the responder signed is the WHOLE INIT followed by its own
    //    fields up to (excluding) Sig — resp.transcriptPrefix(init). Its
    //    canonicalBytes are those fields ALONE plus the signature: the two
    //    byte strings share a tail, not a head, and conflating them puts
    //    the INIT into the transcript twice.
    std::vector<std::uint8_t> resp_fields;
    resp_fields.push_back(resp_version);
    resp_fields.push_back(resp_profile);
    resp_fields.insert(resp_fields.end(), resp_chain.begin(), resp_chain.end());
    resp_fields.push_back(resp_kem_scheme);
    resp_fields.insert(resp_fields.end(), resp_node_id.begin(), resp_node_id.end());
    append_lp(resp_fields, resp_mldsa_pub);
    append_lp(resp_fields, resp_kem_ct);

    std::vector<std::uint8_t> resp_prefix = init_bytes;
    resp_prefix.insert(resp_prefix.end(), resp_fields.begin(), resp_fields.end());

    {
        static constexpr std::string_view kCtx = "NODE_PQ_HANDSHAKE_V1/responder";
        const int rc = mldsa65_verify_ctx(
            const_cast<char*>(reinterpret_cast<const char*>(resp_mldsa_pub.data())), int(resp_mldsa_pub.size()),
            const_cast<char*>(reinterpret_cast<const char*>(resp_prefix.data())), int(resp_prefix.size()),
            const_cast<char*>(kCtx.data()), int(kCtx.size()),
            const_cast<char*>(reinterpret_cast<const char*>(resp_sig.data())), int(resp_sig.size()));
        if (rc != 0) { out.error = "responder signature failed"; return out; }
    }

    // 7. Decapsulate to recover the shared secret.
    std::array<std::uint8_t, 32> shared_secret{};
    {
        int ss_len = int(shared_secret.size());
        if (mlkem768_decapsulate(reinterpret_cast<char*>(const_cast<std::uint8_t*>(kem_sk.data())),
                                 int(kem_sk.size()),
                                 const_cast<char*>(reinterpret_cast<const char*>(resp_kem_ct.data())),
                                 int(resp_kem_ct.size()),
                                 reinterpret_cast<char*>(shared_secret.data()), &ss_len) != 0) {
            out.error = "mlkem768_decapsulate failed";
            return out;
        }
    }

    // 8. Bind both messages and both identities, hash, and derive the key.
    std::vector<std::uint8_t> resp_canonical = resp_fields;
    append_lp(resp_canonical, resp_sig);

    const auto bound  = bind_transcript(init_bytes, resp_canonical, kProfileStrictPQ, chain_id,
                                        id.public_key(), resp_mldsa_pub);
    const auto digest = transcript_hash(bound);
    const auto key    = aead_key(kKEMSchemeMLKEM768, shared_secret, digest);

    // 9. Bind the responder's claimed NodeID to the ML-DSA key it just
    //    proved possession of — verifyPQIdentityBinding, the same predicate
    //    luxd applies to OUR init. A signature over a transcript naming a
    //    NodeID proves only that the signer chose to name it; this is what
    //    ties the name to the key, and the chain id is `ids.Empty` here
    //    because that is the domain a node's primary identity is derived
    //    under.
    const auto derived = derive_node_id(resp_mldsa_pub);
    if (derived != resp_node_id) {
        out.error = "peer identity binding failed: claimed NodeID does not match its ML-DSA key";
        return out;
    }

    out.ok             = true;
    out.peer_node_id   = resp_node_id;
    out.peer_mldsa_pub = resp_mldsa_pub;
    out.aead_key       = key;
    return out;
}

}  // namespace lux::node::pq
