// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco

#include "lux/node/pq_handshake.hpp"

#include "lux/node/keccak.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <cstring>
#include <fstream>
#include <stdexcept>

// lux-crypto's C ABI (github.com/luxfi/crypto/bindings/cabi) — ground-truth
// symbol names confirmed via `nm -D libluxcrypto.so` (no "lux_" prefix, one
// dylib-per-machine build; the exact spelling matters for the linker and
// does not appear this way in every doc that describes this library).
// `_ctx` variants were ADDED to this port (see LLM.md) because the
// unqualified mldsa65_sign/verify hardcode an EMPTY FIPS 204 context, which
// is a different signed message than this handshake's non-empty context
// strings.
extern "C" {
int mlkem768_keypair(char* pk, int* pkLen, char* sk, int* skLen);
int mlkem768_decapsulate(char* skData, int skLen, char* ctData, int ctLen, char* ss, int* ssLen);
int mlkem768_pk_size();
int mlkem768_sk_size();
int mlkem768_ct_size();
int mldsa65_keypair(char* pk, int* pkLen, char* sk, int* skLen);
int mldsa65_sign_ctx(char* skData, int skLen, char* ctxData, int ctxLen, char* msgData, int msgLen,
                     char* sig, int* sigLen);
int mldsa65_verify_ctx(char* pkData, int pkLen, char* ctxData, int ctxLen, char* msgData, int msgLen,
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

// cSHAKE256(x, out, "TupleHash", "NODE_TRANSCRIPT_V1") over a SINGLE
// already-concatenated input — luxd's HashTranscript is called with one
// []byte at this call site (bindAEADTranscript's output), so the general
// N-ary TupleHash construction degenerates to one encode_string + one
// right_encode(L) here, which is what this reproduces directly rather than
// through an N-ary helper nothing else in this port needs.
std::array<std::uint8_t, 48> hash_transcript(std::span<const std::uint8_t> transcript) {
    auto x = keccak::encode_string(transcript);
    auto re = keccak::right_encode(48ull * 8);
    x.insert(x.end(), re.begin(), re.end());
    std::array<std::uint8_t, 48> out{};
    keccak::cshake256(x, out, "TupleHash", "NODE_TRANSCRIPT_V1");
    return out;
}

std::array<std::uint8_t, 32> derive_aead_key(std::uint8_t scheme_id,
                                             const std::array<std::uint8_t, 32>& shared_secret,
                                             const std::array<std::uint8_t, 48>& transcript_hash) {
    std::vector<std::uint8_t> in;
    in.push_back(scheme_id);
    in.insert(in.end(), shared_secret.begin(), shared_secret.end());
    in.insert(in.end(), transcript_hash.begin(), transcript_hash.end());
    std::array<std::uint8_t, 32> out{};
    keccak::cshake256(in, out, "KEMDerive", "NODE_AEAD_V1");
    return out;
}

}  // namespace

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
                             const_cast<char*>(kCtx.data()), int(kCtx.size()),
                             reinterpret_cast<char*>(init_prefix.data()), int(init_prefix.size()),
                             reinterpret_cast<char*>(sig.data()), &sig_len) != 0) {
            out.error = "mldsa65_sign_ctx (INIT) failed";
            return out;
        }
        sig.resize(std::size_t(sig_len));
    }
    std::vector<std::uint8_t> init_bytes = init_prefix;
    append_lp(init_bytes, sig);

    write_frame(init_bytes);

    // 4. Read and parse RESP.
    const auto resp_bytes = read_frame();
    Cursor r(resp_bytes);
    const std::uint8_t resp_version = r.u8();
    const std::uint8_t resp_profile = r.u8();
    std::array<std::uint8_t, 32> resp_chain{};
    r.fixed(resp_chain);
    const std::uint8_t resp_kem_scheme = r.u8();
    std::array<std::uint8_t, 20> resp_node_id{};
    r.fixed(resp_node_id);
    const auto resp_mldsa_pub = r.bytes();
    const auto resp_kem_ct    = r.bytes();
    const auto resp_sig       = r.bytes();
    if (r.remaining() != 0) { out.error = "RESP has trailing bytes"; return out; }

    if (resp_version != kProtocolVersionV1) { out.error = "RESP: unexpected ProtocolVersion"; return out; }
    if (resp_profile != kProfileStrictPQ) { out.error = "RESP: unexpected Profile"; return out; }
    if (resp_chain != chain_id) { out.error = "RESP: ChainID mismatch"; return out; }
    if (resp_kem_scheme != kKEMSchemeMLKEM768) { out.error = "RESP: unexpected KEMScheme"; return out; }

    // 5. resp.transcriptPrefix(init) = init.canonicalBytes() ++ RESP fields
    //    up to (excluding) Sig.
    std::vector<std::uint8_t> resp_prefix = init_bytes;  // init.canonicalBytes()
    resp_prefix.push_back(resp_version);
    resp_prefix.push_back(resp_profile);
    resp_prefix.insert(resp_prefix.end(), resp_chain.begin(), resp_chain.end());
    resp_prefix.push_back(resp_kem_scheme);
    resp_prefix.insert(resp_prefix.end(), resp_node_id.begin(), resp_node_id.end());
    append_lp(resp_prefix, resp_mldsa_pub);
    append_lp(resp_prefix, resp_kem_ct);

    {
        static constexpr std::string_view kCtx = "NODE_PQ_HANDSHAKE_V1/responder";
        const int rc = mldsa65_verify_ctx(
            const_cast<char*>(reinterpret_cast<const char*>(resp_mldsa_pub.data())), int(resp_mldsa_pub.size()),
            const_cast<char*>(kCtx.data()), int(kCtx.size()),
            const_cast<char*>(reinterpret_cast<const char*>(resp_prefix.data())), int(resp_prefix.size()),
            const_cast<char*>(reinterpret_cast<const char*>(resp_sig.data())), int(resp_sig.size()));
        if (rc != 0) { out.error = "responder signature failed"; return out; }
    }

    // 6. Decapsulate to recover the shared secret.
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

    // 7. bindAEADTranscript(init, resp) = init.canonicalBytes() ++
    //    resp.canonicalBytes() ++ Profile ++ ChainID ++ init.MLDSAPub ++
    //    resp.MLDSAPub — then TupleHash256/cSHAKE256 into the 48-byte
    //    TranscriptHash, then cSHAKE256 into the 32-byte AEAD key.
    std::vector<std::uint8_t> resp_canonical = resp_prefix;
    append_lp(resp_canonical, resp_sig);

    std::vector<std::uint8_t> full_transcript = init_bytes;
    full_transcript.insert(full_transcript.end(), resp_canonical.begin(), resp_canonical.end());
    full_transcript.push_back(kProfileStrictPQ);
    full_transcript.insert(full_transcript.end(), chain_id.begin(), chain_id.end());
    full_transcript.insert(full_transcript.end(), id.public_key().begin(), id.public_key().end());
    full_transcript.insert(full_transcript.end(), resp_mldsa_pub.begin(), resp_mldsa_pub.end());

    const auto transcript_hash = hash_transcript(full_transcript);
    const auto aead_key        = derive_aead_key(kKEMSchemeMLKEM768, shared_secret, transcript_hash);

    // 8. Bind the responder's claimed NodeID to the ML-DSA key it just
    //    proved possession of — verifyPQIdentityBinding, same predicate
    //    luxd applies to OUR init.
    const auto derived = derive_node_id(resp_mldsa_pub);
    if (derived != resp_node_id) {
        out.error = "peer identity binding failed: claimed NodeID does not match its ML-DSA key";
        return out;
    }

    out.ok             = true;
    out.peer_node_id    = resp_node_id;
    out.peer_mldsa_pub = resp_mldsa_pub;
    out.aead_key        = aead_key;
    return out;
}

}  // namespace lux::node::pq
