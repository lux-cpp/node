// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco

#include "lux/node/staking.hpp"

#include "lux/consensus/bls.hpp"

#include <openssl/asn1.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ec_key.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/x509.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstring>
#include <fstream>
#include <stdexcept>

namespace lux::node::staking {

namespace {

// A private, mode-0600 write: the mode is set AT CREATION (O_CREAT's mode
// argument), not patched on afterward, so there is no window where the file
// exists world-readable.
void write_private(const std::filesystem::path& path, std::span<const std::uint8_t> data) {
    const int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) throw std::runtime_error("staking: cannot create " + path.string());
    std::size_t off = 0;
    while (off < data.size()) {
        const ssize_t n = ::write(fd, data.data() + off, data.size() - off);
        if (n < 0) { ::close(fd); throw std::runtime_error("staking: write failed: " + path.string()); }
        off += std::size_t(n);
    }
    ::close(fd);
}

std::vector<std::uint8_t> read_all(const std::filesystem::path& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("staking: cannot open " + path.string());
    return std::vector<std::uint8_t>(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
}

EC_KEY* new_p256_key() {
    EC_KEY* k = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!k) throw std::runtime_error("staking: EC_KEY_new_by_curve_name failed");
    if (!EC_KEY_generate_key(k)) { EC_KEY_free(k); throw std::runtime_error("staking: EC_KEY_generate_key failed"); }
    return k;
}

// Self-signed, empty subject/issuer DN, single "lux" SAN — luxd identifies a
// peer by the key inside the certificate, not by anything a CA or a name
// would assert, so the certificate's job is to CARRY the key, nothing more.
std::vector<std::uint8_t> self_sign(EC_KEY* ec) {
    X509* x = X509_new();
    if (!x) throw std::runtime_error("staking: X509_new failed");
    struct Guard { X509* p; ~Guard() { X509_free(p); } } guard{x};

    X509_set_version(x, 2);  // X.509v3
    ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
    X509_gmtime_adj(X509_getm_notBefore(x), 0);
    X509_gmtime_adj(X509_getm_notAfter(x), 60L * 60 * 24 * 365 * 20);  // 20 years

    X509_NAME* name = X509_get_subject_name(x);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                reinterpret_cast<const unsigned char*>("lux"), -1, -1, 0);
    X509_set_issuer_name(x, name);  // self-issued

    EVP_PKEY* pkey = EVP_PKEY_new();
    if (!pkey) throw std::runtime_error("staking: EVP_PKEY_new failed");
    struct PGuard { EVP_PKEY* p; ~PGuard() { EVP_PKEY_free(p); } } pguard{pkey};
    // set1, not assign/1: this function does not take ownership of `ec` — the
    // caller (open()) keeps it alive as the Identity's signing key.
    if (!EVP_PKEY_set1_EC_KEY(pkey, ec)) throw std::runtime_error("staking: EVP_PKEY_set1_EC_KEY failed");
    if (!X509_set_pubkey(x, pkey)) throw std::runtime_error("staking: X509_set_pubkey failed");
    if (!X509_sign(x, pkey, EVP_sha256())) throw std::runtime_error("staking: X509_sign failed");

    std::uint8_t* der = nullptr;
    const int len = i2d_X509(x, &der);
    if (len <= 0 || der == nullptr) throw std::runtime_error("staking: i2d_X509 failed");
    std::vector<std::uint8_t> out(der, der + len);
    OPENSSL_free(der);
    return out;
}

}  // namespace

std::array<std::uint8_t, 20> hash160(std::span<const std::uint8_t> data) noexcept {
    std::uint8_t sha[32];
    SHA256(data.data(), data.size(), sha);
    std::array<std::uint8_t, 20> out{};
    RIPEMD160(sha, sizeof sha, out.data());
    return out;
}

std::string cb58(std::span<const std::uint8_t> raw) {
    std::uint8_t sha[32];
    SHA256(raw.data(), raw.size(), sha);
    std::vector<std::uint8_t> payload(raw.begin(), raw.end());
    payload.insert(payload.end(), sha + 28, sha + 32);  // 4-byte checksum

    static constexpr char kAlphabet[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    // Big-integer base58 via BIGNUM — payload is short (24 bytes), correctness
    // over cleverness.
    BIGNUM* n = BN_bin2bn(payload.data(), int(payload.size()), nullptr);
    BIGNUM* base = BN_new();
    BN_set_word(base, 58);
    BN_CTX* ctx = BN_CTX_new();
    std::string out;
    BIGNUM* rem = BN_new();
    while (!BN_is_zero(n)) {
        BN_div(n, rem, n, base, ctx);
        out.push_back(kAlphabet[BN_get_word(rem)]);
    }
    for (auto b : payload) {  // leading zero bytes -> leading '1's, in order
        if (b != 0) break;
        out.push_back(kAlphabet[0]);
    }
    std::reverse(out.begin(), out.end());
    BN_free(n);
    BN_free(base);
    BN_free(rem);
    BN_CTX_free(ctx);
    return out;
}

Identity::~Identity() { close(); }

void Identity::close() noexcept {
    if (ec_key_) { EC_KEY_free(reinterpret_cast<EC_KEY*>(ec_key_)); ec_key_ = nullptr; }
}

Identity::Identity(Identity&& o) noexcept
    : cert_der_(std::move(o.cert_der_)), node_id_(o.node_id_), bls_sk_(o.bls_sk_), bls_pk_(o.bls_pk_),
      ec_key_(o.ec_key_) {
    o.ec_key_ = nullptr;
}
Identity& Identity::operator=(Identity&& o) noexcept {
    if (this != &o) {
        close();
        cert_der_ = std::move(o.cert_der_);
        node_id_  = o.node_id_;
        bls_sk_   = o.bls_sk_;
        bls_pk_   = o.bls_pk_;
        ec_key_   = o.ec_key_;
        o.ec_key_ = nullptr;
    }
    return *this;
}

Identity Identity::open(const std::filesystem::path& dir) {
    std::filesystem::create_directories(dir);
    const auto cert_path = dir / "staker.der";
    const auto key_path  = dir / "staker.key";
    const auto bls_path  = dir / "bls.key";

    Identity id;

    EC_KEY* ec = nullptr;
    if (std::filesystem::exists(cert_path) && std::filesystem::exists(key_path)) {
        // KEPT, not regenerated: NodeID is a function of the certificate, so a
        // fresh one would be a different validator than any genesis names.
        id.cert_der_       = read_all(cert_path);
        const auto key_der = read_all(key_path);
        const std::uint8_t* p = key_der.data();
        ec = d2i_ECPrivateKey(nullptr, &p, long(key_der.size()));
        if (!ec) throw std::runtime_error("staking: corrupt staker.key at " + key_path.string());
    } else {
        ec              = new_p256_key();
        id.cert_der_    = self_sign(ec);
        std::uint8_t* der = nullptr;
        const int len = i2d_ECPrivateKey(ec, &der);
        if (len <= 0) { EC_KEY_free(ec); throw std::runtime_error("staking: i2d_ECPrivateKey failed"); }
        write_private(key_path, std::span<const std::uint8_t>(der, std::size_t(len)));
        OPENSSL_free(der);
        write_private(cert_path, id.cert_der_);
    }
    id.ec_key_  = ec;
    id.node_id_ = hash160(id.cert_der_);

    if (std::filesystem::exists(bls_path)) {
        const auto sk = read_all(bls_path);
        if (sk.size() != 32) throw std::runtime_error("staking: bls.key has the wrong length");
        std::copy(sk.begin(), sk.end(), id.bls_sk_.begin());
    } else {
        std::uint8_t seed[32];
        if (RAND_bytes(seed, sizeof seed) != 1) throw std::runtime_error("staking: RAND_bytes failed");
        if (lux::consensus::bls::keygen(seed, id.bls_sk_.data()) != 0)
            throw std::runtime_error("staking: bls keygen failed");
        write_private(bls_path, std::span<const std::uint8_t>(id.bls_sk_.data(), id.bls_sk_.size()));
    }
    if (lux::consensus::bls::sk_to_pk(id.bls_sk_.data(), id.bls_pk_.data()) != 0)
        throw std::runtime_error("staking: bls sk_to_pk failed");

    return id;
}

std::vector<std::uint8_t> Identity::sign_ecdsa_sha256(std::span<const std::uint8_t> msg) const {
    std::uint8_t digest[32];
    SHA256(msg.data(), msg.size(), digest);
    auto* ec = reinterpret_cast<EC_KEY*>(ec_key_);
    std::vector<std::uint8_t> sig(ECDSA_size(ec));
    unsigned int sig_len = 0;
    if (!ECDSA_sign(0, digest, sizeof digest, sig.data(), &sig_len, ec))
        throw std::runtime_error("staking: ECDSA_sign failed");
    sig.resize(sig_len);
    return sig;
}

std::array<std::uint8_t, 96> Identity::pop_sign(std::span<const std::uint8_t> msg) const {
    std::array<std::uint8_t, 96> sig{};
    if (lux::consensus::bls::pop_sign(bls_sk_.data(), msg.data(), msg.size(), sig.data()) != 0)
        throw std::runtime_error("staking: bls pop_sign failed");
    return sig;
}

std::array<std::uint8_t, 26> signed_ip(std::array<std::uint8_t, 4> v4, std::uint16_t port,
                                       std::uint64_t timestamp) noexcept {
    std::array<std::uint8_t, 26> out{};
    // The IPv4-mapped IPv6 form: 10 zero bytes, 2 bytes of 0xff, then the 4
    // address bytes — RFC 4291 §2.5.5.2, what `net.IP.To16()` / Rust's
    // `to_ipv6_mapped()` both produce for a v4 address.
    out[10] = 0xff;
    out[11] = 0xff;
    out[12] = v4[0]; out[13] = v4[1]; out[14] = v4[2]; out[15] = v4[3];
    out[16] = std::uint8_t(port >> 8);
    out[17] = std::uint8_t(port);
    for (int i = 0; i < 8; ++i) out[std::size_t(18 + i)] = std::uint8_t(timestamp >> (56 - 8 * i));
    return out;
}

}  // namespace lux::node::staking
