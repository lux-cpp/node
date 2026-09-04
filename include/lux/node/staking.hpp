// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// staking.hpp — the identity a luxd peer link is conducted under. Two keys,
// answering two different questions, exactly as node.rs and Go keep them:
//
//   - a self-signed ECDSA P-256 certificate. `NodeID = ripemd160(sha256(cert
//     DER))`, so the certificate IS the validator's name — a regenerated one
//     is a different validator, which is why it is KEPT, never rotated in
//     place. It signs the TLS handshake (mutual TLS, peer identified by key,
//     not by a CA) and the handshake's "signed IP" field.
//   - a BLS12-381 secret key (32 bytes, `/dev/urandom` seed through
//     `lux::consensus::bls::keygen`). It signs consensus votes (kVoteDST) and
//     proves possession of itself (kPopDST) — both over the SAME curve as
//     Go's `luxfi/crypto`, so a proof made here verifies there.
//
// Both live under one directory, one file each, mode 0600: `staker.der` (the
// certificate), `staker.key` (the EC private key, SEC1/DER), `bls.key` (the
// raw 32-byte BLS secret). `open()` loads what is there and creates what is
// not — it never regenerates a file that exists, because that would silently
// change who this validator is.

#pragma once

#include <array>
#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <vector>

namespace lux::node::staking {

// hash160: ripemd160(sha256(x)) — Go's `ids.NodeIDFromCert`, chained
// explicitly (the sha256 pass is NOT folded into a single "hash160" primitive
// on either side of this port).
[[nodiscard]] std::array<std::uint8_t, 20> hash160(std::span<const std::uint8_t> data) noexcept;

// Base58, with a 4-byte checksum appended before encoding: base58(raw ++
// sha256(raw)[28..32]). What luxd prints a NodeID as.
[[nodiscard]] std::string cb58(std::span<const std::uint8_t> raw);

// This validator's whole identity: what it dials luxd with, and what it votes
// with. Non-copyable (owns OpenSSL-API handles); move only.
class Identity {
public:
    static Identity open(const std::filesystem::path& dir);
    ~Identity();
    Identity(Identity&&) noexcept;
    Identity& operator=(Identity&&) noexcept;
    Identity(const Identity&)            = delete;
    Identity& operator=(const Identity&) = delete;

    [[nodiscard]] const std::vector<std::uint8_t>& cert_der() const noexcept { return cert_der_; }
    [[nodiscard]] const std::array<std::uint8_t, 20>& node_id() const noexcept { return node_id_; }
    // The staking key as an opaque `EC_KEY*`, for `peer_tls::Connection::connect`
    // to present as this side's TLS client certificate key. Opaque here so
    // this header stays free of AWS-LC's C API; the one caller that needs it
    // is peer.cpp, which already links AWS-LC.
    [[nodiscard]] void* ec_key() const noexcept { return ec_key_; }
    [[nodiscard]] std::string node_id_string() const { return "NodeID-" + cb58(node_id_); }

    // DER-encoded ECDSA-P256 signature over SHA256(msg) — the staking key's
    // signature, `crypto.Signer` convention: sign the digest, DER on the wire.
    [[nodiscard]] std::vector<std::uint8_t> sign_ecdsa_sha256(std::span<const std::uint8_t> msg) const;

    [[nodiscard]] const std::array<std::uint8_t, 32>& bls_sk() const noexcept { return bls_sk_; }
    [[nodiscard]] const std::array<std::uint8_t, 48>& bls_pk() const noexcept { return bls_pk_; }

    // 96-byte compressed BLS signature over `msg` under kPopDST — the one
    // primitive both proof-of-possession uses in this port need (see
    // `genesis_pop()` and the handshake's `bls_ip_pop()` below for the two
    // different messages it is asked to sign).
    [[nodiscard]] std::array<std::uint8_t, 96> pop_sign(std::span<const std::uint8_t> msg) const;

    // The genesis `signer` block's proof: `pop_sign(bls_pk_)` — proves
    // possession of the secret key behind the 48-byte compressed public key,
    // independent of any node id (used to mint an `initialStakers` entry).
    [[nodiscard]] std::array<std::uint8_t, 96> genesis_pop() const { return pop_sign(bls_pk_); }

private:
    Identity() = default;
    void close() noexcept;

    std::vector<std::uint8_t>    cert_der_;
    std::array<std::uint8_t, 20> node_id_{};
    std::array<std::uint8_t, 32> bls_sk_{};
    std::array<std::uint8_t, 48> bls_pk_{};
    void* ec_key_ = nullptr;  // EC_KEY*, opaque here so this header stays free of AWS-LC's C API
};

// The handshake's "signed IP" preimage — NOT what the wire FIELD carries. 26
// bytes: the IPv4 address mapped into its 16-byte IPv6 form, then the port as
// a big-endian u16, then the timestamp as a big-endian u64. Signing the
// field's 4 raw bytes instead of this 26-byte mapped form is a validly-shaped
// signature over the WRONG message, and luxd simply closes the connection —
// the two encodings must never be conflated.
[[nodiscard]] std::array<std::uint8_t, 26> signed_ip(std::array<std::uint8_t, 4> v4_octets,
                                                      std::uint16_t port,
                                                      std::uint64_t timestamp) noexcept;

}  // namespace lux::node::staking
