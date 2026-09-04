// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// keccak.hpp — Keccak-f[1600] and the two XOFs the strict-PQ peer handshake
// is defined in terms of: SHAKE256 (FIPS 202) and cSHAKE256 (NIST SP
// 800-185). Neither AWS-LC nor lux-crypto exports SHA-3/SHAKE/cSHAKE — this
// is a from-scratch, standards-conformant implementation, not a port of
// luxd's Go (which reaches golang.org/x/crypto/sha3); the two must agree
// only on OUTPUT bytes for the same input, which the standard fixes.
//
// Used for exactly three derivations, all defined precisely in
// `pq_handshake.hpp`: the ML-DSA-key-bound NodeID (plain SHAKE256), the
// handshake TranscriptHash (cSHAKE256, N="TupleHash", S="NODE_TRANSCRIPT_V1"
// — SP 800-185 TupleHash256 over one already-concatenated input, which is
// exactly what luxd's own HashTranscript does), and the AEAD session key
// (cSHAKE256, N="KEMDerive", S="NODE_AEAD_V1").

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

namespace lux::node::keccak {

// An extendable-output sponge over Keccak-f[1600] at a caller-chosen
// domain-separation suffix (the padding byte). SHAKE256 and cSHAKE256 are
// both this sponge; they differ only in that byte and in what (if
// anything) is absorbed before the caller's own input.
class Sponge {
public:
    // `rate_bytes` is 136 for the *256 family (1600-bit state, 512-bit
    // capacity). `domain_suffix` is SHAKE's 0x1F or cSHAKE's 0x04 (cSHAKE
    // with an empty N and S degrades to plain SHAKE by definition, but this
    // type never takes that shortcut — callers choose the byte explicitly).
    explicit Sponge(std::uint8_t domain_suffix, std::size_t rate_bytes = 136) noexcept;

    void absorb(std::span<const std::uint8_t> data) noexcept;
    // Finalizes on first call; every call after that continues squeezing —
    // an XOF has no fixed output length, and re-finalizing would restart
    // the permutation mid-stream and silently corrupt the second call's
    // output, which is exactly the bug this design makes impossible to
    // reach through the public interface.
    void squeeze(std::span<std::uint8_t> out) noexcept;

private:
    void permute() noexcept;
    void absorb_block(const std::uint8_t* block) noexcept;

    std::uint64_t state_[25]{};
    std::uint8_t  buf_[136]{};
    std::size_t   buf_len_ = 0;
    std::size_t   rate_;
    std::uint8_t  domain_suffix_;
    bool          finalized_ = false;
    std::size_t   squeeze_pos_ = 0;
};

// SHAKE256(data, out) — FIPS 202 §6.2, arbitrary-length output.
void shake256(std::span<const std::uint8_t> data, std::span<std::uint8_t> out) noexcept;

// cSHAKE256(data, out, function_name, customization) — NIST SP 800-185 §3.
// Degrades to SHAKE256(data) when both N and S are empty (per the spec);
// this implementation takes that path explicitly rather than special-casing
// it, since every caller in this codebase passes a non-empty N or S.
void cshake256(std::span<const std::uint8_t> data, std::span<std::uint8_t> out,
               std::string_view function_name, std::string_view customization) noexcept;

// ── SP 800-185 §2.3 encoding primitives ─────────────────────────────────
// left_encode/right_encode/encode_string, byte-for-byte the definitions
// luxd's Go ports these from (network/kem/mlkem.go, luxfi/ids
// node_id_scheme.go) — both operate on a BIT length, which is why every
// call site below multiplies a byte count by 8 before encoding it.

[[nodiscard]] std::vector<std::uint8_t> left_encode(std::uint64_t x);
[[nodiscard]] std::vector<std::uint8_t> right_encode(std::uint64_t x);
[[nodiscard]] std::vector<std::uint8_t> encode_string(std::span<const std::uint8_t> s);

}  // namespace lux::node::keccak
