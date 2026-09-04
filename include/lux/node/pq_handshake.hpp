// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// pq_handshake.hpp — the strict-PQ application-layer handshake luxd's
// network/peer/handshake.go runs immediately after the TLS 1.3
// (X25519+ML-KEM-768) session completes: ML-KEM-768 + ML-DSA-65, INIT then
// RESP, binding a validator identity to the link and deriving a session
// AEAD key. Ported field-for-field and byte-for-byte from that file's own
// doc comment and implementation — this is the SECOND PQ layer, distinct
// from (and running on top of) the TLS group negotiation `peer_tls.hpp`
// already does.
//
// THIS LAYER IS NOT OPTIONAL ON THIS NETWORK. Verified empirically: a
// bare-TLS peer (this crate's own classical p2p Handshake, sent without
// this exchange first) completed the TLS 1.3 X25519MLKEM768 session six
// times against a live luxd and was closed immediately after every time —
// `network/network.go`'s security-profile resolution defaults to
// STRICT_E2E_PQ whenever no genesis pin says otherwise (a hardening change
// since node.rs's original proof, which ran classical-compat). See LLM.md.
//
// Why a NodeID derivation SEPARATE from `staking.hpp`'s: the classical
// NodeID (hash160 of the TLS certificate) and this one (SHAKE256 of the
// ML-DSA-65 public key, domain "NODE_ID_V1") answer the same QUESTION for
// two different WIRES. `verifyPQIdentityBinding` on luxd's side replaces a
// peer's TLS-cert NodeID with this key-derived one the moment the PQ
// handshake completes — so the NodeID this validator is tracked under, once
// this handshake succeeds, is `pq::derive_node_id`'s output, not
// `staking::Identity::node_id()`.

#pragma once

#include <array>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace lux::node::pq {

// The wire byte for ML-KEM-768 (network/kem.KeyExchangeMLKEM768) and the
// profile byte for strict-PQ (network/peer.ProfileStrictPQ) — the two
// values this port sends and expects echoed. Named so a call site reads as
// policy, not a magic number.
inline constexpr std::uint8_t kKEMSchemeMLKEM768 = 0x01;
inline constexpr std::uint8_t kProfileStrictPQ    = 0x01;
inline constexpr std::uint8_t kProtocolVersionV1  = 0x01;

// This validator's post-quantum identity: an ML-DSA-65 keypair, persisted
// (mode 0600) exactly like `staking::Identity`'s BLS key — regenerating it
// would be a different validator on every restart, which a genesis or a
// peer that has already bound this NodeID would not forgive.
class Identity {
public:
    static Identity open(const std::filesystem::path& dir);

    [[nodiscard]] const std::vector<std::uint8_t>& public_key() const noexcept { return pk_; }
    [[nodiscard]] const std::vector<std::uint8_t>& secret_key() const noexcept { return sk_; }
    [[nodiscard]] const std::array<std::uint8_t, 20>& node_id() const noexcept { return node_id_; }

private:
    std::vector<std::uint8_t>    pk_, sk_;
    std::array<std::uint8_t, 20> node_id_{};
};

// SHAKE256("NODE_ID_V1" ‖ chain_id ‖ scheme ‖ pubkey), SP 800-185
// left_encode-framed per field, first 20 of 48 output bytes — luxfi/ids
// `NodeIDScheme.DeriveMLDSA`. `chain_id` is `ids.Empty` (all-zero) for a
// node's own primary identity, which is what this handshake binds.
[[nodiscard]] std::array<std::uint8_t, 20> derive_node_id(std::span<const std::uint8_t> mldsa_pub,
                                                           const std::array<std::uint8_t, 32>& chain_id = {});

// What a completed handshake proves and produces. `ok == false` means the
// link must be dropped — there is no partial-trust state in this protocol.
struct Outcome {
    bool                          ok = false;
    std::string                   error;
    std::array<std::uint8_t, 20>  peer_node_id{};
    std::vector<std::uint8_t>     peer_mldsa_pub;
    std::array<std::uint8_t, 32>  aead_key{};  // derived, not yet consumed — see LLM.md
};

// Runs the FULL initiator side over an already-open, already-TLS-upgraded
// byte stream: builds and signs INIT, writes it framed, reads and verifies
// framed RESP, decapsulates, derives the transcript and AEAD key, and
// checks the responder's NodeID<->key binding. `write_frame`/`read_frame`
// are injected so this stays transport-agnostic (bound to
// `peer_tls::Connection` at the one call site in peer.cpp) and directly
// unit-testable against canned bytes.
//
// `chain_id` matches what luxd's own `peer.HandshakeConfig` sends — the
// primary-network peer handshake leaves it at the zero value, not the
// chain this validator will vote on, so the default is correct for that
// link and callers should not pass a chain id "to be safe".
Outcome run_initiator(const Identity& id,
                      const std::function<void(std::span<const std::uint8_t>)>& write_frame,
                      const std::function<std::vector<std::uint8_t>()>& read_frame,
                      const std::array<std::uint8_t, 32>& chain_id = {});

}  // namespace lux::node::pq
