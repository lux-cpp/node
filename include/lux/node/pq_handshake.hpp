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
// WHETHER THIS LAYER RUNS IS A PROPERTY OF THE CHAIN, NOT OF THE PEER, and
// the two answers are not interchangeable. `network/network.go`'s
// `profileRequiresPQHandshake` runs it for `ProfileStrictPQ` and
// `ProfileFIPS` and skips it entirely otherwise; a node whose genesis
// carries no `securityProfile.json` pin boots classical-compat
// (`node/node.go`'s `applySecurityProfile`). Guessing either way desyncs the
// link on its first frame. Sent to a permissive peer, a 6512-byte INIT is
// read as a p2p frame whose tag byte is 0x01, CompressedZstd, and fails to
// decompress; withheld from a strict-PQ peer, the p2p Handshake frame is
// read as an INIT whose first byte is the tag 0x04 and fails
// `ErrHandshakeBadVersion`. Both end in an immediate close, which is the
// observation behind the earlier note here that bare TLS "was closed every
// time" — true, and true for the same reason in reverse. So the axis is a
// parameter of `peer::Peer::connect`, never a default in this file. The
// shipped pins are strict-PQ for mainnet, testnet and local/localnet, and
// permissive for devnet.
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
#include <string_view>
#include <vector>

namespace lux::node::pq {

// The wire byte for ML-KEM-768 (network/kem.KeyExchangeMLKEM768) and the
// profile byte for strict-PQ (network/peer.ProfileStrictPQ) — the two
// values this port sends and expects echoed. Named so a call site reads as
// policy, not a magic number.
inline constexpr std::uint8_t kKEMSchemeMLKEM768 = 0x01;
inline constexpr std::uint8_t kProfileStrictPQ    = 0x01;
inline constexpr std::uint8_t kProtocolVersionV1  = 0x01;

// THE ROLE IS PART OF THE SIGNED MESSAGE, and that is the whole of the replay
// argument: without it a responder's signature is a well-formed initiator's
// signature over the same bytes. The version is in there for the same reason,
// one protocol version ahead.
inline constexpr std::string_view kContextInitiator = "NODE_PQ_HANDSHAKE_V1/initiator";
inline constexpr std::string_view kContextResponder = "NODE_PQ_HANDSHAKE_V1/responder";

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

// ── Framing (network/peer/pq_frame.go) ──────────────────────────────────
// One INIT or RESP goes on the wire as a 4-byte big-endian length and that
// many bytes, with no tag. It is the same shape the p2p wire uses and a
// different rule: p2p counts its tag byte in the length and caps at 2 MiB,
// this counts nothing extra and caps at 16 KiB. The largest legitimate
// frame is 6896 bytes (ML-KEM-1024 INIT), so the cap refuses an allocation
// a stranger asked for before making it.
inline constexpr std::uint32_t kFrameMax = 16u * 1024u;

// The bytes to write for one message. Throws if the payload is over the cap.
[[nodiscard]] std::vector<std::uint8_t> frame(std::span<const std::uint8_t> payload);
// How many bytes follow a frame header. Throws if the peer announced more
// than the cap — refused before the buffer is allocated, as Go refuses it.
[[nodiscard]] std::uint32_t body_size(std::span<const std::uint8_t, 4> header);

// ── The key schedule (network/peer/handshake.go, network/kem/mlkem.go) ──
// Three functions because Go has three, and because the concatenation
// order below is the part of this protocol that no two-C++-ends test can
// check: both sides would agree on the same wrong bytes. Each is a value a
// known-answer test pins against the Go implementation directly.

// `bindAEADTranscript`: the two wire messages, then profile, chain id and
// both identity keys again. The repetition is Go's and is deliberate — a
// disagreement about profile or chain surfaces here even if the encoding of
// either message drifted. Note that `resp_canonical` is the RESPONSE ALONE,
// which is not the same byte string the responder signs (that one carries
// the whole INIT in front of it).
[[nodiscard]] std::vector<std::uint8_t> bind_transcript(std::span<const std::uint8_t> init_canonical,
                                                        std::span<const std::uint8_t> resp_canonical,
                                                        std::uint8_t profile,
                                                        const std::array<std::uint8_t, 32>& chain_id,
                                                        std::span<const std::uint8_t> init_mldsa_pub,
                                                        std::span<const std::uint8_t> resp_mldsa_pub);

// `kem.HashTranscript`: SP 800-185 TupleHash256 with customization
// "NODE_TRANSCRIPT_V1", over ONE tuple element — the arity every call site
// in the peer handshake uses, so the general N-ary form is not reproduced.
[[nodiscard]] std::array<std::uint8_t, 48> transcript_hash(std::span<const std::uint8_t> transcript);

// `KEMSession.DeriveAEADKey`: cSHAKE256(N="KEMDerive", S="NODE_AEAD_V1")
// over the scheme byte, the raw KEM secret and the transcript hash.
[[nodiscard]] std::array<std::uint8_t, 32> aead_key(std::uint8_t scheme,
                                                    const std::array<std::uint8_t, 32>& shared_secret,
                                                    const std::array<std::uint8_t, 48>& transcript);

// What a completed handshake proves and produces. `ok == false` means the
// link must be dropped — there is no partial-trust state in this protocol.
struct Outcome {
    bool                          ok = false;
    std::string                   error;
    std::array<std::uint8_t, 20>  peer_node_id{};
    std::vector<std::uint8_t>     peer_mldsa_pub;
    // Derived, and deliberately not consumed: luxd stores this on the peer
    // as `pqAEADKey` and encrypts nothing with it, so post-handshake p2p
    // frames are plaintext inside TLS on both sides. Its value still
    // matters — two ends that derived different keys disagreed about the
    // transcript, which is what makes it worth returning and asserting on.
    std::array<std::uint8_t, 32>  aead_key{};
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
