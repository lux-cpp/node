// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// ledger.hpp — what this node keeps on the device besides its keys and its
// journal: the certificate every block it accepted was accepted on, the import
// gate, and the block it last signed.
//
//   <data>/ledger       height ‖ block id ‖ certificate, one record per accepted
//                       height, synced BEFORE the chain is told to accept — a
//                       crash between leaves proof of a block never taken, which
//                       is harmless; the other order leaves a block this node
//                       can never prove to a peer that is behind. The first
//                       record of an imported chain is its ANCHOR: the imported
//                       tip and the certificate α validators made on it.
//   <data>/uncertified  the import gate (lux-rs/node src/gate.rs). Present, this
//                       node signs no block and builds none: its tip came off an
//                       export, and nothing a quorum said stands under it.
//                       Written and synced before the chain reads the export;
//                       removed, and the removal synced, only once a certificate
//                       stands on the tip.
//   <data>/held         the proposal this validator last signed a vote for,
//                       synced before the vote (lux-rs/node src/held.rs): a
//                       restart that finds itself bound at a height can offer
//                       the block again, and a height a whole committee restarted
//                       in the middle of can still be certified.

#pragma once

#include "lux/node/statement.hpp"

#include <cstdint>
#include <filesystem>
#include <map>
#include <optional>
#include <span>
#include <vector>

namespace lux::node {

struct Record {
    std::uint64_t height = 0;
    Id            block{};
    Certificate   cert;
};

class Ledger {
public:
    // Open (creating) `path` and index it. A torn final record is cut back.
    // Throws std::runtime_error when the file cannot be read or its heights do
    // not rise.
    [[nodiscard]] static Ledger open(const std::filesystem::path& path);
    ~Ledger();
    Ledger(Ledger&& o) noexcept;
    Ledger& operator=(Ledger&&)      = delete;
    Ledger(const Ledger&)            = delete;
    Ledger& operator=(const Ledger&) = delete;

    // Append a record above the last one, synced. Heights rise and are
    // consecutive except where an anchor starts a history this node did not
    // certify. False when it is not above the last, or did not reach the device.
    [[nodiscard]] bool append(const Record& r);

    [[nodiscard]] std::optional<Record> at(std::uint64_t height) const;

    // The last record's height and block.
    [[nodiscard]] std::optional<std::pair<std::uint64_t, Id>> last() const;

    [[nodiscard]] std::optional<std::uint64_t> first() const;

private:
    Ledger() = default;
    int                                  fd_ = -1;
    std::map<std::uint64_t, std::uint64_t> offsets_;  // height → file offset
    Id                                   last_block_{};
};

// The import gate.
[[nodiscard]] bool gated(const std::filesystem::path& data);
// Close it, synced. Throws std::runtime_error when it cannot.
void close_gate(const std::filesystem::path& data);
// Lift it, synced. False when the removal did not reach the device.
[[nodiscard]] bool lift_gate(const std::filesystem::path& data);

// A proposal: what a proposer signed and pushed. `from` is the link it arrived
// on, never part of the bytes.
struct Proposal {
    Node                      from{};
    std::uint64_t             height = 0;
    std::uint64_t             slot   = 0;
    std::vector<std::uint8_t> signature;  // ML-DSA-65, 3309 bytes
    std::vector<std::uint8_t> block;
};

// ZAP msg type 59, lux-rs/node mesh.rs BLOCK, and its bytes:
// version(1) ‖ height(u64 BE) ‖ slot(u64 BE) ‖ signature(3309) ‖ block.
inline constexpr std::uint8_t  kProposalMsgType = 59;
inline constexpr std::uint8_t  kProposalVersion = 1;
inline constexpr std::size_t   kProposalSignatureLen = 3309;
inline constexpr std::size_t   kProposalHead    = 1 + 8 + 8 + kProposalSignatureLen;
// A block is bounded by its gas limit: 12M gas buys ~750 KiB of calldata, so
// 2 MiB covers any block and refuses what could only be a lie. mesh.rs:139.
inline constexpr std::uint32_t kBlockMax = 2u * 1024u * 1024u;

[[nodiscard]] std::vector<std::uint8_t> encode(const Proposal& p);
[[nodiscard]] std::optional<Proposal>   decode_proposal(const Node& from, std::span<const std::uint8_t> payload);

// The held proposal: one, the last signed for. Written to a temporary, synced,
// renamed over, and the directory synced.
[[nodiscard]] bool                    keep_held(const std::filesystem::path& data, const Proposal& p);
[[nodiscard]] std::optional<Proposal> held(const std::filesystem::path& data);

}  // namespace lux::node
