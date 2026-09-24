// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// journal.hpp — what this validator has already signed, on disk, before it
// signs it. lux-rs/node src/journal.rs, the same file format.
//
// A validator makes ONE statement per slot — (chain, height, round), and this
// node only ever says round 0, so one per height (Go reserveSlotForSign,
// engine.go:2489; SlotKey{Height}, vote_guard.go:60). A second is
// equivocation. In one process a map is enough; across a restart it is not, and
// the network cannot tell amnesia from an attack. consensus::Party kept that map
// in memory; this is the durable one, and there is no other path to the key.
//
// WRITE FIRST, SIGN SECOND. `admit` appends and syncs to the device before the
// caller may sign. A crash between the two leaves a statement recorded that was
// never made, which costs one vote; the other order leaves one made that was
// never recorded, which costs the stake.
//
// THE RECORD IS THE SIGNED BYTES: each entry is one 226-byte message exactly as
// signed, and the slot is read back out of it by the same function a receiver
// uses (statement.hpp read). Both kinds a validator signs — a block vote and an
// anchor — share the layout and so share the slot: an anchor at T and a vote at
// T are one slot, and only one of them is ever admitted.
//
// Entries are fixed width, so a torn tail is arithmetic: a length that is not a
// multiple of 226 ends in a write that never completed, which under write-first
// is a statement never signed. It is cut back to the last whole entry. Two whole
// entries that disagree at one slot are corruption, not a crash, and the file is
// refused rather than half-believed. The file is 0600 and held under an
// exclusive flock: two processes signing from one record would each believe the
// other's statements were never made.

#pragma once

#include "lux/node/statement.hpp"

#include <filesystem>
#include <map>
#include <optional>

namespace lux::node {

class Journal {
public:
    // Open (creating) the journal at `path` and read it back. Throws
    // std::runtime_error when another process holds it, when it cannot be read,
    // or when it holds a message this network disowns or two at one slot.
    [[nodiscard]] static Journal open(const std::filesystem::path& path);
    ~Journal();
    Journal(Journal&& o) noexcept;
    Journal& operator=(Journal&&) = delete;
    Journal(const Journal&)            = delete;
    Journal& operator=(const Journal&) = delete;

    enum class Admit {
        Ok,              // on the device; sign it
        NotAStatement,   // not a message this network signs
        Equivocation,    // a different statement stands at this slot
        NotDurable,      // did not reach the device; do not sign
    };

    // Admit `m`, or refuse it. The identical message admitted twice is Ok: a
    // signer that crashed after recording has to be able to send what it
    // recorded.
    [[nodiscard]] Admit admit(const Message& m);

    // What this validator stands by at `slot`, if anything.
    [[nodiscard]] std::optional<Message> standing(const Slot& slot) const;

    // A failed write that could not be cut back: nothing more is written until a
    // reopen reads the file back whole.
    [[nodiscard]] bool broken() const noexcept { return broken_; }

    [[nodiscard]] std::size_t size() const noexcept { return said_.size(); }

private:
    Journal() = default;
    int                     fd_ = -1;
    std::map<Slot, Message> said_;
    bool                    broken_ = false;
};

}  // namespace lux::node
