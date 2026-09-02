// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco

#include "lux/node/engine.hpp"

#include <chrono>
#include <mutex>
#include <thread>

namespace lux::node {

Engine::Engine(std::unique_ptr<VM> vm, Node2Host& host, std::mutex& guard)
    : vm_(std::move(vm)), host_(host), guard_(guard) {}

lux::consensus::VotePosition Engine::position(const Block& b) const {
    lux::consensus::VotePosition pos{};
    pos.chain_id  = vm_->chain_id();
    pos.height    = b.height();
    pos.round     = 1;

    // Transport identity — what a peer used to name the block.
    pos.block_id  = b.id();
    pos.parent_id = b.parent();

    // Canonical (signed) identity. There is no proposervm envelope here, so the
    // canonical axes ARE the transport ones — the degrade Go applies when a VM
    // does not implement canonicalCommitter, applied explicitly rather than left
    // to a type assertion.
    pos.canonical_id        = b.id();
    pos.parent_canonical_id = b.parent();

    // The axis this whole exercise is about: the root THIS node's execution
    // produced, put into the message this node signs.
    pos.execution_state_root = b.root();

    // payload_root stays empty, and deliberately so. It would have to be a
    // transactions root every implementation computes identically, and inventing
    // one here that only this node computes would be a second identity for a
    // block rather than a shared one. Empty is signed consistently as empty.
    return pos;
}

std::optional<Decided> Engine::settle(const std::shared_ptr<Block>& blk, int deadline_ms,
                                      const std::function<void()>& after_submit) {
    if (!blk) return std::nullopt;

    // An honest node does not vote for a block its own execution rejected. This
    // is where a peer's claimed root, having disagreed with ours, stops.
    if (!blk->verify()) return std::nullopt;

    const auto pos = position(*blk);
    host_.submit(pos);
    if (after_submit) after_submit();

    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(deadline_ms);
    while (!host_.isFinal(pos.block_id)) {
        host_.round(pos.block_id);  // β-confirmation rounds → sign + broadcast once decided
        host_.pump();               // drain peers' votes into the gate
        if (std::chrono::steady_clock::now() >= deadline) return std::nullopt;
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }

    // Certified ⇒ decided. accept() takes the witness AND advances the
    // decided-height frontier, so this validator can never sign a sibling here.
    auto cert = host_.accept(pos);
    if (!cert) return std::nullopt;

    // Only now does the chain's tip move: the VM is told the block was decided,
    // by a certificate, after that certificate verified. This is a write to the
    // chain, so it — and not the wait above it — is what takes the lock.
    {
        const std::lock_guard<std::mutex> lock(guard_);
        blk->accept();
    }
    return Decided{blk, *cert};
}

std::optional<Decided> Engine::decide(const std::shared_ptr<Block>& blk, int deadline_ms) {
    return settle(blk, deadline_ms, nullptr);
}

std::optional<Decided> Engine::propose(
    const std::function<void(std::span<const std::uint8_t>)>& publish, int deadline_ms) {
    std::shared_ptr<Block> blk;
    {
        const std::lock_guard<std::mutex> lock(guard_);
        blk = vm_->build();
    }
    if (!blk) return std::nullopt;
    // Registered by settle(), published immediately after — in that order.
    return settle(blk, deadline_ms, [&] { publish(blk->bytes()); });
}

std::optional<Decided> Engine::advance(int deadline_ms) {
    return propose([](std::span<const std::uint8_t>) {}, deadline_ms);
}

std::optional<Decided> Engine::follow(std::span<const std::uint8_t> bytes, int deadline_ms) {
    // Parsing IS executing, so it is a call into the VM and takes the lock.
    // Deciding, below it, does not.
    std::shared_ptr<Block> blk;
    {
        const std::lock_guard<std::mutex> lock(guard_);
        blk = vm_->parse(bytes);
    }
    return settle(blk, deadline_ms, nullptr);
}

}  // namespace lux::node
