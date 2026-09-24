// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// engine_test.cpp — what the engine asks of a chain, and what it does with a
// chain that says no.
//
// Go is the reference. engine/chain/engine.go rejects the losing block after a
// clean accept, exactly once, and DROPS a block that fails Verify instead ("built
// block failed verification — dropping"): it never entered consensus and took
// nothing. A BuildBlock error is logged and the height waits; it never stops the
// node. A chain in another process says no by refusing a call, and a refusal of
// a peer's bytes that ended the node would be a halt any peer could send.

#include "lux/consensus/threshold.hpp"
#include "lux/node/engine.hpp"
#include "lux/node/node_host.hpp"
#include "bls_signature.hpp"

#include <array>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <vector>

using namespace lux::node;
using namespace lux::consensus;

namespace {

int g_fail = 0;
void check(bool ok, const std::string& what) {
    std::printf("  %s  %s\n", ok ? "ok  " : "FAIL", what.c_str());
    if (!ok) ++g_fail;
}

// The engine's contract is about WHICH call it makes and when, so the VM under
// it is a tally rather than a chain: a real one would prove the C-Chain's
// bookkeeping a second time and say nothing more about the engine.

struct Tally {
    int accepted = 0;
    int rejected = 0;
};

class CountingBlock final : public Block {
public:
    CountingBlock(Tally* t, bool verifies) : t_(t), verifies_(verifies) {
        id_.fill(0x7c);
        root_.fill(0x5e);
        bytes_ = {0x7c};
    }
    Id                            id() const override { return id_; }
    Id                            parent() const override { return kEmptyId; }
    std::uint64_t                 height() const override { return 1; }
    std::span<const std::uint8_t> bytes() const override { return bytes_; }
    Id                            root() const override { return root_; }
    bool                          verify() override { return verifies_; }
    void                          accept() override { ++t_->accepted; }
    void                          reject() override { ++t_->rejected; }

private:
    Tally*                    t_;
    bool                      verifies_;
    Id                        id_{}, root_{};
    std::vector<std::uint8_t> bytes_;
};

class CountingVM final : public VM {
public:
    CountingVM(Tally* t, bool verifies) : t_(t), verifies_(verifies) {}
    Id          chain_id() const override { Id c{}; c.fill(0xc1); return c; }
    std::string alias() const override { return "T"; }
    std::shared_ptr<Block> build() override { return std::make_shared<CountingBlock>(t_, verifies_); }
    std::shared_ptr<Block> parse(std::span<const std::uint8_t>) override {
        return std::make_shared<CountingBlock>(t_, verifies_);
    }
    std::shared_ptr<Block> get(const Id&) const override { return nullptr; }
    void                   prefer(const Id&) override {}
    Id                     last_accepted() const override { return kEmptyId; }
    std::uint64_t          last_accepted_height() const override { return 0; }
    // Nothing was ever handed to this chain from outside, so its own decisions
    // reach its tip and the engine's gate has nothing to hold.
    std::uint64_t          frontier() const override { return 0; }

private:
    Tally* t_;
    bool   verifies_;
};

// One host out of a four-validator set — the committee floor — with nobody
// else up. A single key can never carry a two-thirds certificate over four, so
// this height CANNOT be decided: whether the wait ends at the deadline or at a
// certificate that will not verify, the engine gives the block up, and giving
// up is the thing under test.
constexpr std::uint32_t kN = 4;

std::unique_ptr<Node2Host> lone_host() {
    HostConfig cfg;
    std::vector<Validator> set;
    for (std::uint8_t i = 0; i < kN; ++i) {
        std::array<std::uint8_t, 32> seed{};
        seed[0] = std::uint8_t(0x5A + i);
        for (int j = 1; j < 32; ++j) seed[j] = std::uint8_t(0x3C ^ (i + j));
        std::array<std::uint8_t, 32> sk{};
        PubKey                       pk{};
        if (cevm::crypto::bls::keygen(seed.data(), sk.data()) != 0) { std::puts("keygen"); std::exit(2); }
        if (cevm::crypto::bls::sk_to_pk(sk.data(), pk.data()) != 0) { std::puts("sk_to_pk"); std::exit(2); }
        set.push_back({pk, 25});
        if (i == 0) { cfg.sk = sk; cfg.pk = pk; }
    }
    cfg.index      = 0;
    cfg.port       = 0;
    cfg.validators = set;
    cfg.wave       = WaveConfig{kN, two_thirds_count(kN), 2};
    cfg.accepted   = 0;
    auto h = std::make_unique<Node2Host>(std::move(cfg));
    h->listen_bind();
    return h;
}

// A chain in another process that refuses every build and every parse, the way
// a plugin with an empty pool, or one handed bytes it cannot read, answers.
class RefusingVM final : public VM {
public:
    Id          chain_id() const override { Id c{}; c.fill(0xc2); return c; }
    std::string alias() const override { return "T"; }
    std::shared_ptr<Block> build() override { throw std::runtime_error("build: no pending transactions"); }
    std::shared_ptr<Block> parse(std::span<const std::uint8_t>) override {
        throw std::runtime_error("parse: not a block");
    }
    std::shared_ptr<Block> get(const Id&) const override { return nullptr; }
    void                   prefer(const Id&) override {}
    Id                     last_accepted() const override { return kEmptyId; }
    std::uint64_t          last_accepted_height() const override { return 0; }
    std::uint64_t          frontier() const override { return 0; }
};

}  // namespace

int main() {
    std::printf("node — the engine and the chain under it\n\n");

    std::printf("a block the engine gives up on is rejected, and one it never voted for is not\n");
    {
        auto       host = lone_host();
        std::mutex guard;
        Tally      t;
        Engine     engine(std::make_unique<CountingVM>(&t, /*verifies=*/true), *host, guard);

        const auto d = engine.advance(/*deadline_ms=*/150);
        check(!d.has_value(), "one key out of four certifies nothing, so the height is given up");
        check(t.rejected == 1, "and the block it gave up on was rejected — exactly once");
        check(t.accepted == 0, "never accepted");
    }
    {
        auto       host = lone_host();
        std::mutex guard;
        Tally      t;
        Engine     engine(std::make_unique<CountingVM>(&t, /*verifies=*/false), *host, guard);

        const auto d = engine.advance(/*deadline_ms=*/150);
        check(!d.has_value(), "a block this node's own execution refuses is not proposed");
        check(t.rejected == 0, "and it is dropped, not rejected: it never entered consensus");
        check(t.accepted == 0, "and certainly not accepted");
    }

    std::printf("\na chain that says no\n");
    {
        auto       host = lone_host();
        std::mutex guard;
        Engine     engine(std::make_unique<RefusingVM>(), *host, guard);

        bool published = false;
        const auto d = engine.propose([&](std::span<const std::uint8_t>) { published = true; },
                                      /*deadline_ms=*/50);
        check(!d.has_value(), "a refused build proposes nothing this height, and the node goes on");
        check(!published, "and publishes nothing");

        const std::vector<std::uint8_t> junk{0xde, 0xad};
        check(!engine.follow(junk, /*deadline_ms=*/50).has_value(),
              "a peer's bytes the chain refuses are not voted for, and the node goes on");
    }

    std::printf("\n%s\n", g_fail ? "FAIL" : "PASS");
    return g_fail ? 1 : 0;
}
