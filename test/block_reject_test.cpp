// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// block_reject_test.cpp — a block that is not accepted gives its transactions
// back, and the engine is what asks it to.
//
// THE BUG THIS PINS. The seam used to have accept() and nothing else, so a
// chain could only ever be told about the half of a decision that went its way.
// The daemon's height loop retries a height it could not certify (noded.cpp:
// "timeout — retrying") and the C-Chain's build() swaps the WHOLE mempool into
// the block it builds, so one uncertified height emptied this node's pool while
// every peer still held those transactions. The node then proposed a block
// built from that disagreement — and the transactions were gone for good, since
// `seen` remembers a hash forever and re-submitting one is a no-op.
//
// GO IS THE REFERENCE, and it says this in three places:
//   platformvm block/executor/rejector.go — free the block's pinned state,
//     reissue its decision txs to the mempool, wake the builder.
//   xvm block/executor/block.go Reject     — free the state, ask each tx again
//     against the state that won, reissue the ones that still hold.
//   engine/chain/engine.go                 — Reject is called on the losing
//     subtree AFTER a clean accept, exactly once per block; a block that FAILS
//     Verify is dropped instead ("built block failed verification — dropping"),
//     never rejected, because it never entered consensus and took nothing.
// Both halves of that last sentence are asserted here.
//
// THE TRANSACTIONS ARE REAL. Two EIP-155 legacy transactions, signed offline
// for chain 31337 by 0x913e0e315432c446261dd1736c729d899c4a537a. Nothing here
// asserts the sender: Chain::accept_tx recovers it with secp256k1 and refuses
// anything it cannot, so the pool accepting them IS the proof they are genuine.

#include "lux/consensus/threshold.hpp"
#include "lux/node/engine.hpp"
#include "lux/node/evm.hpp"
#include "lux/node/node_host.hpp"
#include "bls_signature.hpp"

#include <array>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <mutex>
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

// ── the two signed transactions ─────────────────────────────────────────────

const std::vector<std::uint8_t> kTx0{
    0xf8, 0x66, 0x80, 0x01, 0x82, 0x52, 0x08, 0x94, 0x70, 0x99, 0x79, 0x70, 0xc5, 0x18, 0x12, 0xdc,
    0x3a, 0x01, 0x0c, 0x7d, 0x01, 0xb5, 0x0e, 0x0d, 0x17, 0xdc, 0x79, 0xc8, 0x87, 0x03, 0x8d, 0x7e,
    0xa4, 0xc6, 0x80, 0x00, 0x80, 0x82, 0xf4, 0xf6, 0xa0, 0x51, 0x59, 0x93, 0x06, 0xac, 0xed, 0x09,
    0x2e, 0xb4, 0x9d, 0xd3, 0x8d, 0x04, 0x32, 0x1a, 0xa9, 0xe8, 0xae, 0x9d, 0xfb, 0x7a, 0x1b, 0xb1,
    0x88, 0x93, 0x23, 0x9a, 0xa5, 0x33, 0xf9, 0x73, 0x06, 0x9e, 0xd5, 0x45, 0x5a, 0x7b, 0x90, 0x1e,
    0x5c, 0x21, 0x30, 0xad, 0x2a, 0x7c, 0xee, 0x4d, 0x79, 0xfc, 0xaf, 0x34, 0x9f, 0x1b, 0xfe, 0x37,
    0x17, 0x08, 0x36, 0x8a, 0x1d, 0xfb, 0x54, 0x31};

const std::vector<std::uint8_t> kTx1{
    0xf8, 0x68, 0x01, 0x01, 0x82, 0x52, 0x08, 0x94, 0x70, 0x99, 0x79, 0x70, 0xc5, 0x18, 0x12, 0xdc,
    0x3a, 0x01, 0x0c, 0x7d, 0x01, 0xb5, 0x0e, 0x0d, 0x17, 0xdc, 0x79, 0xc8, 0x87, 0x03, 0x8d, 0x7e,
    0xa4, 0xc6, 0x80, 0x00, 0x80, 0x82, 0xf4, 0xf5, 0xa0, 0x7c, 0x70, 0x16, 0x35, 0x15, 0xc0, 0xdc,
    0x70, 0xc6, 0xe5, 0xfb, 0x89, 0x36, 0xc9, 0x76, 0x36, 0x97, 0x7d, 0x43, 0xdc, 0x02, 0x05, 0x0d,
    0x08, 0x14, 0xc5, 0x8c, 0xb6, 0x13, 0xa2, 0x91, 0xbe, 0xa0, 0x12, 0x3f, 0x4b, 0x97, 0xf6, 0x8e,
    0x18, 0xcb, 0x31, 0x0f, 0xac, 0xb1, 0xe5, 0x4c, 0x1b, 0x9e, 0x4a, 0xaa, 0x63, 0xb3, 0x1f, 0x27,
    0x01, 0xda, 0xe4, 0x20, 0xad, 0xad, 0xb3, 0x05, 0x77, 0xe4};

// The sender of both, funded in genesis so the block executes rather than
// reverting for want of a balance.
const evm::Address kSender{0x91, 0x3e, 0x0e, 0x31, 0x54, 0x32, 0xc4, 0x46, 0x26, 0x1d,
                           0xd1, 0x73, 0x6c, 0x72, 0x9d, 0x89, 0x9c, 0x4a, 0x53, 0x7a};

evm::Chain funded_chain() {
    evm::Genesis g;
    g.chain_id  = 31337;
    g.gas_limit = 30'000'000;
    evm::Word balance{};
    balance[23] = 0x01;  // 2^64 wei, far more than both transfers and their gas
    g.alloc.emplace_back(kSender, balance);
    return evm::Chain(std::move(g));
}

bool pool_holds(const evm::Chain& c, const std::vector<std::uint8_t>& raw) {
    for (const auto& p : c.pending_raw())
        if (p == raw) return true;
    return false;
}

// ── a chain that only counts, for the engine half ───────────────────────────
//
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

}  // namespace

int main() {
    std::printf("node — a rejected block gives its transactions back\n\n");

    // ── the C-Chain ─────────────────────────────────────────────────────────
    std::printf("Chain: build takes the pool, reject returns it\n");
    {
        auto chain = funded_chain();
        check(chain.accept_tx(kTx0).has_value() && chain.accept_tx(kTx1).has_value(),
              "two signed transactions are admitted (their senders recover)");
        check(chain.pending() == 2, "and both are waiting");

        auto blk = chain.build();
        check(blk != nullptr, "a block is built over them");
        check(chain.pending() == 0, "which empties the pool — build() swaps it whole into the block");
        const auto id = blk->id();
        check(chain.get(id) != nullptr, "and the block is pinned while it is undecided");

        blk->reject();
        check(chain.pending() == 2, "rejecting it returns BOTH transactions to the pool");
        check(pool_holds(chain, kTx0) && pool_holds(chain, kTx1),
              "byte for byte the same transactions, not re-encodings of them");
        check(chain.get(id) == nullptr, "and the block is freed — nothing may build on it (Go: free)");

        blk->reject();
        check(chain.pending() == 2, "rejecting twice returns them once (decided is decided)");

        // The transactions are back and USABLE: the next height mines them, which
        // is the whole point of handing them back rather than merely counting them.
        auto next = chain.build();
        check(next != nullptr && chain.pending() == 0, "the next block picks them up again");
        next->accept();
        check(chain.pending() == 0, "accepting it retires them");
        check(chain.last_accepted_height() == 1, "and the tip moved exactly one height");

        next->reject();
        check(chain.last_accepted_height() == 1 && chain.pending() == 0,
              "a reject after the accept is inert — it cannot un-mine what was accepted");
    }

    // A followed block's transactions arrived by gossip and were never taken
    // out of the pool, so rejecting one must not leave a second copy behind: the
    // same transaction twice in a pool is the same transaction twice in a block.
    std::printf("\nChain: a rejected block never duplicates what is still waiting\n");
    {
        auto chain = funded_chain();
        chain.accept_tx(kTx0);
        auto blk = chain.build();          // takes it
        chain.accept_tx_from_peer(kTx1);   // arrives while the block is in flight
        check(chain.pending() == 1, "one transaction waiting beside the block in flight");
        blk->reject();
        check(chain.pending() == 2, "reject adds only what it took");
        check(pool_holds(chain, kTx0) && pool_holds(chain, kTx1), "and both are there, once each");
    }

    // ── the engine ──────────────────────────────────────────────────────────
    //
    // A seam nobody calls is the same bug one level up, so this half asks the
    // engine rather than the chain.
    std::printf("\nEngine: a block it gives up on is rejected, and one it never voted for is not\n");
    {
        auto        host = lone_host();
        std::mutex  guard;
        Tally       t;
        Engine      engine(std::make_unique<CountingVM>(&t, /*verifies=*/true), *host, guard);

        const auto d = engine.advance(/*deadline_ms=*/150);
        check(!d.has_value(), "one key out of four certifies nothing, so the height is given up");
        check(t.rejected == 1, "and the block it gave up on was rejected — exactly once");
        check(t.accepted == 0, "never accepted");
    }
    {
        auto        host = lone_host();
        std::mutex  guard;
        Tally       t;
        Engine      engine(std::make_unique<CountingVM>(&t, /*verifies=*/false), *host, guard);

        const auto d = engine.advance(/*deadline_ms=*/150);
        check(!d.has_value(), "a block this node's own execution refuses is not proposed");
        check(t.rejected == 0,
              "and it is DROPPED, not rejected — it never entered consensus, so it holds "
              "nothing to give back (Go: \"built block failed verification — dropping\")");
        check(t.accepted == 0, "and certainly not accepted");
    }

    std::printf("\n%s\n",
                g_fail ? "FAIL"
                       : "PASS — reject is on the seam, the engine calls it, and the pool survives "
                         "a height that did not certify");
    return g_fail ? 1 : 0;
}
