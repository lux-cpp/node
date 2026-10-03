// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// engine_test.cpp — one validator against a peer the test scripts.
//
// live_test proves validators converge; this proves what one of them refuses,
// each against a control that shows the refusal is the thing being tested:
//
//   - a proposal signed for a window that is not its signer's is never parsed —
//     the chain is not shown a byte of it — while the same signer's proposal in
//     its own window is parsed, executed and relayed;
//   - a block the chain refuses is never signed;
//   - a node whose tip came off an export builds nothing in its own windows and
//     signs nothing but its anchor, where the same node without the gate builds;
//   - a chain that refuses to build does not stop the node;
//   - a gated node lifts its gate on a vote certificate at its own tip, and not
//     on one for another block there;
//   - a parent with a stale time opens no slot further than kReach windows
//     back of this validator's own clock.

#include "fake_chain.hpp"
#include "lux/node/engine.hpp"
#include "lux/node/host.hpp"
#include "lux/node/journal.hpp"
#include "lux/node/signer.hpp"
#include "lux/zap/wire.hpp"

#include <chrono>
#include <cstdio>
#include <filesystem>
#include <functional>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include <unistd.h>

using namespace lux::node;
using namespace std::chrono_literals;

namespace {

int g_fail = 0;
void check(bool ok, const std::string& what) {
    std::printf("  %s  %s\n", ok ? "ok  " : "FAIL", what.c_str());
    if (!ok) ++g_fail;
}

constexpr auto          kWindow = 300ms;
constexpr std::uint64_t kTip    = 799;

Id filled(std::uint8_t b) {
    Id id{};
    id.fill(b);
    return id;
}

// A chain that says no to building, in the way a chain in another process does:
// the call fails.
class Refusing final : public VM {
public:
    explicit Refusing(std::shared_ptr<test::Store> s) : inner_(std::move(s)) {}
    Id                     chain_id() const override { return {}; }
    std::string            alias() const override { return "test"; }
    std::shared_ptr<Block> build() override {
        ++calls;
        throw std::runtime_error("build: the chain is not ready");
    }
    std::shared_ptr<Block> parse(std::span<const std::uint8_t> b) override { return inner_.parse(b); }
    std::shared_ptr<Block> get(const Id& id) const override { return inner_.get(id); }
    void                   prefer(const Id&) override {}
    Id                     last_accepted() const override { return inner_.last_accepted(); }
    std::uint64_t          last_accepted_height() const override { return inner_.last_accepted_height(); }
    int                    calls = 0;

private:
    test::FakeChain inner_;
};

// A validator under test (seat 0) and a scripted peer (seat 1) in a committee
// of four, the two linked over a real loopback socket.
struct Rig {
    std::filesystem::path                 root;
    Id                                    chain = filled(0x2c);
    std::vector<std::unique_ptr<Signer>>  signers;
    Committee                             committee;
    std::shared_ptr<test::Store>          store;
    std::unique_ptr<Host>                 host, peer;
    std::mutex                            guard;
    std::unique_ptr<Engine>               engine;
    VM*                                   vm = nullptr;

    Rig(const std::string& name, bool gate, std::function<std::unique_ptr<VM>(std::shared_ptr<test::Store>)> make = {}) {
        root = std::filesystem::temp_directory_path() / ("node-engine-" + std::to_string(::getpid()) + "-" + name);
        std::filesystem::remove_all(root);
        std::string text;
        for (int i = 0; i < 4; ++i) {
            signers.push_back(std::make_unique<Signer>(Signer::open(root / ("v" + std::to_string(i)))));
            text += signers.back()->publish(chain) + "\n";
        }
        committee = Committee::read(text, chain);
        store     = test::Store::imported(filled(0x79), kTip, 1747000000);
        if (gate) close_gate(root / "v0");

        auto link = [this](std::uint32_t i) {
            Link l;
            l.me    = signers[i]->identity();
            l.chain = chain;
            l.seat  = [this](const Node& who) -> std::optional<std::uint32_t> {
                const auto at = committee.seat(who);
                if (!at) return std::nullopt;
                return std::uint32_t(*at);
            };
            return l;
        };
        HostConfig a;
        a.index = 0;
        a.link  = link(0);
        host    = std::make_unique<Host>(std::move(a));
        HostConfig b;
        b.index = 1;
        b.link  = link(1);
        peer    = std::make_unique<Host>(std::move(b));
        const auto pa = host->listen_bind();
        const auto pb = peer->listen_bind();
        std::thread t([&] { peer->connect_mesh({{0, {"127.0.0.1", pa}}}, 2000); });
        host->connect_mesh({{1, {"127.0.0.1", pb}}}, 2000);
        t.join();

        EngineConfig ec;
        ec.committee = committee;
        ec.self      = signers[0]->node();
        ec.sk        = signers[0]->secret();
        ec.identity  = signers[0]->identity();
        ec.chain     = chain;
        ec.binding   = Binding::Transport;
        ec.window    = kWindow;
        ec.data      = root / "v0";
        auto chainp  = make ? make(store) : std::make_unique<test::FakeChain>(store);
        vm           = chainp.get();
        engine       = std::make_unique<Engine>(std::move(chainp), *host, guard, std::move(ec));
    }
    ~Rig() {
        engine.reset();
        host.reset();
        peer.reset();
        std::filesystem::remove_all(root);
    }

    // Drive the engine for `d`, draining what reaches the peer.
    std::vector<Event> run(std::chrono::milliseconds d) {
        std::vector<Event> events;
        const auto         end = std::chrono::steady_clock::now() + d;
        while (std::chrono::steady_clock::now() < end) {
            auto s = engine->step();
            events.insert(events.end(), s.events.begin(), s.events.end());
            peer->pump();
            std::this_thread::sleep_for(1ms);
        }
        return events;
    }

    // A proposal the peer (seat 1) signs at `slot`, of a block on `parent`.
    Proposal proposal(std::uint64_t slot, const Id& parent, std::uint64_t nonce) {
        std::vector<std::uint8_t> b{'F', 'A', 'K', 'E'};
        b.insert(b.end(), parent.begin(), parent.end());
        for (std::uint64_t v : {kTip + 1, std::uint64_t(1747000100), nonce})
            for (int s = 56; s >= 0; s -= 8) b.push_back(std::uint8_t(v >> s));
        Proposal p;
        p.height = kTip + 1;
        p.slot   = slot;
        p.block  = b;
        const auto header = proposal_header(chain, committee.root(), store->tip, p.height, slot,
                                            signers[1]->identity().public_key(), b);
        p.signature = pq::sign(signers[1]->identity().secret_key(), kProposalContext, header);
        return p;
    }

    // The first slot at the next height whose proposer is (or is not) seat `i`.
    std::uint64_t slot_of(std::uint32_t i, bool is) const {
        for (std::uint64_t s = 0;; ++s)
            if ((engine->proposer(kTip + 1, s) == committee.members()[i].node) == is) return s;
    }
};

}  // namespace

int main() {
    std::printf("============= node — the engine, one validator at a time =============\n\n");

    // [1] Whose window a proposal is in decides whether it is looked at.
    {
        Rig        r("windows", false);
        const auto theirs = r.slot_of(1, true);
        const auto others = r.slot_of(1, false);
        // The engine under test takes its own windows too; its store has
        // nothing to build, so the only block at the height is the peer's.
        r.store->pending = false;
        r.run(50ms);
        r.peer->gossip(kProposalMsgType, encode(r.proposal(others, r.store->tip, 1)));
        r.run(3 * kWindow);
        check(r.store->parses == 0, "[1] a proposal signed for a window that is not its signer's is never parsed");
        r.peer->gossip(kProposalMsgType, encode(r.proposal(theirs, r.store->tip, 2)));
        r.run(3 * kWindow);
        check(r.store->parses == 1 && r.store->verifies >= 1,
              "[1] the signer's own window: parsed and executed");
    }

    // [2] A block the chain refuses is never signed.
    {
        Rig r("refused", false);
        r.store->pending = false;
        const auto theirs = r.slot_of(1, true);
        r.run(50ms);
        // On a parent that is not the tip: the chain refuses it.
        r.peer->gossip(kProposalMsgType, encode(r.proposal(theirs, filled(0x13), 3)));
        const auto events = r.run(4 * kWindow);
        bool       said   = false;
        for (const auto& e : events) said = said || e.text.find("proposer") != std::string::npos;
        check(r.store->parses == 1, "[2] a correctly signed proposal is parsed");
        check(said, "[2] and the refusal is said once");
        r.engine.reset();
        auto j = Journal::open(r.root / "v0" / "votes");
        check(j.size() == 0, "[2] and nothing was signed for it");
        // control: the same proposal on the tip is signed.
        Rig c("refused-control", false);
        c.store->pending = false;
        const auto s = c.slot_of(1, true);
        c.run(50ms);
        c.peer->gossip(kProposalMsgType, encode(c.proposal(s, c.store->tip, 4)));
        c.run(4 * kWindow);
        c.engine.reset();
        auto k = Journal::open(c.root / "v0" / "votes");
        check(k.size() == 1, "[2] control: the same block on the tip is signed, once");
    }

    // [3] A gated node builds nothing in its own windows and signs only its
    // anchor; the same node ungated builds.
    {
        Rig        g("gated", true);
        const auto mine = g.slot_of(0, true);
        g.run(kWindow * std::int64_t(mine + 3));
        check(g.store->builds == 0, "[3] a gated node builds nothing, its own window included");
        check(!g.engine->caught_up(), "[3] and says it is not caught up");
        g.engine.reset();
        auto j      = Journal::open(g.root / "v0" / "votes");
        const auto a = j.standing(Slot{g.chain, kTip, 0});
        check(j.size() == 1 && a && read(*a) && read(*a)->kind == Kind::Anchor && read(*a)->block == g.store->tip,
              "[3] its journal holds one statement: the anchor on its imported tip");

        Rig        c("gated-control", false);
        const auto m = c.slot_of(0, true);
        c.run(kWindow * std::int64_t(m + 3));
        check(c.store->builds >= 1, "[3] control: ungated, the same node builds in its window");
    }

    // [4] A chain that refuses to build does not stop the node.
    {
        Refusing* refusing = nullptr;
        Rig       r("refusing", false, [&](std::shared_ptr<test::Store> s) {
            auto v   = std::make_unique<Refusing>(std::move(s));
            refusing = v.get();
            return v;
        });
        const auto mine   = r.slot_of(0, true);
        const auto events = r.run(kWindow * std::int64_t(mine + 3));
        bool       said   = false;
        for (const auto& e : events) said = said || e.text.find("building") != std::string::npos;
        check(refusing->calls >= 1 && said, "[4] the refusal reached the engine, which said so and went on");
    }

    // [5] A certificate on the tip itself lifts the gate, whatever its kind: the
    // vote certificate the network decided the tip on is as good as an anchor.
    // One for another block at that height is not.
    for (const bool same : {true, false}) {
        Rig         g(same ? "tipcert" : "tipcert-control", true);
        const Id    block  = same ? g.store->tip : filled(0x7a);
        lux::consensus::VotePosition pos{};
        pos.chain_id            = g.chain;
        pos.height              = kTip;
        pos.block_id            = block;
        pos.canonical_id        = block;
        pos.parent_id           = Id{};  // the fake chain's imported tip has no parent
        pos.parent_canonical_id = Id{};
        pos.validator_set_root  = g.committee.root();
        const Message m = vote_message(pos);
        std::map<Node, Signature> sigs;
        for (int i = 1; i < 4; ++i) sigs[g.signers[std::size_t(i)]->node()] = sign(m, {}, g.signers[std::size_t(i)]->secret()).sig;
        const auto cert = certify(m, sigs, g.committee);
        std::optional<std::uint64_t> asked;
        g.peer->on(kAskMsgType, [&](std::uint32_t, const std::vector<std::uint8_t>& q) {
            std::uint64_t from = 0;
            for (int i = 0; i < 8; ++i) from = (from << 8) | q[std::size_t(i)];
            asked = from;
        });
        const auto end = std::chrono::steady_clock::now() + 6 * kWindow;
        bool       answered = false;
        while (std::chrono::steady_clock::now() < end && !g.engine->caught_up()) {
            (void)g.engine->step();
            g.peer->pump();
            if (asked && !answered) {
                lux::zap::Writer w;
                w.write_u64(*asked);
                w.write_u64(kTip);
                w.write_u32(1);
                const std::vector<std::uint8_t> bytes{'I', 'M', 'P', 'O', 'R', 'T', 'E', 'D'};
                w.write_bytes(bytes);
                w.write_bytes(encode(*cert));
                answered = g.peer->send(0, kAnswerMsgType, w.take());
            }
            std::this_thread::sleep_for(1ms);
        }
        check(cert && asked && *asked == kTip, "[5] a gated node asks for its own tip's height");
        if (same) check(g.engine->caught_up(), "[5] a vote certificate on its tip lifts the gate");
        else check(!g.engine->caught_up(), "[5] control: a vote certificate on another block there does not");
    }

    // [6] A parent's time is its proposer's to choose, and a chain takes a time
    // equal to its parent's: a tip from 2025 must not open every slot since. A
    // proposal from a slot 40 windows past this validator's own time in the
    // height is not looked at; one within kReach windows is.
    {
        Rig r("stale", false);
        r.store->pending = false;
        std::uint64_t far = 40, near = 2;
        while (r.engine->proposer(kTip + 1, far) != r.committee.members()[1].node) ++far;
        while (near <= kReach && r.engine->proposer(kTip + 1, near) != r.committee.members()[1].node) ++near;
        r.run(50ms);
        r.peer->gossip(kProposalMsgType, encode(r.proposal(far, r.store->tip, 5)));
        r.run(3 * kWindow);
        check(r.store->parses == 0, "[6] a slot " + std::to_string(far) +
                                        " windows ahead, on a parent from 2025, is not looked at");
        if (near <= kReach) {
            r.peer->gossip(kProposalMsgType, encode(r.proposal(near, r.store->tip, 6)));
            r.run(3 * kWindow);
            check(r.store->parses == 1, "[6] control: slot " + std::to_string(near) + ", within reach, is");
        }
    }

    std::printf("----------------------------------------------------------------------\n");
    if (g_fail) { std::printf("==== node ENGINE: FAIL (%d) ====\n", g_fail); return 1; }
    std::printf("==== node ENGINE: PASS — what one validator refuses, against a control ====\n");
    return 0;
}
