// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// engine.cpp — the rule engine.hpp states, clause for clause from lux-rs/node
// src/engine.rs. Each function names the Rust function it renders.

#include "lux/node/engine.hpp"

#include "lux/zap/wire.hpp"

#include <sha256/cpp/sha256.hpp>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <limits>
#include <stdexcept>

namespace lux::node {

namespace {

using Digest = std::array<std::uint8_t, 32>;

std::string short_hex(const std::uint8_t* p) {
    char b[9];
    std::snprintf(b, sizeof b, "%02x%02x%02x%02x", p[0], p[1], p[2], p[3]);
    return b;
}
std::string short_hex(const Id& id) { return short_hex(id.data()); }
std::string short_hex(const Node& n) { return short_hex(n.data()); }

void put_be(std::vector<std::uint8_t>& out, std::uint64_t v, int bytes) {
    for (int s = 8 * (bytes - 1); s >= 0; s -= 8) out.push_back(std::uint8_t(v >> s));
}

std::uint64_t be(const std::uint8_t* p, int bytes) {
    std::uint64_t v = 0;
    for (int i = 0; i < bytes; ++i) v = (v << 8) | p[i];
    return v;
}

// A proposal frame's digest: everything it says, so two frames that differ
// anywhere are two frames. engine.rs:1476.
Digest digest(const Proposal& p) {
    std::vector<std::uint8_t> in;
    in.reserve(24 + p.signature.size() + p.block.size());
    put_be(in, p.height, 8);
    put_be(in, p.slot, 8);
    put_be(in, p.signature.size(), 8);
    in.insert(in.end(), p.signature.begin(), p.signature.end());
    in.insert(in.end(), p.block.begin(), p.block.end());
    Digest d{};
    cevm::crypto::sha256(reinterpret_cast<std::byte*>(d.data()), reinterpret_cast<const std::byte*>(in.data()),
                         in.size());
    return d;
}

// Take one of `key`'s `limit` turns this window of `every`, if one is left.
// engine.rs:1456.
template <class K>
bool spend(std::map<K, std::pair<std::uint32_t, Clock::time_point>>& turns, const K& key, std::uint32_t limit,
           Duration every) {
    const auto now      = Clock::now();
    auto [it, fresh]    = turns.try_emplace(key, limit, now);
    auto& [left, since] = it->second;
    if (!fresh && now - since >= every) {
        left  = limit;
        since = now;
    }
    if (left == 0) return false;
    --left;
    return true;
}

std::uint64_t sat_add(std::uint64_t a, std::uint64_t b) {
    return a > std::numeric_limits<std::uint64_t>::max() - b ? std::numeric_limits<std::uint64_t>::max() : a + b;
}
std::uint64_t sat_sub(std::uint64_t a, std::uint64_t b) { return a > b ? a - b : 0; }

std::vector<std::pair<Node, std::uint64_t>> weights(const Committee& c) {
    std::vector<std::pair<Node, std::uint64_t>> out;
    for (const auto& m : c.members()) out.emplace_back(m.node, m.weight);
    return out;
}

// `name` under `data`, which is made if it is not there yet.
std::filesystem::path under(const std::filesystem::path& data, const char* name) {
    std::filesystem::create_directories(data);
    return data / name;
}

Event refused(std::string why) {
    Event e;
    e.what = Event::What::Refused;
    e.text = std::move(why);
    return e;
}

}  // namespace

Engine::Engine(std::unique_ptr<VM> vm, Host& host, std::mutex& guard, EngineConfig cfg)
    : vm_(std::move(vm)),
      host_(host),
      guard_(guard),
      cfg_(std::move(cfg)),
      set_root_(cfg_.committee.root()),
      windower_(cfg_.chain, weights(cfg_.committee)),
      journal_(Journal::open(under(cfg_.data, "votes"))),
      ledger_(Ledger::open(under(cfg_.data, "ledger"))),
      gated_(gated(cfg_.data)) {
    // What the mesh hands over is queued here, per link and bounded, and taken
    // on the next pass: one peer streaming frames holds a fixed amount of this
    // node and cannot crowd out what the others sent (mesh.rs ARRIVALS_MAX,
    // VOTES_MAX).
    host_.on(kProposalMsgType, [this](std::uint32_t seat, const std::vector<std::uint8_t>& raw) {
        if (seat >= cfg_.committee.size()) return;
        auto p = decode_proposal(node_at(seat), raw);
        if (!p) return;
        auto& q = proposals_in_[seat];
        if (q.size() >= kArrivalsMax) q.pop_front();
        q.push_back(std::move(*p));
    });
    host_.on(kStatementMsgType, [this](std::uint32_t seat, const std::vector<std::uint8_t>& raw) {
        if (seat >= cfg_.committee.size()) return;
        auto s = decode_statement(raw);
        if (!s) return;
        auto& q = statements_in_[seat];
        if (q.size() >= kStatementsMax) q.pop_front();
        q.push_back(*s);
    });
    host_.on(kAskMsgType, [this](std::uint32_t seat, const std::vector<std::uint8_t>& q) { serve(seat, q); });
    host_.on(kAnswerMsgType, [this](std::uint32_t seat, const std::vector<std::uint8_t>& a) {
        if (answers_in_.size() < cfg_.committee.size() * 2) answers_in_.emplace_back(seat, a);
    });

    // A gate whose tip a certificate in the ledger already stands on is a lift
    // that did not reach the device, or an import that brought nothing new. It
    // is lifted again rather than left to wait for the next certificate.
    if (gated_) {
        const std::lock_guard<std::mutex> lock(guard_);
        const auto                        rec = ledger_.at(vm_->last_accepted_height());
        if (rec && rec->block == vm_->last_accepted() && lift_gate(cfg_.data)) gated_ = false;
    }
}

Duration Engine::settle() const {
    return std::clamp<Duration>(cfg_.window / 5, kSettleMin, kSettleMax);
}

std::uint64_t Engine::slot_of(const Instance& at) const {
    return std::uint64_t((Clock::now() - at.began) / cfg_.window);
}

// This validator's own wall-clock slot at the height: windows since the tip's
// timestamp. engine.rs:787.
std::uint64_t Engine::wall(const Instance& at) const {
    const auto now   = std::chrono::system_clock::now().time_since_epoch();
    const auto since = now - std::chrono::seconds(at.opened);
    if (since.count() <= 0) return 0;
    return std::uint64_t(since / cfg_.window);
}

Node Engine::node_at(std::uint32_t seat) const { return cfg_.committee.members()[seat].node; }

std::optional<std::pair<std::uint64_t, std::uint64_t>> Engine::slot() const {
    if (!at_) return std::nullopt;
    return std::make_pair(at_->height, slot_of(*at_));
}

lux::consensus::VotePosition Engine::position(const Block& b) const {
    lux::consensus::VotePosition pos{};
    pos.chain_id = cfg_.chain;
    pos.height   = b.height();
    // One statement per height (vote_guard.go:60), so there is no round for it
    // to name. Round 0 is what every statement says. engine.rs:471.
    pos.round     = 0;
    pos.block_id  = b.id();
    pos.parent_id = b.parent();
    // The block IS its own canonical identity: no proposervm envelope here.
    pos.canonical_id        = b.id();
    pos.parent_canonical_id = b.parent();
    if (cfg_.binding == Binding::Executed) pos.execution_state_root = b.root();
    pos.validator_set_root = set_root_;
    return pos;
}

Step Engine::step() {
    Step out;
    Id            tip{};
    std::uint64_t height = 0;
    {
        const std::lock_guard<std::mutex> lock(guard_);
        tip    = vm_->last_accepted();
        height = vm_->last_accepted_height() + 1;
    }
    if (gated_ && !anchor_) anchor_begin(out);

    std::vector<std::pair<Node, Arrival>> arrivals;
    if (!at_ || at_->tip != tip) {
        // The height moved. Every block still live at the old one lost: it can
        // never be accepted, so what it holds goes back to the pool — the one
        // the ledger names at its height is the one that won.
        if (at_) {
            const auto won = ledger_.at(at_->height);
            for (const auto& [id, s] : at_->siblings) {
                if (won && won->block == id) continue;
                const std::lock_guard<std::mutex> lock(guard_);
                try { s.block->reject(); } catch (const std::exception&) {}
            }
        }
        for (auto& [link, kept] : later_)
            for (auto& a : kept) arrivals.emplace_back(link, std::move(a));
        later_.clear();
        std::erase_if(heights_, [&](const auto& kv) { return kv.second <= height; });
        at_ = enter(height, tip, out);
    }
    Instance& at = *at_;

    host_.pump();
    for (auto& [seat, q] : proposals_in_)
        for (auto& p : q) arrivals.emplace_back(node_at(seat), Arrival{false, std::move(p), std::nullopt});
    for (auto& [seat, q] : statements_in_)
        for (auto& s : q) arrivals.emplace_back(node_at(seat), Arrival{true, std::nullopt, s});
    proposals_in_.clear();
    statements_in_.clear();
    out.quiet = arrivals.empty() && answers_in_.empty();
    for (auto& [link, a] : arrivals) arrive(at, link, std::move(a), out);

    // A peer came onto the mesh: what this validator said and holds here goes
    // out now, not a backed-off retry later.
    if (const auto joined = host_.joined(); joined != joined_) {
        joined_ = joined;
        hurry(at);
        if (anchor_) {
            anchor_->backoff = settle() * 2;
            anchor_->retry   = Clock::now();
        }
    }

    // A statement that did not reach the device is not tried again at once. And
    // an imported chain is not an agreed chain: while the gate stands this node
    // builds nothing and signs no block. It still executes, so it can accept
    // what the others certify — which is what lifts the gate.
    const bool calm = !at.stalled || Clock::now() - *at.stalled >= cfg_.window / 5;
    if (!gated_ && calm) {
        offer(at, out);
        vote(at, out);
    }
    const bool lost      = calm && decide(at, out);
    const bool exhausted = retry(at, out);
    const bool settled   = Clock::now() - at.began >= cfg_.window / 2;
    if (gated_) anchor_step(out);
    behind(height, lost || exhausted, settled, out);

    auto answers = std::move(answers_in_);
    answers_in_.clear();
    for (auto& [seat, a] : answers) answered(seat, a, out);
    return out;
}

// Take `height` up on `tip`. A statement this validator already made here — in
// an earlier run — is bound, and said again as it was: Go's clone recovery
// re-signs the durable binding, never a fresh winner (integration.go:1018). The
// block it signed is offered again too, when it was kept. engine.rs:560.
Engine::Instance Engine::enter(std::uint64_t height, const Id& tip, Step& out) {
    Instance at;
    at.height = height;
    at.tip    = tip;
    at.began  = Clock::now();
    {
        const std::lock_guard<std::mutex> lock(guard_);
        try {
            if (const auto b = vm_->get(tip)) at.opened = b->timestamp();
        } catch (const std::exception&) {
        }
    }
    at.backoff = settle() * 2;
    at.retry   = Clock::now() + at.backoff;

    const auto standing = journal_.standing(Slot{cfg_.chain, height, 0});
    if (!standing) return at;
    const auto s = say(*standing, out, at.stalled);
    if (!s) return at;
    at.votes[cfg_.self] = *s;
    at.bound            = *s;
    const auto claim    = read(*standing);
    if (!claim || claim->kind != Kind::Vote) return at;

    auto                   kept = held(cfg_.data);
    std::shared_ptr<Block> b;
    if (kept && kept->height == height) {
        const std::lock_guard<std::mutex> lock(guard_);
        try {
            b = vm_->parse(kept->block);
        } catch (const std::exception&) {
        }
    }
    if (!b || b->id() != claim->block) {
        out.events.push_back(refused("height " + std::to_string(height) + ": this validator signed block " +
                                     short_hex(claim->block) +
                                     " and kept no copy of it; the height waits on a validator that did"));
        return at;
    }
    bool ok = false;
    {
        const std::lock_guard<std::mutex> lock(guard_);
        try {
            ok = b->verify();
        } catch (const std::exception&) {
        }
    }
    if (ok) {
        kept->from = cfg_.self;
        host_.gossip(kProposalMsgType, encode(*kept));
        const Digest frame = digest(*kept);
        const Node   who   = proposer(height, kept->slot);
        live(at, b->id(), Sibling{*kept, frame, who, false, b});
    }
    return at;
}

// One arrival: into this height, held for the next one, or noted as a sign
// this node is behind. `link` is the peer it came in on, proven by the
// handshake; nothing an arrival says about who made it is believed before its
// signature checks. engine.rs:637.
void Engine::arrive(Instance& at, const Node& link, Arrival a, Step& out) {
    if (!a.vote) {
        Proposal& p = *a.proposal;
        if (p.height == at.height) proposed(at, std::move(p), out);
        else if (p.height == at.height + 1) later_from(link, std::move(a));
        return;
    }
    const Statement& s     = *a.statement;
    const auto       claim = read(s.message);
    if (!claim) return;
    if (claim->kind == Kind::Anchor) {
        anchor_statement(s, *claim, out);
        return;
    }
    const std::uint64_t h = claim->slot.height;
    if (h == at.height) {
        voted(at, s);
        return;
    }
    if (h < at.height) return;
    const bool next = h == at.height + 1;
    // A signer already heard this far on says nothing new — unless it is a vote
    // to keep for the next height.
    if (const auto it = heights_.find(s.node); !next && it != heights_.end() && it->second >= h) return;
    if (!spend(checks_, link, kAheadEach, settle()) || !signed_vote(s, *claim)) return;
    auto& seen = heights_[s.node];
    seen       = std::max(seen, h);
    if (next) later_from(link, std::move(a));
}

void Engine::later_from(const Node& link, Arrival a) {
    auto& kept = later_[link];
    if (kept.size() < kLaterEach) kept.push_back(std::move(a));
}

// An accepting vote on this chain, under this set, at round 0, that its signer
// signed. engine.rs:686.
bool Engine::signed_vote(const Statement& s, const Claim& c) const {
    return c.kind == Kind::Vote && c.slot.chain == cfg_.chain && c.slot.round == 0 && c.set_root == set_root_ &&
           verify(s, cfg_.committee);
}

// A proposal: signed by its slot's proposer, each live frame looked at once.
// Every one that is signed and executes is live, within kEach a proposer and
// kSiblingsMax a height, the lowest kept. A block taken up is relayed, so a
// peer its proposer never reached holds it too. engine.rs:693-785.
void Engine::proposed(Instance& at, Proposal p, Step& out) {
    const Node who  = proposer(at.height, p.slot);
    const Node link = p.from;
    const auto now  = Clock::now();
    if (const auto j = at.junk.find({who, link});
        j != at.junk.end() && j->second.first == 0 && now - j->second.second < settle())
        return;
    const Digest frame = digest(p);
    for (const auto& [id, s] : at.siblings)
        if (s.frame == frame) return;
    if (const auto r = at.refused.find(frame);
        r != at.refused.end() && (!r->second.first || now < *r->second.first))
        return;

    // A slot ahead of this validator's clock is taken when its own wall clock
    // since the tip's timestamp says the slot can have opened, within kSkew
    // windows — never off a local start alone.
    const std::uint64_t wall_slot = wall(at);
    const bool          ahead     = p.slot > sat_add(slot_of(at), kEarly);
    if (ahead && sat_sub(p.slot, kEarly) > sat_add(wall_slot, kSkew)) return;

    const Member* member = nullptr;
    for (const auto& m : cfg_.committee.members())
        if (m.node == who) member = &m;
    if (!member) return;
    const auto header =
        proposal_header(cfg_.chain, set_root_, at.tip, at.height, p.slot, member->identity, p.block);
    // Not that slot's proposer's: not believed, not parsed, not executed, and
    // not logged — a peer that could make every forgery a log line could fill
    // the disk with them.
    if (p.signature.size() != kProposalSignatureLen ||
        !pq::verify(member->identity, kProposalContext, header, p.signature))
        return;

    std::shared_ptr<Block> b;
    bool                   unavailable = false;
    {
        const std::lock_guard<std::mutex> lock(guard_);
        try {
            b = vm_->parse(p.block);
        } catch (const std::exception&) {
            unavailable = true;
        }
    }
    if (unavailable) return refuse(at, who, link, frame, true, "the chain could not be asked", out);
    if (!b) return refuse(at, who, link, frame, false, "not a block", out);
    if (b->height() != at.height || b->parent() != at.tip)
        return refuse(at, who, link, frame, false, "not on the tip", out);
    const Id id = b->id();
    if (at.siblings.count(id)) return;

    // No room: let go — a block the votes come to name is taken when it is
    // pushed again. It still arrived, and the settle window restarts.
    const auto has_room = room(at, who, id);
    if (!has_room) {
        {
            const std::lock_guard<std::mutex> lock(guard_);
            try { b->reject(); } catch (const std::exception&) {}
        }
        return stir(at);
    }
    bool ok = false;
    {
        const std::lock_guard<std::mutex> lock(guard_);
        try {
            ok = b->verify();
        } catch (const std::exception&) {
        }
    }
    if (!ok) return refuse(at, who, link, frame, false, "the chain refused it", out);
    if (const auto& displaced = *has_room) {
        const auto it = at.siblings.find(*displaced);
        if (it != at.siblings.end()) {
            const auto gone = it->second.block;
            at.siblings.erase(it);
            const std::lock_guard<std::mutex> lock(guard_);
            try { gone->reject(); } catch (const std::exception&) {}
        }
    }
    // Once such a block has run the clock moves up to it, and never past this
    // validator's own wall-clock slot: nothing a peer sends puts it ahead of
    // itself.
    if (ahead) {
        const std::uint64_t to     = std::min(p.slot - kEarly, wall_slot);
        const auto          behind = cfg_.window * std::int64_t(std::min<std::uint64_t>(to, 1u << 30));
        if (now - Clock::time_point{} > behind) at.began = std::min(at.began, now - behind);
    }
    host_.gossip(kProposalMsgType, encode(p));
    live(at, id, Sibling{std::move(p), frame, who, false, b});
}

// A frame `who` signed, from `link`, refused: one of that pair's turns this
// settle window, the frame remembered, and said the first time `who` is
// refused here. engine.rs:819.
void Engine::refuse(Instance& at, const Node& who, const Node& link, const Digest& frame, bool unavailable,
                    const std::string& why, Step& out) {
    bool first = true;
    for (const auto& [k, v] : at.junk)
        if (k.first == who) first = false;
    (void)spend(at.junk, std::make_pair(who, link), kJunkEach, settle());
    const auto now  = Clock::now();
    const bool kept = at.refused.size() < kRefusedMax || at.refused.count(frame);
    if (unavailable) {
        // The chain could not be asked: the block may be fine. Asked again when
        // it is pushed again, after a wait that doubles.
        const auto     r    = at.refused.find(frame);
        const Duration wait = r == at.refused.end() ? settle() : std::min<Duration>(r->second.second * 2, kRetryMax);
        if (kept) at.refused[frame] = {now + wait, wait};
    } else if (kept) {
        at.refused[frame] = {std::nullopt, Duration::zero()};
    }
    if (first)
        out.events.push_back(refused("height " + std::to_string(at.height) + ": proposer " + short_hex(who) +
                                     "'s block: " + why));
}

// Whether block `id` from `who` has room, and which block it displaces: past
// kEach of that proposer's, or kSiblingsMax in all, the highest id nothing
// holds here — not this validator's own block, and not one a verified vote
// names — and only for a lower one. A block a verified vote names always has
// room. nullopt: no room. engine.rs:796.
std::optional<std::optional<Id>> Engine::room(const Instance& at, const Node& who, const Id& id) const {
    std::size_t theirs = 0;
    for (const auto& [k, s] : at.siblings)
        if (s.proposer == who) ++theirs;
    std::vector<Id> full;
    if (theirs >= kEach) {
        for (const auto& [k, s] : at.siblings)
            if (s.proposer == who) full.push_back(k);
    } else if (at.siblings.size() >= kSiblingsMax) {
        for (const auto& [k, s] : at.siblings) full.push_back(k);
    } else {
        return std::optional<Id>{};
    }
    std::optional<Id> highest;
    for (auto it = full.rbegin(); it != full.rend(); ++it)
        if (!at.siblings.at(*it).own && named(at, *it) == 0) {
            highest = *it;
            break;
        }
    if (named(at, id) > 0) return highest;
    if (!highest || !(id < *highest)) return std::nullopt;
    return highest;
}

// Put a block live at this height. engine.rs:861.
void Engine::live(Instance& at, const Id& id, Sibling s) {
    if (at.siblings.empty()) {
        // The first block live here: the retry starts again from its first
        // window, whatever a quiet height let it grow to.
        at.backoff = settle() * 2;
        at.retry   = Clock::now() + at.backoff;
    }
    stir(at);
    const auto bound     = at.bound ? read(at.bound->message) : std::nullopt;
    const bool elsewhere = bound && bound->block != id;
    at.siblings.emplace(id, std::move(s));
    // A block beside the one this validator signed: its proposer, and whoever
    // holds it, hear now what this validator signed and holds.
    if (elsewhere) hurry(at);
}

// A block arrived at the height: the settle window restarts, until the
// height's one deadline. engine.rs:884.
void Engine::stir(Instance& at) const {
    const auto now = Clock::now();
    if (!at.closes) at.closes = now + kSettleMax;
    if (*at.closes >= now) at.offered = now;
}

// Owe a push of what this validator said and holds here, now and outside the
// retry's schedule, at most once a settle window. engine.rs:893.
void Engine::hurry(Instance& at) const {
    if (at.hurried && Clock::now() - *at.hurried < settle()) return;
    at.hurried = Clock::now();
    at.push    = true;
}

std::size_t Engine::named(const Instance& at, const Id& id) const {
    std::size_t n = 0;
    for (const auto& [who, v] : at.votes)
        if (const auto c = read(v.message); c && c->block == id) ++n;
    return n;
}

// The first vote from each validator at this height, checked. engine.rs:907.
void Engine::voted(Instance& at, const Statement& s) {
    if (at.votes.count(s.node)) return;
    const auto claim = read(s.message);
    if (!claim || !signed_vote(s, *claim)) return;
    at.votes.emplace(s.node, s);
}

// Build and propose, when this validator's window is open and nothing is live
// or signed at the height. So is a block f+1 validators signed that this one
// lacks: one of them is honest and pushes it again — it is waited for, not
// built beside, until the retry gives up on it. engine.rs:914-972.
void Engine::offer(Instance& at, Step& out) {
    if (at.bound || !at.siblings.empty() || at.built) return;
    const std::size_t faults = (cfg_.committee.size() - 1) / 3;
    if (at.attempts < kRetryAttempts) {
        if (const auto l = leading(at); l && l->second > faults) return;
    }
    const std::uint64_t slot = slot_of(at);
    if (proposer(at.height, slot) != cfg_.self) return;
    if (at.empty && Clock::now() - *at.empty < poll()) return;

    std::shared_ptr<Block> b;
    {
        const std::lock_guard<std::mutex> lock(guard_);
        try {
            b = vm_->build();
        } catch (const std::exception& e) {
            at.empty = Clock::now();
            out.events.push_back(refused(std::string("building: ") + e.what()));
            return;
        }
    }
    // Nothing to run: it looks again a poll later, while its window lasts.
    if (!b) {
        at.empty = Clock::now();
        return;
    }
    if (b->height() != at.height || b->parent() != at.tip) {
        at.empty = Clock::now();
        out.events.push_back(refused("height " + std::to_string(at.height) +
                                     ": the chain built a block that is not on the accepted tip"));
        return;
    }
    Proposal p;
    p.from   = cfg_.self;
    p.height = at.height;
    p.slot   = slot;
    p.block.assign(b->bytes().begin(), b->bytes().end());
    const auto header = proposal_header(cfg_.chain, set_root_, at.tip, at.height, slot,
                                        cfg_.identity.public_key(), p.block);
    try {
        p.signature = pq::sign(cfg_.identity.secret_key(), kProposalContext, header);
    } catch (const std::exception& e) {
        at.empty = Clock::now();
        out.events.push_back(refused(std::string("signing a proposal: ") + e.what()));
        return;
    }
    host_.gossip(kProposalMsgType, encode(p));
    const Digest frame = digest(p);
    at.built           = b->id();
    live(at, b->id(), Sibling{std::move(p), frame, cfg_.self, true, b});
}

// Sign the converged winner, once: the lowest id among the live blocks that can
// still reach α — its verified votes plus every validator not yet heard from —
// once no new block has been offered for a settle window. engine.rs:974-1038.
void Engine::vote(Instance& at, Step& out) {
    if (at.bound || !at.offered) return;
    if (Clock::now() - *at.offered < settle()) return;
    const std::size_t open = cfg_.committee.size() > at.votes.size() ? cfg_.committee.size() - at.votes.size() : 0;
    const std::size_t need = quorum();
    auto              it   = std::find_if(at.siblings.begin(), at.siblings.end(),
                                          [&](const auto& kv) { return named(at, kv.first) + open >= need; });
    if (it == at.siblings.end()) return;
    Sibling&      sib = it->second;
    const Message m   = vote_message(position(*sib.block));

    // Bound already, by a run this one does not remember: what stands is what
    // this validator said, and it says that again.
    if (const auto standing = journal_.standing(Slot{cfg_.chain, at.height, 0})) {
        if (const auto s = say(*standing, out, at.stalled)) {
            at.votes[cfg_.self] = *s;
            at.bound            = *s;
        }
        return;
    }
    // The block reaches the device before the signature does, so a restart
    // that finds this validator bound can offer the block as well.
    if (!keep_held(cfg_.data, sib.proposal)) {
        at.stalled = Clock::now();
        out.events.push_back(refused("keeping the block it signs: the held record did not reach the device"));
        return;
    }
    if (const auto s = say(m, out, at.stalled)) {
        at.votes[cfg_.self] = *s;
        at.bound            = *s;
    }
}

// The block with the most verified votes at this height, the lowest id among
// equals, and how many. engine.rs:1041.
std::optional<std::pair<Id, std::size_t>> Engine::leading(const Instance& at) const {
    std::map<Id, std::size_t> count;
    for (const auto& [who, v] : at.votes)
        if (const auto c = read(v.message)) ++count[c->block];
    std::optional<std::pair<Id, std::size_t>> best;
    for (const auto& [id, n] : count)
        if (!best || n > best->second) best = std::make_pair(id, n);
    return best;
}

// Accept the block α validators signed, once this node holds and has executed
// it. Returns whether such a block exists that this node does NOT hold — the
// sign it has to ask for it. engine.rs:1052-1096.
bool Engine::decide(Instance& at, Step& out) {
    const auto l = leading(at);
    if (!l || l->second < quorum()) return false;
    const auto it = at.siblings.find(l->first);
    if (it == at.siblings.end()) return true;
    const Sibling& sib = it->second;
    // Each vote was checked against what it claimed; the certificate is over
    // this block's own position. A vote that signed other roots under this
    // block's id is not a vote for it, and is let go.
    const Message             m = vote_message(position(*sib.block));
    std::map<Node, Signature> sigs;
    std::vector<Node>         wrong;
    for (const auto& [who, v] : at.votes) {
        const auto c = read(v.message);
        if (!c || c->block != l->first) continue;
        if (v.message == m) sigs.emplace(who, v.sig);
        else wrong.push_back(who);
    }
    for (const auto& w : wrong) at.votes.erase(w);
    const auto cert = certify(m, sigs, cfg_.committee);
    if (!cert) return false;
    if (!accept_certified(sib.block, *cert, out)) {
        at.stalled = Clock::now();
        return false;
    }
    Event e;
    e.what    = Event::What::Decided;
    e.height  = at.height;
    e.slot    = sib.proposal.slot;
    e.block   = l->first;
    e.signers = cert->signers.size();
    e.built   = at.built == l->first;
    out.events.push_back(std::move(e));
    return false;
}

// The retry (rePollAllPending): when due, say the standing vote again and push
// this validator's own block, and the block it signed, again; the window
// doubles to kRetryMax. Returns whether kRetryAttempts have gone by with
// something pending — Go's cue to ask for the certified block instead. A push
// owed out of turn goes out at once and is no attempt. engine.rs:1098-1141.
bool Engine::retry(Instance& at, Step& out) {
    const auto now = Clock::now();
    const bool due = now >= at.retry;
    if (!due && !at.push) return false;
    at.push              = false;
    const auto bound     = at.bound ? read(at.bound->message) : std::nullopt;
    if (at.bound) broadcast(*at.bound);
    for (const auto& [id, s] : at.siblings)
        if (s.own || (bound && bound->block == id)) host_.gossip(kProposalMsgType, encode(s.proposal));
    if (!due) return false;
    at.backoff = std::min<Duration>(at.backoff * 2, kRetryMax);
    at.retry   = now + at.backoff;
    if (at.siblings.empty() && at.votes.empty()) return false;
    ++at.attempts;
    Event e;
    e.what         = Event::What::Waiting;
    e.height       = at.height;
    e.slot         = slot_of(at);
    const auto l   = leading(at);
    e.signers      = l ? l->second : 0;
    e.text         = std::to_string(e.signers) + " of " + std::to_string(quorum()) + " votes on " +
             std::to_string(at.siblings.size()) + " blocks, asking again";
    out.events.push_back(std::move(e));
    return at.attempts >= kRetryAttempts;
}

// Ask the peers for what this node missed, when there is a sign it is behind: a
// certificate for a block it does not hold, a height the retry gave up on, or
// f+1 validators heard at later heights — one of them honest, so the height is
// decided. A gated node asks from its own tip, for the anchor or a block
// certified on it. At most once a window. engine.rs:1148.
void Engine::behind(std::uint64_t height, bool lost, bool settled, Step&) {
    const std::size_t faults = (cfg_.committee.size() - 1) / 3;
    std::size_t       ahead  = 0;
    for (const auto& [who, h] : heights_)
        if (h > height) ++ahead;
    if (!lost && !(settled && ahead > faults) && !gated_) return;
    if (asked_ && Clock::now() - *asked_ < cfg_.window) return;
    asked_ = Clock::now();
    ask(gated_ ? height - 1 : height);
}

void Engine::broadcast(const Statement& s) { host_.gossip(kStatementMsgType, encode(s)); }

// Admit `m` to the journal, then sign and send it. The journal is the only way
// to the key. A different statement standing at the slot is said again in its
// place — it is what this validator said.
std::optional<Statement> Engine::say(const Message& m, Step& out, std::optional<Clock::time_point>& stalled) {
    switch (journal_.admit(m)) {
        case Journal::Admit::Ok: {
            const Statement s = sign(m, cfg_.self, cfg_.sk);
            broadcast(s);
            return s;
        }
        case Journal::Admit::Equivocation: {
            const auto c        = read(m);
            const auto standing = journal_.standing(c->slot);
            const Statement s   = sign(*standing, cfg_.self, cfg_.sk);
            broadcast(s);
            return s;
        }
        case Journal::Admit::NotDurable:
            stalled = Clock::now();
            out.events.push_back(refused("signing: the journal did not reach the device"));
            return std::nullopt;
        case Journal::Admit::NotAStatement:
            out.events.push_back(refused("signing: not a statement this network makes"));
            return std::nullopt;
    }
    return std::nullopt;
}

// ── the anchor ────────────────────────────────────────────────────────────────

void Engine::anchor_begin(Step& out) {
    Anchor a;
    {
        const std::lock_guard<std::mutex> lock(guard_);
        a.height = vm_->last_accepted_height();
        a.tip    = vm_->last_accepted();
    }
    a.message = anchor_message(cfg_.chain, a.height, a.tip, set_root_);
    a.backoff = settle() * 2;
    a.retry   = Clock::now();
    Event e;
    e.what   = Event::What::Refused;
    e.height = a.height;
    e.block  = a.tip;
    e.text   = "height " + std::to_string(a.height) + ": the tip " + short_hex(a.tip) +
             " was imported, not decided; this validator signs no block until α validators anchor it";
    out.events.push_back(std::move(e));
    anchor_ = std::move(a);
}

void Engine::anchor_statement(const Statement& s, const Claim& c, Step&) {
    if (!gated_ || !anchor_) return;
    Anchor& a = *anchor_;
    if (c.slot.chain != cfg_.chain || c.set_root != set_root_ || c.slot.height != a.height || c.block != a.tip)
        return;
    if (a.sigs.count(s.node) || !verify(s, cfg_.committee)) return;
    a.sigs.emplace(s.node, s.sig);
}

void Engine::anchor_step(Step& out) {
    if (!gated_ || !anchor_) return;
    Anchor& a = *anchor_;
    if (!a.signed_ && !a.refused) {
        switch (journal_.admit(a.message)) {
            case Journal::Admit::Ok: {
                const Statement s = sign(a.message, cfg_.self, cfg_.sk);
                a.sigs[cfg_.self] = s.sig;
                a.signed_         = true;
                break;
            }
            case Journal::Admit::Equivocation:
                a.refused = true;
                out.events.push_back(refused("height " + std::to_string(a.height) +
                                             ": this validator already signed another statement there, so it "
                                             "cannot anchor the imported tip; it waits for a block certified on it"));
                break;
            case Journal::Admit::NotDurable:
            case Journal::Admit::NotAStatement:
                out.events.push_back(refused("anchoring: the journal did not take the statement"));
                break;
        }
    }
    if (a.signed_ && Clock::now() >= a.retry) {
        broadcast(Statement{a.message, cfg_.self, a.sigs[cfg_.self]});
        a.retry   = Clock::now() + a.backoff;
        a.backoff = std::min<Duration>(a.backoff * 2, kRetryMax);
    }
    if (a.sigs.size() < quorum()) return;
    const auto cert = certify(a.message, a.sigs, cfg_.committee);
    if (!cert) return;
    if (!ledger_.append(Record{a.height, a.tip, *cert})) {
        out.events.push_back(refused("anchoring: the certificate did not reach the device"));
        return;
    }
    Event e;
    e.what    = Event::What::Anchored;
    e.height  = a.height;
    e.block   = a.tip;
    e.signers = cert->signers.size();
    out.events.push_back(std::move(e));
    lift(out);
}

bool Engine::lift(Step& out) {
    if (!gated_) return true;
    if (!lift_gate(cfg_.data)) {
        out.events.push_back(refused("lifting the import gate: the removal did not reach the device"));
        return false;
    }
    gated_ = false;
    anchor_.reset();
    out.events.push_back(refused("the import gate is lifted: a certificate stands on the tip, and this "
                                 "validator signs again"));
    return true;
}

// ── catch-up ──────────────────────────────────────────────────────────────────

void Engine::ask(std::uint64_t from) {
    std::vector<std::uint8_t> q;
    put_be(q, from, 8);
    put_be(q, kBatchMax, 4);
    host_.gossip(kAskMsgType, q);
}

// Answer a peer's question from the ledger: heights in order until one is
// missing, the count is reached, or the next record would take the frame past
// the link's cap. Paced per validator: kAskBurst, then kAskRate a second.
// mesh.rs:499.
void Engine::serve(std::uint32_t seat, const std::vector<std::uint8_t>& question) {
    if (question.size() != 12) return;
    auto&      pace = askers_[seat];
    const auto now  = Clock::now();
    if (pace.since == Clock::time_point{}) pace.since = now;
    const auto secs = std::chrono::duration_cast<std::chrono::seconds>(now - pace.since).count();
    if (secs > 0) {
        pace.left  = std::uint32_t(std::min<long long>(kAskBurst, pace.left + secs * kAskRate));
        pace.since = now;
    }
    if (pace.left == 0) return;
    --pace.left;

    const std::uint64_t from  = be(question.data(), 8);
    const std::uint32_t count = std::min<std::uint32_t>(std::uint32_t(be(question.data() + 8, 4)), kBatchMax);
    std::vector<std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>> records;
    std::size_t size = 8 + 8 + 4;
    for (std::uint64_t h = from; h < from + count; ++h) {
        const auto rec = ledger_.at(h);
        if (!rec) break;
        std::vector<std::uint8_t> block;
        {
            const std::lock_guard<std::mutex> lock(guard_);
            try {
                if (const auto b = vm_->get(rec->block)) block.assign(b->bytes().begin(), b->bytes().end());
            } catch (const std::exception&) {
            }
        }
        if (block.empty()) break;
        auto cert = encode(rec->cert);
        size += 8 + block.size() + cert.size();
        if (size > kMaxMeshFrame) break;
        records.emplace_back(std::move(block), std::move(cert));
    }
    std::uint64_t tip = 0;
    {
        const std::lock_guard<std::mutex> lock(guard_);
        tip = vm_->last_accepted_height();
    }
    lux::zap::Writer w;
    w.write_u64(from);
    w.write_u64(tip);
    w.write_u32(std::uint32_t(records.size()));
    for (const auto& [block, cert] : records) {
        w.write_bytes(block);
        w.write_bytes(cert);
    }
    (void)host_.send(seat, kAnswerMsgType, w.take());
}

// Certified blocks, in order, each held to this committee before the chain sees
// a byte of it: a certificate of THIS committee over this chain, the next
// height, the block's own id and this node's tip as its parent — and then only
// if the chain, executing the block, arrives at what the certificate signs. A
// peer that fails any of it is not believed further in this answer; what came
// before stood on its own proof. Silent: a height taken here was decided
// without this node. engine.rs:1265-1453.
void Engine::answered(std::uint32_t seat, const std::vector<std::uint8_t>& answer, Step& out) {
    lux::zap::Reader r(answer.data(), answer.size());
    std::uint64_t    from = 0, reported = 0;
    std::uint32_t    n    = 0;
    if (!r.read_u64(from) || !r.read_u64(reported) || !r.read_u32(n) || n > kBatchMax) return;
    std::vector<std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>> records;
    for (std::uint32_t i = 0; i < n; ++i) {
        std::vector<std::uint8_t> block, cert;
        if (!r.read_bytes(block) || !r.read_bytes(cert)) return;
        records.emplace_back(std::move(block), std::move(cert));
    }
    if (r.remaining() != 0) return;

    std::uint64_t height = 0;
    Id            tip{};
    {
        const std::lock_guard<std::mutex> lock(guard_);
        height = vm_->last_accepted_height();
        tip    = vm_->last_accepted();
    }
    std::uint64_t accepted = 0;
    const auto    doubt    = [&](std::uint64_t h, const std::string& why) {
        out.events.push_back(refused("catching up: seat " + std::to_string(seat) + " not believed at height " +
                                     std::to_string(h) + ": " + why));
    };
    for (std::size_t i = 0; i < records.size(); ++i) {
        const std::uint64_t h    = from + i;
        const auto          cert = decode_certificate(records[i].second);
        if (!cert || !verify(*cert, cfg_.committee)) return doubt(h, "not a certificate of this committee");
        const auto c = read(cert->message);
        if (c->slot.chain != cfg_.chain || c->set_root != set_root_ || c->slot.height != h)
            return doubt(h, "a certificate for another place");
        if (c->kind == Kind::Anchor) {
            // An anchor is a certificate on a tip, not a block: it lifts the gate
            // of a node whose imported tip it names, and is nothing to any other.
            if (gated_ && h == height && c->block == tip) {
                if (!ledger_.at(h) && !ledger_.append(Record{h, tip, *cert})) return;
                Event e;
                e.what    = Event::What::Anchored;
                e.height  = h;
                e.block   = tip;
                e.signers = cert->signers.size();
                out.events.push_back(std::move(e));
                lift(out);
            }
            continue;
        }
        if (h <= height) continue;
        if (h != height + 1 || c->parent != tip || c->slot.round != 0)
            return doubt(h, "a certificate that does not build on this tip");
        std::shared_ptr<Block> b;
        {
            const std::lock_guard<std::mutex> lock(guard_);
            try {
                b = vm_->parse(records[i].first);
            } catch (const std::exception&) {
            }
        }
        if (!b || b->id() != c->block || b->parent() != tip || b->height() != h ||
            vote_message(position(*b)) != cert->message)
            return doubt(h, "the certificate does not sign this block");
        bool ok = false;
        {
            const std::lock_guard<std::mutex> lock(guard_);
            try {
                ok = b->verify();
            } catch (const std::exception&) {
            }
        }
        if (!ok) return doubt(h, "the block does not run here");
        if (!accept_certified(b, *cert, out)) return;
        height = h;
        tip    = b->id();
        ++accepted;
    }
    if (accepted > 0) {
        Event e;
        e.what    = Event::What::Caught;
        e.height  = height;
        e.block   = tip;
        e.signers = std::size_t(accepted);
        e.text    = "caught up " + std::to_string(accepted) + " blocks; peers report height " +
                 std::to_string(reported);
        out.events.push_back(std::move(e));
    }
}

// Record the certificate, then accept: the ONE place a block becomes accepted.
// A crash between the two leaves proof of a block never taken, which is
// harmless; the other order leaves a block this node can never prove.
// engine.rs:1184.
bool Engine::accept_certified(const std::shared_ptr<Block>& b, const Certificate& cert, Step& out) {
    const auto have = ledger_.at(b->height());
    if (have && have->block != b->id()) {
        out.events.push_back(refused("height " + std::to_string(b->height()) + ": a second certificate, for " +
                                     short_hex(b->id()) + " beside " + short_hex(have->block) +
                                     " — refused, and worth an alarm"));
        return false;
    }
    if (!have && !ledger_.append(Record{b->height(), b->id(), cert})) {
        out.events.push_back(refused("accepting: the certificate did not reach the device"));
        return false;
    }
    {
        const std::lock_guard<std::mutex> lock(guard_);
        try {
            b->accept();
        } catch (const std::exception& e) {
            out.events.push_back(refused(std::string("accepting: ") + e.what()));
            return false;
        }
    }
    // A certified block on the imported tip is a quorum building on that
    // history — what the gate waits for.
    if (gated_) lift(out);
    return true;
}

}  // namespace lux::node
