// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// engine.hpp — what turns a VM and a mesh into a chain that advances.
//
// THE RULE IS GO'S (luxfi/consensus engine/chain, B1: the α-of-K certificate is
// the only decider), ported clause for clause from lux-rs/node src/engine.rs,
// which runs it. There are no rounds and no locks: Go deleted its Tendermint
// braid in luxfi/consensus d13b4559, and one signature a height is the whole of
// what keeps two certificates from one height.
//
//  - ONE PROPOSER A WINDOW. The windower (windower.hpp) names who may build at
//    each slot of a height; a proposal is ML-DSA-signed by its slot's proposer
//    and refused from anyone else (proposervm verifyPostDurangoBlockDelay,
//    block.go:474). A validator builds only in its own window and only while no
//    block is live or signed at the height, so the next window's proposer builds
//    when the one before it went silent. engine.rs:923-972 `offer`.
//  - THE SLOT CLOCK counts windows from when this validator took the height up;
//    a proposal from a later slot is taken while this validator's wall clock,
//    counted from the tip's timestamp, allows the slot within SKEW windows, and
//    once it has run the local clock moves up to it — never past the wall-clock
//    slot. engine.rs:701-794.
//  - ONE SIGNATURE PER HEIGHT, through the journal (journal.hpp): a validator
//    signs one block at a height, before or after a restart, and never a second
//    (reserveSlotForSign, engine.go:2489; vote_guard.go:60).
//  - THE CONVERGED WINNER. After a settle window with no new block, a validator
//    signs the lowest-id live block that can still reach α given the verified
//    votes — its votes plus every validator not yet heard from
//    (snapshotVotableSlotsLocked engine.go:2922, convergedWinnerAtHeightLocked
//    engine.go:2829, emitConvergedVote integration.go:1002; the α filter is
//    lux-rs/node's own, engine.rs:974-1038 `vote`).
//  - NO BUILDING BESIDE. Not while a sibling is live, not while bound, and not
//    while f+1 verified votes name a block this validator lacks: one of those
//    signers is honest, holds it and pushes it again — it is waited for until
//    the retry gives up on it. engine.rs:914-930.
//  - BOUNDED SIBLINGS. Every signed block that executes is live, two from one
//    proposer included, within EACH a proposer and SIBLINGS_MAX a height; past
//    either the highest id that nothing holds goes, so nobody drops the winner.
//    engine.rs:796-817 `room`.
//  - ONE SETTLE DEADLINE PER HEIGHT: a block arriving restarts the settle window
//    only until SETTLE_MAX after the first arrived. engine.rs:882-889 `stir`.
//  - THE RETRY re-sends the bound vote and re-pushes this validator's own block
//    and the block it signed, doubling from twice the settle window to 16 s; a
//    peer that joins, or the first live sibling beside the one signed, brings it
//    forward (rePollAllPending, engine.go:1784). engine.rs:1098-1141.
//  - A NODE THAT FELL BEHIND ASKS: certified blocks, each checked against this
//    committee before the chain sees a byte of it. engine.rs:1143-1453.
//
// AND ONE THING THE RUST NODE DOES NOT HAVE YET — THE ANCHOR. An export carries
// blocks and no certificates, so a chain read off one has a tip nothing decided
// (the import gate, ledger.hpp). When every validator imports the same export
// nobody can build on it. So a gated validator whose tip is (T, H) signs ONE
// statement at height T — anchor_message(chain, T, H, set root), through the
// journal like any vote — and gossips it; α distinct committee signatures on the
// same (T, H) are a certificate, the gate lifts, and T+1 is built. A validator
// that imported a different tip signs a different message and is simply not in
// the quorum. LLM.md "The anchor" is the specification.
//
// WHY IT IS SAFE: two certificates at one height need α signers each, so 2α − n
// > f signers in both — an honest validator signing twice at one height, which
// the journal refuses. The winner rule, the retry and the anchor only decide
// which statement an honest validator makes, never whether it makes two.

#pragma once

#include "lux/node/committee.hpp"
#include "lux/node/host.hpp"
#include "lux/node/journal.hpp"
#include "lux/node/ledger.hpp"
#include "lux/node/pq_handshake.hpp"
#include "lux/node/statement.hpp"
#include "lux/node/vm.hpp"
#include "lux/node/windower.hpp"

#include <chrono>
#include <deque>
#include <filesystem>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace lux::node {

using Clock    = std::chrono::steady_clock;
using Duration = std::chrono::steady_clock::duration;

// WHOSE MESSAGE THIS NODE SIGNS. The vote's execution axis is filled two ways
// and they are mutually exclusive: validators that disagree about which do not
// form a quorum.
//
//   Executed  — bind execution_state_root to what THIS node's EVM produced, so
//               divergent execution stalls a height instead of hiding.
//   Transport — leave it empty, as luxd signs: Go's proposervm returns
//               ids.Empty for ExecutionStateRoot. A chain in a plugin takes
//               this: its root does not cross the boundary (plugin.hpp).
enum class Binding { Executed, Transport };

// engine.rs:104-154, the same constants.
inline constexpr auto          kSettleMin     = std::chrono::milliseconds(150);
inline constexpr auto          kSettleMax     = std::chrono::milliseconds(2000);
inline constexpr auto          kRetryMax      = std::chrono::milliseconds(16000);
inline constexpr std::uint32_t kRetryAttempts = 8;
inline constexpr std::uint64_t kEarly         = 1;
inline constexpr std::uint64_t kSkew          = 2;
inline constexpr std::size_t   kSiblingsMax   = 64;
inline constexpr std::size_t   kEach          = 16;
inline constexpr std::uint32_t kJunkEach      = 16;
inline constexpr std::size_t   kRefusedMax    = 256;
inline constexpr std::uint32_t kAheadEach     = 4;
inline constexpr std::size_t   kLaterEach     = 16;

// Catch-up on the mesh: lux-rs/node mesh.rs ASK (57, the answer under ZAP's
// response flag), a question `from(u64) ‖ count(u32)`, an answer
// `from(u64) ‖ tip(u64) ‖ n(u32) ‖ n × (block ‖ certificate)`.
inline constexpr std::uint8_t  kAskMsgType    = 57;
inline constexpr std::uint8_t  kAnswerMsgType = 57 | 0x80;
inline constexpr std::uint32_t kBatchMax      = 64;
inline constexpr std::uint32_t kAskBurst      = 32;
inline constexpr std::uint32_t kAskRate       = 16;  // a second, past the burst
// Proposals and statements held from one link between two passes.
inline constexpr std::size_t   kArrivalsMax   = 8;
inline constexpr std::size_t   kStatementsMax = 256;

struct EngineConfig {
    Committee             committee;
    Node                  self{};
    std::array<std::uint8_t, 32> sk{};   // the BLS voting key
    pq::Identity          identity;       // the ML-DSA name a proposal is signed with
    Id                    chain{};
    Binding               binding = Binding::Executed;
    Duration              window  = std::chrono::milliseconds(1000);
    std::filesystem::path data;           // journal, ledger, held, the gate
};

// Something worth saying.
struct Event {
    enum class What { Decided, Anchored, Waiting, Caught, Refused } what = What::Refused;
    std::uint64_t              height = 0;
    std::optional<std::uint64_t> slot;
    Id                         block{};
    std::size_t                signers = 0;
    bool                       built   = false;
    std::string                text;
};

struct Step {
    std::vector<Event> events;
    bool               quiet = true;  // nothing arrived from a peer
};

class Engine {
public:
    // Open the journal and the ledger under `cfg.data`, and read the import
    // gate. Throws std::runtime_error when either cannot be opened: a validator
    // that cannot record what it signs does not sign. `guard` is the chain's
    // lock, the one the RPC holds while it answers.
    Engine(std::unique_ptr<VM> vm, Host& host, std::mutex& guard, EngineConfig cfg);

    Engine(const Engine&)            = delete;
    Engine& operator=(const Engine&) = delete;

    // One pass: take what arrived, propose if this validator's window is open
    // and nothing is live, sign the converged winner once the height has
    // settled, accept a block once a certificate stands for it, retry what is
    // due, and ask for what this node missed. Never waits on the network.
    Step step();

    VM&           vm() noexcept { return *vm_; }
    std::uint64_t height() const { return vm_->last_accepted_height(); }
    // False while the import gate stands.
    bool          caught_up() const noexcept { return !gated_; }
    // The height in progress and this validator's slot in it.
    std::optional<std::pair<std::uint64_t, std::uint64_t>> slot() const;
    // Who proposes at (height, slot).
    Node          proposer(std::uint64_t height, std::uint64_t slot) const { return windower_.expected(height, slot); }
    std::uint32_t quorum() const { return lux::node::quorum(cfg_.committee); }
    // The journal cannot write, and only a restart reopens it whole.
    bool          broken() const noexcept { return journal_.broken(); }

    // The position this node signs for a block. ONE definition, so a block
    // proposed and the same block followed produce the same message.
    lux::consensus::VotePosition position(const Block& b) const;

private:
    struct Sibling {
        Proposal               proposal;
        std::array<std::uint8_t, 32> frame{};
        Node                   proposer{};
        bool                   own = false;
        std::shared_ptr<Block> block;
    };
    struct Instance {
        std::uint64_t                  height = 0;
        Id                             tip{};
        Clock::time_point              began;
        std::uint64_t                  opened = 0;  // the tip's timestamp, seconds
        std::map<Id, Sibling>          siblings;    // by id: the first is the lowest
        std::optional<Clock::time_point> offered, closes;
        std::map<std::pair<Node, Node>, std::pair<std::uint32_t, Clock::time_point>> junk;
        std::map<std::array<std::uint8_t, 32>, std::pair<std::optional<Clock::time_point>, Duration>> refused;
        std::map<Node, Statement>      votes;       // the first verified vote from each validator
        std::optional<Statement>       bound;       // this validator's own statement here
        std::optional<Id>              built;
        std::optional<Clock::time_point> empty, stalled, hurried;
        bool                           push = false;
        // The block and signature count a certificate was last tried with and
        // did not form: tried again only when either moves, so a set that
        // cannot certify (below the Quasar floor) costs no pairing a pass.
        std::optional<std::pair<Id, std::size_t>> tried;
        Clock::time_point              retry;
        Duration                       backoff{};
        std::uint32_t                  attempts = 0;
    };
    struct Arrival {
        bool                     vote = false;
        std::optional<Proposal>  proposal;
        std::optional<Statement> statement;
    };
    // The anchor in progress, while the gate stands.
    struct Anchor {
        std::uint64_t              height = 0;
        Id                         tip{};
        Message                    message{};
        std::map<Node, Signature>  sigs;
        bool                       signed_ = false;
        bool                       refused = false;  // another statement stands at T, or T is behind the ledger
        Clock::time_point          retry;
        Duration                   backoff{};
        std::optional<Clock::time_point> stalled;    // the journal did not take it
        std::size_t                tried = 0;        // signatures a certificate was last tried with
    };
    struct Asked {
        std::uint32_t     left = kAskBurst;
        Clock::time_point since;
    };

    Duration settle() const;
    Duration poll() const { return cfg_.window / 100; }
    std::uint64_t slot_of(const Instance& at) const;
    std::uint64_t wall(const Instance& at) const;
    Node          node_at(std::uint32_t seat) const;

    Instance enter(std::uint64_t height, const Id& tip, Step& out);
    void     arrive(Instance& at, const Node& link, Arrival a, Step& out);
    void     later_from(const Node& link, Arrival a);
    bool     signed_vote(const Statement& s, const Claim& c) const;
    void     proposed(Instance& at, Proposal p, Step& out);
    void     refuse(Instance& at, const Node& who, const Node& link, const std::array<std::uint8_t, 32>& frame,
                    bool unavailable, const std::string& why, Step& out);
    std::optional<std::optional<Id>> room(const Instance& at, const Node& who, const Id& id) const;
    void     live(Instance& at, const Id& id, Sibling s);
    void     stir(Instance& at) const;
    void     hurry(Instance& at) const;
    std::size_t named(const Instance& at, const Id& id) const;
    void     offer(Instance& at, Step& out);
    void     vote(Instance& at, Step& out);
    std::optional<std::pair<Id, std::size_t>> leading(const Instance& at) const;
    bool     decide(Instance& at, Step& out);
    bool     retry(Instance& at, Step& out);
    void     behind(std::uint64_t height, bool lost, bool settled, Step& out);

    // Statements and the anchor.
    void     broadcast(const Statement& s);
    std::optional<Statement> say(const Message& m, Step& out, std::optional<Clock::time_point>& stalled);
    void     anchor_begin(Step& out);
    void     anchor_statement(const Statement& s, const Claim& c, Step& out);
    void     anchor_step(Step& out);
    bool     lift(Step& out);

    // Catch-up.
    void     ask(std::uint64_t from, std::uint32_t count);
    void     serve(std::uint32_t seat, const std::vector<std::uint8_t>& question);
    void     answered(std::uint32_t seat, const std::vector<std::uint8_t>& answer, Step& out);
    bool     accept_certified(const std::shared_ptr<Block>& b, const Certificate& cert, Step& out);

    std::unique_ptr<VM> vm_;
    Host&               host_;
    std::mutex&         guard_;
    EngineConfig        cfg_;
    Id                  set_root_{};
    Windower            windower_;
    Journal             journal_;
    Ledger              ledger_;
    bool                gated_ = false;

    std::optional<Instance> at_;
    std::optional<Anchor>   anchor_;
    std::map<Node, std::vector<Arrival>> later_;
    std::map<Node, std::uint64_t>        heights_;
    std::map<Node, std::pair<std::uint32_t, Clock::time_point>> checks_;
    std::size_t                          joined_ = 0;
    std::optional<Clock::time_point>     asked_;
    std::map<std::uint32_t, Asked>       askers_;
    // The question each peer has not answered yet: an answer is taken only to
    // a question this node asked that peer (mesh.rs NONE).
    std::map<std::uint32_t, std::uint64_t> awaiting_;
    // Statements at this height whose signature did not check, a link's turns
    // a settle window: past them, that link's statements are not looked at.
    std::map<Node, std::pair<std::uint32_t, Clock::time_point>> forged_;

    // What the mesh handed over since the last pass, by the seat it came in on.
    std::map<std::uint32_t, std::deque<Proposal>>  proposals_in_;
    std::map<std::uint32_t, std::deque<Statement>> statements_in_;
    std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t>>> answers_in_;
};

}  // namespace lux::node
