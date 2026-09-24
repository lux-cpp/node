// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// statement_test.cpp — what a validator signs, what it keeps, and what α of it
// make: the two message kinds and their domain separation, the one journal both
// go through, the certificate rule, and the ledger and held records a restart
// reads back.

#include "lux/consensus/bls.hpp"
#include "lux/node/journal.hpp"
#include "lux/node/ledger.hpp"
#include "lux/node/signer.hpp"
#include "lux/node/statement.hpp"

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include <unistd.h>

using namespace lux::node;

namespace {

int g_fail = 0;
void check(bool ok, const std::string& what) {
    std::printf("  %s  %s\n", ok ? "ok  " : "FAIL", what.c_str());
    if (!ok) ++g_fail;
}

std::filesystem::path scratch(const std::string& name) {
    const auto dir = std::filesystem::temp_directory_path() /
                     ("node-statement-" + std::to_string(::getpid()) + "-" + name);
    std::filesystem::remove_all(dir);
    std::filesystem::create_directories(dir);
    return dir;
}

Id filled(std::uint8_t b) {
    Id id{};
    id.fill(b);
    return id;
}

lux::consensus::VotePosition position(const Id& chain, std::uint64_t height, const Id& block, const Id& parent,
                                      const Id& set) {
    lux::consensus::VotePosition p{};
    p.chain_id            = chain;
    p.height              = height;
    p.block_id            = block;
    p.parent_id           = parent;
    p.canonical_id        = block;
    p.parent_canonical_id = parent;
    p.validator_set_root  = set;
    return p;
}

struct Seat {
    std::unique_ptr<Signer> signer;
};

}  // namespace

int main() {
    std::printf("=========== node — statements, the journal, certificates ===========\n");

    const Id chain = filled(0xc1), set = filled(0x5e), block = filled(0xb1), parent = filled(0xb0);

    // ── the two messages ─────────────────────────────────────────────────────
    const auto pos  = position(chain, 800, block, parent, set);
    const auto vote = vote_message(pos);
    {
        const auto go = lux::consensus::canonical_vote_message(pos, true);
        check(go.size() == kMessageLen && std::equal(go.begin(), go.end(), vote.begin()),
              "a vote is Go's canonical vote message, 226 bytes");
        check(std::equal(kVoteTag.begin(), kVoteTag.end(), go.begin()), "under Go's tag");
        const auto c = read(vote);
        check(c && c->kind == Kind::Vote && c->slot.chain == chain && c->slot.height == 800 &&
                  c->slot.round == 0 && c->block == block && c->parent == parent && c->set_root == set,
              "and reads back to the position it signs");
    }
    const auto anchor = anchor_message(chain, 799, parent, set);
    {
        const auto c = read(anchor);
        check(c && c->kind == Kind::Anchor && c->slot.chain == chain && c->slot.height == 799 &&
                  c->block == parent && c->set_root == set && c->parent == Id{},
              "an anchor names the chain, the height, the tip and the set");
        check(std::equal(anchor.begin() + 18, anchor.begin() + 21, vote.begin() + 18),
              "and carries the vote's version and role");
        Message odd = anchor;
        odd[100]    = 1;  // the parent axis, which an anchor leaves zero
        check(!read(odd), "an anchor with a parent is no anchor");
        odd       = anchor;
        odd[225]  = 0;
        check(!read(odd), "nor one that is not an accept");
        odd       = vote;
        odd[0]    = 'X';
        check(!read(odd), "and a message under neither tag is nothing");
    }
    {
        // THE TAG IS THE DOMAIN. An anchor on (799, H) and a vote for block H at
        // 799 differ in the tag, so a signature over one is not one over the
        // other, though both are made with the one voting key.
        std::array<std::uint8_t, 32> seed{7}, sk{};
        lux::consensus::PubKey        pk{};
        (void)lux::consensus::bls::keygen(seed.data(), sk.data());
        (void)lux::consensus::bls::sk_to_pk(sk.data(), pk.data());
        const auto same = vote_message(position(chain, 799, parent, filled(0xaa), set));
        const auto s    = sign(anchor, Node{}, sk);
        check(lux::consensus::bls::verify(pk.data(), anchor.data(), anchor.size(), s.sig.data()) == 0,
              "an anchor signature verifies as an anchor");
        check(lux::consensus::bls::verify(pk.data(), same.data(), same.size(), s.sig.data()) != 0,
              "and never as a vote for the same block at the same height");
    }

    // ── a committee of five, published the way a daemon publishes ─────────────
    std::vector<Seat> seats;
    std::string       text;
    const auto        keys = scratch("keys");
    for (int i = 0; i < 5; ++i) {
        Seat s;
        s.signer = std::make_unique<Signer>(Signer::open(keys / std::to_string(i)));
        text += s.signer->publish(chain) + "\n";
        seats.push_back(std::move(s));
    }
    const Committee committee = Committee::read(text, chain);
    check(quorum(committee) == 4, "five validators certify with four");

    // ── statements on the wire ───────────────────────────────────────────────
    {
        const Statement s = sign(vote, seats[0].signer->node(), seats[0].signer->secret());
        check(verify(s, committee), "a member's signed vote verifies");
        const auto frame = encode(s);
        const auto back  = decode_statement(frame);
        check(frame.size() == 4 + 226 + 4 + 20 + 4 + 96 && back && back->message == s.message &&
                  back->node == s.node && back->sig == s.sig,
              "a statement is 354 bytes on the wire, and reads back whole");
        auto longer = frame;
        longer.push_back(0);
        check(!decode_statement(longer), "a byte past it is refused");
        Statement wrong = s;
        wrong.node      = seats[1].signer->node();
        check(!verify(wrong, committee), "a signature under another member's name is refused");
    }

    // ── certificates ─────────────────────────────────────────────────────────
    // Over this committee's own chain and set: a certificate speaks of the
    // committee that made it.
    const auto                anchored = anchor_message(chain, 799, parent, committee.root());
    std::map<Node, Signature> sigs;
    for (int i = 0; i < 4; ++i)
        sigs[seats[std::size_t(i)].signer->node()] = sign(anchored, {}, seats[std::size_t(i)].signer->secret()).sig;
    {
        auto three = sigs;
        three.erase(three.begin());
        check(!certify(anchored, three, committee), "three of five certify nothing");
        check(!certify(anchor, sigs, committee), "signatures over one message certify no other");
        const auto cert = certify(anchored, sigs, committee);
        check(cert && verify(*cert, committee), "four of five are a certificate");
        const auto bytes = encode(*cert);
        const auto back  = decode_certificate(bytes);
        check(back && back->message == cert->message && back->signers == cert->signers &&
                  back->aggregate == cert->aggregate && verify(*back, committee),
              "which reads back and verifies");
        auto longer = bytes;
        longer.push_back(0);
        check(!decode_certificate(longer), "a byte past it is refused");
        Certificate forged = *cert;
        forged.message     = anchor_message(chain, 799, block, committee.root());
        check(!verify(forged, committee), "the same signatures over another tip are not a certificate");
        forged         = *cert;
        forged.message = anchor;  // the same tip under a set root that is not this committee's
        check(!verify(forged, committee), "nor under a set root that is not this committee's");
        forged         = *cert;
        forged.signers = {cert->signers[1], cert->signers[0], cert->signers[2], cert->signers[3]};
        check(!verify(forged, committee), "signers out of order are refused");
        forged                    = *cert;
        forged.signers.push_back(cert->signers[3]);
        check(!verify(forged, committee), "a signer counted twice is refused");
        forged         = *cert;
        forged.signers.pop_back();
        check(!verify(forged, committee), "a certificate that drops a signer does not verify");

        // The same five, entitled on another chain, are another committee.
        std::string elsewhere;
        for (auto& s : seats) elsewhere += s.signer->publish(filled(0xee)) + "\n";
        check(!verify(*cert, Committee::read(elsewhere, filled(0xee))),
              "a certificate does not carry to another chain's committee");

        // Below the Quasar floor there is no certificate at all.
        std::string three_text;
        for (int i = 0; i < 3; ++i) three_text += seats[std::size_t(i)].signer->publish(chain) + "\n";
        const Committee small = Committee::read(three_text, chain);
        const auto                msg3 = anchor_message(chain, 799, parent, small.root());
        std::map<Node, Signature> all3;
        for (int i = 0; i < 3; ++i)
            all3[seats[std::size_t(i)].signer->node()] = sign(msg3, {}, seats[std::size_t(i)].signer->secret()).sig;
        check(!certify(msg3, all3, small), "three validators certify nothing, even all three");
    }

    // ── the journal ──────────────────────────────────────────────────────────
    {
        const auto dir  = scratch("journal");
        const auto path = dir / "votes";
        {
            auto j = Journal::open(path);
            check(j.admit(vote) == Journal::Admit::Ok, "a first statement at height 800 is admitted");
            check(j.admit(vote) == Journal::Admit::Ok, "the same statement again is the same statement");
            const auto other = vote_message(position(chain, 800, filled(0xb2), parent, set));
            check(j.admit(other) == Journal::Admit::Equivocation, "another block at 800 is equivocation");
            check(j.admit(anchor_message(chain, 800, block, set)) == Journal::Admit::Equivocation,
                  "and so is an anchor at 800: one slot, one statement, whatever its kind");
            check(j.admit(anchor) == Journal::Admit::Ok, "an anchor at 799 is admitted");
            Message junk{};
            check(j.admit(junk) == Journal::Admit::NotAStatement, "bytes that are no statement are refused");
            bool held = false;
            try {
                (void)Journal::open(path);
            } catch (const std::runtime_error&) {
                held = true;
            }
            check(held, "a second holder of one journal is refused");
        }
        {
            std::ofstream torn(path, std::ios::app | std::ios::binary);
            torn << std::string(100, 'x');
        }
        auto j = Journal::open(path);
        check(j.size() == 2 && j.standing(Slot{chain, 800, 0}) == vote && j.standing(Slot{chain, 799, 0}) == anchor,
              "a reopen reads both back, and drops a torn tail");
        check(std::filesystem::file_size(path) == 2 * kMessageLen, "cut back to the last whole entry");
        check(j.admit(vote_message(position(chain, 800, filled(0xb3), parent, set))) == Journal::Admit::Equivocation,
              "and still refuses a second statement at 800 after the restart");
    }

    // ── the ledger and the held proposal ─────────────────────────────────────
    {
        const auto dir  = scratch("ledger");
        const auto cert = *certify(anchored, sigs, committee);
        {
            auto l = Ledger::open(dir / "ledger");
            check(l.append(Record{799, parent, cert}), "the anchor is the first record");
            check(l.append(Record{800, block, cert}) && l.append(Record{801, filled(0xb4), cert}),
                  "and heights above it follow");
            check(!l.append(Record{801, filled(0xb5), cert}), "a height already recorded is refused");
            check(l.append(Record{900, filled(0xb6), cert}), "a record may start past a gap (a later anchor)");
        }
        {
            std::ofstream torn(dir / "ledger", std::ios::app | std::ios::binary);
            torn << std::string(7, 'x');
        }
        auto       l    = Ledger::open(dir / "ledger");
        const auto r800 = l.at(800);
        check(r800 && r800->block == block && r800->cert.message == cert.message && !l.at(850) &&
                  l.last() && l.last()->first == 900 && l.first() == 799,
              "a reopen indexes every record and drops a torn tail");

        Proposal p;
        p.height = 800;
        p.slot   = 3;
        p.signature.assign(kProposalSignatureLen, 0x42);
        p.block = {1, 2, 3};
        check(keep_held(dir, p), "the held proposal reaches the device");
        const auto h = held(dir);
        check(h && h->height == 800 && h->slot == 3 && h->signature == p.signature && h->block == p.block,
              "and reads back as it was kept");
        check(!gated(dir), "no gate unless one was closed");
        close_gate(dir);
        check(gated(dir), "a closed gate stands across a reopen");
        check(lift_gate(dir) && !gated(dir), "and a lift removes it");
    }

    std::printf("--------------------------------------------------------------------\n");
    if (g_fail) { std::printf("==== node STATEMENTS: FAIL (%d) ====\n", g_fail); return 1; }
    std::printf("==== node STATEMENTS: PASS — one statement a height, α of them a certificate ====\n");
    return 0;
}
