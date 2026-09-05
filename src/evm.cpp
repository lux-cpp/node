// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// evm.cpp — the C-Chain, executed by cevm.
//
// The only translation unit in node that knows evmc, intx or StateDB. What
// leaves it is a node::VM, a 32-byte root, and answers to the handful of
// questions the RPC asks.

#include "lux/node/evm.hpp"

#include "rlp.hpp"

#include <cevm/cevm.h>              // evmc_create_cevm
#include <evmc/evmc.hpp>
#include <intx/intx.hpp>
#include <lux/crypto/secp256k1.h>   // secp256k1_ecrecover
#include <state/processor.hpp>      // evm::state::process_block / Transaction / TxContext
#include <state/state_db.hpp>       // evm::state::StateDB
#include <test/state/hash_utils.hpp>  // cevm::keccak256

#include "lux/zap/wire.hpp"         // the one codec: blocks are framed like votes

#include <algorithm>
#include <chrono>
#include <cstring>
#include <map>
#include <stdexcept>
#include <unordered_map>

namespace lux::node::evm {
namespace {

// ── conversions at the boundary, and only here ──────────────────────────────

evmc::address to_evmc(const Address& a) noexcept {
    evmc::address out{};
    std::memcpy(out.bytes, a.data(), 20);
    return out;
}
Id to_id(const evmc::bytes32& b) noexcept {
    Id out{};
    std::memcpy(out.data(), b.bytes, 32);
    return out;
}
intx::uint256 to_uint(const Word& w) noexcept {
    return intx::be::unsafe::load<intx::uint256>(w.data());
}
Word from_uint(const intx::uint256& v) noexcept {
    Word w{};
    intx::be::unsafe::store(w.data(), v);
    return w;
}
Id keccak(std::span<const std::uint8_t> in) noexcept {
    return to_id(cevm::keccak256({in.data(), in.size()}));
}

// The EVM revision this chain runs. CANCUN, because the live C-Chain genesis
// sets cancunTime: 0 — a node pinned to Shanghai executes a different EVM from
// the network it claims to be on, and forks the moment a block uses anything
// the two revisions disagree about (TSTORE/TLOAD, and SELFDESTRUCT, which
// EIP-6780 confines to the transaction that created the account).
//
// Flipping this alone would not have been enough: EIP-6780 has to be
// implemented, or a Cancun-labelled node still destroys accounts Cancun keeps.
// It is, because execution now runs through cevm::state::transition, whose
// Cancun behaviour is checked against go-ethereum t8n — a SELFDESTRUCT
// scenario produces byte-identical roots on both, and differs from the same
// scenario at Shanghai, which is what proves the fork is real rather than a
// label.
constexpr evmc_revision kRevision = EVMC_CANCUN;

// ── the block, and its bytes ────────────────────────────────────────────────
//
// One encoding, written with the ZAP Writer — the same codec the vote frames
// use. A block is defined by these five fields and its id is the keccak of
// exactly them, so two nodes that build the same block agree on its id without
// having to agree on anything else.

class BlockImpl final : public node::Block {
public:
    BlockImpl(Chain::State* st, Id parent, std::uint64_t height, std::uint64_t timestamp,
              Id root, std::vector<Tx> txs, bool verified)
        : st_(st), parent_(parent), height_(height), timestamp_(timestamp), root_(root),
          txs_(std::move(txs)), verified_(verified) {
        lux::zap::Writer w;
        w.write_bytes(parent_.data(), parent_.size());
        w.write_u64(height_);
        w.write_u64(timestamp_);
        w.write_bytes(root_.data(), root_.size());
        w.write_u32(static_cast<std::uint32_t>(txs_.size()));
        for (const auto& t : txs_) w.write_bytes(t.raw);
        bytes_ = w.take();
        id_    = keccak(bytes_);
    }

    Id                            id() const override { return id_; }
    Id                            parent() const override { return parent_; }
    std::uint64_t                 height() const override { return height_; }
    std::span<const std::uint8_t> bytes() const override { return bytes_; }
    Id                            root() const override { return root_; }

    // The block was executed before it was constructed — a BlockImpl cannot be
    // made without a root, and the root can only come from running it. `verify`
    // reports what that execution concluded rather than doing it a second time.
    bool verify() override { return verified_; }

    // Accepting is what moves the tip, and it is the ONLY thing that does. The
    // driver calls it after a quorum certificate over this block's position
    // verified, so the chain advances on a certificate rather than on a local
    // decision. Defined below, where Chain::State is complete.
    void accept() override;

    // The other half of being decided: this block lost, so the transactions it
    // took go back. Defined below, beside accept — the two are one rule read
    // from its two ends.
    void reject() override;

    std::uint64_t          timestamp() const noexcept { return timestamp_; }
    const std::vector<Tx>& txs() const noexcept { return txs_; }

private:
    Chain::State*             st_;
    Id                        parent_, root_, id_;
    std::uint64_t             height_, timestamp_;
    std::vector<Tx>           txs_;
    std::vector<std::uint8_t> bytes_;
    bool                      verified_;
    // A block is decided ONCE, one way. Whichever call arrives first wins and
    // the other is inert, so a second trigger cannot both advance the tip and
    // hand the same transactions back.
    bool                      decided_ = false;
};

}  // namespace

// ── transaction decode + sender recovery ────────────────────────────────────
//
// Three encodings are accepted, because three are in use: EIP-155 legacy,
// EIP-2930 (type 1) and EIP-1559 (type 2). All three differ only in which
// fields precede the signature and what the signing preimage is; the recovery
// is one operation at the end.

std::optional<Tx> Tx::decode(std::span<const std::uint8_t> raw, std::uint64_t chain_id) {
    if (raw.empty()) return std::nullopt;

    const bool          typed = raw[0] <= 0x7f;   // EIP-2718: a leading type byte
    const std::uint8_t  type  = typed ? raw[0] : 0;
    if (typed && type != 0x01 && type != 0x02) return std::nullopt;
    const auto body = typed ? raw.subspan(1) : raw;

    const auto outer = rlp::item(body);
    if (!outer || !outer->list || outer->raw.size() != body.size()) return std::nullopt;
    const auto f = rlp::items(outer->payload);
    if (!f) return std::nullopt;
    const auto& v = *f;

    // Field layout per encoding. `sig_at` is where (v|yParity, r, s) begin, and
    // everything before it is the signing preimage's item list.
    std::size_t sig_at = 0;
    switch (type) {
        case 0x00: if (v.size() != 9)  return std::nullopt; sig_at = 6;  break;
        case 0x01: if (v.size() != 11) return std::nullopt; sig_at = 8;  break;
        case 0x02: if (v.size() != 12) return std::nullopt; sig_at = 9;  break;
        default:   return std::nullopt;
    }

    Tx tx;
    tx.raw.assign(raw.begin(), raw.end());
    tx.hash = keccak(raw);

    // Index of each shared field, which shifts by the leading chainId on a typed
    // transaction and again by the fee split on 1559.
    const std::size_t i0 = typed ? 1 : 0;             // nonce
    const std::size_t ig = i0 + (type == 0x02 ? 3 : 2);  // gas limit
    const std::size_t iprice = (type == 0x02) ? i0 + 2 : i0 + 1;  // maxFee / gasPrice

    auto nonce = rlp::u64(v[i0]);
    auto gas   = rlp::u64(v[ig]);
    auto price = rlp::word(v[iprice]);
    auto value = rlp::word(v[ig + 2]);
    if (!nonce || !gas || !price || !value) return std::nullopt;
    tx.nonce     = *nonce;
    tx.gas       = *gas;
    tx.gas_price = *price;
    tx.value     = *value;

    // `to` empty is a contract creation — the one field whose LENGTH carries
    // meaning rather than its value.
    const auto& to = v[ig + 1];
    if (to.list) return std::nullopt;
    if (to.payload.empty()) {
        tx.create = true;
    } else {
        if (to.payload.size() != 20) return std::nullopt;
        std::copy(to.payload.begin(), to.payload.end(), tx.to.begin());
    }
    const auto& data = v[ig + 3];
    if (data.list) return std::nullopt;
    tx.data.assign(data.payload.begin(), data.payload.end());

    // A typed transaction states its chain id; a legacy one hides it in `v`.
    if (typed) {
        auto cid = rlp::u64(v[0]);
        if (!cid || *cid != chain_id) return std::nullopt;
    }

    // ── the signing preimage ────────────────────────────────────────────────
    // Concatenate the RAW encodings of the preimage fields and re-wrap them as a
    // list. Re-serializing decoded VALUES instead would mean re-choosing an
    // encoding the sender already chose, and any disagreement about minimality
    // would recover a different — valid-looking — sender.
    std::vector<std::uint8_t> inner;
    for (std::size_t i = 0; i < sig_at; ++i)
        inner.insert(inner.end(), v[i].raw.begin(), v[i].raw.end());

    std::uint8_t recid = 0;
    if (type == 0x00) {
        auto vv = rlp::u64(v[6]);
        if (!vv) return std::nullopt;
        if (*vv == 27 || *vv == 28) {
            // Pre-EIP-155: no chain id in the signature, so nothing binds this
            // transaction to this chain. Replayable by construction — refuse it
            // rather than execute someone else's chain's transaction here.
            return std::nullopt;
        }
        // EIP-155: v = chain_id*2 + 35 + recid, and the preimage gains
        // (chain_id, 0, 0).
        const std::uint64_t base = chain_id * 2 + 35;
        if (*vv != base && *vv != base + 1) return std::nullopt;
        recid = static_cast<std::uint8_t>(*vv - base);
        for (auto&& s : {rlp::scalar(chain_id), rlp::scalar(0), rlp::scalar(0)})
            inner.insert(inner.end(), s.begin(), s.end());
    } else {
        auto y = rlp::u64(v[sig_at]);
        if (!y || *y > 1) return std::nullopt;
        recid = static_cast<std::uint8_t>(*y);
    }

    std::vector<std::uint8_t> preimage;
    if (typed) preimage.push_back(type);
    const auto hdr = rlp::list_header(inner.size());
    preimage.insert(preimage.end(), hdr.begin(), hdr.end());
    preimage.insert(preimage.end(), inner.begin(), inner.end());
    const Id sighash = keccak(preimage);

    // r and s, left-padded: RLP strips leading zeros, ecrecover wants 32 bytes.
    const auto& ri = v[sig_at + (type == 0x00 ? 1 : 1)];
    const auto& si = v[sig_at + 2];
    if (ri.list || si.list || ri.payload.size() > 32 || si.payload.size() > 32)
        return std::nullopt;
    std::uint8_t r[32]{}, s[32]{};
    std::copy(ri.payload.begin(), ri.payload.end(), r + 32 - ri.payload.size());
    std::copy(si.payload.begin(), si.payload.end(), s + 32 - si.payload.size());

    std::uint8_t pub[64]{};
    if (secp256k1_ecrecover(sighash.data(), r, s, recid, pub) != SECP256K1_OK)
        return std::nullopt;
    // The address is the low 20 bytes of keccak(pubkey), which is the ONLY place
    // the sender comes from — a transaction never names its own sender.
    const Id pkh = keccak(std::span<const std::uint8_t>(pub, 64));
    std::copy(pkh.begin() + 12, pkh.end(), tx.sender.begin());
    return tx;
}

// ── the chain ───────────────────────────────────────────────────────────────

struct Chain::State {
    Genesis                  genesis;
    ::evm::state::StateDB    db;
    evmc_vm*                 vm = nullptr;

    std::map<Id, std::shared_ptr<BlockImpl>>           blocks;    // by id
    std::map<std::uint64_t, std::shared_ptr<BlockImpl>> by_height;
    Id                                                  accepted_id{};
    std::uint64_t                                       accepted_height = 0;
    Id                                                  preferred{};

    std::vector<Tx>                          mempool;
    std::map<Id, char>                       seen;   // tx hash → in mempool or mined

    ~State() {
        if (vm) vm->destroy(vm);
    }

    // Execute `txs` against the resident state and COMMIT, returning the root
    // execution produced. This is the one place a root is ever made.
    Id execute(const std::vector<Tx>& txs, std::uint64_t height, std::uint64_t timestamp) {
        std::vector<::evm::state::Transaction> batch;
        batch.reserve(txs.size());
        for (const auto& t : txs) {
            ::evm::state::Transaction e;
            e.sender    = to_evmc(t.sender);
            e.recipient = to_evmc(t.to);
            e.value     = to_uint(t.value);
            e.gas_price = to_uint(t.gas_price);
            e.gas_limit = t.gas;
            e.nonce     = t.nonce;
            e.data      = t.data;
            e.is_create = t.create;
            batch.push_back(std::move(e));
        }

        // BLOCKHASH's window: the 256 blocks before this one, most recent
        // first. Built from the accepted chain, so what a contract reads is the
        // id this node actually decided — the host answers zero for anything
        // outside the window, which is what geth answers too.
        std::vector<evmc::bytes32> recent;
        recent.reserve(256);
        for (std::uint64_t h = height; h-- > 0 && recent.size() < 256;) {
            const auto it = by_height.find(h);
            if (it == by_height.end()) break;
            evmc::bytes32 id{};
            const auto bid = it->second->id();
            std::memcpy(id.bytes, bid.data(), 32);
            recent.push_back(id);
        }

        ::evm::state::TxContext ctx{};
        ctx.block_number    = static_cast<std::int64_t>(height);
        ctx.block_timestamp = static_cast<std::int64_t>(timestamp);
        ctx.block_gas_limit = static_cast<std::int64_t>(genesis.gas_limit);
        ctx.chain_id = intx::be::store<evmc::uint256be>(intx::uint256{genesis.chain_id});
        ctx.recent_hashes   = recent.empty() ? nullptr : recent.data();
        ctx.n_recent_hashes = recent.size();

        const auto r = ::evm::state::process_block(db, batch, vm, ctx, kRevision);
        return to_id(r.state_root);
    }
};

Chain::Chain(Genesis genesis) : st_(std::make_unique<State>()) {
    st_->genesis = std::move(genesis);
    st_->vm      = evmc_create_cevm();
    if (st_->vm == nullptr)
        throw std::runtime_error("evm: evmc_create_cevm returned no VM");

    // Genesis: credit the alloc, then COMMIT. The root of that commit is the
    // state root of block 0 — a real MPT root over the real allocation, not a
    // constant. Every validator computes it from the same genesis and therefore
    // starts from the same 32 bytes.
    for (const auto& [addr, bal] : st_->genesis.alloc) {
        const auto a = to_evmc(addr);
        st_->db.create_account(a);
        st_->db.set_balance(a, to_uint(bal));
    }
    const Id root = to_id(st_->db.commit());

    auto g = std::make_shared<BlockImpl>(st_.get(), kEmptyId, 0, 0, root,
                                        std::vector<Tx>{}, true);
    st_->blocks[g->id()]  = g;
    st_->by_height[0]     = g;
    st_->accepted_id      = g->id();
    st_->accepted_height  = 0;
    st_->preferred        = g->id();
}

Chain::~Chain() = default;

Id Chain::chain_id() const {
    // The consensus chain id is the keccak of the EVM chain id under a fixed
    // label, so the two ids are one decision: a chain cannot be configured with
    // an EVM id of 31337 and a consensus id belonging to some other chain.
    std::vector<std::uint8_t> tag{'l', 'u', 'x', '-', 'e', 'v', 'm', ':'};
    for (int i = 7; i >= 0; --i)
        tag.push_back(static_cast<std::uint8_t>((st_->genesis.chain_id >> (i * 8)) & 0xff));
    return keccak(tag);
}

std::uint64_t Chain::eth_chain_id() const noexcept { return st_->genesis.chain_id; }

std::string Chain::alias() const { return st_->genesis.alias; }

std::shared_ptr<node::Block> Chain::build() {
    const auto parent = st_->by_height.at(st_->accepted_height);
    const std::uint64_t height = st_->accepted_height + 1;
    // A block's timestamp must be a function of the chain, not of the wall clock
    // on whichever machine built it: every validator builds the same block here,
    // and two clocks that disagree would produce two different blocks and no
    // quorum. The parent's time plus one second is the whole rule.
    const std::uint64_t ts = parent->timestamp() + 1;

    std::vector<Tx> txs;
    txs.swap(st_->mempool);
    // Deterministic order, so that two nodes holding the same set of pending
    // transactions build the byte-identical block. Sender then nonce is the
    // ordering every EVM already needs to respect; the hash breaks the tie.
    std::sort(txs.begin(), txs.end(), [](const Tx& a, const Tx& b) {
        if (a.sender != b.sender) return a.sender < b.sender;
        if (a.nonce != b.nonce) return a.nonce < b.nonce;
        return a.hash < b.hash;
    });

    const Id root = st_->execute(txs, height, ts);
    auto blk = std::make_shared<BlockImpl>(st_.get(), parent->id(), height, ts, root,
                                          std::move(txs), true);
    st_->blocks[blk->id()] = blk;
    return blk;
}

std::shared_ptr<node::Block> Chain::parse(std::span<const std::uint8_t> b) {
    lux::zap::Reader r(b.data(), b.size());
    std::vector<std::uint8_t> parent, root;
    std::uint64_t             height = 0, ts = 0;
    std::uint32_t             ntx = 0;
    if (!r.read_bytes(parent) || !r.read_u64(height) || !r.read_u64(ts) ||
        !r.read_bytes(root) || !r.read_u32(ntx))
        return nullptr;
    if (parent.size() != 32 || root.size() != 32) return nullptr;

    // NOT reserved from `ntx`. It is a peer-supplied uint32 and reserving it
    // asks for up to 4 billion Transactions in one call — length_error or
    // bad_alloc, thrown out of a decode that no one catches, which ends the
    // process. The loop is already bounded by the bytes actually present: the
    // first tx whose length does not fit fails the read and the block is
    // refused. Growing the vector geometrically costs nothing against that.
    std::vector<Tx> txs;
    for (std::uint32_t i = 0; i < ntx; ++i) {
        std::vector<std::uint8_t> raw;
        if (!r.read_bytes(raw)) return nullptr;
        auto t = Tx::decode(raw, st_->genesis.chain_id);
        if (!t) return nullptr;  // a peer cannot put an unsigned tx in a block
        txs.push_back(std::move(*t));
    }
    if (r.remaining() != 0) return nullptr;  // trailing bytes are a second encoding

    Id p{}, claimed{};
    std::copy(parent.begin(), parent.end(), p.begin());
    std::copy(root.begin(), root.end(), claimed.begin());

    // A PEER'S ROOT IS A CLAIM. Execute the block here and keep OUR root; the
    // block verifies only if the two agree. This is the whole reason the node
    // holds an EVM rather than a header parser.
    const Id ours = st_->execute(txs, height, ts);
    auto blk = std::make_shared<BlockImpl>(st_.get(), p, height, ts, ours, std::move(txs),
                                          ours == claimed);
    st_->blocks[blk->id()] = blk;
    return blk;
}

std::shared_ptr<node::Block> Chain::get(const Id& id) const {
    const auto it = st_->blocks.find(id);
    return it == st_->blocks.end() ? nullptr : it->second;
}

void Chain::prefer(const Id& id) { st_->preferred = id; }
Id   Chain::last_accepted() const { return st_->accepted_id; }
std::uint64_t Chain::last_accepted_height() const { return st_->accepted_height; }

Id Chain::state_root() const { return st_->by_height.at(st_->accepted_height)->root(); }

Word Chain::balance(const Address& a) const {
    return from_uint(st_->db.get_balance(to_evmc(a)));
}
std::uint64_t Chain::nonce(const Address& a) const { return st_->db.get_nonce(to_evmc(a)); }
std::vector<std::uint8_t> Chain::code(const Address& a) const {
    const auto& c = st_->db.get_code(to_evmc(a));
    return {c.begin(), c.end()};
}
Word Chain::storage(const Address& a, const Word& key) const {
    evmc::bytes32 k{};
    std::memcpy(k.bytes, key.data(), 32);
    return to_id(st_->db.get_storage(to_evmc(a), k));
}

std::optional<Id> Chain::accept_tx(std::span<const std::uint8_t> raw) {
    auto t = Tx::decode(raw, st_->genesis.chain_id);
    if (!t) return std::nullopt;
    if (st_->seen.count(t->hash)) return t->hash;  // idempotent, not an error
    st_->seen[t->hash] = 1;
    const Id h = t->hash;
    st_->mempool.push_back(std::move(*t));
    return h;
}

std::optional<Id> Chain::accept_tx_from_peer(std::span<const std::uint8_t> raw) {
    return accept_tx(raw);  // same verification; a peer earns no shortcut
}

std::size_t Chain::pending() const noexcept { return st_->mempool.size(); }

std::vector<std::vector<std::uint8_t>> Chain::pending_raw() const {
    std::vector<std::vector<std::uint8_t>> out;
    out.reserve(st_->mempool.size());
    for (const auto& t : st_->mempool) out.push_back(t.raw);
    return out;
}

std::shared_ptr<node::Block> Chain::at_height(std::uint64_t h) const {
    const auto it = st_->by_height.find(h);
    return it == st_->by_height.end() ? nullptr : it->second;
}

std::vector<Tx> Chain::block_txs(const Id& id) const {
    const auto it = st_->blocks.find(id);
    return it == st_->blocks.end() ? std::vector<Tx>{} : it->second->txs();
}

namespace {

void BlockImpl::accept() {
    if (decided_) return;  // idempotent: a height is decided once
    decided_ = true;
    const auto it = st_->blocks.find(id_);
    if (it == st_->blocks.end()) return;
    st_->by_height[height_]  = it->second;
    st_->accepted_id         = id_;
    st_->accepted_height     = height_;
    st_->preferred           = id_;

    // A mined transaction leaves the pool. This is the only place it can happen
    // and be right: until the block is ACCEPTED the transaction is still
    // pending, and after it a node that kept it would propose it a second time
    // at the next height it leads (where it would fail on its nonce, but only
    // after being executed).
    for (const auto& t : txs_) {
        const auto at = std::find_if(st_->mempool.begin(), st_->mempool.end(),
                                     [&](const Tx& p) { return p.hash == t.hash; });
        if (at != st_->mempool.end()) st_->mempool.erase(at);
    }
}

void BlockImpl::reject() {
    if (decided_) return;  // idempotent, and inert once accepted
    decided_ = true;

    // The block is unreachable now: nothing may build on it and nothing may ask
    // for it. Go frees exactly this much on a reject — the block's pinned state
    // and nothing else (manager.free / backend.free). The map owns a reference,
    // so one is held here first: erasing it is otherwise the last owner
    // releasing the object whose method is running.
    std::shared_ptr<BlockImpl> alive;
    if (const auto pinned = st_->blocks.find(id_); pinned != st_->blocks.end()) {
        alive = std::move(pinned->second);
        st_->blocks.erase(pinned);
    }

    // AND THE TRANSACTIONS COME BACK. build() swapped the whole pool into this
    // block, so this is the only thing standing between a height that failed to
    // certify and a node whose pool is empty while every peer still holds the
    // transactions — the disagreement that then produces a different block at
    // the next height. Go returns them the same way (platformvm's rejector
    // reissues the block's decision txs; xvm's Reject re-checks and reissues).
    //
    // By hash, and skipping what is already waiting, because a followed block's
    // transactions may never have left this node's pool: they arrived by gossip
    // and were only ever removed by ACCEPT. Adding a second copy would put the
    // same transaction in a block twice.
    for (const auto& t : txs_) {
        const auto at = std::find_if(st_->mempool.begin(), st_->mempool.end(),
                                     [&](const Tx& p) { return p.hash == t.hash; });
        if (at == st_->mempool.end()) st_->mempool.push_back(t);
    }
}

}  // namespace

}  // namespace lux::node::evm
