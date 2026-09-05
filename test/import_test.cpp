// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// import_test.cpp — the C-chain's external format, read back, and the refusal
// that has to follow it.
//
// TWO THINGS ARE UNDER TEST AND THE SECOND ONE MATTERS MORE.
//
// The first is the read: an RLP export is walked block by block, every id is
// recomputed from the header's own bytes, every parentHash must name the block
// before it, and every body must rebuild the transactionsRoot its header
// declares. A file that says the right thing at both ends and lies in the
// middle is refused, and that is asserted by splicing one.
//
// The second is what the node BECOMES. Reading an export moves the tip without
// producing a single certificate under it, so the node knows a height it never
// decided — Go names the same state in vms/proposervm/vm.go and says what must
// follow: such a chain "will NOT build blocks and MUST NOT be treated as a
// caught-up validator until the outer index is rebuilt from certified peer
// state". A node that imports and then proposes would sign an ancestry it never
// verified, which is worse than one that cannot import at all. So the refusal
// is asserted the only way that means anything: the engine is driven, and the
// chain is asked afterwards whether it was ever ASKED TO BUILD. It must not
// have been — the gate is in front of execution, not behind it.
//
// THE EXPORT UNDER TEST. Given a path (argv[1] or $LUX_RLP_EXPORT) this walks a
// canonical export and pins its tip against the values Go's import of the same
// bytes produced. Given none, it synthesizes an export of its own — real RLP,
// real keccak, real linkage — so the refusal, the idempotence and every
// rejection are proven on any machine, with no path baked into the repository.

#include "lux/consensus/threshold.hpp"
#include "lux/node/engine.hpp"
#include "lux/node/evm.hpp"
#include "lux/node/import.hpp"
#include "lux/node/node_host.hpp"

#include "bls_signature.hpp"

#include <bin/cevm/eth_mpt.hpp>
#include <test/state/hash_utils.hpp>

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <unistd.h>
#include <vector>

using namespace lux::node;
using namespace lux::consensus;

namespace {

int  g_fail = 0;
void check(bool ok, const std::string& what) {
    std::printf("  %s  %s\n", ok ? "ok  " : "FAIL", what.c_str());
    if (!ok) ++g_fail;
}

std::string hex(const Id& id) {
    std::string s = "0x";
    char        t[3];
    for (auto c : id) { std::snprintf(t, sizeof(t), "%02x", c); s += t; }
    return s;
}

Id id_of(const std::string& h) {
    Id out{};
    for (std::size_t i = 0; i < 32; ++i)
        out[i] = static_cast<std::uint8_t>(std::stoul(h.substr(2 + 2 * i, 2), nullptr, 16));
    return out;
}

using bytes = cevm::eth::bytes;
namespace erlp = cevm::eth::rlp;

Id keccak(const bytes& b) {
    const auto h = cevm::keccak256({b.data(), b.size()});
    Id         out{};
    std::memcpy(out.data(), h.bytes, 32);
    return out;
}

// ── a synthesized export ────────────────────────────────────────────────────
//
// Fifteen header fields, an empty transaction list and an empty uncle list, so
// the roots the reader recomputes are the empty-trie root and keccak(0xc0). The
// bytes are produced the same way an exporter produces them; nothing here is a
// fixture the reader is taught to accept.

bytes header(const Id& parent, std::uint64_t number, std::uint64_t stamp) {
    const Id empty_trie = id_of("0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421");
    const Id ommers     = keccak(bytes{0xc0});
    const Id zero{};

    auto h32 = [](const Id& v) { return erlp::encode({v.data(), 32}); };
    bytes content;
    auto add = [&content](const bytes& piece) {
        content.insert(content.end(), piece.begin(), piece.end());
    };
    add(h32(parent));                               //  0 parentHash
    add(h32(ommers));                               //  1 ommersHash
    add(erlp::encode(bytes(20, 0x00)));             //  2 coinbase
    add(h32(zero));                                 //  3 stateRoot
    add(h32(empty_trie));                           //  4 transactionsRoot
    add(h32(empty_trie));                           //  5 receiptsRoot
    add(erlp::encode(bytes(256, 0x00)));            //  6 logsBloom
    add(erlp::encode_uint64(1));                    //  7 difficulty
    add(erlp::encode_uint64(number));               //  8 number
    add(erlp::encode_uint64(8'000'000));            //  9 gasLimit
    add(erlp::encode_uint64(0));                    // 10 gasUsed
    add(erlp::encode_uint64(stamp));                // 11 timestamp
    add(erlp::encode(bytes{}));                     // 12 extraData
    add(h32(zero));                                 // 13 mixHash
    add(erlp::encode(bytes(8, 0x00)));              // 14 nonce
    return erlp::wrap_list(content);
}

// One block: [header, [], []].
bytes block_of(const bytes& head) {
    bytes content = head;
    content.push_back(0xc0);  // no transactions
    content.push_back(0xc0);  // no uncles
    return erlp::wrap_list(content);
}

struct Export {
    bytes           file;
    std::vector<Id> ids;  // by height, [0] is the export's genesis
};

Export synthesize(std::uint64_t blocks) {
    Export  e;
    Id      parent{};
    for (std::uint64_t n = 0; n <= blocks; ++n) {
        const bytes h = header(parent, n, 1'700'000'000 + n);
        parent        = keccak(h);
        e.ids.push_back(parent);
        const bytes b = block_of(h);
        e.file.insert(e.file.end(), b.begin(), b.end());
    }
    return e;
}

// A file on disk holding exactly these bytes, removed when it goes out of
// scope. The reader takes a path because that is what a flag carries.
class Temp {
public:
    explicit Temp(const bytes& b) {
        char tmpl[] = "/tmp/lux-node-export-XXXXXX";
        const int fd = ::mkstemp(tmpl);
        if (fd < 0) { std::puts("mkstemp"); std::exit(2); }
        path_ = tmpl;
        if (::write(fd, b.data(), b.size()) != static_cast<ssize_t>(b.size())) {
            std::puts("write");
            std::exit(2);
        }
        ::close(fd);
    }
    ~Temp() { ::unlink(path_.c_str()); }
    Temp(const Temp&) = delete;
    Temp& operator=(const Temp&) = delete;
    const std::string& path() const noexcept { return path_; }

private:
    std::string path_;
};

evm::Genesis local_genesis(std::uint64_t chain_id) {
    evm::Genesis g;
    g.chain_id  = chain_id;
    g.gas_limit = 30'000'000;
    return g;
}

bool refused(evm::Chain& chain, const std::string& path, const std::string& what) {
    try {
        (void)import_chain_data(chain, path);
    } catch (const std::exception& e) {
        std::printf("       (%s: %s)\n", what.c_str(), e.what());
        return true;
    }
    return false;
}

// ── the engine, over a chain that was handed its history ────────────────────
//
// A VM that forwards every question to the chain and COUNTS the one that
// matters: build(). The gate is meant to sit in front of execution, so the
// proof is that the chain is never asked, not merely that no block was decided.
class Counted final : public VM {
public:
    explicit Counted(evm::Chain& c) : c_(c) {}

    Id          chain_id() const override { return c_.chain_id(); }
    std::string alias() const override { return c_.alias(); }
    std::shared_ptr<Block> build() override {
        ++builds;
        return c_.build();
    }
    std::shared_ptr<Block> parse(std::span<const std::uint8_t> b) override { return c_.parse(b); }
    std::shared_ptr<Block> get(const Id& id) const override { return c_.get(id); }
    void                   prefer(const Id& id) override { c_.prefer(id); }
    Id                     last_accepted() const override { return c_.last_accepted(); }
    std::uint64_t          last_accepted_height() const override { return c_.last_accepted_height(); }
    std::uint64_t          frontier() const override { return c_.frontier(); }

    int builds = 0;

private:
    evm::Chain& c_;
};

constexpr std::uint32_t kN = 4;

std::unique_ptr<Node2Host> lone_host() {
    HostConfig             cfg;
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

int main(int argc, char** argv) {
    std::printf("node — an export is read, checked block by block, and does not make a validator\n\n");

    // ── the read ────────────────────────────────────────────────────────────
    std::printf("A synthesized export: every id recomputed, every link walked\n");
    const Export e = synthesize(4);  // heights 0..4
    const Temp   good(e.file);
    {
        evm::Chain chain(local_genesis(31337));
        const auto in = import_chain_data(chain, good.path());
        check(in.blocks == 4, "four blocks ingested — the export's own genesis is read, not ingested");
        check(in.skipped == 0, "and nothing was already held");
        check(in.genesis == e.ids[0], "the genesis id is keccak(rlp(header)) of block 0");
        check(in.tip == e.ids[4], "and the tip id is that of block 4");
        check(in.height == 4 && in.timestamp == 1'700'000'004, "with block 4's height and timestamp");
        check(chain.last_accepted_height() == 4, "the chain's tip moved to the imported height");
        check(chain.last_accepted() == e.ids[4], "and names the imported block");
        check(chain.at_height(3) != nullptr && chain.at_height(3)->id() == e.ids[3],
              "every ingested height is retrievable by the id the export gave it");
        check(chain.at_height(2)->parent() == e.ids[1],
              "and points at the block before it, so the tip can be walked down");

        // Idempotence: the flag stays set in a pod spec, so a restart re-reads
        // the same file and must not fail. Go classifies its own "nothing to
        // import" error back into success for exactly this reason.
        const auto again = import_chain_data(chain, good.path());
        check(again.blocks == 0 && again.skipped == 4,
              "a second read of the same export ingests nothing and is not a failure");
        check(again.tip == e.ids[4] && chain.last_accepted_height() == 4,
              "and leaves the tip where it was");
    }

    // ── what the reader refuses ─────────────────────────────────────────────
    std::printf("\nWhat it refuses\n");
    {
        // A spliced middle: block 3's parentHash rewritten to something that
        // hashes to nothing in this file. Head and tail still agree.
        Export     bad = synthesize(4);
        const auto pos = bad.file.find(bytes(bad.ids[2].begin(), bad.ids[2].end()));
        // Block 2's id is written down exactly once in the whole file — as
        // block 3's parentHash — because a header never carries its own hash.
        check(pos != bytes::npos, "block 2's id appears once in the export, as block 3's parent");
        bad.file[pos] ^= 0xff;
        const Temp   spliced(bad.file);
        evm::Chain   chain(local_genesis(31337));
        check(refused(chain, spliced.path(), "spliced parent"),
              "a parentHash that does not name the block before it");
        check(chain.last_accepted_height() == 2,
              "and the chain stops at the last block whose ancestry closed");
    }
    {
        Export bad = synthesize(2);
        bad.file.resize(bad.file.size() - 1);  // truncate the last block
        const Temp trunc(bad.file);
        evm::Chain chain(local_genesis(31337));
        check(refused(chain, trunc.path(), "truncated"), "a truncated encoding");
    }
    {
        // A body that does not rebuild its header's transactionsRoot: the
        // header says the empty trie, the body carries a transaction.
        Export        base = synthesize(1);
        const bytes   h    = header(base.ids[0], 1, 1'700'000'001);
        bytes         content = h;
        bytes         txlist  = erlp::wrap_list(erlp::encode(bytes{0x01, 0x02, 0x03}));
        content.insert(content.end(), txlist.begin(), txlist.end());
        content.push_back(0xc0);
        const bytes blk = erlp::wrap_list(content);
        bytes       file;
        const bytes g = block_of(header(Id{}, 0, 1'700'000'000));
        file.insert(file.end(), g.begin(), g.end());
        file.insert(file.end(), blk.begin(), blk.end());
        const Temp lying(file);
        evm::Chain chain(local_genesis(31337));
        check(refused(chain, lying.path(), "body vs transactionsRoot"),
              "a body that does not rebuild the transactionsRoot its header declares");
    }
    {
        // An export that starts above block 0 has no anchor: nothing in the
        // file can close its first block's ancestry.
        const Export whole = synthesize(2);
        const bytes  g     = block_of(header(Id{}, 0, 1'700'000'000));
        bytes        headless(whole.file.begin() + static_cast<long>(g.size()), whole.file.end());
        const Temp   nogenesis(headless);
        evm::Chain   chain(local_genesis(31337));
        check(refused(chain, nogenesis.path(), "no anchor"), "an export that does not begin at block 0");
    }
    {
        evm::Chain chain(local_genesis(31337));
        check(refused(chain, "/nonexistent/export.rlp", "absent"), "a file that is not there");
    }

    // ── and what the node becomes ───────────────────────────────────────────
    std::printf("\nA tip nobody here decided is not a caught-up validator\n");
    {
        evm::Chain chain(local_genesis(31337));
        check(chain.frontier() == chain.last_accepted_height(),
              "before the read, this node's decisions reach its tip (genesis, by construction)");

        (void)import_chain_data(chain, good.path());
        check(chain.last_accepted_height() == 4 && chain.frontier() == 0,
              "after it, the tip is height 4 and this node's decisions stop at height 0");

        auto       host = lone_host();
        std::mutex guard;
        auto       counted = std::make_unique<Counted>(chain);
        Counted*   seen    = counted.get();
        Engine     engine(std::move(counted), *host, guard);

        check(!engine.propose([](std::span<const std::uint8_t>) {}, 150).has_value(),
              "the engine will not propose on it");
        check(seen->builds == 0,
              "and it never asked the chain to build — the refusal is IN FRONT of execution, so "
              "no block is run against state this node never derived");
        check(!engine.follow(std::vector<std::uint8_t>{0x00, 0x01}, 150).has_value(),
              "nor will it follow a peer's block, which would be a vote on the same ancestry");
        check(chain.last_accepted_height() == 4 && chain.frontier() == 0,
              "and nothing moved: the tip is where the export left it and no height was decided");
    }
    {
        // THE CONTROL. The same engine over the same chain, not imported into,
        // does ask for a block — so the gate above is the import's doing and not
        // an engine that refuses everything.
        evm::Chain chain(local_genesis(31337));
        auto       host = lone_host();
        std::mutex guard;
        auto       counted = std::make_unique<Counted>(chain);
        Counted*   seen    = counted.get();
        Engine     engine(std::move(counted), *host, guard);

        (void)engine.propose([](std::span<const std::uint8_t>) {}, 150);
        check(seen->builds == 1, "a chain that was NOT handed its history is asked to build");
    }

    // ── the canonical export, when there is one to read ─────────────────────
    const char* given = (argc > 1) ? argv[1] : std::getenv("LUX_RLP_EXPORT");
    if (given != nullptr && *given != '\0') {
        std::printf("\nThe canonical export at %s\n", given);
        evm::Chain chain(local_genesis(96368));
        const auto in = import_chain_data(chain, given);
        std::printf("       genesis %s\n", hex(in.genesis).c_str());
        std::printf("       tip     %s\n", hex(in.tip).c_str());
        std::printf("       root    %s\n", hex(in.root).c_str());
        std::printf("       height %llu  time %llu  blocks %llu  txs %llu\n",
                    static_cast<unsigned long long>(in.height),
                    static_cast<unsigned long long>(in.timestamp),
                    static_cast<unsigned long long>(in.blocks),
                    static_cast<unsigned long long>(in.txs));

        // Go's import of these same bytes. A different root is a different
        // chain, so this is the whole point of reading the file at all.
        check(in.tip == id_of("0x722e2b39ae8973ab5d94b51451623352650b728e411ce0261c5efcd23aa381a5"),
              "the tip hash is the one Go's import produced");
        check(in.root == id_of("0x4e19366fcc65d7ddd0b803bfbd7537f0c0ddc5d190c3ded40712408fcb137f35"),
              "and so is the state root its header carries");
        check(in.genesis == id_of("0x1c5fe37764b8bc146dc88bc1c2e0259cd8369b07a06439bcfa1782b5d4fb0995"),
              "anchored on the lux-testnet C-Chain genesis");
        check(in.height == 218 && in.timestamp == 1746815479, "at height 218, timestamp 1746815479");
        check(in.blocks == 218, "218 blocks ingested, block 0 read as the anchor");
        check(chain.last_accepted_height() == 218 && chain.frontier() == 0,
              "and this node's decisions still stop at height 0");
    } else {
        std::printf("\n(no canonical export given — pass one as argv[1] or $LUX_RLP_EXPORT to pin "
                    "a real chain's tip against Go's import of the same bytes)\n");
    }

    std::printf("\n%s\n", g_fail ? "FAIL"
                                 : "PASS — the export is walked link by link, and a tip nobody "
                                   "here decided does not vote");
    return g_fail ? 1 : 0;
}
