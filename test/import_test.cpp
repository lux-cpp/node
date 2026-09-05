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
#include "lux/node/eth.hpp"
#include "lux/node/evm.hpp"
#include "lux/node/import.hpp"
#include "lux/node/node_host.hpp"
#include "lux/node/rpc.hpp"

#include "bls_signature.hpp"

#include <bin/cevm/eth_mpt.hpp>
#include <test/state/hash_utils.hpp>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
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

// ── the RPC door, driven the way a caller drives it ─────────────────────────
//
// A real socket and a real JSON-RPC request, because a door tested by calling
// the function behind it is not a door that was tested at all.
struct Answer {
    int         status = 0;
    Rpc::Json   body;
};

Answer rpc_import(std::uint16_t port, const std::string& path) {
    Answer out;
    const int sock = ::socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return out;
    timeval tv{20, 0};
    ::setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ::setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    sockaddr_in a{};
    a.sin_family      = AF_INET;
    a.sin_port        = htons(port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::connect(sock, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0) {
        ::close(sock);
        return out;
    }

    const Rpc::Json call{{"jsonrpc", "2.0"},
                         {"id", 1},
                         {"method", "admin_importChain"},
                         {"params", Rpc::Json::array({path})}};
    const std::string payload = call.dump();
    std::string req = "POST /v1/chain/C/rpc HTTP/1.1\r\nHost: 127.0.0.1\r\n";
    req += "Content-Type: application/json\r\n";
    req += "Content-Length: " + std::to_string(payload.size()) + "\r\n";
    req += "Connection: close\r\n\r\n" + payload;
    for (std::size_t off = 0; off < req.size();) {
        const ssize_t n = ::send(sock, req.data() + off, req.size() - off, 0);
        if (n <= 0) break;
        off += static_cast<std::size_t>(n);
    }

    std::string raw;
    char        buf[4096];
    while (true) {
        const ssize_t n = ::recv(sock, buf, sizeof(buf), 0);
        if (n <= 0) break;
        raw.append(buf, static_cast<std::size_t>(n));
    }
    ::close(sock);

    if (raw.rfind("HTTP/1.1 ", 0) == 0) out.status = std::atoi(raw.c_str() + 9);
    const auto dbl = raw.find("\r\n\r\n");
    if (dbl != std::string::npos) {
        try {
            out.body = Rpc::Json::parse(raw.substr(dbl + 4));
        } catch (...) {}
    }
    return out;
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

    // ── two doors, one reader ───────────────────────────────────────────────
    //
    // The node is asked to read an export in two ways, and the point of the
    // section is that the second one is a DOOR and not a second reader. So it
    // is driven the way a caller drives it — a real socket, a real JSON-RPC
    // request — and its answer is compared field by field against what the
    // startup flag's call to the same function returned for the same bytes.
    std::printf("\nTwo doors onto one reader\n");
    {
        evm::Chain by_flag(local_genesis(31337));
        const auto flagged = import_chain_data(by_flag, good.path());

        evm::Chain by_rpc(local_genesis(31337));
        Rpc        rpc(0);
        serve_admin(rpc, by_rpc);
        rpc.start();

        const auto answer = rpc_import(rpc.port(), good.path());
        check(answer.status == 200 && answer.body.contains("result"),
              "admin_importChain answers the export the flag was given");
        const auto& r = answer.body["result"];
        check(r["blocks"] == flagged.blocks && r["skipped"] == flagged.skipped &&
                  r["transactions"] == flagged.txs,
              "with the same counts the flag's call returned");
        check(r["tip"] == hex(flagged.tip) && r["stateRoot"] == hex(flagged.root) &&
                  r["genesis"] == hex(flagged.genesis),
              "the same tip, the same carried state root, the same anchoring genesis");
        check(r["heightBefore"] == "0x0" && r["heightAfter"] == "0x4",
              "and says where the chain was before it and where it is after");
        check(by_rpc.last_accepted() == by_flag.last_accepted() &&
                  by_rpc.last_accepted_height() == by_flag.last_accepted_height(),
              "the two chains are at the same block, which is what one reader means");

        // The frontier travels with the answer, so a caller polling this door
        // is told in the same breath that the node is not caught up.
        check(r["frontier"] == "0x0" && by_rpc.frontier() == 0,
              "and the answer itself reports a frontier still at zero");

        // The refusal is a property of the chain, not of the door that filled
        // it: driven after an RPC import, the engine still never asks to build.
        {
            auto     host    = lone_host();
            std::mutex guard;
            auto     counted = std::make_unique<Counted>(by_rpc);
            Counted* seen    = counted.get();
            Engine   engine(std::move(counted), *host, guard);
            (void)engine.propose([](std::span<const std::uint8_t>) {}, 150);
            check(seen->builds == 0,
                  "a chain filled through the RPC door is no more a validator than one "
                  "filled through the flag");
        }

        // Idempotent through this door too — the same reader, so the same rule.
        const auto twice = rpc_import(rpc.port(), good.path());
        check(twice.body["result"]["blocks"] == 0 && twice.body["result"]["skipped"] == 4,
              "a second call ingests nothing and is still a success");

        // A refusal arrives as the reader's own words. A door that summarized
        // them would cost the caller the block number it stopped at.
        const auto absent = rpc_import(rpc.port(), "/nonexistent/export.rlp");
        check(absent.body.contains("error") &&
                  absent.body["error"]["message"].get<std::string>().find("cannot open") !=
                      std::string::npos,
              "and a file that is not there comes back as the reader's own refusal");
        rpc.stop();
    }

    // ── the checkpoint, and what it is allowed to say ───────────────────────
    //
    // Go commits state every 4096 blocks and moves the accepted-block pointer
    // in the same step. Here the pointer is moved by `ingest` and the reader
    // reads it back before telling a door anything — so the assertion that
    // matters is not that a checkpoint arrived but that the chain ALREADY held
    // the height it named, checked from inside the callback itself.
    std::printf("\nThe checkpoint says where the chain actually is\n");
    {
        const Export       big = synthesize(kCheckpointInterval + 4);
        const Temp         file(big.file);
        evm::Chain         chain(local_genesis(31337));
        std::vector<std::uint64_t> marks;
        bool                       behind = false;
        const auto in = import_chain_data(chain, file.path(),
                                          [&](const Id& tip, std::uint64_t height) {
                                              marks.push_back(height);
                                              if (chain.last_accepted_height() < height ||
                                                  chain.last_accepted() != tip)
                                                  behind = true;
                                          });
        check(in.blocks == kCheckpointInterval + 4, "the whole export is read");
        check(marks.size() == 2 && marks[0] == kCheckpointInterval &&
                  marks[1] == kCheckpointInterval + 4,
              "one checkpoint every 4096 blocks, and one for the last short stretch");
        check(!behind,
              "and at each one the chain already held the block it named — the pointer "
              "never trails what a door was told");

        // A re-read ingests nothing, so there is no new height to report and no
        // checkpoint is invented for one.
        std::vector<std::uint64_t> none;
        (void)import_chain_data(chain, file.path(),
                                [&](const Id&, std::uint64_t h) { none.push_back(h); });
        check(none.empty(), "a re-read that ingests nothing reports no checkpoint");
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

        // The same file through the other door. Go's tip is a fact about the
        // BYTES, so both doors must produce it or one of them is not reading
        // the same chain.
        evm::Chain served(local_genesis(96368));
        Rpc        rpc(0);
        serve_admin(rpc, served);
        rpc.start();
        const auto answer = rpc_import(rpc.port(), given);
        const auto& r     = answer.body["result"];
        check(r["tip"] == hex(in.tip) && r["stateRoot"] == hex(in.root) &&
                  r["heightAfter"] == "0xda" && r["blocks"] == 218,
              "admin_importChain reads the canonical export to the same tip, at height 218");
        check(r["frontier"] == "0x0" && served.frontier() == 0,
              "and a node handed 218 real blocks over RPC still has decided none of them");
        rpc.stop();
    } else {
        std::printf("\n(no canonical export given — pass one as argv[1] or $LUX_RLP_EXPORT to pin "
                    "a real chain's tip against Go's import of the same bytes)\n");
    }

    std::printf("\n%s\n", g_fail ? "FAIL"
                                 : "PASS — the export is walked link by link, and a tip nobody "
                                   "here decided does not vote");
    return g_fail ? 1 : 0;
}
