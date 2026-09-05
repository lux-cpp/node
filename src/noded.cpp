// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// noded — a running Lux node: a C-Chain executed by cevm, decided by BLS
// quorum-certificate consensus over a real TCP mesh, and served over JSON-RPC.
//
//   noded --index I --n N --base-port P [--rpc-port R] [--stake S]
//         [--deadline-ms D] [--blocks B] [--chain-id C]
//
// Node j listens for consensus on 127.0.0.1:(P+j) and serves RPC on --rpc-port
// (0 = OS-assigned, printed at startup). The validator set is derived
// deterministically from the index scheme below so every process agrees on it;
// in production the set comes from genesis and the keys from KMS.
//
// WHAT ONE HEIGHT IS. One validator PROPOSES — height mod n, so the turn moves
// and no node is load-bearing — and gossips the block's bytes. Every other
// validator parses those bytes and runs them through ITS OWN cevm, deriving the
// state root itself rather than believing the proposer's. Each then signs a
// VotePosition carrying the root ITS execution produced.
//
// A quorum certificate over that position is therefore agreement about an
// executed RESULT, not about a name. A validator whose EVM diverged computes a
// different root, signs a different message, and is simply not in the quorum;
// the height stalls instead of forking. That is why the root is in the signed
// message and why a follower is handed bytes rather than a header.

#include "lux/node/engine.hpp"
#include "lux/node/eth.hpp"
#include "lux/node/evm.hpp"
#include "lux/node/import.hpp"
#include "lux/node/node_host.hpp"
#include "lux/node/rpc.hpp"
#include "lux/node/validators.hpp"

#include "bls_signature.hpp"

#include <array>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using namespace lux::node;
using namespace lux::consensus;

namespace {

// The C-Chain's local EVM chain id. luxfi/genesis calls it LocalChainID and
// pins it at 31337 ("the Anvil convention"), which is what eth_chainId answers
// as 0x7a69. Mainnet is 96369 and testnet 96368; this daemon runs a local chain,
// so it defaults to the local id and takes --chain-id for the others.
constexpr std::uint64_t kLocalChainId = 31337;

// What web3_clientVersion reports. luxfi/evm answers a bare version string
// (plugin/evm/version.go), so this does too — with a name, because a client
std::string get_client_version(const char* prog) {
    if (std::strstr(prog, "zood")) return "zoo-cpp/zood/v0.1.0";
    if (std::strstr(prog, "luxd")) return "lux-cpp/luxd/v0.1.0";
    return "lux-cpp/noded/v0.1.0";
}

struct Key {
    std::array<std::uint8_t, 32> sk{};
    PubKey                       pk{};
};

Key make_key(std::uint8_t tag) {
    std::array<std::uint8_t, 32> seed{};
    seed[0] = tag;
    for (int i = 1; i < 32; ++i) seed[i] = std::uint8_t(0xA5 ^ (tag + i));
    Key k;
    if (cevm::crypto::bls::keygen(seed.data(), k.sk.data()) != 0) { std::puts("keygen failed"); std::exit(2); }
    if (cevm::crypto::bls::sk_to_pk(k.sk.data(), k.pk.data()) != 0) { std::puts("sk_to_pk failed"); std::exit(2); }
    return k;
}

long arg(int argc, char** argv, const char* flag, long dflt) {
    for (int i = 1; i + 1 < argc; ++i)
        if (std::strcmp(argv[i], flag) == 0) return std::strtol(argv[i + 1], nullptr, 10);
    return dflt;
}

std::string arg_str(int argc, char** argv, const char* flag, std::string dflt) {
    for (int i = 1; i + 1 < argc; ++i)
        if (std::strcmp(argv[i], flag) == 0) return argv[i + 1];
    return dflt;
}

std::string hex(std::span<const std::uint8_t> b) {
    std::string s = "0x";
    char        t[3];
    for (auto c : b) { std::snprintf(t, sizeof(t), "%02x", c); s += t; }
    return s;
}

// The genesis allocation. This is the account every local Ethereum toolchain
// already holds the key for — the first Anvil/Hardhat account, which is the
// convention the 31337 chain id names. It is a REAL keypair, so a transaction
// signed with it recovers to this address and moves this balance; nothing here
// is a placeholder.
//
//   secret 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
//   address 0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266
evm::Genesis local_genesis(std::uint64_t chain_id) {
    evm::Genesis g;
    g.chain_id  = chain_id;
    g.gas_limit = 30'000'000;

    const std::array<std::uint8_t, 20> dev{0xf3, 0x9f, 0xd6, 0xe5, 0x1a, 0xad, 0x88,
                                           0xf6, 0xf4, 0xce, 0x6a, 0xb8, 0x82, 0x72,
                                           0x79, 0xcf, 0xff, 0xb9, 0x22, 0x66};
    evm::Word balance{};                 // 10_000 ether
    balance[23] = 0x02; balance[24] = 0x1e; balance[25] = 0x19;
    balance[26] = 0xe0; balance[27] = 0xc9; balance[28] = 0xba; balance[29] = 0xb2;
    balance[30] = 0x40; balance[31] = 0x00;
    g.alloc.emplace_back(dev, balance);

    // LUX_MNEMONIC treasury: 0x9011E888251AB053B7bD1cdB598Db4f9DEd94714
    const std::array<std::uint8_t, 20> treasury{0x90, 0x11, 0xe8, 0x88, 0x25, 0x1a, 0xb0, 0x53,
                                                0xb7, 0xbd, 0x1c, 0xdb, 0x59, 0x8d, 0xb4, 0xf9,
                                                0xde, 0xd9, 0x47, 0x14};
    g.alloc.emplace_back(treasury, balance);
    return g;
}

// A daemon stops when it is asked to, and finishes the height it is in. The
// handler does nothing but set this — everything that must be torn down is torn
// down on the way out of main, on the main thread.
std::atomic<bool> g_stop{false};
void on_signal(int) { g_stop.store(true); }

}  // namespace

int main(int argc, char** argv) {
    const char* prog = (argc > 0 && argv[0]) ? argv[0] : "luxd";
    if (const char* slash = std::strrchr(prog, '/')) prog = slash + 1;
    const std::string client_version = get_client_version(prog);

    const long index     = arg(argc, argv, "--index", -1);
    const long n         = arg(argc, argv, "--n", -1);
    const long base_port = arg(argc, argv, "--base-port", -1);
    if (index < 0 || n <= 0 || base_port <= 0 || index >= n) {
        std::fprintf(stderr,
                     "usage: %s --index I --n N --base-port P [--rpc-port R] [--stake S]\n"
                     "             [--deadline-ms D] [--blocks B] [--chain-id C] [--archive-rpc URL] [--light]\n"
                     "             [--import-chain-data PATH]\n", prog);
        return 2;
    }
    const long stake       = arg(argc, argv, "--stake", 20);
    const long deadline_ms = arg(argc, argv, "--deadline-ms", 15000);
    const long rpc_port    = arg(argc, argv, "--rpc-port", 0);
    const long blocks      = arg(argc, argv, "--blocks", 0);  // 0 = until stopped
    const auto chain_id    = std::uint64_t(arg(argc, argv, "--chain-id", long(kLocalChainId)));

    // Go's flag, spelled Go's way, so one runbook drives all three
    // implementations: luxd passes --import-chain-data through to the C-Chain's
    // config and the VM reads the export at startup, before the chain serves
    // anything. Same name, same moment, same idempotence.
    const std::string import_path = arg_str(argc, argv, "--import-chain-data", "");

    std::string archive_rpc = arg_str(argc, argv, "--archive-rpc", "");
    if (archive_rpc.empty()) {
        if (const char* env = std::getenv("LUX_ARCHIVE_RPC")) archive_rpc = env;
        else if (const char* env2 = std::getenv("ZOO_ARCHIVE_RPC")) archive_rpc = env2;
    }

    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);

    // Deterministic validator set shared by every process; this node's own key.
    std::vector<Key> keys;
    for (long i = 0; i < n; ++i) keys.push_back(make_key(std::uint8_t(0x80 + i)));
    std::vector<Validator> set;
    for (const auto& k : keys) set.push_back({k.pk, std::uint64_t(stake)});

    // The commitment to that set, which every vote binds. Computed with Go's
    // encoding (lux/node/validators.hpp), so a node in a mixed cluster signs the
    // same message luxd does.
    //
    // The node id and the uncompressed key are placeholders HERE and only here:
    // this daemon derives its validator set from an index scheme rather than
    // from a P-chain, so it has no node ids or uncompressed keys to commit to.
    // A node joining a live network reads the EFFECTIVE set from the P-chain
    // (/v1/chain/P/ops/validators/at?height=0) — the weight the P-chain
    // computed, not the one genesis declared, and the 96-byte uncompressed key,
    // not the 48-byte compressed one the proof of possession signs. Until that
    // read exists, this commits to the set it actually has.
    std::vector<SetMember> members;
    for (long i = 0; i < n; ++i) {
        SetMember m;
        m.node_id.fill(std::uint8_t(0x80 + i));
        m.weight = std::uint64_t(stake);
        m.pubkey.assign(keys[i].pk.begin(), keys[i].pk.end());
        members.push_back(std::move(m));
    }
    const Id set_root = validator_set_root(members);

    HostConfig cfg;
    cfg.index      = std::uint32_t(index);
    cfg.port       = std::uint16_t(base_port + index);
    cfg.sk         = keys[index].sk;
    cfg.pk         = keys[index].pk;
    cfg.validators = set;
    // The committee IS the validator set: this node samples nobody, so a round is
    // "can I still reach a supermajority of the set". feasible() sizes k, the
    // threshold and β from n in one place, so a 5-node and a 33-node cluster run
    // the same rule rather than a literal — and it is the SAME count the stake
    // floor uses, which it has to be: 0.8·n is not the strict-⅔ rule, and at n=4
    // it asks for 4 of 4 while the floor it just cleared asks for 3. A daemon
    // whose stated fault tolerance is defeated by its own threshold reports the
    // mesh up and then never decides a round.
    cfg.wave = WaveConfig::feasible(std::uint32_t(n));

    // consensus throws at its boundary on a set/wave combination that cannot
    // reach a decision. A daemon says so and exits; it does not abort.
    std::unique_ptr<Node2Host> hostp;
    std::unique_ptr<evm::Chain> chainp;
    try {
        hostp  = std::make_unique<Node2Host>(std::move(cfg));
        chainp = std::make_unique<evm::Chain>(local_genesis(chain_id));
    } catch (const std::exception& e) {
        std::fprintf(stderr, "node %ld: cannot start — %s\n", index, e.what());
        return 2;
    }
    Node2Host&  host  = *hostp;
    evm::Chain& chain = *chainp;

    const std::uint16_t port = host.listen_bind();
    std::printf("node %ld: consensus 127.0.0.1:%u  chain C (eth chainId %llu)\n",
                index, port, static_cast<unsigned long long>(chain.eth_chain_id()));
    std::printf("node %ld: genesis state root %s\n", index, hex(chain.state_root()).c_str());
    std::printf("node %ld: validator set root %s\n", index, hex(set_root).c_str());
    std::fflush(stdout);

    // ── the export, read before anything else looks at the chain ────────────
    if (!import_path.empty()) {
        try {
            const Import in = import_chain_data(chain, import_path);
            std::printf("node %ld: import %s\n", index, import_path.c_str());
            std::printf("node %ld: import genesis %s\n", index, hex(in.genesis).c_str());
            std::printf("node %ld: import tip %s height %llu time %llu\n", index,
                        hex(in.tip).c_str(), static_cast<unsigned long long>(in.height),
                        static_cast<unsigned long long>(in.timestamp));
            std::printf("node %ld: import state root %s (carried from the header — an export "
                        "holds blocks, not state)\n", index, hex(in.root).c_str());
            std::printf("node %ld: import %llu blocks ingested, %llu already held, %llu "
                        "transactions recovered\n", index,
                        static_cast<unsigned long long>(in.blocks),
                        static_cast<unsigned long long>(in.skipped),
                        static_cast<unsigned long long>(in.txs));
            std::fflush(stdout);
        } catch (const std::exception& e) {
            std::fprintf(stderr, "node %ld: import failed — %s\n", index, e.what());
            return 2;
        }
    }

    // ── the RPC, up before consensus ────────────────────────────────────────
    // It must answer while the mesh is still forming, so that "is it listening"
    // and "has it reached quorum" are separable questions.
    std::unique_ptr<Rpc> rpcp;
    try {
        rpcp = std::make_unique<Rpc>(std::uint16_t(rpc_port));
    } catch (const std::exception& e) {
        std::fprintf(stderr, "node %ld: cannot serve RPC — %s\n", index, e.what());
        return 2;
    }
    Rpc& rpc = *rpcp;
    if (!archive_rpc.empty()) {
        rpc.set_archive_rpc(archive_rpc);
    }
    serve_eth(rpc, chain, client_version);
    const std::string_view prog_view(prog ? prog : "");
    const std::string public_api = (prog_view == "zood" || prog_view.find("zoo") != std::string_view::npos)
                                       ? "https://api.zoo.network"
                                       : "https://api.lux.network";
    rpc.about(Rpc::Json{
        {"client", client_version},
        {"mode", "light"},
        {"index", index},
        {"validators", n},
        {"endpoint", public_api},
        {"chains", Rpc::Json::object({{"c", "/v1/chain/c"}, {"p", "/v1/chain/p"}, {"x", "/v1/chain/x"}})},
        {"endpoints", Rpc::Json::object({
            {"rpc", "/v1/chain/c"},
            {"p", "/v1/chain/p"},
            {"x", "/v1/chain/x"},
            {"health", "/v1/health"},
            {"public", public_api}
        })}
    });
    rpc.start();
    std::printf("node %ld: mode light node (frontier resident)\n", index);
    if (!archive_rpc.empty()) {
        std::printf("node %ld: archive RPC %s (proxying historical & P/X state)\n", index, archive_rpc.c_str());
    }
    std::printf("node %ld: rpc http://127.0.0.1:%u/v1/chain/c\n", index, rpc.port());
    std::fflush(stdout);

    // ── the mesh ────────────────────────────────────────────────────────────
    std::map<std::uint32_t, PeerAddr> peers;
    for (long j = 0; j < n; ++j)
        if (j != index) peers[std::uint32_t(j)] = PeerAddr{"127.0.0.1", std::uint16_t(base_port + j)};

    // A transaction from a peer goes through the SAME door as one from an RPC
    // caller: decoded, its sender recovered, or refused. A peer is trusted with
    // bytes and nothing else.
    host.on(kTxMsgType, [&](const std::vector<std::uint8_t>& raw) {
        const std::lock_guard<std::mutex> lock(rpc.guard());
        (void)chain.accept_tx_from_peer(raw);
    });

    // Proposed blocks arrive here and wait to be executed. Only the bytes are
    // kept — parsing is execution, and it happens on the driver's thread where
    // the chain is single-threaded, never on the pump.
    std::vector<std::vector<std::uint8_t>> inbox;
    std::mutex                             inbox_mu;
    host.on(kBlockMsgType, [&](const std::vector<std::uint8_t>& raw) {
        const std::lock_guard<std::mutex> lock(inbox_mu);
        inbox.push_back(raw);
    });

    const std::size_t   reached     = host.connect_mesh(peers, int(deadline_ms));
    const std::uint64_t total_stake = std::uint64_t(n) * std::uint64_t(stake);
    const std::uint64_t reachable   = std::uint64_t(reached + 1) * std::uint64_t(stake);
    if (reachable <= two_thirds_stake_floor(total_stake)) {
        std::printf("node %ld: NO QUORUM REACHABLE (peers=%zu/%ld, stake %llu of %llu, floor %llu)\n",
                    index, reached, n - 1,
                    static_cast<unsigned long long>(reachable),
                    static_cast<unsigned long long>(total_stake),
                    static_cast<unsigned long long>(two_thirds_stake_floor(total_stake)));
        rpc.stop();
        return 1;
    }
    std::printf("node %ld: mesh up (%zu of %ld peers, reachable stake %llu > floor %llu)\n",
                index, reached, n - 1,
                static_cast<unsigned long long>(reachable),
                static_cast<unsigned long long>(two_thirds_stake_floor(total_stake)));
    std::fflush(stdout);

    // Executed: this is a C++-only cluster, so the vote binds the root this
    // node's EVM produced and a divergent EVM stalls the height instead of
    // hiding. Joining luxd takes Binding::Transport — see engine.hpp.
    Engine engine(std::move(chainp), host, rpc.guard(), Binding::Executed, set_root);

    // Pump the mesh for `ms`, so gossip lands and inbound blocks arrive. The one
    // place this daemon waits.
    auto settle = [&](int ms) {
        const auto until = std::chrono::steady_clock::now() + std::chrono::milliseconds(ms);
        while (!g_stop.load() && std::chrono::steady_clock::now() < until) {
            host.pump();
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
    };

    // ── a tip nobody here decided ───────────────────────────────────────────
    //
    // Reading an export moves the tip and leaves every consensus frontier below
    // it missing, so this node knows a height it cannot walk down from. It
    // stays UP — the RPC answers, so the imported history is readable and the
    // state is visible rather than silent — and it does not enter the height
    // loop. The engine would refuse each height anyway; saying so once, plainly,
    // is the difference between a refusal and a node that looks wedged.
    if (engine.vm().frontier() < engine.vm().last_accepted_height()) {
        std::printf("node %ld: NOT A CAUGHT-UP VALIDATOR — tip is height %llu, this node's own "
                    "decisions stop at height %llu\n", index,
                    static_cast<unsigned long long>(engine.vm().last_accepted_height()),
                    static_cast<unsigned long long>(engine.vm().frontier()));
        std::printf("node %ld: cause: an export was read; it writes blocks and no certificates, "
                    "so nothing below the tip was decided here\n", index);
        std::printf("node %ld: effect: this node will NOT build blocks and will NOT vote until "
                    "those heights are rebuilt from certified peer state\n", index);
        std::fflush(stdout);
        while (!g_stop.load()) {
            host.pump();
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
        std::printf("node %ld: stopping at height %llu\n", index,
                    static_cast<unsigned long long>(engine.height()));
        std::fflush(stdout);
        rpc.stop();
        return 0;
    }

    // ── the chain, one height at a time ─────────────────────────────────────
    int rc = 0;
    for (long produced = 0; !g_stop.load() && (blocks == 0 || produced < blocks); ++produced) {
        const std::uint64_t height   = engine.height() + 1;
        const bool          proposer = (height % std::uint64_t(n)) == std::uint64_t(index);

        // Hand this node's pending transactions to its peers, so a transaction
        // submitted here is mined by whoever leads next. Gossip is idempotent: a
        // transaction a peer already holds is recognised by its hash and dropped.
        {
            const std::lock_guard<std::mutex> lock(rpc.guard());
            for (const auto& raw : chain.pending_raw()) host.gossip(kTxMsgType, raw);
        }
        settle(blocks == 0 ? 1000 : 60);
        // Asked to stop while waiting: leave BEFORE proposing. Entering a height
        // here would run its full deadline against peers that are also leaving
        // and then report a height as uncertified because the daemon was shutting
        // down — a shutdown that ends in a false alarm and a non-zero exit.
        if (g_stop.load()) break;

        std::optional<Decided> d;
        if (proposer) {
            // Build (which executes), publish the bytes, then let the followers
            // parse and submit before voting starts — a vote for a block a peer
            // has not registered is dropped by its gate, and the proposer does
            // not re-broadcast.
            d = engine.propose(
                [&](std::span<const std::uint8_t> b) {
                    host.gossip(kBlockMsgType, std::vector<std::uint8_t>(b.begin(), b.end()));
                },
                int(deadline_ms));
        } else {
            // Wait for the leader's block, then run it. There is no fallback to
            // building one locally: two nodes proposing at one height is exactly
            // the sibling the equivocation rule exists to refuse.
            std::vector<std::uint8_t> raw;
            const auto until = std::chrono::steady_clock::now() +
                               std::chrono::milliseconds(deadline_ms);
            while (!g_stop.load() && std::chrono::steady_clock::now() < until) {
                host.pump();
                {
                    const std::lock_guard<std::mutex> lock(inbox_mu);
                    if (!inbox.empty()) { raw = std::move(inbox.front()); inbox.erase(inbox.begin()); }
                }
                if (!raw.empty()) break;
                std::this_thread::sleep_for(std::chrono::milliseconds(2));
            }
            if (!raw.empty()) d = engine.follow(raw, int(deadline_ms));
        }
        if (!d) {
            if (blocks != 0) {
                std::printf("node %ld: height %llu NOT CERTIFIED before deadline — stopping\n",
                            index, static_cast<unsigned long long>(height));
                rc = 1;
                break;
            }
            std::printf("node %ld: height %llu timeout — retrying\n",
                        index, static_cast<unsigned long long>(height));
            settle(500);
            continue;
        }
        std::size_t ntx = 0;
        {
            const std::lock_guard<std::mutex> lock(rpc.guard());
            ntx = chain.block_txs(d->block->id()).size();
        }
        std::printf("node %ld: block %llu %s %s  root %s  txs %zu  voters %zu  stake %llu\n",
                    index,
                    static_cast<unsigned long long>(d->block->height()),
                    proposer ? "led " : "flwd",
                    hex(d->block->id()).c_str(),
                    hex(d->block->root()).c_str(),
                    ntx,
                    d->cert.voters.size(),
                    static_cast<unsigned long long>(d->cert.voted_stake));
        std::fflush(stdout);
    }

    std::printf("node %ld: stopping at height %llu\n", index,
                static_cast<unsigned long long>(engine.height()));
    std::fflush(stdout);
    rpc.stop();
    return rc;
}
