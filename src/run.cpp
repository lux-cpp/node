// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// run.cpp — a node on one network: its EVM run as a plugin, decided by BLS
// quorum-certificate consensus over a real TCP mesh, and served over JSON-RPC.
//
//   <daemon> [--network NAME] --committee <file> --peers <a:p,b:p,...>
//            [--data DIR] [--rpc-port R] [--rpc-host H] [--mesh-host H]
//            [--deadline-ms D] [--blocks B] [--import-chain-data PATH]
//            [--archive-rpc URL] [--vm PATH]
//   <daemon> [--network NAME] --data DIR --publish      (also writes DIR/published)
//
// THE VALIDATOR SET IS READ, NOT DERIVED. A committee file names every
// validator of this network by the ML-DSA-65 public key it published, the BLS
// key it votes with, and its proof of possession — and it is the SAME file the
// Rust node reads and the same commitment the Go node computes, so one
// description drives all three. `--publish` prints this node's own line for it.
//
// This node finds ITSELF in that file, by name: its seat is where its own
// identity sits, and the peer list is positional against the same order, so the
// third address belongs to the third line. The entry at this node's own seat is
// where it listens.
//
// THE EVM IS A PLUGIN, started the way the Go node starts one and spoken to
// over the same ZAP protocol (plugin.hpp). The chain's genesis, its history,
// its state and its JSON-RPC are the plugin's; this node decides its blocks and
// relays its RPC. One height: the proposer — height mod n — asks the plugin to
// build and gossips the bytes; every other validator hands those bytes to ITS
// plugin to parse and verify; the quorum certificate then decides the block
// and each plugin is told to accept it.

#include "lux/consensus/threshold.hpp"
#include "lux/node/committee.hpp"
#include "lux/node/engine.hpp"
#include "lux/node/network.hpp"
#include "lux/node/node_host.hpp"
#include "lux/node/plugin.hpp"
#include "lux/node/rpc.hpp"
#include "lux/node/signer.hpp"
#include "lux/node/spec.hpp"

#include <arpa/inet.h>

#include <array>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <memory>
#include <optional>
#include <nlohmann/json.hpp>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace lux::node {

using namespace lux::consensus;

namespace {

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

bool has_flag(int argc, char** argv, const char* flag) {
    for (int i = 1; i < argc; ++i)
        if (std::strcmp(argv[i], flag) == 0) return true;
    return false;
}

// Every validator's mesh address, in committee order.
//
// A peer list is POSITIONS, not names: the names are already fixed by the
// committee, so the third address belongs to the third line. Empty entries are
// skipped BEFORE a position is taken, which is what the Rust node does with the
// same string — a list is a list of addresses, not of commas.
std::vector<PeerAddr> mesh_addresses(const std::string& list) {
    std::vector<PeerAddr> out;
    for (std::size_t at = 0; at <= list.size();) {
        const std::size_t cut = std::min(list.find(',', at), list.size());
        std::string       one = list.substr(at, cut - at);
        at                    = cut + 1;
        const auto space      = [](char c) { return c == ' ' || c == '\t'; };
        while (!one.empty() && space(one.front())) one.erase(one.begin());
        while (!one.empty() && space(one.back())) one.pop_back();
        if (one.empty()) continue;

        const std::size_t colon = one.rfind(':');
        if (colon == std::string::npos || colon + 1 == one.size() || colon == 0)
            throw std::runtime_error("--peers " + one + ": expected host:port");
        const long port = std::strtol(one.c_str() + colon + 1, nullptr, 10);
        if (port <= 0 || port > 65535)
            throw std::runtime_error("--peers " + one + ": that is not a port");
        out.push_back(PeerAddr{one.substr(0, colon), std::uint16_t(port)});
    }
    return out;
}

std::string read_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("cannot read " + path);
    std::ostringstream out;
    out << f.rdbuf();
    return out.str();
}

std::string hex(std::span<const std::uint8_t> b) {
    std::string s = "0x";
    char        t[3];
    for (auto c : b) { std::snprintf(t, sizeof(t), "%02x", c); s += t; }
    return s;
}

// A daemon stops when it is asked to, and finishes the height it is in. The
// handler does nothing but set this — everything that must be torn down is torn
// down on the way out of main, on the main thread.
std::atomic<bool> g_stop{false};
void on_signal(int) { g_stop.store(true); }

}  // namespace

int run(std::span<const Spec> specs, int argc, char** argv) {
    const char* prog = (argc > 0 && argv[0]) ? argv[0] : "node";
    if (const char* slash = std::strrchr(prog, '/')) prog = slash + 1;

    // The network, by name. None named is the first spec; a name no spec has is
    // refused rather than rounded to one, because a node that fell back to a
    // network on a typo would join the wrong one and look like it had started.
    if (specs.empty()) {
        std::fprintf(stderr, "%s: no network to run\n", prog);
        return 2;
    }
    const std::string wanted = arg_str(argc, argv, "--network", specs.front().name);
    const Spec*       spec   = nullptr;
    for (const auto& s : specs)
        if (s.name == wanted) spec = &s;
    if (spec == nullptr) {
        std::string names;
        for (const auto& s : specs) names += (names.empty() ? "" : ", ") + s.name;
        std::fprintf(stderr, "%s: no network %s; this daemon runs %s\n", prog, wanted.c_str(),
                     names.c_str());
        return 2;
    }
    const std::string& client_version = spec->client;

    // A spec's genesis names its own chain. One that named another would start
    // a node that signs for one chain and executes a different one, so the two
    // numbers are held to each other before anything is started.
    try {
        auto doc = nlohmann::json::parse(spec->genesis);
        if (doc.contains("cChainGenesis")) {
            const auto inner = doc["cChainGenesis"];
            doc = inner.is_string() ? nlohmann::json::parse(inner.get<std::string>()) : inner;
        }
        const auto named = doc.at("config").at("chainId").get<std::uint64_t>();
        if (named != spec->chain) {
            std::fprintf(stderr, "%s: the %s genesis is chain %llu, and %s is chain %llu\n", prog,
                         spec->name.c_str(), static_cast<unsigned long long>(named),
                         spec->name.c_str(), static_cast<unsigned long long>(spec->chain));
            return 2;
        }
    } catch (const std::exception& e) {
        std::fprintf(stderr, "%s: the %s genesis is not a genesis document: %s\n", prog,
                     spec->name.c_str(), e.what());
        return 2;
    }

    // The keys first: everything else is named by them. A validator that has
    // none makes them here, once, and keeps them.
    // The flags before the keys, so a mistyped command line leaves no keystore
    // behind: making a validator identity is a thing to do on purpose.
    const bool        publish        = has_flag(argc, argv, "--publish");
    const std::string data           = arg_str(argc, argv, "--data", ".lux");
    const auto        eth            = spec->chain;
    const std::string committee_path = arg_str(argc, argv, "--committee", "");
    const std::string peer_list      = arg_str(argc, argv, "--peers", "");
    if (!publish && (committee_path.empty() || peer_list.empty())) {
        std::fprintf(stderr,
                     "usage: %s [--network NAME] --committee FILE --peers a:p,b:p,... [--data DIR]\n"
                     "             [--rpc-port R] [--rpc-host H] [--mesh-host H] [--deadline-ms D]\n"
                     "             [--blocks B] [--archive-rpc URL] [--import-chain-data PATH] [--vm PATH]\n"
                     "       %s [--network NAME] --data DIR --publish\n"
                     "\n"
                     "--committee names the validators of this network, one published line each;\n"
                     "--publish makes a line for it. --peers gives every validator's mesh address\n"
                     "in committee order, and the entry at this node's own seat is where it listens;\n"
                     "--mesh-host is the address it binds (127.0.0.1; 0.0.0.0 in a pod).\n"
                     "A validator is named for a chain, so --network decides who the file names.\n",
                     prog, prog);
        return 2;
    }

    // THE CHAIN A COMMITTEE LINE IS GOOD ON. It is not in the name — a node
    // answers to one name everywhere — it is what every proof in the file is
    // signed over, so a line published for another network authorises nothing
    // here. Needed before the file is read, and it is the same 32 bytes every
    // vote carries.
    const Id chain_id = lux::node::chain_id(eth);

    // The chains this node answers for are its network's to name, and the chain
    // id names the network (network.hpp). A Zoo node is `zoo`, never `c`.
    const Network     net  = network_of(eth);
    const std::string self = net.served.front();

    // The keys: everything else is named by them.
    std::unique_ptr<Signer> mep;
    try {
        mep = std::make_unique<Signer>(Signer::open(data));
    } catch (const std::exception& e) {
        std::fprintf(stderr, "%s: %s\n", prog, e.what());
        return 2;
    }
    const Signer& me = *mep;

    // What this validator publishes so others can put it in their committee.
    // Public halves only; the proof is over this validator's own name.
    // Written beside the keys as well as printed, so a container with no shell
    // can hand it on: a committee of one line is a committee of this validator,
    // which is what an archive runs as. The keys are reused when present, so a
    // second --publish writes the same line.
    if (publish) {
        const std::string line = me.publish(chain_id);
        const std::string at   = data + "/published";
        std::ofstream     out(at, std::ios::trunc);
        out << line << "\n";
        if (!out) {
            std::fprintf(stderr, "%s: cannot write %s\n", prog, at.c_str());
            return 2;
        }
        std::printf("%s\n", line.c_str());
        return 0;
    }

    // The network, as it was written down. A malformed committee is not a
    // smaller committee — it is a network this node has not been told about, so
    // it refuses rather than starting on part of one.
    std::unique_ptr<Committee> committeep;
    std::vector<Validator>     set;
    std::vector<PeerAddr>      addresses;
    try {
        committeep = std::make_unique<Committee>(Committee::read(read_file(committee_path), chain_id));
        // Possession is checked HERE, at the door, and not taken on trust: a
        // member whose proof does not bind its name to its key is refused.
        set       = committeep->validators();
        addresses = mesh_addresses(peer_list);
    } catch (const std::exception& e) {
        std::fprintf(stderr, "%s: %s: %s\n", prog, committee_path.c_str(), e.what());
        return 2;
    }
    const Committee& committee = *committeep;
    const long       n         = long(committee.size());

    // WHERE THIS NODE SITS COMES FROM THE FILE, not from a flag. Its seat is
    // where its own identity is listed, so two processes cannot be told they
    // are the same validator, and a validator cannot be handed a seat it holds
    // no key for.
    const auto seat = committee.seat(me.node());
    if (!seat) {
        std::fprintf(stderr,
                     "%s: this validator (%s) is not in %s; add the line --publish prints\n",
                     prog, hex(me.node()).c_str(), committee_path.c_str());
        return 2;
    }
    const long index = long(*seat);

    if (addresses.size() > std::size_t(n)) {
        std::fprintf(stderr, "%s: --peers has more addresses than the committee has validators\n",
                     prog);
        return 2;
    }
    if (addresses.size() <= std::size_t(index)) {
        std::fprintf(stderr, "%s: --peers has no address for this validator's own seat (%ld)\n",
                     prog, index);
        return 2;
    }

    const long deadline_ms = arg(argc, argv, "--deadline-ms", 15000);
    const long rpc_port    = arg(argc, argv, "--rpc-port", 0);
    // 127.0.0.1 serves this machine only; a node behind a door or an ingress
    // runs with --rpc-host 0.0.0.0.
    const std::string rpc_host = arg_str(argc, argv, "--rpc-host", "127.0.0.1");
    // The same for the validator mesh: 127.0.0.1 is this machine only, and a
    // validator whose peers are other pods runs with --mesh-host 0.0.0.0. Its
    // own --peers entry is the address the OTHERS dial — in a cluster a Service
    // address the pod does not hold — so it is not what the pod binds.
    const std::string mesh_host = arg_str(argc, argv, "--mesh-host", "127.0.0.1");
    {
        in_addr parsed{};
        if (::inet_pton(AF_INET, mesh_host.c_str(), &parsed) != 1) {
            std::fprintf(stderr, "%s: --mesh-host %s: expected an IPv4 address (0.0.0.0 binds every interface)\n",
                         prog, mesh_host.c_str());
            return 2;
        }
    }
    const long blocks      = arg(argc, argv, "--blocks", 0);  // 0 = until stopped

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

    // The commitment to that set, which every vote binds. Go's encoding, over
    // the names and the UNCOMPRESSED keys the committee file already carries —
    // so a validator here signs the same message a Go one does, and the number
    // is a function of the file rather than of anything this process invented.
    const Id set_root = committee.root();

    HostConfig cfg;
    cfg.index      = std::uint32_t(index);
    cfg.host       = mesh_host;
    cfg.port       = addresses[std::size_t(index)].port;
    cfg.sk         = me.secret();
    cfg.pk         = me.key();
    cfg.validators = set;
    // HOW THIS NODE GREETS. The same identity the committee names it by, the
    // same chain that names it, and the committee itself as the answer to "who
    // is this?" — so a peer's seat is what it signed for, not what it typed.
    cfg.link.me    = me.identity();
    cfg.link.chain = chain_id;
    cfg.link.seat  = [&committee](const Node& who) -> std::optional<std::uint32_t> {
        const auto at = committee.seat(who);
        if (!at) return std::nullopt;
        return static_cast<std::uint32_t>(*at);
    };
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
    // THE CHAIN, in its own process. What it is told is what Go tells it: the
    // network, its id, the validator running it, its genesis, and a config that
    // carries --import-chain-data through, so the plugin reads the export before
    // it serves anything — Go's flag, Go's moment, Go's idempotence.
    plugin::Start with;
    with.network = spec->network;
    with.chain   = chain_id;
    with.node    = me.node();
    with.genesis.assign(spec->genesis.begin(), spec->genesis.end());
    const std::string config =
        import_path.empty() ? std::string("{}")
                            : nlohmann::json{{"import-chain-data", import_path}}.dump();
    with.config.assign(config.begin(), config.end());
    with.data_dir = data + "/chains/" + self;
    with.alias    = self;

    // Where the plugin is: the spec says where the image puts it, and --vm is
    // for a node run anywhere else.
    const std::string vm = arg_str(argc, argv, "--vm", spec->vm);

    std::unique_ptr<Node2Host>     hostp;
    std::unique_ptr<plugin::Chain> chainp;
    std::vector<plugin::Handler>   handlers;
    try {
        hostp  = std::make_unique<Node2Host>(std::move(cfg));
        chainp = plugin::Chain::start(vm, with);
        chainp->enter(plugin::Phase::Bootstrapping);
        chainp->enter(plugin::Phase::Ready);
        handlers = chainp->handlers();
    } catch (const std::exception& e) {
        std::fprintf(stderr, "node %ld: cannot start — %s\n", index, e.what());
        return 2;
    }
    Node2Host&     host  = *hostp;
    plugin::Chain& chain = *chainp;

    std::uint16_t port = 0;
    try {
        port = host.listen_bind();
    } catch (const std::exception& e) {
        std::fprintf(stderr, "node %ld: cannot listen — %s\n", index, e.what());
        return 2;
    }
    std::printf("node %ld: chain %s — the network its validators are entitled on\n", index,
                hex(chain_id).c_str());
    std::printf("node %ld: validator %s, seat %ld of %ld in %s\n", index,
                hex(me.node()).c_str(), index, n, committee_path.c_str());
    std::printf("node %ld: consensus %s:%u  chain %s (eth chainId %llu, network %u)\n", index,
                mesh_host.c_str(), port, self.c_str(), static_cast<unsigned long long>(eth), spec->network);
    std::printf("node %ld: vm %s %s, tip %s at height %llu\n", index, vm.c_str(),
                chain.version().c_str(), hex(chain.last_accepted()).c_str(),
                static_cast<unsigned long long>(chain.last_accepted_height()));
    std::printf("node %ld: validator set root %s\n", index, hex(set_root).c_str());
    std::fflush(stdout);

    // ── the RPC, up before consensus ────────────────────────────────────────
    // It must answer while the mesh is still forming, so that "is it listening"
    // and "has it reached quorum" are separable questions.
    std::unique_ptr<Rpc> rpcp;
    try {
        rpcp = std::make_unique<Rpc>(std::uint16_t(rpc_port), rpc_host);
    } catch (const std::exception& e) {
        std::fprintf(stderr, "node %ld: cannot serve RPC — %s\n", index, e.what());
        return 2;
    }
    Rpc& rpc = *rpcp;
    if (!archive_rpc.empty()) {
        rpc.set_archive_rpc(archive_rpc);
    }
    // The chain's JSON-RPC is its plugin's, relayed under every alias the chain
    // answers to. The plugin names the prefix it serves it under.
    rpc.network(net);
    // A committee below the Quasar floor certifies nothing: a transaction sent
    // here would be built, voted on by this node alone and given back at every
    // height, with its sender told it was taken. It is refused at the door.
    if (committee.size() < kMinBFTCommittee) {
        const std::string why = "this node certifies no blocks (its committee has " +
                                std::to_string(committee.size()) + " validator" +
                                (committee.size() == 1 ? "" : "s") + ", and a block needs " +
                                std::to_string(kMinBFTCommittee) +
                                "), so it accepts no transactions";
        rpc.refuse("eth_sendRawTransaction", why);
        rpc.refuse("eth_sendTransaction", why);
    }
    for (const auto& h : handlers)
        if (h.prefix == "/rpc")
            for (const auto& alias : net.served) rpc.relay(alias, h.addr, h.prefix);
    const std::string& public_api = spec->endpoint;
    rpc.about(Rpc::Json{
        {"client", client_version},
        {"mode", "light"},
        {"index", index},
        {"validators", n},
        {"endpoint", public_api},
        // The chains, and the rpc endpoint among them, are filled in by the Rpc
        // from the network it was given, so they are listed in one place.
        {"endpoints", Rpc::Json::object({
            {"health", "/v1/health"},
            {"public", public_api}
        })}
    });
    rpc.start();
    std::printf("node %ld: mode light node (frontier resident)\n", index);
    if (!archive_rpc.empty()) {
        std::printf("node %ld: archive RPC %s (proxying historical & P/X state)\n", index, archive_rpc.c_str());
    }
    std::printf("node %ld: rpc http://%s:%u/v1/chain/%s\n", index, rpc_host.c_str(), rpc.port(), self.c_str());
    std::fflush(stdout);

    // ── the mesh ────────────────────────────────────────────────────────────
    std::map<std::uint32_t, PeerAddr> peers;
    for (std::size_t j = 0; j < addresses.size(); ++j)
        if (long(j) != index) peers[std::uint32_t(j)] = addresses[j];

    // Proposed blocks arrive here and wait to be executed. Only the bytes are
    // kept — parsing is execution, and it happens on the driver's thread where
    // the chain is single-threaded, never on the pump.
    std::vector<std::vector<std::uint8_t>> inbox;
    std::mutex                             inbox_mu;
    host.on(kBlockMsgType, [&](const std::vector<std::uint8_t>& raw) {
        const std::lock_guard<std::mutex> lock(inbox_mu);
        inbox.push_back(raw);
    });

    const std::size_t reached = host.connect_mesh(peers, int(deadline_ms));
    // ONE LINE, ONE VOTE. A committee carries weight 1 per validator, so the
    // set's total is the number of validators and the reachable stake is the
    // number this node can still see, itself included. The stake a P-chain
    // computed is a different fact from a different source, and when this node
    // reads one the two numbers below are what change.
    const std::uint64_t total_stake = std::uint64_t(n);
    const std::uint64_t reachable   = std::uint64_t(reached + 1);
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

    // Transport, as luxd votes: a plugin's block does not hand its host the
    // root it executed to, so the vote binds the block and the plugin's own
    // verify is what refuses a block that does not execute.
    Engine engine(std::move(chainp), host, rpc.guard(), Binding::Transport, set_root);

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
        std::printf("node %ld: block %llu %s %s  voters %zu  stake %llu\n",
                    index,
                    static_cast<unsigned long long>(d->block->height()),
                    proposer ? "led " : "flwd",
                    hex(d->block->id()).c_str(),
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

}  // namespace lux::node
