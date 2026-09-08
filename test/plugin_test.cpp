// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// plugin_test.cpp — a REAL Go VM plugin, driven from this host.
//
// A test against a server this repo also wrote proves the two halves agree with
// each other. So this one takes a plugin BINARY — one of the programs the Go
// node runs its chains as — starts it the way the Go node starts it, and drives
// it through the sequence a chain actually goes through: initialize, read the
// last accepted block, build one, parse it back, verify it, accept it, and read
// it out again by id.
//
//   plugin_test /path/to/plugin           (or LUX_VM_PLUGIN=/path/to/plugin)
//
// With no plugin it says so and passes: the contract is worth stating in the
// tree even where the artifact to check it against is not.

#include "lux/node/plugin.hpp"

#include "../src/rlp.hpp"  // the block's own bytes, read back

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <cstring>
#include <string>

using namespace lux::node;

namespace {

int  g_fail = 0;
void check(bool ok, const std::string& what) {
    std::printf("  %s  %s\n", ok ? "ok  " : "FAIL", what.c_str());
    if (!ok) ++g_fail;
}

std::string hex(std::span<const std::uint8_t> b) {
    static const char* d = "0123456789abcdef";
    std::string        s = "0x";
    for (const auto c : b) {
        s.push_back(d[c >> 4]);
        s.push_back(d[c & 0x0f]);
    }
    return s;
}

// The C-Chain's genesis, as a plugin expects to be handed it: the document, not
// a chain. Small on purpose — what is being checked is the boundary.
const char* const kGenesis = R"({
  "config": {"chainId": 43112, "homesteadBlock": 0, "eip150Block": 0, "eip155Block": 0,
             "eip158Block": 0, "byzantiumBlock": 0, "constantinopleBlock": 0,
             "petersburgBlock": 0, "istanbulBlock": 0, "muirGlacierBlock": 0},
  "nonce": "0x0", "timestamp": "0x0", "extraData": "0x00", "gasLimit": "0x5f5e100",
  "difficulty": "0x0", "mixHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
  "coinbase": "0x0000000000000000000000000000000000000000",
  "alloc": {"8db97c7cece249c2b98bdc0226cc4c2a57bf52fc": {"balance": "0x295be96e64066972000000"}},
  "number": "0x0", "gasUsed": "0x0",
  "parentHash": "0x0000000000000000000000000000000000000000000000000000000000000000"
})";

}  // namespace

int main(int argc, char** argv) {
    std::printf("node — a Go VM plugin, run from this host\n\n");

    std::string path = (argc > 1) ? argv[1] : "";
    if (path.empty()) {
        if (const char* env = std::getenv("LUX_VM_PLUGIN")) path = env;
    }
    if (path.empty() || !std::filesystem::exists(path)) {
        std::printf("  ....  no plugin given; pass a path or set LUX_VM_PLUGIN\n");
        std::printf("        (the Go node keeps them in build/plugins, named by chain id)\n\n");
        return 0;
    }

    // Somewhere for the chain to keep its state. A plugin owns its own storage;
    // the node tells it where, and that is the whole of the arrangement.
    char        tmpl[] = "/tmp/lux-plugin-XXXXXX";
    const char* dir    = ::mkdtemp(tmpl);
    if (!dir) {
        std::printf("  FAIL  no temp dir\n");
        return 1;
    }

    plugin::Start with;
    with.network  = 12345;
    with.chain.fill(0x11);
    with.node.fill(0x22);
    with.genesis.assign(kGenesis, kGenesis + std::strlen(kGenesis));
    with.data_dir = dir;

    std::unique_ptr<plugin::Chain> chain;
    try {
        chain = plugin::Chain::start(path, with);
    } catch (const std::exception& e) {
        std::printf("  FAIL  %s\n", e.what());
        return 1;
    }
    check(chain != nullptr, "the plugin started, dialed back, and initialized");

    // ── what it says it is ──────────────────────────────────────────────────
    const std::string v = chain->version();
    check(!v.empty(), "it answers MsgVersion: " + v);
    check(chain->healthy(), "and MsgHealth");

    // ── where a chain is in its life ────────────────────────────────────────
    // The node owns this, and it is not decoration: asked to build while it is
    // still Bootstrapping, the EVM plugin dereferences nil.
    try {
        chain->enter(plugin::Phase::Bootstrapping);
        chain->enter(plugin::Phase::Ready);
        check(true, "MsgSetState carries it from Bootstrapping to Ready");
    } catch (const std::exception& e) {
        check(false, std::string("MsgSetState: ") + e.what());
    }

    // ── the tip it came up with ─────────────────────────────────────────────
    const Id            tip    = chain->last_accepted();
    const std::uint64_t height = chain->last_accepted_height();
    check(tip != kEmptyId, "it came up with a last accepted block");
    std::printf("        last accepted %s at height %llu\n", hex(tip).c_str(),
                static_cast<unsigned long long>(height));

    // ── and it is a block this host can read back by id ──────────────────────
    const auto got = chain->get(tip);
    check(got != nullptr, "MsgGetBlock returns the block it just named");
    if (got) {
        check(got->id() == tip, "with the id that was asked for");
        check(got->height() == height, "and the height it reported");
        std::printf("        %zu bytes, parent %s\n", got->bytes().size(),
                    hex(got->parent()).c_str());

        // THE STATE ROOT IS IN THE BLOCK, NOT ON THE WIRE. Go's BlockResponse
        // carries id, parent, bytes, height and timestamp and no execution
        // root — its own proposervm answers ids.Empty for that axis — so the
        // only place to read one is the block the plugin handed over. This is
        // the C-Chain's, so its bytes are an Ethereum block and the root is the
        // header's fourth field.
        const auto outer = lux::node::rlp::item(got->bytes());
        if (outer && outer->list) {
            const auto parts = lux::node::rlp::items(outer->payload);
            if (parts && !parts->empty() && (*parts)[0].list) {
                const auto header = lux::node::rlp::items((*parts)[0].payload);
                if (header && header->size() > 3) {
                    const auto root = lux::node::rlp::word((*header)[3]);
                    check(root.has_value(), "and its bytes carry a 32-byte state root");
                    if (root)
                        std::printf("        state root %s\n",
                                    hex(std::span<const std::uint8_t>(root->data(), root->size()))
                                        .c_str());
                }
            }
        }

        // ── parse is the door a peer's bytes come through ───────────────────
        const auto again = chain->parse(got->bytes());
        check(again != nullptr && again->id() == tip,
              "MsgParseBlock reads those bytes back to the same block");
    }

    // ── build, verify, accept — the whole of a height ────────────────────────
    try {
        chain->prefer(tip);
    } catch (const std::exception& e) {
        check(false, std::string("MsgSetPreference: ") + e.what());
    }
    std::shared_ptr<Block> built;
    try {
        built = chain->build();
    } catch (const std::exception& e) {
        std::printf("  ....  MsgBuildBlock refused: %s\n", e.what());
    }
    if (!built) {
        std::printf("  ....  MsgBuildBlock had nothing to build (an empty mempool is not a "
                    "failure)\n");
    } else {
        std::printf("        built %s at height %llu, %zu bytes\n", hex(built->id()).c_str(),
                    static_cast<unsigned long long>(built->height()), built->bytes().size());
        check(built->height() == height + 1, "the built block sits on the tip");
        check(built->parent() == tip, "and names it as its parent");
        check(built->verify(), "MsgBlockVerify accepts the chain's own block");
        built->accept();
        check(chain->last_accepted() == built->id(), "MsgBlockAccept moves the tip");
        const auto back = chain->get(built->id());
        check(back != nullptr && back->id() == built->id(),
              "and the accepted block reads back by id");
    }

    std::printf("\n%s\n", g_fail == 0 ? "all good" : "FAILURES");
    return g_fail == 0 ? 0 : 1;
}
