// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// export.cpp — `local_export CEVM OUT TXS N`: an export of the local chain
// (31337) whose blocks the cevm plugin built itself, one transaction a block,
// from the first N raw transactions in TXS. Block 0 first, then each block's
// own bytes: the shape luxfi/state's exports have, so `--import-chain-data`
// reads it as it reads theirs. scripts/cluster.sh imports it into every
// validator and continues it.

#include "../../src/local.hpp"
#include "lux/node/network.hpp"
#include "lux/node/plugin.hpp"
#include "lux/node/rpc.hpp"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <thread>
#include <vector>

#include <unistd.h>

using namespace lux::node;

namespace {

std::vector<std::uint8_t> unhex(const std::string& s) {
    std::vector<std::uint8_t> out;
    for (std::size_t i = 2; i + 1 < s.size(); i += 2) out.push_back(std::uint8_t(std::stoi(s.substr(i, 2), nullptr, 16)));
    return out;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc != 5) {
        std::fprintf(stderr, "usage: local_export CEVM OUT TXS N\n");
        return 2;
    }
    const std::string cevm = argv[1], out = argv[2], txs = argv[3];
    const int         n    = std::atoi(argv[4]);
    const auto        dir  = std::filesystem::temp_directory_path() / ("local-export-" + std::to_string(::getpid()));
    std::filesystem::remove_all(dir);

    plugin::Start with;
    with.network = 1337;
    with.chain   = chain_id(31337);
    const std::string genesis = kLocalGenesis;
    with.genesis.assign(genesis.begin(), genesis.end());
    with.config   = {'{', '}'};
    with.data_dir = (dir / "c").string();
    with.alias    = "c";
    auto chain    = plugin::Chain::start(cevm, with);
    chain->enter(plugin::Phase::Bootstrapping);
    chain->enter(plugin::Phase::Ready);
    Rpc rpc(0);
    rpc.network(network_of(31337));
    for (const auto& h : chain->handlers())
        if (h.prefix == "/rpc") rpc.relay("c", h.addr, h.prefix);

    std::vector<std::uint8_t> file;
    const auto                zero = chain->get(chain->last_accepted());
    file.insert(file.end(), zero->bytes().begin(), zero->bytes().end());

    std::ifstream in(txs);
    std::string   line;
    for (int i = 0; i < n && std::getline(in, line); ++i) {
        if (!rpc.submit("c", unhex(line))) {
            std::fprintf(stderr, "local_export: transaction %d was refused\n", i);
            return 1;
        }
        // A Cancun block that would owe a block gas cost is not built, so the
        // next one waits out the target interval rather than asking twice.
        std::shared_ptr<Block> b;
        for (int tries = 0; tries < 100 && !b; ++tries) {
            b = chain->build();
            if (!b) std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        if (!b) {
            std::fprintf(stderr, "local_export: block %d was never built\n", i + 1);
            return 1;
        }
        b->accept();
        file.insert(file.end(), b->bytes().begin(), b->bytes().end());
    }
    std::ofstream(out, std::ios::binary).write(reinterpret_cast<const char*>(file.data()), std::streamsize(file.size()));
    const auto tip = chain->last_accepted();
    std::printf("height %llu tip 0x", static_cast<unsigned long long>(chain->last_accepted_height()));
    for (auto c : tip) std::printf("%02x", c);
    std::printf("\n");
    chain.reset();
    std::filesystem::remove_all(dir);
    return 0;
}
