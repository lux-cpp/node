// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// run_test.cpp — what run() refuses before it starts anything.
//
// Each case runs with --publish on a fresh directory, which on a good spec
// makes this validator's keys, prints its committee line and returns 0 — so a
// refusal here is a 2 that a good spec does not get, rather than the usage
// error a missing committee would also produce.

#include "lux/node/spec.hpp"

#include <array>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <vector>

using namespace lux::node;

namespace {

int  g_fail = 0;
void check(bool ok, const std::string& what) {
    std::printf("  %s  %s\n", ok ? "ok  " : "FAIL", what.c_str());
    if (!ok) ++g_fail;
}

// run() on `specs` with `args`, publishing into a directory of its own.
int publish(std::span<const Spec> specs, std::vector<std::string> args) {
    char tmpl[] = "/tmp/lux-run-XXXXXX";
    const char* dir = ::mkdtemp(tmpl);
    if (dir == nullptr) return -1;
    args.insert(args.begin(), "run_test");
    args.insert(args.end(), {"--data", dir, "--publish"});
    std::vector<char*> argv;
    for (auto& a : args) argv.push_back(a.data());
    argv.push_back(nullptr);
    const int rc = run(specs, int(args.size()), argv.data());
    std::filesystem::remove_all(dir);
    return rc;
}

}  // namespace

int main() {
    std::printf("node — what run() refuses before it starts anything\n\n");

    const Spec good{"local", "lux-cpp/test/v0", "http://127.0.0.1", 1337, 31337,
                    R"({"config":{"chainId":31337},"alloc":{}})", "/nonexistent/vm"};

    check(publish(std::array{good}, {}) == 0, "a good spec publishes this validator's line");

    Spec other  = good;
    other.chain = 31338;
    check(publish(std::array{other}, {}) == 2, "a genesis naming another chain is refused");

    Spec nested    = good;
    nested.genesis = R"({"networkID":1337,"cChainGenesis":"{\"config\":{\"chainId\":31337}}"})";
    check(publish(std::array{nested}, {}) == 0,
          "a network genesis carrying the chain as a string is read through");

    Spec broken    = good;
    broken.genesis = "{";
    check(publish(std::array{broken}, {}) == 2, "a genesis that is not JSON is refused");

    Spec nameless    = good;
    nameless.genesis = R"({"alloc":{}})";
    check(publish(std::array{nameless}, {}) == 2, "a genesis naming no chain is refused");

    const Spec second{"testnet", good.client, good.endpoint, 2, 31338,
                      R"({"config":{"chainId":31338}})", good.vm};
    check(publish(std::array{good, second}, {"--network", "testnet"}) == 0,
          "--network selects a spec by its name");
    check(publish(std::array{good, second}, {"--network", "mainnet"}) == 2,
          "a network no spec has is refused rather than rounded to one");

    std::printf("\n%s\n", g_fail == 0 ? "PASS" : "FAIL");
    return g_fail == 0 ? 0 : 1;
}
