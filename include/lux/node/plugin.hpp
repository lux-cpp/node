// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// plugin.hpp — a chain in another process.
//
// The Go node does not link its chains in. It runs each one as a separate
// program and speaks ZAP to it, which is why a chain can be upgraded, crash or
// be replaced without taking the validator with it. Every chain that is not the
// C-Chain — P, X, Q, Z and the rest — exists as one of those programs today.
//
// So a host that can run them does not need a port of each. `Chain` here IS a
// `node::VM`: the engine cannot tell which side of the boundary its chain is
// on, because it is the same interface, the same calls, in the same order.
//
// ── THE INTEROP CONTRACT, as the Go node performs it ────────────────────────
//
// Nobody had written this down. It is `vms/rpcchainvm/factory.go` and
// `runtime/subprocess/runtime_zap.go`, read off the code:
//
//  1. The NODE binds a listener for the bootstrap — `NewListener()`: a
//     unix-domain socket under a temp dir when `LUXD_VM_UNIX_SOCKET=1`, TCP on
//     127.0.0.1:0 otherwise.
//  2. The node execs the plugin with the parent environment PLUS
//        VM_TRANSPORT=zap
//        VM_RUNTIME_ENGINE_ADDR=<the bootstrap listener's address>
//        LUX_VM_RUNTIME_ENGINE_ADDR=<the same>   (the pre-rename key, for
//                                                 plugins built before it)
//  3. The PLUGIN binds its OWN address, dials the bootstrap listener, and
//     writes one message and nothing else:
//        [4-byte BE length][4-byte BE protocol version][address, as text]
//     where length counts the version and the address together.
//  4. The node refuses a protocol version that is not its own — 42 today
//     (`version.RPCChainVMProtocol`) — and then DIALS the address it was given.
//  5. From there it is ZAP: `[4-byte BE length][1-byte type][payload]`, and
//     every request and response payload begins with a 4-byte big-endian
//     request id. A response is the request's type with 0x80; an error adds
//     0x40.
//
// The message numbers are Go's (`luxfi/api/zap/wire.go`) and are not ours to
// choose. A parallel numbering would be a second protocol wearing the first
// one's frames.

#pragma once

#include "lux/node/vm.hpp"

#include <array>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

namespace lux::node::plugin {

// The node-to-VM methods, as `luxfi/api/zap/wire.go` numbers them. Every id is
// below 0x40 so the response and error bits are free.
enum Msg : std::uint8_t {
    kInitialize   = 1,
    kSetState     = 2,
    kBuildBlock   = 9,
    kParseBlock   = 10,
    kGetBlock     = 11,
    kSetPreference = 12,
    kHealth       = 13,
    kVersion      = 14,
    kAtHeight     = 22,
    kBlockVerify  = 28,
    kBlockAccept  = 29,
    kBlockReject  = 30,
};

// Where a chain is in its life, as `luxfi/vm` numbers it. A chain does not
// build blocks until it is told it is Ready, and a plugin that is asked to
// build before then answers with a nil dereference rather than a refusal —
// measured, and the reason this is not optional.
enum class Phase : std::uint8_t {
    Unknown = 0, Starting = 1, Syncing = 2, Bootstrapping = 3,
    Ready = 4, Degraded = 5, Stopping = 6, Stopped = 7,
};

// The RPCChainVM protocol this host speaks. An exact match is required in both
// directions: Go refuses a mismatch rather than negotiating, because a plugin
// one version off does not differ in a way either side can detect later.
inline constexpr std::uint32_t kProtocol = 42;

// What a chain is told about the network it is joining. Go builds this from
// live node state; the fields a plugin actually reads to come up are these.
struct Start {
    std::uint32_t             network = 0;
    Id                        chain{};        // this chain's 32-byte id
    std::array<std::uint8_t, 20> node{};      // the validator running it
    // The three ids a plugin is told about the network around it. They are
    // FIXED WIDTH on the wire and a plugin refuses a short one — measured:
    // "initialize xChainID: invalid hash length: expected 32 bytes but got 0" —
    // so they are ids here rather than byte strings, and a network with no
    // X-Chain says so with the zero id rather than with nothing.
    Id                        x{};
    Id                        c{};
    Id                        asset{};        // the UTXO asset the network settles in
    std::vector<std::uint8_t> genesis;        // the chain's genesis document
    std::vector<std::uint8_t> upgrade;
    std::vector<std::uint8_t> config;
    std::string               data_dir;       // where the plugin keeps its state
    std::string               alias = "C";    // the path segment RPC reaches it under
};

// One block, as the far side described it: the block's own operations are calls
// back over the link, so it holds its chain rather than any state of its own.
class Remote;

// A chain running in another process. Starting one starts the program; letting
// go of it stops the program.
class Chain final : public VM {
public:
    // Start `path` the way the Go node starts it, complete the bootstrap, dial
    // the address the plugin reports, and Initialize it. Throws
    // std::runtime_error naming the step that refused.
    [[nodiscard]] static std::unique_ptr<Chain> start(const std::filesystem::path& path,
                                                      const Start&                 with);
    ~Chain() override;

    Chain(const Chain&)            = delete;
    Chain& operator=(const Chain&) = delete;

    [[nodiscard]] Id          chain_id() const override;
    [[nodiscard]] std::string alias() const override;

    std::shared_ptr<Block> build() override;
    std::shared_ptr<Block> parse(std::span<const std::uint8_t> bytes) override;
    std::shared_ptr<Block> get(const Id& id) const override;
    void                   prefer(const Id& id) override;

    [[nodiscard]] Id            last_accepted() const override;
    [[nodiscard]] std::uint64_t last_accepted_height() const override;

    // Tell the chain where it is. The node owns this: a chain is Bootstrapping
    // while its history is being fetched and Ready when it may build and vote,
    // and it is the node that knows which.
    void enter(Phase p);

    // What the plugin answers about itself, and whether it says it is well.
    [[nodiscard]] std::string version() const;
    [[nodiscard]] bool        healthy() const;

    struct State;

private:
    friend class Remote;
    Chain();
    std::unique_ptr<State> st_;
};

}  // namespace lux::node::plugin
