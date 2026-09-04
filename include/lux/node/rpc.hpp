// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// rpc.hpp — the node's HTTP JSON-RPC surface.
//
// The paths are Go's, verified against the running node rather than assumed:
// `/v1/chain/<alias>`, where the alias is the VM's own ("C", "P", "X"). The
// alias is matched without regard to case and the trailing `/rpc` is optional,
// so `/v1/chain/C/rpc` and `/v1/chain/c` are the same route; `/v1/bc/...` is
// the same word in the middle and is accepted too. One function decides all of
// that — chain_path() in rpc.cpp — and a chain is registered once, under its
// alias. The `/ext/bc/...` prefix that every Ethereum tutorial writes is GONE
// from luxd — server/http/server.go states baseURL = "/v1" and that there is no
// backward compatibility — so serving it here would be inventing a route the
// network does not have. `POST /` is proxied to the C-Chain, which luxd also
// does, because that is what an unconfigured `eth` client hits first.
//
// A method is a function from params to result. Throwing `Rpc::Error` produces
// a JSON-RPC error object; anything else escaping a method is caught and
// reported as an internal error rather than killing the daemon — an RPC caller
// must never be able to stop a validator.
//
// CONCURRENCY, STATED ONCE. The chain is single-threaded (consensus drives it),
// and the RPC answers on other threads. So the Rpc owns THE lock: it holds it
// for the whole of every method call, and the driver holds it while it advances
// a height. There is exactly one, it is not recursive, and no method may block
// on anything but its own computation.

#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include <nlohmann/json.hpp>

namespace lux::node {

class Rpc {
public:
    using Json   = nlohmann::json;
    using Method = std::function<Json(const Json& params)>;

    // A JSON-RPC error, thrown by a method. The codes are the spec's:
    // -32600 invalid request, -32601 method not found, -32602 invalid params,
    // -32603 internal error.
    struct Error : std::runtime_error {
        Error(int c, std::string what) : std::runtime_error(std::move(what)), code(c) {}
        int code;
    };

    // Bind 127.0.0.1:port. A port of 0 is OS-assigned and readable from port()
    // afterwards. Throws at the boundary if the socket cannot be bound.
    explicit Rpc(std::uint16_t port);
    ~Rpc();

    Rpc(const Rpc&) = delete;
    Rpc& operator=(const Rpc&) = delete;

    // Register `name` on the chain `alias` (e.g. "C", "eth_chainId"). A chain
    // is registered ONCE, under its alias, and is then reachable by every
    // spelling of the path that names it — see chain_path() in rpc.cpp.
    void method(std::string alias, std::string name, Method fn);

    // Answer `POST /` from `alias` as well — Go forwards the bare root to the
    // C-Chain's RPC, and a client pointed at the node with no path expects it.
    void root(std::string alias);

    // A plain GET / — what the node says about itself.
    void about(Json j);

    void          start();
    void          stop();
    std::uint16_t port() const noexcept { return port_; }

    void               set_archive_rpc(std::string url) { archive_rpc_ = std::move(url); }
    const std::string& archive_rpc() const noexcept { return archive_rpc_; }

    // THE lock. The driver holds it while it mutates the chain; the Rpc holds it
    // for the duration of every method call.
    std::mutex& guard() noexcept { return mu_; }

private:
    void serve();
    void answer(int fd);
    Json dispatch(const std::string& alias, const Json& request);

    int                                             fd_ = -1;
    std::uint16_t                                   port_ = 0;
    // Keyed by lowercase chain alias, never by path.
    std::map<std::string, std::map<std::string, Method>> methods_;
    std::string                                     root_alias_;
    std::string                                     archive_rpc_;
    Json                                            about_;
    std::mutex                                      mu_;
    std::thread                                     accepting_;
    bool                                            running_ = false;
};

}  // namespace lux::node
