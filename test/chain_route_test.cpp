// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// chain_route_test.cpp — every spelling of a chain's path reaches the chain.
//
// This is tested over a REAL socket against a running Rpc rather than by
// calling the parser, because the parser is not the contract: what a client
// gets back from `POST /v1/chain/c` is. A client that lowercases its URL, or
// that omits the `/rpc` a directory listing once told it to use, is not asking
// for a favour — it is naming the same chain, and a node that answers one
// spelling and 404s the other has two routes where it means to have one.

#include "lux/node/rpc.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdio>
#include <string>

using namespace lux::node;

namespace {

int  g_fail = 0;
void check(bool ok, const std::string& what) {
    std::printf("  %s  %s\n", ok ? "ok  " : "FAIL", what.c_str());
    if (!ok) ++g_fail;
}

// One request, one answer, one connection — the shape the server serves.
struct Reply {
    int         status = 0;
    std::string body;
};

Reply call(std::uint16_t port, const char* verb, const std::string& path, const std::string& body) {
    Reply out;
    const int sock = ::socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return out;
    timeval tv{5, 0};
    ::setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ::setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port   = ::htons(port);
    a.sin_addr.s_addr = ::htonl(INADDR_LOOPBACK);
    if (::connect(sock, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0) {
        ::close(sock);
        return out;
    }

    std::string req = std::string(verb) + " " + path + " HTTP/1.1\r\n";
    req += "Host: 127.0.0.1\r\nContent-Type: application/json\r\n";
    req += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    req += "Connection: close\r\n\r\n" + body;
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
    if (dbl != std::string::npos) out.body = raw.substr(dbl + 4);
    return out;
}

const char* kChainId = R"({"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]})";

// The answer the one registered method gives, so a 200 that reached the WRONG
// place cannot pass as a 200 that reached the right one.
bool served(const Reply& r) {
    return r.status == 200 && r.body.find("\"0x7a69\"") != std::string::npos;
}

}  // namespace

int main() {
    Rpc rpc(0);
    // Registered ONCE, under the alias, in its natural upper case.
    rpc.method("C", "eth_chainId", [](const Rpc::Json&) { return std::string("0x7a69"); });
    // A second chain whose alias is a word rather than a letter, so folding is
    // tested on something longer than one character.
    rpc.method("Zoo", "eth_chainId", [](const Rpc::Json&) { return std::string("0x7a69"); });
    rpc.root("C");
    rpc.about(Rpc::Json{{"client", "lux-cpp/test"}});
    rpc.start();
    const std::uint16_t port = rpc.port();

    std::printf("chain_route_test — one chain, every spelling (port %u)\n", port);

    // The six paths the node is held to, plus the `bc` spelling of each.
    for (const char* path : {"/v1/chain/C/rpc", "/v1/chain/c/rpc", "/v1/chain/C", "/v1/chain/c",
                             "/v1/bc/C/rpc", "/v1/bc/c/rpc", "/v1/bc/C", "/v1/bc/c"}) {
        check(served(call(port, "POST", path, kChainId)), std::string("POST ") + path);
    }
    // A word-shaped alias folds the same way a letter does — mixed case is not
    // a further spelling to enumerate, it falls out of folding once.
    for (const char* path : {"/v1/chain/zoo", "/v1/chain/ZOO", "/v1/chain/ZoO/rpc", "/v1/bc/Zoo"}) {
        check(served(call(port, "POST", path, kChainId)), std::string("POST ") + path);
    }

    // The bare root still forwards to the C-Chain.
    check(served(call(port, "POST", "/", kChainId)), "POST /");

    // A query string names the same route.
    check(served(call(port, "POST", "/v1/chain/c?trace=1", kChainId)), "POST /v1/chain/c?trace=1");

    // Health, for the same chain, by either case.
    for (const char* path : {"/v1/chain/C/health", "/v1/chain/c/health", "/v1/bc/c/health"}) {
        const auto r = call(port, "GET", path, "");
        check(r.status == 200 && r.body.find("\"healthy\":true") != std::string::npos,
              std::string("GET ") + path);
    }

    // What must still be refused. Folding case is not opening a door: a chain
    // this node does not serve is still absent, and a path that names no chain
    // is still not a chain.
    // The words AROUND the alias are literals, deliberately: only the alias is
    // the caller's to spell, so `/v1/CHAIN/c` is a different path, not a
    // different capitalisation of this one.
    for (const char* path : {"/v1/chain/zzz", "/v1/chain/zzz/rpc", "/v1/chain", "/v1/chain/c/extra",
                             "/v1/chain/c/rpc/../../admin", "/ext/bc/C/rpc", "/v1/bc//rpc",
                             "/V1/chain/c", "/v1/CHAIN/c", "/v1/chain/c/RPC"}) {
        const auto r = call(port, "POST", path, kChainId);
        check(r.status == 404, std::string("POST ") + path + " refused (got " +
                                   std::to_string(r.status) + ")");
    }

    // P and X are the archive's, not this node's. Without one configured the
    // refusal says so — and it says so for every spelling, which is the point.
    for (const char* path : {"/v1/chain/P", "/v1/chain/p/rpc", "/v1/bc/x"}) {
        const auto r = call(port, "POST", path, kChainId);
        check(r.status == 200 && r.body.find("--archive-rpc") != std::string::npos,
              std::string("POST ") + path + " names the archive");
    }

    rpc.stop();
    std::printf("%s\n", g_fail == 0 ? "PASS" : "FAIL");
    return g_fail == 0 ? 0 : 1;
}
