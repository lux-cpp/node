// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// chain_route_test.cpp — every spelling of a chain's path reaches the chain,
// and no spelling of another network's chain reaches anything.
//
// Two halves of one rule. A client that lowercases its URL, or omits the `/rpc`
// a directory listing once told it to use, is not asking for a favour — it is
// naming the same chain, and a node that answers one spelling and 404s the
// other has two routes where it means to have one. But a client that asks a Zoo
// node for `c` is naming a chain that node does not have: C-Chain is the Lux
// primary network's EVM, and answering it with Zoo's chain id inside is how a
// node comes to lie about which network it is on.
//
// Tested over a REAL socket against a running Rpc rather than by calling the
// parser, because the parser is not the contract: what a client gets back from
// `POST /v1/chain/c` is.

#include "lux/node/network.hpp"
#include "lux/node/rpc.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cctype>
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
    a.sin_port   = htons(port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
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

// A node on one network, wired the way serve_eth wires a real one: the method
// table registered under every alias its own chain answers to, and the network
// itself handed to the Rpc. Nothing here enumerates paths — the aliases come
// from the chain id, which is the thing under test.
struct Node {
    Rpc         rpc{0};
    Network     net;
    std::string answer;

    explicit Node(std::uint64_t chain_id) : net(network_of(chain_id)) {
        answer = "0x" + [&] {
            char b[32];
            std::snprintf(b, sizeof(b), "%llx", static_cast<unsigned long long>(chain_id));
            return std::string(b);
        }();
        // By value: a detached handler thread may still be answering while this
        // Node is going away, and the method table outlives nothing it reads.
        for (const auto& alias : net.served)
            rpc.method(alias, "eth_chainId", [a = answer](const Rpc::Json&) { return a; });
        rpc.network(net);
        rpc.about(Rpc::Json{{"client", "lux-cpp/test"}});
        rpc.start();
    }
    std::uint16_t port() { return rpc.port(); }

    // A 200 that reached the WRONG chain must not pass as a 200 that reached the
    // right one, so the chain's OWN id is what the answer has to carry.
    bool served(const Reply& r) const {
        return r.status == 200 && r.body.find("\"" + answer + "\"") != std::string::npos;
    }
};

// Every spelling of one alias: both middle words, both cases, `/rpc` present and
// absent. A node either answers all of them or none of them.
void every_spelling(Node& node, const std::string& alias, bool owned) {
    std::string upper = alias;
    for (char& c : upper) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    for (const char* middle : {"chain", "bc"}) {
        for (const std::string& word : {alias, upper}) {
            for (const char* tail : {"", "/rpc"}) {
                const std::string path = "/v1/" + std::string(middle) + "/" + word + tail;
                const Reply       r    = call(node.port(), "POST", path, kChainId);
                if (owned)
                    check(node.served(r), "POST " + path);
                else
                    check(r.status == 404,
                          "POST " + path + " refused (got " + std::to_string(r.status) + ")");
            }
        }
    }
}

}  // namespace

int main() {
    std::printf("chain_route_test — a node answers for its own network, and only that\n");

    // ── Zoo: the violation this test exists for ─────────────────────────────
    {
        Node zoo(200200);
        std::printf("zoo node (chain id 200200, port %u)\n", zoo.port());

        // Its own name, and its own number. The number is not a courtesy: it is
        // the chain's identity, and a node that 404s its own id is unreachable
        // by anything that knows only what chain it wants.
        every_spelling(zoo, "zoo", true);
        every_spelling(zoo, "200200", true);

        // THE BUG. `c` on a Zoo node used to answer 200200 — a Lux path serving
        // a Zoo chain, which tells a client it is talking to the C-Chain. Only a
        // Lux node has one. `hanzo` is the same refusal from the other side: a
        // network's aliases are not a namespace anyone else may borrow.
        every_spelling(zoo, "c", false);
        every_spelling(zoo, "hanzo", false);
        every_spelling(zoo, "36963", false);

        // P and X belong to the Lux primary network too, so they are not Zoo's
        // to proxy either — and with no archive configured that distinction is
        // exactly the one that could hide: both would be "not served here".
        every_spelling(zoo, "p", false);
        every_spelling(zoo, "x", false);

        // The bare root is this node's own chain, so ethers and viem pointed at
        // the host with no path reach Zoo rather than nothing.
        check(zoo.served(call(zoo.port(), "POST", "/", kChainId)), "POST / is the node's own chain");

        // Health, for its own chain and by either case; and not for a chain it
        // does not have.
        for (const char* path : {"/v1/chain/zoo/health", "/v1/chain/ZOO/health", "/v1/bc/200200/health"}) {
            const Reply r = call(zoo.port(), "GET", path, "");
            check(r.status == 200 && r.body.find("\"healthy\":true") != std::string::npos,
                  std::string("GET ") + path);
        }
        check(call(zoo.port(), "GET", "/v1/chain/c/health", "").status == 404,
              "GET /v1/chain/c/health refused");

        // What it says about itself must match what it serves — an advertisement
        // for a chain that 404s is a second, wrong answer to the same question.
        const Reply about = call(zoo.port(), "GET", "/", "");
        check(about.status == 200 && about.body.find("/v1/chain/zoo") != std::string::npos,
              "GET / advertises zoo");
        check(about.body.find("/v1/chain/p") == std::string::npos &&
              about.body.find("\"c\"") == std::string::npos,
              "…and advertises no chain of another network");
    }

    // ── Lux: the network that does own C, P and X ───────────────────────────
    {
        Node lux(96369);
        std::printf("lux node (chain id 96369, port %u)\n", lux.port());

        every_spelling(lux, "c", true);
        every_spelling(lux, "96369", true);

        // Zoo's and Hanzo's chains are refused from this side too. The rule is
        // ownership, not a deny-list with `c` privileged.
        every_spelling(lux, "zoo", false);
        every_spelling(lux, "hanzo", false);
        every_spelling(lux, "200200", false);

        // P and X ARE this network's, and a light node reaches them through an
        // archive — so they are NOT a 404, and with none configured the answer
        // says which piece is missing rather than pretending the chain is.
        for (const char* path : {"/v1/chain/P", "/v1/chain/p/rpc", "/v1/bc/x"}) {
            const Reply r = call(lux.port(), "POST", path, kChainId);
            check(r.status == 200 && r.body.find("--archive-rpc") != std::string::npos,
                  std::string("POST ") + path + " names the archive");
        }

        check(lux.served(call(lux.port(), "POST", "/", kChainId)), "POST / is the node's own chain");
        check(lux.served(call(lux.port(), "POST", "/v1/chain/c?trace=1", kChainId)),
              "POST /v1/chain/c?trace=1");
    }

    // ── Hanzo: its own EVM, and none of the Lux primary network's chains ────
    {
        Node hanzo(36963);
        std::printf("hanzo node (chain id 36963, port %u)\n", hanzo.port());

        every_spelling(hanzo, "hanzo", true);
        every_spelling(hanzo, "36963", true);
        every_spelling(hanzo, "c", false);
        every_spelling(hanzo, "zoo", false);
        every_spelling(hanzo, "p", false);
        check(hanzo.served(call(hanzo.port(), "POST", "/", kChainId)), "POST / is the node's own chain");
    }

    // ── what is refused whatever the network ────────────────────────────────
    {
        Node lux(31337);  // the localnet id, which is still Lux
        std::printf("lux localnet node (chain id 31337, port %u)\n", lux.port());
        every_spelling(lux, "c", true);
        every_spelling(lux, "31337", true);

        // Folding case is not opening a door, and the words AROUND the alias are
        // literals: only the alias is the caller's to spell, so `/v1/CHAIN/c` is
        // a different path rather than a different capitalisation of this one.
        for (const char* path : {"/v1/chain/zzz", "/v1/chain/zzz/rpc", "/v1/chain", "/v1/chain/c/extra",
                                 "/v1/chain/c/rpc/../../admin", "/ext/bc/C/rpc", "/v1/bc//rpc",
                                 "/V1/chain/c", "/v1/CHAIN/c", "/v1/chain/c/RPC"}) {
            const Reply r = call(lux.port(), "POST", path, kChainId);
            check(r.status == 404, std::string("POST ") + path + " refused (got " +
                                       std::to_string(r.status) + ")");
        }
    }

    // ── a chain id no network claims ────────────────────────────────────────
    {
        // It is still exactly one chain: it answers under its own number, under
        // the root, and under nothing else. Inheriting `c` here — the old
        // default — would give an unknown chain the C-Chain's name.
        Node lone(424242);
        std::printf("unclaimed chain id (424242, port %u)\n", lone.port());
        every_spelling(lone, "424242", true);
        every_spelling(lone, "c", false);
        check(lone.served(call(lone.port(), "POST", "/", kChainId)), "POST / is the node's own chain");
    }

    std::printf("%s\n", g_fail == 0 ? "PASS" : "FAIL");
    return g_fail == 0 ? 0 : 1;
}
