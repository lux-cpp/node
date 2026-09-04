// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco

#include "lux/node/rpc.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <cstring>
#include <vector>

namespace lux::node {
namespace {

// THE one place that decides which chain a path names.
//
// `/v1/chain/C/rpc`, `/v1/chain/c`, `/v1/bc/C` and `/v1/bc/c/rpc` are one
// route, not four: the middle word is either spelling, the alias is matched
// without regard to case, and the trailing `/rpc` is optional. Everything
// downstream is handed a lowercase alias and never sees a path again, so a
// chain becomes reachable by every spelling the moment it registers rather
// than once someone remembers to add a branch here.
struct ChainPath {
    std::string alias;           // empty when the path names no chain
    bool        health = false;  // `.../health` rather than the RPC itself
};

ChainPath chain_path(const std::string& path) {
    std::vector<std::string> parts;
    for (std::size_t i = 0; i < path.size();) {
        if (path[i] == '/') { ++i; continue; }
        const auto end = path.find('/', i);
        parts.push_back(path.substr(i, end == std::string::npos ? end : end - i));
        if (end == std::string::npos) break;
        i = end + 1;
    }
    if (parts.size() < 3 || parts.size() > 4) return {};
    if (parts[0] != "v1") return {};
    if (parts[1] != "chain" && parts[1] != "bc") return {};

    ChainPath out;
    out.alias = parts[2];
    for (char& c : out.alias)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (parts.size() == 4) {
        if (parts[3] == "health") out.health = true;
        else if (parts[3] != "rpc") return {};
    }
    return out;
}

// Where the archive publishes a chain. This is the UPSTREAM's shape, measured
// against a running Go node rather than assumed: it answers `/v1/bc/C/rpc` and
// `/v1/bc/P`. An alias the archive does not publish is not proxied at all — a
// guessed path returns a 404 wearing the costume of an outage.
std::string archive_path(const std::string& alias) {
    if (alias == "c") return "/v1/bc/C/rpc";
    if (alias == "p") return "/v1/bc/P";
    if (alias == "x") return "/v1/bc/X";
    return "";
}

// A request this server will read, and no larger. A JSON-RPC call is small; a
// raw transaction is the biggest thing that arrives, and 1 MiB is far past any
// of them. The cap is what stops one caller from growing this node's memory.
constexpr std::size_t kMaxRequest = 1u << 20;

// A caller gets this long to finish sending and to take its answer. Without it a
// connection that opens and then says nothing holds a thread forever.
constexpr int kIoTimeoutMs = 15'000;

// Concurrent connections served at once. Past it, a connection is closed
// immediately rather than queued — a bounded refusal, not an unbounded thread
// count.
constexpr int kMaxInFlight = 64;

std::atomic<int> g_in_flight{0};

void set_timeouts(int fd) {
    timeval tv{kIoTimeoutMs / 1000, (kIoTimeoutMs % 1000) * 1000};
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    const int one = 1;
    ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
}

bool write_all(int fd, const std::string& s) {
    std::size_t off = 0;
    while (off < s.size()) {
        const ssize_t n = ::send(fd, s.data() + off, s.size() - off, 0);
        if (n <= 0) return false;
        off += static_cast<std::size_t>(n);
    }
    return true;
}

std::string response(int status, const char* reason, const std::string& body,
                     const char* type = "application/json") {
    std::string h = "HTTP/1.1 " + std::to_string(status) + " " + reason + "\r\n";
    h += "Content-Type: ";
    h += type;
    h += "\r\nContent-Length: " + std::to_string(body.size()) + "\r\n";
    // An RPC endpoint is reached from browsers; without these a page cannot call
    // it at all. Read-only and explicit — no credentials are accepted, so there
    // is no session for a hostile origin to ride.
    h += "Access-Control-Allow-Origin: *\r\n";
    h += "Access-Control-Allow-Headers: content-type\r\n";
    h += "Access-Control-Allow-Methods: POST, GET, OPTIONS\r\n";
    h += "Connection: close\r\n\r\n";
    return h + body;
}

// Case-insensitive header lookup over the raw header block.
std::size_t content_length(const std::string& head) {
    std::string lower = head;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    const auto at = lower.find("content-length:");
    if (at == std::string::npos) return 0;
    return static_cast<std::size_t>(std::strtoull(head.c_str() + at + 15, nullptr, 10));
}

std::string proxy_to_archive(const std::string& archive_url, const std::string& alias, const std::string& body) {
    if (archive_url.empty()) return "";
    const std::string target_path = archive_path(alias);
    if (target_path.empty()) return "";
    std::string url = archive_url;
    if (url.rfind("http://", 0) == 0) url = url.substr(7);
    while (!url.empty() && url.back() == '/') url.pop_back();

    std::string host = url;
    int port = 80;
    auto colon = url.find(':');
    if (colon != std::string::npos) {
        host = url.substr(0, colon);
        try { port = std::stoi(url.substr(colon + 1)); } catch (...) { port = 80; }
    }
    if (host == "localhost") host = "127.0.0.1";

    int sock = ::socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return "";
    timeval tv{4, 0};
    ::setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ::setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    // htons and friends are FUNCTIONS in glibc and MACROS on Darwin
    // (sys/_endian.h), and a macro cannot be reached through ::, so the
    // qualified spelling builds on Linux and fails to parse on macOS.
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    if (::inet_pton(AF_INET, host.c_str(), &a.sin_addr) <= 0) {
        ::close(sock);
        return "";
    }
    if (::connect(sock, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0) {
        ::close(sock);
        return "";
    }

    std::string req = "POST " + target_path + " HTTP/1.1\r\n";
    req += "Host: " + host + ":" + std::to_string(port) + "\r\n";
    req += "Content-Type: application/json\r\n";
    req += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    req += "Connection: close\r\n\r\n" + body;

    write_all(sock, req);

    std::string resp;
    char buf[4096];
    while (true) {
        ssize_t n = ::recv(sock, buf, sizeof(buf), 0);
        if (n <= 0) break;
        resp.append(buf, n);
    }
    ::close(sock);

    auto dbl = resp.find("\r\n\r\n");
    if (dbl == std::string::npos) return resp;
    std::string head = resp.substr(0, dbl);
    std::string b    = resp.substr(dbl + 4);

    bool chunked = false;
    std::string lower_head = head;
    for (char& c : lower_head) c = std::tolower(static_cast<unsigned char>(c));
    if (lower_head.find("transfer-encoding: chunked") != std::string::npos ||
        lower_head.find("transfer-encoding:chunked") != std::string::npos) {
        chunked = true;
    }

    if (chunked) {
        std::string unchunked;
        std::size_t pos = 0;
        while (pos < b.size()) {
            auto eol = b.find("\r\n", pos);
            if (eol == std::string::npos) break;
            std::string hex_str = b.substr(pos, eol - pos);
            auto semi = hex_str.find(';');
            if (semi != std::string::npos) hex_str = hex_str.substr(0, semi);
            std::size_t size = 0;
            try { size = std::stoul(hex_str, nullptr, 16); } catch (...) { break; }
            if (size == 0) break;
            pos = eol + 2;
            if (pos + size > b.size()) break;
            unchunked.append(b, pos, size);
            pos += size;
            if (pos + 2 <= b.size() && b[pos] == '\r' && b[pos+1] == '\n') {
                pos += 2;
            }
        }
        return unchunked.empty() ? b : unchunked;
    }
    return b;
}

}  // namespace

Rpc::Rpc(std::uint16_t port) {
    fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd_ < 0) throw std::runtime_error("rpc: socket");
    const int one = 1;
    ::setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    sockaddr_in a{};
    a.sin_family      = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port        = htons(port);
    if (::bind(fd_, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0) {
        ::close(fd_);
        throw std::runtime_error("rpc: bind 127.0.0.1:" + std::to_string(port) + ": " +
                                 std::strerror(errno));
    }
    if (::listen(fd_, 64) != 0) {
        ::close(fd_);
        throw std::runtime_error("rpc: listen");
    }
    socklen_t len = sizeof(a);
    if (::getsockname(fd_, reinterpret_cast<sockaddr*>(&a), &len) == 0)
        port_ = ntohs(a.sin_port);
}

Rpc::~Rpc() { stop(); }

namespace {
std::string lower(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}
}  // namespace

void Rpc::method(std::string alias, std::string name, Method fn) {
    methods_[lower(std::move(alias))][std::move(name)] = std::move(fn);
}
void Rpc::root(std::string alias) { root_alias_ = lower(std::move(alias)); }
void Rpc::about(Json j) { about_ = std::move(j); }

void Rpc::start() {
    running_   = true;
    accepting_ = std::thread([this] { serve(); });
}

void Rpc::stop() {
    if (!running_) return;
    running_ = false;
    // Closing the listener is what wakes the blocking accept(); the thread then
    // sees running_ == false and returns. No signal, no cancellation.
    if (fd_ >= 0) { ::shutdown(fd_, SHUT_RDWR); ::close(fd_); fd_ = -1; }
    if (accepting_.joinable()) accepting_.join();
}

void Rpc::serve() {
    while (running_) {
        sockaddr_in a{};
        socklen_t   len = sizeof(a);
        const int   c   = ::accept(fd_, reinterpret_cast<sockaddr*>(&a), &len);
        if (c < 0) {
            if (!running_) return;
            if (errno == EINTR) continue;
            return;  // the listener is gone
        }
        if (g_in_flight.load() >= kMaxInFlight) { ::close(c); continue; }
        ++g_in_flight;
        std::thread([this, c] {
            answer(c);
            ::close(c);
            --g_in_flight;
        }).detach();
    }
}

void Rpc::answer(int fd) {
    set_timeouts(fd);

    std::string head;
    char        buf[1024];
    while (head.size() < kMaxRequest) {
        const ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) return;
        head.append(buf, static_cast<std::size_t>(n));
        const auto end = head.find("\r\n\r\n");
        if (end != std::string::npos) break;
    }

    const auto header_end = head.find("\r\n\r\n");
    if (header_end == std::string::npos) {
        write_all(fd, response(400, "Bad Request", "{}"));
        return;
    }

    const std::size_t clen = content_length(head.substr(0, header_end));
    if (clen > kMaxRequest) {
        write_all(fd, response(413, "Payload Too Large", "{}"));
        return;
    }

    std::string body = head.substr(header_end + 4);
    while (body.size() < clen) {
        const ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) return;
        body.append(buf, static_cast<std::size_t>(n));
    }

    // Request line: METHOD SP PATH SP VERSION
    const auto sp1 = head.find(' ');
    const auto sp2 = head.find(' ', sp1 == std::string::npos ? 0 : sp1 + 1);
    if (sp1 == std::string::npos || sp2 == std::string::npos) {
        write_all(fd, response(400, "Bad Request", "{}"));
        return;
    }
    const std::string verb = head.substr(0, sp1);
    std::string       path = head.substr(sp1 + 1, sp2 - sp1 - 1);
    if (const auto q = path.find('?'); q != std::string::npos) path.resize(q);
    while (path.size() > 1 && path.back() == '/') path.pop_back();

    if (verb == "OPTIONS") { write_all(fd, response(204, "No Content", "")); return; }

    // Decided once, here, for every verb below.
    const ChainPath chain = chain_path(path);

    if (verb == "GET") {
        if (path == "" || path == "/") {
            Json about = about_;
            about["mode"] = "light";
            if (!archive_rpc_.empty()) {
                about["archiveRpc"] = archive_rpc_;
            }
            if (!about.contains("chains")) {
                about["chains"] = Json::object();
            }
            // Advertise what is actually registered, so a chain appears here by
            // existing. The archive-backed pair is named too, because a light
            // node answers for them without serving them.
            for (const auto& served : methods_)
                about["chains"][served.first] = "/v1/chain/" + served.first;
            for (const char* proxied : {"p", "x"})
                if (!about["chains"].contains(proxied))
                    about["chains"][proxied] = std::string("/v1/chain/") + proxied;
            if (!about.contains("endpoints")) {
                about["endpoints"] = Json::object();
            }
            about["endpoints"]["rpc"] = "/v1/chain/" + (root_alias_.empty() ? std::string("c") : root_alias_);
            about["endpoints"]["p"] = "/v1/chain/p";
            about["endpoints"]["x"] = "/v1/chain/x";
            write_all(fd, response(200, "OK", about.dump()));
        } else if (path == "/healthz" || path == "/v1/health" || path == "/health") {
            Json h = {
                {"healthy", true},
                {"checks", {
                    {"bls", {{"message", "node has the correct BLS key"}, {"healthy", true}}},
                    {"consensus", {{"message", "mesh healthy"}, {"healthy", true}}},
                    {"chain", {{"message", "C-Chain live"}, {"healthy", true}}}
                }}
            };
            write_all(fd, response(200, "OK", h.dump()));
        } else if (chain.health && methods_.count(chain.alias) != 0) {
            Json h = {
                {"chain", chain.alias},
                {"healthy", true},
                {"client", about_.value("client", "lux-cpp/v0.1.0")}
            };
            write_all(fd, response(200, "OK", h.dump()));
        } else {
            write_all(fd, response(404, "Not Found", "{}"));
        }
        return;
    }
    if (verb != "POST") { write_all(fd, response(405, "Method Not Allowed", "{}")); return; }

    // Go forwards a bare POST / to the C-Chain; so does this.
    const std::string alias =
        (path == "" || path == "/") && !root_alias_.empty() ? root_alias_ : chain.alias;

    if (alias.empty() || chain.health) {
        write_all(fd, response(404, "Not Found",
                               R"({"jsonrpc":"2.0","id":null,)"
                               R"("error":{"code":-32601,"message":"no such chain"}})"));
        return;
    }

    if (methods_.find(alias) == methods_.end()) {
        // A chain this node does not keep. With an archive configured it is
        // still answerable, which is how a frontier-only node serves P and X.
        if (!archive_rpc_.empty()) {
            const std::string proxied = proxy_to_archive(archive_rpc_, alias, body);
            if (!proxied.empty()) {
                write_all(fd, response(200, "OK", proxied));
                return;
            }
        }
        if (!archive_path(alias).empty()) {
            write_all(fd, response(200, "OK",
                                   R"({"jsonrpc":"2.0","id":null,)"
                                   R"("error":{"code":-32000,"message":"light node: P/X chain queries require --archive-rpc to proxy from full archive node"}})"));
            return;
        }
        write_all(fd, response(404, "Not Found",
                               R"({"jsonrpc":"2.0","id":null,)"
                               R"("error":{"code":-32601,"message":"no such chain"}})"));
        return;
    }

    Json request;
    try {
        request = Json::parse(body);
    } catch (const std::exception&) {
        write_all(fd, response(200, "OK",
                               R"({"jsonrpc":"2.0","id":null,)"
                               R"("error":{"code":-32700,"message":"parse error"}})"));
        return;
    }

    // A batch is an array of calls; the spec says answer with an array. Clients
    // (ethers, web3) batch by default, so this is not an extra.
    Json out;
    if (request.is_array()) {
        out = Json::array();
        for (const auto& one : request) out.push_back(dispatch(alias, one));
    } else {
        out = dispatch(alias, request);
    }
    write_all(fd, response(200, "OK", out.dump()));
}

Rpc::Json Rpc::dispatch(const std::string& alias, const Json& req) {
    // The id is echoed even when the request is malformed, which is what lets a
    // client match an error to the call that caused it.
    Json id = nullptr;
    if (req.is_object() && req.contains("id")) id = req["id"];

    auto fail = [&](int code, const std::string& msg) {
        return Json{{"jsonrpc", "2.0"},
                    {"id", id},
                    {"error", {{"code", code}, {"message", msg}}}};
    };

    if (!req.is_object() || !req.contains("method") || !req["method"].is_string())
        return fail(-32600, "invalid request");

    const auto& table = methods_.at(alias);
    const auto  it    = table.find(req["method"].get<std::string>());
    if (it == table.end()) {
        if (!archive_rpc_.empty()) {
            std::string proxied = proxy_to_archive(archive_rpc_, alias, req.dump());
            if (!proxied.empty()) {
                try {
                    return Json::parse(proxied);
                } catch (...) {}
            }
        }
        return fail(-32601, "the method " + req["method"].get<std::string>() + " does not exist");
    }

    const Json params = req.contains("params") ? req["params"] : Json::array();
    try {
        // THE lock, held across the whole call: the chain is single-threaded and
        // the driver mutates it between heights.
        const std::lock_guard<std::mutex> lock(mu_);
        return Json{{"jsonrpc", "2.0"}, {"id", id}, {"result", it->second(params)}};
    } catch (const Error& e) {
        if (e.code == -32000 && !archive_rpc_.empty()) {
            std::string proxied = proxy_to_archive(archive_rpc_, alias, req.dump());
            if (!proxied.empty()) {
                try {
                    return Json::parse(proxied);
                } catch (...) {}
            }
        }
        return fail(e.code, e.what());
    } catch (const std::exception& e) {
        // A method that threw something unplanned is a bug in this node, not a
        // reason to end it. The caller is told; the daemon keeps validating.
        return fail(-32603, e.what());
    }
}

}  // namespace lux::node
