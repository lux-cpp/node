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
#include <cerrno>
#include <cstring>

namespace lux::node {
namespace {

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

}  // namespace

Rpc::Rpc(std::uint16_t port) {
    fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd_ < 0) throw std::runtime_error("rpc: socket");
    const int one = 1;
    ::setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    sockaddr_in a{};
    a.sin_family      = AF_INET;
    a.sin_addr.s_addr = ::htonl(INADDR_LOOPBACK);
    a.sin_port        = ::htons(port);
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
        port_ = ::ntohs(a.sin_port);
}

Rpc::~Rpc() { stop(); }

void Rpc::method(std::string path, std::string name, Method fn) {
    methods_[std::move(path)][std::move(name)] = std::move(fn);
}
void Rpc::root(std::string path) { root_path_ = std::move(path); }
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
        const int c = ::accept(fd_, nullptr, nullptr);
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

    // Read the head, then exactly Content-Length more. Bounded at every step.
    std::string buf;
    char        tmp[8192];
    std::size_t head_end = std::string::npos;
    while (head_end == std::string::npos) {
        const ssize_t n = ::recv(fd, tmp, sizeof(tmp), 0);
        if (n <= 0) return;
        buf.append(tmp, static_cast<std::size_t>(n));
        if (buf.size() > kMaxRequest) {
            write_all(fd, response(413, "Payload Too Large", "{}"));
            return;
        }
        head_end = buf.find("\r\n\r\n");
    }
    const std::string head = buf.substr(0, head_end);
    std::string       body = buf.substr(head_end + 4);

    const std::size_t want = content_length(head);
    if (want > kMaxRequest) {
        write_all(fd, response(413, "Payload Too Large", "{}"));
        return;
    }
    while (body.size() < want) {
        const ssize_t n = ::recv(fd, tmp, sizeof(tmp), 0);
        if (n <= 0) return;
        body.append(tmp, static_cast<std::size_t>(n));
    }
    body.resize(want);

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

    if (verb == "GET") {
        if (path == "" || path == "/") {
            write_all(fd, response(200, "OK", about_.dump()));
        } else {
            write_all(fd, response(404, "Not Found", "{}"));
        }
        return;
    }
    if (verb != "POST") { write_all(fd, response(405, "Method Not Allowed", "{}")); return; }

    // Go forwards a bare POST / to the C-Chain; so does this.
    if ((path == "" || path == "/") && !root_path_.empty()) path = root_path_;

    if (methods_.find(path) == methods_.end()) {
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
        for (const auto& one : request) out.push_back(dispatch(path, one));
    } else {
        out = dispatch(path, request);
    }
    write_all(fd, response(200, "OK", out.dump()));
}

Rpc::Json Rpc::dispatch(const std::string& path, const Json& req) {
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

    const auto& table = methods_.at(path);
    const auto  it    = table.find(req["method"].get<std::string>());
    if (it == table.end())
        return fail(-32601, "the method " + req["method"].get<std::string>() + " does not exist");

    const Json params = req.contains("params") ? req["params"] : Json::array();
    try {
        // THE lock, held across the whole call: the chain is single-threaded and
        // the driver mutates it between heights.
        const std::lock_guard<std::mutex> lock(mu_);
        return Json{{"jsonrpc", "2.0"}, {"id", id}, {"result", it->second(params)}};
    } catch (const Error& e) {
        return fail(e.code, e.what());
    } catch (const std::exception& e) {
        // A method that threw something unplanned is a bug in this node, not a
        // reason to end it. The caller is told; the daemon keeps validating.
        return fail(-32603, e.what());
    }
}

}  // namespace lux::node
