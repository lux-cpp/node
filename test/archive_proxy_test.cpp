// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// archive_proxy_test.cpp — what a client learns when this node relays.
//
// A frontier node keeps C and reaches P and X through an archive. On that path
// it is a PROXY: it did not answer the question, it carried one, and carrying an
// answer means carrying what the answer was. The status is the first thing every
// HTTP client reads — `resp.ok`, `raise_for_status`, `if err != nil` — so a node
// that relays the body and mints its own 200 tells the client the call succeeded
// and hands it an error document to parse as a result. The client then reports a
// missing chain as a malformed reply, which is the wrong bug on the wrong host.
//
// So this is tested over a REAL socket against a REAL archive, because the
// contract is not what proxy_to_archive returns — it is what the client sees on
// the wire.

#include "lux/node/rpc.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <cstdio>
#include <string>
#include <thread>

using namespace lux::node;

namespace {

int  g_fail = 0;
int  g_pass = 0;
void check(bool ok, const std::string& what) {
    std::printf("  %s  %s\n", ok ? "ok  " : "FAIL", what.c_str());
    if (ok) ++g_pass; else ++g_fail;
}

struct Reply {
    int         status = 0;
    std::string body;
};

Reply call(std::uint16_t port, const std::string& path, const std::string& body) {
    Reply out;
    const int sock = ::socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return out;
    timeval tv{5, 0};
    ::setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ::setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    sockaddr_in a{};
    a.sin_family      = AF_INET;
    a.sin_port        = htons(port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::connect(sock, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0) {
        ::close(sock);
        return out;
    }

    std::string req = "POST " + path + " HTTP/1.1\r\n";
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

// A stand-in archive: it answers every request with one prepared response, so a
// test can state exactly what the upstream said. `chunked` writes the body the
// other way an archive may write it, because the status has to survive both.
class Archive {
public:
    Archive(int status, const char* reason, std::string body, bool chunked)
        : status_(status), reason_(reason), body_(std::move(body)), chunked_(chunked) {
        fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
        const int one = 1;
        ::setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        sockaddr_in a{};
        a.sin_family      = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        a.sin_port        = 0;
        ::bind(fd_, reinterpret_cast<sockaddr*>(&a), sizeof(a));
        socklen_t len = sizeof(a);
        ::getsockname(fd_, reinterpret_cast<sockaddr*>(&a), &len);
        port_ = ntohs(a.sin_port);
        ::listen(fd_, 8);
        thread_ = std::thread([this] { serve(); });
    }

    ~Archive() {
        running_ = false;
        ::shutdown(fd_, SHUT_RDWR);
        ::close(fd_);
        if (thread_.joinable()) thread_.join();
    }

    std::uint16_t port() const { return port_; }
    std::string   url() const { return "127.0.0.1:" + std::to_string(port_); }
    int           served() const { return served_.load(); }

private:
    void serve() {
        while (running_) {
            const int c = ::accept(fd_, nullptr, nullptr);
            if (c < 0) return;
            // Read the request head; the node always sends Connection: close.
            char        buf[4096];
            std::string in;
            while (in.find("\r\n\r\n") == std::string::npos) {
                const ssize_t n = ::recv(c, buf, sizeof(buf), 0);
                if (n <= 0) break;
                in.append(buf, static_cast<std::size_t>(n));
            }
            std::string out = "HTTP/1.1 " + std::to_string(status_) + " " + reason_ + "\r\n";
            out += "Content-Type: application/json\r\n";
            if (chunked_) {
                out += "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n";
                char hdr[32];
                std::snprintf(hdr, sizeof(hdr), "%zx\r\n", body_.size());
                out += hdr;
                out += body_ + "\r\n0\r\n\r\n";
            } else {
                out += "Content-Length: " + std::to_string(body_.size()) + "\r\n";
                out += "Connection: close\r\n\r\n" + body_;
            }
            for (std::size_t off = 0; off < out.size();) {
                const ssize_t n = ::send(c, out.data() + off, out.size() - off, 0);
                if (n <= 0) break;
                off += static_cast<std::size_t>(n);
            }
            ::close(c);
            ++served_;
        }
    }

    int              status_;
    const char*      reason_;
    std::string      body_;
    bool             chunked_;
    int              fd_ = -1;
    std::uint16_t    port_ = 0;
    std::atomic<int> served_{0};
    std::atomic<bool> running_{true};
    std::thread      thread_;
};

const char* kCall = R"({"jsonrpc":"2.0","id":1,"method":"platform.getHeight","params":[]})";

// A node that keeps C and reaches X through `archive`.
struct Frontier {
    Rpc rpc{0};
    explicit Frontier(const std::string& archive) {
        rpc.method("C", "eth_chainId", [](const Rpc::Json&) { return std::string("0x7a69"); });
        rpc.set_archive_rpc(archive);
        rpc.start();
    }
    std::uint16_t port() { return rpc.port(); }
};

}  // namespace

int main() {
    std::printf("archive_proxy_test — the upstream's status is the answer\n");

    {
        // THE BUG. The archive does not have the chain either, and says so with
        // a 404. Relayed as a 200 the client reads "success" and then fails to
        // find a result in a body that is an error — it blames the reply's shape
        // for what is really a missing chain.
        const std::string said =
            R"({"jsonrpc":"2.0","id":null,"error":{"code":-32601,"message":"no such chain"}})";
        Archive  archive(404, "Not Found", said, false);
        Frontier node(archive.url());
        const Reply r = call(node.port(), "/v1/chain/X", kCall);
        check(archive.served() == 1, "the call reached the archive");
        check(r.status == 404, "a 404 from the archive arrives as a 404");
        check(r.body == said, "…carrying the archive's own body, unaltered");
    }

    {
        // The ordinary case must be untouched: a real answer is still a 200.
        const std::string said = R"({"jsonrpc":"2.0","id":1,"result":"0x2a"})";
        Archive  archive(200, "OK", said, false);
        Frontier node(archive.url());
        const Reply r = call(node.port(), "/v1/chain/X", kCall);
        check(r.status == 200, "a 200 from the archive is still a 200");
        check(r.body == said, "…and the result is relayed unaltered");
    }

    {
        // An archive that is up but cannot answer right now. 503 is the honest
        // relay: a client that retries on 503 and gives up on 404 must be told
        // which of the two happened.
        Archive  archive(503, "Service Unavailable", R"({"error":"catching up"})", false);
        Frontier node(archive.url());
        const Reply r = call(node.port(), "/v1/chain/X", kCall);
        check(r.status == 503, "a 503 from the archive arrives as a 503");
    }

    {
        // The status must survive the other framing too. The chunked branch
        // rebuilds the body, and a status carried in a variable the body-rebuild
        // path forgot would be lost exactly here.
        const std::string said = R"({"jsonrpc":"2.0","id":null,"error":{"code":-32601}})";
        Archive  archive(404, "Not Found", said, true);
        Frontier node(archive.url());
        const Reply r = call(node.port(), "/v1/chain/X", kCall);
        check(r.status == 404, "a chunked 404 is still a 404");
        check(r.body == said, "…and its body is still de-chunked");
    }

    {
        // No archive listening at all: nothing was relayed, so there is no
        // upstream status to carry. This node answers for itself — and says so
        // as itself, which is the case the empty/answered distinction exists for.
        Frontier node("127.0.0.1:1");
        const Reply r = call(node.port(), "/v1/chain/X", kCall);
        check(r.status == 200, "an unreachable archive is this node's own answer");
        check(r.body.find("--archive-rpc") != std::string::npos,
              "…and it says what is missing");
    }

    {
        // A chain nobody publishes is still this node's own 404, unchanged: it
        // was never proxied, so there is nothing to relay.
        Archive  archive(200, "OK", "{}", false);
        Frontier node(archive.url());
        const Reply r = call(node.port(), "/v1/chain/nope", kCall);
        check(r.status == 404, "an unknown chain is this node's own 404");
        check(archive.served() == 0, "…and the archive was never asked");
    }

    std::printf("\narchive_proxy: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
