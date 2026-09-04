// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco

#include "lux/node/peer_tls.hpp"

#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>

namespace lux::node::peer_tls {

namespace {

int tcp_connect(const std::string& host, std::uint16_t port) {
    addrinfo hints{};
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    const std::string port_s = std::to_string(port);
    if (getaddrinfo(host.c_str(), port_s.c_str(), &hints, &res) != 0 || res == nullptr)
        throw std::runtime_error("peer_tls: cannot resolve " + host);
    struct Guard { addrinfo* p; ~Guard() { freeaddrinfo(p); } } guard{res};

    int fd = -1;
    for (addrinfo* rp = res; rp != nullptr; rp = rp->ai_next) {
        fd = ::socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;
        if (::connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;
        ::close(fd);
        fd = -1;
    }
    if (fd < 0) throw std::runtime_error("peer_tls: connect failed to " + host + ":" + port_s);

    int one = 1;
    ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    return fd;
}

}  // namespace

Connection::Connection(Connection&& o) noexcept : ssl_(o.ssl_), ctx_(o.ctx_), fd_(o.fd_) {
    o.ssl_ = nullptr; o.ctx_ = nullptr; o.fd_ = -1;
}
Connection& Connection::operator=(Connection&& o) noexcept {
    if (this != &o) {
        shutdown();
        ssl_ = o.ssl_; ctx_ = o.ctx_; fd_ = o.fd_;
        o.ssl_ = nullptr; o.ctx_ = nullptr; o.fd_ = -1;
    }
    return *this;
}
Connection::~Connection() { shutdown(); }

void Connection::shutdown() noexcept {
    if (ssl_) { SSL_shutdown(reinterpret_cast<SSL*>(ssl_)); SSL_free(reinterpret_cast<SSL*>(ssl_)); ssl_ = nullptr; }
    if (ctx_) { SSL_CTX_free(reinterpret_cast<SSL_CTX*>(ctx_)); ctx_ = nullptr; }
    if (fd_ >= 0) { ::close(fd_); fd_ = -1; }
}

Connection Connection::connect(const std::string& host, std::uint16_t port,
                               std::span<const std::uint8_t> cert_der, void* ec_key,
                               std::chrono::milliseconds connect_timeout) {
    (void)connect_timeout;  // loopback connect is effectively instant; see peer_tls.hpp
    Connection c;
    c.fd_ = tcp_connect(host, port);

    SSL_CTX* ctx = SSL_CTX_new(TLS_method());
    if (!ctx) throw std::runtime_error("peer_tls: SSL_CTX_new failed");
    c.ctx_ = ctx;

    // TLS 1.3, and only TLS 1.3 — luxd's own MinVersion==MaxVersion.
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

    // The single group luxd offers. If this list cannot be satisfied the
    // handshake fails at ClientHello construction, which is the point: no
    // group negotiation, no fallback, no classical-only session possible.
    if (!SSL_CTX_set1_groups_list(ctx, "X25519MLKEM768"))
        throw std::runtime_error("peer_tls: this AWS-LC build does not support X25519MLKEM768");

    // luxd's own InsecureSkipVerify: accept whatever certificate the peer
    // presents. Identity is proven one layer up, by the p2p handshake's
    // signed IP + BLS proof of possession — a CA chain would assert a
    // property luxd itself never checks.
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);

    // This side's client certificate: the P-256 staking identity, presented
    // so luxd's RequireAnyClientCert is satisfied.
    if (!SSL_CTX_use_certificate_ASN1(ctx, cert_der.size(), cert_der.data()))
        throw std::runtime_error("peer_tls: SSL_CTX_use_certificate_ASN1 failed");
    EVP_PKEY* pkey = EVP_PKEY_new();
    if (!pkey) throw std::runtime_error("peer_tls: EVP_PKEY_new failed");
    struct PGuard { EVP_PKEY* p; ~PGuard() { EVP_PKEY_free(p); } } pguard{pkey};
    if (!EVP_PKEY_set1_EC_KEY(pkey, reinterpret_cast<EC_KEY*>(ec_key)))
        throw std::runtime_error("peer_tls: EVP_PKEY_set1_EC_KEY failed");
    if (!SSL_CTX_use_PrivateKey(ctx, pkey))
        throw std::runtime_error("peer_tls: SSL_CTX_use_PrivateKey failed");

    SSL* ssl = SSL_new(ctx);
    if (!ssl) throw std::runtime_error("peer_tls: SSL_new failed");
    c.ssl_ = ssl;
    SSL_set_fd(ssl, c.fd_);
    SSL_set_connect_state(ssl);

    const int rc = SSL_connect(ssl);
    if (rc != 1) {
        const int err = SSL_get_error(ssl, rc);
        char buf[256];
        ERR_error_string_n(ERR_get_error(), buf, sizeof buf);
        throw std::runtime_error("peer_tls: TLS handshake failed (SSL_get_error=" +
                                 std::to_string(err) + ", " + buf + ")");
    }
    return c;
}

void Connection::write_all(std::span<const std::uint8_t> data) {
    auto* ssl = reinterpret_cast<SSL*>(ssl_);
    std::size_t off = 0;
    while (off < data.size()) {
        const int n = SSL_write(ssl, data.data() + off, int(data.size() - off));
        if (n <= 0) {
            const int err = SSL_get_error(ssl, n);
            throw std::runtime_error("peer_tls: SSL_write failed (SSL_get_error=" + std::to_string(err) + ")");
        }
        off += std::size_t(n);
    }
}

void Connection::read_exact(std::span<std::uint8_t> out, std::chrono::milliseconds deadline) {
    auto* ssl = reinterpret_cast<SSL*>(ssl_);
    const auto until = std::chrono::steady_clock::now() + deadline;
    std::size_t got = 0;
    while (got < out.size()) {
        const auto now = std::chrono::steady_clock::now();
        if (now >= until) {
            if (got == 0) throw Quiet{};
            throw Desync{};
        }
        const auto left_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(until - now).count();
        pollfd pfd{fd_, POLLIN, 0};
        const int pr = ::poll(&pfd, 1, int(left_ms));
        if (pr < 0) throw Desync{};
        if (pr == 0) { if (got == 0) throw Quiet{}; throw Desync{}; }

        const int n = SSL_read(ssl, out.data() + got, int(out.size() - got));
        if (n > 0) { got += std::size_t(n); continue; }

        const int err = SSL_get_error(ssl, n);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) continue;  // spurious wake, retry
        // Zero-return (clean TLS close) or a hard syscall/protocol error: the
        // link is gone. A close after some bytes already landed is exactly
        // the desync case; a close with nothing read yet is still NOT quiet
        // (quiet means "healthy but silent", not "gone") so it is Desync too.
        throw Desync{};
    }
}

}  // namespace lux::node::peer_tls
