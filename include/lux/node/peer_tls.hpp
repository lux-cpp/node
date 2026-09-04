// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// peer_tls.hpp — the ONE gate to a live luxd: `network/peer/tls_config.go`
// pins `MinVersion == MaxVersion == VersionTLS13` and, decisively,
// `CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}` — a single-element
// list, so a client that cannot offer the hybrid X25519+ML-KEM-768 group
// never completes a session at all. System OpenSSL on this host (3.0.13) has
// no such group; AWS-LC does (`SSL_GROUP_X25519_MLKEM768 = 0x11EC`, the same
// wire codepoint Go's `crypto/tls` assigns) — the library node.rs reaches
// through `aws-lc-rs` for the identical reason, used here through its C
// `libssl` API instead of a Rust binding.
//
// Mutual TLS, but with nothing checked beyond "a certificate was presented":
// Go's side sets `RequireAnyClientCert` + `InsecureSkipVerify: true` — the
// peer is identified by the key inside its certificate (via the p2p
// handshake's signed IP and BLS PoP), never by a CA, so verifying a chain
// here would check a property luxd itself does not require and does not
// have.

#pragma once

#include <chrono>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <string>

namespace lux::node::peer_tls {

// A `read_exact` deadline that fired having read NOTHING new this call — the
// link is silent, not broken. luxd pings roughly every 22s, so quiet is the
// normal state between frames; the caller should loop and try again.
struct Quiet : std::runtime_error {
    Quiet() : std::runtime_error("peer_tls: quiet link") {}
};
// A deadline that fired AFTER partial bytes were already placed into the
// caller's buffer this call — the stream has lost frame sync (or the peer
// hung up mid-write) and cannot be trusted; the connection must be dropped,
// never resumed.
struct Desync : std::runtime_error {
    Desync() : std::runtime_error("peer_tls: link desynced or closed") {}
};

class Connection {
public:
    Connection(const Connection&)            = delete;
    Connection& operator=(const Connection&) = delete;
    Connection(Connection&&) noexcept;
    Connection& operator=(Connection&&) noexcept;
    ~Connection();

    // TCP-connect to host:port and complete a TLS1.3 handshake, presenting
    // `cert_der` + the EC-P256 key behind it as this side's client
    // certificate. `ec_key` is an `EC_KEY*` (kept `void*` so this header does
    // not require AWS-LC's headers to be on every includer's path).
    static Connection connect(const std::string& host, std::uint16_t port,
                              std::span<const std::uint8_t> cert_der, void* ec_key,
                              std::chrono::milliseconds connect_timeout);

    // Write all of `data` over the session, blocking. Throws on any failure —
    // a partial write on this side is never silently retried past a hard
    // socket error, because a half-sent frame is exactly the desync a peer on
    // the other end cannot tell apart from one it sent whole.
    void write_all(std::span<const std::uint8_t> data);

    // Fill `out` with exactly `out.size()` bytes, or throw `Quiet`/`Desync` —
    // see those types above. Blocks in bounded polls against `deadline`.
    void read_exact(std::span<std::uint8_t> out, std::chrono::milliseconds deadline);

    void shutdown() noexcept;

private:
    Connection() = default;
    void* ssl_ = nullptr;  // SSL*
    void* ctx_ = nullptr;  // SSL_CTX*
    int   fd_  = -1;
};

}  // namespace lux::node::peer_tls
