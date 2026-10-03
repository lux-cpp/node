// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// mesh.hpp — forming the mesh: bind a listener, reach the configured peers, and
// hand each connected socket to a transport.
//
// This is the SOCKET half of a node, and it is only that. It knows who it is
// (an index), where to listen, whom to dial, and where to put an fd once the
// link exists. It has no Node, no gate, no vote, no finality rule — the same
// line MeshVoteTransport already draws between framing and consensus, drawn
// once more between connecting and framing.
//
// Drawing it here is what lets one mesh serve two drivers: Node2Host, which
// runs a bare consensus::Party, and a chain built on lux-cpp/sdk, which runs its
// own validator over the same wire. Neither has to reimplement the dance, and
// neither can drift from the other about who dials whom.
//
// THE MESH IS NOT THE QUORUM. connect() returns how many peers it reached
// within one deadline; it never demands all of them. The finality rule already
// says how many votes are enough, and stating it a second time as "every peer
// must connect" would only be a way to disagree with it — one absent validator
// would take down a cluster the ⅔ rule calls healthy. The caller reads the
// returned count against the rule it already has.
//
// Concurrency: one Mesh is driven by ONE thread. It holds no consensus state,
// so there is nothing here to lock.

#pragma once

#include "lux/node/mesh_vote_transport.hpp"
#include "lux/node/pq_handshake.hpp"

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace lux::node {

struct PeerAddr {
    std::string   host;
    std::uint16_t port;
};

// HOW A MESH GREETS, and what a greeting is worth.
//
// It used to be four plaintext bytes: an index the dialer CLAIMED, checked only
// against the slots the acceptor happened to be waiting on. Anyone who could
// reach the port could claim a seat, and the comment here said so — safety was
// argued from the vote gate downstream, never from the link.
//
// Now the link is the validator handshake (LP-10602): both ends sign a running
// transcript with their ML-DSA-65 identity, and the seat is where the committee
// says that identity's name sits (LP-10603). A stranger cannot take a seat,
// because it cannot sign for the name the seat belongs to — and there is one
// greeting on this wire rather than two.
struct Link {
    // The identity this node proves. Held by value: a mesh outlives whatever
    // read the keys off disk.
    pq::Identity                 me;
    // The chain both the handshake and the committee derive names under. The
    // same 32 bytes, or the name proved is not the name seated.
    std::array<std::uint8_t, 32> chain{};
    // Who a proven name is, in seats. Empty answer: not a validator here, and
    // the link is dropped.
    std::function<std::optional<std::uint32_t>(const std::array<std::uint8_t, 20>&)> seat;
};

// Every blocking operation on a linked peer's socket is bounded by this window,
// so no single peer can hold the node: a peer that stops reading makes its own
// writer fail (and the peer be evicted) rather than hang.
inline constexpr int kPeerIoTimeoutMs = 2000;

// The WHOLE greeting, in either direction, is bounded by this — not each read.
// A stranger that trickles a byte every second defeats a per-read timeout
// forever; against one deadline it costs this much and no more
// (lux-rs/node host.rs HANDSHAKE_TIMEOUT).
inline constexpr int kHandshakeMs = 4000;

// Inbound greetings run at once, each on its own thread and never on the
// accepting one, at most this many in all and this many from one source
// address: strangers that connect and say nothing hold a slot for kHandshakeMs
// and never the door, and one address cannot fill every slot.
inline constexpr std::size_t kHandshakesMax       = 16;
inline constexpr std::size_t kHandshakesPerSource = 4;

// How long ONE dial attempt may take to connect. A dial that is refused fails
// at once, but a dial that is dropped — a firewall, a host that is gone —
// reports nothing and runs to its timeout. A seat is dialed again no sooner
// than this after its last attempt.
inline constexpr int kDialAttemptMs = 250;

class Mesh {
public:
    // `index` is this node's own seat — it decides dial direction. `how` is the
    // greeting, and it is what turns a claimed seat into a proven one; it
    // outlives this Mesh. `tx` receives every connected socket and outlives it
    // too.
    Mesh(std::uint32_t index, MeshVoteTransport& tx, const Link& how) noexcept
        : index_(index), tx_(tx), link_(how) {}
    ~Mesh();

    Mesh(const Mesh&) = delete;
    Mesh& operator=(const Mesh&) = delete;

    // Bind host:port (an IPv4 literal; "0.0.0.0" for every interface), listen,
    // and start ACCEPTING: one thread takes connections and hands each to a
    // greeting of its own (kHandshakesMax in all, kHandshakesPerSource from one
    // address, each bounded by kHandshakeMs), which queues the seat it proves
    // for the driver. Returns the port actually bound (which resolves a
    // requested 0). Throws std::runtime_error at the boundary on failure, a host
    // that is not an IPv4 address among them. Must precede connect().
    std::uint16_t listen_bind(const std::string& host, std::uint16_t port);

    // Reach as many of `peers` as possible within ONE deadline. The lower-
    // indexed end of each pair dials and the higher-indexed end accepts, so a
    // pair has exactly one connection. Returns the number of peers connected
    // (== the transport's peer_count()).
    std::size_t connect(const std::map<std::uint32_t, PeerAddr>& peers, int deadline_ms = 10000);

    // Meet whoever is missing, without waiting on anyone: hand the transport
    // every link a greeting has proven, and start a dial — on its own thread —
    // to each higher seat that holds no link and has none in flight. connect()
    // is the opening rendezvous and it ENDS; without this a validator that
    // restarted dials into a backlog nobody reads while its peers hold a dead
    // socket (lux-rs/node host.rs sweep). The caller's thread never waits on a
    // peer here: not on a dial, not on a greeting, not on a name lookup.
    void sweep(const std::map<std::uint32_t, PeerAddr>& peers);

    std::uint32_t index() const noexcept { return index_; }
    std::uint16_t port()  const noexcept { return bound_port_; }

    // Greetings in flight, inbound and outbound (observability and tests).
    std::size_t greeting() const;

private:
    struct Worker {
        std::thread                        thread;
        std::shared_ptr<std::atomic<bool>> done;
    };

    // The accepting thread's loop.
    void accepting();
    // One greeting on its own thread: as the responder for an inbound `fd`
    // from `source`, or — `expect` set — as the initiator dialing `to`.
    void greet_in(int fd, std::string source);
    void greet_out(std::uint32_t expect, PeerAddr to);
    // Run `work` on a thread of its own, reaped once it is done. Holds mu_.
    void spawn(std::function<void()> work);
    // Join the greetings that are done. Holds mu_.
    void reap();
    // Hand the transport what the greetings proved. The driver's thread only.
    void take_arrivals();

    std::uint32_t      index_;
    MeshVoteTransport& tx_;
    const Link&        link_;
    int                listen_fd_  = -1;
    std::uint16_t      bound_port_ = 0;

    mutable std::mutex                                   mu_;
    std::vector<std::pair<int, std::uint32_t>>           arrived_;  // (fd, proven seat)
    std::vector<Worker>                                  workers_;
    std::set<int>                                        inflight_;  // fds mid-greeting
    std::map<std::string, std::size_t>                   sources_;   // inbound greetings by address
    std::size_t                                          inbound_ = 0;
    std::map<std::uint32_t, std::chrono::steady_clock::time_point> dialed_;  // last attempt
    std::set<std::uint32_t>                              dialing_;
    std::atomic<bool>                                    stopping_{false};
    std::thread                                          acceptor_;
};

}  // namespace lux::node
