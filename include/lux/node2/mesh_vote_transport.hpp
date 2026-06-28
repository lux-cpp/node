// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// mesh_vote_transport.hpp — consensus2's VoteTransport realized over a FULL MESH
// of real TCP sockets, framed by the canonical ZAP wire codec (zap-cpp-core).
//
// The existing zap::ZapVoteTransport is single-peer (one fd) and holds Node*
// directly. node2 needs an N-peer mesh, and takes the chance to decomplect: this
// transport carries a vote SINK (std::function), not a Node — so it knows only
// sockets + ZAP framing + the vote codec. It has no Node type, no gate, no
// finality rule. The host supplies a sink wired to Node::onVote.
//
//   broadcast(v): this node's OWN vote. node.cpp relies on the transport echoing
//     a node's own vote back so its gate counts it (the gate dedups by voter key),
//     so we self-deliver through the sink, then write the ZAP frame to EVERY peer.
//   pump(): drain every peer's socket (non-blocking) through its FrameReader,
//     decode each complete vote frame, deliver via the sink. Returns the number
//     of votes delivered (progress signal for the driver / observability).
//
// Threading: in node2 each MeshVoteTransport is owned and driven by exactly one
// thread (its host), so there is no shared-mutable consensus state. The per-peer
// write mutex exists only to satisfy lux::zap::write_frame_locked's signature; it
// is uncontended here.

#pragma once

#include "lux/consensus2/node.hpp"            // VoteTransport, SignedVote
#include "lux/consensus2/zap/vote_codec.hpp"  // encode_vote/decode_vote, kVoteMsgType
#include "lux/node2/frame_reader.hpp"
#include "lux/zap/wire.hpp"                    // write_frame_locked, strip_flags

#include <cstddef>
#include <functional>
#include <memory>
#include <mutex>
#include <utility>
#include <vector>

#include <unistd.h>  // close

namespace lux::node2 {

// Where decoded inbound (and self-echoed) votes go. Wiring this to Node::onVote
// instead of holding a Node* is what keeps the transport free of consensus.
using VoteSink = std::function<void(const lux::consensus2::SignedVote&)>;

class MeshVoteTransport : public lux::consensus2::VoteTransport {
public:
    explicit MeshVoteTransport(VoteSink sink) : sink_(std::move(sink)) {}

    // The transport owns its peer fds: close them when it dies.
    ~MeshVoteTransport() override {
        for (auto& p : peers_)
            if (p->fd >= 0) ::close(p->fd);
    }

    MeshVoteTransport(const MeshVoteTransport&) = delete;
    MeshVoteTransport& operator=(const MeshVoteTransport&) = delete;

    // Register one connected peer stream socket. Called once per peer during mesh
    // setup, by the single setup thread — no locking needed.
    void add_peer(int fd) { peers_.push_back(std::make_unique<Peer>(fd)); }

    std::size_t peer_count() const noexcept { return peers_.size(); }

    // VoteTransport: disseminate this node's own ACCEPT vote.
    void broadcast(const lux::consensus2::SignedVote& v) override {
        sink_(v);  // self-echo: the originator's own vote must reach its own gate
        const std::vector<std::uint8_t> payload = lux::consensus2::zap::encode_vote(v);
        for (auto& p : peers_)
            lux::zap::write_frame_locked(p->fd, p->wmu,
                                         lux::consensus2::zap::kVoteMsgType,
                                         payload.data(), payload.size());
    }

    // Drain every peer; deliver each complete, structurally-valid vote frame.
    // Returns the number of votes delivered this call. Never blocks.
    std::size_t pump() {
        std::size_t delivered = 0;
        for (auto& p : peers_) {
            p->rx.drain_fd(p->fd);  // non-blocking; WouldBlock/Closed need no action here
            while (auto f = p->rx.next()) {
                if (lux::zap::strip_flags(f->msg_type) != lux::consensus2::zap::kVoteMsgType)
                    continue;  // not a vote frame — ignore
                if (auto vote = lux::consensus2::zap::decode_vote(f->payload)) {
                    sink_(*vote);  // structurally valid → hand to the gate (which verifies + dedups)
                    ++delivered;
                }
                // a structurally-invalid payload is silently dropped: a peer cannot
                // inject a malformed vote (decode_vote enforces exact field widths).
            }
        }
        return delivered;
    }

private:
    struct Peer {
        explicit Peer(int f) : fd(f) {}
        int fd;
        std::mutex wmu;  // serializes write_frame_locked on this fd (uncontended here)
        FrameReader rx;  // this peer's reassembly buffer
    };

    VoteSink sink_;
    std::vector<std::unique_ptr<Peer>> peers_;  // unique_ptr: Peer holds a non-movable mutex
};

}  // namespace lux::node2
