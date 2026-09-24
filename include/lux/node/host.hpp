// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// host.hpp — a validator's place on the mesh: a listener, the links its peers
// proved, and the frames on them. lux-rs/node src/host.rs.
//
// A COMPOSITION of two parts, each usable without it: Mesh forms the links
// (lux/node/mesh.hpp) and MeshVoteTransport frames what rides them. It decides
// nothing — the engine does (engine.hpp) — so it holds no consensus state at all.
//
// Identity (seat + greeting) is fixed at construction; the peer ADDRESSES are
// supplied later, because in a real cluster a listen port may be ephemeral and
// is only known after bind. That split keeps "who am I" orthogonal from "who do
// I dial".
//
// THE MESH IS NOT THE QUORUM. connect_mesh returns how many peers it reached
// within one deadline; it never demands all of them. The finality rule already
// says how many votes are enough, and stating it a second time as "every peer
// must connect" would only be a way to disagree with it. And it is not formed
// once: sweep() is run on the driver's loop, so a validator that restarts is
// met again.
//
// Concurrency: one Host is driven by ONE thread. The acceptor inside Mesh runs
// on its own and shares nothing with the driver but a locked queue of proven
// links.

#pragma once

#include "lux/node/mesh.hpp"
#include "lux/node/mesh_vote_transport.hpp"

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace lux::node {

struct HostConfig {
    std::uint32_t index = 0;             // this node's own seat
    std::string   bind  = "127.0.0.1";   // the address the mesh listens on
    std::uint16_t port  = 0;             // requested listen port (0 = OS-assigned)
    // HOW THE MESH GREETS. The identity this node proves on every link, the
    // chain it proves it on, and how a proven name becomes a seat. There is no
    // default: a node that could not name its peers would be back to trusting
    // an integer.
    Link link;
};

class Host {
public:
    explicit Host(HostConfig cfg)
        : cfg_(std::move(cfg)),
          // The Party-vote path of the transport is not this host's protocol: a
          // statement rides msg type 62 (statement.hpp), so a frame of the old
          // vote type is dropped.
          tx_(std::make_unique<MeshVoteTransport>([](const lux::consensus::SignedVote&) {})),
          mesh_(cfg_.index, *tx_, cfg_.link) {}

    Host(const Host&)            = delete;
    Host& operator=(const Host&) = delete;

    std::uint16_t listen_bind() { return mesh_.listen_bind(cfg_.bind, cfg_.port); }

    std::size_t connect_mesh(const std::map<std::uint32_t, PeerAddr>& peers, int deadline_ms = 10000) {
        return mesh_.connect(peers, deadline_ms);
    }
    void sweep(const std::map<std::uint32_t, PeerAddr>& peers) { mesh_.sweep(peers); }

    // Drain inbound frames from every peer into their handlers. Never blocks.
    std::size_t pump() { return tx_->pump(); }

    void on(std::uint8_t type, Sink h) { tx_->on(type, std::move(h)); }
    void gossip(std::uint8_t type, const std::vector<std::uint8_t>& payload) { tx_->gossip(type, payload); }
    bool send(std::uint32_t seat, std::uint8_t type, const std::vector<std::uint8_t>& payload) {
        return tx_->send(seat, type, payload);
    }

    std::uint32_t              index() const noexcept { return cfg_.index; }
    std::uint16_t              port() const noexcept { return mesh_.port(); }
    std::size_t                peer_count() const noexcept { return tx_->peer_count(); }
    std::vector<std::uint32_t> members() const { return tx_->members(); }
    std::size_t                joined() const noexcept { return tx_->joined(); }

private:
    HostConfig cfg_;
    // Declaration order is the construction order, and it is load-bearing: the
    // transport must outlive the Mesh that hands it sockets.
    std::unique_ptr<MeshVoteTransport> tx_;
    Mesh                               mesh_;
};

}  // namespace lux::node
