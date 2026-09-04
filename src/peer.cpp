// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco

#include "lux/node/peer.hpp"

#include "lux/consensus/bls.hpp"
#include "lux/node/peer_wire.hpp"
#include "rlp.hpp"  // lux::node::rlp — sibling in src/, decode + the tiny encode half

#include <evmc/evmc.hpp>
#include <test/state/hash_utils.hpp>  // cevm::keccak256

#include <openssl/sha.h>

#include <cstring>
#include <ctime>

namespace lux::node::peer {

namespace {

using peer_wire::Tag;

Id sha256_id(std::span<const std::uint8_t> in) noexcept {
    Id out{};
    SHA256(in.data(), in.size(), out.data());
    return out;
}
Id keccak_id(std::span<const std::uint8_t> in) noexcept {
    const evmc::bytes32 h = cevm::keccak256({in.data(), in.size()});
    Id out{};
    std::memcpy(out.data(), h.bytes, 32);
    return out;
}

void put_u32_be(std::vector<std::uint8_t>& b, std::uint32_t v) {
    b.push_back(std::uint8_t(v >> 24));
    b.push_back(std::uint8_t(v >> 16));
    b.push_back(std::uint8_t(v >> 8));
    b.push_back(std::uint8_t(v));
}

// One frame's BODY (tag byte included at [0]) off the wire: the 4-byte BE
// length prefix, then exactly that many bytes. Once the length has been
// read, this side is COMMITTED to the body arriving — a timeout on the body
// itself is never "quiet" (that distinction only applies to the wait BETWEEN
// frames), so a `Quiet` on the body read is reinterpreted as `Desync` here,
// in the one place that knows which read is which.
std::vector<std::uint8_t> read_frame_body(peer_tls::Connection& conn, std::chrono::milliseconds deadline) {
    std::array<std::uint8_t, 4> len_bytes{};
    conn.read_exact(len_bytes, deadline);  // may legitimately throw Quiet — no frame started yet
    const std::uint32_t length = (std::uint32_t(len_bytes[0]) << 24) | (std::uint32_t(len_bytes[1]) << 16) |
                                 (std::uint32_t(len_bytes[2]) << 8) | std::uint32_t(len_bytes[3]);
    if (length == 0 || length > peer_wire::kMessageMax + 1) throw peer_tls::Desync{};
    std::vector<std::uint8_t> body(length);
    try {
        conn.read_exact(body, deadline);
    } catch (const peer_tls::Quiet&) {
        throw peer_tls::Desync{};  // mid-frame: silence here means desync, not quiet
    }
    return body;
}

}  // namespace

Peer Peer::connect(const std::string& host, std::uint16_t port, const staking::Identity& id,
                   std::uint32_t network_id, std::uint16_t advertise_port,
                   std::chrono::milliseconds tls_timeout) {
    auto conn = peer_tls::Connection::connect(host, port, id.cert_der(), id.ec_key(), tls_timeout);
    return Peer(std::move(conn), id, network_id, advertise_port);
}

void Peer::send_handshake() {
    peer_wire::Writer w;
    const std::uint64_t now = std::uint64_t(std::time(nullptr));
    const std::array<std::uint8_t, 4> v4{127, 0, 0, 1};  // loopback: this port is on 127.0.0.1

    w.u32(network_id_);
    w.u64(now);                                                              // myTime
    w.bytes(std::span<const std::uint8_t>(v4.data(), v4.size()));            // ip FIELD: raw v4 bytes
    w.u32(std::uint32_t(advertise_port_));
    w.u64(now);                                                              // signTime

    const auto preimage = staking::signed_ip(v4, advertise_port_, now);
    const auto ecdsa_sig =
        id_->sign_ecdsa_sha256(std::span<const std::uint8_t>(preimage.data(), preimage.size()));
    w.bytes(ecdsa_sig);                                                       // ipNodeIdSig (DER)
    w.list_bytes({});                                                        // trackedSubnets, empty

    w.present();                                                             // Client
    w.text("lux");
    w.u32(1);
    w.u32(36);
    w.u32(181);

    w.list_u32({});                                                          // supportedLps
    w.list_u32({});                                                          // objectedLps
    w.absent();                                                              // known-peers bloom filter

    const auto bls_pop = id_->pop_sign(std::span<const std::uint8_t>(preimage.data(), preimage.size()));
    w.bytes(std::span<const std::uint8_t>(bls_pop.data(), bls_pop.size()));  // ipBlsSig

    w.boolean(true);                                                        // allSubnets

    conn_.write_all(w.frame(Tag::Handshake));
}

void Peer::send_peer_list() {
    peer_wire::Writer w;
    w.u32(0);  // zero ClaimedIpPort entries — an empty PeerList is enough to count
    conn_.write_all(w.frame(Tag::PeerList));
    sent_peer_list_ = true;
}

void Peer::send_pong() {
    peer_wire::Writer w;
    w.u32(100);  // uptime pct — must not exceed 100 or luxd drops this peer
    w.u32(0);
    conn_.write_all(w.frame(Tag::Pong));
}

namespace {
void send_chits(peer_tls::Connection& conn, std::span<const std::uint8_t> chain_id_bytes,
                std::uint32_t request_id, const Id& id_value, std::uint64_t height) {
    peer_wire::Writer w;
    w.bytes(chain_id_bytes);
    w.u32(request_id);
    w.bytes(std::span<const std::uint8_t>(id_value.data(), id_value.size()));  // preferred
    w.bytes(std::span<const std::uint8_t>(id_value.data(), id_value.size()));  // preferred (again)
    w.bytes(std::span<const std::uint8_t>(id_value.data(), id_value.size()));  // accepted
    w.u64(height);
    conn.write_all(w.frame(Tag::Chits));
}
}  // namespace

void Peer::handle_push_query(std::span<const std::uint8_t> body) {
    peer_wire::Reader r(body);
    r.tag();  // PushQuery — already dispatched on
    const auto chain_id_bytes = r.bytes();
    const std::uint32_t request_id = r.u32();
    (void)r.u64();  // deadline — not enforced by this minimal responder
    const auto container = r.bytes();

    const Id outer_id = sha256_id(container);

    // A previously-tracked frontier answers THIS query's Chits — the reply
    // reports what this validator already believed before this query arrived,
    // never the query's own contents.
    if (frontier_) send_chits(conn_, chain_id_bytes, request_id, frontier_->outer_id, frontier_->height);

    // Find the inner Ethereum header: the RLP long-list item that is the LAST
    // thing in the container and consumes exactly the remaining bytes — found
    // by shape (node.rs's `inner_header()`), because the wrapping envelope's
    // own field widths are not assumed fixed here.
    std::optional<lux::node::rlp::Item> header_item;
    for (std::size_t off = 0; off < container.size(); ++off) {
        const auto candidate = std::span<const std::uint8_t>(container).subspan(off);
        auto it = lux::node::rlp::item(candidate);
        if (it && it->list && off + it->raw.size() == container.size()) {
            header_item = it;
            break;
        }
    }
    if (!header_item) return;  // nothing to vote on this round

    const Id canonical_id = keccak_id(header_item->raw);  // == the Ethereum block hash

    // Ethereum header field order: parentHash unclesHash coinbase stateRoot
    // txRoot receiptRoot bloom difficulty number ... — only parentHash (0)
    // and number (8) are needed for a Position.
    auto fields = lux::node::rlp::items(header_item->payload);
    if (!fields || fields->size() <= 8) return;

    Id parent_canonical_id{};
    const auto& parent_item = (*fields)[0];
    if (!parent_item.list && parent_item.payload.size() == 32)
        std::copy(parent_item.payload.begin(), parent_item.payload.end(), parent_canonical_id.begin());

    const auto number = lux::node::rlp::u64((*fields)[8]);
    const std::uint64_t height = number.value_or(0);

    cast_vote(outer_id, canonical_id, parent_canonical_id, height);
    frontier_ = Frontier{outer_id, height};
}

void Peer::cast_vote(const Id& outer_id, const Id& canonical_id, const Id& parent_canonical_id,
                     std::uint64_t height) {
    if (!ballot_) return;  // not told which chain/set-root to vote under yet

    lux::consensus::VotePosition pos{};
    pos.chain_id             = ballot_->chain_id;
    pos.height                = height;
    pos.round                 = 0;
    // Go's degrade applies when a VM has no separate transport envelope; here
    // there genuinely is one (the proposervm container luxd sent), but this
    // responder does not track it beyond the outer id used for the envelope
    // address, so the transport axes mirror node.rs's own field assignment:
    // canonical stands in for both.
    pos.block_id              = canonical_id;
    pos.parent_id              = parent_canonical_id;
    pos.canonical_id           = canonical_id;
    pos.parent_canonical_id    = parent_canonical_id;
    pos.execution_state_root  = Id{};  // Transport binding — luxd signs Empty here, not a computed root
    pos.payload_root          = Id{};
    pos.validator_set_root    = ballot_->validator_set_root;

    const auto message = lux::consensus::canonical_vote_message(pos, /*accept=*/true);

    std::array<std::uint8_t, 96> sig{};
    if (lux::consensus::bls::sign(id_->bls_sk().data(), message.data(), message.size(), sig.data()) != 0)
        return;

    // quorum::vote payload: nodeID(20) || sigLen(u32 BE) || sig — Go's
    // chains/quorum.go `encodeSignedVote`.
    std::vector<std::uint8_t> payload;
    payload.insert(payload.end(), id_->node_id().begin(), id_->node_id().end());
    put_u32_be(payload, std::uint32_t(sig.size()));
    payload.insert(payload.end(), sig.begin(), sig.end());

    // Envelope: "LXQ\x01" || kind(1=VOTE) || OUTER container id || payload.
    // The OUTER id, not the canonical one — this is the key luxd's
    // `pendingBlocks` looks the vote up by; addressed to the inner id it is
    // "buffered, never counted".
    std::vector<std::uint8_t> envelope{'L', 'X', 'Q', 0x01, 0x01};
    envelope.insert(envelope.end(), outer_id.begin(), outer_id.end());
    envelope.insert(envelope.end(), payload.begin(), payload.end());

    peer_wire::Writer w;
    w.bytes(std::span<const std::uint8_t>(ballot_->chain_id.data(), ballot_->chain_id.size()));
    w.bytes(envelope);
    conn_.write_all(w.frame(Tag::Gossip));
    ++votes_cast_;
}

void Peer::track(const Ballot& ballot, const Frontier& initial) {
    ballot_   = ballot;
    frontier_ = initial;
}

void Peer::read_frame_dispatch(std::chrono::milliseconds deadline) {
    const auto body = read_frame_body(conn_, deadline);
    peer_wire::Reader r(body);
    const auto tag = r.tag();
    switch (tag) {
        case Tag::Ping:
            send_pong();
            break;
        case Tag::Pong:
            break;
        case Tag::Handshake:
            // Reaching here already proves the TLS layer and this side's OWN
            // outbound Handshake were accepted (luxd would simply have closed
            // the socket otherwise). Answering with our PeerList is what
            // flips luxd's OWN `finishedHandshake` for this link.
            if (!sent_peer_list_) send_peer_list();
            break;
        case Tag::GetPeerList:
            send_peer_list();
            break;
        case Tag::PeerList:
            accepted_ = true;  // this flips OUR finishedHandshake — not the Handshake exchange itself
            break;
        case Tag::PushQuery:
            handle_push_query(body);
            break;
        default:
            break;  // read and drop — outside this responder's surface for now
    }
}

void Peer::join(std::chrono::milliseconds deadline) {
    send_handshake();
    const auto until = std::chrono::steady_clock::now() + deadline;
    while (!accepted_) {
        const auto now = std::chrono::steady_clock::now();
        if (now >= until) throw std::runtime_error("peer: join timed out waiting for PeerList");
        read_frame_dispatch(std::chrono::duration_cast<std::chrono::milliseconds>(until - now));
    }
}

void Peer::step(std::chrono::milliseconds deadline) { read_frame_dispatch(deadline); }

}  // namespace lux::node::peer
