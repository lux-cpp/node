// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// mesh_transport_test.cpp — what one hostile or dead socket can do to this node.
//
// The transport is the node's whole attack surface before any signature is
// checked: a peer that has done nothing but connect can already make us read,
// buffer and write. Each case here is a way that used to cost us something and
// now costs the peer its seat:
//
//   [1] a frame length larger than this link's frames  → rejected, peer dropped,
//       and — the part that matters — the buffer does NOT grow while the peer
//       keeps sending. A 4 GiB length header followed by a flood used to be an
//       unbounded allocation on the receiving node.
//   [2] a length under the ZAP ceiling but over the vote cap is the same lie in
//       a smaller hat, and is treated the same way.
//   [3] a peer that votes and then hangs up still counts: the frames already
//       reassembled are delivered BEFORE the corpse is evicted.
//   [4] a socket that will not take a write is gone: broadcast drops it instead
//       of writing to it again every round.
//   [5] eviction is per-peer — the rest of the mesh is untouched.

#include "lux/consensus2/zap/vote_codec.hpp"
#include "lux/node2/mesh_vote_transport.hpp"
#include "lux/zap/wire.hpp"

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include <sys/socket.h>
#include <unistd.h>

using namespace lux::node2;
using namespace lux::consensus2;

namespace {

int g_fail = 0;
void check(bool ok, const std::string& what) {
    if (!ok) { std::printf("    ASSERT FAILED: %s\n", what.c_str()); ++g_fail; }
}

// A connected pair: `ours` goes to the transport, `theirs` is the peer we play.
struct Link {
    int ours = -1, theirs = -1;
    Link() {
        int fds[2];
        if (::socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) { std::puts("socketpair"); std::exit(2); }
        ours = fds[0];
        theirs = fds[1];
    }
    void close_theirs() { if (theirs >= 0) { ::close(theirs); theirs = -1; } }
    ~Link() { close_theirs(); }
};

// Raw bytes onto the peer end. Returns what the kernel took (a full socket
// buffer is normal when we are deliberately flooding).
std::size_t send_raw(int fd, const std::vector<std::uint8_t>& b) {
    const ssize_t w = ::send(fd, b.data(), b.size(), MSG_DONTWAIT);
    return w > 0 ? static_cast<std::size_t>(w) : 0;
}

std::vector<std::uint8_t> header(std::uint32_t len, std::uint8_t type) {
    lux::zap::Writer w;
    w.write_u32(len);
    std::vector<std::uint8_t> b = w.take();
    b.push_back(type);
    return b;
}

// A structurally valid vote frame (decode_vote checks widths, not signatures).
std::vector<std::uint8_t> vote_frame(std::uint8_t tag) {
    SignedVote v;
    v.block_id.fill(tag);
    v.voter.fill(0x01);
    v.sig.fill(0x02);
    const std::vector<std::uint8_t> payload = lux::consensus2::zap::encode_vote(v);
    std::vector<std::uint8_t> f = header(static_cast<std::uint32_t>(payload.size()),
                                         lux::consensus2::zap::kVoteMsgType);
    f.insert(f.end(), payload.begin(), payload.end());
    return f;
}

}  // namespace

int main() {
    std::printf("=============== node2 — mesh transport under a hostile peer ===============\n");
    std::printf("one socket must never cost this node unbounded memory, a stalled write, or a seat it kept\n\n");

    std::size_t delivered = 0;
    auto counting_sink = [&delivered](const SignedVote&) { ++delivered; };

    // [1] oversize length + flood: rejected, evicted, and the buffer stays flat.
    {
        MeshVoteTransport tx(counting_sink);
        Link l;
        tx.add_peer(l.ours);
        send_raw(l.theirs, header(0xFFFFFFFFu, lux::consensus2::zap::kVoteMsgType));

        // Flood as hard as the peer can while the transport keeps pumping. The
        // old reader latched its error flag and then went on buffering every one
        // of these bytes; nothing consumed the flag, so the node grew without limit.
        std::vector<std::uint8_t> junk(64 * 1024, 'A');
        std::size_t sent = 0;
        for (int i = 0; i < 256; ++i) {
            sent += send_raw(l.theirs, junk);
            tx.pump();
        }
        check(tx.peer_count() == 0, "[1] the peer that announced a 4 GiB frame is gone");
        check(tx.evicted() == 1, "[1] exactly one eviction");
        check(delivered == 0, "[1] no vote was delivered from the flood");
        std::printf("  [1] flood: peer sent %zu KiB, peers left %zu, evictions %zu\n",
                    sent / 1024, tx.peer_count(), tx.evicted());
    }

    // [2] a length the ZAP ceiling would allow but this link never carries.
    {
        delivered = 0;
        MeshVoteTransport tx(counting_sink);
        Link l;
        tx.add_peer(l.ours);
        const std::uint32_t over = kMaxVoteFrame + 1;
        check(over < lux::zap::MaxMessageSize, "[2] the test length is legal ZAP, illegal here");
        send_raw(l.theirs, header(over, lux::consensus2::zap::kVoteMsgType));
        tx.pump();
        check(tx.peer_count() == 0, "[2] a frame too large for a vote link drops the peer");
    }

    // [3] a validator that votes and then hangs up still counts.
    {
        delivered = 0;
        MeshVoteTransport tx(counting_sink);
        Link l;
        tx.add_peer(l.ours);
        send_raw(l.theirs, vote_frame(0x42));
        l.close_theirs();  // EOF arrives with the vote already in flight
        tx.pump();
        check(delivered == 1, "[3] the vote of a peer that then disconnected was delivered");
        check(tx.peer_count() == 0, "[3] and the closed peer was evicted");
    }

    // [4] a socket that cannot take a write is gone, not retried forever.
    {
        delivered = 0;
        MeshVoteTransport tx(counting_sink);
        Link l;
        tx.add_peer(l.ours);
        l.close_theirs();
        ::shutdown(l.ours, SHUT_RDWR);  // writes now fail outright

        SignedVote v;
        v.block_id.fill(0x43);
        v.voter.fill(0x01);
        v.sig.fill(0x02);
        tx.broadcast(v);
        check(delivered == 1, "[4] broadcast still self-echoes to our own gate");
        check(tx.peer_count() == 0, "[4] the unwritable peer was dropped by broadcast");
    }

    // [5] eviction is per-peer: one hostile socket does not cost an honest one.
    {
        delivered = 0;
        MeshVoteTransport tx(counting_sink);
        Link bad, good;
        tx.add_peer(bad.ours);
        tx.add_peer(good.ours);
        send_raw(bad.theirs, header(0xFFFFFFFFu, lux::consensus2::zap::kVoteMsgType));
        send_raw(good.theirs, vote_frame(0x44));
        tx.pump();
        check(tx.peer_count() == 1, "[5] the honest peer kept its seat");
        check(delivered == 1, "[5] and its vote arrived");
        send_raw(good.theirs, vote_frame(0x45));
        tx.pump();
        check(delivered == 2, "[5] the honest peer still works after the eviction");
    }

    std::printf("---------------------------------------------------------------------------\n");
    if (g_fail) { std::printf("==== node2 MESH TRANSPORT: FAIL (%d) ====\n", g_fail); return 1; }
    std::printf("==== node2 MESH TRANSPORT: PASS — a hostile peer costs itself, not the node ====\n");
    return 0;
}
