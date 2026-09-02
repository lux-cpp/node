// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// hostile_decode_test.cpp — the two decoders that take bytes from strangers,
// fed bytes a stranger would send.
//
// Both are reachable from outside the validator set: `Tx::decode` from any
// `eth_sendRawTransaction` caller, `Chain::parse` from any peer that can put a
// block frame on the mesh. Neither may abort, allocate on a number it was
// handed, or read past its buffer — a decoder that dies on bad input is a
// cluster-wide halt available to anyone who can reach one node's RPC port.
//
// The check is the same for every case: the call RETURNS, and it returns a
// refusal. That the process is still alive to print the result is the assertion
// these cases are really making.

#include "lux/node/evm.hpp"
#include "lux/zap/wire.hpp"
#include "../src/rlp.hpp"   // the decoder itself, where the bound actually lives

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

using namespace lux::node;

namespace {

int g_fail = 0;
void check(bool ok, const std::string& what) {
    std::printf("  %s  %s\n", ok ? "ok  " : "FAIL", what.c_str());
    if (!ok) ++g_fail;
}

bool refused(const std::vector<std::uint8_t>& raw) {
    return !evm::Tx::decode(raw, 31337).has_value();
}

// PEAK virtual size in KiB, from /proc/self/status.
//
// The reserve DoS does not throw on a Linux host that overcommits — it quietly
// takes ~893 GB of address space (measured: sizeof(Tx) is 208, and 2^32-1 of
// them is 893,353,197,360 bytes) and waits for the OOM killer, or for a
// stricter host to turn it into a bad_alloc thrown out of a decode nothing
// catches. So the assertion is about ADDRESS SPACE, not about an exception.
//
// It has to be the PEAK. The vector is a local inside parse, so the moment
// parse returns nullptr the reservation is unmapped and the current size is
// back to normal — sampling after the call sees nothing at all, which is how a
// first version of this check passed against the unfixed decoder. VmPeak is a
// high-water mark and does not fall.
std::size_t vm_peak_kb() {
    std::FILE* f = std::fopen("/proc/self/status", "r");
    if (f == nullptr) return 0;
    char line[256];
    unsigned long kb = 0;
    while (std::fgets(line, sizeof(line), f) != nullptr)
        if (std::sscanf(line, "VmPeak: %lu kB", &kb) == 1) break;
    std::fclose(f);
    return kb;
}

// A block frame: parent(32) height(8) timestamp(8) root(32) ntx(4) then txs,
// each ZAP-length-prefixed. Built by hand so the counts can lie.
std::vector<std::uint8_t> block_frame(std::uint32_t ntx,
                                      const std::vector<std::vector<std::uint8_t>>& txs) {
    lux::zap::Writer w;
    std::vector<std::uint8_t> id32(32, 0x11);
    w.write_bytes(id32.data(), id32.size());   // parent
    w.write_u64(1);                            // height
    w.write_u64(1);                            // timestamp
    w.write_bytes(id32.data(), id32.size());   // root
    w.write_u32(ntx);                          // the count, which may be a lie
    for (const auto& t : txs) w.write_bytes(t);
    return w.take();
}

}  // namespace

int main() {
    std::printf("node — what a stranger can send the two decoders\n\n");

    // ── Tx::decode ──────────────────────────────────────────────────────────
    std::printf("Tx::decode (reachable from eth_sendRawTransaction)\n");

    check(refused({}), "empty input");
    check(refused({0xf8}), "a long-form header with no length byte");
    check(refused({0xf8, 0x00}), "a non-minimal long-form length");
    check(refused({0xc0}), "an empty list where nine fields were due");

    // THE OVERFLOW, asserted where it lives. `Tx::decode` happens to reject
    // these anyway — the outer item's wrapped `raw` size stops matching the body
    // length — so asking it would pass whether the bound is right or wrong, and a
    // check that cannot fail is not a check. The bound is in rlp::item, so that
    // is what is called.
    //
    // 0xbf is a long string whose length is the next EIGHT bytes; all-0xff
    // declares 2^64-1. The header is 9 bytes, so a bound written as
    // `size < head + len` computes 9 + (2^64-1), which WRAPS to 8 — less than
    // the buffer — and the length is ACCEPTED, after which subspan is asked for
    // 18 exabytes. Written as `len > size - head` it cannot wrap.
    {
        std::vector<std::uint8_t> v{0xbf};
        for (int i = 0; i < 8; ++i) v.push_back(0xff);
        v.resize(64, 0xaa);
        check(!rlp::item(v).has_value(),
              "rlp::item refuses a declared length of 2^64-1 (the add-and-compare overflow)");
        check(refused(v), "and Tx::decode refuses it too");
    }
    {
        std::vector<std::uint8_t> v{0xff};   // the same, as a LIST
        for (int i = 0; i < 8; ++i) v.push_back(0xff);
        v.resize(64, 0xaa);
        check(!rlp::item(v).has_value(), "rlp::item refuses the same overflow declared as a list");
    }
    // Every wrapping length: head is 9, so len in [2^64-8, 2^64-1] lands
    // head+len in [1, 8] and slips under a 64-byte buffer.
    {
        bool all_refused = true;
        for (int k = 1; k <= 8; ++k) {
            std::vector<std::uint8_t> v{0xbf};
            const std::uint64_t len = ~0ull - static_cast<std::uint64_t>(k) + 1;
            for (int i = 7; i >= 0; --i) v.push_back(std::uint8_t((len >> (i * 8)) & 0xff));
            v.resize(64, 0xaa);
            if (rlp::item(v).has_value()) all_refused = false;
        }
        check(all_refused, "rlp::item refuses every length that wraps the bound");
    }
    {
        std::vector<std::uint8_t> v{0xbf, 0x7f};
        for (int i = 0; i < 7; ++i) v.push_back(0xff);
        v.resize(64, 0xaa);
        check(!rlp::item(v).has_value(), "rlp::item refuses a huge-but-unwrapped declared length");
    }
    // A well-formed long string is still ACCEPTED — the bound rejects lies, not
    // length. Without this the two checks above would pass on a decoder that
    // refused everything.
    {
        std::vector<std::uint8_t> v{0xb8, 60};
        v.resize(62, 0xaa);
        const auto it = rlp::item(v);
        check(it.has_value() && it->payload.size() == 60,
              "rlp::item still accepts an honest 60-byte string");
    }

    // A well-formed list whose FIELDS are hostile.
    check(refused({0xc9, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80}),
          "nine empty fields (no signature to recover)");
    // A typed transaction whose body is truncated mid-header.
    check(refused({0x02, 0xf8, 0xff}), "a typed transaction truncated in its header");
    check(refused({0x01}), "a bare type byte");
    check(refused({0x03, 0xc0}), "an unknown transaction type");

    // Every prefix of a byte string that is not a transaction. None may crash.
    {
        bool all_refused = true;
        for (std::size_t n = 1; n <= 64; ++n) {
            std::vector<std::uint8_t> v(n, 0xff);
            if (!refused(v)) all_refused = false;
        }
        check(all_refused, "64 all-0xff prefixes, none accepted and none fatal");
    }

    // ── Chain::parse ────────────────────────────────────────────────────────
    std::printf("\nChain::parse (reachable from any peer on the mesh)\n");

    evm::Genesis g;
    g.chain_id  = 31337;
    g.gas_limit = 30'000'000;
    evm::Chain chain(g);

    // THE RESERVE. The count says four billion transactions; the frame carries
    // none. Reserving what the count asks for is ~900 GB at sizeof(Tx), which on
    // a strict host is a bad_alloc thrown out of a decode nothing catches — the
    // validator is gone — and on a host that overcommits is a silent 900 GB of
    // address space and an OOM kill later.
    //
    // Returning nullptr is NOT the assertion: the unfixed code returns nullptr
    // too, right after taking the memory. The assertion is that the process did
    // not grow.
    {
        const std::size_t before = vm_peak_kb();
        const auto f = block_frame(0xffffffffu, {});
        check(chain.parse(f) == nullptr, "a block claiming 2^32-1 transactions and carrying none");
        const std::size_t after = vm_peak_kb();
        // 64 MiB of headroom: far above any honest decode of an empty block, and
        // three orders of magnitude below the 893 GB the lie asks for.
        check(after <= before + 64u * 1024u,
              "and decoding it did not grow this process (the reserve, not the return)");
        std::printf("        peak virtual size %zu -> %zu kB\n", before, after);
    }
    {
        const std::size_t before = vm_peak_kb();
        const auto f = block_frame(1u << 30, {});
        check(chain.parse(f) == nullptr, "a block claiming 2^30 transactions and carrying none");
        check(vm_peak_kb() <= before + 64u * 1024u, "and that one did not grow it either");
    }
    // A count that lies downward is a different encoding of the same block, so
    // trailing bytes are refused rather than ignored.
    {
        std::vector<std::uint8_t> tx{0xc0};
        const auto f = block_frame(0, {tx});
        check(chain.parse(f) == nullptr, "a block with transactions past its count");
    }
    check(chain.parse(std::vector<std::uint8_t>{}) == nullptr, "an empty block frame");
    check(chain.parse(std::vector<std::uint8_t>(16, 0xff)) == nullptr, "sixteen bytes of noise");
    {
        // A truncated frame at every length: the reader must run out, not read on.
        const auto full = block_frame(0, {});
        bool all_refused = true;
        for (std::size_t n = 0; n < full.size(); ++n)
            if (chain.parse(std::vector<std::uint8_t>(full.begin(), full.begin() + n)) != nullptr)
                all_refused = false;
        check(all_refused, "every truncation of a valid frame");
    }
    // A block whose one transaction does not decode is refused whole: a peer
    // cannot put an unsigned transaction into a block.
    {
        const auto f = block_frame(1, {{0xff, 0xff, 0xff}});
        check(chain.parse(f) == nullptr, "a block carrying an undecodable transaction");
    }

    std::printf("\n%s\n", g_fail ? "FAIL" : "PASS — hostile input is refused, not fatal");
    return g_fail ? 1 : 0;
}
