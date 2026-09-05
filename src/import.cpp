// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// import.cpp — the RLP block export, read and checked.
//
// The file is mapped rather than read: an export is a bare concatenation of
// blocks with no index, so the reader walks it once from the front, and mapping
// lets a 1.2 GB mainnet export be walked without a 1.2 GB copy of it on the
// heap. The mapping is read-only and private, so the canonical exports are
// never written to.

#include "lux/node/import.hpp"

#include "rlp.hpp"

#include <bin/cevm/eth_mpt.hpp>       // the Ethereum MPT + RLP encoder, reused
#include <test/state/hash_utils.hpp>  // cevm::keccak256

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

namespace lux::node {
namespace {

// A header's fields, by the position the Ethereum block header has always put
// them in. Named rather than indexed at the use site, because a header read
// with 3 and 4 the wrong way round would compare a transactions root against a
// state root and refuse a chain that was fine.
enum Field : std::size_t {
    kParent = 0,
    kOmmers = 1,
    kState  = 3,
    kTxs    = 4,
    kNumber = 8,
    kTime   = 11,
    kMin    = 15,  // through the nonce; anything after it is chain-specific
};

// The three parts of a block body. A Shanghai export carries a fourth
// (withdrawals) and these exports do not; both are accepted and the parts
// beyond the uncle list are left alone, because a reader that INSISTS on a
// field it cannot check is refusing files for its own convenience.
constexpr std::size_t kHeaderPart = 0;
constexpr std::size_t kTxPart     = 1;
constexpr std::size_t kOmmerPart  = 2;

// A read-only mapping of the export, released however this function leaves.
class Mapped {
public:
    explicit Mapped(const std::string& path) {
        const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
        if (fd < 0) throw std::runtime_error("import: cannot open " + path);
        struct stat st {};
        if (::fstat(fd, &st) != 0 || st.st_size <= 0) {
            ::close(fd);
            throw std::runtime_error("import: cannot size " + path);
        }
        size_ = static_cast<std::size_t>(st.st_size);
        void* p = ::mmap(nullptr, size_, PROT_READ, MAP_PRIVATE, fd, 0);
        ::close(fd);  // the mapping keeps its own reference to the file
        if (p == MAP_FAILED) throw std::runtime_error("import: cannot map " + path);
        base_ = static_cast<const std::uint8_t*>(p);
    }
    ~Mapped() { if (base_ != nullptr) ::munmap(const_cast<std::uint8_t*>(base_), size_); }

    Mapped(const Mapped&) = delete;
    Mapped& operator=(const Mapped&) = delete;

    std::span<const std::uint8_t> bytes() const noexcept { return {base_, size_}; }

private:
    const std::uint8_t* base_ = nullptr;
    std::size_t         size_ = 0;
};

std::string at(std::uint64_t n) { return " (block " + std::to_string(n) + ")"; }

// A 32-byte hash field. Exactly 32: a hash that is shorter is not a short hash,
// it is a different encoding of the block, and accepting it would let two
// spellings name one header.
Id hash32(const rlp::Item& it, const char* what, std::uint64_t n) {
    if (it.list || it.payload.size() != 32)
        throw std::runtime_error(std::string("import: ") + what + " is not 32 bytes" + at(n));
    Id out{};
    std::memcpy(out.data(), it.payload.data(), 32);
    return out;
}

Id keccak(std::span<const std::uint8_t> in) noexcept {
    const auto h = cevm::keccak256({in.data(), in.size()});
    Id out{};
    std::memcpy(out.data(), h.bytes, 32);
    return out;
}

// The root of the trie a block's transactions hang in: key = RLP(index),
// value = the transaction as the body carries it. A legacy transaction is a
// list, so its value is the whole item; a typed one (EIP-2930, EIP-1559) is
// carried as a byte string holding `type || rlp(...)`, so its value is the
// payload without the string header. Getting that distinction wrong changes
// every root, which is precisely why the root is checked rather than assumed.
Id tx_root(const std::vector<rlp::Item>& txs) {
    cevm::eth::MPT trie;
    for (std::size_t i = 0; i < txs.size(); ++i) {
        const auto key = cevm::eth::rlp::encode_uint64(i);
        const auto v   = txs[i].list ? txs[i].raw : txs[i].payload;
        trie.insert({key.data(), key.size()}, cevm::eth::bytes{v.begin(), v.end()});
    }
    const auto h = trie.hash();
    Id out{};
    std::memcpy(out.data(), h.bytes, 32);
    return out;
}

}  // namespace

Import import_chain_data(evm::Chain& chain, const std::string& path) {
    const Mapped file(path);
    auto         rest = file.bytes();

    Import        out{};
    const auto    chain_id  = chain.eth_chain_id();
    const auto    head      = chain.last_accepted_height();
    bool          anchored  = false;  // the file's block 0 has been read
    Id            prev_id{};
    std::uint64_t prev_number = 0;

    while (!rest.empty()) {
        const auto block = rlp::item(rest);
        if (!block || !block->list)
            throw std::runtime_error("import: not a block at byte offset " +
                                     std::to_string(file.bytes().size() - rest.size()));
        rest = rest.subspan(block->raw.size());

        const auto parts = rlp::items(block->payload);
        if (!parts || parts->size() < 3)
            throw std::runtime_error("import: a block is [header, transactions, uncles]" +
                                     at(prev_number + 1));

        const auto& head_item = (*parts)[kHeaderPart];
        if (!head_item.list) throw std::runtime_error("import: header is not a list");
        const auto fields = rlp::items(head_item.payload);
        if (!fields || fields->size() < kMin)
            throw std::runtime_error("import: header has fewer than 15 fields" +
                                     at(prev_number + 1));

        const auto number = rlp::u64((*fields)[kNumber]);
        const auto stamp  = rlp::u64((*fields)[kTime]);
        if (!number || !stamp)
            throw std::runtime_error("import: header number/timestamp is not a scalar" +
                                     at(prev_number + 1));

        // COMPUTED, NOT COPIED. A block's id is the keccak of its header's own
        // bytes, which is why the header item keeps the bytes it was encoded as.
        const Id id     = keccak(head_item.raw);
        const Id parent = hash32((*fields)[kParent], "parentHash", *number);

        // The body is bound to the header it arrived under: the transactions
        // rebuild the header's transactionsRoot, and the uncle list hashes to
        // its ommersHash. Both are recomputed here from the bytes on disk.
        if (!(*parts)[kTxPart].list || !(*parts)[kOmmerPart].list)
            throw std::runtime_error("import: transactions and uncles are lists" + at(*number));
        const auto txs = rlp::items((*parts)[kTxPart].payload);
        if (!txs) throw std::runtime_error("import: malformed transaction list" + at(*number));
        if (const Id got = tx_root(*txs), want = hash32((*fields)[kTxs], "transactionsRoot", *number);
            got != want)
            throw std::runtime_error("import: transactions do not rebuild the header's "
                                     "transactionsRoot" + at(*number));
        if (const Id got = keccak((*parts)[kOmmerPart].raw),
            want = hash32((*fields)[kOmmers], "ommersHash", *number);
            got != want)
            throw std::runtime_error("import: uncle list does not hash to the header's "
                                     "ommersHash" + at(*number));

        // Block 0 is the file's own anchor and the only thing that can close
        // block 1's ancestry, so it is READ and not ingested. Go skips it for
        // the same reason and checks block 1's parent against the genesis its
        // node was configured with; this node's genesis is a ZAP block of its
        // own, so the export's genesis is what block 1 must name.
        if (*number == 0) {
            if (anchored) throw std::runtime_error("import: a second block 0");
            anchored    = true;
            out.genesis = id;
            prev_id     = id;
            prev_number = 0;
            out.tip     = id;
            out.root    = hash32((*fields)[kState], "stateRoot", 0);
            out.height  = 0;
            out.timestamp = *stamp;
            continue;
        }
        if (!anchored)
            throw std::runtime_error("import: the export does not begin at block 0, so its "
                                     "first block's ancestry cannot be closed" + at(*number));

        // EVERY block, walked — the chain is checked link by link rather than at
        // its ends, because a file whose head and tail agree can still be spliced
        // in the middle.
        if (*number != prev_number + 1)
            throw std::runtime_error("import: height skips from " + std::to_string(prev_number) +
                                     " to " + std::to_string(*number));
        if (parent != prev_id)
            throw std::runtime_error("import: parentHash does not name the block before it" +
                                     at(*number));

        std::vector<evm::Tx> decoded;
        decoded.reserve(txs->size());
        for (const auto& t : *txs) {
            const auto raw = t.list ? t.raw : t.payload;
            auto       tx  = evm::Tx::decode(raw, chain_id);
            if (!tx)
                throw std::runtime_error("import: a transaction does not decode and recover on "
                                         "chain " + std::to_string(chain_id) + at(*number));
            decoded.push_back(std::move(*tx));
        }

        prev_id       = id;
        prev_number   = *number;
        out.tip       = id;
        out.root      = hash32((*fields)[kState], "stateRoot", *number);
        out.height    = *number;
        out.timestamp = *stamp;
        out.txs      += txs->size();

        // Already held. Verified all the same — a re-read that skipped its
        // checks would report a chain it had not looked at — but not ingested,
        // which is what makes a second run of an unchanged flag a no-op rather
        // than a failure.
        if (*number <= head) {
            ++out.skipped;
            continue;
        }

        evm::Past past;
        past.id        = id;
        past.parent    = parent;
        past.root      = out.root;
        past.height    = *number;
        past.timestamp = *stamp;
        past.txs       = std::move(decoded);
        past.bytes.assign(block->raw.begin(), block->raw.end());
        chain.ingest(std::move(past));
        ++out.blocks;
    }

    if (!anchored) throw std::runtime_error("import: no blocks in " + path);
    return out;
}

}  // namespace lux::node
