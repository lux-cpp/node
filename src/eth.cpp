// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco

#include "lux/node/eth.hpp"

#include <algorithm>
#include <array>
#include <cstdio>
#include <span>
#include <stdexcept>

namespace lux::node {
namespace {

using Json = Rpc::Json;

// ── hex, in the two shapes Ethereum uses ────────────────────────────────────
// A QUANTITY is minimal ("0x0", "0x2a"); DATA is full width ("0x00...2a"). They
// are different encodings of the same bytes and clients reject the wrong one.

std::string quantity(std::uint64_t v) {
    char b[32];
    std::snprintf(b, sizeof(b), "0x%llx", static_cast<unsigned long long>(v));
    return b;
}

std::string quantity(std::span<const std::uint8_t> be) {
    std::size_t i = 0;
    while (i < be.size() && be[i] == 0) ++i;
    if (i == be.size()) return "0x0";
    std::string out = "0x";
    char        b[3];
    std::snprintf(b, sizeof(b), "%x", be[i]);  // first nibble-pair, unpadded
    out += b;
    for (++i; i < be.size(); ++i) {
        std::snprintf(b, sizeof(b), "%02x", be[i]);
        out += b;
    }
    return out;
}

// Named `octets`, not `data`: `std::data` is found by ADL on a std::array
// argument and silently wins the overload, so a call meaning "hex of these
// bytes" compiles into "pointer to these bytes". The clash is real and the fix
// is a name of its own.
std::string octets(std::span<const std::uint8_t> bytes) {
    std::string out = "0x";
    char        b[3];
    for (auto c : bytes) {
        std::snprintf(b, sizeof(b), "%02x", c);
        out += b;
    }
    return out;
}

int nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

std::vector<std::uint8_t> unhex(const std::string& s) {
    std::size_t i = (s.size() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) ? 2 : 0;
    if ((s.size() - i) % 2 != 0) throw Rpc::Error(-32602, "odd-length hex");
    std::vector<std::uint8_t> out;
    out.reserve((s.size() - i) / 2);
    for (; i + 1 < s.size(); i += 2) {
        const int hi = nibble(s[i]), lo = nibble(s[i + 1]);
        if (hi < 0 || lo < 0) throw Rpc::Error(-32602, "not hex");
        out.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
    }
    return out;
}

// A QUANTITY read back. Ethereum writes quantities MINIMALLY — "0x5", not
// "0x05" — so a quantity has an odd number of digits about half the time and
// cannot be read with the DATA decoder. Reading `eth_getBlockByNumber("0x5")`
// as data is a refusal to answer for every other block number.
std::uint64_t number(const std::string& s) {
    std::size_t i = (s.size() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) ? 2 : 0;
    if (i == s.size()) throw Rpc::Error(-32602, "empty quantity");
    if (s.size() - i > 16) throw Rpc::Error(-32602, "quantity does not fit");
    std::uint64_t v = 0;
    for (; i < s.size(); ++i) {
        const int d = nibble(s[i]);
        if (d < 0) throw Rpc::Error(-32602, "not a hex quantity");
        v = (v << 4) | static_cast<std::uint64_t>(d);
    }
    return v;
}

const Json& arg(const Json& params, std::size_t i) {
    if (!params.is_array() || params.size() <= i)
        throw Rpc::Error(-32602, "missing parameter " + std::to_string(i));
    return params[i];
}

std::string text(const Json& params, std::size_t i) {
    const Json& v = arg(params, i);
    if (!v.is_string()) throw Rpc::Error(-32602, "parameter " + std::to_string(i) +
                                                 " must be a string");
    return v.get<std::string>();
}

evm::Address address(const Json& params, std::size_t i) {
    const auto b = unhex(text(params, i));
    if (b.size() != 20) throw Rpc::Error(-32602, "an address is 20 bytes");
    evm::Address a{};
    std::copy(b.begin(), b.end(), a.begin());
    return a;
}

// A 256-bit parameter, right-aligned. It is read as a QUANTITY, because that is
// what the spec calls a storage position: `eth_getStorageAt(addr, "0x0")` is the
// ordinary way to ask for slot zero, and reading it as DATA rejects it for being
// an odd number of digits. Every nibble counts and the value is padded on the
// left, so "0x0", "0x00" and the full-width form all name slot zero.
evm::Word word(const Json& params, std::size_t i) {
    const std::string  s  = text(params, i);
    const std::size_t  at = (s.size() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) ? 2 : 0;
    const std::size_t  n  = s.size() - at;
    if (n == 0) throw Rpc::Error(-32602, "empty quantity");
    if (n > 64) throw Rpc::Error(-32602, "a word is at most 32 bytes");
    evm::Word w{};
    // Fill from the right, one nibble at a time, so an odd digit count lands
    // where it should instead of being an error.
    std::size_t bit = 0;
    for (std::size_t k = s.size(); k-- > at; ++bit) {
        const int d = nibble(s[k]);
        if (d < 0) throw Rpc::Error(-32602, "not hex");
        w[31 - bit / 2] |= static_cast<std::uint8_t>(d << (4 * (bit % 2)));
    }
    return w;
}

// A block parameter, resolved against the chain. Only the accepted tip is
// readable: this node keeps ONE resident state, so a historical balance would
// have to be reconstructed rather than read, and returning the tip's answer for
// a past height would be a wrong answer rather than a missing one.
std::uint64_t height_param(const evm::Chain& c, const Json& params, std::size_t i) {
    const std::uint64_t tip = c.last_accepted_height();
    if (!params.is_array() || params.size() <= i) return tip;
    const Json& v = params[i];
    if (v.is_string()) {
        const auto s = v.get<std::string>();
        if (s == "latest" || s == "pending" || s == "safe" || s == "finalized") return tip;
        if (s == "earliest") return 0;
        return number(s);
    }
    if (v.is_number_unsigned()) return v.get<std::uint64_t>();
    return tip;
}

Json block_json(const evm::Chain& c, const node::Block& b, bool full) {
    Json txs = Json::array();
    for (const auto& t : c.block_txs(b.id())) {
        if (!full) {
            txs.push_back(octets(t.hash));
            continue;
        }
        txs.push_back(Json{
            {"hash", octets(t.hash)},
            {"from", octets(t.sender)},
            {"to", t.create ? Json(nullptr) : Json(octets(t.to))},
            {"value", quantity(t.value)},
            {"gas", quantity(t.gas)},
            {"gasPrice", quantity(t.gas_price)},
            {"nonce", quantity(t.nonce)},
            {"input", octets(t.data)},
            {"blockHash", octets(b.id())},
            {"blockNumber", quantity(b.height())},
        });
    }
    return Json{
        {"hash", octets(b.id())},
        {"parentHash", octets(b.parent())},
        {"number", quantity(b.height())},
        // The REAL Merkle-Patricia-Trie root cevm computed for this block. It is
        // the same 32 bytes the validators put in their signed VotePosition.
        {"stateRoot", octets(b.root())},
        {"transactions", txs},
    };
}

}  // namespace

void serve_eth(Rpc& rpc, evm::Chain& chain, const std::string& client) {
    const std::string path = "/v1/chain/" + chain.alias() + "/rpc";
    auto              on   = [&](const char* name, Rpc::Method fn) {
        rpc.method(path, name, std::move(fn));
    };

    on("eth_chainId", [&chain](const Json&) { return quantity(chain.eth_chain_id()); });
    on("net_version", [&chain](const Json&) { return std::to_string(chain.eth_chain_id()); });
    on("web3_clientVersion", [client](const Json&) { return client; });
    on("eth_blockNumber", [&chain](const Json&) { return quantity(chain.last_accepted_height()); });

    // Not a fee market yet: this chain executes at a zero base fee, so the
    // honest answer is zero rather than a number invented to look plausible.
    on("eth_gasPrice", [](const Json&) { return std::string("0x0"); });

    on("eth_getBalance", [&chain](const Json& p) {
        const auto a = address(p, 0);
        (void)height_param(chain, p, 1);
        return quantity(chain.balance(a));
    });
    on("eth_getTransactionCount", [&chain](const Json& p) {
        const auto a = address(p, 0);
        (void)height_param(chain, p, 1);
        return quantity(chain.nonce(a));
    });
    on("eth_getCode", [&chain](const Json& p) {
        const auto a = address(p, 0);
        (void)height_param(chain, p, 1);
        return octets(chain.code(a));
    });
    on("eth_getStorageAt", [&chain](const Json& p) {
        const auto a = address(p, 0);
        const auto k = word(p, 1);
        (void)height_param(chain, p, 2);
        return octets(chain.storage(a, k));
    });

    on("eth_getBlockByNumber", [&chain](const Json& p) -> Json {
        const auto h = height_param(chain, p, 0);
        const auto b = chain.at_height(h);
        if (!b) return nullptr;
        const bool full = p.is_array() && p.size() > 1 && p[1].is_boolean() &&
                          p[1].get<bool>();
        return block_json(chain, *b, full);
    });
    on("eth_getBlockByHash", [&chain](const Json& p) -> Json {
        const auto raw = unhex(text(p, 0));
        if (raw.size() != 32) throw Rpc::Error(-32602, "a block hash is 32 bytes");
        Id id{};
        std::copy(raw.begin(), raw.end(), id.begin());
        const auto b = chain.get(id);
        if (!b) return nullptr;
        const bool full = p.is_array() && p.size() > 1 && p[1].is_boolean() &&
                          p[1].get<bool>();
        return block_json(chain, *b, full);
    });

    // The write. The transaction is decoded and its sender RECOVERED here; only
    // a transaction that survives that reaches the mempool, so what is returned
    // is the hash of something this node has verified rather than an
    // acknowledgement that bytes arrived.
    on("eth_sendRawTransaction", [&chain](const Json& p) {
        const auto raw = unhex(text(p, 0));
        const auto h   = chain.accept_tx(raw);
        if (!h)
            throw Rpc::Error(-32602,
                             "the transaction did not decode, was not signed for chain " +
                                 std::to_string(chain.eth_chain_id()) +
                                 ", or its signature did not recover");
        return octets(*h);
    });

    // The chain's own view of itself, useful enough to be worth serving and
    // cheap enough to be honest: how many transactions are waiting, and the root
    // the last certificate certified.
    on("eth_syncing", [](const Json&) { return false; });
    on("txpool_status", [&chain](const Json&) {
        return Json{{"pending", quantity(chain.pending())}, {"queued", "0x0"}};
    });

    rpc.root(path);
}

}  // namespace lux::node
