// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// fake_chain.hpp — a chain whose blocks are bytes and nothing else, for tests of
// the engine that should prove the engine and not the EVM a second time.
//
// A block is "FAKE" ‖ parent(32) ‖ height(8) ‖ time(8) ‖ nonce(8), named by the
// SHA-256 of those bytes. It verifies when it builds on the accepted tip. The
// state lives in a Store the test holds, so a validator that stops and starts
// again comes back to the chain it left — as a plugin's data directory does —
// and a chain can begin as an import: a tip at a height, with no certificate.

#pragma once

#include "lux/node/vm.hpp"

#include <sha256/cpp/sha256.hpp>

#include <atomic>
#include <chrono>
#include <cstring>
#include <map>
#include <memory>
#include <mutex>

namespace lux::node::test {

struct Store {
    std::mutex                                    mu;
    Id                                            tip{};
    std::uint64_t                                 height = 0;
    std::uint64_t                                 stamp  = 0;
    std::map<Id, std::vector<std::uint8_t>>       accepted;  // id → bytes, the accepted chain
    std::map<std::uint64_t, Id>                   at;        // height → id, the accepted chain
    std::uint64_t                                 nonce = 0;
    std::atomic<bool>                             pending{true};  // the pool has something to build
    std::atomic<int>                              builds{0}, parses{0}, verifies{0}, rejects{0};

    // An imported history: a tip nothing here decided.
    static std::shared_ptr<Store> imported(const Id& tip, std::uint64_t height, std::uint64_t stamp) {
        auto s     = std::make_shared<Store>();
        s->tip     = tip;
        s->height  = height;
        s->stamp   = stamp;
        s->at[height] = tip;
        s->accepted[tip] = {'I', 'M', 'P', 'O', 'R', 'T', 'E', 'D'};
        return s;
    }
};

inline Id fake_id(const std::vector<std::uint8_t>& bytes) {
    Id id{};
    cevm::crypto::sha256(reinterpret_cast<std::byte*>(id.data()),
                         reinterpret_cast<const std::byte*>(bytes.data()), bytes.size());
    return id;
}

class FakeBlock final : public Block {
public:
    static constexpr std::size_t kLen = 4 + 32 + 8 + 8 + 8;

    FakeBlock(std::shared_ptr<Store> s, std::vector<std::uint8_t> bytes, Id id, std::uint64_t stamp = 0)
        : s_(std::move(s)), bytes_(std::move(bytes)), id_(id), stamp_(stamp) {
        if (bytes_.size() == kLen) {
            std::memcpy(parent_.data(), bytes_.data() + 4, 32);
            height_ = be(bytes_.data() + 36);
            stamp_  = be(bytes_.data() + 44);
        }
    }

    Id                            id() const override { return id_; }
    Id                            parent() const override { return parent_; }
    std::uint64_t                 height() const override { return height_; }
    std::uint64_t                 timestamp() const override { return stamp_; }
    std::span<const std::uint8_t> bytes() const override { return bytes_; }
    Id                            root() const override { return id_; }
    bool                          verify() override {
        ++s_->verifies;
        const std::lock_guard<std::mutex> lock(s_->mu);
        return parent_ == s_->tip && height_ == s_->height + 1;
    }
    void accept() override {
        const std::lock_guard<std::mutex> lock(s_->mu);
        if (s_->tip == id_) return;
        if (parent_ != s_->tip || height_ != s_->height + 1) throw std::runtime_error("not on the tip");
        s_->tip          = id_;
        s_->height       = height_;
        s_->stamp        = stamp_;
        s_->accepted[id_] = bytes_;
        s_->at[height_]  = id_;
    }
    void reject() override { ++s_->rejects; }

    static std::uint64_t be(const std::uint8_t* p) {
        std::uint64_t v = 0;
        for (int i = 0; i < 8; ++i) v = (v << 8) | p[i];
        return v;
    }

private:
    std::shared_ptr<Store>    s_;
    std::vector<std::uint8_t> bytes_;
    Id                        id_{}, parent_{};
    std::uint64_t             height_ = 0, stamp_ = 0;
};

class FakeChain final : public VM {
public:
    explicit FakeChain(std::shared_ptr<Store> s) : s_(std::move(s)) {}

    Id          chain_id() const override { return Id{}; }
    std::string alias() const override { return "test"; }

    std::shared_ptr<Block> build() override {
        if (!s_->pending.load()) return nullptr;
        ++s_->builds;
        std::vector<std::uint8_t> b{'F', 'A', 'K', 'E'};
        std::uint64_t             height = 0, stamp = 0, nonce = 0;
        {
            const std::lock_guard<std::mutex> lock(s_->mu);
            b.insert(b.end(), s_->tip.begin(), s_->tip.end());
            height = s_->height + 1;
            const auto now =
                std::uint64_t(std::chrono::duration_cast<std::chrono::seconds>(
                                  std::chrono::system_clock::now().time_since_epoch()).count());
            stamp = std::max(now, s_->stamp);
            nonce = ++s_->nonce;
        }
        put(b, height);
        put(b, stamp);
        put(b, nonce);
        return std::make_shared<FakeBlock>(s_, b, fake_id(b));
    }

    std::shared_ptr<Block> parse(std::span<const std::uint8_t> bytes) override {
        ++s_->parses;
        if (bytes.size() != FakeBlock::kLen || std::memcmp(bytes.data(), "FAKE", 4) != 0) return nullptr;
        std::vector<std::uint8_t> b(bytes.begin(), bytes.end());
        return std::make_shared<FakeBlock>(s_, b, fake_id(b));
    }

    std::shared_ptr<Block> get(const Id& id) const override {
        const std::lock_guard<std::mutex> lock(s_->mu);
        const auto                        it = s_->accepted.find(id);
        if (it == s_->accepted.end()) return nullptr;
        // The imported tip is not one of this chain's blocks: its time is the
        // one the store was given.
        return std::make_shared<FakeBlock>(s_, it->second, id, s_->stamp);
    }

    void prefer(const Id&) override {}

    Id last_accepted() const override {
        const std::lock_guard<std::mutex> lock(s_->mu);
        return s_->tip;
    }
    std::uint64_t last_accepted_height() const override {
        const std::lock_guard<std::mutex> lock(s_->mu);
        return s_->height;
    }

private:
    static void put(std::vector<std::uint8_t>& b, std::uint64_t v) {
        for (int s = 56; s >= 0; s -= 8) b.push_back(std::uint8_t(v >> s));
    }
    std::shared_ptr<Store> s_;
};

}  // namespace lux::node::test
