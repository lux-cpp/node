// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco

#include "lux/node/signer.hpp"

#include "lux/consensus/bls.hpp"     // keygen, sk_to_pk, pop_sign — one BLS surface
#include "lux/node/pq_handshake.hpp"  // derive_node_id — the one naming rule

#include <fcntl.h>
#include <unistd.h>

#include <algorithm>
#include <span>
#include <stdexcept>

namespace lux::node {
namespace {

// A secret reaches the disk exactly one way: created 0600, written whole, or
// the call fails. A key half-written is a validator that cannot vote and does
// not know it.
void write_secret(const std::filesystem::path& path, std::span<const std::uint8_t> data) {
    const int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) throw std::runtime_error("signer: cannot create " + path.string());
    std::size_t off = 0;
    while (off < data.size()) {
        const ssize_t n = ::write(fd, data.data() + off, data.size() - off);
        if (n <= 0) {
            ::close(fd);
            throw std::runtime_error("signer: short write to " + path.string());
        }
        off += std::size_t(n);
    }
    ::close(fd);
}

std::vector<std::uint8_t> read_whole(const std::filesystem::path& path) {
    const int fd = ::open(path.c_str(), O_RDONLY);
    if (fd < 0) throw std::runtime_error("signer: cannot open " + path.string());
    std::vector<std::uint8_t> out;
    std::uint8_t              buf[4096];
    for (;;) {
        const ssize_t n = ::read(fd, buf, sizeof(buf));
        if (n < 0) {
            ::close(fd);
            throw std::runtime_error("signer: cannot read " + path.string());
        }
        if (n == 0) break;
        out.insert(out.end(), buf, buf + n);
    }
    ::close(fd);
    return out;
}

// Randomness from the kernel, which is the source anything else would wrap.
// This is the one place the node needs entropy.
void fill(std::span<std::uint8_t> out) {
    const int fd = ::open("/dev/urandom", O_RDONLY);
    if (fd < 0) throw std::runtime_error("signer: no randomness: /dev/urandom");
    std::size_t off = 0;
    while (off < out.size()) {
        const ssize_t n = ::read(fd, out.data() + off, out.size() - off);
        if (n <= 0) {
            ::close(fd);
            throw std::runtime_error("signer: short read from /dev/urandom");
        }
        off += std::size_t(n);
    }
    ::close(fd);
}

}  // namespace

Signer Signer::open(const std::filesystem::path& dir) {
    std::filesystem::create_directories(dir);
    const auto vote_at = dir / "consensus.key";

    Signer k;

    // The name, from the ONE place this tree keeps an ML-DSA keypair. A second
    // keystore here would be a second identity for one validator.
    k.identity_ = pq::Identity::open(dir);
    // The vote.
    if (std::filesystem::exists(vote_at)) {
        const auto raw = read_whole(vote_at);
        if (raw.size() != k.secret_.size())
            throw std::runtime_error("signer: the consensus key at " + vote_at.string() +
                                     " is not one");
        std::copy(raw.begin(), raw.end(), k.secret_.begin());
    } else {
        std::array<std::uint8_t, 32> material{};
        fill(material);
        if (lux::consensus::bls::keygen(material.data(), k.secret_.data()) != 0)
            throw std::runtime_error("signer: cannot make a consensus key");
        write_secret(vote_at, k.secret_);
    }
    if (lux::consensus::bls::sk_to_pk(k.secret_.data(), k.key_.data()) != 0)
        throw std::runtime_error("signer: the consensus key does not yield a public key");

    return k;
}

std::string Signer::publish(const std::array<std::uint8_t, 32>& chain) const {
    const Node me = node(chain);

    // The proof binds node ‖ key, 68 bytes, under the proof-of-possession
    // domain — the message `bls::pop_verify` checks and the one the committee
    // door will hold this line to.
    std::array<std::uint8_t, lux::consensus::bls::kNodeLen + 48> message{};
    std::copy(me.begin(), me.end(), message.begin());
    std::copy(key_.begin(), key_.end(), message.begin() + lux::consensus::bls::kNodeLen);

    lux::consensus::Signature proof{};
    if (lux::consensus::bls::pop_sign(secret_.data(), message.data(), message.size(),
                                      proof.data()) != 0)
        throw std::runtime_error("signer: cannot prove possession of the consensus key");

    return Committee::line(identity_.public_key(), key_, proof);
}

}  // namespace lux::node
