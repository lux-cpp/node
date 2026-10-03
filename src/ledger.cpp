// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco

#include "lux/node/ledger.hpp"

#include "lux/node/journal.hpp"  // sync_dir

#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <string>

#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

namespace lux::node {

namespace {

void put_be(std::vector<std::uint8_t>& out, std::uint64_t v, int bytes) {
    for (int s = 8 * (bytes - 1); s >= 0; s -= 8) out.push_back(std::uint8_t(v >> s));
}

std::uint64_t be(const std::uint8_t* p, int bytes) {
    std::uint64_t v = 0;
    for (int i = 0; i < bytes; ++i) v = (v << 8) | p[i];
    return v;
}

bool write_all(int fd, const std::uint8_t* p, std::size_t n) {
    while (n > 0) {
        const ssize_t w = ::write(fd, p, n);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) return false;
        p += w;
        n -= std::size_t(w);
    }
    return true;
}

std::vector<std::uint8_t> read_all(int fd) {
    std::vector<std::uint8_t> raw;
    std::uint8_t              buf[1 << 16];
    for (;;) {
        const ssize_t n = ::read(fd, buf, sizeof buf);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) throw std::runtime_error("ledger: read failed");
        if (n == 0) break;
        raw.insert(raw.end(), buf, buf + n);
    }
    return raw;
}


// Write `bytes` to `path` durably: a temporary, synced, renamed over, the
// directory synced.
bool replace_file(const std::filesystem::path& path, const std::vector<std::uint8_t>& bytes) {
    const auto tmp = path.string() + ".tmp";
    const int  fd  = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) return false;
    const bool ok = write_all(fd, bytes.data(), bytes.size()) && ::fsync(fd) == 0;
    ::close(fd);
    if (!ok || ::rename(tmp.c_str(), path.c_str()) != 0) {
        ::unlink(tmp.c_str());
        return false;
    }
    return sync_dir(path.parent_path());
}

}  // namespace

Ledger Ledger::open(const std::filesystem::path& path) {
    Ledger l;
    l.fd_ = ::open(path.c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (l.fd_ < 0) throw std::runtime_error("ledger: cannot open " + path.string() + ": " + std::strerror(errno));
    if (::flock(l.fd_, LOCK_EX | LOCK_NB) != 0)
        throw std::runtime_error("ledger: " + path.string() + " is held by another process");
    if (!sync_dir(path.parent_path()))
        throw std::runtime_error("ledger: cannot sync the directory of " + path.string());
    const auto  raw = read_all(l.fd_);
    std::size_t at  = 0;
    for (;;) {
        if (raw.size() - at < 4) break;
        const std::size_t len = std::size_t(be(raw.data() + at, 4));
        if (len < 8 + 32 || raw.size() - at - 4 < len) break;  // torn: cut back below
        const std::uint64_t height = be(raw.data() + at + 4, 8);
        const auto cert = decode_certificate({raw.data() + at + 4 + 8 + 32, len - 8 - 32});
        if (!cert) throw std::runtime_error("ledger: " + path.string() + " holds a record that is not one");
        if (!l.offsets_.empty() && height <= l.offsets_.rbegin()->first)
            throw std::runtime_error("ledger: " + path.string() + " goes back from height " +
                                     std::to_string(l.offsets_.rbegin()->first) + " to " +
                                     std::to_string(height));
        l.offsets_.emplace(height, at);
        std::memcpy(l.last_block_.data(), raw.data() + at + 4 + 8, 32);
        at += 4 + len;
    }
    if (at != raw.size() && ::ftruncate(l.fd_, off_t(at)) != 0)
        throw std::runtime_error("ledger: cannot cut back a torn record in " + path.string());
    if (::lseek(l.fd_, off_t(at), SEEK_SET) < 0) throw std::runtime_error("ledger: cannot seek");
    return l;
}

Ledger::Ledger(Ledger&& o) noexcept
    : fd_(o.fd_), offsets_(std::move(o.offsets_)), last_block_(o.last_block_) {
    o.fd_ = -1;
}

Ledger::~Ledger() {
    if (fd_ >= 0) ::close(fd_);
}

bool Ledger::append(const Record& r) {
    if (!offsets_.empty() && r.height <= offsets_.rbegin()->first) return false;
    const auto                cert = encode(r.cert);
    std::vector<std::uint8_t> rec;
    put_be(rec, 8 + 32 + cert.size(), 4);
    put_be(rec, r.height, 8);
    rec.insert(rec.end(), r.block.begin(), r.block.end());
    rec.insert(rec.end(), cert.begin(), cert.end());
    const off_t end = ::lseek(fd_, 0, SEEK_END);
    if (end < 0) return false;
    if (!write_all(fd_, rec.data(), rec.size()) || ::fdatasync(fd_) != 0) {
        if (::ftruncate(fd_, end) == 0) (void)::lseek(fd_, end, SEEK_SET);
        return false;
    }
    offsets_.emplace(r.height, std::uint64_t(end));
    last_block_ = r.block;
    return true;
}

std::optional<Record> Ledger::at(std::uint64_t height) const {
    const auto found = offsets_.find(height);
    if (found == offsets_.end()) return std::nullopt;
    const std::uint64_t off = found->second;
    std::uint8_t        head[4];
    if (::pread(fd_, head, 4, off_t(off)) != 4) return std::nullopt;
    const std::size_t         len = std::size_t(be(head, 4));
    std::vector<std::uint8_t> body(len);
    if (::pread(fd_, body.data(), len, off_t(off + 4)) != ssize_t(len)) return std::nullopt;
    Record r;
    r.height = be(body.data(), 8);
    std::memcpy(r.block.data(), body.data() + 8, 32);
    auto cert = decode_certificate({body.data() + 40, len - 40});
    if (!cert) return std::nullopt;
    r.cert = std::move(*cert);
    return r;
}

std::optional<std::pair<std::uint64_t, Id>> Ledger::last() const {
    if (offsets_.empty()) return std::nullopt;
    return std::make_pair(offsets_.rbegin()->first, last_block_);
}

std::optional<std::uint64_t> Ledger::first() const {
    if (offsets_.empty()) return std::nullopt;
    return offsets_.begin()->first;
}

bool gated(const std::filesystem::path& data) {
    std::error_code ec;
    return std::filesystem::exists(data / "uncertified", ec);
}

void close_gate(const std::filesystem::path& data) {
    if (!replace_file(data / "uncertified", {}))
        throw std::runtime_error("the import gate could not be written to " + (data / "uncertified").string());
}

bool lift_gate(const std::filesystem::path& data) {
    const auto at = data / "uncertified";
    if (::unlink(at.c_str()) != 0 && errno != ENOENT) return false;
    return sync_dir(data);
}

std::vector<std::uint8_t> encode(const Proposal& p) {
    std::vector<std::uint8_t> out;
    out.reserve(kProposalHead + p.block.size());
    out.push_back(kProposalVersion);
    put_be(out, p.height, 8);
    put_be(out, p.slot, 8);
    out.insert(out.end(), p.signature.begin(), p.signature.end());
    out.insert(out.end(), p.block.begin(), p.block.end());
    return out;
}

std::optional<Proposal> decode_proposal(const Node& from, std::span<const std::uint8_t> payload) {
    if (payload.size() <= kProposalHead || payload.size() > kProposalHead + kBlockMax ||
        payload[0] != kProposalVersion)
        return std::nullopt;
    Proposal p;
    p.from   = from;
    p.height = be(payload.data() + 1, 8);
    p.slot   = be(payload.data() + 9, 8);
    p.signature.assign(payload.begin() + 17, payload.begin() + std::ptrdiff_t(kProposalHead));
    p.block.assign(payload.begin() + std::ptrdiff_t(kProposalHead), payload.end());
    return p;
}

bool keep_held(const std::filesystem::path& data, const Proposal& p) {
    return replace_file(data / "held", encode(p));
}

std::optional<Proposal> held(const std::filesystem::path& data) {
    const auto at = data / "held";
    const int  fd = ::open(at.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) return std::nullopt;
    std::vector<std::uint8_t> raw;
    try {
        raw = read_all(fd);
    } catch (const std::exception&) {
        ::close(fd);
        return std::nullopt;
    }
    ::close(fd);
    return decode_proposal(Node{}, raw);
}

}  // namespace lux::node
