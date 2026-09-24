// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco

#include "lux/node/journal.hpp"

#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

namespace lux::node {

Journal Journal::open(const std::filesystem::path& path) {
    Journal j;
    j.fd_ = ::open(path.c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (j.fd_ < 0)
        throw std::runtime_error("journal: cannot open " + path.string() + ": " + std::strerror(errno));
    if (::flock(j.fd_, LOCK_EX | LOCK_NB) != 0)
        throw std::runtime_error("journal: " + path.string() + " is held by another process");

    std::vector<std::uint8_t> raw;
    std::uint8_t              buf[1 << 16];
    for (;;) {
        const ssize_t n = ::read(j.fd_, buf, sizeof buf);
        if (n < 0) {
            if (errno == EINTR) continue;
            throw std::runtime_error("journal: cannot read " + path.string());
        }
        if (n == 0) break;
        raw.insert(raw.end(), buf, buf + n);
    }
    const std::size_t whole = raw.size() - raw.size() % kMessageLen;
    if (whole != raw.size() && ::ftruncate(j.fd_, off_t(whole)) != 0)
        throw std::runtime_error("journal: cannot cut back a torn entry in " + path.string());

    for (std::size_t at = 0; at < whole; at += kMessageLen) {
        Message m{};
        std::memcpy(m.data(), raw.data() + at, kMessageLen);
        const auto claim = read(m);
        if (!claim) throw std::runtime_error("journal: " + path.string() + " holds a statement this network disowns");
        const auto [it, fresh] = j.said_.emplace(claim->slot, m);
        if (!fresh && it->second != m)
            throw std::runtime_error("journal: " + path.string() + " holds two statements at one slot");
    }
    if (::lseek(j.fd_, off_t(whole), SEEK_SET) < 0)
        throw std::runtime_error("journal: cannot seek " + path.string());
    return j;
}

Journal::Journal(Journal&& o) noexcept : fd_(o.fd_), said_(std::move(o.said_)), broken_(o.broken_) { o.fd_ = -1; }

Journal::~Journal() {
    if (fd_ >= 0) ::close(fd_);
}

Journal::Admit Journal::admit(const Message& m) {
    const auto claim = read(m);
    if (!claim) return Admit::NotAStatement;
    if (const auto it = said_.find(claim->slot); it != said_.end())
        return it->second == m ? Admit::Ok : Admit::Equivocation;
    if (broken_) return Admit::NotDurable;

    // Write, sync, then remember. A failure leaves none of the entry behind:
    // part of one would put every later entry out of step with the boundaries a
    // reopen reads.
    const off_t end = ::lseek(fd_, 0, SEEK_END);
    if (end < 0) return Admit::NotDurable;
    std::size_t done = 0;
    bool        ok   = true;
    while (done < m.size()) {
        const ssize_t n = ::write(fd_, m.data() + done, m.size() - done);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { ok = false; break; }
        done += std::size_t(n);
    }
    if (ok && ::fdatasync(fd_) != 0) ok = false;
    if (!ok) {
        if (::ftruncate(fd_, end) != 0 || ::lseek(fd_, end, SEEK_SET) < 0) broken_ = true;
        return Admit::NotDurable;
    }
    said_.emplace(claim->slot, m);
    return Admit::Ok;
}

std::optional<Message> Journal::standing(const Slot& slot) const {
    const auto it = said_.find(slot);
    if (it == said_.end()) return std::nullopt;
    return it->second;
}

}  // namespace lux::node
