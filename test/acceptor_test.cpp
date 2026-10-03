// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// acceptor_test.cpp — can a stranger hold the door?
//
// The review's probe, made to assert (scratchpad review-zlive, 6a9f2c7). Then,
// one accepting thread ran every greeting, bounded per READ: a stranger that
// announced a 16 000-byte greeting and trickled a byte every 1.5 s held it for
// the whole 12 s the dialer waited, and twelve silent ones held it in turn.
// Now the door only takes and hands on; each greeting is a thread of its own
// under one deadline (kHandshakeMs), at most kHandshakesMax at once and
// kHandshakesPerSource from one address.
//
// Seat 1 accepts and seat 0 dials, from 127.0.0.1; the strangers come from other
// loopback addresses, as another machine's would.
//
//   control   nothing else connects: a link at once
//   [A]       one trickling stranger: a link at once, and the stranger is cut
//             off at its deadline, trickle or not
//   [B]       twelve silent strangers from ONE address: four held, the rest
//             closed at once; a link at once
//   [C]       twenty silent strangers from twenty addresses fill every slot: the
//             link waits for the deadline and no longer

#include "lux/node/host.hpp"
#include "lux/node/signer.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <memory>
#include <string>
#include <thread>
#include <vector>

using namespace lux::node;
using namespace std::chrono_literals;

namespace {

int g_fail = 0;
void check(bool ok, const std::string& what) {
    std::printf("  %s  %s\n", ok ? "ok  " : "FAIL", what.c_str());
    if (!ok) ++g_fail;
}

// A connection to 127.0.0.1:port from `source`, another loopback address.
int stranger(std::uint16_t port, const std::string& source) {
    const int   fd = ::socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in from{};
    from.sin_family = AF_INET;
    ::inet_pton(AF_INET, source.c_str(), &from.sin_addr);
    if (::bind(fd, reinterpret_cast<sockaddr*>(&from), sizeof from) != 0) {
        ::close(fd);
        return -1;
    }
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port   = htons(port);
    ::inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    if (::connect(fd, reinterpret_cast<sockaddr*>(&a), sizeof a) != 0) {
        ::close(fd);
        return -1;
    }
    return fd;
}

// Whether the node has closed `fd` within `wait`.
bool closed_within(int fd, std::chrono::milliseconds wait) {
    const auto until = std::chrono::steady_clock::now() + wait;
    while (std::chrono::steady_clock::now() < until) {
        pollfd pf{fd, POLLIN, 0};
        if (::poll(&pf, 1, 20) > 0) {
            char b[64];
            const ssize_t n = ::recv(fd, b, sizeof b, MSG_DONTWAIT);
            if (n == 0 || (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)) return true;
        }
    }
    return false;
}

struct Pair {
    std::vector<std::unique_ptr<Signer>> signers;
    Committee                            committee;
    std::unique_ptr<Host>                dialer, acceptor;
    std::uint16_t                        port = 0;
    Id                                   chain{};

    explicit Pair(const std::filesystem::path& root) {
        chain.fill(0x2c);
        std::string text;
        for (int i = 0; i < 4; ++i) {
            signers.push_back(std::make_unique<Signer>(Signer::open(root / ("v" + std::to_string(i)))));
            text += signers.back()->publish(chain) + "\n";
        }
        committee = Committee::read(text, chain);
        auto link = [this](std::uint32_t i) {
            Link l;
            l.me    = signers[i]->identity();
            l.chain = chain;
            l.seat  = [this](const Node& who) -> std::optional<std::uint32_t> {
                const auto at = committee.seat(who);
                if (!at) return std::nullopt;
                return std::uint32_t(*at);
            };
            return l;
        };
        HostConfig a;
        a.index = 0;
        a.link  = link(0);
        dialer  = std::make_unique<Host>(std::move(a));
        HostConfig b;
        b.index  = 1;
        b.link   = link(1);
        acceptor = std::make_unique<Host>(std::move(b));
        (void)dialer->listen_bind();
        port = acceptor->listen_bind();
    }
    // Seconds seat 0 took, and whether it got a link, within `deadline_ms`. The
    // acceptor's side is swept alongside, as its driver would.
    std::pair<double, std::size_t> dial(int deadline_ms) {
        std::atomic<bool> done{false};
        std::thread       other([&] {
            while (!done.load()) {
                acceptor->sweep({});
                std::this_thread::sleep_for(10ms);
            }
        });
        const auto t0 = std::chrono::steady_clock::now();
        const auto n  = dialer->connect_mesh({{1, {"127.0.0.1", port}}}, deadline_ms);
        const double s = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
        done = true;
        other.join();
        return {s, n};
    }
};

}  // namespace

int main() {
    std::printf("============ node — a stranger cannot hold the door ============\n");
    const auto root  = std::filesystem::temp_directory_path() / ("acceptor-" + std::to_string(::getpid()));
    const double bound = kHandshakeMs / 1000.0;
    {
        Pair p(root / "control");
        const auto [s, n] = p.dial(8000);
        check(n == 1 && s < 2.0, "control: a link in " + std::to_string(s) + " s");
    }
    {
        Pair              p(root / "trickle");
        std::atomic<bool> stop{false};
        std::atomic<bool> cut{false};
        std::thread       t([&] {
            const int fd = stranger(p.port, "127.0.0.2");
            const std::uint8_t head[4] = {0, 0, 0x3e, 0x80};  // 16000, under the 16 KiB cap
            (void)::send(fd, head, 4, MSG_NOSIGNAL);
            const auto began = std::chrono::steady_clock::now();
            while (!stop.load()) {
                const std::uint8_t b = 0;
                (void)::send(fd, &b, 1, MSG_NOSIGNAL);
                if (closed_within(fd, 1500ms)) {
                    cut = std::chrono::steady_clock::now() - began < std::chrono::milliseconds(kHandshakeMs + 1500);
                    break;
                }
            }
            ::close(fd);
        });
        std::this_thread::sleep_for(200ms);
        const auto [s, n] = p.dial(12000);
        check(n == 1 && s < 2.0, "[A] one trickling stranger: a link in " + std::to_string(s) + " s");
        std::this_thread::sleep_for(std::chrono::milliseconds(kHandshakeMs + 1600));
        stop = true;
        t.join();
        check(cut.load(), "[A] and the stranger was cut off at the greeting's deadline, trickle or not");
    }
    {
        Pair             p(root / "silent");
        std::vector<int> fds;
        for (int i = 0; i < 12; ++i) fds.push_back(stranger(p.port, "127.0.0.3"));
        std::this_thread::sleep_for(200ms);
        std::size_t shut = 0;
        for (int fd : fds)
            if (closed_within(fd, 50ms)) ++shut;
        check(shut == 12 - kHandshakesPerSource, "[B] of 12 silent strangers from one address, " +
                                                     std::to_string(12 - shut) + " hold a greeting and " +
                                                     std::to_string(shut) + " were closed at once");
        const auto [s, n] = p.dial(8000);
        check(n == 1 && s < 2.0, "[B] and a validator from another address has a link in " + std::to_string(s) + " s");
        for (int fd : fds) ::close(fd);
    }
    {
        Pair             p(root / "crowd");
        std::vector<int> fds;
        for (int i = 0; i < 20; ++i) fds.push_back(stranger(p.port, "127.0.1." + std::to_string(10 + i)));
        std::this_thread::sleep_for(200ms);
        const auto [s, n] = p.dial(12000);
        check(n == 1 && s < bound + 1.5,
              "[C] 20 silent strangers from 20 addresses fill every slot; the link came when their "
              "greetings expired, in " + std::to_string(s) + " s (deadline " + std::to_string(bound) + " s)");
        for (int fd : fds) ::close(fd);
    }
    std::filesystem::remove_all(root);
    std::printf("-----------------------------------------------------------------\n");
    if (g_fail) { std::printf("==== node ACCEPTOR: FAIL (%d) ====\n", g_fail); return 1; }
    std::printf("==== node ACCEPTOR: PASS — a greeting has one deadline, and the door is never held ====\n");
    return 0;
}
