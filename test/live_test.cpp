// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// live_test.cpp — a network of validators that imported a chain, run to see it
// continue: the anchor, the proposer windows, one seat down, a seat that
// imported something else, and a seat that stopped and came back.
//
// Every validator here is the daemon's own composition — keys a Signer made
// and published, a committee read from those lines, a Host on a real loopback
// socket greeting its peers with the post-quantum handshake, an Engine with its
// journal and ledger on disk — driven on its own thread. Only the chain is a
// stand-in (fake_chain.hpp), because what is under test is the engine and not
// the EVM; scripts/live.sh runs the same scenarios as processes over cevm and a
// real export.
//
// The history each validator imports is Zoo mainnet's, as a tip: height 799,
// 0xd6f92941…f72b8, the tip `zood --import-chain-data zoo-mainnet-200200.rlp`
// reaches.

#include "fake_chain.hpp"
#include "lux/node/engine.hpp"
#include "lux/node/host.hpp"
#include "lux/node/journal.hpp"
#include "lux/node/signer.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

using namespace lux::node;
using namespace std::chrono_literals;

namespace {

int g_fail = 0;
void check(bool ok, const std::string& what) {
    std::printf("  %s  %s\n", ok ? "ok  " : "FAIL", what.c_str());
    std::fflush(stdout);
    if (!ok) ++g_fail;
}

Id from_hex(const char* h) {
    Id id{};
    for (std::size_t i = 0; i < 32; ++i) {
        unsigned v = 0;
        std::sscanf(h + 2 + 2 * i, "%2x", &v);
        id[i] = std::uint8_t(v);
    }
    return id;
}

std::string hex8(const Id& id) {
    char b[9];
    std::snprintf(b, sizeof b, "%02x%02x%02x%02x", id[0], id[1], id[2], id[3]);
    return b;
}

// Zoo mainnet's imported tip.
const Id            kZooTip    = from_hex("0xd6f92941bb2ac91dfd2443f32b0d93f2730e6cc81ddb2edd3f35720a9e1f72b8");
constexpr std::uint64_t kZooHeight = 799;
constexpr std::uint64_t kZooTime   = 1747000000;  // a time long before the test runs

constexpr auto kWindow = 400ms;

// A port nothing listens on: bound and let go.
std::uint16_t free_port() {
    const int   fd = ::socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in a{};
    a.sin_family      = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ::bind(fd, reinterpret_cast<sockaddr*>(&a), sizeof a);
    socklen_t len = sizeof a;
    ::getsockname(fd, reinterpret_cast<sockaddr*>(&a), &len);
    ::close(fd);
    return ntohs(a.sin_port);
}

struct Seat {
    std::uint32_t                      index = 0;
    std::filesystem::path              dir;
    std::unique_ptr<Signer>            signer;
    std::shared_ptr<test::Store>       store;
    std::uint16_t                      port = 0;
    std::unique_ptr<Host>              host;
    std::unique_ptr<Engine>            engine;
    std::mutex                         guard;
    std::thread                        driver;
    std::atomic<bool>                  stop{false};
    std::atomic<bool>                  running{false};

    std::mutex                         mu;  // guards what the driver records
    std::map<std::uint64_t, Id>        decided;
    std::map<std::uint64_t, std::uint64_t> slots;
    std::optional<std::pair<std::uint64_t, Id>> anchored;
    std::vector<std::string>           log;
};

class Cluster {
public:
    Cluster(const std::string& name, std::uint32_t n) : chain_{} {
        chain_.fill(0x20);
        chain_[0] = 0x0c;
        root_ = std::filesystem::temp_directory_path() / ("node-live-" + std::to_string(::getpid()) + "-" + name);
        std::filesystem::remove_all(root_);
        std::string text;
        for (std::uint32_t i = 0; i < n; ++i) {
            auto s    = std::make_unique<Seat>();
            s->index  = i;
            s->dir    = root_ / ("v" + std::to_string(i));
            s->signer = std::make_unique<Signer>(Signer::open(s->dir));
            s->port   = free_port();
            text += s->signer->publish(chain_) + "\n";
            seats_.push_back(std::move(s));
        }
        committee_ = Committee::read(text, chain_);
        for (std::uint32_t i = 0; i < n; ++i) peers_[i] = PeerAddr{"127.0.0.1", seats_[i]->port};
    }

    ~Cluster() {
        for (auto& s : seats_) stop(s->index);
        std::filesystem::remove_all(root_);
    }

    Seat&            seat(std::uint32_t i) { return *seats_[i]; }
    const Committee& committee() const { return committee_; }
    const Id&        chain() const { return chain_; }

    // Give seat `i` its imported history.
    void import(std::uint32_t i, const Id& tip) {
        seats_[i]->store = test::Store::imported(tip, kZooHeight, kZooTime);
        close_gate(seats_[i]->dir);  // what the daemon does before the chain reads an export
    }

    // Bind every listed seat, then let each meet the others on its own thread
    // and drive its engine until stopped.
    void start(const std::vector<std::uint32_t>& which) {
        for (auto i : which) {
            Seat& s = *seats_[i];
            HostConfig cfg;
            cfg.index      = i;
            cfg.port       = s.port;
            cfg.link.me    = s.signer->identity();
            cfg.link.chain = chain_;
            cfg.link.seat  = [this](const Node& who) -> std::optional<std::uint32_t> {
                const auto at = committee_.seat(who);
                if (!at) return std::nullopt;
                return std::uint32_t(*at);
            };
            s.host = std::make_unique<Host>(std::move(cfg));
            s.host->listen_bind();
            EngineConfig ec;
            ec.committee = committee_;
            ec.self      = s.signer->node();
            ec.sk        = s.signer->secret();
            ec.identity  = s.signer->identity();
            ec.chain     = chain_;
            ec.binding   = Binding::Transport;
            ec.window    = kWindow;
            ec.data      = s.dir;
            s.engine     = std::make_unique<Engine>(std::make_unique<test::FakeChain>(s.store), *s.host, s.guard,
                                                    std::move(ec));
        }
        for (auto i : which) {
            Seat& s = *seats_[i];
            s.stop  = false;
            s.running = true;
            s.driver = std::thread([this, &s] { drive(s); });
        }
    }

    void stop(std::uint32_t i) {
        Seat& s = *seats_[i];
        if (!s.running) return;
        s.stop = true;
        if (s.driver.joinable()) s.driver.join();
        s.engine.reset();
        s.host.reset();
        s.running = false;
    }

    // Wait until `ok` holds, polling, or `limit` passes.
    bool until(const std::function<bool()>& ok, std::chrono::milliseconds limit) {
        const auto end = std::chrono::steady_clock::now() + limit;
        while (std::chrono::steady_clock::now() < end) {
            if (ok()) return true;
            std::this_thread::sleep_for(50ms);
        }
        return ok();
    }

    bool reached(std::uint32_t i, std::uint64_t h) {
        const std::lock_guard<std::mutex> lock(seats_[i]->store->mu);
        return seats_[i]->store->height >= h;
    }

    // The accepted id at every height in [from, to], the same on every listed
    // seat — read off each seat's own chain.
    bool agree(const std::vector<std::uint32_t>& which, std::uint64_t from, std::uint64_t to) {
        for (std::uint64_t h = from; h <= to; ++h) {
            std::optional<Id> first;
            for (auto i : which) {
                const std::lock_guard<std::mutex> lock(seats_[i]->store->mu);
                const auto                        it = seats_[i]->store->at.find(h);
                if (it == seats_[i]->store->at.end()) return false;
                if (!first) first = it->second;
                else if (*first != it->second) return false;
            }
        }
        return true;
    }

    void dump(std::uint32_t i, std::size_t last = 12) {
        Seat& s = *seats_[i];
        const std::lock_guard<std::mutex> lock(s.mu);
        const std::size_t from = s.log.size() > last ? s.log.size() - last : 0;
        for (std::size_t k = from; k < s.log.size(); ++k) std::printf("      [%u] %s\n", i, s.log[k].c_str());
    }

private:
    void drive(Seat& s) {
        const std::map<std::uint32_t, PeerAddr> others = [&] {
            auto m = peers_;
            m.erase(s.index);
            return m;
        }();
        s.host->connect_mesh(others, 1500);
        auto met = std::chrono::steady_clock::now();
        while (!s.stop) {
            if (std::chrono::steady_clock::now() - met >= kWindow * 2) {
                s.host->sweep(others);
                met = std::chrono::steady_clock::now();
            }
            const Step pass = s.engine->step();
            if (!pass.events.empty()) {
                const std::lock_guard<std::mutex> lock(s.mu);
                for (const auto& e : pass.events) {
                    switch (e.what) {
                        case Event::What::Decided:
                            s.decided[e.height] = e.block;
                            s.slots[e.height]   = e.slot.value_or(0);
                            s.log.push_back("decided " + std::to_string(e.height) + " " + hex8(e.block) +
                                            " slot " + std::to_string(e.slot.value_or(0)) + " signers " +
                                            std::to_string(e.signers));
                            break;
                        case Event::What::Anchored:
                            s.anchored = std::make_pair(e.height, e.block);
                            s.log.push_back("anchored " + std::to_string(e.height) + " " + hex8(e.block));
                            break;
                        default:
                            s.log.push_back(e.text);
                    }
                }
            }
            if (pass.quiet && pass.events.empty()) std::this_thread::sleep_for(1ms);
        }
    }

    Id                                   chain_;
    std::filesystem::path                root_;
    std::vector<std::unique_ptr<Seat>>   seats_;
    Committee                            committee_;
    std::map<std::uint32_t, PeerAddr>    peers_;
};

std::vector<std::uint32_t> all(std::uint32_t n) {
    std::vector<std::uint32_t> v;
    for (std::uint32_t i = 0; i < n; ++i) v.push_back(i);
    return v;
}

}  // namespace

int main() {
    std::printf("====== node — a validator network continues an imported chain ======\n");
    std::printf("five seats import Zoo mainnet to height 799 and build 800, 801, ...\n\n");

    // [1] Five seats import the same export, anchor it, and build on it.
    {
        std::printf("[1] five seats, one export\n");
        Cluster c("five", 5);
        for (auto i : all(5)) c.import(i, kZooTip);
        c.start(all(5));
        const bool built = c.until([&] {
            for (auto i : all(5)) if (!c.reached(i, 806)) return false;
            return true;
        }, 60s);
        check(built, "[1] every seat reached height 806");
        bool anchored = true;
        for (auto i : all(5)) {
            const std::lock_guard<std::mutex> lock(c.seat(i).mu);
            anchored = anchored && c.seat(i).anchored && c.seat(i).anchored->first == kZooHeight &&
                       c.seat(i).anchored->second == kZooTip;
        }
        check(anchored, "[1] every seat anchored height 799 at Zoo mainnet's tip");
        check(c.agree(all(5), 800, 806), "[1] and all five accepted the same block at 800..806");
        for (auto i : all(5)) check(!gated(c.seat(i).dir), "[1] seat " + std::to_string(i) + "'s gate is lifted");
        if (!built) for (auto i : all(5)) c.dump(i);
    }

    // [2] One seat down: four of five certify, and the heights whose first
    // window belongs to the missing seat are built in the next one. Then the
    // seat comes back, lifts its gate on the anchor its peers hold, and
    // catches up.
    {
        std::printf("[2] five seats, one of them down\n");
        Cluster c("down", 5);
        const std::uint32_t down = 3;
        for (auto i : all(5)) c.import(i, kZooTip);
        std::vector<std::uint32_t> up{0, 1, 2, 4};
        // The heights where the missing seat holds the first window.
        std::vector<std::pair<Node, std::uint64_t>> w;
        for (const auto& m : c.committee().members()) w.emplace_back(m.node, m.weight);
        const Windower            windower(c.chain(), w);
        std::vector<std::uint64_t> its;
        for (std::uint64_t h = 800; h < 1000 && its.size() < 2; ++h)
            if (windower.expected(h, 0) == c.committee().members()[down].node) its.push_back(h);
        const std::uint64_t target = its.back() + 1;
        std::printf("  the missing seat leads slot 0 at heights %llu and %llu; running to %llu\n",
                    static_cast<unsigned long long>(its[0]), static_cast<unsigned long long>(its[1]),
                    static_cast<unsigned long long>(target));
        c.start(up);
        const bool built = c.until([&] {
            for (auto i : up) if (!c.reached(i, target)) return false;
            return true;
        }, 90s);
        check(built, "[2] four seats carried the chain to " + std::to_string(target));
        check(c.agree(up, 800, target), "[2] and agree at every height");
        {
            const std::lock_guard<std::mutex> lock(c.seat(0).mu);
            bool later = true;
            for (auto h : its) later = later && c.seat(0).slots.count(h) && c.seat(0).slots[h] >= 1;
            check(later, "[2] a height whose first window was the missing seat's was built in a later one");
        }
        if (!built) for (auto i : up) c.dump(i);

        c.start({down});
        const bool back = c.until([&] { return c.reached(down, target + 2) && c.agree({0, down}, 800, target + 2); },
                                  60s);
        check(back, "[2] the seat that was down came back, anchored, caught up, and went on with the others");
        check(!gated(c.seat(down).dir), "[2] its gate is lifted");
        if (!back) c.dump(down, 30);
    }

    // [3] A seat that imported a different tip cannot join the anchor, and
    // cannot stop the four that agree.
    {
        std::printf("[3] one seat imported another tip\n");
        Cluster c("stranger", 5);
        const std::uint32_t odd = 4;
        Id                  other = kZooTip;
        other[31] ^= 0x01;
        for (auto i : all(5)) c.import(i, i == odd ? other : kZooTip);
        c.start(all(5));
        std::vector<std::uint32_t> good{0, 1, 2, 3};
        const bool built = c.until([&] {
            for (auto i : good) if (!c.reached(i, 805)) return false;
            return true;
        }, 90s);
        check(built, "[3] the four that imported the same tip built to 805");
        check(c.agree(good, 800, 805), "[3] and agree");
        {
            const std::lock_guard<std::mutex> lock(c.seat(odd).mu);
            check(!c.seat(odd).anchored && c.seat(odd).decided.empty(), "[3] the odd seat anchored nothing and decided nothing");
        }
        check(!c.reached(odd, 800) && gated(c.seat(odd).dir), "[3] its chain stayed at its own tip, gated");
        c.stop(odd);
        auto j = Journal::open(c.seat(odd).dir / "votes");
        const auto anchor = j.standing(Slot{c.chain(), kZooHeight, 0});
        const auto claim  = anchor ? read(*anchor) : std::nullopt;
        check(j.size() == 1 && claim && claim->kind == Kind::Anchor && claim->block == other,
              "[3] its journal holds one statement: its anchor on its own tip, and no vote");
        if (!built) for (auto i : all(5)) c.dump(i);
    }

    // [4] A seat stops and comes back: its journal holds it to what it signed,
    // its peers meet it again, and it takes the blocks it missed on their
    // certificates.
    {
        std::printf("[4] a seat restarts\n");
        Cluster c("restart", 5);
        for (auto i : all(5)) c.import(i, kZooTip);
        c.start(all(5));
        const bool first = c.until([&] { return c.reached(2, 803); }, 60s);
        check(first, "[4] seat 2 reached 803");
        c.stop(2);
        std::vector<std::uint32_t> rest{0, 1, 3, 4};
        const bool on = c.until([&] {
            for (auto i : rest) if (!c.reached(i, 808)) return false;
            return true;
        }, 60s);
        check(on, "[4] the other four went on to 808 without it");
        c.start({2});
        const bool back = c.until([&] { return c.reached(2, 811) && c.agree(all(5), 800, 811); }, 60s);
        check(back, "[4] seat 2 caught up on certificates and went on to 811 with the others");
        if (!back) c.dump(2, 30);
        c.stop(2);
        // One statement a height, before and after the restart.
        auto j = Journal::open(c.seat(2).dir / "votes");
        check(j.size() >= 1 && j.standing(Slot{c.chain(), kZooHeight, 0}).has_value(),
              "[4] its journal reopens whole, anchor included");
    }

    std::printf("--------------------------------------------------------------------\n");
    if (g_fail) { std::printf("==== node LIVE: FAIL (%d) ====\n", g_fail); return 1; }
    std::printf("==== node LIVE: PASS — an imported chain continues, and one seat cannot stop it ====\n");
    return 0;
}
