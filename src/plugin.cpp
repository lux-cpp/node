// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco

#include "lux/node/plugin.hpp"

#include "lux/zap/client.hpp"
#include "lux/zap/wire.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstdlib>
#include <cstring>
#include <stdexcept>

extern char** environ;

namespace lux::node::plugin {
namespace {

// A socket the plugin can reach us on, and the text it is told to dial.
//
// TCP UNLESS ASKED, which is Go's rule and is not a preference. A unix socket is
// the better transport — no TCP stack, no ephemeral-port exhaustion,
// filesystem-namespaced — and Go's NewListener offers it under
// LUXD_VM_UNIX_SOCKET=1 for one reason: a plugin built against an older
// api/zap infers the network from the address and dials "tcp" on ANY of them.
// Measured here, against the shipped EVM plugin:
//
//   evm plugin: failed to connect to runtime: dial tcp:
//   address /tmp/luxd-vm-SerAeL/vm.sock: missing port in address
//
// So the socket is opt-in on the same env key Go uses, and a host that turns it
// on is saying it knows every plugin it runs was rebuilt.
struct Door {
    int         fd   = -1;
    std::string addr;      // what the plugin is told to dial
    std::string dir;       // the temp dir a unix socket lives in, if any
};

void unlink_dir(const std::string& dir) {
    if (dir.empty()) return;
    ::unlink((dir + "/vm.sock").c_str());
    ::rmdir(dir.c_str());
}

Door open_unix() {
    Door d;
    char tmpl[] = "/tmp/luxd-vm-XXXXXX";
    const char* made = ::mkdtemp(tmpl);
    if (!made) return d;
    d.dir  = made;
    d.addr = d.dir + "/vm.sock";

    d.fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (d.fd < 0) { unlink_dir(d.dir); d.dir.clear(); return d; }
    sockaddr_un a{};
    a.sun_family = AF_UNIX;
    std::strncpy(a.sun_path, d.addr.c_str(), sizeof(a.sun_path) - 1);
    if (::bind(d.fd, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0 || ::listen(d.fd, 1) != 0) {
        ::close(d.fd);
        d.fd = -1;
        unlink_dir(d.dir);
        d.dir.clear();
    }
    return d;
}

Door open_tcp() {
    Door d;
    d.fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (d.fd < 0) return d;
    sockaddr_in a{};
    a.sin_family      = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port        = 0;
    socklen_t len     = sizeof(a);
    if (::bind(d.fd, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0 || ::listen(d.fd, 1) != 0 ||
        ::getsockname(d.fd, reinterpret_cast<sockaddr*>(&a), &len) != 0) {
        ::close(d.fd);
        d.fd = -1;
        return d;
    }
    d.addr = "127.0.0.1:" + std::to_string(ntohs(a.sin_port));
    return d;
}

// Connect to what the plugin reported. A path is a unix socket; anything with a
// colon is host:port — the same inference Go's api/zap Dial makes.
int reach(const std::string& addr) {
    if (!addr.empty() && addr.front() == '/') {
        const int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0) return -1;
        sockaddr_un a{};
        a.sun_family = AF_UNIX;
        std::strncpy(a.sun_path, addr.c_str(), sizeof(a.sun_path) - 1);
        if (::connect(fd, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0) { ::close(fd); return -1; }
        return fd;
    }
    const auto colon = addr.rfind(':');
    if (colon == std::string::npos) return -1;
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port   = htons(static_cast<std::uint16_t>(std::atoi(addr.c_str() + colon + 1)));
    if (::inet_pton(AF_INET, addr.substr(0, colon).c_str(), &a.sin_addr) != 1 ||
        ::connect(fd, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0) {
        ::close(fd);
        return -1;
    }
    return fd;
}

Id to_id(const std::vector<std::uint8_t>& b) {
    Id id{};
    if (b.size() == id.size()) std::copy(b.begin(), b.end(), id.begin());
    return id;
}

}  // namespace

// One block, as the far side described it. Everything about it came over the
// wire; nothing about it is computed here, which is the point of the boundary.
class Remote final : public Block {
public:
    Remote(Chain& on, Id id, Id parent, std::uint64_t height, std::vector<std::uint8_t> bytes)
        : on_(on), id_(id), parent_(parent), height_(height), bytes_(std::move(bytes)) {}

    Id                            id() const override { return id_; }
    Id                            parent() const override { return parent_; }
    std::uint64_t                 height() const override { return height_; }
    std::span<const std::uint8_t> bytes() const override { return bytes_; }

    // THE ROOT DOES NOT CROSS THIS BOUNDARY. Go's BlockResponse carries id,
    // parent, bytes, height and timestamp — and no execution state root, because
    // Go's own proposervm returns ids.Empty for it and a Go validator signs a
    // transport binding rather than an executed one. A plugin-hosted chain
    // therefore has to be driven with Binding::Transport; answering anything
    // else here would be inventing a root nobody computed.
    Id   root() const override { return kEmptyId; }
    bool verify() override;
    void accept() override;
    void reject() override;

private:
    Chain&                    on_;
    Id                        id_{}, parent_{};
    std::uint64_t             height_ = 0;
    std::vector<std::uint8_t> bytes_;
};

struct Chain::State {
    lux::zap::ZapClient link;
    ::pid_t             child = -1;
    std::string         dir;          // the bootstrap socket's temp dir, if any
    Start               with;
    Id                  accepted{};
    std::uint64_t       height = 0;

    // One call, with the two refusals a caller cannot tell apart from outside
    // told apart here: the transport failed, or the chain said no and said why.
    std::vector<std::uint8_t> call(std::uint8_t msg, const lux::zap::Writer& body,
                                   const char* what) {
        const auto r = link.call(msg, body);
        if (r.is_error) throw std::runtime_error(std::string(what) + ": " + r.err_str);
        if (lux::zap::strip_flags(r.resp_type) != msg)
            throw std::runtime_error(std::string(what) + ": answered a different message");
        return r.payload;
    }
};

Chain::Chain() : st_(std::make_unique<State>()) {}

Chain::~Chain() {
    st_->link.close();
    if (st_->child > 0) {
        ::kill(st_->child, SIGTERM);
        int status = 0;
        ::waitpid(st_->child, &status, 0);
    }
    unlink_dir(st_->dir);
}

std::unique_ptr<Chain> Chain::start(const std::filesystem::path& path, const Start& with) {
    auto chain     = std::unique_ptr<Chain>(new Chain());
    chain->st_->with = with;

    const char* socket_ok = std::getenv("LUXD_VM_UNIX_SOCKET");
    Door        door;
    if (socket_ok && std::string(socket_ok) == "1") door = open_unix();
    if (door.fd < 0) door = open_tcp();
    if (door.fd < 0) throw std::runtime_error("plugin: cannot bind a bootstrap listener");
    chain->st_->dir = door.dir;

    // The environment Go gives a plugin: the parent's, plus the transport and
    // the address to dial back on under BOTH spellings of the key.
    const std::string transport = "VM_TRANSPORT=zap";
    const std::string engine    = "VM_RUNTIME_ENGINE_ADDR=" + door.addr;
    const std::string legacy    = "LUX_VM_RUNTIME_ENGINE_ADDR=" + door.addr;

    std::vector<char*> env;
    for (char** e = environ; *e; ++e) env.push_back(*e);
    env.push_back(const_cast<char*>(transport.c_str()));
    env.push_back(const_cast<char*>(engine.c_str()));
    env.push_back(const_cast<char*>(legacy.c_str()));
    env.push_back(nullptr);

    const std::string exe = path.string();
    char* const       argv[] = {const_cast<char*>(exe.c_str()), nullptr};

    const ::pid_t pid = ::fork();
    if (pid < 0) { ::close(door.fd); throw std::runtime_error("plugin: fork failed"); }
    if (pid == 0) {
        ::execve(exe.c_str(), argv, env.data());
        _exit(127);  // exec failed; the parent sees the bootstrap time out
    }
    chain->st_->child = pid;

    // The plugin's one message: [len][protocol][address].
    timeval tv{30, 0};
    ::setsockopt(door.fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    const int back = ::accept(door.fd, nullptr, nullptr);
    ::close(door.fd);
    if (back < 0) throw std::runtime_error("plugin: it never dialed back on " + door.addr);

    std::uint8_t head[8];
    if (!lux::zap::read_exact(back, head, sizeof head)) {
        ::close(back);
        throw std::runtime_error("plugin: no handshake header");
    }
    const std::uint32_t len =
        (std::uint32_t(head[0]) << 24) | (std::uint32_t(head[1]) << 16) |
        (std::uint32_t(head[2]) << 8) | std::uint32_t(head[3]);
    const std::uint32_t protocol =
        (std::uint32_t(head[4]) << 24) | (std::uint32_t(head[5]) << 16) |
        (std::uint32_t(head[6]) << 8) | std::uint32_t(head[7]);
    if (len < 4 || len > 4096) { ::close(back); throw std::runtime_error("plugin: handshake length"); }
    std::vector<std::uint8_t> addr(len - 4);
    if (!addr.empty() && !lux::zap::read_exact(back, addr.data(), addr.size())) {
        ::close(back);
        throw std::runtime_error("plugin: no handshake address");
    }
    // AN EXACT MATCH, as Go demands, and BEFORE the acknowledgement — a plugin
    // one protocol off does not differ in a way either side can detect later,
    // and the closed connection is how it learns it was refused.
    if (protocol != kProtocol) {
        ::close(back);
        throw std::runtime_error("plugin: speaks RPCChainVM protocol " + std::to_string(protocol) +
                                 ", this host speaks " + std::to_string(kProtocol));
    }

    // AND THE ACK, one byte, which the plugin waits for before it serves.
    // Closing the connection here instead is an EOF on its side — measured:
    // "evm plugin: failed to read handshake ack: EOF", and then it exits and
    // the address it just reported answers nothing.
    const std::uint8_t ok = 1;
    const bool         acked = lux::zap::write_exact(back, &ok, 1);
    ::close(back);
    if (!acked) throw std::runtime_error("plugin: could not acknowledge the handshake");

    const std::string where(addr.begin(), addr.end());
    const int         fd = reach(where);
    if (fd < 0) throw std::runtime_error("plugin: cannot reach it at " + where);
    std::string err;
    if (!chain->st_->link.attach(fd, err)) throw std::runtime_error("plugin: " + err);

    // Initialize, field for field with zapwire.InitializeRequest. The two
    // trailing server addresses are empty: those are handles onto live node
    // state (shared memory, validator state) that this host does not serve yet,
    // and Go's own decoder treats an absent one as "the capability is not
    // wired" rather than as an error.
    lux::zap::Writer w;
    w.write_u32(with.network);
    w.write_bytes(with.chain.data(), with.chain.size());
    w.write_bytes(with.node.data(), with.node.size());
    w.write_bytes(nullptr, 0);                      // PublicKey
    w.write_bytes(with.x.data(), with.x.size());
    w.write_bytes(with.c.data(), with.c.size());
    w.write_bytes(with.asset.data(), with.asset.size());
    w.write_string(with.data_dir);
    w.write_bytes(with.genesis);
    w.write_bytes(with.upgrade);
    w.write_bytes(with.config);
    w.write_string("");                             // DBServerAddr
    w.write_string("");                             // ServerAddr
    w.write_string("");                             // AtomicServerAddr
    w.write_bytes(nullptr, 0);                      // DChainID
    w.write_string("");                             // ValidatorServerAddr

    const auto        payload = chain->st_->call(kInitialize, w, "initialize");
    lux::zap::Reader  r(payload.data(), payload.size());
    std::vector<std::uint8_t> last, parent, bytes;
    std::uint64_t             height = 0;
    std::int64_t              stamp  = 0;
    if (!r.read_bytes(last) || !r.read_bytes(parent) || !r.read_u64(height) ||
        !r.read_bytes(bytes) || !r.read_i64(stamp))
        throw std::runtime_error("initialize: the answer is not an InitializeResponse");

    chain->st_->accepted = to_id(last);
    chain->st_->height   = height;
    return chain;
}

Id          Chain::chain_id() const { return st_->with.chain; }
std::string Chain::alias() const { return st_->with.alias; }

Id            Chain::last_accepted() const { return st_->accepted; }
std::uint64_t Chain::last_accepted_height() const { return st_->height; }

namespace {

// Go's BlockResponse: id, parent, bytes, height, timestamp, verify-with-context,
// and an error byte that is ErrorUnspecified (0) when there is a block.
struct Answer {
    std::vector<std::uint8_t> id, parent, bytes;
    std::uint64_t             height = 0;
    std::uint8_t              err    = 0;
    bool                      ok     = false;
};

Answer read_block(const std::vector<std::uint8_t>& payload) {
    Answer           a;
    lux::zap::Reader r(payload.data(), payload.size());
    std::int64_t     stamp = 0;
    bool             with_context = false;
    if (!r.read_bytes(a.id) || !r.read_bytes(a.parent) || !r.read_bytes(a.bytes) ||
        !r.read_u64(a.height) || !r.read_i64(stamp) || !r.read_bool(with_context) ||
        !r.read_u8(a.err))
        return a;
    a.ok = true;
    return a;
}

}  // namespace

std::shared_ptr<Block> Chain::build() {
    lux::zap::Writer w;
    const auto       a = read_block(st_->call(kBuildBlock, w, "build"));
    // NOTHING TO BUILD IS "NO", NOT A FAILURE — the house form, and Go's: an
    // empty mempool answers with an error code, not a broken link.
    if (!a.ok || a.err != 0) return nullptr;
    return std::make_shared<Remote>(*this, to_id(a.id), to_id(a.parent), a.height, a.bytes);
}

std::shared_ptr<Block> Chain::parse(std::span<const std::uint8_t> bytes) {
    lux::zap::Writer w;
    w.write_bytes(bytes.data(), bytes.size());
    const auto a = read_block(st_->call(kParseBlock, w, "parse"));
    if (!a.ok || a.err != 0) return nullptr;
    return std::make_shared<Remote>(*this, to_id(a.id), to_id(a.parent), a.height, a.bytes);
}

std::shared_ptr<Block> Chain::get(const Id& id) const {
    lux::zap::Writer w;
    w.write_bytes(id.data(), id.size());
    const auto a = read_block(st_->call(kGetBlock, w, "get"));
    if (!a.ok || a.err != 0) return nullptr;
    return std::make_shared<Remote>(const_cast<Chain&>(*this), to_id(a.id), to_id(a.parent),
                                    a.height, a.bytes);
}

void Chain::prefer(const Id& id) {
    lux::zap::Writer w;
    w.write_bytes(id.data(), id.size());
    (void)st_->call(kSetPreference, w, "prefer");
}

void Chain::enter(Phase p) {
    lux::zap::Writer w;
    w.write_u8(static_cast<std::uint8_t>(p));
    const auto payload = st_->call(kSetState, w, "set state");
    // The answer is the tip as it stands after the change, which is how a node
    // learns where a chain got to while it was bootstrapping.
    lux::zap::Reader          r(payload.data(), payload.size());
    std::vector<std::uint8_t> last, parent, bytes;
    std::uint64_t             height = 0;
    std::int64_t              stamp  = 0;
    if (r.read_bytes(last) && r.read_bytes(parent) && r.read_u64(height) && r.read_bytes(bytes) &&
        r.read_i64(stamp) && last.size() == st_->accepted.size()) {
        st_->accepted = to_id(last);
        st_->height   = height;
    }
}

std::string Chain::version() const {
    lux::zap::Writer w;
    const auto       payload = st_->call(kVersion, w, "version");
    lux::zap::Reader r(payload.data(), payload.size());
    std::string      v;
    if (!r.read_string(v)) return {};
    return v;
}

bool Chain::healthy() const {
    lux::zap::Writer w;
    try {
        (void)st_->call(kHealth, w, "health");
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

bool Remote::verify() {
    lux::zap::Writer w;
    w.write_bytes(id_.data(), id_.size());
    try {
        (void)on_.st_->call(kBlockVerify, w, "verify");
        return true;
    } catch (const std::exception&) {
        // A REFUSAL, NOT AN ERROR. An honest node does not vote for a block its
        // chain rejected, and that is the whole of what false means here.
        return false;
    }
}

void Remote::accept() {
    lux::zap::Writer w;
    w.write_bytes(id_.data(), id_.size());
    (void)on_.st_->call(kBlockAccept, w, "accept");
    on_.st_->accepted = id_;
    on_.st_->height   = height_;
}

void Remote::reject() {
    lux::zap::Writer w;
    w.write_bytes(id_.data(), id_.size());
    (void)on_.st_->call(kBlockReject, w, "reject");
}

}  // namespace lux::node::plugin
