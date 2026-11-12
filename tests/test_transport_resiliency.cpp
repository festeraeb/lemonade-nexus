// Transport resiliency: the TCP 443 WebSocket rung (WssTunnel + the server's
// TransportBridge), path selection under one BoringTun session
// (TransportMux), and the cold-start race between UDP and WSS.
//
// Every test runs on loopback with real components: two UserspaceDataplane
// instances with real Noise sessions, the smoltcp netstack on both ends, a
// real TLS WebSocket listener with a verified certificate, and real HTTP
// streams. "UDP blocked" is a drop shim in the UDP path, not a host firewall.

#include <gtest/gtest.h>

#include <LemonadeNexus/Boringtun/UserspaceDataplane.hpp>
#include <LemonadeNexus/Network/TransportBridge.hpp>
#include <LemonadeNexus/Network/VirtualNetService.hpp>
#include <LemonadeNexus/Relay/RelayWire.hpp>
#include <LemonadeNexusSDK/TransportMux.hpp>
#include <LemonadeNexusSDK/WssTunnel.hpp>

#include "support/localhost_cert.hpp"

#include <httplib.h>
#include <sodium.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <cstdio>
#include <deque>
#include <filesystem>
#include <fstream>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using namespace std::chrono_literals;
using lnsdk::MuxPolicy;
using lnsdk::TransportMux;
using lnsdk::TransportPath;
using lnsdk::WssTunnel;
using nexus::boringtun::UserspaceDataplane;
using nexus::network::TransportBridge;
using nexus::network::VirtualNetService;
using Clock = std::chrono::steady_clock;

namespace {

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

struct Keypair {
    std::string pub_b64, priv_b64;
};

Keypair make_keypair() {
    unsigned char pk[crypto_box_PUBLICKEYBYTES];
    unsigned char sk[crypto_box_SECRETKEYBYTES];
    crypto_box_keypair(pk, sk);
    char pub[sodium_base64_ENCODED_LEN(32, sodium_base64_VARIANT_ORIGINAL)];
    char priv[sodium_base64_ENCODED_LEN(32, sodium_base64_VARIANT_ORIGINAL)];
    sodium_bin2base64(pub, sizeof(pub), pk, 32, sodium_base64_VARIANT_ORIGINAL);
    sodium_bin2base64(priv, sizeof(priv), sk, 32, sodium_base64_VARIANT_ORIGINAL);
    return {pub, priv};
}

int udp_socket_bound(uint16_t* port_out) {
    int s = ::socket(AF_INET, SOCK_DGRAM, 0);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ::bind(s, reinterpret_cast<sockaddr*>(&a), sizeof a);
    socklen_t len = sizeof a;
    ::getsockname(s, reinterpret_cast<sockaddr*>(&a), &len);
    timeval tv{0, 50 * 1000};
    ::setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    int big = 4 << 20;
    ::setsockopt(s, SOL_SOCKET, SO_RCVBUF, &big, sizeof big);
    ::setsockopt(s, SOL_SOCKET, SO_SNDBUF, &big, sizeof big);
    if (port_out) *port_out = ntohs(a.sin_port);
    return s;
}

sockaddr_in loopback(uint16_t port) {
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons(port);
    return a;
}

template <typename Pred>
bool wait_for(Pred pred, std::chrono::milliseconds limit) {
    const auto deadline = Clock::now() + limit;
    while (Clock::now() < deadline) {
        if (pred()) return true;
        std::this_thread::sleep_for(5ms);
    }
    return pred();
}

/// A UDP service that answers every datagram with the same bytes.
class UdpEcho {
public:
    UdpEcho() {
        sock_ = udp_socket_bound(&port_);
        thread_ = std::thread([this] {
            std::vector<char> buf(70000);
            while (run_) {
                sockaddr_in from{};
                socklen_t len = sizeof from;
                auto n = ::recvfrom(sock_, buf.data(), buf.size(), 0,
                                    reinterpret_cast<sockaddr*>(&from), &len);
                if (n > 0) {
                    ++count_;
                    ::sendto(sock_, buf.data(), n, 0, reinterpret_cast<sockaddr*>(&from), len);
                }
            }
        });
    }
    ~UdpEcho() {
        run_ = false;
        thread_.join();
        ::close(sock_);
    }
    uint16_t port() const { return port_; }
    int count() const { return count_; }

private:
    int sock_{-1};
    uint16_t port_{0};
    std::atomic<bool> run_{true};
    std::atomic<int> count_{0};
    std::thread thread_;
};

/// A UDP forwarder between a client and a fixed target that can drop all
/// traffic in both directions ("UDP blocked") and can record every datagram
/// it carries.
class UdpShim {
public:
    explicit UdpShim(uint16_t target_port) : target_(loopback(target_port)) {
        front_ = udp_socket_bound(&front_port_);
        back_ = udp_socket_bound(nullptr);
        up_ = std::thread([this] { pump_up(); });
        down_ = std::thread([this] { pump_down(); });
    }
    ~UdpShim() {
        run_ = false;
        up_.join();
        down_.join();
        ::close(front_);
        ::close(back_);
    }
    uint16_t port() const { return front_port_; }
    std::string endpoint() const { return "127.0.0.1:" + std::to_string(front_port_); }
    void set_blocked(bool blocked) { blocked_ = blocked; }
    uint64_t carried() const { return carried_; }
    void set_recording(bool on) { recording_ = on; }
    std::vector<std::vector<uint8_t>> recorded() const {
        std::lock_guard lock(rec_mtx_);
        return {rec_.begin(), rec_.end()};
    }

private:
    void record(const char* p, ssize_t n) {
        if (!recording_) return;
        std::lock_guard lock(rec_mtx_);
        rec_.emplace_back(p, p + n);
        if (rec_.size() > 200000) rec_.pop_front();
    }
    void pump_up() {
        std::vector<char> buf(70000);
        while (run_) {
            sockaddr_in from{};
            socklen_t len = sizeof from;
            auto n = ::recvfrom(front_, buf.data(), buf.size(), 0,
                                reinterpret_cast<sockaddr*>(&from), &len);
            if (n <= 0) continue;
            {
                std::lock_guard lock(client_mtx_);
                client_ = from;
                have_client_ = true;
            }
            if (blocked_) continue;
            record(buf.data(), n);
            ++carried_;
            ::sendto(back_, buf.data(), n, 0, reinterpret_cast<const sockaddr*>(&target_),
                     sizeof target_);
        }
    }
    void pump_down() {
        std::vector<char> buf(70000);
        while (run_) {
            auto n = ::recv(back_, buf.data(), buf.size(), 0);
            if (n <= 0 || blocked_) continue;
            sockaddr_in to{};
            {
                std::lock_guard lock(client_mtx_);
                if (!have_client_) continue;
                to = client_;
            }
            record(buf.data(), n);
            ++carried_;
            ::sendto(front_, buf.data(), n, 0, reinterpret_cast<sockaddr*>(&to), sizeof to);
        }
    }

    sockaddr_in target_;
    int front_{-1}, back_{-1};
    uint16_t front_port_{0};
    std::atomic<bool> run_{true}, blocked_{false}, recording_{false};
    std::atomic<uint64_t> carried_{0};
    std::mutex client_mtx_;
    sockaddr_in client_{};
    bool have_client_{false};
    mutable std::mutex rec_mtx_;
    std::deque<std::vector<uint8_t>> rec_;
    std::thread up_, down_;
};

/// A TCP forwarder that counts and records the bytes it carries. It sits
/// between a WSS client and the TLS listener to measure the rung's real
/// per-message overhead, and it sees only TLS records.
class TcpCounter {
public:
    explicit TcpCounter(uint16_t target) : target_(target) {
        lsock_ = ::socket(AF_INET, SOCK_STREAM, 0);
        int on = 1;
        ::setsockopt(lsock_, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
        auto a = loopback(0);
        ::bind(lsock_, reinterpret_cast<sockaddr*>(&a), sizeof a);
        ::listen(lsock_, 4);
        socklen_t len = sizeof a;
        ::getsockname(lsock_, reinterpret_cast<sockaddr*>(&a), &len);
        port_ = ntohs(a.sin_port);
        accept_ = std::thread([this] {
            int c = ::accept(lsock_, nullptr, nullptr);
            if (c < 0) return;
            int s = ::socket(AF_INET, SOCK_STREAM, 0);
            auto t = loopback(target_);
            if (::connect(s, reinterpret_cast<sockaddr*>(&t), sizeof t) != 0) {
                ::close(c);
                ::close(s);
                return;
            }
            int on = 1;
            ::setsockopt(c, IPPROTO_TCP, TCP_NODELAY, &on, sizeof on);
            ::setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &on, sizeof on);
            client_ = c;
            server_ = s;
            std::thread down([this] { pipe(server_, client_, &down_bytes_); });
            pipe(client_, server_, &up_bytes_);
            ::shutdown(client_, SHUT_RDWR);
            down.join();
        });
    }
    ~TcpCounter() {
        ::shutdown(lsock_, SHUT_RDWR);
        ::close(lsock_);
        if (client_ >= 0) ::shutdown(client_, SHUT_RDWR);
        if (server_ >= 0) ::shutdown(server_, SHUT_RDWR);
        accept_.join();
        if (client_ >= 0) ::close(client_);
        if (server_ >= 0) ::close(server_);
    }
    uint16_t port() const { return port_; }
    uint64_t up_bytes() const { return up_bytes_; }
    uint64_t down_bytes() const { return down_bytes_; }
    std::string seen() const {
        std::lock_guard lock(seen_mtx_);
        return seen_;
    }

private:
    void pipe(int from, int to, std::atomic<uint64_t>* count) {
        char buf[65536];
        for (;;) {
            auto n = ::recv(from, buf, sizeof buf, 0);
            if (n <= 0) break;
            if (count) {
                *count += static_cast<uint64_t>(n);
                std::lock_guard lock(seen_mtx_);
                if (seen_.size() < (8u << 20)) seen_.append(buf, static_cast<size_t>(n));
            }
            if (::send(to, buf, n, MSG_NOSIGNAL) <= 0) break;
        }
        ::shutdown(to, SHUT_WR);
    }
    uint16_t target_;
    int lsock_{-1};
    std::atomic<int> client_{-1}, server_{-1};
    uint16_t port_{0};
    std::atomic<uint64_t> up_bytes_{0};
    std::atomic<uint64_t> down_bytes_{0};
    mutable std::mutex seen_mtx_;
    std::string seen_;
    std::thread accept_;
};

/// A TLS listener with the transport bridge on it, like the server's public
/// API listener, plus an ordinary API route to show that both share it.
class BridgeServer {
public:
    explicit BridgeServer(std::vector<std::pair<std::string, uint16_t>> targets,
                          TransportBridge::Limits limits = {})
        : bridge_(limits) {
        dir_ = std::filesystem::temp_directory_path() /
               ("ln-wss-" + std::to_string(::getpid()) + "-" + std::to_string(counter_++));
        std::filesystem::create_directories(dir_);
        cert_ = (dir_ / "cert.pem").string();
        key_ = (dir_ / "key.pem").string();
        if (!test_support::make_localhost_cert(cert_, key_)) return;
        server_ = std::make_unique<httplib::SSLServer>(cert_.c_str(), key_.c_str());
        server_->Get("/api/health", [](const httplib::Request&, httplib::Response& res) {
            res.set_content("ok", "text/plain");
        });
        for (const auto& [name, port] : targets) bridge_.add_target(name, port);
        bridge_.register_routes(*server_);
        port_ = static_cast<uint16_t>(server_->bind_to_any_port("127.0.0.1"));
        thread_ = std::thread([this] { server_->listen_after_bind(); });
        server_->wait_until_ready();
    }
    ~BridgeServer() {
        bridge_.stop();
        if (server_) server_->stop();
        if (thread_.joinable()) thread_.join();
        std::error_code ec;
        std::filesystem::remove_all(dir_, ec);
    }
    bool ok() const { return server_ && port_ != 0; }
    uint16_t port() const { return port_; }
    std::string url(const std::string& target, uint16_t port = 0) const {
        return "wss://localhost:" + std::to_string(port ? port : port_) +
               nexus::network::kTransportBridgePathPrefix + target;
    }
    WssTunnel::Options tunnel_options(const std::string& target, uint16_t port = 0) const {
        WssTunnel::Options o;
        o.url = url(target, port);
        o.ca_bundle_path = cert_;
        o.host_map = {{"localhost", "127.0.0.1"}};
        o.connect_timeout = 3000ms;
        return o;
    }
    TransportBridge& bridge() { return bridge_; }
    const std::string& cert() const { return cert_; }

private:
    static inline std::atomic<int> counter_{0};
    std::filesystem::path dir_;
    std::string cert_, key_;
    TransportBridge bridge_;
    std::unique_ptr<httplib::SSLServer> server_;
    uint16_t port_{0};
    std::thread thread_;
};

/// A plain TCP server that accepts and answers every request with an HTML
/// login page, like a captive portal or a transparent proxy.
class CaptivePortal {
public:
    CaptivePortal() {
        lsock_ = ::socket(AF_INET, SOCK_STREAM, 0);
        int on = 1;
        ::setsockopt(lsock_, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
        auto a = loopback(0);
        ::bind(lsock_, reinterpret_cast<sockaddr*>(&a), sizeof a);
        ::listen(lsock_, 16);
        socklen_t len = sizeof a;
        ::getsockname(lsock_, reinterpret_cast<sockaddr*>(&a), &len);
        port_ = ntohs(a.sin_port);
        thread_ = std::thread([this] {
            while (run_) {
                int c = ::accept(lsock_, nullptr, nullptr);
                if (c < 0) break;
                ++accepted_;
                char buf[4096];
                (void)::recv(c, buf, sizeof buf, 0);
                const char* page =
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 38\r\n"
                    "Connection: close\r\n\r\n<html><body>Please log in</body></html>";
                (void)::send(c, page, std::strlen(page), MSG_NOSIGNAL);
                ::close(c);
            }
        });
    }
    ~CaptivePortal() {
        run_ = false;
        ::shutdown(lsock_, SHUT_RDWR);
        ::close(lsock_);
        thread_.join();
    }
    uint16_t port() const { return port_; }
    int accepted() const { return accepted_; }

private:
    int lsock_{-1};
    uint16_t port_{0};
    std::atomic<bool> run_{true};
    std::atomic<int> accepted_{0};
    std::thread thread_;
};

/// A TLS WebSocket server that completes the upgrade and sends every binary
/// message straight back: a connected, upgraded socket that answers with
/// bytes, but not with a Noise handshake.
class EchoWsServer {
public:
    EchoWsServer() {
        dir_ = std::filesystem::temp_directory_path() / ("ln-wsecho-" + std::to_string(::getpid()));
        std::filesystem::create_directories(dir_);
        cert_ = (dir_ / "cert.pem").string();
        key_ = (dir_ / "key.pem").string();
        test_support::make_localhost_cert(cert_, key_);
        server_ = std::make_unique<httplib::SSLServer>(cert_.c_str(), key_.c_str());
        server_->WebSocket(std::string(nexus::network::kTransportBridgePathPrefix) + "dataplane",
                           [this](const httplib::Request&, httplib::ws::WebSocket& ws) {
                               std::string msg;
                               ws.set_read_timeout(200ms);
                               while (run_) {
                                   auto r = ws.read(msg);
                                   if (r == httplib::ws::ReadResult::Fail) break;
                                   if (r == httplib::ws::ReadResult::Binary && !msg.empty()) {
                                       ++echoed_;
                                       ws.send(msg.data(), msg.size());
                                   }
                               }
                           });
        port_ = static_cast<uint16_t>(server_->bind_to_any_port("127.0.0.1"));
        thread_ = std::thread([this] { server_->listen_after_bind(); });
        server_->wait_until_ready();
    }
    ~EchoWsServer() {
        run_ = false;
        server_->stop();
        thread_.join();
        std::error_code ec;
        std::filesystem::remove_all(dir_, ec);
    }
    WssTunnel::Options tunnel_options() const {
        WssTunnel::Options o;
        o.url = "wss://localhost:" + std::to_string(port_) +
                nexus::network::kTransportBridgePathPrefix + "dataplane";
        o.ca_bundle_path = cert_;
        o.host_map = {{"localhost", "127.0.0.1"}};
        return o;
    }
    int echoed() const { return echoed_; }

private:
    std::filesystem::path dir_;
    std::string cert_, key_;
    std::unique_ptr<httplib::SSLServer> server_;
    uint16_t port_{0};
    std::atomic<bool> run_{true};
    std::atomic<int> echoed_{0};
    std::thread thread_;
};

/// Two mesh endpoints on loopback: a "server" (dataplane + netstack +
/// HTTP service on its tunnel address) and a "client" (dataplane +
/// netstack, the server as its peer through a UDP shim). The client's
/// inbound packets pass the mux first.
struct MeshPair {
    static constexpr const char* kServerIp = "10.64.0.1";
    static constexpr const char* kClientIp = "10.64.0.2";

    Keypair server_keys = make_keypair();
    Keypair client_keys = make_keypair();
    UserspaceDataplane server_dp;
    VirtualNetService server_vnet;
    UserspaceDataplane client_dp;
    VirtualNetService client_vnet;
    httplib::Server api;
    uint16_t api_port{0};
    std::thread api_thread;
    std::unique_ptr<UdpShim> shim;
    std::atomic<TransportMux*> mux{nullptr};

    explicit MeshPair(std::function<void(httplib::Server&)> routes) {
        routes(api);
        api_port = static_cast<uint16_t>(api.bind_to_any_port("127.0.0.1"));
        api_thread = std::thread([this] { api.listen_after_bind(); });

        server_vnet.start();
        server_dp.set_inbound_handler(
            [this](std::span<const uint8_t> p) { server_vnet.deliver_inbound_ip_packet(p); });
        server_vnet.set_outbound_sink(
            [this](std::span<const uint8_t> p) { server_dp.send_outbound_ip_packet(p); });
        (void)server_dp.start({server_keys.priv_b64, server_keys.pub_b64, 0, 2});
        server_dp.add_local_ip(0x0A400001u);
        server_vnet.add_local_ip("10.64.0.1/10");
        (void)server_dp.add_peer(client_keys.pub_b64, "10.64.0.2/32", "");
        (void)server_vnet.add_tcp_forward("10.64.0.1", 80,
                                          "tcp:127.0.0.1:" + std::to_string(api_port));

        shim = std::make_unique<UdpShim>(server_dp.bound_port());

        client_vnet.start();
        client_dp.set_inbound_handler([this](std::span<const uint8_t> p) {
            if (auto* m = mux.load(); m && m->observe_inbound(p)) return;
            client_vnet.deliver_inbound_ip_packet(p);
        });
        client_vnet.set_outbound_sink(
            [this](std::span<const uint8_t> p) { client_dp.send_outbound_ip_packet(p); });
        (void)client_dp.start({client_keys.priv_b64, client_keys.pub_b64, 0, 2});
        client_dp.add_local_ip(0x0A400002u);
        client_vnet.add_local_ip("10.64.0.2/10");
        // Persistent keepalive 0: the test controls every packet the client
        // originates, so a background keepalive does not mask a dead path.
        (void)client_dp.add_peer(server_keys.pub_b64, "10.64.0.0/10", shim->endpoint(), 0);
    }

    ~MeshPair() {
        mux.store(nullptr);
        client_dp.stop();
        server_dp.stop();
        client_vnet.stop();
        server_vnet.stop();
        shim.reset();
        api.stop();
        if (api_thread.joinable()) api_thread.join();
    }

    TransportMux::Options mux_options(const WssTunnel::Options& wss) const {
        TransportMux::Options o;
        o.peer_pubkey = server_keys.pub_b64;
        o.udp_endpoint = shim->endpoint();
        o.wss = wss;
        o.own_ip = kClientIp;
        o.peer_ip = kServerIp;
        o.establish_timeout = 8000ms;
        return o;
    }

    uint16_t egress() { return client_vnet.add_tcp_egress(kServerIp, 80, kClientIp); }
};

std::string get_once(uint16_t port, const std::string& path) {
    httplib::Client c("127.0.0.1", port);
    c.set_connection_timeout(5, 0);
    c.set_read_timeout(5, 0);
    for (int i = 0; i < 25; ++i) {
        if (auto r = c.Get(path); r && r->status == 200) return r->body;
        std::this_thread::sleep_for(100ms);
    }
    return {};
}

}  // namespace

// ===========================================================================
// MuxPolicy: deterministic path decisions
// ===========================================================================

class MuxPolicyTest : public ::testing::Test {
protected:
    MuxPolicy::Timing timing() {
        MuxPolicy::Timing t;
        t.probe_interval = 100ms;
        t.miss_limit = 4;
        t.hold_down = 2000ms;
        t.trial_window = 500ms;
        t.trial_backoff_min = 1000ms;
        t.trial_backoff_max = 4000ms;
        return t;
    }
    Clock::time_point t0 = Clock::now();
};

TEST_F(MuxPolicyTest, LiveUdpStays) {
    MuxPolicy p(timing());
    p.install(TransportPath::Udp, t0);
    for (int i = 1; i <= 50; ++i) {
        const auto now = t0 + std::chrono::milliseconds(100 * i);
        p.on_reply(TransportPath::Udp, now);
        EXPECT_EQ(p.decide(now, true), MuxPolicy::Action::None);
    }
    EXPECT_EQ(p.active(), TransportPath::Udp);
}

TEST_F(MuxPolicyTest, DeadUdpMovesToWarmWssAfterMissLimit) {
    MuxPolicy p(timing());
    p.install(TransportPath::Udp, t0);
    p.on_reply(TransportPath::Udp, t0 + 100ms);
    EXPECT_EQ(p.decide(t0 + 400ms, true), MuxPolicy::Action::None);  // 300 ms of silence
    EXPECT_EQ(p.decide(t0 + 500ms, true), MuxPolicy::Action::MoveToWss);
    EXPECT_EQ(p.active(), TransportPath::Wss);
}

TEST_F(MuxPolicyTest, DeadUdpWithoutStandbyStays) {
    MuxPolicy p(timing());
    p.install(TransportPath::Udp, t0);
    EXPECT_EQ(p.decide(t0 + 5000ms, false), MuxPolicy::Action::None);
    EXPECT_EQ(p.active(), TransportPath::Udp);
}

TEST_F(MuxPolicyTest, AReplyOnTheOtherRungDoesNotKeepTheActiveRungAlive) {
    MuxPolicy p(timing());
    p.install(TransportPath::Udp, t0);
    p.on_reply(TransportPath::Wss, t0 + 350ms);
    EXPECT_EQ(p.decide(t0 + 400ms, true), MuxPolicy::Action::MoveToWss);
}

TEST_F(MuxPolicyTest, HoldDownThenTryUdpThenKeepIt) {
    MuxPolicy p(timing());
    p.install(TransportPath::Udp, t0);
    ASSERT_EQ(p.decide(t0 + 400ms, true), MuxPolicy::Action::MoveToWss);
    // Udp answers again at once, but the hold-down keeps Wss.
    for (int i = 5; i < 24; ++i) {
        const auto now = t0 + std::chrono::milliseconds(100 * i);
        p.on_reply(TransportPath::Wss, now);
        EXPECT_EQ(p.decide(now, true), MuxPolicy::Action::None) << i;
    }
    const auto at = t0 + 2400ms;
    p.on_reply(TransportPath::Wss, at);
    ASSERT_EQ(p.decide(at, true), MuxPolicy::Action::TryUdp);
    EXPECT_TRUE(p.trying());
    p.on_reply(TransportPath::Udp, at + 30ms);
    EXPECT_EQ(p.decide(at + 40ms, true), MuxPolicy::Action::KeepUdp);
    EXPECT_EQ(p.active(), TransportPath::Udp);
    EXPECT_FALSE(p.trying());
}

TEST_F(MuxPolicyTest, FailedTryGoesBackToWssAndBacksOff) {
    MuxPolicy p(timing());
    p.install(TransportPath::Wss, t0);
    auto now = t0;
    auto tick = [&](std::chrono::milliseconds step) {
        now += step;
        p.on_reply(TransportPath::Wss, now);
        return p.decide(now, true);
    };
    while (tick(100ms) != MuxPolicy::Action::TryUdp) ASSERT_LT(now - t0, 10s);
    const auto first_try = now;
    MuxPolicy::Action a;
    while ((a = tick(100ms)) == MuxPolicy::Action::None) ASSERT_LT(now - first_try, 2s);
    EXPECT_EQ(a, MuxPolicy::Action::BackToWss);
    EXPECT_GE(now - first_try, 500ms);
    // The next try waits for the hold-down (2 s) since the move back.
    const auto back = now;
    while (tick(100ms) != MuxPolicy::Action::TryUdp) ASSERT_LT(now - back, 10s);
    EXPECT_GE(now - back, 2000ms);
}

TEST_F(MuxPolicyTest, ClosedWssMovesToUdpAtOnce) {
    MuxPolicy p(timing());
    p.install(TransportPath::Wss, t0);
    p.on_reply(TransportPath::Wss, t0 + 10ms);
    EXPECT_EQ(p.decide(t0 + 20ms, false), MuxPolicy::Action::MoveToUdp);
    EXPECT_EQ(p.active(), TransportPath::Udp);
}

// ===========================================================================
// MTU across rungs
// ===========================================================================

TEST(TransportMtu, PinnedToTheSmallestRungMeasuredFromTheEncoders) {
    // The relay's Data header, measured from the relay's own encoder.
    const std::vector<uint8_t> payload(100, 0xAB);
    const auto datagram = nexus::relay::make_relay_datagram(
        nexus::relay::RelayMsgType::Data, nexus::relay::SessionId{}, 1, payload);
    const auto relay_header = static_cast<uint32_t>(datagram.size() - payload.size());
    EXPECT_EQ(relay_header, nexus::relay::kRelayHeaderSize);

    // Udp only: 1500 - 28 - 32 = 1440, capped by the dataplane's 1420.
    EXPECT_EQ(lnsdk::pinned_mtu(1500, false, relay_header, 1420), 1420u);
    // With the 9103 relay rung: 1500 - 28 - 26 - 32 = 1414.
    EXPECT_EQ(lnsdk::pinned_mtu(1500, true, relay_header, 1420), 1414u);
    EXPECT_EQ(lnsdk::pinned_mtu(60, true, relay_header, 1420), 0u);
}

TEST(TransportMtu, WebSocketFrameOverhead) {
    EXPECT_EQ(WssTunnel::frame_overhead(100, true), 6u);
    EXPECT_EQ(WssTunnel::frame_overhead(1452, true), 8u);
    EXPECT_EQ(WssTunnel::frame_overhead(1452, false), 4u);
    EXPECT_EQ(WssTunnel::frame_overhead(70000, true), 14u);
}

// ===========================================================================
// WssTunnel + TransportBridge: framing
// ===========================================================================

TEST(WssFraming, OneDatagramIsOneMessageInOrderAndIntact) {
    ASSERT_GE(sodium_init(), 0);
    UdpEcho echo;
    BridgeServer srv({{"echo", echo.port()}});
    ASSERT_TRUE(srv.ok());

    uint16_t inner_port = 0;
    const int inner = udp_socket_bound(&inner_port);
    auto opts = srv.tunnel_options("echo");
    opts.inner_port = inner_port;
    WssTunnel tunnel;
    ASSERT_TRUE(tunnel.open(opts));
    ASSERT_TRUE(wait_for([&] { return tunnel.state() == WssTunnel::State::Open; }, 5s))
        << "failure " << int(tunnel.failure()) << " status " << tunnel.http_status();

    // Sizes across every WebSocket length encoding, the dataplane's largest
    // packet, and the IPv4 UDP maximum.
    const std::vector<size_t> sizes{1, 2, 125, 126, 127, 1452, 4096, 65535 - 28, 3, 1452};
    const auto to = loopback(tunnel.local_port());
    for (size_t i = 0; i < sizes.size(); ++i) {
        std::vector<uint8_t> d(sizes[i]);
        for (size_t j = 0; j < d.size(); ++j) d[j] = uint8_t(i * 31 + j);
        ASSERT_EQ(::sendto(inner, d.data(), d.size(), 0, reinterpret_cast<const sockaddr*>(&to),
                           sizeof to),
                  static_cast<ssize_t>(d.size()));
    }
    std::vector<uint8_t> buf(70000);
    for (size_t i = 0; i < sizes.size(); ++i) {
        ssize_t n = -1;
        const auto deadline = Clock::now() + 5s;
        while (n <= 0 && Clock::now() < deadline) n = ::recv(inner, buf.data(), buf.size(), 0);
        ASSERT_EQ(n, static_cast<ssize_t>(sizes[i])) << "datagram " << i;
        for (size_t j = 0; j < sizes[i]; ++j) ASSERT_EQ(buf[j], uint8_t(i * 31 + j)) << i;
    }
    // Exactly one message per datagram at each hop: nothing split or joined.
    EXPECT_EQ(tunnel.counters().datagrams_up, sizes.size());
    EXPECT_EQ(tunnel.counters().datagrams_down, sizes.size());
    EXPECT_EQ(srv.bridge().counters().datagrams_up, sizes.size());
    EXPECT_EQ(srv.bridge().counters().datagrams_down, sizes.size());
    EXPECT_EQ(echo.count(), static_cast<int>(sizes.size()));
    tunnel.close();
    ::close(inner);
}

TEST(WssFraming, ForeignLocalSenderIsDropped) {
    UdpEcho echo;
    BridgeServer srv({{"echo", echo.port()}});
    ASSERT_TRUE(srv.ok());
    uint16_t inner_port = 0, other_port = 0;
    const int inner = udp_socket_bound(&inner_port);
    const int other = udp_socket_bound(&other_port);
    auto opts = srv.tunnel_options("echo");
    opts.inner_port = inner_port;
    WssTunnel tunnel;
    ASSERT_TRUE(tunnel.open(opts));
    ASSERT_TRUE(wait_for([&] { return tunnel.state() == WssTunnel::State::Open; }, 5s));
    const auto to = loopback(tunnel.local_port());
    const char x[4] = {1, 2, 3, 4};
    ::sendto(other, x, 4, 0, reinterpret_cast<const sockaddr*>(&to), sizeof to);
    EXPECT_TRUE(wait_for([&] { return tunnel.counters().dropped == 1; }, 2s));
    EXPECT_EQ(srv.bridge().counters().datagrams_up, 0u);
    ::close(inner);
    ::close(other);
}

TEST(WssFraming, BridgeClosesATextMessageAndCountsNoDatagram) {
    UdpEcho echo;
    BridgeServer srv({{"echo", echo.port()}});
    ASSERT_TRUE(srv.ok());
    httplib::ws::WebSocketClient ws(srv.url("echo"));
    ws.set_ca_cert_path(srv.cert());
    ws.set_hostname_addr_map({{"localhost", "127.0.0.1"}});
    ASSERT_TRUE(ws.connect());
    ASSERT_TRUE(ws.send(std::string("hello")));
    std::string msg;
    ws.set_read_timeout(3s);
    EXPECT_EQ(ws.read(msg), httplib::ws::ReadResult::Fail);
    EXPECT_EQ(srv.bridge().counters().datagrams_up, 0u);
    EXPECT_EQ(echo.count(), 0);
}

TEST(WssFraming, ApiAndBridgeShareOneTlsListener) {
    UdpEcho echo;
    BridgeServer srv({{"echo", echo.port()}});
    ASSERT_TRUE(srv.ok());
    httplib::SSLClient api("localhost", srv.port());
    api.set_ca_cert_path(srv.cert().c_str());
    api.set_hostname_addr_map({{"localhost", "127.0.0.1"}});
    auto r = api.Get("/api/health");
    ASSERT_TRUE(r);
    EXPECT_EQ(r->body, "ok");
    WssTunnel tunnel;
    ASSERT_TRUE(tunnel.open(srv.tunnel_options("echo")));
    EXPECT_TRUE(wait_for([&] { return tunnel.state() == WssTunnel::State::Open; }, 5s));
}

TEST(WssFraming, BridgeRefusesBeyondItsConnectionLimit) {
    UdpEcho echo;
    TransportBridge::Limits limits;
    limits.max_connections = 1;
    BridgeServer srv({{"echo", echo.port()}}, limits);
    ASSERT_TRUE(srv.ok());
    WssTunnel a, b;
    ASSERT_TRUE(a.open(srv.tunnel_options("echo")));
    ASSERT_TRUE(wait_for([&] { return a.state() == WssTunnel::State::Open; }, 5s));
    ASSERT_TRUE(wait_for([&] { return srv.bridge().active_connections() == 1; }, 2s));
    ASSERT_TRUE(b.open(srv.tunnel_options("echo")));
    EXPECT_TRUE(wait_for([&] { return b.state() == WssTunnel::State::Failed; }, 5s));
    EXPECT_GE(srv.bridge().counters().connections_refused, 1u);
}

TEST(WssFraming, UnverifiedCertificateFailsTheTunnel) {
    UdpEcho echo;
    BridgeServer srv({{"echo", echo.port()}});
    ASSERT_TRUE(srv.ok());
    auto opts = srv.tunnel_options("echo");
    // A file that is not this server's certificate: verification must fail.
    const auto bogus = std::filesystem::temp_directory_path() / "ln-wss-bogus-ca.pem";
    test_support::make_localhost_cert(bogus, bogus.string() + ".key");
    opts.ca_bundle_path = bogus.string();
    WssTunnel tunnel;
    ASSERT_TRUE(tunnel.open(opts));
    ASSERT_TRUE(wait_for([&] { return tunnel.state() == WssTunnel::State::Failed; }, 5s));
    EXPECT_EQ(tunnel.failure(), WssTunnel::Failure::Connect);
    EXPECT_EQ(srv.bridge().counters().connections_accepted, 0u);
    std::filesystem::remove(bogus);
    std::filesystem::remove(bogus.string() + ".key");
}

// The real per-message cost of the rung, measured on the wire between the
// client and the TLS listener (TLS records + WebSocket frame headers).
TEST(WssFraming, MeasuredPerMessageOverhead) {
    UdpEcho echo;
    BridgeServer srv({{"echo", echo.port()}});
    ASSERT_TRUE(srv.ok());
    TcpCounter counter(srv.port());
    uint16_t inner_port = 0;
    const int inner = udp_socket_bound(&inner_port);
    auto opts = srv.tunnel_options("echo", counter.port());
    opts.inner_port = inner_port;
    opts.ping_interval = 0s;  // no pings in the measured window
    WssTunnel tunnel;
    ASSERT_TRUE(tunnel.open(opts));
    ASSERT_TRUE(wait_for([&] { return tunnel.state() == WssTunnel::State::Open; }, 5s));
    std::this_thread::sleep_for(100ms);

    const auto to = loopback(tunnel.local_port());
    std::vector<uint8_t> buf(70000);
    for (const size_t size : {size_t(148), size_t(1452)}) {
        constexpr int kCount = 200;
        const uint64_t before = counter.up_bytes();
        std::vector<uint8_t> d(size, 0x5A);
        for (int i = 0; i < kCount; ++i) {
            ::sendto(inner, d.data(), d.size(), 0, reinterpret_cast<const sockaddr*>(&to), sizeof to);
            // Wait for the echo so each message leaves as its own TLS record.
            ssize_t n = -1;
            const auto deadline = Clock::now() + 2s;
            while (n <= 0 && Clock::now() < deadline) n = ::recv(inner, buf.data(), buf.size(), 0);
            ASSERT_EQ(n, static_cast<ssize_t>(size));
        }
        const double per_msg = double(counter.up_bytes() - before) / kCount;
        const double overhead = per_msg - double(size);
        const double tls = overhead - double(WssTunnel::frame_overhead(size, true));
        std::printf("[measure] WSS rung client->server: %zu-byte datagram -> %.1f bytes on TCP "
                    "(overhead %.1f = WS frame %zu + TLS %.1f, about %.1f TLS records of 22 B)\n",
                    size, per_msg, overhead, WssTunnel::frame_overhead(size, true), tls,
                    tls / 22.0);
        // At least one TLS 1.3 AEAD record (5 header + 1 type + 16 tag). The
        // WebSocket writer may split one frame into several records.
        EXPECT_GE(tls, 21.0);
        EXPECT_LE(tls, 5 * 40.0);
    }
    tunnel.close();
    ::close(inner);
}

// ===========================================================================
// The race: authenticated handshake wins, never a bare socket
// ===========================================================================

TEST(TransportRace, CaptivePortalNeverOpensATunnel) {
    CaptivePortal portal;
    // TLS to a portal that speaks plain HTTP: no TLS session.
    {
        WssTunnel t;
        WssTunnel::Options o;
        o.url = "wss://localhost:" + std::to_string(portal.port()) + "/api/transport/ws/dataplane";
        o.host_map = {{"localhost", "127.0.0.1"}};
        o.connect_timeout = 2000ms;
        ASSERT_TRUE(t.open(o));
        ASSERT_TRUE(wait_for([&] { return t.state() == WssTunnel::State::Failed; }, 5s));
        EXPECT_EQ(t.failure(), WssTunnel::Failure::Connect);
    }
    // A portal reached without TLS answers the upgrade with a 200 page.
    {
        WssTunnel t;
        WssTunnel::Options o;
        o.url = "ws://127.0.0.1:" + std::to_string(portal.port()) + "/api/transport/ws/dataplane";
        ASSERT_TRUE(t.open(o));
        ASSERT_TRUE(wait_for([&] { return t.state() == WssTunnel::State::Failed; }, 5s));
        EXPECT_EQ(t.failure(), WssTunnel::Failure::Upgrade);
        EXPECT_EQ(t.http_status(), 200);
    }
    EXPECT_GE(portal.accepted(), 2);
}

TEST(TransportRace, UdpBlockedAndPortalOnTcpGivesNoWinner) {
    ASSERT_GE(sodium_init(), 0);
    CaptivePortal portal;
    MeshPair mesh([](httplib::Server&) {});
    mesh.shim->set_blocked(true);
    WssTunnel::Options wss;
    wss.url = "ws://127.0.0.1:" + std::to_string(portal.port()) + "/api/transport/ws/dataplane";
    auto o = mesh.mux_options(wss);
    o.establish_timeout = 2500ms;
    TransportMux mux(mesh.client_dp, o);
    mesh.mux.store(&mux);
    EXPECT_EQ(mux.establish(), TransportPath::None);
    EXPECT_GE(portal.accepted(), 1);
    EXPECT_EQ(mesh.client_dp.peer_path_info(mesh.server_keys.pub_b64)->handshakes, 0u);
}

TEST(TransportRace, UpgradedSocketThatAnswersBytesDoesNotWin) {
    ASSERT_GE(sodium_init(), 0);
    EchoWsServer echo_ws;
    MeshPair mesh([](httplib::Server&) {});
    mesh.shim->set_blocked(true);
    auto o = mesh.mux_options(echo_ws.tunnel_options());
    o.establish_timeout = 2500ms;
    TransportMux mux(mesh.client_dp, o);
    mesh.mux.store(&mux);
    EXPECT_EQ(mux.establish(), TransportPath::None);
    // The initiation went through the upgraded socket and came back; it is
    // not a handshake response, so it proved nothing.
    EXPECT_GE(echo_ws.echoed(), 1);
    EXPECT_EQ(mesh.client_dp.peer_path_info(mesh.server_keys.pub_b64)->handshakes, 0u);
}

// Acceptance: on a UDP-clean network the client picks path=direct and the
// WSS rung carries zero datagrams.
TEST(TransportRace, CleanUdpWinsAndTheRelayCarriesNothing) {
    ASSERT_GE(sodium_init(), 0);
    MeshPair mesh([](httplib::Server& api) {
        api.Get("/ping", [](const httplib::Request&, httplib::Response& res) {
            res.set_content("pong", "text/plain");
        });
    });
    BridgeServer srv({{"dataplane", mesh.server_dp.bound_port()}});
    ASSERT_TRUE(srv.ok());
    TransportMux mux(mesh.client_dp, mesh.mux_options(srv.tunnel_options("dataplane")));
    mesh.mux.store(&mux);
    ASSERT_EQ(mux.establish(), TransportPath::Udp);
    EXPECT_EQ(mux.path(), TransportPath::Udp);
    std::printf("[measure] cold start on clean UDP: %lld ms\n",
                static_cast<long long>(mux.stats().establish_ms));
    EXPECT_EQ(get_once(mesh.egress(), "/ping"), "pong");
    // The warm standby may be open, but it carried no mesh datagram.
    EXPECT_EQ(srv.bridge().counters().datagrams_up, 0u);
    EXPECT_EQ(srv.bridge().counters().datagrams_down, 0u);
}

// Acceptance: on a network with UDP blocked, the WSS rung wins the race and
// the client reaches the service behind the peer.
TEST(TransportRace, UdpBlockedWssWinsAndCarriesTcp) {
    ASSERT_GE(sodium_init(), 0);
    MeshPair mesh([](httplib::Server& api) {
        api.Get("/ping", [](const httplib::Request&, httplib::Response& res) {
            res.set_content("pong", "text/plain");
        });
    });
    mesh.shim->set_blocked(true);
    BridgeServer srv({{"dataplane", mesh.server_dp.bound_port()}});
    ASSERT_TRUE(srv.ok());
    TransportMux mux(mesh.client_dp, mesh.mux_options(srv.tunnel_options("dataplane")));
    mesh.mux.store(&mux);
    ASSERT_EQ(mux.establish(), TransportPath::Wss);
    std::printf("[measure] cold start with UDP blocked (WSS wins): %lld ms\n",
                static_cast<long long>(mux.stats().establish_ms));
    EXPECT_EQ(mux.path(), TransportPath::Wss);
    EXPECT_EQ(mesh.shim->carried(), 0u);
    EXPECT_EQ(get_once(mesh.egress(), "/ping"), "pong");
    EXPECT_GT(srv.bridge().counters().datagrams_up, 0u);
}

// ===========================================================================
// Roaming: a live stream survives a path swap; the session stays
// ===========================================================================

namespace {

constexpr const char* kMarker = "PLAINTEXT-MARKER-7f3a9c";

/// An SSE-like route: `chunks` lines, one every `gap`, each naming its
/// sequence number and the plaintext marker.
void add_stream_route(httplib::Server& api, int chunks, std::chrono::milliseconds gap) {
    api.Get("/stream", [chunks, gap](const httplib::Request&, httplib::Response& res) {
        res.set_chunked_content_provider(
            "text/event-stream", [chunks, gap, i = 0](size_t, httplib::DataSink& sink) mutable {
                if (i >= chunks) {
                    sink.done();
                    return true;
                }
                std::this_thread::sleep_for(gap);
                const std::string line =
                    "data: " + std::to_string(i++) + " " + kMarker + "\n\n";
                return sink.write(line.data(), line.size());
            });
    });
}

struct StreamResult {
    bool ok{false};
    std::vector<int> seqs;
    int64_t max_gap_ms{0};
};

StreamResult read_stream(uint16_t port) {
    StreamResult out;
    httplib::Client c("127.0.0.1", port);
    c.set_connection_timeout(5, 0);
    c.set_read_timeout(15, 0);
    std::string pending;
    auto last = Clock::now();
    auto r = c.Get("/stream", [&](const char* data, size_t len) {
        const auto now = Clock::now();
        out.max_gap_ms = std::max<int64_t>(
            out.max_gap_ms,
            std::chrono::duration_cast<std::chrono::milliseconds>(now - last).count());
        last = now;
        pending.append(data, len);
        size_t pos;
        while ((pos = pending.find("\n\n")) != std::string::npos) {
            const std::string line = pending.substr(0, pos);
            pending.erase(0, pos + 2);
            if (line.rfind("data: ", 0) == 0) out.seqs.push_back(std::stoi(line.substr(6)));
        }
        return true;
    });
    out.ok = r && r->status == 200;
    return out;
}

}  // namespace

TEST(TransportRoaming, StreamSurvivesUdpCutAndRestoreWithTheSameSession) {
    ASSERT_GE(sodium_init(), 0);
    constexpr int kChunks = 300;  // 300 x 20 ms = 6 s
    MeshPair mesh([](httplib::Server& api) { add_stream_route(api, kChunks, 20ms); });
    BridgeServer srv({{"dataplane", mesh.server_dp.bound_port()}});
    ASSERT_TRUE(srv.ok());
    auto o = mesh.mux_options(srv.tunnel_options("dataplane"));
    o.timing.probe_interval = 100ms;
    o.timing.miss_limit = 4;
    o.timing.hold_down = 1000ms;
    o.timing.trial_window = 600ms;
    o.timing.trial_backoff_min = 500ms;
    TransportMux mux(mesh.client_dp, o);
    mesh.mux.store(&mux);
    ASSERT_EQ(mux.establish(), TransportPath::Udp);
    mux.start();
    ASSERT_TRUE(wait_for([&] { return !mux.wss_endpoint().empty(); }, 3s));
    ASSERT_TRUE(wait_for([&] { return mux.stats().replies > 3; }, 3s));

    const auto before = *mesh.client_dp.peer_path_info(mesh.server_keys.pub_b64);
    const uint16_t egress = mesh.egress();
    ASSERT_NE(egress, 0);

    std::vector<std::string> path_log;
    std::atomic<bool> watching{true};
    std::mutex log_mtx;
    std::thread watcher([&] {
        std::string last;
        while (watching) {
            const std::string now = lnsdk::transport_path_name(mux.path());
            if (now != last) {
                std::lock_guard lock(log_mtx);
                path_log.push_back(now);
                last = now;
            }
            std::this_thread::sleep_for(10ms);
        }
    });

    StreamResult result;
    std::thread reader([&] { result = read_stream(egress); });
    std::this_thread::sleep_for(1500ms);
    mesh.shim->set_blocked(true);  // UDP cut mid-stream
    std::this_thread::sleep_for(1500ms);
    mesh.shim->set_blocked(false);  // UDP back
    reader.join();
    // The upgrade back to UDP may land after the stream ends.
    EXPECT_TRUE(wait_for([&] { return mux.path() == TransportPath::Udp; }, 6s));
    watching = false;
    watcher.join();

    const auto after = *mesh.client_dp.peer_path_info(mesh.server_keys.pub_b64);
    const auto s = mux.stats();
    std::printf("[measure] mid-stream failover: outage %lld ms (last reply on UDP -> first on "
                "WSS), recover %lld ms after the move; stream max gap %lld ms; moves %llu, "
                "failovers %llu, trials %llu\n",
                static_cast<long long>(s.last_outage_ms), static_cast<long long>(s.last_recover_ms),
                static_cast<long long>(result.max_gap_ms),
                static_cast<unsigned long long>(s.moves),
                static_cast<unsigned long long>(s.failovers),
                static_cast<unsigned long long>(s.trials));
    {
        std::lock_guard lock(log_mtx);
        std::string joined;
        for (const auto& p : path_log) joined += p + " ";
        std::printf("[measure] path log: %s\n", joined.c_str());
        // The path field flipped to wss and back to direct.
        ASSERT_GE(path_log.size(), 3u) << joined;
        EXPECT_EQ(path_log.front(), "direct");
        EXPECT_NE(std::find(path_log.begin(), path_log.end(), "wss"), path_log.end()) << joined;
        EXPECT_EQ(path_log.back(), "direct") << joined;
    }

    // The stream did not reset: every chunk arrived once, in order.
    ASSERT_TRUE(result.ok);
    ASSERT_EQ(result.seqs.size(), static_cast<size_t>(kChunks));
    for (int i = 0; i < kChunks; ++i) ASSERT_EQ(result.seqs[i], i);

    // The session stayed: same tunnel index, same session slot, and no
    // handshake ran during the swaps.
    EXPECT_EQ(after.tunnel_index, before.tunnel_index);
    EXPECT_EQ(after.rx_session, before.rx_session);
    EXPECT_EQ(after.handshakes, before.handshakes);
    EXPECT_GE(s.failovers, 1u);
    EXPECT_GT(srv.bridge().counters().datagrams_up, 0u);
    // Sub-second failover target.
    EXPECT_GE(s.last_outage_ms, 0);
    EXPECT_LT(s.last_outage_ms, 1000);
    mux.stop();
}

// Acceptance: the relay node sees only ciphertext. The bridge's target is a
// recording forwarder in front of the peer's dataplane; the TLS side is
// recorded by a TCP counter. A plaintext marker in every stream chunk must
// appear in neither, and every bridged datagram must be a Noise message.
TEST(TransportRoaming, RelayNodeSeesOnlyCiphertext) {
    ASSERT_GE(sodium_init(), 0);
    MeshPair mesh([](httplib::Server& api) { add_stream_route(api, 50, 5ms); });
    UdpShim spy(mesh.server_dp.bound_port());
    spy.set_recording(true);
    BridgeServer srv({{"dataplane", spy.port()}});
    ASSERT_TRUE(srv.ok());
    TcpCounter tls_side(srv.port());
    mesh.shim->set_blocked(true);
    auto o = mesh.mux_options(srv.tunnel_options("dataplane", tls_side.port()));
    // The peer's UDP endpoint for the race is the spy as well: the server
    // learns only one client address.
    TransportMux mux(mesh.client_dp, o);
    mesh.mux.store(&mux);
    ASSERT_EQ(mux.establish(), TransportPath::Wss);
    const auto r = read_stream(mesh.egress());
    ASSERT_TRUE(r.ok);
    ASSERT_EQ(r.seqs.size(), 50u);

    const auto datagrams = spy.recorded();
    ASSERT_GT(datagrams.size(), 8u);
    const std::string marker(kMarker);
    size_t noise = 0;
    for (const auto& d : datagrams) {
        const std::string text(d.begin(), d.end());
        EXPECT_EQ(text.find(marker), std::string::npos);
        // Noise message types 1-4 with three zero bytes (WireProtocol.hpp).
        ASSERT_GE(d.size(), 4u);
        if (d[0] >= 1 && d[0] <= 4 && d[1] == 0 && d[2] == 0 && d[3] == 0) ++noise;
    }
    EXPECT_EQ(noise, datagrams.size());
    EXPECT_EQ(tls_side.seen().find(marker), std::string::npos);
    EXPECT_GT(tls_side.up_bytes(), 0u);
}

// ===========================================================================
// The SDK mesh plane: BoringtunMesh with a WSS route
// ===========================================================================

#include <LemonadeNexusSDK/BoringtunMesh.hpp>
#include <LemonadeNexusSDK/LemonadeNexusClient.hpp>

// The client's real mesh plane (BoringtunMesh) with wss_urls set: it races,
// reports the server path in mesh_status(), and keeps the private-API style
// egress working when UDP to the server is cut.
TEST(TransportMeshPlane, BoringtunMeshFailsOverToWssAndReportsThePath) {
    ASSERT_GE(sodium_init(), 0);
    // A server side: dataplane + netstack + HTTP service, as in MeshPair.
    MeshPair server_side([](httplib::Server& api) {
        api.Get("/ping", [](const httplib::Request&, httplib::Response& res) {
            res.set_content("pong", "text/plain");
        });
    });
    BridgeServer srv({{"dataplane", server_side.server_dp.bound_port()}});
    ASSERT_TRUE(srv.ok());
    UdpShim shim(server_side.server_dp.bound_port());

    lnsdk::set_ca_bundle_path(srv.cert());
    const auto keys = lnsdk::BoringtunMesh::generate_keypair();
    // Replace the MeshPair's client key on the server with this mesh's key.
    (void)server_side.server_dp.remove_peer(server_side.client_keys.pub_b64);
    ASSERT_TRUE(server_side.server_dp.add_peer(keys.second, "10.64.0.2/32", ""));

    lnsdk::BoringtunMesh mesh;
    lnsdk::BoringtunConfig cfg;
    cfg.private_key = keys.first;
    cfg.public_key = keys.second;
    cfg.tunnel_ip = "10.64.0.2/32";
    cfg.server_public_key = server_side.server_keys.pub_b64;
    cfg.server_endpoint = shim.endpoint();
    cfg.server_tunnel_ip = "10.64.0.1";
    cfg.allowed_ips = {"10.64.0.0/10"};
    cfg.keepalive = 25;
    cfg.wss_urls = {srv.url("dataplane")};
    ASSERT_TRUE(mesh.start(cfg));

    ASSERT_TRUE(wait_for([&] { return mesh.mesh_status().server_path == "direct"; }, 8s))
        << mesh.mesh_status().server_path;
    const uint16_t egress = mesh.tcp_egress("10.64.0.1", 80);
    ASSERT_NE(egress, 0);
    EXPECT_EQ(get_once(egress, "/ping"), "pong");

    shim.set_blocked(true);
    ASSERT_TRUE(wait_for([&] { return mesh.mesh_status().server_path == "wss"; }, 5s));
    EXPECT_EQ(get_once(egress, "/ping"), "pong");
    EXPECT_GT(srv.bridge().counters().datagrams_up, 0u);

    // A plane without a WSS route reports no server path.
    lnsdk::BoringtunMesh plain;
    auto plain_cfg = cfg;
    plain_cfg.wss_urls.clear();
    const auto plain_keys = lnsdk::BoringtunMesh::generate_keypair();
    plain_cfg.private_key = plain_keys.first;
    plain_cfg.public_key = plain_keys.second;
    ASSERT_TRUE(plain.start(plain_cfg));
    EXPECT_TRUE(plain.mesh_status().server_path.empty());
    plain.stop();
    mesh.stop();
    lnsdk::set_ca_bundle_path("");
}

// ===========================================================================
// Bridge abuse limits
// ===========================================================================

namespace {

/// A plain-HTTP listener with the bridge, for tests that speak raw bytes.
struct PlainBridge {
    TransportBridge bridge;
    httplib::Server server;
    int port{0};
    std::thread thread;
    PlainBridge(uint16_t target, TransportBridge::Limits limits) : bridge(limits) {
        bridge.add_target("echo", target);
        bridge.register_routes(server);
        port = server.bind_to_any_port("127.0.0.1");
        thread = std::thread([this] { server.listen_after_bind(); });
        server.wait_until_ready();
    }
    ~PlainBridge() {
        bridge.stop();
        server.stop();
        thread.join();
    }
    std::string url() const {
        return "ws://127.0.0.1:" + std::to_string(port) + nexus::network::kTransportBridgePathPrefix + "echo";
    }
};

int raw_connect(int port) {
    int s = ::socket(AF_INET, SOCK_STREAM, 0);
    auto a = loopback(static_cast<uint16_t>(port));
    if (::connect(s, reinterpret_cast<sockaddr*>(&a), sizeof a) != 0) {
        ::close(s);
        return -1;
    }
    timeval tv{5, 0};
    ::setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    return s;
}

/// Read until the peer closes; true when it closed within the timeout.
bool peer_closes(int s) {
    char buf[4096];
    for (;;) {
        const auto n = ::recv(s, buf, sizeof buf, 0);
        if (n == 0) return true;
        if (n < 0) return false;  // timeout
    }
}

}  // namespace

TEST(BridgeAbuse, ConnectionsPerAddressAreLimited) {
    UdpEcho echo;
    TransportBridge::Limits limits;
    limits.max_per_ip = 2;
    PlainBridge pb(echo.port(), limits);
    WssTunnel a, b, c;
    WssTunnel::Options o;
    o.url = pb.url();
    ASSERT_TRUE(a.open(o));
    ASSERT_TRUE(b.open(o));
    ASSERT_TRUE(wait_for([&] { return pb.bridge.active_connections() == 2; }, 5s));
    ASSERT_TRUE(c.open(o));
    EXPECT_TRUE(wait_for([&] { return c.state() == WssTunnel::State::Failed; }, 5s));
    EXPECT_EQ(pb.bridge.counters().refused_per_ip, 1u);
    // The slot comes back when a connection ends.
    a.close();
    ASSERT_TRUE(wait_for([&] { return pb.bridge.active_connections() == 1; }, 5s));
    WssTunnel d;
    ASSERT_TRUE(d.open(o));
    EXPECT_TRUE(wait_for([&] { return d.state() == WssTunnel::State::Open; }, 5s));
}

TEST(BridgeAbuse, AMessageLargerThanADatagramEndsTheConnection) {
    UdpEcho echo;
    PlainBridge pb(echo.port(), {});
    httplib::ws::WebSocketClient ws(pb.url());
    ASSERT_TRUE(ws.connect());
    const std::string big(70000, 'x');
    ws.send(big.data(), big.size());
    std::string msg;
    ws.set_read_timeout(3s);
    EXPECT_EQ(ws.read(msg), httplib::ws::ReadResult::Fail);
    EXPECT_EQ(echo.count(), 0);
    EXPECT_TRUE(wait_for([&] { return pb.bridge.active_connections() == 0; }, 3s));
}

TEST(BridgeAbuse, ASilentClientIsDroppedOnTheIdleTimer) {
    UdpEcho echo;
    TransportBridge::Limits limits;
    limits.idle_timeout = std::chrono::seconds(2);
    PlainBridge pb(echo.port(), limits);
    httplib::ws::WebSocketClient ws(pb.url());
    ws.set_websocket_ping_interval(0);
    ASSERT_TRUE(ws.connect());
    ASSERT_TRUE(wait_for([&] { return pb.bridge.active_connections() == 1; }, 2s));
    const auto t0 = Clock::now();
    EXPECT_TRUE(wait_for([&] { return pb.bridge.active_connections() == 0; }, 6s));
    EXPECT_GE(Clock::now() - t0, 1500ms);
    EXPECT_EQ(pb.bridge.counters().closed_idle, 1u);
}

TEST(BridgeAbuse, GarbageAfterTheUpgradeIsDroppedAndTheServerKeepsServing) {
    UdpEcho echo;
    PlainBridge pb(echo.port(), {});
    for (int round = 0; round < 3; ++round) {
        const int s = raw_connect(pb.port);
        ASSERT_GE(s, 0);
        const std::string upgrade =
            std::string("GET ") + nexus::network::kTransportBridgePathPrefix +
            "echo HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
        ASSERT_GT(::send(s, upgrade.data(), upgrade.size(), MSG_NOSIGNAL), 0);
        // Unmasked frames with nonsense opcodes and lengths, then noise.
        std::string garbage = "\x8f\xff\xff\xff\xff\xff\xff\xff\xff\xff";
        for (int i = 0; i < 4096; ++i) garbage.push_back(static_cast<char>((i * 131 + round) & 0xFF));
        (void)::send(s, garbage.data(), garbage.size(), MSG_NOSIGNAL);
        EXPECT_TRUE(peer_closes(s)) << "round " << round;
        ::close(s);
    }
    EXPECT_TRUE(wait_for([&] { return pb.bridge.active_connections() == 0; }, 3s));
    EXPECT_EQ(echo.count(), 0);
    WssTunnel t;
    WssTunnel::Options o;
    o.url = pb.url();
    ASSERT_TRUE(t.open(o));
    EXPECT_TRUE(wait_for([&] { return t.state() == WssTunnel::State::Open; }, 5s));
}

// ===========================================================================
// Several WSS routes: failover between them
// ===========================================================================

TEST(TransportWssList, TheNextUrlIsUsedWhenTheFirstIsDead) {
    ASSERT_GE(sodium_init(), 0);
    CaptivePortal portal;
    MeshPair mesh([](httplib::Server& api) {
        api.Get("/ping", [](const httplib::Request&, httplib::Response& res) {
            res.set_content("pong", "text/plain");
        });
    });
    mesh.shim->set_blocked(true);
    BridgeServer srv({{"dataplane", mesh.server_dp.bound_port()}});
    ASSERT_TRUE(srv.ok());
    auto o = mesh.mux_options(srv.tunnel_options("dataplane"));
    o.wss_urls = {"wss://localhost:" + std::to_string(portal.port()) + "/api/transport/ws/dataplane",
                  srv.url("dataplane")};
    TransportMux mux(mesh.client_dp, o);
    mesh.mux.store(&mux);
    ASSERT_EQ(mux.establish(), TransportPath::Wss);
    EXPECT_EQ(mux.stats().wss_url, srv.url("dataplane"));
    EXPECT_GE(portal.accepted(), 1);
    EXPECT_EQ(get_once(mesh.egress(), "/ping"), "pong");
}

TEST(TransportWssList, ARouteThatDiesFailsOverToTheNextOne) {
    ASSERT_GE(sodium_init(), 0);
    MeshPair mesh([](httplib::Server& api) {
        api.Get("/ping", [](const httplib::Request&, httplib::Response& res) {
            res.set_content("pong", "text/plain");
        });
    });
    mesh.shim->set_blocked(true);
    auto first = std::make_unique<BridgeServer>(
        std::vector<std::pair<std::string, uint16_t>>{{"dataplane", mesh.server_dp.bound_port()}});
    ASSERT_TRUE(first->ok());
    // The second route is another listener of the same bridge (plain
    // WebSocket here, so one CA file still verifies the first).
    PlainBridge second(mesh.server_dp.bound_port(), {});
    auto o = mesh.mux_options(first->tunnel_options("dataplane"));
    o.wss_urls = {first->url("dataplane"), second.url()};
    o.timing.probe_interval = 100ms;
    TransportMux mux(mesh.client_dp, o);
    mesh.mux.store(&mux);
    ASSERT_EQ(mux.establish(), TransportPath::Wss);
    mux.start();
    ASSERT_EQ(mux.stats().wss_url, o.wss_urls[0]);
    first.reset();  // the first route goes away mid-session
    EXPECT_TRUE(wait_for(
        [&] { return mux.path() == TransportPath::Wss && mux.stats().wss_url == o.wss_urls[1]; }, 10s))
        << mux.stats().wss_url;
    EXPECT_EQ(get_once(mesh.egress(), "/ping"), "pong");
    mux.stop();
}

TEST(TransportMtu, TheMeshPlaneFollowsTheSmallestEnabledRung) {
    ASSERT_GE(sodium_init(), 0);
    const auto start = [](uint32_t link, bool relay) {
        lnsdk::BoringtunMesh mesh;
        const auto keys = lnsdk::BoringtunMesh::generate_keypair();
        lnsdk::BoringtunConfig cfg;
        cfg.private_key = keys.first;
        cfg.public_key = keys.second;
        cfg.tunnel_ip = "10.64.0.9/32";
        cfg.allowed_ips = {"10.64.0.0/10"};
        cfg.link_mtu = link;
        cfg.relay_rung = relay;
        EXPECT_TRUE(mesh.start(cfg));
        const auto mtu = mesh.mtu();
        mesh.stop();
        return mtu;
    };
    EXPECT_EQ(start(1500, true), 1414u);   // the 9103 relay's Data header
    EXPECT_EQ(start(1500, false), 1420u);  // direct UDP and WSS only: the dataplane cap
    EXPECT_EQ(start(1400, true), 1314u);   // a 1400-byte link (PPPoE, tunnels)
    EXPECT_EQ(start(1400, false), 1340u);
}

// A full-size inner packet crosses the direct rung within one 1500-byte
// link packet, and the WSS rung after a swap carries the same packets.
TEST(TransportMtu, AFullSizePacketCrossesTheDirectAndWssRungs) {
    ASSERT_GE(sodium_init(), 0);
    MeshPair server_side([](httplib::Server& api) {
        api.Post("/upload", [](const httplib::Request& req, httplib::Response& res) {
            res.set_content(std::to_string(req.body.size()), "text/plain");
        });
    });
    BridgeServer srv({{"dataplane", server_side.server_dp.bound_port()}});
    ASSERT_TRUE(srv.ok());
    UdpShim shim(server_side.server_dp.bound_port());
    lnsdk::set_ca_bundle_path(srv.cert());
    const auto keys = lnsdk::BoringtunMesh::generate_keypair();
    (void)server_side.server_dp.remove_peer(server_side.client_keys.pub_b64);
    ASSERT_TRUE(server_side.server_dp.add_peer(keys.second, "10.64.0.2/32", ""));
    lnsdk::BoringtunMesh mesh;
    lnsdk::BoringtunConfig cfg;
    cfg.private_key = keys.first;
    cfg.public_key = keys.second;
    cfg.tunnel_ip = "10.64.0.2/32";
    cfg.server_public_key = server_side.server_keys.pub_b64;
    cfg.server_endpoint = shim.endpoint();
    cfg.server_tunnel_ip = "10.64.0.1";
    cfg.allowed_ips = {"10.64.0.0/10"};
    cfg.link_mtu = 1500;
    cfg.wss_urls = {srv.url("dataplane")};
    ASSERT_TRUE(mesh.start(cfg));
    ASSERT_EQ(mesh.mtu(), 1414u);
    ASSERT_TRUE(wait_for([&] { return mesh.server_path() == "direct"; }, 8s));
    const uint16_t egress = mesh.tcp_egress("10.64.0.1", 80);
    const auto upload = [&] {
        httplib::Client c("127.0.0.1", egress);
        c.set_read_timeout(10, 0);
        const std::string body(256 * 1024, 'm');
        for (int i = 0; i < 20; ++i) {
            if (auto r = c.Post("/upload", body, "application/octet-stream"); r && r->status == 200) {
                return r->body == std::to_string(body.size());
            }
            std::this_thread::sleep_for(200ms);
        }
        return false;
    };
    shim.set_recording(true);
    ASSERT_TRUE(upload());
    shim.set_recording(false);
    std::size_t largest = 0;
    for (const auto& d : shim.recorded()) largest = std::max(largest, d.size());
    EXPECT_EQ(largest, 1414u + lnsdk::kBoringtunDataOverhead);  // a full-size segment
    EXPECT_LE(largest + lnsdk::kIpv4UdpOverhead, 1500u);
    shim.set_blocked(true);
    ASSERT_TRUE(wait_for([&] { return mesh.server_path() == "wss"; }, 5s));
    EXPECT_TRUE(upload());
    mesh.stop();
    lnsdk::set_ca_bundle_path("");
}

// Both rungs silent (for example the server restarted and lost the
// session): the moves between them slow down instead of flapping every
// dead_after, and a reply ends the backoff.
TEST(MuxPolicyBackoff, BothRungsDeadBacksOffTheMoves) {
    MuxPolicy::Timing t;
    t.probe_interval = 100ms;
    t.miss_limit = 4;
    t.hold_down = 10s;
    MuxPolicy p(t);
    const auto t0 = Clock::now();
    p.install(TransportPath::Udp, t0);
    std::vector<int64_t> moves;
    for (int ms = 0; ms <= 20000; ms += 10) {
        const auto now = t0 + std::chrono::milliseconds(ms);
        const auto a = p.decide(now, true);
        if (a == MuxPolicy::Action::MoveToWss || a == MuxPolicy::Action::MoveToUdp) moves.push_back(ms);
    }
    ASSERT_GE(moves.size(), 4u);
    // The first two moves come at the normal dead time; later gaps grow.
    EXPECT_LE(moves[1] - moves[0], 450);
    EXPECT_GT(moves[3] - moves[2], moves[1] - moves[0]);
    EXPECT_LT(moves.size(), 20u) << "no flapping every 400 ms for 20 s";
    EXPECT_GE(p.dead_streak(), 3u);
    // A reply on the active rung ends the streak.
    p.on_reply(p.active(), t0 + 20001ms);
    EXPECT_EQ(p.dead_streak(), 0u);
}

// After a network change (the host calls resume, which kicks the mux) the
// WSS standby is replaced at once: the old tunnel may be bound to an address
// the device no longer has.
TEST(TransportMuxKick, AKickReplacesTheWssStandbyAtOnce) {
    ASSERT_GE(sodium_init(), 0);
    MeshPair mesh([](httplib::Server&) {});
    BridgeServer srv({{"dataplane", mesh.server_dp.bound_port()}});
    ASSERT_TRUE(srv.ok());
    TransportMux mux(mesh.client_dp, mesh.mux_options(srv.tunnel_options("dataplane")));
    mesh.mux.store(&mux);
    ASSERT_EQ(mux.establish(), TransportPath::Udp);
    mux.start();
    ASSERT_TRUE(wait_for([&] { return !mux.wss_endpoint().empty(); }, 5s));
    const auto before = mux.wss_endpoint();
    const auto accepted = srv.bridge().counters().connections_accepted;
    mux.kick();
    EXPECT_TRUE(wait_for(
        [&] { return !mux.wss_endpoint().empty() && mux.wss_endpoint() != before; }, 3s));
    EXPECT_TRUE(wait_for([&] { return srv.bridge().counters().connections_accepted > accepted; }, 3s));
    EXPECT_EQ(mux.path(), TransportPath::Udp);
    mux.stop();
}
