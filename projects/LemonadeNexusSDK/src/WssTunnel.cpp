#include <LemonadeNexusSDK/WssTunnel.hpp>

#include <LemonadeNexusSDK/LemonadeNexusClient.hpp>

#include <httplib.h>
#include <spdlog/spdlog.h>

#include <mutex>
#include <stdexcept>
#include <thread>
#include <vector>

#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
using wss_socket_t = SOCKET;
static constexpr wss_socket_t kNoSocket = INVALID_SOCKET;
static void close_wss_socket(wss_socket_t s) { closesocket(s); }
using wss_len_t = int;
#else
#  include <arpa/inet.h>
#  include <netinet/in.h>
#  include <sys/socket.h>
#  include <unistd.h>
using wss_socket_t = int;
static constexpr wss_socket_t kNoSocket = -1;
static void close_wss_socket(wss_socket_t s) { ::close(s); }
using wss_len_t = socklen_t;
#endif

#ifndef LEMONADE_NEXUS_HTTPLIB_VERSION
#error "LEMONADE_NEXUS_HTTPLIB_VERSION names the cpp-httplib release (see cmake/libraries/httplib.cmake)"
#endif
// close() from a thread other than the reader is safe from v0.54.0 (see
// end_event_socket in LemonadeNexusClient.cpp).
#if LEMONADE_NEXUS_HTTPLIB_VERSION >= 54000
#  define LN_WSS_TUNNEL_SUPPORTED 1
#else
#  define LN_WSS_TUNNEL_SUPPORTED 0
#endif

namespace lnsdk {

namespace {

constexpr std::size_t kMaxDatagram = 65535;

}  // namespace

struct WssTunnel::Impl {
    Options                    opts;
    wss_socket_t               sock{kNoSocket};
    uint16_t                   port{0};
    std::atomic<State>         state{State::Idle};
    std::atomic<Failure>       failure{Failure::None};
    std::atomic<int>           http_status{0};
    std::atomic<int64_t>       connect_ms{-1};
    std::atomic<bool>          running{false};
    std::chrono::steady_clock::time_point opened_at{};

    // The local sender, learned from the first datagram when inner_port is
    // 0. Written by the UDP thread, read by the WebSocket thread.
    std::atomic<uint16_t>      inner_port{0};
    std::atomic<int64_t>       last_send_ms{0};

    std::atomic<uint64_t> datagrams_up{0};
    std::atomic<uint64_t> datagrams_down{0};
    std::atomic<uint64_t> bytes_up{0};
    std::atomic<uint64_t> bytes_down{0};
    std::atomic<uint64_t> dropped{0};

#if LN_WSS_TUNNEL_SUPPORTED
    std::mutex                                       client_mtx;
    std::unique_ptr<httplib::ws::WebSocketClient>    client;  // guarded by client_mtx
#endif
    std::thread ws_thread;
    std::thread udp_thread;
    std::mutex  close_mtx;

    void fail(Failure why) {
        Failure expected = Failure::None;
        failure.compare_exchange_strong(expected, why);
        state.store(State::Failed);
    }

    void send_local(const char* data, std::size_t len) {
        const uint16_t to = inner_port.load();
        if (to == 0) {
            dropped.fetch_add(1);
            return;
        }
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons(to);
        ::sendto(sock, data, static_cast<int>(len), 0, reinterpret_cast<const sockaddr*>(&addr),
                 sizeof(addr));
        datagrams_down.fetch_add(1);
        bytes_down.fetch_add(len);
    }

    void run_ws();
    void run_udp();
};

void WssTunnel::Impl::run_ws() {
#if LN_WSS_TUNNEL_SUPPORTED
    httplib::ws::WebSocketClient* ws = nullptr;
    {
        std::lock_guard lock(client_mtx);
        try {
            client = std::make_unique<httplib::ws::WebSocketClient>(opts.url);
        } catch (const std::exception&) {
            client.reset();
        }
        if (!client || !client->is_valid()) {
            fail(Failure::Connect);
            running.store(false);
            return;
        }
        ws = client.get();
        if (!opts.host_map.empty()) ws->set_hostname_addr_map(opts.host_map);
        const auto bundle = opts.ca_bundle_path.empty() ? ca_bundle_path() : opts.ca_bundle_path;
        if (!bundle.empty()) ws->set_ca_cert_path(bundle);
        ws->enable_server_certificate_verification(opts.verify_tls);
        ws->enable_server_hostname_verification(opts.verify_tls);
        ws->set_connection_timeout(opts.connect_timeout);
        ws->set_websocket_ping_interval(static_cast<time_t>(opts.ping_interval.count()));
        ws->set_websocket_max_missed_pongs(opts.max_missed_pongs);
        // One datagram per message, sent at once: Nagle would hold a small
        // message back for the previous one's ACK.
        ws->set_tcp_nodelay(true);
        ws->set_read_timeout(std::chrono::milliseconds(200));
#ifdef __APPLE__
        ws->set_socket_options([](httplib::socket_t s) {
            int on = 1;
            ::setsockopt(s, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof on);
        });
#endif
    }

    const auto opened = ws->connect();
    if (!opened) {
        http_status.store(std::max(opened.status(), 0));
        fail(opened.status() > 0 ? Failure::Upgrade : Failure::Connect);
        running.store(false);
        spdlog::info("[WssTunnel] {} not opened ({}, status {})", opts.url,
                     httplib::to_string(opened.error()), opened.status());
        return;
    }
    if (!running.load()) return;
    connect_ms.store(std::chrono::duration_cast<std::chrono::milliseconds>(
                         std::chrono::steady_clock::now() - opened_at)
                         .count());
    state.store(State::Open);

    const auto steady_ms = [] {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
                   std::chrono::steady_clock::now().time_since_epoch())
            .count();
    };
    last_send_ms.store(steady_ms());
    const int64_t keepalive_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(opts.keepalive_interval).count();
    std::string msg;
    while (running.load()) {
        const auto r = ws->read(msg);
        if (r == httplib::ws::ReadResult::Timeout) {
            if (keepalive_ms > 0 && steady_ms() - last_send_ms.load() >= keepalive_ms) {
                std::lock_guard lock(client_mtx);
                if (ws->send(static_cast<const char*>(""), 0)) last_send_ms.store(steady_ms());
            }
            continue;
        }
        if (r == httplib::ws::ReadResult::Fail) {
            if (running.load()) fail(Failure::Closed);
            break;
        }
        if (r == httplib::ws::ReadResult::Text) {
            fail(Failure::Protocol);
            ws->close(httplib::ws::CloseStatus::UnsupportedData, "binary only");
            break;
        }
        if (msg.empty()) continue;  // keepalive
        if (msg.size() > kMaxDatagram) {
            dropped.fetch_add(1);
            continue;
        }
        send_local(msg.data(), msg.size());
    }
    running.store(false);
#else
    fail(Failure::Unsupported);
    running.store(false);
#endif
}

void WssTunnel::Impl::run_udp() {
    std::vector<char> buf(kMaxDatagram + 1);
    while (running.load()) {
        sockaddr_in from{};
        wss_len_t from_len = sizeof(from);
        const auto n = ::recvfrom(sock, buf.data(), static_cast<int>(buf.size()), 0,
                                  reinterpret_cast<sockaddr*>(&from), &from_len);
        if (n <= 0) continue;  // timeout, shutdown, or a transient error
        const auto len = static_cast<std::size_t>(n);
        if (from.sin_addr.s_addr != htonl(INADDR_LOOPBACK) || len > kMaxDatagram) {
            dropped.fetch_add(1);
            continue;
        }
        const uint16_t sender = ntohs(from.sin_port);
        uint16_t expected = inner_port.load();
        if (expected == 0) {
            inner_port.compare_exchange_strong(expected, sender);
            expected = inner_port.load();
        }
        if (sender != expected || state.load() != State::Open) {
            dropped.fetch_add(1);
            continue;
        }
#if LN_WSS_TUNNEL_SUPPORTED
        bool sent = false;
        {
            std::lock_guard lock(client_mtx);
            if (client) sent = client->send(buf.data(), len);
        }
        if (sent) {
            datagrams_up.fetch_add(1);
            bytes_up.fetch_add(len);
            last_send_ms.store(std::chrono::duration_cast<std::chrono::milliseconds>(
                                   std::chrono::steady_clock::now().time_since_epoch())
                                   .count());
        } else {
            dropped.fetch_add(1);
        }
#endif
    }
}

WssTunnel::WssTunnel() : impl_(std::make_unique<Impl>()) {}

WssTunnel::~WssTunnel() { close(); }

bool WssTunnel::open(Options options) {
    if (impl_->state.load() != State::Idle) return false;
#if !LN_WSS_TUNNEL_SUPPORTED
    (void)options;
    impl_->fail(Failure::Unsupported);
    return false;
#else
    const bool scheme_ok = options.url.rfind("wss://", 0) == 0 || options.url.rfind("ws://", 0) == 0;
    if (!scheme_ok) return false;

    const wss_socket_t sock = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == kNoSocket) return false;
#ifdef _WIN32
    DWORD timeout_ms = 100;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout_ms),
               sizeof(timeout_ms));
#else
    timeval tv{};
    tv.tv_usec = 100 * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif
#ifdef __APPLE__
    int no_sigpipe = 1;
    setsockopt(sock, SOL_SOCKET, SO_NOSIGPIPE, &no_sigpipe, sizeof(no_sigpipe));
#endif
    sockaddr_in bind_addr{};
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::bind(sock, reinterpret_cast<const sockaddr*>(&bind_addr), sizeof(bind_addr)) != 0) {
        close_wss_socket(sock);
        return false;
    }
    sockaddr_in actual{};
    wss_len_t actual_len = sizeof(actual);
    ::getsockname(sock, reinterpret_cast<sockaddr*>(&actual), &actual_len);

    impl_->opts = std::move(options);
    impl_->sock = sock;
    impl_->port = ntohs(actual.sin_port);
    impl_->inner_port.store(impl_->opts.inner_port);
    impl_->opened_at = std::chrono::steady_clock::now();
    impl_->state.store(State::Connecting);
    impl_->running.store(true);
    impl_->udp_thread = std::thread([impl = impl_.get()] { impl->run_udp(); });
    impl_->ws_thread = std::thread([impl = impl_.get()] { impl->run_ws(); });
    return true;
#endif
}

void WssTunnel::close() {
    std::lock_guard lock(impl_->close_mtx);
    impl_->running.store(false);
#if LN_WSS_TUNNEL_SUPPORTED
    {
        // Only after connect() returned (State::Open): the client is not
        // safe to touch while it connects. A close during Connecting waits
        // for the connect timeout at most.
        std::lock_guard client_lock(impl_->client_mtx);
        if (impl_->state.load() == State::Open && impl_->client && impl_->client->is_open()) {
            impl_->client->close(httplib::ws::CloseStatus::GoingAway, "closed");
        }
    }
#endif
    if (impl_->ws_thread.joinable()) impl_->ws_thread.join();
    if (impl_->udp_thread.joinable()) impl_->udp_thread.join();
#if LN_WSS_TUNNEL_SUPPORTED
    {
        std::lock_guard client_lock(impl_->client_mtx);
        impl_->client.reset();
    }
#endif
    if (impl_->sock != kNoSocket) {
        close_wss_socket(impl_->sock);
        impl_->sock = kNoSocket;
    }
    const State st = impl_->state.load();
    if (st == State::Connecting || st == State::Open) impl_->fail(Failure::Closed);
}

WssTunnel::State WssTunnel::state() const { return impl_->state.load(); }
WssTunnel::Failure WssTunnel::failure() const { return impl_->failure.load(); }
int WssTunnel::http_status() const { return impl_->http_status.load(); }

std::chrono::milliseconds WssTunnel::connect_time() const {
    return std::chrono::milliseconds(impl_->connect_ms.load());
}

std::string WssTunnel::local_endpoint() const {
    if (impl_->port == 0) return {};
    return "127.0.0.1:" + std::to_string(impl_->port);
}

uint16_t WssTunnel::local_port() const { return impl_->port; }

WssTunnel::Counters WssTunnel::counters() const {
    Counters c;
    c.datagrams_up = impl_->datagrams_up.load();
    c.datagrams_down = impl_->datagrams_down.load();
    c.bytes_up = impl_->bytes_up.load();
    c.bytes_down = impl_->bytes_down.load();
    c.dropped = impl_->dropped.load();
    return c;
}

}  // namespace lnsdk
