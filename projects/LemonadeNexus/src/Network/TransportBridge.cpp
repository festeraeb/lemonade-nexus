#include <LemonadeNexus/Network/TransportBridge.hpp>

#include <spdlog/spdlog.h>

#include <algorithm>
#include <cctype>
#include <thread>
#include <vector>

#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
namespace {
using udp_socket_t = SOCKET;
constexpr udp_socket_t kNoSocket = INVALID_SOCKET;
void close_udp(udp_socket_t s) { closesocket(s); }
}  // namespace
#else
#  include <arpa/inet.h>
#  include <netinet/in.h>
#  include <sys/socket.h>
#  include <unistd.h>
namespace {
using udp_socket_t = int;
constexpr udp_socket_t kNoSocket = -1;
void close_udp(udp_socket_t s) { ::close(s); }
}  // namespace
#endif

namespace nexus::network {

namespace {

/// How long one WebSocket read waits, so the loop sees stop() and the idle
/// limit in time.
constexpr auto kReadSlice = std::chrono::seconds(1);

bool valid_target_name(const std::string& name) {
    if (name.empty() || name.size() > 32) return false;
    return std::all_of(name.begin(), name.end(), [](unsigned char c) {
        return std::isalnum(c) != 0 || c == '-' || c == '_';
    });
}

/// A UDP socket bound to 127.0.0.1 (any port) and connected to
/// 127.0.0.1:`port`, so it receives only from the target. kNoSocket on error.
udp_socket_t open_target_socket(uint16_t port) {
    const udp_socket_t sock = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == kNoSocket) return kNoSocket;
#ifdef _WIN32
    DWORD timeout_ms = 100;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout_ms),
               sizeof(timeout_ms));
#else
    timeval tv{};
    tv.tv_usec = 100 * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif
    sockaddr_in local{};
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sockaddr_in target = local;
    target.sin_port = htons(port);
    if (::bind(sock, reinterpret_cast<const sockaddr*>(&local), sizeof(local)) != 0 ||
        ::connect(sock, reinterpret_cast<const sockaddr*>(&target), sizeof(target)) != 0) {
        close_udp(sock);
        return kNoSocket;
    }
    return sock;
}

int64_t steady_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
}

}  // namespace

TransportBridge::~TransportBridge() { stop(); }

bool TransportBridge::add_target(const std::string& name, uint16_t udp_port) {
    if (!valid_target_name(name) || udp_port == 0) return false;
    targets_[name] = udp_port;
    return true;
}

void TransportBridge::register_routes(httplib::Server& server) {
    for (const auto& [name, port] : targets_) {
        server.WebSocket(kTransportBridgePathPrefix + name,
                         [this, port = port](const httplib::Request& req, httplib::ws::WebSocket& ws) {
                             serve(req.remote_addr, port, ws);
                         });
    }
}

void TransportBridge::stop() {
    stopping_.store(true);
    // Each connection checks stopping_ at least once per read slice.
    const auto deadline = std::chrono::steady_clock::now() + 3 * kReadSlice;
    while (active_.load() > 0 && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
}

TransportBridge::Counters TransportBridge::counters() const {
    Counters c;
    c.connections_accepted = accepted_.load();
    c.connections_refused = refused_.load();
    c.datagrams_up = datagrams_up_.load();
    c.datagrams_down = datagrams_down_.load();
    c.bytes_up = bytes_up_.load();
    c.bytes_down = bytes_down_.load();
    c.dropped = dropped_.load();
    c.refused_per_ip = refused_per_ip_.load();
    c.closed_oversize = closed_oversize_.load();
    c.closed_idle = closed_idle_.load();
    return c;
}

bool TransportBridge::admit(const std::string& client_ip, bool& per_ip) {
    per_ip = false;
    if (stopping_.load()) return false;
    std::lock_guard lock(ip_mtx_);
    if (active_.load() >= limits_.max_connections) return false;
    auto& count = per_ip_[client_ip];
    if (count >= limits_.max_per_ip) {
        if (count == 0) per_ip_.erase(client_ip);
        per_ip = true;
        return false;
    }
    ++count;
    active_.fetch_add(1);
    return true;
}

void TransportBridge::release(const std::string& client_ip) {
    std::lock_guard lock(ip_mtx_);
    if (auto it = per_ip_.find(client_ip); it != per_ip_.end() && --it->second == 0) {
        per_ip_.erase(it);
    }
    active_.fetch_sub(1);
}

void TransportBridge::serve(const std::string& client_ip, uint16_t udp_port,
                            httplib::ws::WebSocket& ws) {
    bool per_ip = false;
    if (!admit(client_ip, per_ip)) {
        refused_.fetch_add(1);
        if (per_ip) refused_per_ip_.fetch_add(1);
        ws.close(httplib::ws::CloseStatus::GoingAway, "bridge busy");
        return;
    }
    const udp_socket_t sock = open_target_socket(udp_port);
    if (sock == kNoSocket) {
        release(client_ip);
        refused_.fetch_add(1);
        ws.close(httplib::ws::CloseStatus::InternalError, "no target");
        return;
    }
    accepted_.fetch_add(1);

    std::atomic<bool>    done{false};
    std::atomic<int64_t> last_activity{steady_ms()};

    // Target to client. The socket is connected, so every datagram comes
    // from the target.
    std::thread down([&] {
        std::vector<char> buf(limits_.max_datagram + 1);
        while (!done.load()) {
            const auto n = ::recv(sock, buf.data(), static_cast<int>(buf.size()), 0);
            if (n <= 0) continue;  // timeout or a transient error
            const auto len = static_cast<std::size_t>(n);
            if (len > limits_.max_datagram) {
                dropped_.fetch_add(1);
                continue;
            }
            if (!ws.send(buf.data(), len)) break;
            datagrams_down_.fetch_add(1);
            bytes_down_.fetch_add(len);
            last_activity.store(steady_ms());
        }
        done.store(true);
    });

    // Client to target.
    ws.set_read_timeout(kReadSlice);
    std::string msg;
    const int64_t idle_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(limits_.idle_timeout).count();
    while (!done.load() && !stopping_.load()) {
        const auto r = ws.read(msg);
        if (r == httplib::ws::ReadResult::Timeout) {
            if (steady_ms() - last_activity.load() > idle_ms) {
                closed_idle_.fetch_add(1);
                break;
            }
            continue;
        }
        if (r == httplib::ws::ReadResult::Fail) break;
        if (r == httplib::ws::ReadResult::Text) {
            // The bridge carries datagrams only.
            ws.close(httplib::ws::CloseStatus::UnsupportedData, "binary only");
            break;
        }
        if (msg.empty()) {
            // A keepalive: it keeps a warm standby tunnel open.
            last_activity.store(steady_ms());
            continue;
        }
        if (msg.size() > limits_.max_datagram) {
            closed_oversize_.fetch_add(1);
            ws.close(httplib::ws::CloseStatus::MessageTooBig, "one datagram per message");
            break;
        }
        ::send(sock, msg.data(), static_cast<int>(msg.size()), 0);
        datagrams_up_.fetch_add(1);
        bytes_up_.fetch_add(msg.size());
        last_activity.store(steady_ms());
    }

    done.store(true);
    down.join();
    close_udp(sock);
    // Free the slot before the close handshake: a peer that never answers
    // the close frame (a silent or broken client) holds only this thread,
    // for the library's close timeout, not a bridge slot.
    release(client_ip);
    if (ws.is_open()) ws.close(httplib::ws::CloseStatus::GoingAway, "bridge closed");
}

}  // namespace nexus::network
