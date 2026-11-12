#pragma once

/// Datagram bridge from TLS WebSocket connections to local UDP services.
///
/// A client on a network that blocks UDP (a hotel or airport access point, a
/// network that permits only outbound TCP 443) cannot reach the mesh
/// transport port or the relay port. The bridge lets such a client reach the
/// same two services over the public HTTPS listener instead:
///
///     GET /api/transport/ws/dataplane  ->  127.0.0.1:<mesh transport port>
///     GET /api/transport/ws/relay      ->  127.0.0.1:<relay port>
///
/// Each WebSocket connection gets its own UDP socket, bound to 127.0.0.1 and
/// connected to the one target the route names. One binary WebSocket message
/// is one datagram, in both directions. Messages are never split or joined,
/// so the bridge adds no ordering coupling between datagrams beyond the TCP
/// stream itself. An empty binary message is a keepalive: it resets the
/// idle limit and is not forwarded.
///
/// The bridge never decrypts. The dataplane target receives BoringTun
/// datagrams that the Noise session authenticates and encrypts end to end;
/// the relay target receives the relay wire protocol (RelayWire.hpp), whose
/// Data payload is the same BoringTun ciphertext. The bridge only moves
/// bytes between a client and a service that the client could reach over
/// UDP anyway, so it adds no authority: the target services apply their own
/// checks (Noise handshake, relay ticket) to every datagram.
///
/// A route shares the public listener with the HTTPS API: cpp-httplib routes
/// a request with `Upgrade: websocket` on a bridge path to the bridge, and
/// every other request to the API, so one TLS port serves both.

#include <httplib.h>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
#include <mutex>
#include <string>

namespace nexus::network {

/// Path prefix of every bridge route. The target name follows it.
inline constexpr const char* kTransportBridgePathPrefix = "/api/transport/ws/";

class TransportBridge {
public:
    struct Limits {
        /// Bridge connections open at once. A connection holds one HTTP
        /// worker thread for its whole life, so this must stay well below
        /// the listener's thread pool.
        std::size_t max_connections{32};
        /// Bridge connections open at once from one client address. Behind
        /// a TCP pass-through proxy every client has the proxy's address, so
        /// raise it there.
        std::size_t max_per_ip{4};
        /// Largest datagram in either direction (the UDP maximum). A larger
        /// message ends the connection. The WebSocket reader itself refuses
        /// a frame over CPPHTTPLIB_WEBSOCKET_MAX_PAYLOAD_LENGTH (64 KiB in
        /// this build, cmake/libraries/httplib.cmake) before it allocates.
        std::size_t max_datagram{65535};
        /// A connection that carries nothing in either direction for this
        /// long is closed.
        std::chrono::seconds idle_timeout{90};
    };

    struct Counters {
        uint64_t connections_accepted{0};
        uint64_t connections_refused{0};
        uint64_t datagrams_up{0};      ///< WebSocket to UDP
        uint64_t datagrams_down{0};    ///< UDP to WebSocket
        uint64_t bytes_up{0};
        uint64_t bytes_down{0};
        uint64_t refused_per_ip{0};    ///< refused by max_per_ip
        uint64_t closed_oversize{0};   ///< ended by a message over max_datagram
        uint64_t closed_idle{0};       ///< ended by the idle limit
        uint64_t dropped{0};           ///< oversized datagrams from the target
    };

    TransportBridge() = default;
    explicit TransportBridge(Limits limits) : limits_(limits) {}
    /// Calls stop().
    ~TransportBridge();

    TransportBridge(const TransportBridge&) = delete;
    TransportBridge& operator=(const TransportBridge&) = delete;

    /// Name a target: `name` (letters, digits, '-' and '_') becomes the
    /// route kTransportBridgePathPrefix + name, which forwards to
    /// 127.0.0.1:`udp_port`. False for an invalid name or port 0. Call
    /// before register_routes.
    bool add_target(const std::string& name, uint16_t udp_port);

    /// Register one WebSocket route per target on `server`, and turn on
    /// TCP_NODELAY for the listener (see the .cpp). Re-runnable when the
    /// listener object is replaced (a plain-to-TLS upgrade).
    void register_routes(httplib::Server& server);

    /// Refuse new connections and close the open ones within about one
    /// second. Idempotent.
    void stop();

    [[nodiscard]] std::size_t active_connections() const { return active_.load(); }
    [[nodiscard]] Counters counters() const;

private:
    void serve(const std::string& client_ip, uint16_t udp_port, httplib::ws::WebSocket& ws);
    /// Take a connection slot for `client_ip`. Sets `per_ip` when the
    /// address limit refused it.
    [[nodiscard]] bool admit(const std::string& client_ip, bool& per_ip);
    void release(const std::string& client_ip);

    Limits                          limits_;
    std::map<std::string, uint16_t> targets_;
    std::atomic<bool>               stopping_{false};
    std::atomic<std::size_t>        active_{0};

    std::atomic<uint64_t> accepted_{0};
    std::atomic<uint64_t> refused_{0};
    std::atomic<uint64_t> datagrams_up_{0};
    std::atomic<uint64_t> datagrams_down_{0};
    std::atomic<uint64_t> bytes_up_{0};
    std::atomic<uint64_t> bytes_down_{0};
    std::atomic<uint64_t> dropped_{0};
    std::atomic<uint64_t> refused_per_ip_{0};
    std::atomic<uint64_t> closed_oversize_{0};
    std::atomic<uint64_t> closed_idle_{0};

    std::mutex                         ip_mtx_;
    std::map<std::string, std::size_t> per_ip_;  ///< guarded by ip_mtx_; no zero entries

};

}  // namespace nexus::network
