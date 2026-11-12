#pragma once

/// A datagram path over a TLS WebSocket (the TCP 443 rung).
///
/// A WssTunnel owns a UDP socket on 127.0.0.1 and one wss:// connection to a
/// server's transport bridge (LemonadeNexus/Network/TransportBridge.hpp).
/// The dataplane points a peer at local_endpoint(), so it needs no
/// WebSocket support of its own:
///   - a datagram from the local sender becomes one binary WebSocket message;
///   - a binary WebSocket message becomes one datagram to the local sender.
/// Datagrams are never split or joined. A datagram that arrives while the
/// connection is not open is dropped, like a datagram on a lost UDP path; the
/// BoringTun session above retransmits what it needs.
///
/// The connection carries only what the local sender sends: BoringTun
/// ciphertext for the dataplane target, or relay wire datagrams for the relay
/// target (RelayChannel can use a tunnel as its relay address). The tunnel
/// never sees plaintext and holds no keys. TLS verification follows the SDK's
/// HTTPS client (the CA bundle from set_ca_bundle_path()); a failed
/// verification fails the tunnel. A captive portal or a proxy that answers
/// the upgrade with anything but 101 also fails it.
///
/// An empty binary message is a keepalive in both directions: it is never
/// forwarded as a datagram.
///
/// The local socket accepts datagrams only from 127.0.0.1, and only from one
/// sender: `inner_port` when it is set, otherwise the first one that sends.
///
/// Needs the cpp-httplib WebSocket client with a close() that is safe from
/// another thread (v0.54.0 and newer). On an older library open() fails with
/// Failure::Unsupported.

#include <atomic>
#include <chrono>
#include <cstdint>
#include <map>
#include <memory>
#include <string>

namespace lnsdk {

class WssTunnel {
public:
    enum class State : uint8_t {
        Idle,        ///< Not opened.
        Connecting,  ///< TCP, TLS, and the WebSocket upgrade are in progress.
        Open,        ///< Datagrams flow.
        Failed,      ///< Ended; see failure().
    };

    enum class Failure : uint8_t {
        None,
        Connect,      ///< No TCP or TLS connection (includes a failed TLS verification).
        Upgrade,      ///< The server answered the upgrade with another status (http_status()).
        Closed,       ///< The connection ended after it opened.
        Protocol,     ///< The server sent a text message.
        Socket,       ///< The local UDP socket failed.
        Unsupported,  ///< This cpp-httplib has no usable WebSocket client.
    };

    struct Options {
        /// wss://host[:port]/api/transport/ws/<target>. ws:// is accepted
        /// for tests on loopback.
        std::string url;
        /// The only local port allowed to send (0: the first local sender).
        uint16_t inner_port{0};
        /// PEM CA bundle. Empty: the SDK's bundle (ca_bundle_path()), and the
        /// system store when that is empty too.
        std::string ca_bundle_path;
        /// False only for tests with a self-signed server.
        bool verify_tls{true};
        /// Connect the URL's host to another address, keeping the name for
        /// TLS verification (tests use {"name", "127.0.0.1"}).
        std::map<std::string, std::string> host_map;
        std::chrono::milliseconds connect_timeout{5000};
        /// WebSocket ping schedule. With max_missed_pongs > 0, a server that
        /// stops answering pings ends the connection (Failure::Closed).
        std::chrono::seconds ping_interval{5};
        int                  max_missed_pongs{2};
        /// An empty binary message goes to the bridge when nothing was sent
        /// for this long, so the bridge's idle limit does not close a warm
        /// standby tunnel. The bridge does not forward it.
        std::chrono::seconds keepalive_interval{25};
    };

    struct Counters {
        uint64_t datagrams_up{0};    ///< local socket to WebSocket
        uint64_t datagrams_down{0};  ///< WebSocket to local socket
        uint64_t bytes_up{0};
        uint64_t bytes_down{0};
        uint64_t dropped{0};         ///< not open, foreign sender, or oversized
    };

    WssTunnel();
    /// Closes the tunnel.
    ~WssTunnel();

    WssTunnel(const WssTunnel&) = delete;
    WssTunnel& operator=(const WssTunnel&) = delete;

    /// Bind the local socket and start connecting in the background. Returns
    /// false (and opens nothing) when the options are invalid, the socket
    /// cannot be bound, or the library has no WebSocket client. Call once.
    bool open(Options options);

    /// Close the connection and the socket and stop the threads. Idempotent.
    /// Thread-safe.
    void close();

    [[nodiscard]] State   state() const;
    [[nodiscard]] Failure failure() const;
    /// The server's answer to a refused upgrade; 0 when unknown.
    [[nodiscard]] int http_status() const;
    /// Time from open() to State::Open; -1 ms before the tunnel opened.
    [[nodiscard]] std::chrono::milliseconds connect_time() const;

    /// "127.0.0.1:<port>": where the local sender sends. Empty before open().
    [[nodiscard]] std::string local_endpoint() const;
    [[nodiscard]] uint16_t local_port() const;

    [[nodiscard]] Counters counters() const;

    /// Bytes a WebSocket frame header adds to a `payload` byte message: 2,
    /// 4, or 10 bytes by payload size, plus 4 for the mask a client must
    /// add (RFC 6455 section 5.2). TLS adds its own record overhead on top.
    [[nodiscard]] static constexpr std::size_t frame_overhead(std::size_t payload, bool masked) {
        const std::size_t base = payload < 126 ? 2 : (payload <= 0xFFFF ? 4 : 10);
        return base + (masked ? 4 : 0);
    }

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace lnsdk
