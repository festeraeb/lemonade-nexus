#pragma once

/// Path selection under one BoringTun session: UDP, or a TLS WebSocket.
///
/// The dataplane (UserspaceDataplane) owns the peer's Noise state: keys,
/// tunnel index, and sessions. The netstack is bound above the dataplane
/// once. A TransportMux decides which path the peer's datagrams take and
/// moves the peer between paths with UserspaceDataplane::repoint_endpoint:
/// the session stays, no handshake runs, and the netstack sees no change.
/// The peer follows by normal authenticated roaming on the first packet from
/// the new path. On this side the mux pins the endpoint it chose, so packets
/// still in flight on the old path (a TCP stream drains for a while) do not
/// pull the peer back; stop() releases the pin.
///
/// Rungs:
///   - Udp: the peer's own UDP endpoint (direct path).
///   - Wss: a WssTunnel to the peer's transport bridge over TLS on TCP
///     (normally 443). For networks that block UDP. It is a fallback: TCP
///     carrying a tunneled TCP stream collapses under loss, so the mux
///     prefers Udp whenever Udp works.
///
/// Establishment (establish()): a handshake initiation goes to the Udp
/// endpoint at once. After `head_start` the WSS tunnel opens; when it is
/// open, one fresh initiation goes to both rungs. The rung of the first
/// handshake the dataplane completes wins. A connected socket never wins: a
/// captive portal or proxy that accepts TCP and answers with a web page
/// completes no Noise handshake. The losing rung stays warm: an open WSS
/// tunnel stays open, and an unproven Udp rung is tried again later.
///
/// Monitoring (start()): an ICMP echo request goes through the tunnel to the
/// peer's tunnel address every `probe_interval`; the peer's netstack answers
/// it. observe_inbound() takes the replies out of the inbound packet stream.
/// When the active rung gives no reply for miss_limit intervals, the mux
/// moves to the other rung (failover). After a move, it stays for
/// `hold_down` before it tries Udp again (hysteresis); a failed try backs
/// off. A move away from a dead rung is never held back.
///
/// MTU: pinned_mtu() gives the netstack MTU that every rung carries without
/// fragmenting, so a move never black-holes a packet that fit the old rung.

#include <LemonadeNexusSDK/WssTunnel.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <thread>
#include <vector>

namespace nexus::boringtun {
class UserspaceDataplane;
}

namespace lnsdk {

enum class TransportPath : uint8_t {
    None,  ///< No rung proved yet.
    Udp,   ///< The peer's UDP endpoint.
    Wss,   ///< The TLS WebSocket tunnel.
};

/// "none", "direct", or "wss" (the status `path` vocabulary).
[[nodiscard]] const char* transport_path_name(TransportPath path);

/// The pure decision core of TransportMux. It holds the path state; the
/// caller feeds it the time and the facts and carries out its decision.
class MuxPolicy {
public:
    using Clock = std::chrono::steady_clock;

    struct Timing {
        std::chrono::milliseconds probe_interval{100};
        /// The active rung is dead after this many probe intervals without
        /// a reply on it.
        uint32_t miss_limit{4};
        /// After a move, no voluntary move back to Udp for this long.
        std::chrono::milliseconds hold_down{10000};
        /// How long a try of the Udp rung may take to give a reply.
        std::chrono::milliseconds trial_window{600};
        /// Delay before the next try after a failed one; doubles per failure.
        std::chrono::milliseconds trial_backoff_min{5000};
        std::chrono::milliseconds trial_backoff_max{60000};

        [[nodiscard]] std::chrono::milliseconds dead_after() const {
            return probe_interval * static_cast<int>(miss_limit);
        }
    };

    enum class Action : uint8_t {
        None,
        MoveToWss,    ///< Failover from a dead Udp rung.
        MoveToUdp,    ///< Failover from a dead or closed Wss rung.
        TryUdp,       ///< Start a try of the Udp rung (repoint to Udp).
        KeepUdp,      ///< The try gave a reply on Udp: stay there.
        BackToWss,    ///< The try failed: repoint to Wss.
    };

    explicit MuxPolicy(Timing timing) : timing_(timing) {}

    /// Install the rung establishment chose, at `now`.
    void install(TransportPath path, Clock::time_point now);

    /// A probe reply arrived through `path` at `now`.
    void on_reply(TransportPath path, Clock::time_point now);

    /// The decision at `now`. `wss_ready`: a WSS tunnel is open. The policy
    /// updates its own state to the decision.
    Action decide(Clock::time_point now, bool wss_ready);

    [[nodiscard]] TransportPath active() const { return active_; }
    /// Moves away from a dead rung in a row with no reply in between. From
    /// 2 on, both rungs are silent (the peer likely lost the session): each
    /// further move waits twice as long (up to 16 x dead_after), and the mux
    /// starts a new handshake on both rungs.
    [[nodiscard]] uint32_t dead_streak() const { return dead_streak_; }
    [[nodiscard]] bool          trying() const { return trial_; }
    [[nodiscard]] Clock::time_point last_move() const { return last_move_; }
    [[nodiscard]] const Timing& timing() const { return timing_; }

private:
    Timing            timing_;
    TransportPath     active_{TransportPath::None};
    Clock::time_point last_move_{};
    Clock::time_point last_reply_udp_{};
    Clock::time_point last_reply_wss_{};
    bool              trial_{false};
    Clock::time_point trial_started_{};
    Clock::time_point next_trial_{};
    std::chrono::milliseconds backoff_{0};
    uint32_t          dead_streak_{0};
};

/// Bytes the rungs add around one inner IP packet.
inline constexpr uint32_t kIpv4UdpOverhead = 28;        ///< outer IPv4 + UDP header
inline constexpr uint32_t kBoringtunDataOverhead = 32;  ///< type, index, counter, tag

/// The largest inner IP packet that every enabled rung carries in one link
/// packet of `link_mtu` bytes, capped at `cap` (the dataplane default).
///   - Udp:   link_mtu - 28 - 32
///   - relay: link_mtu - 28 - relay_header - 32 (the 9103 relay's Data header)
///   - Wss:   a TCP stream: TCP segments the message, so the rung adds no
///            per-packet limit below the 65535-byte message maximum.
[[nodiscard]] uint32_t pinned_mtu(uint32_t link_mtu, bool relay_rung, uint32_t relay_header,
                                  uint32_t cap);

class TransportMux {
public:
    struct Options {
        std::string peer_pubkey;    ///< base64 mesh public key of the peer
        std::string udp_endpoint;   ///< "a.b.c.d:port" of the peer
        /// The WSS rung's tunnel settings. inner_port is set by the mux to
        /// the dataplane port; url is replaced by the entries of wss_urls.
        WssTunnel::Options wss;
        /// The WSS routes in preference order. A tunnel that fails (no
        /// connection, a refused upgrade, or a closed connection) moves the
        /// rung to the next route; the reopen backoff applies only after
        /// every route failed in a row. Empty: wss.url alone, and no WSS
        /// rung when that is empty too.
        std::vector<std::string> wss_urls;
        /// Our tunnel address (dotted), the probe source, and the peer's,
        /// the probe target. Without both, the mux races and keeps the
        /// winner but does not fail over (no liveness signal).
        std::string own_ip;
        std::string peer_ip;
        std::chrono::milliseconds head_start{250};
        std::chrono::milliseconds establish_timeout{10000};
        /// Handshake initiations are repeated this often during establish().
        std::chrono::milliseconds handshake_retry{1000};
        MuxPolicy::Timing timing;
        /// Delay before a failed WSS tunnel is opened again; doubles per
        /// failure up to the maximum.
        std::chrono::milliseconds wss_reopen_min{500};
        std::chrono::milliseconds wss_reopen_max{30000};
    };

    struct Stats {
        TransportPath path{TransportPath::None};
        TransportPath established_on{TransportPath::None};
        int64_t       establish_ms{-1};    ///< establish() start to the first handshake
        uint64_t      moves{0};            ///< every repoint after establishment
        uint64_t      failovers{0};        ///< moves away from a dead rung
        uint64_t      trials{0};
        uint64_t      rehandshakes{0};     ///< handshakes started because both rungs were silent
        uint64_t      probes_sent{0};
        uint64_t      replies{0};
        /// The newest failover: from the last reply on the dead rung to the
        /// first reply on the new one (the gap a stream sees), and from the
        /// move to that first reply. -1 until a failover completed.
        int64_t       last_outage_ms{-1};
        int64_t       last_recover_ms{-1};
        int64_t       rtt_us{-1};          ///< newest probe round trip
        std::string   wss_url;             ///< the route the open tunnel uses
        uint64_t      wss_route_changes{0};
    };

    TransportMux(nexus::boringtun::UserspaceDataplane& dataplane, Options options);
    /// Calls stop().
    ~TransportMux();

    TransportMux(const TransportMux&) = delete;
    TransportMux& operator=(const TransportMux&) = delete;

    /// The cold-start race. Blocks for at most establish_timeout. Returns the
    /// winning rung, or None when no handshake completed. Not thread-safe
    /// with start().
    TransportPath establish();

    /// Run in a background thread: establish() until it succeeds (with
    /// backoff), then monitor and move between rungs. Idempotent.
    void start();

    /// Stop the thread and close the WSS tunnel. The peer stays at the
    /// endpoint it has. Idempotent.
    void stop();

    /// Offer one decrypted inbound IP packet. True when it is a reply to
    /// this mux's probe, which the caller must then not deliver further.
    /// Thread-safe; called from dataplane receive threads.
    bool observe_inbound(std::span<const uint8_t> ip_packet);

    /// The rung the dataplane sends to now.
    [[nodiscard]] TransportPath path() const;
    [[nodiscard]] Stats stats() const;
    /// The open WSS tunnel's local endpoint, empty when none.
    [[nodiscard]] std::string wss_endpoint() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace lnsdk
