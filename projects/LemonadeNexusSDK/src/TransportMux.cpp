#include <LemonadeNexusSDK/TransportMux.hpp>

#include <LemonadeNexus/Boringtun/UserspaceDataplane.hpp>

#include <sodium.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <vector>

#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
#else
#  include <arpa/inet.h>
#endif

namespace lnsdk {

using nexus::boringtun::UserspaceDataplane;
using Clock = std::chrono::steady_clock;

const char* transport_path_name(TransportPath path) {
    switch (path) {
        case TransportPath::Udp: return "direct";
        case TransportPath::Wss: return "wss";
        case TransportPath::None: break;
    }
    return "none";
}

// ---------------------------------------------------------------------------
// MuxPolicy
// ---------------------------------------------------------------------------

void MuxPolicy::install(TransportPath path, Clock::time_point now) {
    active_ = path;
    last_move_ = now;
    trial_ = false;
    backoff_ = timing_.trial_backoff_min;
    next_trial_ = now + timing_.hold_down;
}

void MuxPolicy::on_reply(TransportPath path, Clock::time_point now) {
    if (path == TransportPath::Udp) last_reply_udp_ = now;
    if (path == TransportPath::Wss) last_reply_wss_ = now;
}

MuxPolicy::Action MuxPolicy::decide(Clock::time_point now, bool wss_ready) {
    if (active_ == TransportPath::None) return Action::None;

    if (trial_) {
        if (last_reply_udp_ > trial_started_) {
            trial_ = false;
            active_ = TransportPath::Udp;
            last_move_ = now;
            backoff_ = timing_.trial_backoff_min;
            next_trial_ = now + timing_.hold_down;
            return Action::KeepUdp;
        }
        if (now - trial_started_ < timing_.trial_window) return Action::None;
        trial_ = false;
        next_trial_ = now + backoff_;
        backoff_ = std::min(backoff_ * 2, timing_.trial_backoff_max);
        if (wss_ready) {
            active_ = TransportPath::Wss;
            last_move_ = now;
            return Action::BackToWss;
        }
        // No WSS to go back to: stay on Udp and let the dead check decide.
        active_ = TransportPath::Udp;
        last_move_ = now;
        return Action::None;
    }

    const auto& last_reply = active_ == TransportPath::Udp ? last_reply_udp_ : last_reply_wss_;
    // A rung gets dead_after from the move to it before it can be dead.
    const auto alive_since = std::max(last_reply, last_move_);
    const bool dead = now - alive_since >= timing_.dead_after();

    if (active_ == TransportPath::Wss && !wss_ready) {
        active_ = TransportPath::Udp;
        last_move_ = now;
        return Action::MoveToUdp;
    }
    if (dead) {
        if (active_ == TransportPath::Udp && wss_ready) {
            active_ = TransportPath::Wss;
            last_move_ = now;
            next_trial_ = now + timing_.hold_down;
            return Action::MoveToWss;
        }
        if (active_ == TransportPath::Wss) {
            active_ = TransportPath::Udp;
            last_move_ = now;
            return Action::MoveToUdp;
        }
        return Action::None;  // Udp is dead and there is no standby
    }
    if (active_ == TransportPath::Wss && now - last_move_ >= timing_.hold_down &&
        now >= next_trial_) {
        trial_ = true;
        trial_started_ = now;
        return Action::TryUdp;
    }
    return Action::None;
}

uint32_t pinned_mtu(uint32_t link_mtu, bool relay_rung, uint32_t relay_header, uint32_t cap) {
    if (link_mtu <= kIpv4UdpOverhead + kBoringtunDataOverhead + relay_header) return 0;
    uint32_t mtu = std::min(cap, link_mtu - kIpv4UdpOverhead - kBoringtunDataOverhead);
    if (relay_rung) {
        mtu = std::min(mtu, link_mtu - kIpv4UdpOverhead - relay_header - kBoringtunDataOverhead);
    }
    // The Wss rung adds no per-packet limit: TCP segments each message.
    return mtu;
}

// ---------------------------------------------------------------------------
// ICMP echo probes
// ---------------------------------------------------------------------------

namespace {

constexpr std::size_t kProbePayload = 8;
constexpr std::size_t kProbePacket = 20 + 8 + kProbePayload;
constexpr std::size_t kSentSlots = 256;

uint16_t checksum(const uint8_t* data, std::size_t len) {
    uint32_t sum = 0;
    for (std::size_t i = 0; i + 1 < len; i += 2) sum += (uint32_t(data[i]) << 8) | data[i + 1];
    if (len & 1) sum += uint32_t(data[len - 1]) << 8;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return static_cast<uint16_t>(~sum);
}

std::optional<uint32_t> parse_ipv4(const std::string& text) {
    in_addr addr{};
    if (inet_pton(AF_INET, text.c_str(), &addr) != 1) return std::nullopt;
    return ntohl(addr.s_addr);
}

void put32(uint8_t* p, uint32_t v) {
    p[0] = uint8_t(v >> 24); p[1] = uint8_t(v >> 16); p[2] = uint8_t(v >> 8); p[3] = uint8_t(v);
}
uint32_t get32(const uint8_t* p) {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | p[3];
}

std::array<uint8_t, kProbePacket> echo_request(uint32_t src, uint32_t dst, uint16_t ident,
                                               uint16_t seq, uint64_t stamp) {
    std::array<uint8_t, kProbePacket> pkt{};
    pkt[0] = 0x45;
    pkt[2] = uint8_t(kProbePacket >> 8);
    pkt[3] = uint8_t(kProbePacket & 0xFF);
    pkt[4] = uint8_t(seq >> 8);
    pkt[5] = uint8_t(seq);
    pkt[8] = 64;  // TTL
    pkt[9] = 1;   // ICMP
    put32(&pkt[12], src);
    put32(&pkt[16], dst);
    const uint16_t ip_sum = checksum(pkt.data(), 20);
    pkt[10] = uint8_t(ip_sum >> 8);
    pkt[11] = uint8_t(ip_sum);
    uint8_t* icmp = &pkt[20];
    icmp[0] = 8;  // echo request
    icmp[4] = uint8_t(ident >> 8);
    icmp[5] = uint8_t(ident);
    icmp[6] = uint8_t(seq >> 8);
    icmp[7] = uint8_t(seq);
    for (int i = 0; i < 8; ++i) icmp[8 + i] = uint8_t(stamp >> (56 - 8 * i));
    const uint16_t icmp_sum = checksum(icmp, 8 + kProbePayload);
    icmp[2] = uint8_t(icmp_sum >> 8);
    icmp[3] = uint8_t(icmp_sum);
    return pkt;
}

int64_t now_us() {
    return std::chrono::duration_cast<std::chrono::microseconds>(Clock::now().time_since_epoch())
        .count();
}

}  // namespace

// ---------------------------------------------------------------------------
// TransportMux
// ---------------------------------------------------------------------------

struct TransportMux::Impl {
    UserspaceDataplane& dp;
    Options             opts;
    uint32_t            own_ip{0};
    uint32_t            peer_ip{0};
    uint16_t            ident{0};

    mutable std::mutex         mtx;  // guards everything below that is not atomic
    MuxPolicy                  policy;
    std::unique_ptr<WssTunnel> tunnel;
    std::string                wss_ep;
    Clock::time_point          next_wss_open{};
    std::chrono::milliseconds  wss_backoff{0};
    Stats                      stats;
    // Failover measurement: the last reply on the rung that died, and the
    // move away from it. Reset when the first reply on the new rung arrives.
    bool                       measuring{false};
    TransportPath              measuring_to{TransportPath::None};
    Clock::time_point          moved_at{};
    Clock::time_point          last_reply_any{};
    Clock::time_point          last_reply_before_move{};

    std::atomic<bool>          running{false};
    std::thread                thread;
    std::atomic<uint16_t>      seq{0};
    std::array<std::atomic<int64_t>, kSentSlots> sent_us{};

    Impl(UserspaceDataplane& d, Options o)
        : dp(d), opts(std::move(o)), policy(opts.timing) {
        own_ip = parse_ipv4(opts.own_ip).value_or(0);
        peer_ip = parse_ipv4(opts.peer_ip).value_or(0);
        randombytes_buf(&ident, sizeof ident);
        wss_backoff = opts.wss_reopen_min;
    }

    bool wss_enabled() const { return !opts.wss.url.empty(); }

    /// The rung of an endpoint string. Caller holds mtx.
    TransportPath classify_locked(const std::string& endpoint) const {
        if (endpoint.empty()) return TransportPath::None;
        if (!wss_ep.empty() && endpoint == wss_ep) return TransportPath::Wss;
        if (endpoint == opts.udp_endpoint) return TransportPath::Udp;
        return TransportPath::None;
    }

    std::string dp_endpoint() const {
        const auto info = dp.peer_path_info(opts.peer_pubkey);
        return info ? info->endpoint : std::string{};
    }

    std::string dp_last_rx_from() const {
        const auto info = dp.peer_path_info(opts.peer_pubkey);
        return info ? info->last_rx_from : std::string{};
    }

    /// Open a new tunnel when none is open and the backoff allows. Caller
    /// holds mtx.
    void maintain_tunnel_locked(Clock::time_point now) {
        if (!wss_enabled()) return;
        if (tunnel) {
            const auto st = tunnel->state();
            if (st == WssTunnel::State::Open) {
                wss_backoff = opts.wss_reopen_min;
                return;
            }
            if (st == WssTunnel::State::Connecting) return;
            // Failed: release it and schedule the next one.
            tunnel->close();
            tunnel.reset();
            wss_ep.clear();
            next_wss_open = now + wss_backoff;
            wss_backoff = std::min(wss_backoff * 2, opts.wss_reopen_max);
            return;
        }
        if (now < next_wss_open) return;
        auto fresh = std::make_unique<WssTunnel>();
        auto wopts = opts.wss;
        wopts.inner_port = dp.bound_port();
        if (!fresh->open(std::move(wopts))) {
            next_wss_open = now + wss_backoff;
            wss_backoff = std::min(wss_backoff * 2, opts.wss_reopen_max);
            return;
        }
        wss_ep = fresh->local_endpoint();
        tunnel = std::move(fresh);
    }

    bool wss_ready_locked() const {
        return tunnel && tunnel->state() == WssTunnel::State::Open;
    }

    void send_probe() {
        if (own_ip == 0 || peer_ip == 0) return;
        const uint16_t s = seq.fetch_add(1);
        const int64_t stamp = now_us();
        sent_us[s % kSentSlots].store(stamp);
        const auto pkt = echo_request(own_ip, peer_ip, ident, s, static_cast<uint64_t>(stamp));
        (void)dp.send_outbound_ip_packet(pkt);
        std::lock_guard lock(mtx);
        ++stats.probes_sent;
    }

    /// Carry out a policy decision. Caller holds mtx.
    void apply_locked(MuxPolicy::Action action, Clock::time_point now) {
        using A = MuxPolicy::Action;
        auto move = [&](TransportPath to, bool failover) {
            const std::string& ep = to == TransportPath::Wss ? wss_ep : opts.udp_endpoint;
            if (ep.empty()) return;
            // Pinned: packets still in flight on the old rung must not
            // pull the peer back by roaming.
            (void)dp.repoint_endpoint(opts.peer_pubkey, ep, true);
            ++stats.moves;
            if (failover) {
                ++stats.failovers;
                measuring = true;
                measuring_to = to;
                moved_at = now;
                last_reply_before_move = last_reply_any;
            }
            spdlog::info("[TransportMux] path -> {}{}", transport_path_name(to),
                         failover ? " (failover)" : "");
        };
        switch (action) {
            case A::MoveToWss: move(TransportPath::Wss, true); break;
            case A::MoveToUdp: move(TransportPath::Udp, true); break;
            case A::TryUdp:
                ++stats.trials;
                move(TransportPath::Udp, false);
                break;
            case A::BackToWss: move(TransportPath::Wss, false); break;
            case A::KeepUdp:
            case A::None: break;
        }
    }

    void monitor() {
        auto next_probe = Clock::now();
        while (running.load()) {
            const auto now = Clock::now();
            if (now >= next_probe) {
                send_probe();
                next_probe = now + opts.timing.probe_interval;
            }
            {
                std::lock_guard lock(mtx);
                maintain_tunnel_locked(now);
                // Without probe addresses there is no liveness signal: keep
                // the rung establishment chose instead of guessing.
                if (own_ip != 0 && peer_ip != 0) {
                    const auto action = policy.decide(now, wss_ready_locked());
                    apply_locked(action, now);
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }

    void run() {
        auto backoff = std::chrono::milliseconds(500);
        while (running.load()) {
            bool established = false;
            {
                std::lock_guard lock(mtx);
                established = policy.active() != TransportPath::None;
            }
            if (established) break;
            if (establish_once() != TransportPath::None) break;
            const auto until = Clock::now() + backoff;
            while (running.load() && Clock::now() < until) {
                std::this_thread::sleep_for(std::chrono::milliseconds(20));
            }
            backoff = std::min(backoff * 2, std::chrono::milliseconds(30000));
        }
        if (running.load()) monitor();
    }

    TransportPath establish_once();
};

TransportPath TransportMux::Impl::establish_once() {
    const auto base = dp.peer_path_info(opts.peer_pubkey);
    if (!base) return TransportPath::None;
    const uint64_t base_handshakes = base->handshakes;
    const auto t0 = Clock::now();

    (void)dp.probe_endpoints(opts.peer_pubkey, {opts.udp_endpoint});
    auto last_probe = t0;
    bool wss_probed = false;

    while (Clock::now() - t0 < opts.establish_timeout) {
        const auto now = Clock::now();
        std::vector<std::string> targets{opts.udp_endpoint};
        bool wss_open = false;
        std::string ep;
        {
            std::lock_guard lock(mtx);
            if (now - t0 >= opts.head_start) maintain_tunnel_locked(now);
            wss_open = wss_ready_locked();
            ep = wss_ep;
        }
        if (wss_open) targets.push_back(ep);
        // One fresh initiation to every rung as soon as the tunnel opens,
        // then a retransmission every handshake_retry.
        if ((wss_open && !wss_probed) || now - last_probe >= opts.handshake_retry) {
            (void)dp.probe_endpoints(opts.peer_pubkey, targets);
            last_probe = now;
            if (wss_open) wss_probed = true;
        }
        const auto info = dp.peer_path_info(opts.peer_pubkey);
        if (info && info->handshakes > base_handshakes) {
            std::lock_guard lock(mtx);
            const auto winner = classify_locked(info->endpoint);
            if (winner == TransportPath::None) {
                // A handshake from an address that is neither rung (for
                // example a stale tunnel): keep waiting for a rung's.
            } else {
                const auto done = Clock::now();
                // From here on the mux owns the path choice.
                (void)dp.repoint_endpoint(opts.peer_pubkey, info->endpoint, true);
                policy.install(winner, done);
                policy.on_reply(winner, done);
                stats.established_on = winner;
                stats.establish_ms =
                    std::chrono::duration_cast<std::chrono::milliseconds>(done - t0).count();
                spdlog::info("[TransportMux] established on {} in {} ms",
                             transport_path_name(winner), stats.establish_ms);
                return winner;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    return TransportPath::None;
}

TransportMux::TransportMux(UserspaceDataplane& dataplane, Options options)
    : impl_(std::make_unique<Impl>(dataplane, std::move(options))) {}

TransportMux::~TransportMux() { stop(); }

TransportPath TransportMux::establish() { return impl_->establish_once(); }

void TransportMux::start() {
    if (impl_->running.exchange(true)) return;
    impl_->thread = std::thread([impl = impl_.get()] { impl->run(); });
}

void TransportMux::stop() {
    impl_->running.store(false);
    if (impl_->thread.joinable()) impl_->thread.join();
    impl_->dp.release_pin(impl_->opts.peer_pubkey);
    std::lock_guard lock(impl_->mtx);
    if (impl_->tunnel) {
        impl_->tunnel->close();
        impl_->tunnel.reset();
    }
}

bool TransportMux::observe_inbound(std::span<const uint8_t> p) {
    if (p.size() < kProbePacket || (p[0] >> 4) != 4) return false;
    const std::size_t ihl = std::size_t(p[0] & 0x0F) * 4;
    if (ihl < 20 || p.size() < ihl + 8 + kProbePayload || p[9] != 1) return false;
    const uint8_t* icmp = p.data() + ihl;
    if (icmp[0] != 0 /* echo reply */ || icmp[1] != 0) return false;
    const uint16_t ident = uint16_t((icmp[4] << 8) | icmp[5]);
    if (ident != impl_->ident) return false;
    if (get32(p.data() + 12) != impl_->peer_ip || get32(p.data() + 16) != impl_->own_ip) return false;

    const uint16_t s = uint16_t((icmp[6] << 8) | icmp[7]);
    uint64_t stamp = 0;
    for (int i = 0; i < 8; ++i) stamp = (stamp << 8) | icmp[8 + i];
    const int64_t sent = impl_->sent_us[s % kSentSlots].load();
    const bool ours = sent != 0 && static_cast<uint64_t>(sent) == stamp;

    // The dataplane recorded this packet's source before it delivered the
    // packet, so last_rx_from names the rung the reply came through (the
    // pinned endpoint may differ).
    const std::string endpoint = impl_->dp_last_rx_from();
    const auto now = Clock::now();
    std::lock_guard lock(impl_->mtx);
    ++impl_->stats.replies;
    if (ours) impl_->stats.rtt_us = now_us() - sent;
    const auto rung = impl_->classify_locked(endpoint);
    impl_->policy.on_reply(rung, now);
    if (impl_->measuring && rung == impl_->measuring_to && rung != TransportPath::None) {
        impl_->measuring = false;
        impl_->stats.last_recover_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(now - impl_->moved_at).count();
        impl_->stats.last_outage_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                          now - impl_->last_reply_before_move)
                                          .count();
    }
    impl_->last_reply_any = now;
    return true;
}

TransportPath TransportMux::path() const {
    const auto endpoint = impl_->dp_endpoint();
    std::lock_guard lock(impl_->mtx);
    return impl_->classify_locked(endpoint);
}

TransportMux::Stats TransportMux::stats() const {
    const auto endpoint = impl_->dp_endpoint();
    std::lock_guard lock(impl_->mtx);
    Stats s = impl_->stats;
    s.path = impl_->classify_locked(endpoint);
    return s;
}

std::string TransportMux::wss_endpoint() const {
    std::lock_guard lock(impl_->mtx);
    return impl_->wss_ep;
}

}  // namespace lnsdk
