#pragma once

// Client-side address map. A device that reaches the servers through a forward (for example a phone
// that reaches LAN-only servers over Tailscale) cannot use the hosts and IPv4 addresses the servers
// advertise. The host app sets a map from advertised host or IPv4 to an address the device can reach;
// the SDK applies it to the HTTPS clients (name -> address, the certificate is still verified against
// the name), the server's dataplane endpoint, relay endpoints and peer endpoints. Process-wide, empty
// by default (no change). A server never sets it.

#include <map>
#include <mutex>
#include <string>

namespace nexus::network {

class AddressMap {
public:
    static void set(std::map<std::string, std::string> m) {
        auto& s = state();
        std::lock_guard lock(s.mtx);
        s.map = std::move(m);
    }
    static std::map<std::string, std::string> all() {
        auto& s = state();
        std::lock_guard lock(s.mtx);
        return s.map;
    }
    static bool empty() {
        auto& s = state();
        std::lock_guard lock(s.mtx);
        return s.map.empty();
    }
    /// The address to use for `host` (itself when not in the map).
    static std::string host(const std::string& host) {
        auto& s = state();
        std::lock_guard lock(s.mtx);
        auto it = s.map.find(host);
        return it == s.map.end() ? host : it->second;
    }
    /// "host:port" with the host mapped; anything without a port is returned unchanged.
    static std::string endpoint(const std::string& ep) {
        const auto colon = ep.rfind(':');
        if (colon == std::string::npos || colon == 0) return ep;
        return host(ep.substr(0, colon)) + ep.substr(colon);
    }

private:
    struct State {
        std::mutex mtx;
        std::map<std::string, std::string> map;
    };
    static State& state() {
        static State s;
        return s;
    }
};

}  // namespace nexus::network
