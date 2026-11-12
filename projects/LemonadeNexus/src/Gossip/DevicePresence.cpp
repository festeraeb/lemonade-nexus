#include <LemonadeNexus/Gossip/DevicePresence.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>

namespace nexus::gossip {

namespace {

using json = nlohmann::json;

bool online_at(uint64_t seen, uint64_t now) {
    return seen > 0 && seen + kDevicePresenceOnlineSec > now;
}

bool lan_listed_at(uint64_t lan_at, uint64_t now) {
    return lan_at > 0 && lan_at + kDevicePresenceLanTtlSec > now;
}

bool services_listed_at(uint64_t services_at, uint64_t now) {
    return services_at > 0 && services_at + kDevicePresenceServicesTtlSec > now;
}

bool token_char(char c, bool allow_colon_slash) {
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
        c == '_' || c == '-' || c == '.') {
        return true;
    }
    return allow_colon_slash && (c == ':' || c == '/' || c == '@' || c == '+');
}

bool token_valid(std::string_view text, std::size_t max_len, bool allow_colon_slash) {
    return !text.empty() && text.size() <= max_len &&
           std::all_of(text.begin(), text.end(),
                       [&](char c) { return token_char(c, allow_colon_slash); });
}

// msgpack bytes of the outer map with an array header for up to
// kPresenceSyncMaxEntries entries: fixmap, the "entries" key, array16.
constexpr std::size_t kPayloadOverheadBytes = 1 + 8 + 3;
// msgpack bytes of one entry besides the node id characters: fixmap, the
// "node_id" key, a str8 header, the "seen" key, and a uint64.
constexpr std::size_t kEntryOverheadBytes = 1 + 8 + 2 + 5 + 9;
// msgpack bytes of a "lan" list besides the endpoint characters: the "lan"
// key, a fixarray header, and a fixstr header per endpoint.
constexpr std::size_t kLanOverheadBytes      = 4 + 1;
constexpr std::size_t kLanEndpointHeaderBytes = 1;

/// A decimal number of 1 to `max_digits` digits without a leading zero, at
/// most `max`.
std::optional<uint32_t> strict_decimal(std::string_view text, std::size_t max_digits,
                                       uint32_t max) {
    if (text.empty() || text.size() > max_digits || (text.size() > 1 && text[0] == '0')) {
        return std::nullopt;
    }
    uint32_t value = 0;
    for (const char c : text) {
        if (c < '0' || c > '9') return std::nullopt;
        value = value * 10 + static_cast<uint32_t>(c - '0');
    }
    if (value > max) return std::nullopt;
    return value;
}

/// The LAN endpoints of `entry` that PresenceSync carries: the valid private
/// ones, in order, at most kDevicePresenceMaxLanEndpoints.
json wire_lan(const PresenceEntry& entry) {
    json out = json::array();
    for (const auto& endpoint : entry.lan) {
        if (out.size() >= kDevicePresenceMaxLanEndpoints) break;
        if (presence_lan_endpoint_valid(endpoint, false)) out.push_back(endpoint);
    }
    return out;
}

}  // namespace

bool presence_service_valid(const ServiceAnnouncement& service) {
    if (!token_valid(service.name, kDevicePresenceMaxServiceName, false) ||
        !token_valid(service.kind, kDevicePresenceMaxServiceKind, false) || service.port == 0 ||
        service.models.size() > kDevicePresenceMaxServiceModels) {
        return false;
    }
    return std::all_of(service.models.begin(), service.models.end(), [](const std::string& m) {
        return token_valid(m, kDevicePresenceMaxServiceModelLen, true);
    });
}

bool presence_services_valid(const std::vector<ServiceAnnouncement>& services) {
    if (services.size() > kDevicePresenceMaxServices) return false;
    for (std::size_t i = 0; i < services.size(); ++i) {
        if (!presence_service_valid(services[i])) return false;
        for (std::size_t j = 0; j < i; ++j) {
            if (services[j].name == services[i].name) return false;
        }
    }
    return true;
}

std::optional<std::vector<ServiceAnnouncement>> parse_presence_services(const json& value) {
    if (!value.is_array() || value.size() > kDevicePresenceMaxServices) return std::nullopt;
    std::vector<ServiceAnnouncement> out;
    for (const auto& item : value) {
        if (!item.is_object()) return std::nullopt;
        ServiceAnnouncement service;
        for (const auto& [key, field] : item.items()) {
            if (key == "name" && field.is_string()) {
                service.name = field.get<std::string>();
            } else if (key == "kind" && field.is_string()) {
                service.kind = field.get<std::string>();
            } else if (key == "port" && field.is_number_unsigned()) {
                const auto port = field.get<uint64_t>();
                if (port == 0 || port > 65535) return std::nullopt;
                service.port = static_cast<uint16_t>(port);
            } else if (key == "models" && field.is_array() &&
                       field.size() <= kDevicePresenceMaxServiceModels) {
                for (const auto& model : field) {
                    if (!model.is_string()) return std::nullopt;
                    service.models.push_back(model.get<std::string>());
                }
            } else {
                return std::nullopt;
            }
        }
        out.push_back(std::move(service));
    }
    if (!presence_services_valid(out)) return std::nullopt;
    return out;
}

json presence_services_json(const std::vector<ServiceAnnouncement>& services) {
    json out = json::array();
    for (const auto& service : services) {
        out.push_back({{"name", service.name},
                       {"kind", service.kind},
                       {"port", service.port},
                       {"models", service.models}});
    }
    return out;
}

bool presence_node_id_valid(std::string_view node_id) {
    if (node_id.empty() || node_id.size() > kDevicePresenceMaxNodeIdBytes) return false;
    return std::all_of(node_id.begin(), node_id.end(), [](char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
               c == '_' || c == '-';
    });
}

bool presence_lan_endpoint_valid(std::string_view text, bool allow_loopback) {
    const auto colon = text.find(':');
    if (colon == std::string_view::npos || text.find(':', colon + 1) != std::string_view::npos) {
        return false;
    }
    const auto port = strict_decimal(text.substr(colon + 1), 5, 65535);
    if (!port || *port == 0) return false;
    uint32_t ip = 0;
    std::string_view rest = text.substr(0, colon);
    for (int i = 0; i < 4; ++i) {
        const auto dot = rest.find('.');
        const bool last = i == 3;
        if (last != (dot == std::string_view::npos)) return false;
        const auto octet = strict_decimal(rest.substr(0, dot), 3, 255);
        if (!octet) return false;
        ip = (ip << 8) | *octet;
        if (!last) rest = rest.substr(dot + 1);
    }
    const auto in = [ip](uint32_t network, int prefix) {
        return (ip & (~uint32_t{0} << (32 - prefix))) == network;
    };
    if (in(0x0A000000, 8) || in(0xAC100000, 12) || in(0xC0A80000, 16) || in(0x64400000, 10)) {
        return true;
    }
    return allow_loopback && in(0x7F000000, 8);
}

std::vector<std::vector<uint8_t>> encode_presence_sync(const std::vector<PresenceEntry>& entries) {
    std::vector<std::vector<uint8_t>> out;
    json page = json::array();
    std::size_t page_bytes = kPayloadOverheadBytes;
    const auto flush = [&] {
        if (page.empty()) return;
        out.push_back(json::to_msgpack(json{{"entries", std::move(page)}}));
        page = json::array();
        page_bytes = kPayloadOverheadBytes;
    };
    for (const auto& e : entries) {
        if (e.seen == 0 || !presence_node_id_valid(e.node_id)) continue;
        json item{{"node_id", e.node_id}, {"seen", e.seen}};
        auto bytes = kEntryOverheadBytes + e.node_id.size();
        if (auto lan = wire_lan(e); !lan.empty()) {
            bytes += kLanOverheadBytes;
            for (const auto& endpoint : lan) {
                bytes += kLanEndpointHeaderBytes + endpoint.get_ref<const std::string&>().size();
            }
            item["lan"] = std::move(lan);
        }
        if (presence_services_valid(e.services) && !e.services.empty()) {
            auto services = presence_services_json(e.services);
            bytes += json::to_msgpack(json{{"services", services}}).size();
            item["services"] = std::move(services);
        }
        if (page.size() >= kPresenceSyncMaxEntries ||
            page_bytes + bytes > kPresenceSyncMaxPayloadBytes) {
            flush();
        }
        page.push_back(std::move(item));
        page_bytes += bytes;
    }
    flush();
    return out;
}

std::optional<std::vector<PresenceEntry>> decode_presence_sync(std::span<const uint8_t> payload) {
    if (payload.empty() || payload.size() > kPresenceSyncMaxPayloadBytes) return std::nullopt;
    const auto doc = json::from_msgpack(payload.begin(), payload.end(), true, false);
    if (doc.is_discarded() || !doc.is_object()) return std::nullopt;
    const auto list = doc.find("entries");
    if (list == doc.end() || !list->is_array() || list->empty() ||
        list->size() > kPresenceSyncMaxEntries) {
        return std::nullopt;
    }
    std::vector<PresenceEntry> out;
    out.reserve(list->size());
    for (const auto& e : *list) {
        if (!e.is_object()) return std::nullopt;
        const auto id = e.find("node_id");
        const auto seen = e.find("seen");
        if (id == e.end() || !id->is_string() || seen == e.end() ||
            !seen->is_number_unsigned()) {
            return std::nullopt;
        }
        const auto& node_id = id->get_ref<const std::string&>();
        const auto time = seen->get<uint64_t>();
        if (!presence_node_id_valid(node_id) || time == 0) return std::nullopt;
        PresenceEntry entry{node_id, time};
        // A gossip peer is not the device: its LAN list gets the heartbeat
        // rules again, without the single-host loopback exception.
        if (const auto lan = e.find("lan"); lan != e.end()) {
            if (!lan->is_array() || lan->size() > kDevicePresenceMaxLanEndpoints) {
                return std::nullopt;
            }
            for (const auto& endpoint : *lan) {
                if (!endpoint.is_string()) return std::nullopt;
                const auto& text = endpoint.get_ref<const std::string&>();
                if (!presence_lan_endpoint_valid(text, false) ||
                    std::find(entry.lan.begin(), entry.lan.end(), text) != entry.lan.end()) {
                    return std::nullopt;
                }
                entry.lan.push_back(text);
            }
        }
        // The device's own announcement, relayed: the same bounds again.
        if (const auto services = e.find("services"); services != e.end()) {
            auto parsed = parse_presence_services(*services);
            if (!parsed) return std::nullopt;
            entry.services = std::move(*parsed);
        }
        out.push_back(std::move(entry));
    }
    return out;
}

DevicePresence::Entry* DevicePresence::find_or_add_locked(const std::string& node_id,
                                                          uint64_t now) {
    if (const auto it = entries_.find(node_id); it != entries_.end()) return &it->second;
    if (entries_.size() >= kDevicePresenceMaxEntries) {
        std::erase_if(entries_, [now](const auto& item) {
            return now >= item.second.seen && now - item.second.seen >= kDevicePresenceRetentionSec;
        });
        if (entries_.size() >= kDevicePresenceMaxEntries) return nullptr;
    }
    return &entries_[node_id];
}

DevicePresence::LocalResult DevicePresence::record_local(
    const std::string& node_id, uint64_t now, std::optional<std::vector<std::string>> lan,
    std::optional<std::vector<ServiceAnnouncement>> services) {
    LocalResult result;
    if (now == 0 || !presence_node_id_valid(node_id)) return result;
    {
        std::lock_guard lock(mtx_);
        auto* entry = find_or_add_locked(node_id, now);
        if (!entry) return result;
        result.accepted = true;
        result.became_online = !online_at(entry->seen, now);
        result.locally_new = !online_at(entry->local_seen, now);
        entry->seen = std::max(entry->seen, now);
        entry->local_seen = std::max(entry->local_seen, now);
        entry->online = true;
        if (lan) {
            const bool listed = lan_listed_at(entry->lan_at, now);
            result.lan_changed = lan->empty() ? listed : (!listed || entry->lan != *lan);
            entry->lan = std::move(*lan);
            entry->lan_at = entry->lan.empty() ? 0 : now;
        }
        if (services) {
            const bool listed = services_listed_at(entry->services_at, now);
            result.services_changed =
                services->empty() ? listed : (!listed || entry->services != *services);
            entry->services = std::move(*services);
            entry->services_at = entry->services.empty() ? 0 : now;
        }
    }
    if (result.became_online || result.lan_changed || result.services_changed) notify_changed();
    return result;
}

DevicePresence::MergeResult DevicePresence::merge_remote(const std::vector<PresenceEntry>& entries,
                                                         uint64_t now) {
    MergeResult result;
    {
        std::lock_guard lock(mtx_);
        for (const auto& e : entries) {
            if (!presence_node_id_valid(e.node_id) || e.seen == 0) continue;
            if (e.seen > now + kDevicePresenceMaxSkewSec) {
                ++result.ahead;
                continue;
            }
            const auto seen = std::min(e.seen, now);
            if (now - seen >= kDevicePresenceRetentionSec) continue;
            auto* entry = find_or_add_locked(e.node_id, now);
            if (!entry || seen <= entry->seen) continue;
            ++result.merged;
            if (!online_at(entry->seen, now) && online_at(seen, now)) result.became_online = true;
            entry->seen = seen;
            if (online_at(seen, now)) entry->online = true;
            // The server that heard the device last says what it reported.
            const bool was_listed = lan_listed_at(entry->lan_at, now);
            const bool listed = !e.lan.empty() && lan_listed_at(seen, now);
            if (listed != was_listed || (listed && entry->lan != e.lan)) result.lan_changed = true;
            entry->lan = e.lan;
            entry->lan_at = e.lan.empty() ? 0 : seen;
            const bool services_were = services_listed_at(entry->services_at, now);
            const bool services_now = !e.services.empty() && services_listed_at(seen, now);
            if (services_now != services_were || (services_now && entry->services != e.services)) {
                result.services_changed = true;
            }
            entry->services = e.services;
            entry->services_at = e.services.empty() ? 0 : seen;
        }
    }
    if (result.became_online || result.lan_changed || result.services_changed) notify_changed();
    return result;
}

DevicePresence::Status DevicePresence::status(const std::string& node_id, uint64_t now) const {
    std::lock_guard lock(mtx_);
    const auto it = entries_.find(node_id);
    if (it == entries_.end()) return {};
    return {online_at(it->second.seen, now), it->second.seen};
}

std::vector<std::string> DevicePresence::lan_endpoints(const std::string& node_id,
                                                       uint64_t now) const {
    std::lock_guard lock(mtx_);
    const auto it = entries_.find(node_id);
    if (it == entries_.end() || !lan_listed_at(it->second.lan_at, now)) return {};
    return it->second.lan;
}

std::vector<ServiceAnnouncement> DevicePresence::services(const std::string& node_id,
                                                          uint64_t now) const {
    std::lock_guard lock(mtx_);
    const auto it = entries_.find(node_id);
    if (it == entries_.end() || !services_listed_at(it->second.services_at, now)) return {};
    return it->second.services;
}

std::vector<PresenceEntry> DevicePresence::local_online(uint64_t now) const {
    std::vector<PresenceEntry> out;
    {
        std::lock_guard lock(mtx_);
        for (const auto& [id, entry] : entries_) {
            if (!online_at(entry.local_seen, now)) continue;
            out.push_back({id, entry.local_seen,
                           lan_listed_at(entry.lan_at, now) ? entry.lan : std::vector<std::string>{},
                           services_listed_at(entry.services_at, now)
                               ? entry.services
                               : std::vector<ServiceAnnouncement>{}});
        }
    }
    std::sort(out.begin(), out.end(),
              [](const PresenceEntry& a, const PresenceEntry& b) { return a.node_id < b.node_id; });
    return out;
}

DevicePresence::Sweep DevicePresence::sweep(uint64_t now) {
    Sweep result;
    std::lock_guard lock(mtx_);
    for (auto it = entries_.begin(); it != entries_.end();) {
        auto& entry = it->second;
        const bool online = online_at(entry.seen, now);
        if (entry.online && !online) result.went_offline = true;
        entry.online = online;
        if (online) {
            const auto expiry = entry.seen + kDevicePresenceOnlineSec;
            if (result.next_expiry == 0 || expiry < result.next_expiry) result.next_expiry = expiry;
        }
        if (entry.lan_at > 0 && !lan_listed_at(entry.lan_at, now)) {
            entry.lan.clear();
            entry.lan_at = 0;
        }
        if (entry.services_at > 0 && !services_listed_at(entry.services_at, now)) {
            entry.services.clear();
            entry.services_at = 0;
        }
        if (now >= entry.seen && now - entry.seen >= kDevicePresenceRetentionSec) {
            it = entries_.erase(it);
        } else {
            ++it;
        }
    }
    return result;
}

void DevicePresence::set_changed_hook(std::function<void()> hook) {
    std::lock_guard lock(hook_mtx_);
    hook_ = std::move(hook);
}

void DevicePresence::notify_changed() {
    // The hook runs under hook_mtx_, so set_changed_hook waits for a running
    // call and the hook's owner can clear it before it is destroyed.
    std::lock_guard lock(hook_mtx_);
    if (hook_) hook_();
}

std::size_t DevicePresence::size() const {
    std::lock_guard lock(mtx_);
    return entries_.size();
}

}  // namespace nexus::gossip
