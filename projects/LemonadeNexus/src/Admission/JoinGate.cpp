#include <LemonadeNexus/Admission/JoinGate.hpp>

#include <LemonadeNexus/Auth/AuthService.hpp>
#include <LemonadeNexus/Tree/TreeTypes.hpp>

#include <httplib.h>
#include <spdlog/spdlog.h>

#include <fstream>

namespace nexus::admission {

namespace {

/// "http://host:port" -> {host, port}. Only plain http is used (LAN or loopback, bearer token).
bool split_url(const std::string& url, std::string& host, int& port) {
    constexpr std::string_view scheme = "http://";
    if (!url.starts_with(scheme)) return false;
    auto rest = url.substr(scheme.size());
    if (const auto slash = rest.find('/'); slash != std::string::npos) rest.resize(slash);
    const auto colon = rest.rfind(':');
    if (colon == std::string::npos) {
        host = rest;
        port = 80;
        return !host.empty();
    }
    host = rest.substr(0, colon);
    try {
        port = std::stoi(rest.substr(colon + 1));
    } catch (...) {
        return false;
    }
    return !host.empty() && port > 0 && port < 65536;
}

std::string strip_prefix(const std::string& key) {
    constexpr std::string_view p = "ed25519:";
    return key.starts_with(p) ? key.substr(p.size()) : key;
}

std::set<std::string> read_set(const nlohmann::json& j, const char* name) {
    std::set<std::string> out;
    if (!j.contains(name) || !j.at(name).is_array()) return out;
    for (const auto& v : j.at(name)) {
        if (v.is_string()) out.insert(tree::canonical_principal(v.get<std::string>()));
    }
    return out;
}

} // namespace

JoinGate::JoinGate(std::string base_url, std::string token, std::filesystem::path state_file,
                   std::string server_name, auth::AuthService& auth,
                   std::chrono::milliseconds poll_every)
    : base_url_(std::move(base_url)), token_(std::move(token)), state_file_(std::move(state_file)),
      server_name_(std::move(server_name)), auth_(auth), poll_every_(poll_every) {
    load_state();
}

JoinGate::~JoinGate() { stop(); }

void JoinGate::start() {
    if (thread_.joinable()) return;
    stop_ = false;
    thread_ = std::thread([this] { run(); });
}

void JoinGate::stop() {
    stop_ = true;
    wake_.notify_all();
    if (thread_.joinable()) thread_.join();
}

bool JoinGate::has_policy() const {
    std::lock_guard lock(mutex_);
    return have_policy_;
}

void JoinGate::load_state() {
    std::ifstream in(state_file_);
    if (!in) return;
    const auto j = nlohmann::json::parse(in, nullptr, false);
    if (!j.is_object()) return;
    std::lock_guard lock(mutex_);
    allowed_           = read_set(j, "allowed");
    banned_            = read_set(j, "banned");
    applied_banned_    = read_set(j, "applied_banned");
    applied_unbanned_  = read_set(j, "applied_unbanned");
    have_policy_       = j.value("have_policy", false);
    spdlog::info("[admission] cached policy loaded: {} allowed, {} banned", allowed_.size(),
                 banned_.size());
}

void JoinGate::save_state_locked() const {
    nlohmann::json j = {{"have_policy", have_policy_},
                        {"allowed", allowed_},
                        {"banned", banned_},
                        {"applied_banned", applied_banned_},
                        {"applied_unbanned", applied_unbanned_}};
    std::error_code ec;
    std::filesystem::create_directories(state_file_.parent_path(), ec);
    const auto tmp = state_file_.string() + ".tmp";
    {
        std::ofstream out(tmp, std::ios::trunc);
        out << j.dump();
        if (!out) return;
    }
    std::filesystem::rename(tmp, state_file_, ec);
}

void JoinGate::run() {
    while (!stop_) {
        try {
            poll_once();
        } catch (const std::exception& e) {
            spdlog::warn("[admission] poll failed: {}", e.what());
        }
        std::unique_lock lk(wake_mutex_);
        wake_.wait_for(lk, poll_every_, [this] { return stop_.load(); });
    }
}

bool JoinGate::poll_once() {
    std::string host;
    int port = 0;
    if (!split_url(base_url_, host, port)) return false;
    httplib::Client cli(host, port);
    cli.set_connection_timeout(2, 0);
    cli.set_read_timeout(3, 0);
    const httplib::Headers headers{{"Authorization", "Bearer " + token_}};
    const auto res = cli.Get("/v1/policy", headers);
    if (!res || res->status != 200) {
        return false;
    }
    const auto j = nlohmann::json::parse(res->body, nullptr, false);
    if (!j.is_object()) return false;
    apply(j);
    return true;
}

void JoinGate::apply(const nlohmann::json& policy) {
    const auto allowed   = read_set(policy, "allowed");
    const auto banned    = read_set(policy, "banned");
    const auto unbanned  = read_set(policy, "unbanned");

    std::lock_guard lock(mutex_);
    const bool changed = !have_policy_ || allowed != allowed_ || banned != banned_;
    allowed_     = allowed;
    banned_      = banned;
    have_policy_ = true;
    last_ok_     = std::chrono::steady_clock::now();
    bool dirty   = changed;

    for (const auto& k : banned_) {
        if (applied_banned_.contains(k)) continue;
        if (auth_.revoke_ed25519(strip_prefix(k))) {
            applied_banned_.insert(k);
            applied_unbanned_.erase(k);
            dirty = true;
            spdlog::warn("[admission] k-line applied for {}", k.substr(0, 16));
        }
    }
    for (auto it = applied_banned_.begin(); it != applied_banned_.end();) {
        if (banned_.contains(*it)) {
            ++it;
            continue;
        }
        (void)auth_.unrevoke_ed25519(strip_prefix(*it));
        spdlog::info("[admission] k-line lifted for {}", it->substr(0, 16));
        applied_unbanned_.insert(*it);
        it = applied_banned_.erase(it);
        dirty = true;
    }
    // An unban this server missed while it was down: the delete that came with the
    // k-line may have revoked the key here without this server ever applying the ban.
    for (const auto& k : unbanned) {
        if (banned_.contains(k) || applied_unbanned_.contains(k)) continue;
        (void)auth_.unrevoke_ed25519(strip_prefix(k));
        applied_unbanned_.insert(k);
        dirty = true;
    }
    if (dirty) save_state_locked();
}

Decision JoinGate::admit(const std::string& key, const nlohmann::json& hints,
                         const std::string& remote_addr) {
    {
        std::lock_guard lock(mutex_);
        if (banned_.contains(key)) {
            return {Verdict::Banned, {}, "this device was removed by the operator"};
        }
        if (allowed_.contains(key)) return {Verdict::Allowed, {}, {}};
        if (!have_policy_) {
            return {Verdict::Unavailable, {},
                    "this network's admission service is not reachable; try again shortly"};
        }
    }
    std::string host;
    int port = 0;
    if (!split_url(base_url_, host, port)) {
        return {Verdict::Unavailable, {}, "admission service is not configured"};
    }
    httplib::Client cli(host, port);
    cli.set_connection_timeout(2, 0);
    cli.set_read_timeout(4, 0);
    const httplib::Headers headers{{"Authorization", "Bearer " + token_}};
    nlohmann::json body = {{"key", key}, {"server", server_name_}, {"remote", remote_addr},
                           {"hints", hints}};
    const auto res = cli.Post("/v1/request", headers, body.dump(), "application/json");
    if (!res || res->status != 200) {
        return {Verdict::Unavailable, {},
                "this network's admission service is not reachable; try again shortly"};
    }
    const auto j = nlohmann::json::parse(res->body, nullptr, false);
    if (!j.is_object()) return {Verdict::Unavailable, {}, "admission service answered badly"};
    const auto state = j.value("state", std::string{});
    if (state == "allowed") {
        // The gate allowed it between two polls.
        return {Verdict::Allowed, {}, {}};
    }
    if (state == "banned") return {Verdict::Banned, {}, "this device was removed by the operator"};
    Decision d;
    d.verdict    = Verdict::Pending;
    d.request_id = j.value("request_id", std::string{});
    d.message    = state == "rejected"
                       ? "the operator declined this device's request; ask the operator"
                       : "waiting for operator approval of this device (request " + d.request_id + ")";
    return d;
}

} // namespace nexus::admission
