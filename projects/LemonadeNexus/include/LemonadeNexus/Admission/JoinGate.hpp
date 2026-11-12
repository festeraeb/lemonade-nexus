#pragma once

#include <nlohmann/json.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <mutex>
#include <set>
#include <string>
#include <thread>

namespace nexus::auth { class AuthService; }

namespace nexus::admission {

/// What the operator's admission list says about an identity that has no node yet.
enum class Verdict {
    Allowed,      ///< on the allow list
    Banned,       ///< k-lined
    Pending,      ///< unknown: a request was filed and the operator was told
    Unavailable,  ///< no policy known and the gate cannot be reached: fail closed
};

struct Decision {
    Verdict     verdict{Verdict::Unavailable};
    std::string request_id;  ///< set for Pending
    std::string message;     ///< safe to show to the joining device
};

/// Operator admission list for new devices (fork-local; operator request 2026-11-12).
///
/// The list lives in one small service (the "gate"), not in this server: every server of the
/// network polls it, so one decision reaches all of them. A server keeps the last policy on disk
/// and goes on with it when the gate is down. An identity that already has a node is never asked
/// about again here. Bans are applied through the existing Ed25519 revocation list, which
/// already refuses sign-in, sessions and joins for the key.
class JoinGate {
public:
    JoinGate(std::string base_url, std::string token, std::filesystem::path state_file,
             std::string server_name, auth::AuthService& auth,
             std::chrono::milliseconds poll_every = std::chrono::milliseconds{2000});
    ~JoinGate();
    JoinGate(const JoinGate&)            = delete;
    JoinGate& operator=(const JoinGate&) = delete;

    void start();
    void stop();

    /// Decision for a key that has no node. `key` is "ed25519:<base64>" in canonical form.
    /// A key not on the list files a request with the gate (the gate de-duplicates).
    [[nodiscard]] Decision admit(const std::string& key, const nlohmann::json& hints,
                                 const std::string& remote_addr);

    /// True once a policy (live or from disk) is known.
    [[nodiscard]] bool has_policy() const;

private:
    void run();
    bool poll_once();
    void apply(const nlohmann::json& policy);
    void load_state();
    void save_state_locked() const;

    std::string base_url_;
    std::string token_;
    std::filesystem::path state_file_;
    std::string server_name_;
    auth::AuthService& auth_;
    std::chrono::milliseconds poll_every_;

    mutable std::mutex mutex_;
    bool have_policy_{false};
    std::set<std::string> allowed_;          // canonical "ed25519:<b64>"
    std::set<std::string> banned_;
    std::set<std::string> applied_banned_;   // keys this server revoked for the gate
    std::set<std::string> applied_unbanned_; // unban records already handled
    std::set<std::string> held_requests_;    // keys already filed during this run (rate limit)
    std::chrono::steady_clock::time_point last_ok_{};

    std::atomic<bool> stop_{false};
    std::thread thread_;
    std::mutex wake_mutex_;
    std::condition_variable wake_;
};

} // namespace nexus::admission
