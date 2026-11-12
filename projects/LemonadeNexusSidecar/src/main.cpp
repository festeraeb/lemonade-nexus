// Headless mesh client for embedding in a host app (e.g. Lemonade's lemond):
// joins a mesh over the SDK's userspace dataplane, publishes the host's local
// services to mesh peers, and serves a localhost control API the parent polls.

#include <LemonadeNexusSDK/LemonadeNexusClient.hpp>
#include <LemonadeNexusSDK/MeshPort.hpp>

#include <httplib.h>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#ifdef _WIN32
#  include <process.h>
#  include <windows.h>
#  define getpid _getpid
#else
#  include <csignal>
#  include <unistd.h>
#endif

#ifndef NEXUS_VERSION
#  define NEXUS_VERSION "0.0.0-dev"
#endif
#ifndef NEXUS_GIT_COMMIT
#  define NEXUS_GIT_COMMIT "unknown"
#endif

namespace {

using namespace std::chrono_literals;

// --- Shutdown signalling ----------------------------------------------------

std::atomic<bool>       g_stop{false};
std::condition_variable g_stop_cv;
std::mutex              g_stop_mtx;

void request_stop() {
    g_stop.store(true);
    g_stop_cv.notify_all();
}

extern "C" void handle_signal(int) { request_stop(); }

/// Returns false if shutdown was requested during the wait.
bool interruptible_sleep(std::chrono::milliseconds d) {
    std::unique_lock lock(g_stop_mtx);
    g_stop_cv.wait_for(lock, d, [] { return g_stop.load(); });
    return !g_stop.load();
}

// --- Parent-process liveness (closes the orphan gap on all platforms) -------

bool parent_alive(long parent_pid) {
    if (parent_pid <= 0) return true;  // no parent to track
#ifdef _WIN32
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                           static_cast<DWORD>(parent_pid));
    if (!h) return false;
    DWORD code = 0;
    bool alive = GetExitCodeProcess(h, &code) && code == STILL_ACTIVE;
    CloseHandle(h);
    return alive;
#else
    return ::kill(static_cast<pid_t>(parent_pid), 0) == 0 || errno == EPERM;
#endif
}

// --- Config -----------------------------------------------------------------

struct ExposeMapping {
    uint16_t vport{0};       // published at <mesh_ip>:vport
    uint16_t local_port{0};  // bridged to 127.0.0.1:local_port
};

struct SidecarConfig {
    std::string host{"127.0.0.1"};
    uint16_t    port{9100};
    bool        use_tls{true};
    std::string identity_path;
    std::string data_root{"nexus-sidecar"};
    std::string link_token;
    std::vector<ExposeMapping> exposes;
    uint16_t    control_port{9110};
    std::string control_token;                 // bearer required by the control API (disabled if empty)
    long        parent_pid{0};
    std::string log_level{"info"};
    bool        pin_server{false};             // keep the configured endpoint (no SEIP switch)
    bool        inference{false};              // join as a Tier 3 inference node (ln_set_inference_node)
    std::string catalog_path;                  // service catalog JSON registered on the first exposed vport
    std::string genesis_key;                   // base64 Genesis key to pin for Tier 1 verification
    uint16_t    mesh_port{0};                  // 0 = no mesh port; else 127.0.0.1:<mesh_port> serves the group
    std::string mesh_local;                    // local Lemonade URL the mesh port serves as "local"
    std::string mesh_selection{"auto"};        // local | auto | <node id>
    std::string link_token_out;                // after the join, mint an invite for this group and write it here (0600)
    std::vector<std::string> link_token_perms; // permissions that invite grants (default: the server's default set)
    std::string device_name;                   // name of this device's endpoint when the join creates it
    std::vector<std::string> fallback_servers; // more "host:port" public APIs to try when `server` is down
    bool        leave{false};                  // one-shot: sign in, delete this device's node, exit
    int         leave_after_sec{0};            // with leave: run the mesh this long first (a live check)
};

std::optional<ExposeMapping> parse_expose(const std::string& spec) {
    auto colon = spec.find(':');
    if (colon == std::string::npos) return std::nullopt;
    try {
        ExposeMapping m;
        m.vport      = static_cast<uint16_t>(std::stoi(spec.substr(0, colon)));
        m.local_port = static_cast<uint16_t>(std::stoi(spec.substr(colon + 1)));
        if (m.vport == 0 || m.local_port == 0) return std::nullopt;
        return m;
    } catch (...) {
        return std::nullopt;
    }
}

void apply_json_config(SidecarConfig& cfg, const nlohmann::json& j) {
    if (j.contains("server")) {
        auto s = j.at("server").get<std::string>();
        if (auto c = s.rfind(':'); c != std::string::npos) {
            cfg.host = s.substr(0, c);
            cfg.port = static_cast<uint16_t>(std::stoi(s.substr(c + 1)));
        }
    }
    if (j.contains("tls"))          cfg.use_tls       = j.at("tls").get<bool>();
    if (j.contains("identity"))     cfg.identity_path = j.at("identity").get<std::string>();
    if (j.contains("data_root"))    cfg.data_root     = j.at("data_root").get<std::string>();
    if (j.contains("link_token"))   cfg.link_token    = j.at("link_token").get<std::string>();
    if (j.contains("control_port")) cfg.control_port  = j.at("control_port").get<uint16_t>();
    if (j.contains("control_token")) cfg.control_token = j.at("control_token").get<std::string>();
    if (j.contains("log_level"))    cfg.log_level     = j.at("log_level").get<std::string>();
    if (j.contains("inference"))    cfg.inference     = j.at("inference").get<bool>();
    if (j.contains("catalog"))      cfg.catalog_path  = j.at("catalog").get<std::string>();
    if (j.contains("genesis_key"))  cfg.genesis_key   = j.at("genesis_key").get<std::string>();
    if (j.contains("device_name"))  cfg.device_name   = j.at("device_name").get<std::string>();
    if (j.contains("leave"))        cfg.leave         = j.at("leave").get<bool>();
    if (j.contains("leave_after_sec")) cfg.leave_after_sec = j.at("leave_after_sec").get<int>();
    if (j.contains("fallback_servers") && j.at("fallback_servers").is_array())
        cfg.fallback_servers = j.at("fallback_servers").get<std::vector<std::string>>();
    if (j.contains("mesh_port"))    cfg.mesh_port     = j.at("mesh_port").get<uint16_t>();
    if (j.contains("mesh_local"))   cfg.mesh_local    = j.at("mesh_local").get<std::string>();
    if (j.contains("mesh_selection")) cfg.mesh_selection = j.at("mesh_selection").get<std::string>();
    if (j.contains("link_token_out")) cfg.link_token_out = j.at("link_token_out").get<std::string>();
    if (j.contains("link_token_perms") && j.at("link_token_perms").is_array())
        cfg.link_token_perms = j.at("link_token_perms").get<std::vector<std::string>>();
    if (j.contains("expose") && j.at("expose").is_array()) {
        for (const auto& e : j.at("expose")) {
            if (auto m = parse_expose(e.get<std::string>())) cfg.exposes.push_back(*m);
        }
    }
}

void apply_env(SidecarConfig& cfg) {
    if (const char* v = std::getenv("LN_SIDECAR_SERVER")) {
        std::string s = v;
        if (auto c = s.rfind(':'); c != std::string::npos) {
            cfg.host = s.substr(0, c);
            cfg.port = static_cast<uint16_t>(std::atoi(s.substr(c + 1).c_str()));
        }
    }
    if (std::getenv("LN_SIDECAR_TLS"))            cfg.use_tls = true;
    if (const char* v = std::getenv("LN_SIDECAR_IDENTITY"))   cfg.identity_path = v;
    if (const char* v = std::getenv("LN_SIDECAR_DATA_ROOT"))  cfg.data_root = v;
    if (const char* v = std::getenv("LN_SIDECAR_LINK_TOKEN")) cfg.link_token = v;
    if (const char* v = std::getenv("LN_SIDECAR_CONTROL_PORT"))
        cfg.control_port = static_cast<uint16_t>(std::atoi(v));
    if (const char* v = std::getenv("LN_SIDECAR_CONTROL_TOKEN")) cfg.control_token = v;
    if (const char* v = std::getenv("LN_SIDECAR_EXPOSE")) {
        if (auto m = parse_expose(v)) cfg.exposes.push_back(*m);
    }
    if (std::getenv("LN_SIDECAR_PIN_SERVER"))         cfg.pin_server = true;
    if (std::getenv("LN_SIDECAR_INFERENCE"))          cfg.inference = true;
    if (const char* v = std::getenv("LN_SIDECAR_CATALOG")) cfg.catalog_path = v;
    if (const char* v = std::getenv("SP_PARENT_PID")) cfg.parent_pid = std::atol(v);
    if (const char* v = std::getenv("SP_LOG_LEVEL"))  cfg.log_level = v;
}

void print_usage(const char* prog) {
    std::printf(
        "Usage: %s [OPTIONS]\n\n"
        "Headless Lemonade Nexus mesh client. Joins a mesh and publishes local\n"
        "services to authorized peers over the userspace dataplane.\n\n"
        "Options:\n"
        "  --server <fqdn:port>    Nexus server public API by cert FQDN (default 127.0.0.1:9100)\n"
        "  --tls                   Use HTTPS for the public API (default; verification always on)\n"
        "  --pin-server            Keep the configured endpoint (no SEIP switch after join)\n"
        "  --identity <path>       Ed25519 identity file (default <data-root>/identity.json)\n"
        "  --data-root <path>      State directory (default ./nexus-sidecar)\n"
        "  --link-token <token>    Single-use device link token (first join)\n"
        "  --expose <vport:local>  Publish 127.0.0.1:local at <mesh_ip>:vport (repeatable)\n"
        "  --inference             Join as a Tier 3 inference node (the device a mesh port can select);\n"
        "                          pair with --expose 13305:<lemond port>\n"
        "  --catalog <path>        Service catalog JSON to register on the first --expose vport, so\n"
        "                          svc:<family> permissions gate the exposed service\n"
        "  --genesis-key <b64>     Pin the network's Genesis key (Tier 1 verification)\n"
        "  --mesh-port <N>         Serve this device's group on 127.0.0.1:N (the mesh port)\n"
        "  --mesh-local <url>      Local Lemonade URL the mesh port serves as 'local'\n"
        "  --mesh-selection <sel>  local | auto | <node id> (default auto)\n"
        "  --link-token-out <path> After joining, mint a 1 h invite for this group and write it to <path> (0600)\n"
        "  --control-port <N>      Localhost control API port (default 9110)\n"
        "  --control-token <tok>   Bearer required by all control endpoints (API off if unset)\n"
        "  --parent-pid <pid>      Exit when this process disappears\n"
        "  --config <path>         JSON config file (CLI and env override it)\n"
        "  --log-level <level>     trace/debug/info/warn/error\n"
        "  --version               Print version and commit, then exit\n",
        prog);
}

// Precedence: config file < env < CLI flags.
SidecarConfig load_config(int argc, char* argv[], bool& want_exit) {
    SidecarConfig cfg;

    // First pass: --config and --version.
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--version") == 0) {
            std::printf("lemonade-nexus-sidecar %s (%s)\n", NEXUS_VERSION, NEXUS_GIT_COMMIT);
            want_exit = true;
            return cfg;
        }
        if ((std::strcmp(argv[i], "--help") == 0 || std::strcmp(argv[i], "-h") == 0)) {
            print_usage(argv[0]);
            want_exit = true;
            return cfg;
        }
        if (std::strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
            std::ifstream ifs(argv[i + 1]);
            if (ifs) {
                auto j = nlohmann::json::parse(ifs, nullptr, false);
                if (!j.is_discarded()) apply_json_config(cfg, j);
                else spdlog::warn("--config {}: invalid JSON, ignoring", argv[i + 1]);
            } else {
                spdlog::warn("--config {}: cannot open, ignoring", argv[i + 1]);
            }
        }
    }

    apply_env(cfg);

    for (int i = 1; i < argc; ++i) {
        auto next = [&](const char* flag) -> const char* {
            return (std::strcmp(argv[i], flag) == 0 && i + 1 < argc) ? argv[++i] : nullptr;
        };
        if (const char* v = next("--server")) {
            std::string s = v;
            if (auto c = s.rfind(':'); c != std::string::npos) {
                cfg.host = s.substr(0, c);
                cfg.port = static_cast<uint16_t>(std::atoi(s.substr(c + 1).c_str()));
            } else {
                cfg.host = s;
            }
        } else if (std::strcmp(argv[i], "--tls") == 0) {
            cfg.use_tls = true;
        } else if (std::strcmp(argv[i], "--pin-server") == 0) {
            cfg.pin_server = true;
        } else if (const char* v2 = next("--identity")) {
            cfg.identity_path = v2;
        } else if (const char* v3 = next("--data-root")) {
            cfg.data_root = v3;
        } else if (const char* v4 = next("--link-token")) {
            cfg.link_token = v4;
        } else if (const char* v5 = next("--expose")) {
            if (auto m = parse_expose(v5)) cfg.exposes.push_back(*m);
            else spdlog::warn("--expose {}: expected vport:localport, ignoring", v5);
        } else if (const char* v6 = next("--control-port")) {
            cfg.control_port = static_cast<uint16_t>(std::atoi(v6));
        } else if (const char* v7 = next("--parent-pid")) {
            cfg.parent_pid = std::atol(v7);
        } else if (const char* v8 = next("--log-level")) {
            cfg.log_level = v8;
        } else if (const char* v9 = next("--control-token")) {
            cfg.control_token = v9;
        } else if (std::strcmp(argv[i], "--inference") == 0) {
            cfg.inference = true;
        } else if (const char* v10 = next("--catalog")) {
            cfg.catalog_path = v10;
        } else if (const char* v11 = next("--genesis-key")) {
            cfg.genesis_key = v11;
        } else if (const char* v12 = next("--mesh-port")) {
            cfg.mesh_port = static_cast<uint16_t>(std::atoi(v12));
        } else if (const char* v13 = next("--mesh-local")) {
            cfg.mesh_local = v13;
        } else if (const char* v14 = next("--mesh-selection")) {
            cfg.mesh_selection = v14;
        } else if (const char* v15 = next("--link-token-out")) {
            cfg.link_token_out = v15;
        } else if (next("--config")) {
            // already handled
        }
    }

    if (cfg.identity_path.empty()) cfg.identity_path = cfg.data_root + "/identity.json";
    return cfg;
}

// --- Shared runtime state exposed by the control API ------------------------

struct SidecarState {
    std::mutex   mtx;
    std::string  status{"starting"};  // starting|joining|running|degraded|stopped
    std::string  node_id;
    std::string  tunnel_ip;
    bool         mesh_up{false};
    uint32_t     peer_count{0};
    uint32_t     join_failures{0};
};

}  // namespace

int main(int argc, char* argv[]) {
    bool want_exit = false;
    SidecarConfig cfg = load_config(argc, argv, want_exit);
    if (want_exit) return 0;

    spdlog::set_level(spdlog::level::from_str(cfg.log_level));

    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);

    spdlog::info("lemonade-nexus-sidecar {} ({})", NEXUS_VERSION, NEXUS_GIT_COMMIT);
    spdlog::info("Server {}://{}:{}, control 127.0.0.1:{}, {} service(s) to expose",
                 cfg.use_tls ? "https" : "http", cfg.host, cfg.port,
                 cfg.control_port, cfg.exposes.size());

    // Identity: reuse the persisted keypair so the node keeps its account across
    // restarts; generate on first run.
    lnsdk::Identity identity;
    if (!identity.load(cfg.identity_path)) {
        spdlog::info("No identity at {} — generating a new keypair", cfg.identity_path);
        identity.generate();
        if (!identity.save(cfg.identity_path)) {
            spdlog::error("Failed to persist identity to {}", cfg.identity_path);
            return 1;
        }
    }

    lnsdk::ServerConfig sc(cfg.host, cfg.port, cfg.use_tls);
    // Pin only when asked. --server must be a cert FQDN (verification is always
    // on); pinning keeps the SDK on that FQDN instead of switching to the
    // server's advertised SEIP FQDN after join.
    sc.pin_server = cfg.pin_server;
    // Fallback public APIs: the SDK's Tier 1 refresh asks only the servers in its pool, and the
    // pool held just `server`, so a client whose server went away had nobody to ask (seen on the
    // CESARops work Nexus 2026-11-12). Seed the pool with the others.
    for (const auto& f : cfg.fallback_servers) {
        if (auto c = f.rfind(':'); c != std::string::npos) {
            sc.servers.push_back({f.substr(0, c), static_cast<uint16_t>(std::stoi(f.substr(c + 1))), cfg.use_tls});
        }
    }
    lnsdk::LemonadeNexusClient client{sc};
    client.set_identity(identity);
    if (!cfg.link_token.empty()) client.set_link_token(cfg.link_token);
    // Tier 3: the server records is_inference when it creates the endpoint, so
    // this must precede the join. Without it the device is Tier 4 and a mesh
    // port answers 409 "not an inference server" for it.
    if (cfg.inference) {
        client.set_inference_node(true);
        spdlog::info("Joining as a Tier 3 inference node");
    }
    if (!cfg.device_name.empty() && !client.set_device_name(cfg.device_name)) {
        spdlog::error("device_name refused: {}", cfg.device_name);
        return 1;
    }
    if (!cfg.genesis_key.empty()) {
        auto g = client.set_genesis_key(cfg.genesis_key);
        if (!g.ok) {
            spdlog::error("--genesis-key: {}", g.error);
            return 1;
        }
    }
    std::unique_ptr<lnsdk::MeshPort> mesh_port;
    nlohmann::json catalog_json;  // empty = none
    if (!cfg.catalog_path.empty()) {
        std::ifstream cin(cfg.catalog_path);
        if (!cin) {
            spdlog::error("--catalog {}: cannot read", cfg.catalog_path);
            return 1;
        }
        catalog_json = nlohmann::json::parse(cin, nullptr, false);
        if (catalog_json.is_discarded() || !catalog_json.is_object()) {
            spdlog::error("--catalog {}: not a JSON object", cfg.catalog_path);
            return 1;
        }
    }

    SidecarState state;

    // --- Localhost control API (parent health-checks this) ------------------
    // Loopback is not an authorization boundary: any local process (or a browser
    // via DNS-rebinding) can reach it. Every endpoint requires the bearer token
    // the parent passes in; with no token configured the control API serves
    // nothing.
    httplib::Server control;
    control.set_pre_routing_handler(
        [&cfg](const httplib::Request& req, httplib::Response& res) {
        if (req.has_header("Origin")) {  // block browser (DNS-rebinding/CSRF) callers
            res.status = 403;
            res.set_content(R"({"error":"origin not allowed"})", "application/json");
            return httplib::Server::HandlerResponse::Handled;
        }
        if (cfg.control_token.empty()) {
            res.status = 503;
            res.set_content(R"({"error":"control API disabled: no control token configured"})",
                            "application/json");
            return httplib::Server::HandlerResponse::Handled;
        }
        const auto& h = req.get_header_value("Authorization");
        constexpr std::string_view bearer = "Bearer ";
        if (h.size() <= bearer.size() || h.compare(0, bearer.size(), bearer) != 0 ||
            h.substr(bearer.size()) != cfg.control_token) {
            res.status = 401;
            res.set_content(R"({"error":"control token required"})", "application/json");
            return httplib::Server::HandlerResponse::Handled;
        }
        return httplib::Server::HandlerResponse::Unhandled;
    });
    control.Get("/version", [](const httplib::Request&, httplib::Response& res) {
        nlohmann::json j = {{"service", "lemonade-nexus-sidecar"},
                            {"version", NEXUS_VERSION},
                            {"commit", NEXUS_GIT_COMMIT}};
        res.set_content(j.dump(), "application/json");
    });
    control.Get("/health", [&state](const httplib::Request&, httplib::Response& res) {
        std::lock_guard lock(state.mtx);
        bool ok = state.status == "running";
        nlohmann::json j = {{"status", ok ? "ok" : "degraded"},
                            {"mesh", state.mesh_up ? "up" : "down"},
                            {"detail", state.status}};
        res.status = ok ? 200 : 503;
        res.set_content(j.dump(), "application/json");
    });
    control.Get("/status", [&](const httplib::Request&, httplib::Response& res) {
        std::lock_guard lock(state.mtx);
        nlohmann::json exposed = nlohmann::json::array();
        for (const auto& e : cfg.exposes) {
            exposed.push_back({{"vport", e.vport}, {"local_port", e.local_port}});
        }
        nlohmann::json j = {
            {"status", state.status},
            {"node_id", state.node_id},
            {"tunnel_ip", state.tunnel_ip},
            {"mesh_up", state.mesh_up},
            {"peer_count", state.peer_count},
            {"join_failures", state.join_failures},
            {"server", cfg.host + ":" + std::to_string(cfg.port)},
            {"exposed", exposed},
            {"mesh_port", mesh_port ? mesh_port->status() : nlohmann::json()},
        };
        res.set_content(j.dump(), "application/json");
    });
    // Live dataplane view for a status page: the tunnel status the SDK reports
    // (server_path direct/wss/none, tunnel_up, per-peer endpoint or relay,
    // last handshake, bytes) plus this sidecar's own state and version.
    control.Get("/mesh", [&](const httplib::Request&, httplib::Response& res) {
        const auto ms = client.mesh_status();
        nlohmann::json peers = nlohmann::json::array();
        for (const auto& p : client.get_mesh_peers()) {
            peers.push_back({{"node_id", p.node_id}, {"hostname", p.hostname},
                             {"tunnel_ip", p.tunnel_ip}, {"is_online", p.is_online},
                             {"server_online", p.server_online}, {"path", p.path},
                             {"endpoint", p.endpoint}, {"relay_endpoint", p.relay_endpoint},
                             {"last_handshake", p.last_handshake}, {"last_seen", p.last_seen},
                             {"rx_bytes", p.rx_bytes}, {"tx_bytes", p.tx_bytes},
                             {"latency_ms", p.latency_ms}, {"mesh_pubkey", p.mesh_pubkey},
                             {"permissions", p.permissions}});
        }
        nlohmann::json j = {
            {"version", NEXUS_VERSION}, {"commit", NEXUS_GIT_COMMIT},
            {"server", cfg.host + ":" + std::to_string(cfg.port)},
            {"is_up", ms.is_up}, {"tunnel_up", ms.tunnel_up},
            {"server_path", ms.server_path}, {"needs_rejoin", ms.needs_rejoin},
            {"tunnel_ip", ms.tunnel_ip}, {"peer_count", ms.peer_count},
            {"online_count", ms.online_count},
            {"total_rx_bytes", ms.total_rx_bytes}, {"total_tx_bytes", ms.total_tx_bytes},
            {"dataplane_peers", ms.peers}, {"peers", peers},
        };
        {
            std::lock_guard lock(state.mtx);
            j["status"] = state.status;
            j["node_id"] = state.node_id;
            j["join_failures"] = state.join_failures;
        }
        res.set_content(j.dump(), "application/json");
    });
    // Mint a device link token so another device can join this account.
    control.Get("/peers", [&](const httplib::Request&, httplib::Response& res) {
        nlohmann::json out = nlohmann::json::array();
        for (const auto& p : client.get_mesh_peers()) {
            out.push_back({{"node_id", p.node_id}, {"hostname", p.hostname}, {"tunnel_ip", p.tunnel_ip},
                           {"is_online", p.is_online}, {"path", p.path}, {"latency_ms", p.latency_ms},
                           {"mgmt_pubkey", p.mgmt_pubkey}, {"permissions", p.permissions}});
        }
        res.set_content(out.dump(), "application/json");
    });
    // Set one key's assignment on a tree node this device administers:
    // {"node_id", "pubkey", "permissions": [...]}. The server replaces that key's
    // entry; an empty list removes it. This is how a service permission such as
    // svc:nauti-worker is granted when an invite did not carry it.
    control.Post("/assign", [&](const httplib::Request& req, httplib::Response& res) {
        auto j = nlohmann::json::parse(req.body, nullptr, false);
        if (j.is_discarded() || !j.contains("node_id") || !j.contains("pubkey") || !j.contains("permissions")) {
            res.status = 400;
            res.set_content(R"({"error":"expected {node_id, pubkey, permissions}"})", "application/json");
            return;
        }
        const nlohmann::json body = {{"pubkey", j.at("pubkey")}, {"permissions", j.at("permissions")}};
        auto r = client.call_private_api("POST", "/api/tree/node/assignments/" + j.at("node_id").get<std::string>(),
                                         body.dump());
        res.status = r.ok ? 200 : 502;
        res.set_content(r.ok ? r.value : nlohmann::json{{"error", r.error}}.dump(), "application/json");
    });
    control.Post("/link-token", [&](const httplib::Request& req, httplib::Response& res) {
        uint32_t ttl_sec = 600;
        if (!req.body.empty()) {
            auto j = nlohmann::json::parse(req.body, nullptr, false);
            if (!j.is_discarded()) ttl_sec = j.value("ttl_sec", ttl_sec);
        }
        auto result = client.create_link_token(ttl_sec);
        if (!result.ok) {
            res.status = 502;
            res.set_content(nlohmann::json{{"error", result.error}}.dump(),
                            "application/json");
            return;
        }
        auto named = result.value;
        {
                            auto by = client.session_server();
                            named["issued_by"] = by.empty() ? cfg.host + ":" + std::to_string(cfg.port) : by;
                        }  // redeem it there
        res.set_content(named.dump(), "application/json");
    });
    // Bridge a peer's mesh service to a loopback port the host app can dial.
    control.Post("/egress", [&](const httplib::Request& req, httplib::Response& res) {
        auto j = nlohmann::json::parse(req.body, nullptr, false);
        if (j.is_discarded() || !j.contains("ip") || !j.contains("port")) {
            res.status = 400;
            res.set_content(R"({"error":"expected {ip, port}"})", "application/json");
            return;
        }
        uint16_t lp = client.open_egress(j.at("ip").get<std::string>(),
                                         j.at("port").get<uint16_t>());
        if (lp == 0) {
            res.status = 502;
            res.set_content(R"({"error":"mesh inactive or egress failed"})",
                            "application/json");
            return;
        }
        res.set_content(nlohmann::json{{"loopback_port", lp}}.dump(),
                        "application/json");
    });

    std::thread control_thread([&] {
        if (!control.listen("127.0.0.1", cfg.control_port)) {
            spdlog::error("Control API failed to bind 127.0.0.1:{}", cfg.control_port);
            request_stop();
        }
    });

    // --- Parent-liveness watcher --------------------------------------------
    std::thread parent_watch;
    if (cfg.parent_pid > 0) {
        parent_watch = std::thread([pid = cfg.parent_pid] {
            while (!g_stop.load()) {
                if (!parent_alive(pid)) {
                    spdlog::info("Parent process {} gone — shutting down", pid);
                    request_stop();
                    return;
                }
                if (!interruptible_sleep(2s)) return;
            }
        });
    }

    // --- Join + supervise loop ----------------------------------------------
    auto set_status = [&](const std::string& s) {
        std::lock_guard lock(state.mtx);
        state.status = s;
    };

    bool joined = false;
    auto backoff = 1s;
    constexpr auto max_backoff = 60s;

    while (!g_stop.load()) {
        if (!joined) {
            set_status("joining");
            auto res = client.join_network("lemonade-sidecar", "");
            if (res.ok) {
                joined = true;
                backoff = 1s;
                {
                    std::lock_guard lock(state.mtx);
                    state.node_id   = res.value.node_id;
                    state.tunnel_ip = res.value.tunnel_ip;
                }
                spdlog::info("Joined mesh: node_id={} tunnel_ip={}",
                             res.value.node_id, res.value.tunnel_ip);

                // The link token is single-use and now consumed; drop it so a
                // later re-join doesn't replay it.
                client.set_link_token("");

                if (cfg.leave) {
                    // One-shot cleanup of a device (test devices, a retired node): the SDK
                    // deletes this device's node through its session server, then we exit.
                    // One attempt only. The server deletes the node and drops this device's
                    // mesh peer before its reply goes back over that same tunnel, so a lost
                    // reply ("did not reach the server") usually means it worked; check the
                    // server's device count. Retrying would sign in again and, with the node
                    // gone, create a new device.
                    if (cfg.leave_after_sec > 0) {
                        client.enable_mesh();
                        std::this_thread::sleep_for(std::chrono::seconds(cfg.leave_after_sec));
                        const auto ms = client.mesh_status();
                        spdlog::info("Before leaving: tunnel_up={} server_path='{}' needs_rejoin={} "
                                     "rx={} tx={}", ms.tunnel_up, ms.server_path, ms.needs_rejoin,
                                     ms.total_rx_bytes, ms.total_tx_bytes);
                    }
                    auto left = client.leave_network();
                    if (left.ok) spdlog::info("Left the network: device node {} deleted", res.value.node_id);
                    else spdlog::warn("leave_network: {} (the delete is often applied anyway)", left.error);
                    spdlog::default_logger()->flush();
                    std::_Exit(left.ok ? 0 : 2);
                }
                // Learn every server GET /api/servers lists (with its announced port) so a
                // later outage of the session server leaves others to fail over to.
                client.discover_servers();
                client.enable_mesh();  // background peer discovery + heartbeat

                bool catalog_registered = false;
                for (const auto& e : cfg.exposes) {
                    auto r = client.expose_service(
                        e.vport, "tcp:127.0.0.1:" + std::to_string(e.local_port));
                    if (r.ok) {
                        spdlog::info("Exposed 127.0.0.1:{} at mesh :{}", e.local_port, e.vport);
                        if (catalog_json.is_object() && !catalog_json.empty() && !catalog_registered) {
                            auto c = client.set_service_catalog(e.vport, catalog_json);
                            if (c.ok) {
                                spdlog::info("Registered service catalog on mesh :{}", e.vport);
                                catalog_registered = true;
                            } else {
                                spdlog::warn("Failed to register catalog on :{}: {}", e.vport, c.error);
                            }
                        }
                    } else {
                        spdlog::warn("Failed to expose :{} -> 127.0.0.1:{}: {}",
                                     e.vport, e.local_port, r.error);
                    }
                }
                if (!cfg.link_token_out.empty()) {
                    auto inv = client.create_link_token(3600, "", cfg.link_token_perms);
                    if (inv.ok) {
                        // An invite is honoured only by the server that minted it (seen on the
                        // CESARops work Nexus 2026-10-30 and 2026-11-12): name that server.
                        auto named = inv.value;
                        {
                            auto by = client.session_server();
                            named["issued_by"] = by.empty() ? cfg.host + ":" + std::to_string(cfg.port) : by;
                        }
                        std::ofstream out(cfg.link_token_out, std::ios::trunc);
                        out << named.dump() << "\n";
                        out.close();
                        std::error_code ec;
                        std::filesystem::permissions(cfg.link_token_out,
                            std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
                            std::filesystem::perm_options::replace, ec);
                        spdlog::info("Invite for this group written to {} (expires_at {})",
                                     cfg.link_token_out,
                                     inv.value.contains("expires_at") ? inv.value["expires_at"].dump() : "?");
                    } else {
                        spdlog::warn("create_link_token failed: {}", inv.error);
                    }
                }
                if (cfg.mesh_port != 0 && !mesh_port) {
                    mesh_port = std::make_unique<lnsdk::MeshPort>(lnsdk::make_mesh_port_backend(client));
                    const auto rc = mesh_port->start(cfg.mesh_port, cfg.mesh_local);
                    if (rc == lnsdk::MeshPortStartResult::Ok) {
                        const int sel = mesh_port->set_selection(cfg.mesh_selection, "");
                        spdlog::info("Mesh port on 127.0.0.1:{} (local {}), selection '{}' -> {}",
                                     cfg.mesh_port, cfg.mesh_local, cfg.mesh_selection, sel);
                    } else {
                        spdlog::error("Mesh port on 127.0.0.1:{} failed to start (code {})",
                                      cfg.mesh_port, static_cast<int>(rc));
                        mesh_port.reset();
                    }
                }
                set_status("running");
            } else {
                {
                    std::lock_guard lock(state.mtx);
                    state.join_failures++;
                    state.mesh_up = false;
                }
                set_status("degraded");
                spdlog::warn("Join failed ({}); retrying in {}s",
                             res.error, backoff.count());
                if (!interruptible_sleep(backoff)) break;
                backoff = std::min(backoff * 2, max_backoff);
                continue;
            }
        }

        // Supervise. The dataplane being active is the real liveness signal
        // (mesh_status().is_up reflects the orchestrator's peer-refresh state,
        // which lags and would cause spurious teardowns). The SDK's MeshOrchestrator
        // handles peer refresh, heartbeat and server-pool failover internally; we
        // only re-join if the dataplane itself is gone.
        // TODO: detect a silently-dead server (dataplane stays "active" on a local
        // UDP socket) via a periodic private-API probe over the mesh, then re-join.
        auto status = client.mesh_status();
        bool active = client.is_mesh_active();
        {
            std::lock_guard lock(state.mtx);
            state.mesh_up    = active;
            state.peer_count = status.peer_count;
        }

        if (!active) {
            spdlog::warn("Mesh dataplane down — re-joining");
            set_status("degraded");
            client.disable_mesh();
            joined = false;  // exposures re-apply on the next join
            continue;
        }
        set_status("running");
        if (!interruptible_sleep(10s)) break;
    }

    // --- Shutdown -----------------------------------------------------------
    spdlog::info("Shutting down");
    set_status("stopped");
    if (joined) {
        client.disable_mesh();
    }
    control.stop();
    if (control_thread.joinable()) control_thread.join();
    if (parent_watch.joinable()) parent_watch.join();
    return 0;
}
