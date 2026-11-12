// Transport lab: a server and a client of the mesh for real-path tests in
// network namespaces (tests/lab/run_lab.sh). Not a unit test.
//
//   transport_lab server --dir D [--udp-port 51940] [--wss-port 443] [--bind 0.0.0.0]
//   transport_lab client --dir D --server-ip IP [--udp-port 51940] [--wss-port 443]
//                        [--stream-sec N] [--upload-mib N] [--soak-sec N]
//
// The server writes D/server.pub and D/cert.pem (a certificate for the
// server IP), waits for D/client.pub, and serves on its tunnel address
// 10.64.0.1:80: GET /ping, GET /stream?n=&gap_ms=, POST /upload. Its UDP
// mesh port takes the dataplane; the TLS listener on --wss-port carries the
// transport bridge (dataplane + relay routes) and GET /api/health.
//
// The client writes D/client.pub, starts BoringtunMesh with the WSS route
// and the server's UDP endpoint, and prints one JSON object per measurement
// (event lines while it runs). Exit status 0 when every measurement it ran
// completed.

#include <LemonadeNexus/Boringtun/UserspaceDataplane.hpp>
#include <LemonadeNexus/Network/TransportBridge.hpp>
#include <LemonadeNexus/Network/VirtualNetService.hpp>
#include <LemonadeNexusSDK/BoringtunMesh.hpp>
#include <LemonadeNexusSDK/LemonadeNexusClient.hpp>
#include <LemonadeNexusSDK/WssTunnel.hpp>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <httplib.h>
#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <sodium.h>
#include <spdlog/spdlog.h>

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <map>
#include <string>
#include <thread>
#include <vector>

using namespace std::chrono_literals;
using Clock = std::chrono::steady_clock;
namespace fs = std::filesystem;

namespace {

std::atomic<bool> g_stop{false};

std::map<std::string, std::string> parse_args(int argc, char** argv, int from) {
    std::map<std::string, std::string> out;
    for (int i = from; i + 1 < argc; i += 2) out[argv[i]] = argv[i + 1];
    return out;
}

std::string arg(const std::map<std::string, std::string>& a, const std::string& k, const std::string& d = {}) {
    auto it = a.find(k);
    return it == a.end() ? d : it->second;
}

int64_t ms_since(Clock::time_point t) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - t).count();
}

std::string read_file(const fs::path& p) {
    std::ifstream in(p);
    std::string s((std::istreambuf_iterator<char>(in)), {});
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) s.pop_back();
    return s;
}

void write_file(const fs::path& p, const std::string& s) {
    const auto tmp = p.string() + ".tmp";
    std::ofstream(tmp) << s << "\n";
    fs::rename(tmp, p);
}

std::string wait_file(const fs::path& p) {
    while (!g_stop && !fs::exists(p)) std::this_thread::sleep_for(50ms);
    return read_file(p);
}

/// A self-signed certificate for the server's IP address (SAN IP and DNS).
bool make_ip_cert(const std::string& ip, const fs::path& cert_p, const fs::path& key_p) {
    EVP_PKEY* key = EVP_RSA_gen(2048);
    if (!key) return false;
    X509* x = X509_new();
    ASN1_INTEGER_set(X509_get_serialNumber(x), 7);
    X509_gmtime_adj(X509_getm_notBefore(x), -60);
    X509_gmtime_adj(X509_getm_notAfter(x), 7 * 24 * 3600);
    X509_set_pubkey(x, key);
    X509_NAME* name = X509_get_subject_name(x);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>("nexus-lab"), -1, -1, 0);
    X509_set_issuer_name(x, name);
    const std::string san = "IP:" + ip + ",DNS:nexus-lab";
    for (const auto& [nid, spec] : std::vector<std::pair<int, std::string>>{
             {NID_basic_constraints, "critical,CA:TRUE"}, {NID_subject_alt_name, san}}) {
        if (X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, nullptr, nid, spec.c_str())) {
            X509_add_ext(x, ext, -1);
            X509_EXTENSION_free(ext);
        }
    }
    bool ok = X509_sign(x, key, EVP_sha256()) != 0;
    if (FILE* f = std::fopen(cert_p.c_str(), "wb")) {
        ok = ok && PEM_write_X509(f, x);
        std::fclose(f);
    }
    if (FILE* f = std::fopen(key_p.c_str(), "wb")) {
        ok = ok && PEM_write_PrivateKey(f, key, nullptr, nullptr, 0, nullptr, nullptr);
        std::fclose(f);
    }
    X509_free(x);
    EVP_PKEY_free(key);
    return ok;
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

int run_server(const std::map<std::string, std::string>& a) {
    const fs::path dir = arg(a, "--dir");
    const auto udp_port = static_cast<uint16_t>(std::stoi(arg(a, "--udp-port", "51940")));
    const int wss_port = std::stoi(arg(a, "--wss-port", "443"));
    const std::string server_ip = arg(a, "--server-ip", "10.99.0.2");
    fs::create_directories(dir);
    // The server keeps its identity across restarts, like a real server.
    std::pair<std::string, std::string> keys;  // {private, public}
    if (fs::exists(dir / "server.key")) {
        keys.first = read_file(dir / "server.key");
        keys.second = read_file(dir / "server.pub");
    } else {
        keys = lnsdk::BoringtunMesh::generate_keypair();
        write_file(dir / "server.key", keys.first);
    }
    if (!fs::exists(dir / "cert.pem") && !make_ip_cert(server_ip, dir / "cert.pem", dir / "key.pem")) {
        std::fprintf(stderr, "certificate generation failed\n");
        return 2;
    }

    httplib::Server api;
    api.Get("/ping", [](const httplib::Request&, httplib::Response& res) { res.set_content("pong", "text/plain"); });
    api.Get("/stream", [](const httplib::Request& req, httplib::Response& res) {
        const int n = req.has_param("n") ? std::stoi(req.get_param_value("n")) : 100;
        const int gap = req.has_param("gap_ms") ? std::stoi(req.get_param_value("gap_ms")) : 20;
        res.set_chunked_content_provider(
            "text/event-stream", [n, gap, i = 0](size_t, httplib::DataSink& sink) mutable {
                if (i >= n) {
                    sink.done();
                    return true;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(gap));
                const std::string line = "data: " + std::to_string(i++) + "\n\n";
                return sink.write(line.data(), line.size());
            });
    });
    api.Post("/upload", [](const httplib::Request& req, httplib::Response& res) {
        res.set_content(std::to_string(req.body.size()), "text/plain");
    });
    const int api_port = api.bind_to_any_port("127.0.0.1");
    std::thread api_thread([&] { api.listen_after_bind(); });

    nexus::boringtun::UserspaceDataplane dp;
    nexus::network::VirtualNetService vnet;
    vnet.start();
    dp.set_inbound_handler([&](std::span<const uint8_t> p) { vnet.deliver_inbound_ip_packet(p); });
    vnet.set_outbound_sink([&](std::span<const uint8_t> p) { dp.send_outbound_ip_packet(p); });
    if (!dp.start({keys.first, keys.second, udp_port, 2})) {
        std::fprintf(stderr, "dataplane bind failed on %u\n", udp_port);
        return 2;
    }
    dp.add_local_ip(0x0A400001u);
    vnet.add_local_ip("10.64.0.1/10");
    (void)vnet.add_tcp_forward("10.64.0.1", 80, "tcp:127.0.0.1:" + std::to_string(api_port));

    nexus::network::TransportBridge::Limits limits;
    if (a.count("--bridge-max")) limits.max_connections = std::stoul(arg(a, "--bridge-max"));
    if (a.count("--bridge-per-ip")) limits.max_per_ip = std::stoul(arg(a, "--bridge-per-ip"));
    if (a.count("--bridge-idle")) limits.idle_timeout = std::chrono::seconds(std::stoi(arg(a, "--bridge-idle")));
    nexus::network::TransportBridge bridge(limits);
    bridge.add_target("dataplane", dp.bound_port());
    httplib::SSLServer tls((dir / "cert.pem").c_str(), (dir / "key.pem").c_str());
    tls.Get("/api/health", [&](const httplib::Request&, httplib::Response& res) {
        const auto c = bridge.counters();
        res.set_content(nlohmann::json{{"active", bridge.active_connections()},
                                       {"accepted", c.connections_accepted},
                                       {"refused", c.connections_refused},
                                       {"refused_per_ip", c.refused_per_ip},
                                       {"closed_idle", c.closed_idle},
                                       {"closed_oversize", c.closed_oversize},
                                       {"up", c.datagrams_up},
                                       {"down", c.datagrams_down}}
                            .dump(),
                        "application/json");
    });
    bridge.register_routes(tls);
    if (!tls.bind_to_port(arg(a, "--bind", "0.0.0.0"), wss_port)) {
        std::fprintf(stderr, "TLS listener bind failed on %d\n", wss_port);
        return 2;
    }
    std::thread tls_thread([&] { tls.listen_after_bind(); });

    write_file(dir / "server.pub", keys.second);
    std::printf("{\"event\":\"server_ready\",\"udp\":%u,\"wss\":%d}\n", dp.bound_port(), wss_port);
    std::fflush(stdout);

    std::string client_pub;
    while (!g_stop) {
        // A client that restarts writes a new key; follow it.
        if (fs::exists(dir / "client.pub")) {
            const auto now = read_file(dir / "client.pub");
            if (!now.empty() && now != client_pub) {
                if (!client_pub.empty()) (void)dp.remove_peer(client_pub);
                client_pub = now;
                (void)dp.add_peer(client_pub, "10.64.0.2/32", "", 0);
                std::printf("{\"event\":\"client_peer\",\"key\":\"%.8s\"}\n", client_pub.c_str());
                std::fflush(stdout);
            }
        }
        std::this_thread::sleep_for(100ms);
    }
    bridge.stop();
    tls.stop();
    tls_thread.join();
    dp.stop();
    vnet.stop();
    api.stop();
    api_thread.join();
    return 0;
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

struct StreamResult {
    bool ok{false};
    int chunks{0};
    int out_of_order{0};
    int64_t max_gap_ms{0};
    int64_t total_ms{0};
};

StreamResult read_stream(uint16_t egress, int n, int gap_ms) {
    StreamResult r;
    httplib::Client c("127.0.0.1", egress);
    c.set_connection_timeout(10, 0);
    c.set_read_timeout(60, 0);
    std::string pending;
    auto last = Clock::now();
    const auto t0 = Clock::now();
    int expect = 0;
    auto res = c.Get("/stream?n=" + std::to_string(n) + "&gap_ms=" + std::to_string(gap_ms),
                     [&](const char* data, size_t len) {
                         r.max_gap_ms = std::max<int64_t>(r.max_gap_ms, ms_since(last));
                         last = Clock::now();
                         pending.append(data, len);
                         size_t pos;
                         while ((pos = pending.find("\n\n")) != std::string::npos) {
                             const auto line = pending.substr(0, pos);
                             pending.erase(0, pos + 2);
                             if (line.rfind("data: ", 0) != 0) continue;
                             const int seq = std::stoi(line.substr(6));
                             if (seq != expect) ++r.out_of_order;
                             expect = seq + 1;
                             ++r.chunks;
                         }
                         return true;
                     });
    r.total_ms = ms_since(t0);
    r.ok = res && res->status == 200 && r.chunks == n && r.out_of_order == 0;
    return r;
}

int run_client(const std::map<std::string, std::string>& a) {
    const fs::path dir = arg(a, "--dir");
    const std::string server_ip = arg(a, "--server-ip", "10.99.0.2");
    const std::string udp_port = arg(a, "--udp-port", "51940");
    const std::string wss_port = arg(a, "--wss-port", "443");
    const int stream_sec = std::stoi(arg(a, "--stream-sec", "10"));
    const int upload_mib = std::stoi(arg(a, "--upload-mib", "8"));
    const int soak_sec = std::stoi(arg(a, "--soak-sec", "0"));

    const auto keys = lnsdk::BoringtunMesh::generate_keypair();
    write_file(dir / "client.pub", keys.second);
    const auto server_pub = wait_file(dir / "server.pub");
    lnsdk::set_ca_bundle_path((dir / "cert.pem").string());

    lnsdk::BoringtunMesh mesh;
    lnsdk::BoringtunConfig cfg;
    cfg.private_key = keys.first;
    cfg.public_key = keys.second;
    cfg.tunnel_ip = "10.64.0.2/32";
    cfg.server_public_key = server_pub;
    cfg.server_endpoint = server_ip + ":" + udp_port;
    cfg.server_tunnel_ip = "10.64.0.1";
    cfg.allowed_ips = {"10.64.0.0/10"};
    cfg.keepalive = 25;
    cfg.wss_urls = {"wss://" + server_ip + ":" + wss_port + "/api/transport/ws/dataplane"};
    if (a.count("--link-mtu")) cfg.link_mtu = static_cast<uint32_t>(std::stoul(arg(a, "--link-mtu")));

    // Wait for the server to add this key before the race starts.
    std::this_thread::sleep_for(300ms);
    const auto t0 = Clock::now();
    if (!mesh.start(cfg)) {
        std::printf("{\"event\":\"error\",\"what\":\"mesh start\"}\n");
        return 2;
    }
    nlohmann::json out{{"event", "client_up"}, {"mtu", mesh.mtu()}};
    std::printf("%s\n", out.dump().c_str());
    std::fflush(stdout);

    // Path watcher: one event line per change.
    std::atomic<bool> watching{true};
    std::vector<std::pair<int64_t, std::string>> path_log;
    std::mutex log_mtx;
    std::thread watcher([&] {
        std::string last;
        while (watching) {
            const auto p = mesh.server_path();
            if (p != last) {
                const auto s = mesh.server_session();
                std::lock_guard lock(log_mtx);
                path_log.emplace_back(ms_since(t0), p);
                std::printf("{\"event\":\"path\",\"t_ms\":%lld,\"path\":\"%s\",\"handshakes\":%llu}\n",
                            static_cast<long long>(ms_since(t0)), p.c_str(),
                            static_cast<unsigned long long>(s ? s->handshakes : 0));
                std::fflush(stdout);
                last = p;
            }
            std::this_thread::sleep_for(10ms);
        }
    });

    bool all_ok = true;
    // 1. Establishment: first /ping answered.
    while (mesh.server_path() == "none" || mesh.server_path().empty()) {
        if (ms_since(t0) > 30000) break;
        std::this_thread::sleep_for(5ms);
    }
    const auto established_path = mesh.server_path();
    const int64_t established_ms = ms_since(t0);
    const uint16_t egress = mesh.tcp_egress("10.64.0.1", 80);
    int64_t first_ping_ms = -1;
    {
        httplib::Client c("127.0.0.1", egress);
        c.set_connection_timeout(5, 0);
        c.set_read_timeout(5, 0);
        while (ms_since(t0) < 30000) {
            if (auto r = c.Get("/ping"); r && r->status == 200) {
                first_ping_ms = ms_since(t0);
                break;
            }
            std::this_thread::sleep_for(50ms);
        }
    }
    // RTT over the tunnel: median of 20 pings on a kept-alive connection.
    std::vector<int64_t> rtts;
    {
        httplib::Client c("127.0.0.1", egress);
        c.set_keep_alive(true);
        c.set_read_timeout(5, 0);
        for (int i = 0; i < 21; ++i) {
            const auto s = Clock::now();
            if (auto r = c.Get("/ping"); r && r->status == 200 && i > 0) {
                rtts.push_back(std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - s).count());
            }
        }
    }
    std::sort(rtts.begin(), rtts.end());
    nlohmann::json est{{"event", "established"},
                       {"path", established_path},
                       {"established_ms", established_ms},
                       {"first_ping_ms", first_ping_ms},
                       {"ping_median_us", rtts.empty() ? -1 : rtts[rtts.size() / 2]}};
    std::printf("%s\n", est.dump().c_str());
    std::fflush(stdout);
    if (first_ping_ms < 0) all_ok = false;

    // 2. Upload throughput.
    if (upload_mib > 0 && first_ping_ms >= 0) {
        httplib::Client c("127.0.0.1", egress);
        c.set_read_timeout(120, 0);
        c.set_write_timeout(120, 0);
        const std::string body(static_cast<size_t>(upload_mib) << 20, 'u');
        const auto s = Clock::now();
        auto r = c.Post("/upload", body, "application/octet-stream");
        const double secs = std::chrono::duration<double>(Clock::now() - s).count();
        const bool ok = r && r->status == 200 && r->body == std::to_string(body.size());
        nlohmann::json up{{"event", "upload"}, {"ok", ok}, {"mib", upload_mib}, {"seconds", secs},
                          {"mbit_s", ok ? body.size() * 8.0 / secs / 1e6 : 0.0}, {"path", mesh.server_path()}};
        std::printf("%s\n", up.dump().c_str());
        std::fflush(stdout);
        if (!ok) all_ok = false;
    }

    // 3. A stream (the orchestrator may cut paths while it runs).
    if (stream_sec > 0 && first_ping_ms >= 0) {
        const auto before = mesh.server_session();
        const int n = stream_sec * 50;
        const auto r = read_stream(egress, n, 20);
        const auto after = mesh.server_session();
        nlohmann::json st{{"event", "stream"}, {"ok", r.ok}, {"chunks", r.chunks}, {"expected", n},
                          {"out_of_order", r.out_of_order}, {"max_gap_ms", r.max_gap_ms},
                          {"total_ms", r.total_ms},
                          {"handshakes_before", before ? before->handshakes : 0},
                          {"handshakes_after", after ? after->handshakes : 0},
                          {"tunnel_index_same", before && after && before->tunnel_index == after->tunnel_index}};
        std::printf("%s\n", st.dump().c_str());
        std::fflush(stdout);
        if (!r.ok) all_ok = false;
    }

    // 3b. Ping watch: a /ping every 100 ms; reports each outage.
    if (const int watch = std::stoi(arg(a, "--ping-watch-sec", "0")); watch > 0 && first_ping_ms >= 0) {
        const auto start = Clock::now();
        int64_t down_since = -1, longest = 0;
        int outages = 0;
        while (ms_since(start) < watch * 1000LL && !g_stop) {
            httplib::Client c("127.0.0.1", egress);
            c.set_connection_timeout(1, 0);
            c.set_read_timeout(1, 0);
            const bool ok = [&] { auto r = c.Get("/ping"); return r && r->status == 200; }();
            const int64_t now = ms_since(t0);
            if (!ok && down_since < 0) down_since = now;
            if (ok && down_since >= 0) {
                ++outages;
                longest = std::max(longest, now - down_since);
                std::printf("{\"event\":\"outage\",\"from_ms\":%lld,\"to_ms\":%lld,\"ms\":%lld,\"path\":\"%s\"}\n",
                            static_cast<long long>(down_since), static_cast<long long>(now),
                            static_cast<long long>(now - down_since), mesh.server_path().c_str());
                std::fflush(stdout);
                down_since = -1;
            }
            std::this_thread::sleep_for(100ms);
        }
        const auto sess = mesh.server_session();
        nlohmann::json w{{"event", "ping_watch"}, {"outages", outages}, {"longest_ms", longest},
                         {"still_down", down_since >= 0}, {"handshakes", sess ? sess->handshakes : 0}};
        std::printf("%s\n", w.dump().c_str());
        std::fflush(stdout);
        if (down_since >= 0) all_ok = false;
    }

    // 4. Soak: back-to-back streams for soak_sec; counts resets and gaps.
    if (soak_sec > 0 && first_ping_ms >= 0) {
        const auto start = Clock::now();
        const auto first = mesh.server_session();
        int streams = 0, failed = 0;
        int64_t worst_gap = 0;
        while (ms_since(start) < soak_sec * 1000LL && !g_stop) {
            const auto r = read_stream(egress, 1500, 20);  // 30 s each
            ++streams;
            if (!r.ok) ++failed;
            worst_gap = std::max(worst_gap, r.max_gap_ms);
            nlohmann::json one{{"event", "soak_stream"}, {"n", streams}, {"ok", r.ok}, {"chunks", r.chunks},
                               {"max_gap_ms", r.max_gap_ms}, {"t_s", ms_since(start) / 1000}};
            std::printf("%s\n", one.dump().c_str());
            std::fflush(stdout);
        }
        const auto last = mesh.server_session();
        nlohmann::json soak{{"event", "soak"}, {"streams", streams}, {"failed", failed}, {"worst_gap_ms", worst_gap},
                            {"seconds", ms_since(start) / 1000},
                            {"handshakes", (last ? last->handshakes : 0) - (first ? first->handshakes : 0)},
                            {"tunnel_index_same", first && last && first->tunnel_index == last->tunnel_index}};
        std::printf("%s\n", soak.dump().c_str());
        std::fflush(stdout);
        if (failed > 0) all_ok = false;
    }

    watching = false;
    watcher.join();
    {
        std::lock_guard lock(log_mtx);
        nlohmann::json pl = nlohmann::json::array();
        for (const auto& [t, p] : path_log) pl.push_back({t, p});
        std::printf("%s\n", nlohmann::json{{"event", "done"}, {"ok", all_ok}, {"paths", pl}}.dump().c_str());
    }
    mesh.stop();
    return all_ok ? 0 : 1;
}


// ---------------------------------------------------------------------------
// Storm and abuse against the bridge
// ---------------------------------------------------------------------------

int run_storm(const std::map<std::string, std::string>& a) {
    const std::string url = arg(a, "--url");
    const int clients = std::stoi(arg(a, "--clients", "200"));
    const int rounds = std::stoi(arg(a, "--rounds", "3"));
    lnsdk::set_ca_bundle_path(arg(a, "--ca"));
    for (int round = 0; round < rounds; ++round) {
        std::vector<std::unique_ptr<lnsdk::WssTunnel>> tunnels;
        const auto t0 = Clock::now();
        for (int i = 0; i < clients; ++i) {
            auto t = std::make_unique<lnsdk::WssTunnel>();
            lnsdk::WssTunnel::Options o;
            o.url = url;
            o.connect_timeout = 10000ms;
            (void)t->open(o);
            tunnels.push_back(std::move(t));
        }
        int open = 0, failed = 0;
        while (ms_since(t0) < 20000) {
            open = failed = 0;
            for (auto& t : tunnels) {
                if (t->state() == lnsdk::WssTunnel::State::Open) ++open;
                if (t->state() == lnsdk::WssTunnel::State::Failed) ++failed;
            }
            if (open + failed == clients) break;
            std::this_thread::sleep_for(50ms);
        }
        std::this_thread::sleep_for(500ms);
        for (auto& t : tunnels) t->close();
        std::printf("{\"event\":\"storm_round\",\"round\":%d,\"open\":%d,\"failed\":%d,\"ms\":%lld}\n", round,
                    open, failed, static_cast<long long>(ms_since(t0)));
        std::fflush(stdout);
    }
    return 0;
}

int raw_tcp(const std::string& ip, int port) {
    int s = ::socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in to{};
    to.sin_family = AF_INET;
    to.sin_port = htons(static_cast<uint16_t>(port));
    inet_pton(AF_INET, ip.c_str(), &to.sin_addr);
    if (::connect(s, reinterpret_cast<sockaddr*>(&to), sizeof to) != 0) {
        ::close(s);
        return -1;
    }
    return s;
}

int run_abuse(const std::map<std::string, std::string>& a) {
    const std::string ip = arg(a, "--host");
    const int port = std::stoi(arg(a, "--port", "443"));
    const std::string url = arg(a, "--url");
    const int silent = std::stoi(arg(a, "--silent", "20"));
    const int garbage = std::stoi(arg(a, "--garbage", "50"));
    const int hold = std::stoi(arg(a, "--hold-sec", "10"));
    lnsdk::set_ca_bundle_path(arg(a, "--ca"));
    // Garbage instead of a TLS handshake.
    int refused = 0;
    for (int i = 0; i < garbage; ++i) {
        const int s = raw_tcp(ip, port);
        if (s < 0) {
            ++refused;
            continue;
        }
        std::string junk(4096, '\0');
        for (size_t j = 0; j < junk.size(); ++j) junk[j] = static_cast<char>((j * 7919 + i) & 0xFF);
        (void)::send(s, junk.data(), junk.size(), MSG_NOSIGNAL);
        ::close(s);
    }
    // Upgraded WebSockets that never send a datagram.
    std::vector<std::unique_ptr<httplib::ws::WebSocketClient>> quiet;
    int upgraded = 0;
    for (int i = 0; i < silent; ++i) {
        auto ws = std::make_unique<httplib::ws::WebSocketClient>(url);
        ws->set_ca_cert_path(arg(a, "--ca"));
        ws->set_websocket_ping_interval(0);
        if (ws->connect()) ++upgraded;
        quiet.push_back(std::move(ws));
    }
    std::this_thread::sleep_for(std::chrono::seconds(hold));
    int closed_by_server = 0;
    for (auto& ws : quiet) {
        std::string msg;
        ws->set_read_timeout(1s);
        if (ws->read(msg) == httplib::ws::ReadResult::Fail) ++closed_by_server;
    }
    std::printf("{\"event\":\"abuse\",\"garbage\":%d,\"garbage_refused\":%d,\"silent\":%d,\"upgraded\":%d,"
                "\"closed_by_server\":%d}\n",
                garbage, refused, silent, upgraded, closed_by_server);
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    if (sodium_init() < 0 || argc < 2) {
        std::fprintf(stderr, "usage: transport_lab server|client --dir D ...\n");
        return 2;
    }
    std::signal(SIGTERM, [](int) { g_stop = true; });
    std::signal(SIGINT, [](int) { g_stop = true; });
    std::signal(SIGPIPE, SIG_IGN);
    spdlog::set_level(spdlog::level::warn);
    if (const char* v = std::getenv("LAB_LOG"); v && std::string(v) == "info") spdlog::set_level(spdlog::level::info);
    const auto args = parse_args(argc, argv, 2);
    const std::string mode = argv[1];
    if (mode == "server") return run_server(args);
    if (mode == "client") return run_client(args);
    if (mode == "storm") return run_storm(args);
    if (mode == "abuse") return run_abuse(args);
    std::fprintf(stderr, "unknown mode %s\n", mode.c_str());
    return 2;
}
