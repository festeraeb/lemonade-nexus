#include <LemonadeNexus/Security/EvidenceOperatorEnrolled.hpp>

#include <LemonadeNexus/Security/CanonicalEncoding.hpp>

#include "AttestationDetail.hpp"

#include <nlohmann/json.hpp>
#include <sodium.h>

#include <algorithm>
#include <array>
#include <filesystem>
#include <fstream>
#include <vector>

namespace nexus::security {

using json = nlohmann::json;
using detail::b64;
using detail::exact_keys;
using detail::unb64;
using detail::valid_hex;

Digest operator_enrollment_digest(const OperatorEnrollment& enrollment) {
    CanonicalEncoder encoder(kOperatorEnrollmentDomain);
    encoder.add_u32(enrollment.version);
    encoder.add_bytes(enrollment.network_id);
    encoder.add_bytes(enrollment.node_key);
    encoder.add_string(enrollment.binary_sha256);
    encoder.add_u64(enrollment.issued_at_unix);
    encoder.add_bytes(enrollment.operator_key);
    return encoder.digest();
}

OperatorEnrollment sign_operator_enrollment(OperatorEnrollment enrollment,
                                            const crypto::Ed25519Keypair& operator_keypair) {
    enrollment.operator_key = operator_keypair.public_key;
    const Digest digest = operator_enrollment_digest(enrollment);
    crypto_sign_detached(enrollment.operator_signature.data(), nullptr, digest.data(),
                         digest.size(), operator_keypair.private_key.data());
    return enrollment;
}

bool operator_enrollment_signature_valid(const OperatorEnrollment& enrollment) {
    if (enrollment.version != kOperatorEnrollmentVersion) return false;
    if (enrollment.operator_key == crypto::Ed25519PublicKey{}) return false;
    const Digest digest = operator_enrollment_digest(enrollment);
    return crypto_sign_verify_detached(enrollment.operator_signature.data(), digest.data(),
                                       digest.size(), enrollment.operator_key.data()) == 0;
}

namespace {

template <std::size_t N>
bool fill_array(const std::vector<uint8_t>& bytes, std::array<uint8_t, N>& out) {
    if (bytes.size() != N) return false;
    std::copy(bytes.begin(), bytes.end(), out.begin());
    return true;
}

json enrollment_json(const OperatorEnrollment& e) {
    json j;
    j["version"] = e.version;
    j["network_id"] = b64(e.network_id);
    j["node_key"] = b64(e.node_key);
    j["binary_sha256"] = e.binary_sha256;
    j["issued_at_unix"] = e.issued_at_unix;
    j["operator_key"] = b64(e.operator_key);
    j["operator_signature"] = b64(e.operator_signature);
    return j;
}

std::optional<OperatorEnrollment> enrollment_from_json(const json& j) {
    if (!exact_keys(j, {"version", "network_id", "node_key", "binary_sha256",
                        "issued_at_unix", "operator_key", "operator_signature"})) {
        return std::nullopt;
    }
    try {
        OperatorEnrollment e;
        e.version = j.at("version").get<uint32_t>();
        if (!fill_array(unb64(j.at("network_id")), e.network_id)) return std::nullopt;
        if (!fill_array(unb64(j.at("node_key")), e.node_key)) return std::nullopt;
        e.binary_sha256 = j.at("binary_sha256").get<std::string>();
        if (!e.binary_sha256.empty() && !valid_hex(e.binary_sha256, 64)) return std::nullopt;
        e.issued_at_unix = j.at("issued_at_unix").get<uint64_t>();
        if (!fill_array(unb64(j.at("operator_key")), e.operator_key)) return std::nullopt;
        if (!fill_array(unb64(j.at("operator_signature")), e.operator_signature)) {
            return std::nullopt;
        }
        return e;
    } catch (const json::exception&) {
        return std::nullopt;
    }
}

}  // namespace

std::string encode_operator_enrollment(const OperatorEnrollment& enrollment) {
    return enrollment_json(enrollment).dump();
}

std::optional<OperatorEnrollment> decode_operator_enrollment(std::string_view text) {
    const json j = json::parse(text, nullptr, false);
    if (j.is_discarded() || !j.is_object()) return std::nullopt;
    return enrollment_from_json(j);
}

std::string encode_operator_enrolled_evidence(const OperatorEnrolledEvidence& ev) {
    json j;
    j["profile"] = "operator-enrolled";
    j["enrollment"] = enrollment_json(ev.enrollment);
    j["binary_sha256"] = ev.binary_sha256;
    j["host_note"] = ev.host_note;
    return j.dump();
}

std::optional<OperatorEnrolledEvidence> decode_operator_enrolled_evidence(
    std::string_view text) {
    const json j = json::parse(text, nullptr, false);
    if (j.is_discarded() || !j.is_object() ||
        !exact_keys(j, {"profile", "enrollment", "binary_sha256", "host_note"}) ||
        j.value("profile", "") != "operator-enrolled" || !j.at("enrollment").is_object()) {
        return std::nullopt;
    }
    try {
        OperatorEnrolledEvidence ev;
        auto enrollment = enrollment_from_json(j.at("enrollment"));
        if (!enrollment) return std::nullopt;
        ev.enrollment = std::move(*enrollment);
        ev.binary_sha256 = j.at("binary_sha256").get<std::string>();
        if (!ev.binary_sha256.empty() && !valid_hex(ev.binary_sha256, 64)) return std::nullopt;
        ev.host_note = j.at("host_note").get<std::string>();
        if (ev.host_note.size() > 256) return std::nullopt;
        return ev;
    } catch (const json::exception&) {
        return std::nullopt;
    }
}

std::string self_binary_sha256_hex() {
#if defined(__linux__)
    std::error_code ec;
    const auto exe = std::filesystem::read_symlink("/proc/self/exe", ec);
    if (ec) return {};
    std::ifstream in(exe, std::ios::binary);
    if (!in) return {};
    crypto_hash_sha256_state state;
    crypto_hash_sha256_init(&state);
    std::array<char, 1 << 16> buffer{};
    while (in.read(buffer.data(), static_cast<std::streamsize>(buffer.size())) ||
           in.gcount() > 0) {
        crypto_hash_sha256_update(&state,
                                  reinterpret_cast<const unsigned char*>(buffer.data()),
                                  static_cast<unsigned long long>(in.gcount()));
    }
    std::array<uint8_t, crypto_hash_sha256_BYTES> out{};
    crypto_hash_sha256_final(&state, out.data());
    return crypto::to_hex(out);
#else
    return {};
#endif
}

}  // namespace nexus::security
