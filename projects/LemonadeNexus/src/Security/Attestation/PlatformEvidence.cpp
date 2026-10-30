#include <LemonadeNexus/Security/Attestation/PlatformEvidence.hpp>

#include <nlohmann/json.hpp>

#include <type_traits>

namespace nexus::security {

using json = nlohmann::json;

PlatformEvidenceType platform_evidence_type(const PlatformEvidence& evidence) {
    if (std::holds_alternative<SnpVtpmEvidence>(evidence)) return PlatformEvidenceType::AzureSnpVtpm;
    if (std::holds_alternative<OperatorEnrolledEvidence>(evidence)) {
        return PlatformEvidenceType::OperatorEnrolled;
    }
    return PlatformEvidenceType::SnpSvsmVtpm;
}

std::string_view platform_evidence_type_name(PlatformEvidenceType type) {
    switch (type) {
        case PlatformEvidenceType::AzureSnpVtpm: return "azure-snp-vtpm";
        case PlatformEvidenceType::SnpSvsmVtpm: return "snp-svsm-vtpm";
        case PlatformEvidenceType::OperatorEnrolled: return "operator-enrolled";
    }
    return "unknown";
}

std::string encode_platform_evidence(const PlatformEvidence& evidence) {
    json envelope;
    envelope["version"] = kPlatformEvidenceWireVersion;
    const auto type = platform_evidence_type(evidence);
    envelope["type"] = platform_evidence_type_name(type);
    envelope["payload"] = std::visit(
        [](const auto& value) -> std::string {
            using T = std::decay_t<decltype(value)>;
            if constexpr (std::is_same_v<T, SnpVtpmEvidence>) {
                return encode_snp_vtpm_evidence(value);
            } else if constexpr (std::is_same_v<T, SnpSvsmVtpmEvidence>) {
                return encode_snp_svsm_vtpm_evidence(value);
            } else {
                return encode_operator_enrolled_evidence(value);
            }
        },
        evidence);
    return envelope.dump();
}

std::optional<PlatformEvidence> decode_platform_evidence(std::string_view text) {
    if (text.empty()) return std::nullopt;
    const json envelope = json::parse(text, nullptr, false);
    if (envelope.is_discarded() || !envelope.is_object() || envelope.size() != 3 ||
        !envelope.contains("version") || !envelope["version"].is_number_unsigned() ||
        envelope["version"].get<uint32_t>() != kPlatformEvidenceWireVersion ||
        !envelope.contains("type") || !envelope["type"].is_string() ||
        !envelope.contains("payload") || !envelope["payload"].is_string()) {
        return std::nullopt;
    }
    const std::string type = envelope["type"].get<std::string>();
    const std::string payload = envelope["payload"].get<std::string>();
    if (type == platform_evidence_type_name(PlatformEvidenceType::AzureSnpVtpm)) {
        auto decoded = decode_snp_vtpm_evidence(payload);
        if (!decoded) return std::nullopt;
        return PlatformEvidence{std::move(*decoded)};
    }
    if (type == platform_evidence_type_name(PlatformEvidenceType::SnpSvsmVtpm)) {
        auto decoded = decode_snp_svsm_vtpm_evidence(payload);
        if (!decoded) return std::nullopt;
        return PlatformEvidence{std::move(*decoded)};
    }
    if (type == platform_evidence_type_name(PlatformEvidenceType::OperatorEnrolled)) {
        auto decoded = decode_operator_enrolled_evidence(payload);
        if (!decoded) return std::nullopt;
        return PlatformEvidence{std::move(*decoded)};
    }
    return std::nullopt;
}

std::size_t platform_evidence_size(const PlatformEvidence& evidence) {
    return encode_platform_evidence(evidence).size();
}

}  // namespace nexus::security
