#include <LemonadeNexus/Security/Attestation/Providers/OperatorEnrolledProvider.hpp>

#include <LemonadeNexus/Security/Attestation/AttestationTypes.hpp>
#include <LemonadeNexus/Security/EvidenceOperatorEnrolled.hpp>

#include <algorithm>
#include <utility>

namespace nexus::security {

namespace {

std::optional<crypto::Ed25519PublicKey> decode_root(const std::string& b64) {
    if (b64.empty()) return std::nullopt;
    const auto bytes = crypto::from_base64(b64);
    if (bytes.size() != crypto::kEd25519PublicKeySize) return std::nullopt;
    crypto::Ed25519PublicKey key{};
    std::copy(bytes.begin(), bytes.end(), key.begin());
    if (key == crypto::Ed25519PublicKey{}) return std::nullopt;
    return key;
}

}  // namespace

OperatorEnrolledProvider::OperatorEnrolledProvider(LinuxAttestationProfile profile)
    : profile_(std::move(profile)),
      root_key_(decode_root(profile_.operator_root_pubkey_b64)),
      policy_digest_(profile_digest(profile_)) {}

std::optional<AttestationFailure> OperatorEnrolledProvider::readiness() const {
    if (!root_key_) return AttestationFailure::ProfileIncomplete;
    return std::nullopt;
}

PlatformVerification OperatorEnrolledProvider::examine(
    const AttestationChallenge& challenge, const AttestationEvidence& evidence,
    const PlatformVerificationState&) const {
    PlatformVerification result;
    result.claims.profile_id = profile_id();
    result.claims.profile_ruleset = profile_ruleset();
    const auto fail = [&result](AttestationFailure failure) {
        result.failure = failure;
        return result;
    };

    const auto* bundle = std::get_if<OperatorEnrolledEvidence>(&evidence.platform);
    if (!bundle) return fail(AttestationFailure::ProfileIdMismatch);
    if (bundle->empty()) return fail(AttestationFailure::EndorsementRevoked);
    if (!root_key_) return fail(AttestationFailure::ProfileIncomplete);

    const OperatorEnrollment& enrollment = bundle->enrollment;

    // 1. Signed by the pinned root. Another key, even a valid one, is not the
    //    operator; a bad signature is no enrollment at all.
    if (enrollment.operator_key != *root_key_) return fail(AttestationFailure::EndorsementRevoked);
    if (!operator_enrollment_signature_valid(enrollment)) {
        return fail(AttestationFailure::EndorsementRevoked);
    }

    // 2. For this network and this node identity. The verifier already bound
    //    the surrounding evidence to the challenge; this binds the operator's
    //    statement to the same identity and network.
    if (enrollment.network_id != challenge.network_id) {
        return fail(AttestationFailure::NetworkMismatch);
    }
    if (enrollment.node_key != challenge.node_key) return fail(AttestationFailure::IdentityMismatch);

    // 3. Binary pins. The profile list, when present, must contain the
    //    enrolled binary; the self-reported running binary must agree with the
    //    pin. The self-report is a consistency check, not a measurement.
    const auto& approved = profile_.operator_approved_binaries_hex;
    if (!approved.empty() &&
        std::find(approved.begin(), approved.end(), enrollment.binary_sha256) == approved.end()) {
        return fail(AttestationFailure::BinaryMeasurementInvalid);
    }
    if (!enrollment.binary_sha256.empty() && bundle->binary_sha256 != enrollment.binary_sha256) {
        return fail(AttestationFailure::BinaryMeasurementInvalid);
    }

    // The operator vouched. Every platform claim below MEANS exactly that under
    // this profile ID: no hardware measured anything. See the header comment.
    auto& c = result.claims;
    c.hardware_confidentiality_valid = true;  // operator-vouched, not SEV-SNP
    c.platform_identity_valid = true;         // the enrolled node key, not a vTPM
    c.evidence_freshness_valid = true;        // the verifier bound this answer to a live challenge
    c.tcb_valid = true;                       // operator-vouched
    c.boot_integrity_valid = true;            // operator-vouched, not measured boot
    c.ima_anchored = true;                    // operator-vouched, no IMA
    c.binary_approved = true;                 // pins agreed above, or the operator chose not to pin
    c.runtime_profile_enforced = true;        // operator-vouched
    c.runtime_integrity_valid = c.ima_anchored && c.binary_approved && c.runtime_profile_enforced;
    return result;
}

}  // namespace nexus::security
