#pragma once

// OPERATOR TRUST, NOT HARDWARE TRUST.
//
// Verifies OperatorEnrolledEvidence: the operator root key pinned in the
// profile (operator_root_pubkey_b64) signed an enrollment for exactly this
// network and this node identity key, and the binary pins agree. Nothing here
// touches a TPM, an SNP report or an IMA log, because the hosts this profile
// serves have none.
//
// Tier1EligibilityPolicy is a strict conjunction over claims whose names come
// from the confidential-computing profiles. This provider sets them because
// the policy requires them, and the profile ID that travels with every claim
// set says what they mean here: "the operator vouched for this host". The
// policy itself is not relaxed, no claim is left half-set, and a default build
// (LEMONADE_NEXUS_OPERATOR_TRUST=OFF) never compiles this provider into the
// verifier's set, so it can never answer a challenge there.
//
// The honest security statement for a mesh built this way: Tier 1 is exactly
// as trustworthy as the operator's root key and the hosts the operator chose.

#include <LemonadeNexus/Security/Attestation/LinuxAttestationProfile.hpp>
#include <LemonadeNexus/Security/Attestation/PlatformEvidenceProvider.hpp>

#include <optional>

namespace nexus::security {

class OperatorEnrolledProvider final : public PlatformEvidenceProvider {
public:
    explicit OperatorEnrolledProvider(LinuxAttestationProfile profile);

    [[nodiscard]] AttestationProfileId profile_id() const override {
        return AttestationProfileId::OperatorEnrolled;
    }
    [[nodiscard]] AttestationProfileRuleset profile_ruleset() const override {
        return kAttestationProfileRulesetVersion;
    }
    [[nodiscard]] Digest policy_digest() const override { return policy_digest_; }

    /// True by policy of this fork: the operator's signature stands in for
    /// every platform claim. See the file comment for what that means.
    [[nodiscard]] bool tier1_capable() const override { return true; }

    /// ProfileIncomplete until the profile pins a decodable operator root key.
    [[nodiscard]] std::optional<AttestationFailure> readiness() const override;

    [[nodiscard]] PlatformVerification examine(
        const AttestationChallenge& challenge, const AttestationEvidence& evidence,
        const PlatformVerificationState& state) const override;

private:
    LinuxAttestationProfile profile_;
    std::optional<crypto::Ed25519PublicKey> root_key_;
    Digest policy_digest_;
};

}  // namespace nexus::security
