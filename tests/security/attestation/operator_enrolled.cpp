// OPERATOR TRUST, NOT HARDWARE TRUST: the OperatorEnrolled provider.
//
// What this file proves: an operator-signed enrollment for exactly this
// network and node passes the verifier and maps onto every Tier 1 platform
// prerequisite; anything else (another operator, a tampered signature, another
// node or network, a binary that disagrees with the pin, no pin at all in the
// profile) fails closed at the named step; the wire form round-trips; a profile
// without operator pins keeps its upstream digest; and a default build has no
// provider for the profile at all.
//
// The provider is constructed directly here so the contract holds in both
// builds. The LEMONADE_NEXUS_OPERATOR_TRUST=ON path, where the compiled
// verifier set and the real producer carry it, is at the end under #if.

#include <LemonadeNexus/Security/Attestation/AttestationService.hpp>
#include <LemonadeNexus/Security/Attestation/AttestationVerifier.hpp>
#include <LemonadeNexus/Security/Attestation/LinuxAttestationProfile.hpp>
#include <LemonadeNexus/Security/Attestation/PlatformEvidence.hpp>
#include <LemonadeNexus/Security/Attestation/PlatformEvidenceProducer.hpp>
#include <LemonadeNexus/Security/Attestation/Providers/OperatorEnrolledProvider.hpp>
#include <LemonadeNexus/Security/EvidenceOperatorEnrolled.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>
#include <LemonadeNexus/Security/Policy/Tier1Evidence.hpp>

#include "support/provider_conformance.hpp"

#include <gtest/gtest.h>
#include <sodium.h>

#include <filesystem>
#include <fstream>
#include <memory>
#include <string>

namespace constants = nexus::security::constants;
namespace fs = std::filesystem;

using namespace nexus::security;

namespace {

constexpr const char* kBinary =
    "aa00aa00aa00aa00aa00aa00aa00aa00aa00aa00aa00aa00aa00aa00aa00aa00";
constexpr const char* kOtherBinary =
    "bb00bb00bb00bb00bb00bb00bb00bb00bb00bb00bb00bb00bb00bb00bb00bb00";

template <std::size_t N>
std::array<uint8_t, N> patterned(uint8_t seed) {
    std::array<uint8_t, N> out{};
    for (std::size_t i = 0; i < N; ++i) out[i] = static_cast<uint8_t>(seed + i);
    return out;
}

nexus::crypto::Ed25519Keypair keypair() {
    nexus::crypto::Ed25519Keypair kp;
    crypto_sign_keypair(kp.public_key.data(), kp.private_key.data());
    return kp;
}

struct OperatorEnrolledTest : ::testing::Test {
    void SetUp() override {
        ASSERT_GE(sodium_init(), 0);
        operator_ = keypair();
        other_operator_ = keypair();
        node_ = keypair();
        network_ = patterned<32>(0x4e);

        profile_ = linux_attestation_profile_v1();
        profile_.operator_root_pubkey_b64 = nexus::crypto::to_base64(operator_.public_key);

        enrollment_ = enrollment_for(node_.public_key, network_, kBinary, operator_);
        challenge_ = make_challenge();
    }

    static OperatorEnrollment enrollment_for(const nexus::crypto::Ed25519PublicKey& node_key,
                                             const NetworkId& network, std::string binary,
                                             const nexus::crypto::Ed25519Keypair& signer) {
        OperatorEnrollment e;
        e.network_id = network;
        e.node_key = node_key;
        e.binary_sha256 = std::move(binary);
        e.issued_at_unix = 1'761'800'000;
        return sign_operator_enrollment(e, signer);
    }

    [[nodiscard]] AttestationVerifier verifier() const {
        ProviderSet set;
        set.push_back(std::make_shared<OperatorEnrolledProvider>(profile_));
        return AttestationVerifier(std::move(set));
    }

    [[nodiscard]] AttestationChallenge make_challenge() const {
        AttestationChallenge c;
        c.network_id = network_;
        c.nonce = patterned<32>(0x01);
        c.node_id.bytes = node_.public_key;
        c.node_key = node_.public_key;
        c.incarnation = 1;
        c.epoch = 1;
        c.security_ruleset = constants::kSecurityRulesetVersion;
        c.consensus_ruleset = constants::kConsensusRulesetVersion;
        c.profile_id = AttestationProfileId::OperatorEnrolled;
        c.profile_ruleset = kAttestationProfileRulesetVersion;
        c.policy_digest = OperatorEnrolledProvider(profile_).policy_digest();
        return c;
    }

    /// What the producer builds, without the producer: the test must not depend
    /// on the build option to prove the provider.
    [[nodiscard]] AttestationEvidence answer(const AttestationChallenge& c,
                                             const OperatorEnrollment& enrollment,
                                             std::string running_binary) const {
        AttestationEvidence e;
        e.network_id = c.network_id;
        e.challenge_digest = challenge_digest(c);
        e.node_id.bytes = node_.public_key;
        e.incarnation = c.incarnation;
        e.epoch = c.epoch;
        e.security_ruleset = constants::kSecurityRulesetVersion;
        e.consensus_ruleset = constants::kConsensusRulesetVersion;
        e.profile_id = c.profile_id;
        e.profile_ruleset = c.profile_ruleset;
        e.purpose = c.purpose;
        e.context_digest = c.context_digest;
        e.ima_mode = c.ima_mode;
        e.epoch_vote_key = patterned<32>(0x77);
        OperatorEnrolledEvidence bundle;
        bundle.enrollment = enrollment;
        bundle.binary_sha256 = std::move(running_binary);
        bundle.host_note = "test-host";
        e.platform = PlatformEvidence{std::move(bundle)};
        sign(e);
        return e;
    }

    void sign(AttestationEvidence& e) const {
        const Digest digest = evidence_signing_digest(e);
        ASSERT_EQ(crypto_sign_detached(e.identity_signature.data(), nullptr, digest.data(),
                                       digest.size(), node_.private_key.data()),
                  0);
    }

    [[nodiscard]] Tier1MeshFacts facts() const {
        Tier1MeshFacts f;
        f.certificate_valid = true;
        f.uptime_valid = true;
        f.mesh_health_valid = true;
        f.current_epoch = challenge_.epoch;
        f.current_incarnation = challenge_.incarnation;
        return f;
    }

    nexus::crypto::Ed25519Keypair operator_, other_operator_, node_;
    NetworkId network_{};
    LinuxAttestationProfile profile_;
    OperatorEnrollment enrollment_;
    AttestationChallenge challenge_;
};

// --- The passing path ---------------------------------------------------------

TEST_F(OperatorEnrolledTest, OperatorSignedEnrollmentPassesAndIsTier1Eligible) {
    const auto verdict = verifier().examine(challenge_, answer(challenge_, enrollment_, kBinary));
    ASSERT_TRUE(verdict.passed) << static_cast<int>(verdict.failure);
    EXPECT_EQ(verdict.failure, AttestationFailure::None);
    EXPECT_EQ(verdict.claims.profile_id, AttestationProfileId::OperatorEnrolled);
    EXPECT_TRUE(all_platform_claims_proved(verdict.claims));
    EXPECT_TRUE(platform_claims_are_consistent(verdict.claims));
    EXPECT_EQ(tier1_eligibility(verdict, facts()), Tier1Eligibility::Eligible);
    EXPECT_TRUE(Tier1EligibilityPolicy::failed_prerequisites(tier1_evidence_state(verdict, facts()))
                    .empty());
}

TEST_F(OperatorEnrolledTest, AnUnpinnedBinaryIsStillVouchedFor) {
    const auto enrollment = enrollment_for(node_.public_key, network_, "", operator_);
    const auto verdict = verifier().examine(challenge_, answer(challenge_, enrollment, kBinary));
    EXPECT_TRUE(verdict.passed);
}

// --- Refusals, each at its own step -------------------------------------------

TEST_F(OperatorEnrolledTest, AProfileWithoutARootPinRefusesEveryCandidate) {
    profile_.operator_root_pubkey_b64.clear();
    challenge_ = make_challenge();
    const auto verdict = verifier().examine(challenge_, answer(challenge_, enrollment_, kBinary));
    EXPECT_FALSE(verdict.passed);
    EXPECT_EQ(verdict.failure, AttestationFailure::ProfileIncomplete);
    EXPECT_EQ(missing_platform_claims(verdict.claims).size(), 11u);
}

TEST_F(OperatorEnrolledTest, AnotherOperatorsKeyIsNotTheRoot) {
    const auto enrollment = enrollment_for(node_.public_key, network_, kBinary, other_operator_);
    const auto verdict = verifier().examine(challenge_, answer(challenge_, enrollment, kBinary));
    EXPECT_FALSE(verdict.passed);
    EXPECT_EQ(verdict.failure, AttestationFailure::EndorsementRevoked);
    EXPECT_FALSE(verdict.claims.hardware_confidentiality_valid);
}

TEST_F(OperatorEnrolledTest, ATamperedEnrollmentSignatureIsRefused) {
    auto enrollment = enrollment_;
    enrollment.operator_signature[5] ^= 0x10;
    const auto verdict = verifier().examine(challenge_, answer(challenge_, enrollment, kBinary));
    EXPECT_EQ(verdict.failure, AttestationFailure::EndorsementRevoked);
}

TEST_F(OperatorEnrolledTest, AnEnrollmentWhoseFieldsWereEditedAfterSigningIsRefused) {
    auto enrollment = enrollment_;
    enrollment.issued_at_unix += 1;
    const auto verdict = verifier().examine(challenge_, answer(challenge_, enrollment, kBinary));
    EXPECT_EQ(verdict.failure, AttestationFailure::EndorsementRevoked);
}

TEST_F(OperatorEnrolledTest, AnEnrollmentForAnotherNodeIsRefused) {
    const auto stranger = keypair();
    const auto enrollment = enrollment_for(stranger.public_key, network_, kBinary, operator_);
    const auto verdict = verifier().examine(challenge_, answer(challenge_, enrollment, kBinary));
    EXPECT_EQ(verdict.failure, AttestationFailure::IdentityMismatch);
}

TEST_F(OperatorEnrolledTest, AnEnrollmentForAnotherNetworkIsRefused) {
    const auto enrollment =
        enrollment_for(node_.public_key, patterned<32>(0x99), kBinary, operator_);
    const auto verdict = verifier().examine(challenge_, answer(challenge_, enrollment, kBinary));
    EXPECT_EQ(verdict.failure, AttestationFailure::NetworkMismatch);
}

TEST_F(OperatorEnrolledTest, TheRunningBinaryMustAgreeWithThePin) {
    const auto verdict =
        verifier().examine(challenge_, answer(challenge_, enrollment_, kOtherBinary));
    EXPECT_EQ(verdict.failure, AttestationFailure::BinaryMeasurementInvalid);
    EXPECT_FALSE(verdict.claims.binary_approved);
}

TEST_F(OperatorEnrolledTest, TheProfileBinaryListExcludesAnUnlistedPin) {
    profile_.operator_approved_binaries_hex = {kOtherBinary};
    challenge_ = make_challenge();
    const auto verdict = verifier().examine(challenge_, answer(challenge_, enrollment_, kBinary));
    EXPECT_EQ(verdict.failure, AttestationFailure::BinaryMeasurementInvalid);
}

TEST_F(OperatorEnrolledTest, AnEmptyBundleIsRefused) {
    auto evidence = answer(challenge_, enrollment_, kBinary);
    evidence.platform = PlatformEvidence{OperatorEnrolledEvidence{}};
    sign(evidence);
    const auto verdict = verifier().examine(challenge_, evidence);
    EXPECT_FALSE(verdict.passed);
    EXPECT_EQ(verdict.failure, AttestationFailure::EndorsementRevoked);
}

TEST_F(OperatorEnrolledTest, EvidenceOfAnotherShapeIsAProfileMismatch) {
    auto evidence = answer(challenge_, enrollment_, kBinary);
    evidence.platform = PlatformEvidence{SnpSvsmVtpmEvidence{}};
    sign(evidence);
    EXPECT_EQ(verifier().examine(challenge_, evidence).failure,
              AttestationFailure::ProfileIdMismatch);
}

// --- Wire form and profile digest -----------------------------------------------

TEST_F(OperatorEnrolledTest, TheEnrollmentAndTheBundleRoundTrip) {
    const auto encoded = encode_operator_enrollment(enrollment_);
    const auto decoded = decode_operator_enrollment(encoded);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(encode_operator_enrollment(*decoded), encoded);
    EXPECT_TRUE(operator_enrollment_signature_valid(*decoded));

    const auto evidence = answer(challenge_, enrollment_, kBinary);
    const auto wire = encode_platform_evidence(evidence.platform);
    const auto back = decode_platform_evidence(wire);
    ASSERT_TRUE(back.has_value());
    EXPECT_EQ(platform_evidence_type(*back), PlatformEvidenceType::OperatorEnrolled);
    EXPECT_EQ(encode_platform_evidence(*back), wire);
    EXPECT_EQ(platform_evidence_digest(*back), platform_evidence_digest(evidence.platform));
}

TEST_F(OperatorEnrolledTest, MalformedBundlesDoNotDecode) {
    EXPECT_FALSE(decode_operator_enrolled_evidence("{}").has_value());
    EXPECT_FALSE(decode_operator_enrolled_evidence("not json").has_value());
    EXPECT_FALSE(decode_operator_enrollment(R"({"version":1})").has_value());
    auto enrollment = enrollment_;
    enrollment.binary_sha256 = "zz";  // not hex, not 64 chars
    EXPECT_FALSE(decode_operator_enrollment(encode_operator_enrollment(enrollment)).has_value());
}

TEST_F(OperatorEnrolledTest, AProfileWithoutOperatorPinsKeepsItsUpstreamDigest) {
    const auto upstream = linux_attestation_profile_v1();
    LinuxAttestationProfile same = upstream;
    same.operator_approved_binaries_hex = {kBinary};  // ignored without a root key
    EXPECT_EQ(profile_digest(same), profile_digest(upstream));
    EXPECT_NE(profile_digest(profile_), profile_digest(upstream));
    LinuxAttestationProfile other_root = profile_;
    other_root.operator_root_pubkey_b64 = nexus::crypto::to_base64(other_operator_.public_key);
    EXPECT_NE(profile_digest(other_root), profile_digest(profile_));
}

TEST_F(OperatorEnrolledTest, TheProfileIdIsNamedAndKnown) {
    EXPECT_EQ(attestation_profile_id_name(AttestationProfileId::OperatorEnrolled),
              "operator-enrolled");
    EXPECT_TRUE(is_known_attestation_profile_id(AttestationProfileId::OperatorEnrolled));
}

// --- The shared provider contract -------------------------------------------------

TEST_F(OperatorEnrolledTest, SatisfiesTheProviderConformanceContract) {
    nexus_test::ConformanceSubject subject;
    subject.name = "operator-enrolled";
    subject.profile_id = AttestationProfileId::OperatorEnrolled;
    subject.verifier = [this] { return verifier(); };
    subject.challenge = [this] { return challenge_; };
    subject.answer = [this](const AttestationChallenge& c) {
        return answer(c, enrollment_, kBinary);
    };
    subject.resign = [this](AttestationEvidence& e) { sign(e); };
    nexus_test::run_provider_conformance(subject);
}

// --- Build-option behaviour ----------------------------------------------------------

#if defined(NEXUS_OPERATOR_TRUST) && NEXUS_OPERATOR_TRUST

TEST_F(OperatorEnrolledTest, OptionOnTheCompiledVerifierCarriesTheProvider) {
    EXPECT_EQ(kTier1AttestationProfileId, AttestationProfileId::OperatorEnrolled);
    const AttestationVerifier compiled(profile_);
    ASSERT_NE(compiled.provider_for(AttestationProfileId::OperatorEnrolled), nullptr);
    EXPECT_TRUE(compiled.examine(challenge_, answer(challenge_, enrollment_, kBinary)).passed);
}

TEST_F(OperatorEnrolledTest, OptionOnTheRealProducerAnswersAServiceChallenge) {
    const fs::path root = fs::path(::testing::TempDir()) / "operator-enrolled-producer";
    fs::remove_all(root);
    fs::create_directories(root);

    // The operator pins the hash of THIS test binary, so the self-report must
    // agree with the pin for the verdict to pass.
    const std::string self_hash = self_binary_sha256_hex();
    ASSERT_EQ(self_hash.size(), 64u);
    const auto enrollment = enrollment_for(node_.public_key, network_, self_hash, operator_);
    {
        std::ofstream out(root / "operator-enrollment.json");
        out << encode_operator_enrollment(enrollment);
    }

    AttestationService service(network_, profile_, {}, root / "state");
    const auto challenge = service.create_challenge(NodeId{node_.public_key}, node_.public_key,
                                                    1, 1, AttestationPurpose::Eligibility);
    ASSERT_TRUE(challenge.has_value());
    EXPECT_EQ(challenge->profile_id, AttestationProfileId::OperatorEnrolled);

    EvidenceProducerSources sources;
    sources.identity = node_;
    const auto vote_pk = patterned<32>(0x55);
    sources.vote_key_for_epoch = [vote_pk](EpochId) { return std::optional{vote_pk}; };
    sources.cache_directory = root;
    PlatformEvidenceProducer producer{std::move(sources)};
    const auto evidence = producer.produce(*challenge);
    ASSERT_TRUE(evidence.has_value());
    EXPECT_EQ(platform_evidence_type(evidence->platform), PlatformEvidenceType::OperatorEnrolled);

    const auto verdict = service.receive_evidence(*evidence);
    EXPECT_TRUE(verdict.passed) << static_cast<int>(verdict.failure);
    EXPECT_EQ(tier1_eligibility(verdict, facts()), Tier1Eligibility::Eligible);
}

TEST_F(OperatorEnrolledTest, OptionOnAMissingEnrollmentFileAnswersWithAnEmptyBundleThatFails) {
    const fs::path root = fs::path(::testing::TempDir()) / "operator-enrolled-missing";
    fs::remove_all(root);
    fs::create_directories(root);
    AttestationService service(network_, profile_, {}, root / "state");
    const auto challenge = service.create_challenge(NodeId{node_.public_key}, node_.public_key,
                                                    1, 1, AttestationPurpose::Eligibility);
    ASSERT_TRUE(challenge.has_value());
    EvidenceProducerSources sources;
    sources.identity = node_;
    const auto vote_pk = patterned<32>(0x55);
    sources.vote_key_for_epoch = [vote_pk](EpochId) { return std::optional{vote_pk}; };
    sources.cache_directory = root;
    PlatformEvidenceProducer producer{std::move(sources)};
    const auto evidence = producer.produce(*challenge);
    ASSERT_TRUE(evidence.has_value());
    const auto verdict = service.receive_evidence(*evidence);
    EXPECT_FALSE(verdict.passed);
    EXPECT_EQ(verdict.failure, AttestationFailure::EndorsementRevoked);
}

#else

TEST_F(OperatorEnrolledTest, DefaultBuildHasNoProviderForTheProfile) {
    EXPECT_EQ(kTier1AttestationProfileId, AttestationProfileId::SnpSvsmVtpm);
    const AttestationVerifier compiled(profile_);
    EXPECT_EQ(compiled.provider_for(AttestationProfileId::OperatorEnrolled), nullptr);
    const auto verdict = compiled.examine(challenge_, answer(challenge_, enrollment_, kBinary));
    EXPECT_FALSE(verdict.passed);
    EXPECT_EQ(verdict.failure, AttestationFailure::ProviderUnknown);
}

#endif

}  // namespace
