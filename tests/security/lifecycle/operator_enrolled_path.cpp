// Five founders reach Tier 1 under OPERATOR TRUST, in process, with the real
// attestation pipeline: each observer's AttestationService issues the
// challenge, the subject's PlatformEvidenceProducer answers it from an
// operator-signed enrollment, and the observer's AttestationVerifier (with the
// OperatorEnrolledProvider compiled into its set) produces the verdict that is
// fed to the driver. Only the wire between challenge and answer is skipped; the
// other lifecycle tests inject fixture verdicts at the same point.
//
// Compiled only with LEMONADE_NEXUS_OPERATOR_TRUST=ON. The default build has no
// provider for the profile, so the same test would (correctly) never found.

#include "support/lifecycle_mesh.hpp"

#if defined(NEXUS_OPERATOR_TRUST) && NEXUS_OPERATOR_TRUST

#include <LemonadeNexus/Security/Attestation/PlatformEvidenceProducer.hpp>
#include <LemonadeNexus/Security/EvidenceOperatorEnrolled.hpp>

#include <fstream>
#include <map>
#include <memory>

namespace lifecycle_test {
namespace {

using nexus::security::EvidenceProducerSources;
using nexus::security::OperatorEnrollment;
using nexus::security::PlatformEvidenceProducer;

struct OperatorEnrolledPath : DriverMesh {
    OperatorEnrolledPath() {
        crypto_sign_keypair(operator_.public_key.data(), operator_.private_key.data());
        profile_ = nexus::security::linux_attestation_profile_v1();
        profile_.operator_root_pubkey_b64 = nexus::crypto::to_base64(operator_.public_key);
        self_hash_ = nexus::security::self_binary_sha256_hex();
    }

    /// Every node verifies under the operator-pinned profile and can answer
    /// for itself from an enrollment the operator signed for its identity.
    void on_node_built(Node& node) override {
        node.runtime->attestation().replace_profile(profile_);

        const fs::path enroll_dir = node.dir / "enroll";
        fs::create_directories(enroll_dir);
        OperatorEnrollment enrollment;
        enrollment.network_id = network;
        enrollment.node_key = node.identity.public_key;
        enrollment.binary_sha256 = self_hash_;  // the operator pins THIS binary
        enrollment.issued_at_unix = 1'761'850'000;
        std::ofstream(enroll_dir / "operator-enrollment.json")
            << nexus::security::encode_operator_enrollment(
                   nexus::security::sign_operator_enrollment(enrollment, operator_));

        EvidenceProducerSources sources;
        sources.identity = node.identity;
        sources.cache_directory = enroll_dir;
        Node* self = &node;
        sources.vote_key_for_epoch = [self](EpochId epoch) {
            return self->driver ? self->driver->vote_key_for_epoch(epoch) : std::nullopt;
        };
        producers_[node.id] = std::make_unique<PlatformEvidenceProducer>(std::move(sources));
    }

    /// The real pipeline for one (observer, subject) pair. Returns the verdict
    /// the observer's own verifier produced, plus the evidence it examined.
    std::pair<AttestationVerdict, AttestationEvidence> attest(Node& observer, Node& subject,
                                                               EpochId epoch) {
        auto& service = observer.runtime->attestation();
        service.reset_attempts(epoch, subject.id);  // the harness drives many rounds
        const auto challenge = service.create_challenge(
            subject.id, subject.identity.public_key, 1, epoch,
            AttestationPurpose::Eligibility);
        EXPECT_TRUE(challenge.has_value()) << "no challenge issued";
        EXPECT_EQ(challenge->profile_id, AttestationProfileId::OperatorEnrolled);
        const auto evidence = producers_.at(subject.id)->produce(*challenge);
        EXPECT_TRUE(evidence.has_value()) << "producer did not answer";
        AttestationVerdict verdict = service.receive_evidence(*evidence);
        EXPECT_TRUE(verdict.passed) << "verdict failed: " << static_cast<int>(verdict.failure);
        EXPECT_EQ(verdict.claims.profile_id, AttestationProfileId::OperatorEnrolled);
        return {verdict, *evidence};
    }

    void deliver(Node& observer, Node& subject, EpochId epoch) {
        auto [verdict, evidence] = attest(observer, subject, epoch);
        observer.driver->on_attestation_verdict(verdict, evidence);
    }

    // The founding, with real verdicts instead of eligibility_verdict().
    void collect_founding_real() {
        for (auto& node : nodes) node->driver->start(mesh.now_ms);
        for (Node* founder : founders) genesis_node->driver->on_peer(founder->id, mesh.now_ms);
        mesh.pump();
        for (Node* founder : founders) deliver(*genesis_node, *founder, 1);
        mesh.pump();
    }

    void run_founding_eligibility_real() {
        for (std::size_t round = 0; round < constants::kMinContinuityObservations; ++round) {
            for (Node* observer : founders) {
                for (Node* subject : founders) {
                    if (observer == subject) continue;
                    deliver(*observer, *subject, 0);
                }
            }
            mesh.pump();
        }
    }

    void bootstrap_real() {
        collect_founding_real();
        ASSERT_EQ(genesis_node->driver->phase(), DriverPhase::GenesisCollecting);
        for (Node* founder : founders) {
            ASSERT_EQ(founder->driver->phase(), DriverPhase::GenesisEligibility);
        }
        run_founding_eligibility_real();
        for (Node* founder : founders) {
            ASSERT_EQ(founder->driver->phase(), DriverPhase::Active);
            ASSERT_EQ(founder->driver->current_epoch(), 1u);
            ASSERT_NE(founder->runtime->consensus(), nullptr);
            ASSERT_TRUE(founder->runtime->consensus()->usable());
        }
    }

    nexus::crypto::Ed25519Keypair operator_;
    LinuxAttestationProfile profile_;
    std::string self_hash_;
    std::map<NodeId, std::unique_ptr<PlatformEvidenceProducer>> producers_;
};

TEST_F(OperatorEnrolledPath, FiveOperatorEnrolledFoundersReachTier1AndKeepQuorumWithOneDown) {
    ASSERT_EQ(founders.size(), constants::kBootstrapThreshold);
    ASSERT_EQ(self_hash_.size(), 64u) << "the test binary must hash itself for the pin";

    bootstrap_real();

    for (Node* founder : founders) {
        EXPECT_TRUE(founder->driver->is_tier1_member()) << "founder is not Tier 1";
        const auto& epoch = founder->runtime->epochs()->current();
        EXPECT_EQ(epoch.tier1_members.members().size(), 5u);
        EXPECT_EQ(epoch.consensus_quorum, constants::consensus_quorum(5));
        EXPECT_EQ(epoch.consensus_quorum, 4u);
    }
    // The genesis anchor never joins Tier 1.
    EXPECT_FALSE(genesis_node->driver->is_tier1_member());

    // One re-attestation round with the real pipeline keeps every member
    // eligible: the verdicts carry the operator-enrolled profile, not a
    // confidential-computing one.
    for (Node* observer : founders) {
        for (Node* subject : founders) {
            if (observer == subject) continue;
            deliver(*observer, *subject, 1);
        }
    }
    mesh.pump();

    // Quorum holds with one founder down: 4 of 5 keep committing.
    const Height before = founders.front()->driver->last_committed_height();
    std::vector<Node*> online(founders.begin(), founders.end() - 1);
    mesh.offline.insert(founders.back()->id);
    advance_commit(online);
    EXPECT_GT(online.front()->driver->last_committed_height(), before)
        << "no commit with 4 of 5 founders online";
    mesh.offline.erase(founders.back()->id);
}

TEST_F(OperatorEnrolledPath, AFounderWithoutAnEnrollmentCannotBeVerified) {
    // Remove one founder's enrollment before anything runs: its producer
    // answers with an empty bundle and every verifier refuses it.
    Node* stranger = founders.back();
    fs::remove(stranger->dir / "enroll" / "operator-enrollment.json");

    for (auto& node : nodes) node->driver->start(mesh.now_ms);
    auto& service = genesis_node->runtime->attestation();
    const auto challenge = service.create_challenge(
        stranger->id, stranger->identity.public_key, 1, 1, AttestationPurpose::Eligibility);
    ASSERT_TRUE(challenge.has_value());
    const auto evidence = producers_.at(stranger->id)->produce(*challenge);
    ASSERT_TRUE(evidence.has_value());
    const auto verdict = service.receive_evidence(*evidence);
    EXPECT_FALSE(verdict.passed);
    EXPECT_EQ(verdict.failure, AttestationFailure::EndorsementRevoked);
    EXPECT_FALSE(verdict.claims.hardware_confidentiality_valid);
}

}  // namespace
}  // namespace lifecycle_test

#endif  // NEXUS_OPERATOR_TRUST
