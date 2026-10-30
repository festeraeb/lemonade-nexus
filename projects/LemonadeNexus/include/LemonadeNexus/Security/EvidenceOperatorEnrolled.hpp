#pragma once

// Operator-enrolled evidence: OPERATOR TRUST, NOT HARDWARE TRUST.
//
// An operator root key (Ed25519) signs one enrollment per server: this network,
// this node identity key, and optionally the SHA-256 of the server binary the
// operator installed. The server presents that enrollment as its "platform
// evidence". The verifier's own chain (challenge digest, node identity
// signature, epoch, incarnation, purpose, context) binds it to one live
// challenge; the OperatorEnrolledProvider checks the enrollment itself.
//
// What this proves: the holder of the operator root key vouched for this
// identity on this network. What it does NOT prove: anything about the
// hardware, the boot chain, the kernel, or what the process has loaded. The
// claims the provider emits (hardware_confidentiality_valid, boot_integrity_valid,
// ima_anchored, ...) are named by Tier1EligibilityPolicy and have to be set for
// a node to reach Tier 1; under this profile each of them MEANS "the operator
// vouched", and the profile ID carried in every verdict and claim set says so.
//
// Intended for self-hosted meshes whose servers have no SEV-SNP, TDX or TPM
// (an all-Intel homelab, for example). A build enables it with
// LEMONADE_NEXUS_OPERATOR_TRUST=ON; the default build names the profile and
// refuses it. See docs/Operator-Trust.md.

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Security/Policy/SecurityTypes.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace nexus::security {

inline constexpr std::string_view kOperatorEnrollmentDomain =
    "LEMONADE-NEXUS-OPERATOR-ENROLL-V1";
inline constexpr uint32_t kOperatorEnrollmentVersion = 1;

/// The static credential the operator issues per server. Signed once, offline
/// if the operator wants; it carries no nonce because the surrounding
/// AttestationEvidence (identity-signed over the challenge digest) is what
/// makes an answer fresh.
struct OperatorEnrollment {
    uint32_t version{kOperatorEnrollmentVersion};
    NetworkId network_id{};
    crypto::Ed25519PublicKey node_key{};
    /// Hex SHA-256 of the approved server binary; empty means the operator
    /// pinned no binary for this server.
    std::string binary_sha256;
    /// Unix seconds when the operator signed. Informational: there is no
    /// expiry rule in v1; revocation is removing or rotating the root pin.
    uint64_t issued_at_unix{};
    crypto::Ed25519PublicKey operator_key{};
    crypto::Ed25519Signature operator_signature{};
};

/// Canonical digest the operator signs. Every field above the signature enters.
[[nodiscard]] Digest operator_enrollment_digest(const OperatorEnrollment& enrollment);

/// Fills operator_key and operator_signature from the operator's keypair.
[[nodiscard]] OperatorEnrollment sign_operator_enrollment(
    OperatorEnrollment unsigned_enrollment, const crypto::Ed25519Keypair& operator_keypair);

/// True when operator_signature verifies under operator_key over the digest.
/// Says nothing about whether operator_key is the pinned root; the provider
/// checks that.
[[nodiscard]] bool operator_enrollment_signature_valid(const OperatorEnrollment& enrollment);

[[nodiscard]] std::string encode_operator_enrollment(const OperatorEnrollment& enrollment);
[[nodiscard]] std::optional<OperatorEnrollment> decode_operator_enrollment(
    std::string_view json);

/// What a server returns as its platform bundle under the OperatorEnrolled
/// profile.
struct OperatorEnrolledEvidence {
    OperatorEnrollment enrollment;
    /// SELF-REPORTED hex SHA-256 of the running executable. A modified binary
    /// reports whatever it likes; the provider only checks that it matches the
    /// operator's pin, which is a consistency check and not a measurement.
    std::string binary_sha256;
    /// Free text for the operator's logs (hostname, for example). Never a
    /// verification input.
    std::string host_note;

    [[nodiscard]] bool empty() const {
        return enrollment.operator_signature == crypto::Ed25519Signature{};
    }
};

[[nodiscard]] std::string encode_operator_enrolled_evidence(const OperatorEnrolledEvidence& ev);
[[nodiscard]] std::optional<OperatorEnrolledEvidence> decode_operator_enrolled_evidence(
    std::string_view json);

/// Hex SHA-256 of this process's executable (/proc/self/exe on Linux). Empty
/// where it cannot be read. Diagnostic: the measured party measuring itself.
[[nodiscard]] std::string self_binary_sha256_hex();

}  // namespace nexus::security
