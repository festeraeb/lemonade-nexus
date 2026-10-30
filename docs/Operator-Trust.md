---
layout: default
title: Operator Trust
---

# Operator trust (not hardware trust)

Status: a fork-local build option, `LEMONADE_NEXUS_OPERATOR_TRUST=ON`, default
OFF. A default build names the profile and refuses it. Draft: the prose is to
be read and edited with the operator before any of it is proposed upstream.

## What it is

Upstream Tier 1 requires AMD SEV-SNP with a vTPM (`SnpSvsmVtpm`): the silicon
measures the boot chain, the kernel's IMA log anchors what the process loaded,
and a hardware-signed quote binds all of it to one challenge. Hosts without
SEV-SNP, TDX or a TPM cannot produce that evidence, so on such a fleet no node
can ever reach Tier 1 and the mesh stays pre-quorum.

The `OperatorEnrolled` profile (`AttestationProfileId::OperatorEnrolled = 5`)
replaces the hardware chain with one statement: **the operator root key signed
this server in.** The enrollment names the network, the server's node identity
key and, optionally, the SHA-256 of the server binary the operator installed.
The server returns the enrollment as its platform evidence; the verifier's own
checks still bind that answer to one live challenge, one node, one epoch and
one incarnation.

## What it proves, and what it does not

| Claim name (from the upstream policy) | Under `OperatorEnrolled` it means |
|---|---|
| `hardware_confidentiality_valid` | the operator vouched for this host (no SEV-SNP report exists) |
| `platform_identity_valid` | the enrolled node identity key (no vTPM) |
| `boot_integrity_valid` | the operator vouched (no measured boot) |
| `ima_anchored`, `binary_approved`, `runtime_profile_enforced` | the operator vouched; the binary pin, when set, is a self-report compared against the operator's pin |
| `tcb_valid` | the operator vouched |
| `evidence_freshness_valid` | the verifier bound this answer to a live challenge through the node's identity signature |

`Tier1EligibilityPolicy` is not relaxed: it still needs every claim, plus the
mesh facts (certificate, mesh-observed uptime, participation). What changes is
the meaning of the platform claims, and the profile ID that travels with every
verdict and every claim set says which meaning applies.

The honest statement for a mesh built this way: **Tier 1 is exactly as
trustworthy as the operator's root key and the hosts the operator chose.** A
compromised host that keeps its identity key and its enrollment file passes.
There is no remote way to tell a modified binary from the approved one.

## Files

- `include/LemonadeNexus/Security/EvidenceOperatorEnrolled.hpp`: the enrollment
  and evidence structs, the signing digest, the codecs.
- `include/LemonadeNexus/Security/Attestation/Providers/OperatorEnrolledProvider.hpp`:
  the verifier side.
- `LinuxAttestationProfile::operator_root_pubkey_b64` and
  `operator_approved_binaries_hex`: the pins. They enter `profile_digest()` only
  when the root key is set, so every existing profile keeps its digest.
- `PlatformEvidenceProducer`: with the option ON, answers an `OperatorEnrolled`
  challenge from `<cache_directory>/operator-enrollment.json`.
- Tests: `tests/security/attestation/operator_enrolled.cpp` (both builds), and
  the lifecycle bring-up under the option.

## Possible later step

A TPM 2.0 measured-boot profile (no SEV-SNP) would move boot integrity from
"vouched" to "measured" on hosts that have a TPM module. It needs TPM hardware
on each server and a release process that pins the clean-boot PCRs.
