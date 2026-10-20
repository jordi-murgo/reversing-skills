---
name: android-keystore-analysis
description: "Trigger: AndroidKeyStore aliases, KeyMint metadata, TEE key operation, keystore oracle. Analyse app-scoped keys safely."
license: MIT
metadata:
  author: reversing-skills
  version: "1.0.0"
---

# Android Keystore analysis

## Activation Contract

Load for authorized enumeration of an Android application's keystore aliases, KeyInfo/KeyMint
metadata, hardware/authentication properties, or a bounded operation using a non-exportable key.
Do not load for APK signer recovery, private-key extraction, or unrestricted device-wide scans.

## Hard Rules

- Scope package, device, user/profile, and UID before probing; shared UIDs widen the boundary.
- AndroidKeyStore isolation is UID-based. An adb shell process sees only its own namespace.
- Root/UID impersonation exposes metadata and key operations, not exportable private-key bytes.
- Default to enumeration. Encrypt/sign/MAC can consume usage quotas or require user presence.
- Never use production transactions, credentials, challenges, or backend-bound payloads as probes.
- Keep aliases, certificates, reports, operation outputs, and device identifiers outside VCS.

## Decision Gates

| Situation | Action |
|---|---|
| Device lacks authorized root | Observe the app's own KeyStore calls or report UID probing blocked |
| Alias inventory requested | Probe only approved packages/UIDs; include UID-mates explicitly |
| Metadata shows auth or usage limits | Stop before operations until side effects and unlock state are approved |
| Local operation is required | Use an analyst-owned test vector; never submit its output to production |
| Claim says key was extracted | Reject it unless raw key bytes were independently proven; normal KeyMint use is non-exporting |
| Attestation chain is present | Treat it as public certificate evidence, not proof of every hardware claim |

## Execution Steps

1. Record authorization, artifact, device build, Android user, package, UID, and root mechanism.
2. Resolve every package sharing the UID and confirm that all are in scope.
3. Select an auditable, pinned external probe; record source revision and binary/probe hash.
4. Enumerate aliases and metadata before any cryptographic operation.
5. Classify algorithm, purposes, modes, paddings, digests, origin, security level, auth binding,
   validity, remaining usage, and public certificate/attestation evidence.
6. Run a local operation only after its authorization and side effects are explicit.
7. Remove staged tooling, preserve external evidence, and report unsupported or inaccessible fields.

## Output Contract

Return scope and UID mapping, tool/probe identity, alias inventory, KeyMint metadata, public
certificate evidence, inaccessible fields, authentication/usage constraints, each approved
operation and local test vector, side effects, cleanup state, and residual unknowns. Never return
or claim private-key material without direct evidence.

## References

- `references/keystore-analysis-workflow.md` — UID boundary, safe operation model, and external-tool assessment.
