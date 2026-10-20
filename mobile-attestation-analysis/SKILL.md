---
name: mobile-attestation-analysis
description: "Trigger: mobile attestation blob, opaque telemetry field, device-integrity payload. Classify and reconstruct authorized client-generated blobs offline."
license: MIT
metadata:
  author: reversing-skills
  version: "1.0.0"
---

# Mobile attestation analysis

## Activation Contract

Load for authorized analysis of an opaque mobile request field, device-integrity payload, or
client-generated telemetry blob. Require the exact application artifact and sanitized captures in
scope. Route AndroidKeyStore certificate attestation to `android-keystore-analysis`.

## Hard Rules

- Work offline by default; backend replay, login, operation signing, and production probes require separate written approval.
- Never use real credentials, customer data, production challenges, or automatic retries.
- Determine representation before size, entropy, or crypto claims; hex can also parse as Base64 text.
- Entropy is a triage signal, never proof of encryption, signing, compression, or native origin.
- Trace the producing call path; a nearby protector library does not prove the blob came from it.
- Preserve captures outside VCS, redact reports, and bind every claim to artifact/capture hashes.
- Require exact byte round-trip before claiming reconstruction; backend acceptance remains unknown.

## Decision Gates

| Evidence | Action |
|---|---|
| Valid JSON or structured text | Inventory schema and producer before cryptographic hypotheses |
| Multiple encodings parse | Follow the application's encode call and expected decoded length |
| Platform attestation certificate chain | Route chain/policy validation to `android-keystore-analysis` |
| Block-aligned decoded bytes | Inspect the exact cipher transformation and key/IV derivation call path |
| Runtime-only values feed construction | Observe only the narrow producer boundary if separately authorized |
| One capture only | Reconstruct cautiously; variable/constant classification remains unknown |
| Exact offline round-trip succeeds | Claim construction equivalence only, not server acceptance or bypass |

## Execution Steps

1. Hash artifacts and sanitized captures; inventory field spelling, representation, length, and neighboring fields.
2. Test text and encoding candidates without executing content; compute entropy only on correctly decoded bytes.
3. Locate serialization, encoding, crypto, and field-insertion callsites; trace backward to every input source.
4. Record the exact transformation, provider semantics, key/IV derivation, padding, field order, state, and freshness.
5. Build an offline reconstruction using only approved synthetic or sanitized inputs.
6. Verify decode and exact re-encode equality across independent captures; preserve negative mismatches.
7. Separate construction findings from backend validation, authorization, anti-replay, and device-binding unknowns.

## Output Contract

Return artifact/capture hashes, representation decision, schema or plaintext grammar, producer
call chain, transformation and derivation evidence, per-capture round-trip results, redactions,
failed hypotheses, authorization boundary, and residual backend/runtime unknowns.

## References

- `references/blob-reconstruction-workflow.md` — representation triage, producer tracing, exact round-trip, and claim boundaries.
