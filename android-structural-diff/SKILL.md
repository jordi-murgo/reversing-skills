---
name: android-structural-diff
description: "Trigger: diff APK versions, R8 obfuscation, malware corpus, Twinflame, library filtering. Compare Android bytecode structurally."
license: MIT
metadata:
  author: reversing-skills
  version: "1.1.0"
---

# Android structural diff

## Activation Contract

Load for authorized comparison of two authenticated APK/DEX versions when names are unstable,
R8/ProGuard obscures changes, or a method-localized delta is required. Do not use for native-only
changes or encrypted payloads that have not been recovered.

## Hard Rules

- Authenticate both artifact sets and preserve version, signer, hash, split, DEX, and ABI identity.
- Treat structural similarity as a candidate match, never proof of semantic equivalence.
- Preserve original DEX/file provenance even when a tool builds one logical class view.
- Pin external differ version, options, report schema, and input hashes for every run.
- Treat known-library signatures as provenance and noise-suppression evidence; never erase the
  underlying classes or hide a modified/repackaged library copy.
- Keep APKs, DEX dumps, prepared records, mappings, reports, and signature packs outside VCS.
- Never copy upstream code or text when its repository lacks a complete license grant.

## Decision Gates

| Situation | Action |
|---|---|
| Small unobfuscated change | Start with manifest/resource/decompiler diff; avoid structural machinery |
| Large or renamed bytecode corpus | Prepare each side once, then compare prepared records |
| One-off application version diff | Known-library labeling is optional; avoid corpus machinery without measurable noise |
| Malware family or large sample corpus | Use a compatible known-library pack to demote shared dependency/runtime code |
| A labeled library changed or was repackaged | Retain it as a first-class finding; do not suppress the delta |
| Packed/encrypted DEX | Recover and hash plaintext DEX before structural comparison |
| Native library change | Load `android-packed-native`; this lane does not inspect ELF behavior |
| Name recovery requested | Require a donor build with usable `SourceFile`; otherwise report unavailable |
| High unmatched/collision volume | Adjust scope/threshold, inspect anchors, and preserve uncertainty |

## Execution Steps

1. Intake both complete artifact sets and establish the intended version relationship.
2. Record baseline manifest, package, DEX, resources, native inventory, and tool versions.
3. Select a pinned external structural differ in an isolated environment.
4. Prepare each input separately; for large apps, never load both raw APKs in one process.
5. For corpus-scale work, load a version-compatible known-library pack and record its hash,
   signature stamp, build date, coordinate coverage, and classification counts.
6. Scope app code, emit changed-only machine output, and retain matching parameters.
7. Reconcile high-value matches against decompiled methods, callers, strings, and runtime evidence.
8. Generate a deobfuscation map only when donor metadata and consumer direction are proven.

## Output Contract

Return input identity, external tool/version, prepared-record hashes, exact options, matched and
unmatched counts, known-library pack identity and demoted/retained counts, confidence/anchor
evidence, method-localized changes, reconciled findings, false-pairing risks, native blind spots,
mapping viability, and residual unknowns.

## References

- `references/structural-diff-workflow.md` — scalable Twinflame boundary, interpretation, rights, and ecosystem gates.
