---
name: react-native-hermes-analysis
description: "Trigger: React Native APK, Hermes bytecode, Expo bundle, index.android.bundle. Recover authorized application structure without redistributing source."
license: MIT
metadata:
  author: reversing-skills
  version: "1.0.0"
---

# React Native Hermes analysis

## Activation Contract

Load for authorized static analysis of a React Native or Expo artifact containing a Hermes
bundle. Require written authorization and the hash of the complete APK or bundle set. Route
ordinary DEX/native work to `apk-reversing-playbook`.

## Hard Rules

- Preserve the original and extract only to a new evidence directory outside VCS.
- Record bundle hash, Hermes bytecode version, ABI, tool version, command, and failures.
- Pin each external decoder by immutable version and verify its license before use.
- Treat decompiler output as a fallible representation; corroborate with raw strings and use sites.
- Never commit bundles, decompiled code, route content, translations, endpoints, tokens, or identifiers.
- Report only structural facts needed by scope; do not reproduce copyrighted application source.
- Do not execute JavaScript or contact discovered services during static analysis.

## Decision Gates

| Evidence | Action |
|---|---|
| `index.android.bundle` plus Hermes native runtime | Identify bytecode version, then select a compatible decoder |
| Plain JavaScript bundle | Analyze text directly; do not force a Hermes decoder |
| Unsupported bytecode version | Continue with bounded string/inventory analysis and report the decode gap |
| Expo metadata present | Inventory configuration and routing metadata before bytecode work |
| Secret or credential-like value appears | Redact it and keep the raw evidence outside VCS |
| Runtime-only construction blocks the question | Stop static claims or route separately approved observation to `android-frida-runtime` |

## Execution Steps

1. Inventory the complete APK set and hash the bundle and relevant native runtimes.
2. Establish React Native, Expo, and Hermes evidence; record the bytecode version.
3. Read plaintext metadata and run a bounded raw-string census before decompilation.
4. Decode with an exact-compatible, pinned tool into a new external evidence directory.
5. Recover routes, modules, localization namespaces, design tokens, storage keys, and API shapes from independent anchors.
6. Trace each reported item to its raw literal and construction/use context; mark unresolved state.
7. Remove temporary derived output when retention is not authorized and report residual unknowns.

## Output Contract

Return artifact and bundle hashes, framework/bytecode evidence, tool versions, structural
inventories with source offsets or module anchors, corroboration status, redactions, failed
methods, derived-evidence paths, and unknowns. Do not return extracted source wholesale.

## References

- `references/hermes-static-workflow.md` — bundle detection, compatible decoding, targeted extraction, and evidence limits.
