---
name: apk-reversing-playbook
description: "Trigger: reverse APK, decompile Android app, diff APK builds, inspect protections. Route an evidence-first Android reversing workflow."
license: MIT
metadata:
  author: reversing-skills
  version: "1.1.0"
---

# APK reversing playbook

## Activation Contract

Load for authorized Android APK analysis, decompilation, build comparison, protection
mapping, runtime instrumentation planning, or rebuild/sign work. Do not load for iOS,
firmware, pure web applications, or targets outside written scope.

## Hard Rules

- Require written authorization and an in-scope artifact.
- Treat an installed application as an APK set; inspect base plus every split and ABI.
- Record hashes, signer, version, source, and tool versions before analysis.
- Preserve per-DEX identity; never merge decompiler trees that can contain colliding paths.
- Identify native code by ELF metadata and behavior, never filename alone.
- Keep target artifacts, captures, credentials, tokens, PII, and runtime dumps outside VCS.
- Mark inference explicitly and preserve failed approaches and residual unknowns.

## Decision Gates

| Situation | Action |
|---|---|
| APK/APKS/XAPK/APKM, split directory, or installed package | Load `android-apk-intake` first |
| Full-APK jadx fails or OOMs | Run `scripts/decode.sh`; retain isolated per-DEX trees |
| Random native filename or encrypted-looking code | Load `android-packed-native` |
| Frida, Java bridge, proxy, or pinning work | Load `android-frida-runtime` |
| AndroidKeyStore aliases, KeyMint, TEE/StrongBox, or per-UID key behavior | Load `android-keystore-analysis` |
| GuardIT callbacks or canonical native component found | Load `arxan-guardit-android` |
| Two large or obfuscated builds | Load `android-structural-diff`; prepare each side once before comparison |
| Re-signed APK installation | Expect signer mismatch; never silently uninstall the store build |

## Execution Steps

1. Establish scope and acquire a complete artifact set through `android-apk-intake`.
2. Inventory manifest, components, permissions, DEX, resources, certificates, and ABIs.
3. Decode with `scripts/decode.sh`; search trust, crypto, tamper, JNI, and loader surfaces.
4. Route structural diff, keystore, packed-native, or GuardIT evidence to its specialist skill.
5. Run dynamic work only after version, transport, device, and evidence preflight.
6. Reconcile static, runtime, and cross-version findings; do not trust one lane alone.
7. Report identity, commands, evidence, failures, unknowns, and reproducible next actions.

## Output Contract

Return authorization status; artifact identity table; evidence-backed findings; exact
commands and tool versions; observed versus inferred claims; failed approaches; residual
unknowns; and evidence paths. A bypass is working only when the protected path reaches its
expected state under observation.

## References

- `references/workflow.md` — concrete static, native, diff, and reporting commands.
- `scripts/decode.sh` — full-APK jadx with isolated per-DEX fallback.
- `scripts/rebuild-sign-install.sh` — rebuild, align, sign, verify, and optional install.
