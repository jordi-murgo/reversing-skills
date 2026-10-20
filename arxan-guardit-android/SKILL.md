---
name: arxan-guardit-android
description: "Trigger: Arxan Android, GuardIT, native tamper callbacks, emulator detection, encrypted GuardIT SO. Analyse and neutralize causes safely."
license: MIT
metadata:
  author: reversing-skills
  version: "1.1.0"
---

# Arxan/GuardIT Android

## Activation Contract

Load when Android evidence identifies GuardIT callbacks, a canonical native component,
integrity reactions, or a packed native runtime. Require written authorization and a
legitimate artifact. Load `android-apk-intake`, `android-packed-native`, and
`android-frida-runtime` for their specialist lanes.

## Hard Rules

- Observe callbacks, arguments, ordering, threads, and downstream state before interference.
- Neutralize the detection source, never checksums, verdict storage, collector, reaction
  sink, packed library, or callback result.
- Do not modify DEX or native code before mapping integrity coverage.
- Preserve original verdict flow; reaction-state tampering may trigger `SIGBUS`.
- Treat Florida as an anti-detection `frida-server` replacement, never as proof that
  GuardIT is absent or as a bypass for root, emulator, syscall, VMA, or integrity checks.
- Treat direct syscalls and self-VMA scans as kernel-visible evidence; libc/property hooks
  cannot hide calls they never mediate.
- Use a copied emulator image and preserve known-working kernel/initrd artifacts.

## Decision Gates

| Evidence | Action |
|---|---|
| JNI-only callback surface | Map callback → collector → native reaction |
| Rotating filename with canonical SONAME | Prove ownership and packing before attribution |
| Stock Frida fails but exact-version Florida survives a controlled baseline | Attribute only the runtime-fingerprint difference; continue cause-level mapping |
| Verdict changes only after hook tampering | Restore original flow; classify reaction-state guard |
| Property/libc hooks have no effect | Investigate direct `svc` and self-VMA evidence |
| Unpacker changes page permissions | Capture the written range after the transition |
| Runtime seed or mapping absent | Stop; report residual unknown instead of guessing |

## Execution Steps

1. Populate `assets/callback-matrix.csv` from a clean baseline.
2. Prove packed-native ownership and unpacker boundaries.
3. Spawn with exact-version anti-detection instrumentation and telemetry-only hooks.
4. Change one environmental cause at a time and preserve the reaction path.
5. Escalate emulator hiding to authorized kernel/KPM controls when direct syscalls are proven.
6. Dump and hash runtime plaintext only after a verified unpacking write.
7. Reconcile callbacks, JNI registration, recovered code, and app behavior.

## Output Contract

Return callback matrix, native identity, packing evidence, baseline verdicts, each changed
cause, reaction/crash evidence, recovered mappings and hashes, negative findings, failed
hypotheses, and residual unknowns.

## References

- `references/deprotection-workflow.md` — static-to-runtime GuardIT procedure.
- `assets/callback-matrix.csv` — observation template; never store client values here.
