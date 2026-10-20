# Changelog

## Unreleased

- Establish the repository contract and offline verification suite.
- Add split-aware Android artifact intake and evidence manifests.
- Add OOM-safe APK decode and safe rebuild/sign helpers.
- Add packed-native candidate ranking for ARM64 Android libraries.
- Add spawn-first Frida runtime instrumentation with exact-version gates.
- Add evidence-first Arxan/GuardIT callback, packing, evasion, and runtime-dump workflow.
- Explain the Frida component model, Florida's replacement role, controlled selection
  evidence, and the detection classes Florida does not solve.
- Add structural APK/DEX and malware-corpus diff guidance with pinned Twinflame records,
  optional `twinflame_libsigs` library-noise suppression, and a pending public-license boundary.
- Add UID-scoped AndroidKeyStore/KeyMint analysis with explicit non-exportability,
  authorization, usage-limit, and external-probe boundaries.
- Add a zero-copy OMP launcher that exposes only repository-authored root skills, disables
  foreign skill sources and extensions, and preserves target project rules.
