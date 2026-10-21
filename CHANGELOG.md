# Changelog

## Unreleased

- Add `security-analysis-reporting` with application, firmware, malware-triage, and full malware
  templates; evidence-state, severity, confidence, lineage, IOC, and remediation contracts; and
  routing from the application, firmware, malware, and general reverse-engineering skills.

## 0.1.0 - 2026-10-21

- Add pinned CI for repository contracts, negative fixtures, the full test suite, and an
  `npx skills add` consumer install from a directory that is not a Git worktree.
- Bound DEX replacement by archive entry, central-directory, member, aggregate-size, and
  compression-ratio budgets; reject parser-differential EOCD records; reconcile streamed central-
  directory records with canonical EOCD/ZIP64 metadata before invoking Python's ZIP parser;
  snapshot inputs once for hash-bound processing; and reject output-parent replacement around
  descriptor-pinned publication. Bind passive capture validation and bounded reads to one
  descriptor; make FIFO rejection nonblocking; reject output-parent replacement and malformed
  encodings; normalize UTF-16 text for URL, marker, and Base64 analysis; recover bounded extra-slash
  HTTP(S) authorities; cap HTML token length before parsing; follow browser first-value semantics for
  duplicate attributes; extract active URL attributes, `srcset`, meta refresh, and network-path
  hosts; normalize browser-ignored ASCII URL whitespace; cap per-file and global indicators, URL
  characters, URL normalization attempts, and serialized report size; account every decoded byte;
  preserve hosts when query fields are truncated; replace query names and values with one fixed
  marker; reject browser-ambiguous authorities; normalize IDN hosts; escape runtime and argument-
  parser diagnostics.
- Add a safe streaming DEX-only APK replacement helper, a clean-room firmware PoC workflow
  for engagements without hardware, and a local-only landing-page indicator extractor with
  bounded Base64 inspection and passive campaign guidance.
- Add clean-room React Native/Hermes static analysis, Android Frida Gadget injection, and
  offline mobile attestation reconstruction skills with explicit authorization, evidence,
  redistribution, control-build, and backend-probing boundaries.
- Harden artifact handling after a security review: reject `--name`/`--out` path escape in
  `decode.sh` and `rebuild-sign-install.sh`, refuse symlinked inputs outside intake trees in
  `intake-apk-set.py` and `triage-native-libs.py`, move the structural-diff venv recipe to a
  `mktemp`-based path with session cleanup, and document digest verification for installs.
- Close the remaining reviewed warnings: the OMP launcher now excludes gitignored or
  gitignore-listed skill directories while keeping every plain `*/SKILL.md` installable
  through `npx skills add` in non-git projects; archive intake enforces entry-count,
  per-member, aggregate, and compression-ratio budgets (`INTAKE_MAX_*`, tuned for split
  sets); and signing passwords can come from `REBUILD_STORE_PASS`/`REBUILD_KEY_PASS` to
  stay out of process arguments.
- Add clean-room, contract-conformant skills for general native reversing, symbol migration,
  patch-diff analysis, firmware assessment, exploit stabilization, .NET reversing, malware
  detection engineering, and iOS application reversing. Engagement artifacts and unlicensed
  third-party challenge material were intentionally not copied.

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
