---
name: android-frida-gadget
description: "Trigger: Frida Gadget Android, instrumentation without root, re-signed APK injection. Build and verify an authorized root-free instrumentation artifact."
license: MIT
metadata:
  author: reversing-skills
  version: "1.0.0"
---

# Android Frida Gadget

## Activation Contract

Load when an authorized Android artifact must use Frida Gadget because a compatible server cannot
run on the device. Require written authorization for APK mutation, installation, and device use.
Use `android-frida-runtime` for server-backed instrumentation.

## Hard Rules

- Preserve originals; write every decoded, repacked, aligned, and signed artifact to a new path.
- Match Gadget, client, architecture, and Java bridge versions before installation.
- Keep Gadget binaries, target APKs, signing keys, credentials, logs, and captures outside VCS.
- Pin external binaries and tools by version, digest, source, and license; never download implicitly.
- Inspect `extractNativeLibs`, ABI splits, compression, and page alignment before choosing packaging.
- Modify the narrowest evidenced load boundary; never apply a generic protection bypass.
- Never silently uninstall or replace a store-signed application.
- A listening socket is not proof: require load evidence, client attachment, and one expected observation.

## Decision Gates

| Situation | Action |
|---|---|
| Writable, non-protected early Java path exists | Consider one explicit `System.loadLibrary` insertion |
| Stable native library is already loaded | Consider one `DT_NEEDED` edge after mapping integrity coverage |
| `extractNativeLibs=false` | Store native entries uncompressed and prove target page alignment |
| Split application | Mutate the owning split and sign the complete compatible set with one analysis key |
| Any control build fails | Stop; do not attribute the failure to Gadget |
| Integrity reaction appears | Observe and report its source; do not patch the reaction sink |

## Execution Steps

1. Record authorization, artifact set, signer, package/version, ABI, device, Android, and page size.
2. Inventory native loading, `extractNativeLibs`, integrity coverage, and candidate load vectors.
3. Build three isolated artifacts: re-signed control, unchanged-repack control, and Gadget candidate.
4. Add a pinned Gadget and matching configuration through one selected load vector.
5. Preserve ZIP compression policy, align for the target, sign every split consistently, and verify all outputs.
6. Install only on the approved test profile/device; confirm load, attach, and one narrow telemetry hook.
7. Compare controls, capture failures, remove test artifacts and forwarding, and cold-start cleanly.

## Output Contract

Return input/output hashes, selected load vector and evidence, exact component/tool versions,
packaging/alignment/signing verification, control outcomes, load/attach/hook proof, integrity
reactions, cleanup state, failures, and unknowns.

## References

- `references/gadget-injection-workflow.md` — load vectors, packaging invariants, controls, and runtime proof.
