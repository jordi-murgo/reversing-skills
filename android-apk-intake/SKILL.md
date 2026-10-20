---
name: android-apk-intake
description: "Trigger: APK intake, split APK, APKS, XAPK, APKM, pull installed Android app. Inventory and authenticate complete Android artifact sets."
license: MIT
metadata:
  author: reversing-skills
  version: "1.0.0"
---

# Android APK intake

## Activation Contract

Load before analysing a local APK/archive, a directory of splits, or an installed Android
package. Do not execute application code or install artifacts during intake.

## Hard Rules

- Require an authorization reference and a new output directory.
- Preserve every split and hash each APK independently.
- Reject archive traversal and existing output destinations.
- Record signer uncertainty; missing `apksigner` is not signer consistency.
- Never conclude native or DEX content is absent from `base.apk` alone.
- Keep pulled APKs and generated tool output outside VCS.

## Decision Gates

| Source | Action |
|---|---|
| Single APK | Inventory it in place |
| Directory | Recursively inventory every `.apk` |
| APKS/XAPK/APKM/ZIP | Safely extract APK members into the evidence directory |
| Installed package | Use `adb shell pm path`, then pull every reported path |
| Signer differs across known records | Stop; do not describe the set as one legitimate installation |

## Execution Steps

1. Run `scripts/intake-apk-set.py` with `--authorization-ref` and `--output`.
2. Verify count, source kind, hashes, ZIP integrity, DEX entries, ABIs, and native libraries.
3. Inspect package/version and raw `aapt2` output.
4. Inspect each raw `apksigner` result and `signer_consistent`.
5. Validate the manifest against `assets/evidence-manifest.schema.json` when a JSON Schema
   validator is available.
6. Pass the immutable manifest path to downstream skills.

## Output Contract

Return the evidence-manifest path, artifact count, all hashes, signer consistency, package
and version, split/ABI coverage, tool availability, extraction errors, and unknown fields.

## References

- `scripts/intake-apk-set.py` — local/archive/device intake helper.
- `assets/evidence-manifest.schema.json` — versioned evidence contract.
