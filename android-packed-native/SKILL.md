---
name: android-packed-native
description: "Trigger: packed Android SO, encrypted native library, random JNI library, Arxan native component. Rank and dissect packed ELF candidates."
license: MIT
metadata:
  author: reversing-skills
  version: "1.0.1"
---

# Android packed-native triage

## Activation Contract

Load when native behavior is unexplained, a library has a rotating filename, code appears
random, or a protection runtime may live in an ABI split. Do not use candidate ranking as
proof of packer identity or successful unpacking.

## Hard Rules

- Inspect all APK splits and ABIs before declaring native code absent.
- Identify libraries through `SONAME`, symbols, relocations, imports, and callers.
- Require multiple packing signals; `entry=0` alone is weak for shared libraries.
- Do not patch encrypted bytes, the unpacker, or integrity-covered code before mapping checks.
- Do not call encrypted/decoy bytes decompiled code.
- Hash runtime dumps and bind them to artifact, process mapping, address range, and time.

## Decision Gates

| Evidence | Action |
|---|---|
| Canonical SONAME plus JNI and unpacking imports | Prioritize the library; corroborate runtime ownership |
| High-entropy windows plus few ARM64 prologues | Locate low-entropy constructor/unpacker islands |
| Relocation targets `init_array` | Disassemble the relocation destination and preceding prologue |
| Executable decoy metadata section | Treat section names as hostile; inspect flags and bytes |
| Static seed/plaintext unavailable | Stop guessing; observe page writes or dump after `mprotect` |

## Execution Steps

1. Run `scripts/triage-native-libs.py` on an APK, `.so`, or directory.
2. Review ranking reasons and weak signals independently.
3. Corroborate candidates with `readelf -d/-r/--dyn-syms` and an AArch64 disassembler.
4. Map constructor, parameter table, page-permission changes, and decrypt loop.
5. Capture runtime plaintext only after the unpacker writes it; preserve mapping evidence.
6. Report the static wall honestly when runtime state was not observed.

## Output Contract

Return every library considered, hashes, ELF identity, SONAME, exports/imports, entropy
windows, prologue count, candidate reasons, weak signals, runtime evidence, and unknowns.

## References

- `references/packed-native-workflow.md` — relocation, entropy, unpacker, and dump workflow.
- `scripts/triage-native-libs.py` — deterministic candidate ranking.
