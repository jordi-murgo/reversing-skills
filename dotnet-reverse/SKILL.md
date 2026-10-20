---
name: dotnet-reverse
description: "Trigger: .NET assembly, C# binary, ConfuserEx, dnSpyEx, ILSpy. Identify, deobfuscate, inspect, and patch managed code."
license: MIT
metadata:
  author: reversing-skills
  version: "1.0.0"
---

# .NET reverse engineering

## Activation Contract

Load for an authorized PE containing a CLR header/metadata or a confirmed managed assembly. Route NativeAOT and IL2CPP native outputs to `reverse-engineering` after identification.

## Hard Rules

- Hash and preserve the original; write deobfuscated and patched outputs to new destinations.
- Confirm managed metadata before choosing a .NET toolchain.
- Treat decompiled C# as a projection; verify security-relevant logic in IL.
- Do not execute an unknown assembly on the analyst host; use an isolated Windows VM or runtime sandbox.
- Record assembly identity, target framework, runtime, obfuscator evidence, and tool revisions.
- Preserve strong-name/signature status and report when a patch invalidates trust metadata.

## Decision Gates

| Evidence | Action |
|---|---|
| CLR header and metadata streams | Use managed tools |
| NativeAOT/IL2CPP without CLR metadata | Pivot to native analysis |
| Known obfuscator signature | Run a pinned deobfuscator on a copy, then compare |
| Decompiled C# conflicts with behavior | Inspect IL and runtime state |
| Strings/config decrypt only at runtime | Break after the decryptor in an isolated VM |
| Patch changes control flow | Rebuild, verify IL, signatures, and behavior |

## Execution Steps

1. Hash, identify CLR metadata, target framework, architecture, and assembly references.
2. Detect packing/obfuscation and preserve both original and transformed artifacts.
3. Map entry points, module initializers, reflection loaders, resources, and P/Invoke boundaries.
4. Inspect critical branches in IL; use C# output for navigation only.
5. Debug in isolation when runtime-decrypted values are required.
6. Apply the smallest IL/metadata patch to a copy and diff the resulting assembly.

## Output Contract

Return artifact hashes, managed/native determination, framework/runtime, obfuscator evidence, transformed-artifact lineage, IL findings, runtime observations, patch diff, signature impact, failures, and unknowns.

## References

- `references/dotnet-workflow.md` — managed identification, deobfuscation, IL analysis, and patch validation.
