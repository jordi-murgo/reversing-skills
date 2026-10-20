---
name: reverse-engineering
description: "Trigger: compiled binary, obfuscation, custom VM, anti-debug, unknown executable behavior. Build an evidence-backed model before exploitation."
license: MIT
metadata:
  author: reversing-skills
  version: "1.0.0"
---

# General reverse engineering

## Activation Contract

Load when the primary task is understanding an authorized compiled, packed, obfuscated, or virtualized artifact. Route platform-specific Android, iOS, .NET, firmware, malware, or exploitation work to the named specialist after intake.

## Hard Rules

- Require written authorization and hash the exact artifact before analysis or execution.
- Prefer static and read-only methods; execute only in an isolated environment with a capture plan.
- Preserve originals; patch, unpack, emulate, and dump only to new destinations.
- Never trust a single decompiler, symbol guess, string, section name, or family label.
- Bind claims to addresses, bytes, control/data-flow, runtime observations, and tool versions.
- Mark observation, inference, failed approach, and unknown distinctly.

## Decision Gates

| Evidence | Action |
|---|---|
| Known format/architecture | Map headers, segments, imports, relocations, and entry points |
| Managed/runtime metadata | Route to a language/platform specialist |
| Packer/virtualizer indicators | Map loader boundary before decompiling payload bytes |
| Anti-debug/anti-VM behavior | Observe the evidence source; avoid reaction-layer tampering |
| Custom dispatcher/state machine | Recover state, operands, and transfer semantics before lifting |
| Static wall remains | Emulate or instrument the narrowest verified boundary |

## Execution Steps

1. Hash and classify format, architecture, ABI, compiler/runtime clues, and signatures.
2. Build a static map: entry, imports, exports, strings, functions, cross-references, and data.
3. Form explicit hypotheses; verify each with independent evidence.
4. Identify obfuscation, packing, VM, anti-analysis, and self-modifying boundaries.
5. Use dynamic observation only where static evidence stops; capture exact addresses and versions.
6. Automate repeated extraction and preserve commands, outputs, failures, and unknowns.

## Output Contract

Return artifact identity, environment, static map, hypothesis/evidence table, recovered semantics, runtime observations, scripts/commands, failed approaches, and residual unknowns.

## References

- `references/patterns.md` — native patterns and custom-VM workflow.
- `references/anti-analysis.md` — anti-debug, anti-VM, integrity, and observation strategy.
- `references/languages.md` — compiled/runtime-specific routing clues.
- `references/tools.md` — capability-based tool selection.
