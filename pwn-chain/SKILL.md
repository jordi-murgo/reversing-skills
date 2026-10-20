---
name: pwn-chain
description: "Trigger: exploit development, ret2libc, heap exploit, kernel pwn. Turn an authorized memory-corruption primitive into a stable lab exploit."
license: MIT
metadata:
  author: reversing-skills
  version: "1.0.0"
---

# Exploit engineering chain

## Activation Contract

Load only after a concrete vulnerability primitive is understood. Require written authorization, exact binaries/libraries/kernel, and an isolated target. This skill stabilizes a lab exploit; it does not authorize deployment.

## Hard Rules

- Reproduce the primitive before designing a chain; preserve the crashing input and debugger state.
- Record architecture, mitigations, loader, libc/kernel build, ASLR, and remote protocol exactly.
- Never disable protections merely to claim success; separate teaching reductions from target behavior.
- Do not target production, persistence, credential access, or lateral movement.
- Keep payload effects minimal: controlled crash, marker, or ephemeral shell in the approved lab.
- Measure reliability; one successful run is not a stable exploit.

## Decision Gates

| Primitive/environment | Action |
|---|---|
| Stack control without NX | Use minimal controlled execution proof |
| NX plus address disclosure | Build ROP/ret2libc against the exact runtime |
| Heap corruption | Bind technique to allocator and version |
| Kernel primitive | Prove read/write/control separately before privilege transition |
| Remote differs from local | Reproduce loader, libc, timing, buffering, and limits |
| Reliability below acceptance threshold | Report instability; do not claim completion |

## Execution Steps

1. Capture crash, controllable fields, constraints, and mitigations.
2. Build the smallest local harness and deterministic trigger.
3. Add one primitive at a time: leak, write, control-flow, then bounded effect.
4. Pin runtime dependencies and verify gadgets against loaded mappings.
5. Replace sleeps with protocol synchronization; handle partial I/O and retries explicitly.
6. Run repeated clean-state trials and record success/failure causes.

## Output Contract

Return hashes and runtime versions, primitive proof, mitigation matrix, exploit stages, exact commands, reliability results, environmental assumptions, failures, and residual unknowns.

## References

- `references/exploit-stabilization.md` — stack, heap, kernel, and remote-reliability workflow.
