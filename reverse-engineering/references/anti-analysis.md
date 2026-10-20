# Anti-analysis workflow

## Classify the evidence source

Common sources include debugger state, process lists, device/filesystem artifacts, timing, CPU features, resource size, parent process, loaded modules, breakpoints, code integrity, and network/sandbox behavior. Map source, check, stored verdict, and reaction separately.

## Observe first

- Static: locate imports/syscalls, constants, paths, exception/TLS callbacks, and integrity regions.
- Dynamic: break or hook the evidence source and record real inputs/outputs.
- Trace: compare protected and baseline environments with identical workload.

Do not patch the crash, exit, checksum result, or verdict storage first. That destroys causal evidence and may trigger secondary integrity checks.

## Neutralization hierarchy

1. Reproduce the expected environment legitimately.
2. Control the external evidence source (clock, filesystem fixture, process metadata) in the isolated lab.
3. Instrument the narrow check with exact build-bound hooks.
4. Patch a copy only after the source/reaction path is understood and integrity coverage is mapped.

## Integrity and self-modifying code

Hash boundaries may include code, metadata, relocations, import tables, or writable pages. Record who computes the digest, when it runs, and what bytes are measured. For runtime decryption, capture before/after mappings and permission changes rather than treating encrypted disk bytes as code.

## Reporting

Return the observed source, check location, reaction, neutralization method, scope, build/ABI, evidence, side effects, failed approaches, and residual detection paths.
