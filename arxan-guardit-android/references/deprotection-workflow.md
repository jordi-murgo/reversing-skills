# Arxan/GuardIT Android deprotection workflow

The goal is observable application behavior without corrupting protection state. Catch-all
bypass scripts are unsafe because GuardIT can correlate checks and react when verdict flow
itself changes.

## Instrumentation boundary

Frida is the host client, device server, injected agent, Java bridge, and script API used to
observe the target. Florida is only a patched, protocol-compatible replacement for stock
`frida-server`; the client and scripts remain Frida. It reduces selected runtime
fingerprints but does not hide root, emulator state, proxying, direct syscalls, self-VMA
inspection, modified code, or integrity-covered changes.

Use a controlled stock-versus-Florida comparison before attributing survival to Florida:
same artifact, device state, launch sequence, and telemetry payload. Process survival is not
proof of deprotection; require the expected application state, callback evidence, and no new
run-attributable tombstone. Load `android-frida-runtime` for the complete component model
and launch contract.

## Protection surface

1. Intake every split and ABI.
2. Identify native candidates through SONAME, exports, relocations, and imports.
3. Find Java callbacks for checksum, root, hook, emulator, debugger, or tamper events.
4. Expect JNI-only callers; missing Java xrefs do not make a callback dead.
5. Locate the collector/reaction sink and populate the callback matrix from a clean baseline.

Record callback, JNI evidence, original argument/return, label, thread, timestamp,
downstream state write, and reaction. Telemetry hooks call originals and preserve ordering.

## Packed runtime

Require multiple signals: high-entropy executable windows, few plausible ARM64 prologues,
a low-entropy constructor/unpacker island, `init_array` relocation, unpacker/self-inspection
imports, and executable decoy metadata sections. A rotating filename is not identity;
canonical SONAME plus behavior is stronger.

Encrypted bytes are not decompiled code. Static work stops at the unpacker when seed or
plaintext exists only at runtime.

## Safe dynamic observation

- Use an analysis-only physical device or copied emulator image.
- Preserve known-working kernels/initrds; perform each experiment on a separate copy.
- Allocate enough RAM to prevent reboot/reversion of kernel masking.
- Match anti-detection server and client versions exactly.
- Spawn, load telemetry hooks, then resume.
- Change one environmental input at a time.
- Record signal, fault address, thread, last callback, and page transition on failure.

A crash after callback/verdict tampering indicates a likely reaction-state guard. Restore
original flow before testing another hypothesis.

## Cause-level response

| Detection source | Evidence | Response |
|---|---|---|
| Instrumentation artifacts | thread names, sockets, ports, mappings, trampolines, ART entrypoints | exact-version anti-detection runtime |
| Root artifacts | files, packages, mounts, properties, SELinux state | hide only the observed artifact |
| Java debugger | exact framework call | narrow hook at that call |
| Emulator through libc/property APIs | observed callsite and comparison | mask the observed source |
| Emulator through direct `svc` or self-VMA scan | syscall site and compared bytes/path | authorized kernel/KPM hiding on a copied image |
| Integrity/checksum | covered range and reaction timing | do not patch; move observation after verified initialization |

libc, property, and `Build.*` hooks cannot hide direct syscalls or evidence read from the
process's own VMAs.

## Runtime recovery

Use the unpacker's page-permission transition as the boundary:

1. resolve constructor through relocations;
2. observe `mprotect` without changing it;
3. capture page address, length, permissions, and caller;
4. dump after the write through an authorized root/debugger path;
5. hash the dump and map VA to image-relative offsets;
6. reconcile recovered functions with JNI registrations and callbacks.

Stop when runtime seed/mapping was not observed, instrumentation changes reaction state, or
a dump cannot be tied to the loaded artifact. Report negative hypotheses: failed property
hooks are useful evidence against repeating the same dead end.
