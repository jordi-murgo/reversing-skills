# Detection-source and kernel escalation

Concealment is justified only by an observed source. Keep the application's verdict and reaction
path intact so the experiment measures the environmental cause rather than corrupting protection
state.

## Source matrix

| Observed source | First response | Kernel boundary |
|---|---|---|
| `Build.*`, Java filesystem/package API | Telemetry at the exact method; coherent lab configuration | None unless a lower source is separately observed |
| `SystemProperties` or libc property call | Observe the exact key/callsite; change one property consistently | Property-area mediation only for proven direct reads |
| Root manager package/process/mount/path | Configure the root framework or mount namespace for that artifact | Do not hide unrelated files or processes |
| libc `open/read/stat/uname` | Narrow hook for observation, preserving arguments/results | Escalate only if the target bypasses libc |
| Direct `svc` reading property memory or `/proc` | Capture callsite, path, offsets, and compared bytes | Scoped property-area or kernel mediation may apply |
| Self-VMA, thread, socket, trampoline, or agent scan | Load `android-frida-runtime`; compare stock server and anti-detection runtime | Kernel changes do not automatically remove in-process evidence |
| Hardware-backed key/attestation verdict | Route to `mobile-attestation-analysis` | An AVD cannot reproduce hardware trust |
| Integrity/checksum reaction | Map covered bytes and timing; move observation boundary | Never patch checksum, stored verdict, or reaction sink |

## Coherent environment changes

A device profile is a set of constraints, not a list of strings. Product/model/fingerprint, ABI,
board, hardware, boot properties, filesystems, drivers, CPU topology, sensors, telephony, mounts,
and attestation must not contradict one another. Record every changed value and its evidence. A
property-area write may affect direct readers but does not alter `/proc`, boot configuration, kernel
command line, devices, or hardware-backed results.

## Custom kernel or KPM gate

Require all of the following before kernel mediation:

1. written authorization names kernel/device modification and the target artifact;
2. the stock negative fixture exposes the source through a direct syscall or kernel-owned surface;
3. app/Java/libc observation cannot mediate that source;
4. stock-kernel lineage, KMI/vermagic, boot recovery, and tool revisions are recorded;
5. the proposed change is scoped to the target UID/PID and exact path/syscall semantics;
6. a control proves system services and unrelated processes retain original behavior.

Build a KPM against the exact KernelPatch revision embedded in the kernel. Inspect undefined symbols
and use only that revision's exported interface; a compiler-generated helper can make module loading
fail. Never hook global `read`, `openat`, or equivalent hot paths. Track an opened target path with
process identity, preserve offsets/lengths/errors, fail open to original data on ambiguity, and
unhook cleanly.

Embed or load a module only on a disposable kernel copy. For revisions supporting it, the command
shape is:

```bash
<kptools> -p -i <patched-kernel-raw> -k <matching-kpimg> \
  -M <module> -T kpm -V post-fs-data -o <derived-kernel-raw>
```

Inspect the pinned tool's help first; module ABI and exported hook APIs change across revisions.
Reapply the original compression wrapper and hash every stage.

## Verification ladder

1. **Stock negative fixture:** observed signal fires at its exact source.
2. **Boot control:** derived kernel cold-boots twice with SELinux state and services recorded.
3. **Narrow source control:** only the observed source differs; unrelated path/property reads match.
4. **Application proof:** expected protected path completes with original verdict/reaction flow.
5. **Health control:** no new tombstone, ANR, kernel warning, module mismatch, or service regression.
6. **Reversion:** stock kernel restores the original signal and behavior.

A hidden indicator is not proof of deprotection. Report the removed evidence source, remaining
signals, app state reached, side effects, failures, and unknown direct-syscall/VMA paths.
