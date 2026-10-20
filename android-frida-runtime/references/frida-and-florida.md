# Frida and Florida on Android

## Mental model

Frida is the instrumentation framework. A host client controls a server on the Android
device; that server injects an agent into the target process. The agent exposes Java/ART,
native interception, module/memory inspection, and tracing APIs to the analyst's script.

```text
host Frida client -> Android server -> injected agent -> Java/ART and native code
```

The relevant components are:

- Frida client: CLI or Python/Node API used by the analyst;
- `frida-server`: privileged Android process that controls and instruments targets;
- injected agent and Gum: runtime placed inside the target process;
- `frida-java-bridge`: Java/ART API used by scripts that call `Java.perform`;
- Gadget: an embedded alternative to an external server, not part of this server workflow.

## Florida's role

Florida is a patched, Frida-compatible replacement for stock `frida-server`. It is not a
second instrumentation framework, client, Java bridge, hook collection, or GuardIT bypass.
The host still uses Frida clients and scripts, but connects to Florida on the device.

Florida aims to remove or rename common instrumentation fingerprints such as recognizable
strings, thread names, server identity, or other stock runtime artifacts. Use the exact
Florida release matching the client version and target ABI. Do not run stock
`frida-server` and Florida for the same session.

| Need or observation | Correct component or action |
|---|---|
| Intercept Java/native calls | Frida agent and script |
| Control a rooted Android process | stock `frida-server` or Florida |
| Stock-server fingerprints trigger protection | exact-version Florida after proving the comparison |
| `Java` is unavailable in the selected Frida 17 runtime | pinned `frida-java-bridge` bundle |
| Root/emulator artifact is detected | remove or hide that observed cause; Florida is insufficient |
| Direct syscall or self-VMA evidence defeats user-space hooks | authorized kernel/KPM control on a copied image |
| Integrity/checksum reaction | map coverage and preserve verdict flow; neither Frida nor Florida makes patching safe |

## Capability boundary

Florida reduces a subset of Frida fingerprints. It does not make instrumentation invisible
and does not automatically hide root, emulator properties, mounts, packages, SELinux state,
proxy configuration, modified code, trampolines, process mappings, direct syscalls, or
self-inspection. Treat each of those as a separate evidence-backed detection source.

A surviving process proves only that the observed reaction did not fire. It does not prove
that GuardIT is absent, Florida is undetected, or every protected path works. Verification
requires the expected application state, callback telemetry, capture behavior when relevant,
and no new crash/tombstone attributable to the run.

## Launch invariant

For the protected Java-bridge workflow:

```text
spawn suspended -> attach to spawned PID -> load bridge -> load hooks -> resume
```

Attaching the bridge to an application that was already running is a different operation and
may crash after ART has initialized. This restriction is evidence-specific, not a universal
claim that Frida can never attach to a running process.

## Selection evidence

Record the stock-versus-Florida comparison only when both runs use the same artifact, device
state, launch sequence, and hook payload. Capture server/client versions, ABI, process exit or
signal, tombstone identity, last observed callback, and expected application state. Without
that controlled comparison, describe Florida as the selected anti-detection runtime, not as
the proven cause of success.
