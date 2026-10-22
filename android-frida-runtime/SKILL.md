---
name: android-frida-runtime
description: "Trigger: Frida Android, Florida server, spawn protected app, Java bridge, TLS capture. Instrument Android runtime safely."
license: MIT
metadata:
  author: reversing-skills
  version: "1.2.0"
---

# Android Frida runtime

## Activation Contract

Load for authorized server-backed Android runtime instrumentation, exact-version Frida setup,
app-layer TLS trust analysis, or remote emulator/device transport. Do not load for static-only
work; use `android-frida-gadget` when instrumentation requires a re-signed application.

## Hard Rules

- Match client and server versions exactly before launch.
- Treat Florida as an exact-version replacement for stock `frida-server`, not as a client,
  bridge, hook kit, or universal GuardIT bypass.
- Florida reduces selected Frida fingerprints; it does not hide root, emulator evidence,
  direct syscalls, self-VMA inspection, integrity reactions, or unsafe hooks.
- Spawn protected applications suspended, load hooks, then resume. Attach is explicit and
  must not introduce a Java bridge into an already-running protected process.
- Use one observable hook layer at a time; call originals for telemetry-only hooks.
- Prefer app trust-provider, pin validator, or exact interceptor over Conscrypt internals.
- Registration of a permissive TrustManager changes nothing until the app receives it.
- Prove capture with decrypted request and response content, not `CONNECT 200`.
- Keep captures, bodies, tokens, credentials, and sensitive screenshots outside VCS.

## Decision Gates

| Situation | Action |
|---|---|
| Remote server | Establish adb/SSH forwarding, then prove `frida-ps` connectivity |
| Compatible server cannot run and APK mutation is authorized | Route to `android-frida-gadget` |
| Stock server triggers evidenced instrumentation fingerprints | Replace it with matching-version Florida; keep client and scripts unchanged |
| Frida 17 Java hook | Supply a bridge bundle in the same script context |
| Version mismatch | Stop before process creation |
| Generic bypass kit proposed | Review one module and exact overload; reject catch-all execution |
| WebView generic error | Remove Conscrypt hooks and inspect app-owned trust paths |
| Protected app already running | Restart and spawn; do not attach the Java bridge |
| Rooted AVD, patched kernel, or evidenced root/emulator concealment needed | Load `android-rooted-emulator` before server deployment |
| Unexplained OkHttp `NullPointerException` on a pinned client | Suspect a hidden app-owned pinning interceptor reading `peerCertificates`; enumerate `*Pinning*` classes across all loaders before changing hooks |
| `ClassNotFoundException` for a class present in shipped DEX | Class lives in a runtime-downloaded dex behind a non-default loader; switch to `enumerateClassLoaders` + `ClassFactory.get` retry-install |
| Conscrypt `checkServerTrusted` hook genuinely required | Return an empty `List`, never `undefined`; a wrong type NPEs inside OkHttp and kills the dispatcher thread |
| Claim that an APK-embedded certificate protects a specific payload | Never conclude from static analysis or startup capture alone; bind it at runtime (source → `CertificateFactory` → SPKI → `doFinal`) |

## Execution Steps

1. Record device, app, client/server/bridge versions, server kind (stock or Florida),
   transport, and authorization.
2. Run `scripts/frida-run.sh --dry-run` and inspect the generated command.
3. Verify transport with `frida-ps`.
4. Spawn with the narrow telemetry hook; establish a clean baseline.
5. Add one evidence-backed app-layer bypass at a time.
6. Capture and verify the protected request/response path.
7. Clear proxy, stop tunnels, and cold-start the app after the session.

## Output Contract

Return preflight state, exact launch command, versions, enabled hook layers, observed
calls, capture proof, crashes/signals, failed layers, cleanup state, and unknowns.

## References

- `references/runtime-and-capture.md` — bridge, topology, TLS, and evidence workflow.
- `references/frida-and-florida.md` — architecture, responsibilities, selection, and limits.
- `scripts/frida-run.sh` — spawn-first launcher with version and transport gates.
