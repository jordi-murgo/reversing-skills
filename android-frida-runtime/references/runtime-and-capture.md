# Android Frida runtime and capture

## Runtime selection

Read [Frida and Florida](frida-and-florida.md) before choosing the device runtime. Frida is
the instrumentation framework; Florida replaces stock `frida-server` to reduce selected
fingerprints. It does not replace the client, Java bridge, agent scripts, or cause-level
root/emulator/integrity controls.

## Preflight

Record authorization, artifact hash, package, device/AVD identity, Android version, Frida
client/server versions, bridge version, transport, proxy port, and analysis CA state.
Client and server must match exactly.

For remote devices, a common topology is:

```text
device:SERVER_PORT --adb forward--> remote-loopback:SERVER_PORT
remote-loopback:SERVER_PORT --ssh -L--> workstation-loopback:SERVER_PORT
```

Use local forwards for both hops. Prove the final endpoint with `frida-ps` before spawn.

## Frida 17 bridge

Build a pinned bridge bundle once in an isolated directory:

```bash
printf "import runtime from 'frida-java-bridge';\nglobalThis.Java = runtime;\n" > entry.mjs
printf '{"type":"module","dependencies":{"frida-java-bridge":"PINNED_VERSION"}}' > package.json
bun install
bun build entry.mjs --format=iife --target=browser --outfile=jbundle.js
```

Launch:

```bash
bash scripts/frida-run.sh \
  --remote 127.0.0.1:PORT \
  --expected-version VERSION \
  --bridge-bundle jbundle.js \
  --package com.example.authorized \
  --script observe.js
```

The Python API must call `spawn`, then attach to that suspended PID, load, and resume. This
is not the forbidden case; the forbidden case is attaching the Java bridge to a process
that was already running.

## Narrow TLS order

1. application pinning feature gate;
2. application trust-manager provider;
3. application pin-validation use case;
4. exact application interceptor or proven `CertificatePinner` overload.

Do not use Conscrypt as a generic final layer. Chromium/WebView expects exact Java chain
objects and can crash on `null`, JavaScript arrays, or incorrect return types. Registering a
TrustManager alone has no effect until the application receives that instance.

## Conscrypt platform trust (when it is genuinely required)

When a justified Conscrypt hook is unavoidable, hook `TrustManagerImpl` on its real entry
points: `checkTrusted`, `checkTrustedRecursive`, and `checkServerTrusted`. There is no
`verifyTrusted` on current Android 14 builds. **All of them return `java.util.List`** — even
`checkServerTrusted`, which looks void. Return an empty `List` (`ArrayList.$new()`), never
`undefined`:

- An `undefined` return from `checkServerTrusted` becomes a `null` chain that surfaces later
  as `NullPointerException: checkServerTrusted(...) must not be null` inside OkHttp
  (`AndroidCertificateChainCleaner.clean` / `Handshake.peerCertificates`), killing the
  process on the OkHttp dispatcher thread.
- That crash is also a **discovery signal**: any app-owned OkHttp interceptor that reads
  `handshake.peerCertificates` is a pinning layer of its own, independent of the app
  TrustManager. Treat an unexplained OkHttp NPE on a pinned client as a lead to enumerate
  `*CertificatePinning*` / `*Pinning*Interceptor` classes in every class loader before
  touching anything else.

## Protected apps: classes outside the default class loader

In protected or dex-delivered applications, security-relevant classes (trust managers,
collectors, interceptors) may not be reachable with a top-level `Java.use`: it throws
`ClassNotFoundException` even though the class string exists in every shipped DEX. The
class is loaded lazily by a non-default loader (runtime-downloaded dex appended to the
application `PathClassLoader`). Pattern that works:

1. `Java.enumerateClassLoaders` and, per loader, `Java.ClassFactory.get(loader).use(name)`
   instead of `Java.use`.
2. Retry-install on an interval (1–1.5 s) — the classes appear late; the first attempts
   legitimately fail until the runtime component loads.
3. Wrap each candidate in its own `try/catch`; a loader that does not carry the class is
   normal, not an error.
4. A `PathClassLoader` whose `DexPathList` contains a rotating-name zip under the app's
  private data directory is the protector's runtime dex — expect pinning, tamper collectors,
  and string-decryptor natives to resolve only through it.

## Capture proof

A valid capture contains the application host request and response, and decrypted bodies
with the expected structural shape. A `CONNECT 200` proves only tunnel establishment.

Keep captures outside VCS with restrictive permissions. Extract only structural facts such
as field names, lengths, encodings, algorithms, status codes, and ordering. Never retain
credentials, tokens, customer data, or sensitive screenshots in a skill repository.

## Cleanup

Clear device proxy state, stop proxy/tunnels, stop owned instrumentation, and cold-start the
application. Record whether cleanup and the clean launch succeeded.
