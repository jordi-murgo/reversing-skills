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

## Capture proof

A valid capture contains the application host request and response, and decrypted bodies
with the expected structural shape. A `CONNECT 200` proves only tunnel establishment.

Keep captures outside VCS with restrictive permissions. Extract only structural facts such
as field names, lengths, encodings, algorithms, status codes, and ordering. Never retain
credentials, tokens, customer data, or sensitive screenshots in a skill repository.

## Cleanup

Clear device proxy state, stop proxy/tunnels, stop owned instrumentation, and cold-start the
application. Record whether cleanup and the clean launch succeeded.
