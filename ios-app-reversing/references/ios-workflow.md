# iOS application workflow

## Intake

Record IPA/app source, SHA-256, bundle ID/version, team ID, provisioning profile, entitlements, architectures, minimum OS, embedded frameworks/extensions, and Mach-O encryption state. Decrypted store binaries and profiles remain engagement evidence.

## Static map

- `Info.plist`: URL schemes, background modes, ATS, queried schemes, document types.
- signing: CodeDirectory, requirements, entitlements, embedded mobile provision.
- Mach-O: load commands, segments, imports, dylibs, symbols, Objective-C metadata, Swift metadata.
- storage/network: keychain access groups, databases, preferences, web views, crypto and trust APIs.

Objective-C selectors and Swift demangling accelerate navigation but do not prove reachability. Validate cross-references and runtime ownership.

## Device/runtime gate

Record device model, OS/build, jailbreak/rootless state, architecture, Frida client/server pair, transport, spawn/attach mode, and app hash. Prefer spawn-first when initialization matters. Hooks must identify module plus offset or exact selector/overload.

## Signing and injection

For patched/gadget builds, preserve the original and record new signer, provisioning profile, entitlements, embedded dylibs, load-command changes, and hash. Never imply the resigned build is equivalent to the store artifact.

## Pinning, jailbreak, and anti-debug

Map the evidence source and reaction independently. Observe trust callbacks, SecTrust evaluation, NSURLSession delegates, `ptrace`/`sysctl`, filesystem/process checks, and dyld image scans as actually used by the target. Generic scripts are candidates only; bind neutralization to the observed build.

## Output

Preserve static inventory, exact hooks, captures, signer deltas, failed attempts, and unknowns outside this skill repository.
