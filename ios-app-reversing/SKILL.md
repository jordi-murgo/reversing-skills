---
name: ios-app-reversing
description: "Trigger: iOS IPA, Mach-O app, Objective-C runtime, Swift symbols, jailbreak detection. Analyze authorized iOS applications."
license: MIT
metadata:
  author: reversing-skills
  version: "1.0.0"
---

# iOS application reverse engineering

## Activation Contract

Load for an authorized IPA, decrypted app bundle, or installed iOS application. Require written scope and signer/artifact identity before decryption, resigning, device instrumentation, keychain access, or traffic capture.

## Hard Rules

- Never redistribute decrypted App Store binaries, provisioning profiles, credentials, keychain data, or captures.
- Record IPA/Mach-O hashes, bundle ID, signer/team, architecture, encryption state, device build, and tool versions.
- Prefer static analysis before device changes or runtime hooks.
- Bind Objective-C selectors, Swift symbols, offsets, and hooks to the exact build and architecture.
- Observe jailbreak/pinning evidence sources before considering bypass; never call a generic script universal.
- Resign and install only copies on an approved device; report entitlement changes.

## Decision Gates

| Evidence | Action |
|---|---|
| Mach-O still encrypted | Acquire an authorized decrypted copy; do not infer code bytes |
| Objective-C metadata present | Map classes, selectors, protocols, and xrefs |
| Swift-heavy binary | Demangle symbols and inspect metadata/witness tables |
| Native-only path | Use Mach-O disassembly and dyld/import evidence |
| Runtime-only secret/config | Hook the narrowest observed API after static mapping |
| Pinning/jailbreak reaction | Map detection source and reaction separately |

## Execution Steps

1. Inventory bundle, plist, entitlements, embedded frameworks, URL schemes, ATS, and signatures.
2. Inspect Mach-O load commands, segments, imports, ObjC/Swift metadata, strings, and symbols.
3. Map entry/delegate/scene flows and sensitive storage/network/crypto boundaries.
4. Prepare an approved device and exact-version Frida pair only if runtime evidence is needed.
5. Instrument observed selectors/functions; capture arguments, returns, addresses, and timestamps.
6. Preserve signer/entitlement deltas for every patched or gadget-injected build.

## Output Contract

Return artifact/signer identity, bundle/entitlement inventory, static map, exact hooks, device/tool versions, runtime evidence, modified-build lineage, failures, and unknowns.

## References

- `references/ios-workflow.md` — IPA intake, Mach-O/ObjC/Swift analysis, signing, and runtime gates.
