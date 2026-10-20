# AndroidKeyStore and KeyMint analysis workflow

## Security model

AndroidKeyStore keys belong to an Android UID namespace. Package names are not the isolation
primitive: packages sharing a UID can share the namespace. A normal adb shell has the shell UID
and cannot enumerate an application's aliases. A rooted probe can execute under an approved app
UID and ask the AndroidKeyStore provider for aliases and metadata.

Hardware-backed private or secret keys normally remain non-exportable. Successful signing,
encryption, decryption, verification, or MAC proves that the provider allowed an operation; it
does not prove extraction of key material. Certificates and attestation chains contain public
data and claims that still require chain and challenge validation.

## Preflight

Record:

- authorization reference and approved package/UID list;
- device serial, build fingerprint, Android/security-patch version, user/profile, and root method;
- APK hash, package/version, install source, and package-to-UID mapping;
- every in-scope package sharing the UID;
- probe source revision and digest of every host/device artifact;
- whether the test permits metadata enumeration only or also local key operations.

Never default to scanning every UID. A device-wide scan crosses application boundaries and needs
explicit scope.

## Metadata interpretation

Capture per alias when exposed:

- entry kind, algorithm, key size, origin, purposes;
- block modes, encryption/signature paddings, and digests;
- software, TEE, StrongBox, or unknown security level;
- user-authentication requirement, validity window/type, enrollment invalidation, trusted
  presence/confirmation requirements;
- key validity intervals and remaining usage count;
- public-key algorithm/size and public certificate chain facts.

Unavailable metadata can mean API-level/provider differences, key type, authorization state, or
probe failure. Preserve it as unknown instead of filling defaults.

## Operation gate

Operations are not read-only. A key can require an unlocked/authenticated user, enforce a limited
usage count, produce audit-visible activity, or be tied to an application protocol. Before an
operation:

1. review purposes, auth binding, and remaining usage;
2. obtain operation-specific authorization;
3. use an offline, analyst-created input with no production meaning;
4. derive or explicitly record transform, digest, padding, IV, AAD, and tag length;
5. keep output local and never replay it to an application backend;
6. re-enumerate relevant metadata only if checking usage side effects is approved.

An auth-bound failure is evidence of policy enforcement, not a reason to bypass user presence.

## External candidate: keystore-oracle

`ankorio/keystore-oracle` provides per-UID alias/metadata enumeration and bounded provider
operations by staging a probe DEX and launching it under an authorized UID through root. Adopt it
only as an external, pinned dependency:

- commit: `11570d6d559cb7fff92fa21157588d866633c28e`;
- declared and in-tree license: MIT, copyright 2026 ankorio;
- runtime status: proof of concept, one commit, no release, no PyPI package;
- prerequisites: Python 3.9+, adb, rooted device;
- boundary: do not copy its prebuilt DEX into this repository; review the pinned checkout and
  hash the actual probe used for each engagement.

Its reports are client/device evidence and stay outside VCS. A successful operation uses the key
inside AndroidKeyStore; it does not export the key. An unrooted device cannot use its UID
impersonation path.

Primary evidence:

- pinned source and README:
  <https://github.com/ankorio/keystore-oracle/tree/11570d6d559cb7fff92fa21157588d866633c28e>
- pinned MIT license:
  <https://raw.githubusercontent.com/ankorio/keystore-oracle/11570d6d559cb7fff92fa21157588d866633c28e/LICENSE>

## Cleanup and proof

Remove staged probe/spec/input files from the device, preserve only the authorized external
report, and record cleanup success. A complete result binds every alias observation to package,
UID, Android user, device build, probe digest, timestamp, and metadata/operation mode. Missing
that binding makes cross-device or cross-user conclusions invalid.
