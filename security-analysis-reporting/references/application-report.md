# Application report guidance

Use `assets/application-report-template.md` for Android, iOS, desktop, or embedded applications.
The primary report remains the source of product context even when a malware companion exists.

## Scope and identity

Record package or bundle identifier, marketing and build versions, distribution channel, signer,
artifact hash, architecture, and assessed backend/environment. For split or multi-package apps,
identify every artifact needed to reproduce the installed application.

## Application evidence

Document components, permissions or entitlements, exposed entry points, trust boundaries, storage,
networking, crypto/key ownership, native loaders, and update behavior only to the depth relevant to
findings. Bind runtime evidence to the exact app build, OS, device, instrumentation version, and
launch mode. Preserve lineage and signer/entitlement deltas for modified builds.

For each finding, identify:

- containing package, framework, library, or native image;
- trigger such as launch, push, deep link, WebView navigation, IPC, or native loader;
- attacker/user prerequisites and reachable data or privileges;
- affected versions and channels, plus evidence for version boundaries;
- whether behavior belongs to first-party code, an SDK, administration functionality, or an
  unresolved third-party component.

## Malware routing

One suspicious string, endpoint, certificate, packed library, or anti-analysis behavior remains a
main-report finding or triage note. Create a malware triage companion only when related evidence
supports a payload, configuration, delivery path, or coherent capability set. Use the full malware
report only for observed malicious execution, persistence, C2, exfiltration, or equivalent behavior.

The primary report must still state where the component resides, how it activates, which versions
are affected, what product data or privileges it can reach, and the companion report identifier.
Never convert SDK risk, dual-use administration behavior, or policy violations into a malware claim
without evidence that excludes those alternatives.
