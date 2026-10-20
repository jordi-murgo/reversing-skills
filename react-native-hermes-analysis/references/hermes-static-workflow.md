# Hermes static workflow

## Identify the artifact before decoding

Inventory every APK in the split set. Record the SHA-256 and ZIP entry metadata for candidate
bundles such as `assets/index.android.bundle`, then inventory ABI-specific React Native and
Hermes libraries. A large bundle plus a Hermes runtime supports the classification; one filename
alone does not. Plain JavaScript, Hermes bytecode, and other engine formats require different
paths.

Read available application and Expo metadata first. Configuration may establish runtime family,
update policy, intent filters, plugin names, and public service origins without decoding bytecode.
Treat endpoints and identifiers as evidence: retain raw values outside VCS and publish only the
minimum scoped structure.

## Decoder gate

Determine the Hermes bytecode version from the bundle header or a parser that reports it without
executing the bundle. Record:

- bundle hash and size;
- bytecode magic and version;
- decoder name, immutable version, source URL, and license;
- exact command and exit status.

Use a decoder only when it explicitly supports the observed version. A partial or warning-bearing
decode is not authoritative. Preserve its diagnostics and compare reported strings or constants
against the original bundle. If no compatible decoder exists, use bounded raw-string extraction
and report control flow as unknown.

## Extraction order

Work from cheap stable anchors toward reconstructed control flow:

1. **Metadata:** application configuration, update metadata, manifest entries, and bundle identity.
2. **Raw literals:** route-like paths, localization keys, URI schemes, storage-key names, and public API path shapes.
3. **Routes:** corroborate file-like route literals with the router table or module that consumes them.
4. **Localization:** identify namespace and locale boundaries before extracting key/value structure. Do not publish complete translation corpora.
5. **Design tokens:** associate colors, spacing, typography, or theme names with the object or getter that exports them; nearby literals alone are weak evidence.
6. **API surface:** trace a path literal to request construction and record method, parameter names, and response shape. Do not call the service.
7. **State and access checks:** distinguish presentation state from server-enforced authorization. A client-side branch does not prove backend behavior.

Hermes decompilers often emit state-machine control flow and synthetic variable names. Search by a
stable literal, then inspect a bounded use context. Do not read a massive generated file as if it
were original source, and do not assign original module names without metadata evidence.

## Corroboration

For each finding retain at least two compatible anchors where available:

- raw bundle offset or string-table identity;
- decoded module/function location;
- metadata or manifest entry;
- call/use context;
- corresponding native bridge registration.

Label a single-literal conclusion as inference. Hash structured extracts such as route or token
inventories, but keep those derived files outside the skill repository. Runtime confirmation is a
separate authorized activity and must not be implied by static reconstruction.
