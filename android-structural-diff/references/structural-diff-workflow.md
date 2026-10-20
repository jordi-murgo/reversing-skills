# Structural Android diff workflow

## External dependency boundary

Twinflame is a beta DEX structural differ that accepts APKs, individual DEX files, DEX dump
directories, or prepared records. It can localize class/method changes despite name-only
R8/ProGuard churn. It does not compare native code, and structural matches remain candidates.

Validated adoption pin:

- package: `twinflame==0.5.0b2`;
- upstream commit: `34d32d54058bf2518e87d1b1dbad4630e06a672a`;
- Python: 3.11 or newer.

Use it as an isolated external dependency. The repository and package metadata declare MIT,
but the pinned repository has no `LICENSE` file. Do not copy its source, tests, prose, or assets
into a skill. Reassess rights before changing this boundary.

An operator may create an isolated environment explicitly; skills never install it silently:

```bash
python3 -m venv /tmp/android-structural-diff
/tmp/android-structural-diff/bin/pip install --pre 'twinflame==0.5.0b2'
/tmp/android-structural-diff/bin/python -m pip show twinflame
```

## Scalable comparison

Prepare each authenticated side independently:

```bash
twinflame prepare old.apk -o evidence/old.tfr
twinflame prepare new.apk -o evidence/new.tfr
sha256sum evidence/old.tfr evidence/new.tfr
```

For large applications, compare records rather than two raw APKs. Direct raw comparison loads
both corpora and can exhaust memory. Keep records next to engagement evidence, never in the
skill repository.

Then scope and preserve a machine report:

```bash
twinflame evidence/old.tfr evidence/new.tfr \
  --app-package com.example.authorized \
  --threshold 0.8 \
  --find-obfuscated \
  -s changed \
  -o evidence/changes.json
```

Confirm the exact options against the pinned CLI help. Record stderr timings, report schema,
class counts, matching threshold, candidate-neighbour setting, worker count, anchors, and
normalization state. Do not compare counts produced under different option sets as if they were
one experiment.

## Interpretation

Prioritize application-origin, anchored, high-confidence, method-localized changes. Reconcile
each important pair against original DEX/class descriptors, decompiler output, calls, strings,
and observed behavior. Added/removed volume under heavy obfuscation contains both real change
and pairing failure.

Known boundaries:

- trivial or identical-structure classes can collide;
- approximate candidate search can omit a valid pair;
- inlining, outlining, and class merging break the assumed one-to-one correspondence;
- native/JNI implementation changes are invisible;
- packed payloads must be recovered first;
- corrupt DEX skipped by a loader reduces coverage and must remain explicit.

Changing thresholds can explore uncertainty; it cannot turn a weak match into proof.

## Known-library suppression at scale

`twinflame_libsigs` is valuable when comparing malware families, repackaged applications, or
large corpora where common SDK/runtime code dominates similarity. Its signature pack labels DEX
classes belonging to known Maven/Google-Maven libraries. Twinflame can then demote third-party
churn in version reports and exclude known-library classes from malware-family containment
scores, preventing a shared runtime from inflating family similarity.

Use this lane when repeated corpus work shows measurable library noise; it is optional for a
one-off red-team APK comparison. A library label is not a deletion rule:

- preserve every labeled class and the pack decision that produced the label;
- retain modified, injected, outdated, or repackaged library copies as findings;
- compare label coverage across samples and versions;
- never suppress app-owned classes solely because their package resembles a library prefix;
- reconcile high-value labels against descriptor, bytecode, package provenance, and manifest.

Packs are version-coupled to Twinflame's signature stamp. Record the pack hash, sidecar hash,
build timestamp, coordinate/version coverage, minimum instruction threshold, signature stamp,
tool version, and whether the native or brute-force query backend was used. A stale or mismatched
pack must fail closed rather than silently relabeling classes.

At the pinned revision, the source, native component, and released pack do not yet carry a public
license file. Use them locally as an external dependency; do not vendor or redistribute source,
binaries, or packs until upstream publishes the license. Engagement- or sample-derived packs
remain sensitive evidence regardless of the software license.

## Name propagation

A cross-version mapping is viable only when the donor build retained useful `SourceFile`
metadata. Check that precondition before generating a map. The output follows ProGuard mapping
direction; verify whether the decompiler requires inversion. Confirm at least one known class
changed name after import. A silently unchanged decompiler tree means the mapping was not proven.

## Related anKorio candidates

- `twinflame_libsigs` is the optional known-library suppression lane for malware/corpus-scale
  comparison. It reduces shared-library noise without authorizing deletion of labeled classes.
  Pin pack provenance and signature compatibility; keep its pending public-license boundary.
- `jadx-twinflame-sigdb` is an Apache-2.0 external jadx plugin for curated team signature packs.
  It is prerelease software and depends on Twinflame plus the license-publication-pending
  libsigs component.
  Evaluate it as an optional external UI boundary, never as authoritative classification.

## Primary evidence

- Twinflame pinned README and metadata:
  <https://github.com/ankorio/twinflame/tree/34d32d54058bf2518e87d1b1dbad4630e06a672a>
- PyPI 0.5.0b2 metadata: <https://pypi.org/project/twinflame/0.5.0b2/>
- Libsigs pinned source: <https://github.com/ankorio/twinflame_libsigs/tree/5b808b8a0dfecb1b838a7e6c02c8b432bc7a0037>
- jadx plugin pinned source and Apache license:
  <https://github.com/ankorio/jadx-twinflame-sigdb/tree/9e38d2ae1efbbab700a47ed940d06212cc51b540>
