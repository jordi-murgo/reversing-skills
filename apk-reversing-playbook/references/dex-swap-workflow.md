# DEX-only replacement workflow

## When to use it

Use DEX-only replacement when an authorized smali change is ready but rebuilding the full apktool
tree fails in resources or manifest linking. This path preserves the original APK container and
replaces exactly one root `classes*.dex` entry. It does not bypass integrity controls and does not
produce a signed artifact.

Do not use it when resources, the manifest, native libraries, or split metadata must change. Start
from a complete artifact set produced by `android-apk-intake`; identify which APK and DEX own the
class rather than assuming `base.apk` or `classes.dex`.

## Assemble and replace

Assemble only the owning smali tree with a pinned smali tool, then run:

```bash
python3 scripts/dex-swap-repack.py original.apk classes2-patched.dex \
  --dex-entry classes2.dex \
  --output work/base-dex-swapped-unsigned.apk \
  --authorization-ref ROE-REFERENCE
```

The helper rejects symlinked inputs, existing outputs, unsafe or duplicate ZIP members, unsupported
compression, archive entry/size/ratio budget violations, a missing target entry, and malformed DEX
headers. Explicit `--max-*` flags can widen budgets for an evidenced large artifact. It streams
unchanged members, preserves their ZIP metadata and ordering, and preserves the target entry's
original stored/deflated policy. The original APK is opened read-only. Rewriting invalidates
existing signatures; the JSON result therefore always reports signing as required.

Run current pinned Android build-tools after replacement:

1. align the unsigned APK for the approved target;
2. sign it with an analysis key kept outside VCS;
3. verify alignment, signing schemes, signer digest, ZIP integrity, and the replaced DEX hash;
4. for a split application, sign and install one complete compatible set with the same key.

Never silently uninstall a store-signed application. Use a separate authorized profile/device.

## Attribution controls

Build three variants from the same artifact set and exercise the same launch path:

- **Control A:** original payload, re-signed only;
- **Control B:** original DEX passed through the same repack/alignment/signing pipeline;
- **Candidate:** replacement DEX through that identical pipeline.

If A fails, signer/device compatibility is unresolved. If B fails, packaging is unresolved. Only a
candidate-specific difference supports attribution to the DEX change. A protection reaction still
requires cause-level observation; do not patch checksums, verdict storage, or reaction sinks merely
to make the candidate start.

Record every input/output hash, tool version, exact command, compression policy, signer digest,
control result, crash/tombstone, failed attempt, and residual unknown. Keep all APKs, DEX files,
signing material, and device evidence outside the repository.
