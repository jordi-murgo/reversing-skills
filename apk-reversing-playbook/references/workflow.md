# Android APK reversing workflow

## Provenance first

```bash
sha256sum app.apk
apksigner verify --verbose --print-certs app.apk
unzip -Z1 app.apk | grep -E '^(classes.*\.dex|lib/.*\.so)$'
```

Use `android-apk-intake` for archives, split directories, and installed packages. An
identical signer across every known split supports one installation; an unavailable signer
is unknown, not consistent.

## Manifest and resources

Record package, version, SDK levels, components, exported surfaces, permissions,
`debuggable`, `allowBackup`, network-security config, and native ABI declarations. Resolve
obfuscated resources through `resources.arsc`:

```bash
aapt2 dump resources app.apk
aapt2 dump badging app.apk
```

Cross-check logical resource IDs against generated `R` classes. Do not infer certificate
identity from an obfuscated `res/raw` filename.

## Decode without losing DEX identity

```bash
bash scripts/decode.sh app.apk --out analysis --name build-a
```

On full-APK jadx failure, the helper preserves partial output and decompiles each
`classes*.dex` into `jadx-dex/classesN/`. Do not merge these trees: duplicate relative class
paths can exist and copy-without-overwrite silently discards evidence.

Search for trust providers, pin validators, crypto entry points, dynamic loaders, JNI
registrations, root/emulator/debugger checks, integrity callbacks, and reaction collectors.
Tie findings to DEX and class/method identity.

## Native lane

Use `android-packed-native` when a library has a rotating name, canonical SONAME,
`JNI_OnLoad`, unpacker imports, high-entropy windows, or implausible disassembly. Require
multiple signals. Shared-library entry point zero is weak by itself.

## Dynamic lane

Use `android-frida-runtime` after static mapping. Instrument the narrowest observed API;
do not start with a universal bypass. For GuardIT evidence, load `arxan-guardit-android`
before changing callbacks or integrity state.

## Cross-version diff

- Authenticate both artifact sets before comparing.
- Separate application packages from third-party library churn.
- Prepare reusable structural records once for very large builds.
- Compare manifest, permissions, DEX/resource/native inventory, trust architecture, JNI
  surface, and runtime behavior.
- Reconcile automated matches against original files or symbols; similarity is a candidate.

## Rebuild/sign

```bash
bash scripts/rebuild-sign-install.sh decoded/apktool \
  --keystore /path/to/analysis.jks \
  --zipalign /path/to/zipalign \
  --apksigner /path/to/apksigner
```

A new signer cannot replace a store-signed installation with `adb install -r`. Use a
separate authorized test profile/device. Split applications require a complete compatible
set and `adb install-multiple`; rebuilding one base APK does not produce that set.

## Reporting

Return authorization reference; artifact hashes/signers/versions; exact tool versions and
commands; findings tied to files/symbols/addresses/events; failed approaches; explicit
`[INFERENCE]`; residual unknowns; and external evidence paths. Never commit target bytes.
