# Frida Gadget injection workflow

## Preflight

Start from the complete authenticated APK set. Record package/version, every APK hash and signer,
ABI coverage, Android version, kernel page size, manifest native-library extraction policy, and the
Frida client/Gadget/bridge versions. Obtain Gadget separately from its authoritative release,
verify its digest and license, and keep it outside the repository.

A new analysis signer cannot update a store-signed installation. Use an approved test profile or
device; never remove the original installation without explicit approval.

## Select one load vector

Prefer the smallest boundary whose execution can be proven:

1. **Direct Java load:** insert one `System.loadLibrary` call into an early, evidenced lifecycle
   method. Reassemble only the owning DEX and verify register types by decoding the result again.
2. **Native dependency:** add one `DT_NEEDED` dependency to a library already loaded on the target
   path. Record the ELF mutation and verify its dynamic table after writing.
3. **Reviewed automation:** an external repacker is acceptable only when its exact mutations,
   version, license, and output can be inspected.

Both DEX and ELF mutation may trigger integrity controls. Do not choose a path merely because it
starts earlier, and do not patch checksums, stored verdicts, or reaction handlers to make it pass.

## Package invariants

Place Gadget and its configuration in the ABI directory owned by the selected APK or split. The
configuration filename derives from the library basename: a library named `libNAME.so` uses
`libNAME.config.so`.

When native extraction is disabled, native entries must remain uncompressed and aligned for the
target's supported page size. Use a current, pinned Android build-tools release and verify rather
than infer:

```bash
zipalign -P PAGE_KIB -f -v 4 input.apk aligned.apk
zipalign -c -P PAGE_KIB -v 4 aligned.apk
apksigner verify --verbose --print-certs signed.apk
```

Replace `PAGE_KIB` with an observed supported value. Preserve compression for unchanged entries.
Sign every APK in an install set with the same analysis key and inspect each signer result.

Use a minimal Gadget configuration. Choose `on_load` deliberately: waiting blocks application
startup until a client connects, while resuming may miss an early hook. Bind the listener to an
approved local transport and fail on port conflicts. Do not embed credentials or target data.

## Required controls

Build and exercise under the same device state:

- **Control A:** original APK set signed with the analysis key, no repack mutation beyond signing.
- **Control B:** unchanged payload repacked through the candidate ZIP/alignment pipeline.
- **Candidate:** identical pipeline plus the single Gadget load mutation and Gadget files.

If A fails, signer/device compatibility is unresolved. If B fails, packaging is unresolved. Only a
candidate-specific difference can be attributed to the Gadget delta, and protection behavior may
still require independent evidence.

## Runtime proof and cleanup

Prove all three layers:

1. process logs or mappings show the expected Gadget library loaded;
2. the version-matched client attaches through the intended forwarded endpoint;
3. a narrow telemetry hook observes a deliberately triggered, in-scope call while preserving the
   original result.

Record crashes, tombstones, startup state, and the first differing event against controls. Remove
forwarding, temporary device files, and the analysis build when required; then cold-start the clean
application state and record whether cleanup succeeded.
