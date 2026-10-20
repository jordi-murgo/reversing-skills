# Packed Android native workflow

## Establish ownership

Inspect every ABI split and universal-APK `lib/<abi>/` tree. Rank candidates, then confirm:

```bash
python3 scripts/triage-native-libs.py app.apk --output native-triage.json
readelf -d -W candidate.so
readelf --dyn-syms -W candidate.so
readelf -r -W candidate.so
rabin2 -S candidate.so
```

A filename may rotate. Stable evidence includes SONAME, exported JNI surface, imported APIs,
relocations, and the Java/native loading path.

## Prove packing from independent signals

- 4 KiB executable windows near 7.9–8.0 bits/byte;
- very few plausible ARM64 frame prologues;
- exported JNI entry disassembles as implausible instructions;
- cleartext low-entropy executable island among encrypted bytes;
- relocation from `init_array` to that island;
- `mprotect`, `mmap`, `dladdr`, `strtoull`, `sysconf`, `mincore`, `syscall`, or
  `dl_iterate_phdr` imports;
- executable sections disguised as metadata.

Entry point zero is common for ordinary shared libraries and is only a weak corroborating
signal.

## Map the unpacker

1. Locate low-entropy executable windows and plausible prologues.
2. Resolve constructor addresses from relocations rather than section names.
3. Separate PLT/dispatcher thunks from the decrypt loop.
4. Record source/destination range, state inputs, block length, and page permissions.
5. Determine whether key/seed material is file-derived or runtime-derived.

Do not brute-force runtime state without a bounded, evidence-backed hypothesis.

## Runtime plaintext boundary

Observe page permission changes without altering them. After the unpacker finishes writing:

- record process, loaded artifact hash, mapping, address, length, caller, old/new permissions,
  timestamp, and tool versions;
- dump only the affected authorized range;
- hash the dump immediately;
- map runtime addresses back to image-relative offsets;
- disassemble recovered plaintext and reconcile it with JNI/callback behavior.

Readable fragments do not prove complete unpacking. If runtime state or mapping is absent,
stop and report the unknown.
