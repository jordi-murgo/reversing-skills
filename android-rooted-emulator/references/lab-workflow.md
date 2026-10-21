# Rooted AVD lab workflow

This procedure creates evidence, not a universal bypass. Replace placeholders locally and keep
artifacts outside the skill directory.

## 1. Authorization and image selection

Record written authorization for AVD modification, root, instrumentation, and any concealment.
Identify the exact app set, signer, hashes, package, supported ABI, minimum API, and native-library
requirements before downloading an image.

Prefer an AOSP or Google APIs system image when `adb root` is sufficient. Google Play images are
production-like and commonly reject it. Verify the selected image rather than relying on the label.
The image ABI must execute every required native library; host acceleration does not imply foreign-
ABI translation.

Create two AVDs from one pinned package: an untouched baseline and a disposable lab. Do not mutate
the SDK's shared system-image directory.

```bash
sdkmanager "system-images;android-<api>;<variant>;<abi>"
avdmanager create avd --name <baseline-avd> \
  --package "system-images;android-<api>;<variant>;<abi>" --device <device-id>
avdmanager create avd --name <lab-avd> \
  --package "system-images;android-<api>;<variant>;<abi>" --device <device-id>
```

Record `emulator -version`, SDK package revision, host architecture/hypervisor, AVD config, and
SHA-256 for `kernel-ranchu`, `ramdisk.img`, and the app artifacts. Discover the actual system
directory with an emulator verbose boot; do not guess it.

## 2. Prove the stock baseline

Cold-boot without loading or saving snapshots:

```bash
emulator -avd <baseline-avd> -no-snapshot -show-kernel
adb -s <serial> wait-for-device
adb -s <serial> shell getprop sys.boot_completed
adb -s <serial> root
```

Record whether `adb root` succeeds, `id`, `uname -a`, SELinux state, boot properties, package state,
and the target's observed root/emulator verdict or expected failure. The unmodified run is the
negative fixture. App failure alone is not a verdict: capture the responsible call, callback, path,
property, syscall, or reaction timing.

If `adb root` provides the required file/process access, use it and stop. A custom root stack adds
state and detection surface.

## 3. Derive a patched stock kernel only when required

Use this route for persistent root, a root-module framework, or an evidenced source below app-level
mediation. Work on copied files in an engagement evidence directory.

1. Identify compression/wrapper with a file-format tool; hash and preserve the original.
2. Acquire KernelPatch and APatch only from pinned upstream revisions in `source-custody.md`.
3. Verify downloaded hashes. Select `kptools` and `kpimg` from one compatible release pair; mixed
   revisions can patch successfully yet fail at manager or module load.
4. Ensure the patch tool can execute on the host. Decompress only when required by that exact
   version, patch to a new filename, then restore the original wrapper deterministically.
5. Never overwrite `kernel-ranchu`, reuse a secret in commands, or trust a prebuilt patched kernel.

For the pinned compatibility example, the clean-room command shape is:

```bash
<kptools> -p -i <stock-kernel-raw> -k <matching-kpimg> -o <patched-kernel-raw>
```

Tool flags are versioned interfaces: inspect the pinned tool's help before use and record it. Some
AVD kernels are gzip-wrapped; if so, deterministic recompression is `gzip -9 -n`. Confirm the result
has the same outer format as stock.

## 4. Boot and initialize the lab

```bash
emulator -avd <lab-avd> -no-snapshot -kernel <patched-kernel> -show-kernel
adb -s <serial> wait-for-device
adb -s <serial> shell getprop sys.boot_completed
```

Add `-writable-system` only when the approved experiment requires system mutation. Do not add
read-only instance flags when persistence is required. Install the hash-verified manager artifact,
initialize root interactively so secrets do not enter shell history/process arguments, and verify:

```bash
adb -s <serial> shell su 0 id
adb -s <serial> shell getenforce
adb -s <serial> shell uname -a
```

A successful `su` is not enough. Require completed boot, stable System UI, expected vendor modules,
no new kernel/module errors, and a clean reboot. KMI generation or `module_layout` disagreement is a
hard rejection; return to the copied stock kernel.

## 5. Detection work and Frida handoff

Use `kernel-and-hiding.md` to classify the exact evidence source. Change one cause per cold boot,
repeat the same target path, and retain baseline/modified logs. Do not globally rewrite an emulator
identity: inconsistent properties, files, mounts, and hardware behavior create stronger signals.

After lab controls pass, load `android-frida-runtime` for exact-version server/client/bridge setup,
spawn-first launch, and capture. Root, emulator concealment, Frida concealment, TLS trust, and app
integrity are independent gates.

## 6. Recovery and custody

Stop the AVD before copying data. Keep stock and derived hashes, boot arguments, manager/module
state, evidence paths, and restore instructions. Never distribute the AVD data image: it may contain
apps, tokens, identifiers, or captures. Destroy the disposable copy or restore from the recorded
clean baseline after the engagement.
