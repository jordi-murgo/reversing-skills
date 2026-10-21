---
name: android-rooted-emulator
description: "Trigger: rooted AVD, APatch, KernelPatch, custom emulator kernel, root hiding. Build an authorized reproducible Android instrumentation lab."
license: MIT
metadata:
  author: reversing-skills
  version: "1.0.0"
---

# Android rooted emulator lab

## Activation Contract

Load when an authorized Android assessment needs a rooted emulator, a patched stock AVD kernel,
or cause-level concealment of evidenced root/emulator signals. Require written device-modification
and instrumentation authorization plus an in-scope app artifact.

## Hard Rules

- Modify only a disposable AVD copy; preserve a cold-boot stock baseline and recovery path.
- Never commit system images, kernels, ramdisks, root managers/modules, APKs, captures, or secrets.
- Pin and hash the emulator, system image, patch tools, manager, kernel, ramdisk, and outputs.
- Match target ABI, host acceleration, kernel release, KMI, vermagic, and patch-tool revisions.
- Patch the exact stock AVD kernel before considering a replacement build; KMI labels alone are insufficient.
- Observe the evidence source first. Never patch checksums, verdict state, callbacks, or reaction sinks.
- Reject catch-all hiding and global syscall hooks; scope kernel mediation to the target and observed source.
- Keep SELinux enforcing unless a separately approved experiment requires otherwise; record every change.
- Prove each gate on an unmodified negative fixture before trusting the modified lab.

## Decision Gates

| Situation | Action |
|---|---|
| AOSP/Google APIs userdebug image and basic root is enough | Try `adb root`; stop if it satisfies the experiment |
| Google Play/production image blocks root | Select an authorized non-Play image or use a derived custom-root route |
| Target native ABI cannot execute on the system image/host | Stop; choose a matching image and host |
| Persistent root or a module framework is required | Derive a separate kernel/ramdisk from the exact system image |
| Replacement kernel changes KMI or module vermagic | Reject it; patch the stock kernel instead |
| Signal is visible through Java, properties, or libc | Use the narrowest app/runtime observation first |
| Direct property-area or `/proc` syscall evidence is proven | Consider scoped root-framework or kernel mediation after approval |
| Hardware-backed attestation is required | Use authorized hardware; an AVD cannot prove equivalent trust |
| Frida transport and hooks are next | Load `android-frida-runtime` after the lab baseline passes |

## Execution Steps

1. Complete `assets/lab-manifest.md` with authorization, artifact, host, SDK, image, ABI, and hashes.
2. Create separate baseline and lab AVDs from one pinned system image; disable snapshot load/save.
3. Cold-boot the baseline, capture boot/root/detection evidence, and prove the negative fixture.
4. Choose the least invasive root route in `references/lab-workflow.md`.
5. If needed, patch a copied stock kernel with a version-matched tool/image pair; preserve its wrapper.
6. Boot the lab with explicit overrides; verify boot completion, root context, SELinux, modules, and stability.
7. Classify each detection source with `references/kernel-and-hiding.md`; change one cause per run.
8. Compare baseline versus lab, run the expected app path, capture failures, then restore or destroy the copy.

## Output Contract

Return authorization and scope, completed lab manifest, stock-to-derived lineage and hashes, exact
commands/tool revisions, baseline and modified boot evidence, root/SELinux state, each observed
signal and scoped response, application-path proof, system-health controls, failures, cleanup, and
residual unknowns.

## References

- `references/lab-workflow.md` — image selection, baseline, stock-kernel patching, boot, and handoff.
- `references/kernel-and-hiding.md` — evidence-source classification and safe kernel escalation.
- `references/source-custody.md` — pinned upstream revisions, licenses, and redistribution boundary.
- `assets/lab-manifest.md` — reproducibility, lineage, authorization, and verification record.
