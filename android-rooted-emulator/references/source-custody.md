# External source custody

This skill vendors no third-party code, binaries, kernels, system images, root managers, or modules.
Acquire them from upstream for each authorized lab, verify hashes, and keep them outside the skill.

## Pinned evidence-backed references

| Component | Upstream and immutable revision | License | Local-change / redistribution note |
|---|---|---|---|
| KernelPatch | https://github.com/bmax121/KernelPatch/tree/0.13.9 — commit `b51197aaba8f2272dd8a3e30c85698a29aa928c9` | GPL-2.0 | No source or binary copied. A locally patched stock kernel is an engagement artifact; retain source/offers and notices if redistributed. |
| APatch | https://github.com/bmax121/APatch/tree/11224 — commit `9a63e0f31b5b3800b5232bce8e3ff975853d0044` | GPL-3.0 | No APK, tool, image, or source copied. Use official releases and preserve notices/source obligations if redistributed. |
| Android Emulator CLI | https://developer.android.com/studio/run/emulator-commandline | Android documentation content license; SDK components carry their own terms | Live operational reference, not copied. Pin the installed SDK package revision and `emulator -version` in the lab manifest because the page is mutable. |

The pinned KernelPatch/APatch pair is a reproducible compatibility reference, not a recommendation
to ignore later security fixes. A later release requires a new revision, license, hash, tool-help
capture, boot negative fixture, and manager/module compatibility proof.

## Acquisition record

For every external artifact record:

- canonical URL and release/tag/commit;
- download time and SHA-256;
- signer or release-attestation result when available;
- detected license and retained notice location;
- exact file selected for host and target ABI;
- local transformations and parent/child hashes;
- whether redistribution is permitted and which source/notice obligations apply.

Unknown license, unverifiable origin, or missing revision blocks copying and redistribution. Never
publish Google system images, patched kernels, APatch APKs, root modules, or engagement AVD images
through this repository.
