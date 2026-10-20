# reversing-skills

Evidence-first reverse-engineering skills for coding agents. The initial release focuses on
Android APK sets, packed native libraries, Frida runtime instrumentation, and authorized
Arxan/GuardIT analysis.

This repository is the upstream source of truth. Projects install copies into
`.agents/skills/`; reusable improvements return here, while client-specific package names,
hosts, captures, and findings stay in the consuming project.

## Skills

| Skill | Purpose |
|---|---|
| `apk-reversing-playbook` | Route a complete Android reversing engagement and provide OOM-safe decode/rebuild helpers |
| `android-apk-intake` | Inventory APK/APKS/XAPK/APKM files, installed split sets, signatures, ABIs, DEX and evidence manifests |
| `android-packed-native` | Rank packed/encrypted ELF candidates from SONAME, exports, entropy, imports and ARM64 structure |
| `android-structural-diff` | Compare obfuscated APK/DEX versions and malware corpora, with prepared records and known-library noise suppression |
| `android-keystore-analysis` | Map per-UID AndroidKeyStore aliases and KeyMint policy without claiming private-key extraction |
| `android-frida-runtime` | Explain Frida versus Florida, then launch spawn-first with exact-version, bridge, transport and capture gates |
| `arxan-guardit-android` | Map GuardIT callbacks, prove packing, avoid reaction-state traps and recover runtime plaintext safely |

## Design

- One skill per root directory; each copied skill remains functional.
- `SKILL.md` is a short runtime contract. Explanations belong in `references/`; schemas and
  templates belong in `assets/`; executable behavior belongs in `scripts/`.
- Commands produce evidence, not conclusions. Observations, inferences, failed approaches,
  and residual unknowns remain distinct.
- No catch-all bypass kits. Hook the narrowest observed boundary.
- No client artifacts, credentials, captures, proprietary binaries, or PII.
- No reverse engineering without written authorization and an in-scope artifact.

## Layout

```text
reversing-skills/
├── apk-reversing-playbook/
│   ├── SKILL.md
│   ├── references/
│   └── scripts/
├── android-apk-intake/
│   ├── SKILL.md
│   ├── assets/
│   └── scripts/
├── android-packed-native/
│   ├── SKILL.md
│   ├── references/
│   └── scripts/
├── android-structural-diff/
│   ├── SKILL.md
│   └── references/
├── android-keystore-analysis/
│   ├── SKILL.md
│   └── references/
├── android-frida-runtime/
│   ├── SKILL.md
│   ├── references/
│   └── scripts/
├── arxan-guardit-android/
│   ├── SKILL.md
│   ├── assets/
│   └── references/
├── docs/
├── scripts/
│   └── omp-reversing-skills
└── tests/
```

## Install

After publication:

```bash
npx skills add jordi-murgo/reversing-skills
```

Manual installation of selected skills:

```bash
UPSTREAM=/path/to/reversing-skills
PROJECT=/path/to/authorized-project

for skill in android-apk-intake android-packed-native android-frida-runtime \
             arxan-guardit-android apk-reversing-playbook; do
  rm -rf "$PROJECT/.agents/skills/$skill"
  cp -R "$UPSTREAM/$skill" "$PROJECT/.agents/skills/$skill"
done
```

Replace directories rather than overlaying them; overlay updates leave retired scripts and
references behind. Project adaptations must be reviewed before replacement.

## Clean OMP environment

Launch OMP with exactly the root-level skills from this repository:

```bash
./scripts/omp-reversing-skills
```

Launch against a different authorized workspace:

```bash
./scripts/omp-reversing-skills --cwd /path/to/authorized-project
```

The launcher discovers `*/SKILL.md`, builds an exact per-process allowlist, disables every
Claude/Codex/Pi/Agents project and user skill source, and disables extension discovery.
Managed skills are excluded by the same exact allowlist. Adding or removing a root skill
therefore changes the environment without maintaining a second copied skill tree.

The default launch reuses the active OMP profile for authentication and model settings; it
does not alter global configuration. For complete separation of authentication, settings,
sessions, and caches, initialize a named profile once and pass it through:

```bash
omp --profile reversing-skills login
./scripts/omp-reversing-skills --profile reversing-skills \
  --cwd /path/to/authorized-project
```

Check the generated inventory and OMP configuration parser without starting a model session:

```bash
./scripts/omp-reversing-skills --check
```

Project rules remain enabled deliberately: the target workspace's authorization and handling
constraints still apply. The isolation boundary is the skill inventory, not the target's
`AGENTS.md` or equivalent project rules.

## Tools

The skills detect tools but do not silently install them. Typical lanes use:

- Android: `adb`, `aapt2`, `apksigner`, `apktool`, `jadx`, `zipalign`, `unzip`;
- native: `readelf`, `rabin2`/radare2, Ghidra or another AArch64-capable decompiler;
- structural diff: a pinned external Twinflame environment; prepared records and reports stay
  outside the repository;
- keystore: `adb`, authorized root, and an audited per-UID probe such as the pinned
  `keystore-oracle` POC;
- runtime: an exact client/server Frida version pair and, where authorized, an
  anti-detection server;
- capture: a controlled proxy and an analysis-only CA installation.

Use `AAPT2`, `APKSIGNER`, `APKSIGNER_JAR`, `ZIPALIGN`, `ANDROID_HOME`, and
`ANDROID_SDK_ROOT` to select non-PATH Android build tools.

## Verify

```bash
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

The suite checks frontmatter, local references, executable modes, shell/Python syntax,
archive traversal rejection, evidence extraction, packed-native scoring, and the Frida CLI
regressions that previously made the launcher attach by default and pass removed flags.

A gate is trusted only after its negative fixture has failed.

## Contribution boundary

External repositories may be studied, but code, prose, tests, identifiers, or assets are
not copied without an immutable source revision, compatible license, and required notices.
Clean-room implementations record behavior and independently implement it here.

See `AGENTS.md`, `CONTRIBUTING.md`, and `docs/skill-style-guide.md` before changing a skill.
