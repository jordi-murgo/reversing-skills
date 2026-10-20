# AGENTS.md — conventions for `reversing-skills`

This repository is the upstream source of truth for reusable reverse-engineering skills.
Consuming projects receive copies and may carry project-only adaptations.

## Layout

- One skill per root directory: `<skill>/SKILL.md` plus its own `scripts/`, `references/`,
  `assets/`, and optional `tests/`.
- A copied skill must remain functional. Do not import helpers from another skill directory.
- Cross-skill routing names the other skill; local Markdown links point only inside the
  current skill.
- Root `tests/` verifies repository contracts and consumer-visible helper behavior.

## Skill contract

Every `SKILL.md` uses this order:

1. frontmatter;
2. Activation Contract;
3. Hard Rules;
4. Decision Gates;
5. Execution Steps;
6. Output Contract;
7. References.

Frontmatter requires `name`, a quoted one-line trigger-first `description`, `license`,
`metadata.author`, and `metadata.version`. Keep the body below 1000 tokens; move detail to
local supporting files.

## Hard rules

1. Require written authorization and an in-scope artifact before bypass, instrumentation,
   dumping, credential-flow analysis, or device modification.
2. Never commit target APKs, APKS/XAPK/APKM archives, DEX/SO dumps, captures, credentials,
   tokens, customer data, screenshots, or client identifiers.
3. Keep generic skills generic. Package names, endpoints, hostnames, ports, device serials,
   client versions, and lab paths are parameters or examples, never hidden constants.
4. Record artifact hashes, signer identity, tool versions, commands, failed approaches, and
   residual unknowns. Mark inference explicitly.
5. Avoid reaction-layer tampering in protected applications. Observe first; neutralize the
   evidence source rather than checksums, verdict storage, or reaction sinks.
6. Scripts must fail loudly on missing tools, invalid inputs, unsafe archive paths, version
   mismatch, and existing output destinations. No silent auto-installation.
7. Python helpers use the standard library unless the skill names and justifies a dependency.
8. Shell helpers use `set -euo pipefail`, quote paths, default to non-destructive behavior,
   and expose destructive operations explicitly.
9. External material needs URL, immutable revision, license, notices, and local-change notes.
   Unknown license blocks copying and redistribution.
10. A verification gate must be shown failing on a negative fixture before it is trusted.

## Verification

Run the repository suite after any behavior change:

```bash
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

For changed runtime helpers, also exercise the actual CLI path or an isolated command shim
that captures consumer-visible arguments. Syntax checks alone do not prove behavior.

## Upstreaming from an engagement

- Remove client paths, identities, secrets, and version assumptions.
- Preserve only evidence-backed general rules.
- Replace copied snippets with clean-room implementations or complete license custody.
- Add a regression test for the failure that motivated the upstream change.
- Keep project evidence in the project; this repository stores reusable procedure only.
