# Firmware Security Analysis Report

## Document control

| Field | Value |
|---|---|
| Report ID / revision | `<identifier / revision>` |
| Date | `<ISO-8601>` |
| Author / reviewer | `<roles or approved identifiers>` |
| Audience / handling | `<audience / classification>` |
| Authorization reference | `<written authorization reference>` |

## Executive assessment

`<Decision-relevant result, affected models/builds, demonstrated impact, confidence, and most important fidelity or hardware limitation.>`

## Scope and exclusions

- In scope: `<models, boards, firmware builds, interfaces, environments>`
- Out of scope: `<explicit exclusions>`
- Assessment window: `<start/end>`

## Artifact identity and lineage

| Artifact ID | Model/build | Container/partition/path | Parent | Method/offset | SHA-256 | Evidence path |
|---|---|---|---|---|---|---|
| `<FW-ART-01>` | `<identity>` | `<location>` | `<parent or Original>` | `<method>` | `<hash>` | `<sanitized external path>` |

Signatures and update channel: `<signer, verification state, acquisition source>`

## Environment, methods, and fidelity

| Environment/tool | Exact version/build | Purpose | Substitution or fidelity gap |
|---|---|---|---|
| `<item>` | `<version>` | `<purpose>` | `<gap or None>` |

Methods and commands: `<sanitized, reproducible record or evidence-manifest reference>`

## Firmware and attack-surface map

`<Partitions, filesystems, startup path, accounts, services, exposed interfaces, privileges, trust/update boundaries, and hardware dependencies relevant to findings.>`

## Findings summary

| ID | Title | Severity | Confidence | Evidence state | Affected models/builds |
|---|---|---|---|---|---|
| `<FW-01>` | `<title>` | `<level>` | `<level>` | `<Observed/Inferred/Modeled/Unverified>` | `<scope>` |

## Finding `<FW-01>` — `<title>`

- Affected scope: `<models, builds, partitions, services>`
- Summary: `<condition and consequence>`
- Evidence: `<evidence IDs, paths, symbols/addresses/events, timestamps>`
- Trigger, reachability, and privileges: `<path and prerequisites>`
- Persistence: `<reboot/reset/update behavior or Unknown>`
- Technical impact: `<demonstrated behavior>`
- Fleet risk and limiting controls: `<deployment consequence and scope evidence>`
- Safe reproduction: `<authorized procedure or evidence query>`
- Remediation: `<root-cause fix and compensating controls>`
- Fix verification: `<positive and negative checks on exact corrected build/hardware>`
- Alternatives considered: `<benign or competing explanations>`
- Limitations: `<emulation/model/hardware gaps, failures, unknowns>`

## Malware assessment

- State / confidence / date: `<Unknown, Suspicious, Probably malicious, or Confirmed malicious / confidence / date>`
- Supporting and missing evidence: `<bounded assessment>`
- Product context: `<component/startup path, privileges, persistence, update relation, fleet scope>`
- Companion report: `<report ID or Not required>`

## Remediation plan

| Priority | Owner | Action | Affected models/builds | Verification evidence |
|---|---|---|---|---|
| `<priority>` | `<role>` | `<action>` | `<scope>` | `<required proof>` |

## Failed approaches and residual unknowns

- Failed approaches: `<attempt, error/evidence, consequence>`
- Unknowns: `<question and evidence needed to resolve it>`

## Evidence manifest

`<External manifest identifier, custody location, hash, and access restrictions. Do not embed sensitive evidence.>`
