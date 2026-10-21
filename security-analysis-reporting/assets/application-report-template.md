# Application Security Analysis Report

## Document control

| Field | Value |
|---|---|
| Report ID / revision | `<identifier / revision>` |
| Date | `<ISO-8601>` |
| Author / reviewer | `<roles or approved identifiers>` |
| Audience / handling | `<audience / classification>` |
| Authorization reference | `<written authorization reference>` |

## Executive assessment

`<Decision-relevant result, affected product/builds, demonstrated impact, confidence, and most important limitation.>`

## Scope and exclusions

- In scope: `<artifacts, versions, channels, environments>`
- Out of scope: `<explicit exclusions>`
- Assessment window: `<start/end>`

## Artifact identity

| Artifact ID | Package/bundle and version | Channel | Signer | SHA-256 | Evidence path |
|---|---|---|---|---|---|
| `<APP-ART-01>` | `<identity>` | `<channel>` | `<signer>` | `<hash>` | `<sanitized external path>` |

## Environment and methods

| Environment/tool | Exact version or build | Purpose | Relevant configuration |
|---|---|---|---|
| `<item>` | `<version>` | `<purpose>` | `<configuration>` |

Methods and commands: `<sanitized, reproducible record or evidence-manifest reference>`

## Application map

`<Components, permissions/entitlements, exposed entry points, trust boundaries, storage, network, crypto, native code, and update path relevant to findings.>`

## Findings summary

| ID | Title | Severity | Confidence | Evidence state | Affected versions |
|---|---|---|---|---|---|
| `<APP-01>` | `<title>` | `<level>` | `<level>` | `<Observed/Inferred/Modeled/Unverified>` | `<scope>` |

## Finding `<APP-01>` — `<title>`

- Affected scope: `<artifacts, versions, channels, components>`
- Summary: `<condition and consequence>`
- Evidence: `<evidence IDs, paths, symbols/addresses/events, timestamps>`
- Trigger and reachability: `<preconditions and path>`
- Technical impact: `<demonstrated behavior>`
- Product risk and limiting controls: `<deployment consequence>`
- Safe reproduction: `<authorized procedure or evidence query>`
- Remediation: `<root-cause fix and compensating controls>`
- Fix verification: `<positive and negative checks on exact corrected build>`
- Alternatives considered: `<benign or competing explanations>`
- Limitations: `<gaps, failures, unknowns>`

## Malware assessment

- State / confidence / date: `<Unknown, Suspicious, Probably malicious, or Confirmed malicious / confidence / date>`
- Supporting and missing evidence: `<bounded assessment>`
- Product context: `<component location, activation, reachable data/privileges, affected versions>`
- Companion report: `<report ID or Not required>`

## Remediation plan

| Priority | Owner | Action | Affected versions | Verification evidence |
|---|---|---|---|---|
| `<priority>` | `<role>` | `<action>` | `<scope>` | `<required proof>` |

## Failed approaches and residual unknowns

- Failed approaches: `<attempt, error/evidence, consequence>`
- Unknowns: `<question and evidence needed to resolve it>`

## Evidence manifest

`<External manifest identifier, custody location, hash, and access restrictions. Do not embed sensitive evidence.>`
