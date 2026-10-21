---
name: security-analysis-reporting
description: "Trigger: app, firmware, or malware analysis report. Turn authorized evidence into a defensible report with bounded conclusions."
license: MIT
metadata:
  author: reversing-skills
  version: "1.0.0"
---

# Security analysis reporting

## Activation Contract

Load when authorized app, firmware, or malware evidence must become a technical or client-facing
report. Analysis skills produce evidence; this skill structures claims, risk, and remediation.

## Hard Rules

- Name the written authorization, in-scope artifacts, versions, audience, and handling class.
- Bind every conclusion to evidence; label it observed, inferred, modeled, or unverified.
- Keep severity separate from confidence. State alternatives and missing evidence.
- Never embed samples, credentials, customer identifiers, raw captures, or executable attack commands.
- Do not call software malicious from packing, obfuscation, one IOC, or an AV label alone.
- Keep evidence outside the report repository; link sanitized paths and record hashes.
- Record tools, versions, commands, failed approaches, and residual unknowns.

## Decision Gates

| Evidence and deliverable | Report action |
|---|---|
| App assessment, no coherent malware evidence | Use the application template |
| Firmware assessment, no coherent malware evidence | Use the firmware template |
| Isolated suspicious signal | Keep a finding in the main report; add a bounded triage appendix |
| Related static indicators, payload, or configuration; behavior unconfirmed | Add a malware triage report linked from the main report |
| Observed malicious execution, persistence, C2, or exfiltration | Add a full malware analysis report linked from the main report |
| Multiple samples or campaign infrastructure | Use a restricted companion report; do not infer attribution |
| Evidence needs new detonation, collection, or device changes | Stop until separately authorized; route analysis to `malware-analysis` |

## Execution Steps

1. Freeze scope, authorization reference, artifact identities, versions, audience, and handling class.
2. Build lineage from original artifact through extracted, decoded, unpacked, and runtime artifacts.
3. Normalize each claim with `references/finding-schema.md`; preserve contradictory evidence.
4. Select one primary template and any gated malware companion using the reporting guides.
5. Tie product impact to component location, trigger, reachability, affected versions, and evidence.
6. Add bounded remediation and a concrete fix-verification plan; do not claim an untested fix.
7. Check hashes, links, redaction, evidence labels, failed approaches, and unknowns before delivery.

## Output Contract

Return a Markdown report with scope and authorization, executive assessment, artifact lineage,
methods, evidence-backed findings, severity and confidence, remediation and verification, failures,
and unknowns. When malware gates are met, keep product context in the primary report and link a
separate triage or full malware report with classification confidence, capabilities, IOCs, and limits.

## References

- `references/finding-schema.md` — claim, severity, confidence, evidence, and remediation fields.
- `references/application-report.md` — app-specific scope, lineage, and malware-routing guidance.
- `references/firmware-report.md` — firmware-specific scope, persistence, fleet, and fidelity guidance.
- `references/malware-reporting.md` — triage versus full-report gates, lineage, IOCs, and attribution limits.
- `assets/application-report-template.md` — primary application report template.
- `assets/firmware-report-template.md` — primary firmware report template.
- `assets/malware-triage-template.md` — bounded suspicious-artifact triage template.
- `assets/malware-analysis-template.md` — confirmed or strongly evidenced malware report template.
