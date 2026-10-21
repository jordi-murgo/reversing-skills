# Finding schema

Use this schema for every report finding. Omit a field only when it is explicitly not applicable;
write `Unknown` when evidence is missing.

## Required fields

| Field | Content |
|---|---|
| ID | Stable report-local identifier, such as `APP-01`, `FW-02`, or `MAL-03` |
| Title | Specific condition and affected component, without claiming unproved impact |
| Severity | Critical, High, Medium, Low, or Informational; derived from demonstrated impact and reachability |
| Confidence | High, Medium, or Low; strength and independence of supporting evidence |
| Evidence state | Observed, Inferred, Modeled, or Unverified |
| Affected scope | Artifact hashes, product versions, channels, components, and environments |
| Summary | What was found, where, and why it matters |
| Evidence | Sanitized evidence IDs, file paths, symbols, addresses, events, timestamps, and tool versions |
| Trigger and reachability | Preconditions and path from exposed surface to the condition |
| Technical impact | Behavior directly supported by evidence |
| Product risk | Consequence in the assessed deployment, including limiting controls |
| Reproduction | Safe, authorized procedure or evidence query; exclude weaponized commands |
| Remediation | Root-cause correction and compensating controls |
| Fix verification | Negative and positive checks on an exact corrected version |
| Alternatives | Plausible benign or competing explanations and how they were tested |
| Limitations | Failed approaches, collection gaps, and residual unknowns |

## Classification rules

- Severity answers **how harmful and reachable** the condition is; confidence answers **how sure**
  the assessment is. Never lower severity merely because confidence is low.
- `Observed` means captured directly on the identified artifact or exact environment.
- `Inferred` means evidence supports a conclusion not directly captured; state the inference chain.
- `Modeled` means reproduced in a substitute environment; name every substitution and fidelity gap.
- `Unverified` is a lead, not a confirmed finding. State the evidence required to resolve it.
- A scanner result, AV label, shared IOC, packed section, or obfuscated code is corroborating evidence,
  not a complete finding by itself.
- Attach each evidence ID to an external manifest containing hash, acquisition time, custody, and
  storage location. Reports contain sanitized references, not the evidence itself.

## Report-level fields

Every report records its identifier, revision, date, author/reviewer, audience, handling class,
authorization reference, scope and exclusions, artifact table, environment/tool versions, and an
explicit list of unresolved questions.
