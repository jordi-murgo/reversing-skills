---
name: binary-diff
description: "Trigger: symbol migration, native binary diff, missing symbols after upgrade. Transfer evidence-backed names across binary versions."
license: MIT
metadata:
  author: reversing-skills
  version: "1.0.0"
---

# Native binary diff

## Activation Contract

Load when an older binary has trusted symbols or analysis and a newer build does not. Require written authorization and both exact artifacts. This skill migrates hypotheses; it does not prove semantic equivalence.

## Hard Rules

- Hash both binaries and record architecture, format, compiler clues, and analysis-tool versions.
- Use stable anchors before similarity: exports, strings, constants, callers, relocations, and data references.
- Never apply names from one weak match or model output alone.
- Keep model prompts local unless disclosure of code to the selected service is explicitly authorized.
- Preserve original databases; write renames and comments to a copy or exportable mapping.
- Mark every migrated name with confidence and supporting evidence.

## Decision Gates

| Evidence | Action |
|---|---|
| Same architecture and closely related build lineage | Start function matching |
| Compiler/LTO/optimization changed materially | Lower confidence; compare semantic anchors |
| Exact export or unique string anchor | Seed propagation from that function |
| Only shape similarity remains | Record candidate; do not rename automatically |
| Independent call/data-flow agreement | Apply mapping to a copied database |

## Execution Steps

1. Inventory and hash old/new artifacts; record analysis bases and rebasing.
2. Export function boundaries, normalized instructions, callers/callees, strings, constants, and old symbols.
3. Seed high-confidence anchors, then rank neighboring candidates.
4. Compare one function pair at a time; produce a structured mapping rather than prose.
5. Validate each proposal against call targets, global references, and ABI behavior.
6. Apply accepted names to a copy; rerun matching iteratively from new anchors.

## Output Contract

Return artifact identities, tool versions, anchor table, proposed symbol mapping, confidence, evidence per mapping, rejected candidates, commands, failed approaches, and residual unknowns.

## References

- `references/symbol-migration-workflow.md` — evidence model, matching strategy, and mapping schema.
