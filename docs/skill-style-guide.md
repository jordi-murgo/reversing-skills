# Skill style guide

A skill is a runtime contract for an LLM, not a tutorial.

## Required shape

```markdown
---
name: skill-name
description: "Trigger: exact phrases. One-sentence behavior."
license: MIT
metadata:
  author: reversing-skills
  version: "1.0.0"
---

## Activation Contract
## Hard Rules
## Decision Gates
## Execution Steps
## Output Contract
## References
```

Descriptions are quoted, one physical line, trigger-first, ideally at most 160 characters
and never more than 250. Use imperative rules. Put meaningful branches in a table. Keep
`SKILL.md` below 1000 tokens; supporting procedures live beside it.

## Reverse-engineering requirements

- Name the authorization and artifact prerequisites.
- State what evidence proves each conclusion.
- Separate observation, inference, failure, and unknown.
- Prefer static/read-only steps before dynamic/device mutation, without forbidding dynamic
  work that the ROE allows.
- Bind hooks and signatures to observed classes, overloads, addresses, versions, and ABIs.
- Never present a generic bypass as universal.
- A helper must preserve artifact identity and avoid overwriting existing evidence.

## Supporting files

- `references/`: methods, edge cases, tool-specific detail.
- `assets/`: schemas, templates, non-sensitive fixtures.
- `scripts/`: deterministic helpers owned by this skill.
- `tests/`: skill-local behavior tests when they must travel with the skill.

Local links must resolve after copying only the skill directory. Cross-skill routing uses the
frontmatter name, not a relative filesystem path.
