# Contributing

## Add or change a skill

1. Read `AGENTS.md` and `docs/skill-style-guide.md`.
2. Start from observed behavior in an authorized engagement or a deterministic fixture.
3. Keep client evidence outside this repository.
4. Put runtime instructions in `SKILL.md`; supporting detail in `references/`; templates and
   schemas in `assets/`; executable behavior in `scripts/`.
5. Add a focused regression test for the user-visible failure or invariant.
6. Run the full offline suite.
7. Record external source revision and license before copying any material.

## Review checklist

- Activation and exclusions are explicit.
- Commands are parameterized and non-destructive by default.
- Observed facts and inference are distinguishable.
- Missing tools and version mismatches fail loudly.
- Every local reference resolves when the skill directory is copied alone.
- The negative fixture fails before the implementation is fixed.
- No APK, binary dump, capture, credential, token, client identity, or lab path is present.

Keep repository changes separate from synchronization into consuming projects.
