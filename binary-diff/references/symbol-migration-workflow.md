# Symbol migration workflow

## Evidence model

A mapping is accepted only when multiple stable features agree. Useful features:

- exact exports and unchanged public ABI;
- unique strings, constants, GUIDs, format strings, and error codes;
- callers/callees, import usage, global references, and vtable slots;
- normalized control-flow shape after ignoring addresses and register allocation;
- argument count, calling convention, stack behavior, and side effects.

Compiler, LTO, inlining, profile-guided optimization, and source refactors can invalidate shape matching. Record these differences before assigning confidence.

## Mapping record

Use JSON/YAML with one record per proposal:

```yaml
old_address: "0x..."
old_name: "..."
new_address: "0x..."
confidence: high|medium|low
evidence:
  - "unique string xref"
  - "same two callees and global"
contradictions: []
status: accepted|candidate|rejected
```

Do not ask a model to invent addresses. Supply exported evidence and require structured output containing only candidates and reasons. Keep code local unless external disclosure is authorized.

## Iteration

1. Seed exact anchors.
2. Compare immediate call-graph neighborhoods.
3. Accept only independently corroborated matches.
4. Apply accepted names to a copy.
5. Export the new database and repeat.

Stop propagation when an anchor is ambiguous: one wrong high-degree node contaminates many descendants.

## Validation

For high-impact mappings, compare bytes/disassembly manually and verify runtime ownership only if authorized. Preserve the pre-rename database, mapping file, importer command, and rejected alternatives.

No external code is vendored by this skill. Pin and record the revision and license of any diff engine, disassembler, or model gateway used.
