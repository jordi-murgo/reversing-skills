# Capability-based tool selection

Choose tools from the artifact and question, not habit.

| Need | Typical capability |
|---|---|
| headers, symbols, relocations, dependencies | platform binutils, LIEF-like parser, `rabin2` |
| interactive decompilation | Ghidra, IDA, Binary Ninja, Cutter/rizin |
| CLI scripting | radare2/rizin, headless Ghidra, tool-native Python API |
| debugger/tracing | gdb/lldb, x64dbg/WinDbg, Frida, system tracers |
| emulation | QEMU user/system, Unicorn, Qiling |
| symbolic/data-flow | angr, Triton, Miasm |
| native binary matching | BinDiff, Diaphora, ghidriff |

## Selection rules

- Use at least two views for security-critical conclusions.
- Pin exact versions; decompiler output and analysis databases change across releases.
- Never silently install. Missing tools fail loudly with explicit prerequisites.
- Keep commercial-license tools optional; the skill must still explain a non-commercial lane.
- Treat cloud decompilers/model services as disclosure boundaries requiring approval.
- Preserve commands, options, logs, and analysis bases so another analyst can reproduce the result.

## Tool custody

No external code is vendored by this skill. Before installing or redistributing a helper, record its canonical URL, immutable revision, license, notices, and local modifications. Unknown license blocks copying.
