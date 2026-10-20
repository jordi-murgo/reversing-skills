# Native analysis patterns

## Loader before payload

Packed or self-modifying targets often expose a small stable loader and unstable payload bytes. Map constructors, memory allocation, copy/decrypt loops, permission changes, indirect transfer, and child mappings. Decompile only bytes that are executable in the observed state.

## Custom virtual machines

Recover the VM contract in this order:

1. state structure and instruction pointer;
2. fetch width and byte order;
3. opcode decode and dispatch;
4. operand encoding and register/stack model;
5. branch/call/return semantics;
6. host imports and side effects.

Validate each instruction with short traces before lifting the whole program. Unknown opcodes remain unknown; do not infer from one path.

## Data transformations

For XOR, table, permutation, S-box, checksum, and rolling-state logic, identify inputs, state update, output, invertibility, and boundary conditions. Reimplement only after comparing intermediate values against the original on multiple fixtures.

## C++ and compiled-language clues

Vtables, RTTI, constructors/destructors, exception metadata, panic/error strings, async state machines, and allocation patterns help recover types. Compiler-generated patterns vary with version and optimization; corroborate with call/data-flow.

## Dynamic boundary

When static analysis stops, instrument the narrowest verified function or memory transition. Capture address, module, offset, mapping, arguments, return, timestamp, and artifact version. Avoid generic bypass scripts that hide evidence sources.

These are clean-room general procedures; no challenge writeups or third-party snippets are copied here.
