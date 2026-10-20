# .NET workflow

## Managed identification

Confirm the CLR runtime header and metadata streams (`#~`, `#Strings`, `#US`, `#Blob`) or valid assembly metadata. Imports such as `mscoree` are supporting evidence. NativeAOT and IL2CPP may contain runtime strings without managed metadata; route those to native analysis.

## Static order

1. Hash and record signer, assembly identity, target framework, runtime, architecture, and references.
2. Inventory module initializers, entry points, resources, embedded assemblies, reflection, serialization, P/Invoke, and dynamic loading.
3. Detect obfuscation from metadata corruption, renamed symbols, encrypted strings/resources, anti-tamper stubs, or flattened control flow.
4. Run a pinned deobfuscator only on a copy. Hash both input and output and diff metadata/method counts.
5. Navigate with decompiled C#, but verify security-sensitive branches, exception paths, async state machines, and patches in IL.

## Tool choices

- `ilspycmd`: headless, cross-platform decompilation.
- ILSpy/dnSpyEx: interactive metadata, IL, debugging, and controlled patching.
- de4dot-family tools: only when the observed protector/version is supported.
- dnlib: scripted metadata/IL inspection; validate emitted assemblies.

Tool behavior varies by revision. Record immutable versions and licenses; no third-party code is copied into this skill.

## Dynamic gates

Execute only in an isolated VM. Break after string/config decryptors, resource loaders, reflection dispatch, or network configuration construction. Capture method token, IL offset, arguments, return values, and child artifact hashes.

## Patching

Prefer the smallest IL edit. Preserve the original, emit to a new path, reload the result in an independent parser, and verify method bodies, metadata, strong-name status, signer changes, and intended behavior. Decompiled-C# recompilation may alter semantics or fail due to missing references; treat it as a separate rebuild, not a transparent patch.
