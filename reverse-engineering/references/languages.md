# Language and runtime clues

## Go

Look for build info, pclntab, function metadata, goroutine/runtime symbols, stack growth, interface dispatch, panic strings, and embedded files. Version-specific metadata recovery is stronger than heuristic renaming.

## Rust

Use demangled symbols when present; recognize `Result`/`Option`, panic paths, trait-object vtables, slices, vectors, and monomorphization. Panic strings and crate paths are leads, not proof of reachable behavior.

## Swift / Objective-C

Demangle Swift names; inspect protocol witness tables, type metadata, selectors, class lists, and dyld bindings. Route application bundles to `ios-app-reversing`.

## JVM / Kotlin

Map class metadata, coroutine state machines, reflection, JNI registration, and resource/config loaders. Route APK sets to `android-apk-intake` and native JNI to `android-packed-native` when applicable.

## .NET

A CLR header and metadata streams indicate managed analysis; use `dotnet-reverse`. NativeAOT and IL2CPP route back to native tooling.

## Python and packaged runtimes

Identify interpreter/version, bytecode magic, archive/container, marshalled objects, native extensions, and loader. Rebuild with the matching interpreter and preserve extraction lineage.

## WebAssembly and custom bytecode

Recover imports/exports, linear-memory layout, tables, block structure, and host boundary. For custom VMs, follow `patterns.md`; do not assign high-level semantics before opcode traces agree.

Language identification is a decision gate, not a conclusion about behavior. Record compiler/runtime version and supporting evidence.
