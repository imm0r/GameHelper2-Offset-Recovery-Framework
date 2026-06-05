# Standalone (Ghidra-free) offset recovery — Proof of Concept

This folder is a **proof of concept** that the offset recovery logic does not
need Ghidra. It re-implements the `Game States` recipe from
`../OffsetRecoveryFramework.java` as a self-contained .NET console app that reads
`PathOfExile.exe` directly.

It exists to validate the architecture described to you in chat, not to replace
the full framework yet — only one of the six recipes is ported.

## Why this works without Ghidra

The Ghidra script relied on four services. Here is what replaces each:

| Ghidra service | Standalone replacement | File |
|---|---|---|
| String table | Scan read-only sections for ASCII/UTF-16 runs | `StringScanner.cs` |
| Disassembly | [`iced-x86`](https://github.com/icedland/iced) decoder | `Analysis.cs` |
| Memory model + pattern search | Hand-rolled PE32+ section map | `PeImage.cs`, `SignatureMaker.cs` |
| **Function bounds + XREFs** | **`.pdata` exception directory** + a self-built XREF map | `PeImage.cs`, `Analysis.cs` |

The key enabler is the **`.pdata` (`RUNTIME_FUNCTION`) table**, which every x64
Windows binary must ship. It gives accurate `[begin, end)` bounds for (almost)
every function for free — that is the part that normally justifies a full
analysis engine. With function bounds in hand, the XREF map is just a linear
decode of each function that records every RIP-relative memory target and
branch/call target.

The instruction matching is actually *more* robust than the original, which
matched on Ghidra's instruction text (e.g. `startsWith("MOV RAX,")`). Here we
match on decoded structure (mnemonic, operand kinds, registers, memory size).

## Build & run

Requires the .NET **SDK** (10.0+; the runtime alone cannot build) and network
access to restore the `Iced` NuGet package.

```bash
cd standalone
dotnet run -c Release -- "C:\path\to\PathOfExile.exe" --verbose
```

Expected output: the resolved static address for `Game States`, a SigMaker-style
`Output pattern` that is unique in executable memory, `BytesToSkip`, and a
confidence score — mirroring the Ghidra script's console output.

## Mapping to the Java source

| Standalone | Ghidra script (`OffsetRecoveryFramework.java`) |
|---|---|
| `GameStatesRecipe.Recover` | `GameStatesRecipe.recoverCandidates` |
| `FindStaticQwordNullCheck` | `findStaticQwordNullCheck` / `isStaticQwordNullCheck` |
| `CodeModel.DirectCallsBefore` | `directCallsBefore` |
| `SignatureMaker.MakeUnique` | `makeUniquePattern` |
| `SignatureMaker.Build` | `ripPattern` / `markReferencedDisplacements` |
| `SignatureMaker.CountExecutableMatches` | `countExecutableMatches` |
| `XrefMap` | `getReferencesTo` / `getReferencesFrom` |
| `FunctionTable` | `getFunctionContaining` / `getFunctionAt` (via `.pdata`) |

## Known simplifications (PoC scope)

These are deliberate cuts, not blockers — each is a known, bounded extension:

- **One recipe only** (`Game States`). The other five port the same way.
- **SigMaker single-start.** The Java `makeBestUniquePattern` also tries earlier
  start addresses to find a shorter/byte-richer pattern; here we only extend
  forward from the match. Enough to prove uniqueness.
- **Linear per-function decode.** Functions absent from `.pdata` (rare leaf
  thunks) are not indexed. A CALL-target sweep would fill those in.
- **No Ghidra annotations.** Bookmarks/labels were a Ghidra-DB feature; output
  is console-only. A JSON or `.csv` emitter would be the production replacement.
