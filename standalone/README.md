# Standalone (Ghidra-free) offset recovery

This folder re-implements `../OffsetRecoveryFramework.java` as a self-contained
.NET console app that reads `PathOfExile.exe` directly — no Ghidra required.

All six recipes are ported (`Game States`, `File Root`, `AreaChangeCounter`,
`Terrain Rotator Helper`, `Terrain Rotation Selector`, `GameCullSize`). Results
are printed to the console and written to a machine-readable `offsets.json`.

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

Per offset the tool prints the anchor, resolved static address, a SigMaker-style
`Output pattern` that is unique in executable memory, `BytesToSkip`, and a
confidence score, then a final summary — mirroring the Ghidra script. It also
writes `offsets.json` in the working directory.

## Mapping to the Java source

| Standalone | Ghidra script (`OffsetRecoveryFramework.java`) |
|---|---|
| `*Recipe.Recover` | `*Recipe.recoverCandidates` |
| `Insn.*` predicates | `isStatic*` / instruction-text checks |
| `CodeModel.DirectCallsBefore` / `DirectCallsToDepth` / `CallDepth` | `directCallsBefore` / `directCallsToDepth` / `callDepth` |
| `SignatureMaker.MakeBestUnique` / `MakeUnique` | `makeBestUniquePattern` / `makeUniquePattern` |
| `SignatureMaker.Build` | `ripPattern` / `markReferencedDisplacements` |
| `SignatureMaker.CountExecutableMatches` | `countExecutableMatches` |
| `XrefMap` | `getReferencesTo` / `getReferencesFrom` |
| `FunctionTable` | `getFunctionContaining` / `getFunctionAt` (via `.pdata`) |
| `JsonExport` | Ghidra bookmarks / labels (`annotate`) |

## Known simplifications

- **Linear per-function decode.** Functions absent from `.pdata` (rare leaf
  thunks) are not indexed. A CALL-target sweep would fill those in.
- **Pattern uniqueness over `.pdata`-covered code.** The executable-memory match
  count scans raw section bytes, same as Ghidra; recipe traversal only sees code
  reachable through the function table.
