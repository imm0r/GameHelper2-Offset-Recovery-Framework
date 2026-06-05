# Standalone (Ghidra-free) offset recovery

This folder re-implements `../OffsetRecoveryFramework.java` in .NET, reading
`PathOfExile.exe` directly — no Ghidra required. It ships two front-ends over a
shared core (`RecoveryRunner`): a **CLI** (`OffsetRecovery.Standalone`) and a
**WPF GUI** (`OffsetRecovery.Gui`).

All six recipes are ported (`Game States`, `File Root`, `AreaChangeCounter`,
`Terrain Rotator Helper`, `Terrain Rotation Selector`, `GameCullSize`). Results
are shown in the UI / console and written to a machine-readable `offsets.json`.

## Projects

| Project | What it is |
|---|---|
| `OffsetRecovery.Standalone` | Core logic + CLI (`RecoveryRunner` does the work) |
| `gui/OffsetRecovery.Gui` | WPF desktop front-end (`net10.0-windows`, references the core) |
| `tests/OffsetRecovery.Tests` | xUnit suite |

`OffsetRecovery.sln` ties all three together.

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
access to restore NuGet packages on first build. The GUI builds on Windows.

```bash
cd standalone
dotnet build OffsetRecovery.sln -c Release   # build core + GUI + tests
```

**GUI** — pick the executable, press *Recover*, read the table; *Copy pattern*,
*Copy address*, or *Save offsets.json…*:

```bash
dotnet run -c Release --project gui/OffsetRecovery.Gui
```

**CLI** — same recovery, console output, writes `offsets.json` to the working
directory:

```bash
dotnet run -c Release --project OffsetRecovery.Standalone -- "C:\path\to\PathOfExile.exe" --verbose
```

Per offset both front-ends report the resolved static address, a SigMaker-style
pattern that is unique in executable memory, `BytesToSkip`, and a confidence
score — mirroring the Ghidra script.

### One-file build

Produce a single self-contained `OffsetRecovery.Gui.exe` (no .NET install
needed to run it):

```powershell
./publish-gui.ps1
# -> gui/OffsetRecovery.Gui/bin/Release/net10.0-windows/win-x64/publish/OffsetRecovery.Gui.exe
```

## Self-check

After recovery, every emitted result is cross-checked the way a runtime AOB
scanner will consume it: read the 4-byte displacement at
`matchAddress + bytesToSkip` and require
`resolved == matchAddress + bytesToSkip + 4 + disp32`, plus that the pattern's
fixed bytes occur at `patternStart` (`PatternSelfCheck.cs`). The run prints
`Self-check: N / N patterns resolve to their static address`; a mismatch is
flagged with `WARN` and means that offset's pattern is not safely consumable
(e.g. a displacement field not flush with the instruction end).

## Tests

A small xUnit suite under `tests/OffsetRecovery.Tests` exercises the pipeline
without the game binary, using a synthetic PE32+ built in memory
(`TestPe.cs`: a `.text` with a few functions, a `.rdata` with strings, and a
`.pdata` table — including a CALL target deliberately omitted from `.pdata` to
exercise the sweep).

```bash
cd standalone
dotnet test tests/OffsetRecovery.Tests
```

Coverage: PE32+ parsing and malformed-file rejection, `.pdata` function bounds,
the CALL sweep, the XREF map and call graph, `InstructionIndex` navigation,
string scanning and `AnchorSpec` matching, the `Insn` structural predicates,
`SignatureMaker` uniqueness and `Pattern.Render`, the self-check, scoring,
confidence labels, and JSON export.

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

## Function discovery

Function bounds come from the `.pdata` exception table first. A second **CALL
sweep** (`CodeModel.Build` phase 2) then finds direct-call targets that `.pdata`
never listed, decodes each with a bounded heuristic (stop at the first top-level
`RET` / tail `JMP` / padding once no forward branch reaches past it), and folds
them into the function table, instruction index, and XREF map. The startup line
reports how many were recovered this way (`Functions: N (+M via CALL sweep)`),
so recipe traversal and uniqueness checks see code even when a patched build
ships an incomplete `.pdata`.

## Known simplifications

- **Indirect/jump-table targets** are not followed (no `NearBranch64`), so a
  function reachable only through an indirect tail jump and never directly
  called stays unindexed.
- **Pattern uniqueness over decoded code.** The executable-memory match count
  scans raw section bytes, same as Ghidra; recipe traversal sees code reachable
  through the function table (now `.pdata` + CALL sweep).
