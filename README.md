# PoEformance - Pattern-Voodoo

This folder contains Ghidra-only helpers for recovering static offsets after game updates.

## How to run

1. Open game `*.exe` in Ghidra and let analysis finish.
2. Add this folder as a Ghidra Script Manager directory.
3. Run `PoEformance.java`.

Validated with Ghidra 12.1. Keep archived or comparison copies outside this script folder, or give them a non-`.java` extension, because Ghidra compiles every Java file in the bundle.

The script prints the best candidate for each offset, confidence, unique output pattern data, and a final summary. High-confidence results also receive bookmarks and labels in the Ghidra database.

Set `VERBOSE = true` in `PoEformance.java` to print score reasons and validation notes while debugging recipes.

## Current offsets

- `Game States`
- `File Root` (`Mods.dat` by filename, regardless of directory)
- `AreaChangeCounter`
- `Terrain Rotator Helper`
- `Terrain Rotation Selector`
- `GameCullSize`

## Recipe model

Most recipes start from one or more anchor strings, follow XREFs and call chains, then scan Ghidra instructions for a RIP-relative static reference. Some recipes, such as `Terrain Rotator Helper` and `GameCullSize`, use function-shape detection instead of a string anchor. After semantic hooks select the best candidate for an offset, the framework runs one SigMaker-style pass for that result by wildcarding RIP-relative displacement bytes and extending across instruction boundaries until the pattern is unique in executable memory. A result is valid only when the final output pattern has exactly one executable-memory match.

For simple offsets, use `AnchorRecipeBuilder`. For complex offsets, add a custom `OffsetRecipe` implementation.

## Adding an offset

1. Pick durable anchors: strings, nearby log text, table paths, or error messages.
2. Define the traversal: same function, direct calls, or nested calls.
3. Match a stable instruction shape, preferably RIP-relative.
4. Resolve the static address with `resolveRipRelative`.
5. Add validation rules that prove the candidate is semantically correct.
6. Make wrong candidates lose score or fail cleanly.

## Patch-day review

If confidence is high, the result is usually enough. If confidence is medium or low, enable `VERBOSE`, rerun the script, and inspect the printed candidate in Ghidra using the bookmarks and validation notes before updating production offsets.
