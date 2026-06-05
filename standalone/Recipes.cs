using System;
using System.Collections.Generic;
using Iced.Intel;

namespace OffsetRecovery.Standalone
{
    public sealed class OffsetMatch
    {
        public ulong MatchStart;
        public ulong InstructionAddress;
        public ulong Resolved;
        public int BytesToSkip;
        public int PatternLength;   // initial minimal length (input to the SigMaker pass)
        public string Kind;
        public readonly HashSet<string> Traits = new HashSet<string>();

        // Filled by the SigMaker pass.
        public string Pattern;
        public ulong PatternStart;
        public int PatternMatchCount;

        public bool HasTrait(string trait) => Traits.Contains(trait);
    }

    public sealed class RecoveryResult
    {
        public string OffsetName;
        public string StaticLabel;
        public string SourceLabel;
        public StringHit Anchor;
        public ulong StringReferenceAddress;
        public PdataFunction XrefFunction;
        public PdataFunction SourceFunction;
        public int CallDepth = -1;
        public OffsetMatch Match;
        public int Score;
        public int CandidateCount;
        public readonly List<string> Reasons = new List<string>();
        public readonly List<string> Validations = new List<string>();
    }

    public interface IOffsetRecipe
    {
        string Name { get; }
        string FailureReason { get; }
        List<RecoveryResult> Recover(List<StringHit> strings);
    }

    public abstract class RecipeBase : IOffsetRecipe
    {
        protected readonly CodeModel Model;

        protected RecipeBase(CodeModel model)
        {
            Model = model;
        }

        public abstract string Name { get; }
        public abstract string FailureReason { get; }
        public abstract List<RecoveryResult> Recover(List<StringHit> strings);

        protected List<StringHit> FindAnchors(List<StringHit> strings, params AnchorSpec[] specs)
        {
            var hits = new List<StringHit>();
            var seen = new HashSet<ulong>();
            foreach (AnchorSpec spec in specs)
            {
                foreach (StringHit hit in strings)
                {
                    if (seen.Contains(hit.Address))
                    {
                        continue;
                    }
                    if (spec.Matches(hit.Value))
                    {
                        hits.Add(hit);
                        seen.Add(hit.Address);
                    }
                }
            }
            return hits;
        }

        protected bool HasThreadLocalSetupNearEntry(PdataFunction function)
        {
            foreach (Instruction instruction in Model.InstructionsInWindow(function, function.Begin, 0x40))
            {
                if (Insn.IsThreadLocalAccess(instruction))
                {
                    return true;
                }
            }
            return false;
        }

        protected static OffsetMatch RipMatch(ulong matchStart, Instruction instruction, int displacementOffset,
            int patternLength, string kind, params string[] traits)
        {
            var match = new OffsetMatch
            {
                MatchStart = matchStart,
                InstructionAddress = instruction.IP,
                Resolved = instruction.IPRelativeMemoryAddress,
                BytesToSkip = (int)(instruction.IP - matchStart) + displacementOffset,
                PatternLength = patternLength,
                Kind = kind,
            };
            foreach (string trait in traits)
            {
                if (!string.IsNullOrEmpty(trait))
                {
                    match.Traits.Add(trait);
                }
            }
            return match;
        }

        protected static OffsetMatch RipMatch(ulong matchStart, Instruction instruction, int displacementOffset,
            string kind, params string[] traits)
        {
            int patternLength = (int)(instruction.IP - matchStart) + instruction.Length;
            return RipMatch(matchStart, instruction, displacementOffset, patternLength, kind, traits);
        }

        protected static string Hex(ulong value) => "0x" + value.ToString("x");

        protected static string Fmt(PdataFunction function)
        {
            return function == null ? "<none>" : function.Name + " @ " + Hex(function.Begin);
        }
    }

    public static class Scoring
    {
        public static int Proximity(ulong from, ulong to, ulong maxDistance, int score, string label, List<string> reasons)
        {
            if (to >= from && to - from < maxDistance)
            {
                reasons.Add(label + " within 0x" + maxDistance.ToString("x") + " bytes");
                return score;
            }
            return 0;
        }

        public static int RefsTo(CodeModel model, ulong address, int score, List<string> reasons, List<string> validations)
        {
            int count = model.Xrefs.CountTo(address);
            if (count >= 2)
            {
                reasons.Add("resolved address has " + count + " XREFs");
                validations.Add("resolved address is referenced elsewhere");
                return score;
            }
            validations.Add("resolved address has low XREF count: " + count);
            return 0;
        }
    }

    public static class Confidence
    {
        public static string Label(int score)
        {
            if (score >= 85) return "high";
            if (score >= 65) return "medium";
            return "low";
        }
    }

    // anchor "Unable to get InGameState" -> XREF caller -> provider call before the
    // error branch -> CMP qword ptr [static], RBP/0  (the global game-state pointer)
    public sealed class GameStatesRecipe : RecipeBase
    {
        public GameStatesRecipe(CodeModel model) : base(model) { }

        public override string Name => "Game States";
        public override string FailureReason => "anchor string, XREF caller, or provider null-check was not found.";

        public override List<RecoveryResult> Recover(List<StringHit> strings)
        {
            var candidates = new List<RecoveryResult>();
            foreach (StringHit anchor in FindAnchors(strings,
                AnchorSpec.Exact("Unable to get InGameState"),
                AnchorSpec.Contains("InGameState")))
            {
                foreach (ulong referenceFrom in Model.Xrefs.To(anchor.Address))
                {
                    PdataFunction xref = Model.FunctionContaining(referenceFrom);
                    if (xref == null)
                    {
                        continue;
                    }

                    foreach (PdataFunction provider in Model.DirectCallsBefore(xref, referenceFrom))
                    {
                        OffsetMatch match = FindStaticQwordNullCheck(provider);
                        if (match == null)
                        {
                            continue;
                        }

                        var result = new RecoveryResult
                        {
                            OffsetName = Name,
                            StaticLabel = "GameStates_Static",
                            SourceLabel = "GameStatesProvider",
                            Anchor = anchor,
                            StringReferenceAddress = referenceFrom,
                            XrefFunction = xref,
                            SourceFunction = provider,
                            Match = match,
                            Score = 30,
                        };
                        result.Reasons.Add("anchor string reached provider call before error branch");
                        result.Score += Scoring.Proximity(provider.Begin, match.InstructionAddress, 0x40, 25, "null-check", result.Reasons);
                        if (provider.Begin < xref.Begin)
                        {
                            result.Score += 10;
                            result.Reasons.Add("provider is a lower-address helper function");
                        }
                        result.Score += Scoring.RefsTo(Model, match.Resolved, 15, result.Reasons, result.Validations);
                        if (match.HasTrait("provider-prologue"))
                        {
                            result.Score += 10;
                            result.Reasons.Add("matched provider prologue context");
                        }
                        result.Validations.Add("provider function: " + Fmt(provider));
                        candidates.Add(result);
                    }
                }
            }
            return candidates;
        }

        private OffsetMatch FindStaticQwordNullCheck(PdataFunction function)
        {
            foreach (Instruction instruction in Model.InstructionsInWindow(function, function.Begin, 0x180))
            {
                if (!Insn.IsStaticQwordNullCheck(instruction))
                {
                    continue;
                }

                bool prologue = Model.Instructions.TryBefore(instruction.IP, out Instruction previous)
                    && function.Contains(previous.IP)
                    && previous.Mnemonic == Mnemonic.Xor
                    && previous.Op0Register == Register.EBP
                    && previous.Op1Register == Register.EBP;

                int length = instruction.Length;
                if (Model.Instructions.TryAfter(instruction.IP, out Instruction next)
                    && function.Contains(next.IP)
                    && next.FlowControl == FlowControl.ConditionalBranch)
                {
                    length += next.Length;
                }

                return RipMatch(instruction.IP, instruction, 3, length, "static qword null-check",
                    prologue ? "provider-prologue" : null);
            }
            return null;
        }
    }

    // anchor "Mods.dat" -> XREF call chain (depth <= 2) -> MOV RAX,[static] + nearby RET
    // inside a TLS-init finder  (the global file-root pointer)
    public sealed class FileRootRecipe : RecipeBase
    {
        public FileRootRecipe(CodeModel model) : base(model) { }

        public override string Name => "File Root";
        public override string FailureReason => "anchor string, XREF call chain, or static return was not found.";

        public override List<RecoveryResult> Recover(List<StringHit> strings)
        {
            var candidates = new List<RecoveryResult>();
            foreach (StringHit anchor in FindAnchors(strings, AnchorSpec.FileName("Mods.dat")))
            {
                foreach (ulong referenceFrom in Model.Xrefs.To(anchor.Address))
                {
                    PdataFunction xref = Model.FunctionContaining(referenceFrom);
                    if (xref == null)
                    {
                        continue;
                    }

                    foreach (PdataFunction finder in Model.DirectCallsToDepth(xref, 2))
                    {
                        OffsetMatch match = FindStaticQwordReturn(finder);
                        if (match == null)
                        {
                            continue;
                        }

                        int depth = Model.CallDepth(xref, finder, 2);
                        var result = new RecoveryResult
                        {
                            OffsetName = Name,
                            StaticLabel = "FileRoot_Static",
                            SourceLabel = "FileRootFinder",
                            Anchor = anchor,
                            StringReferenceAddress = referenceFrom,
                            XrefFunction = xref,
                            SourceFunction = finder,
                            CallDepth = depth,
                            Match = match,
                            Score = 35,
                        };
                        result.Reasons.Add("found static return through file-path XREF call chain");
                        if (depth == 1)
                        {
                            result.Score += 20;
                            result.Reasons.Add("finder is a direct call from XREF function");
                        }
                        else if (depth == 2)
                        {
                            result.Score += 15;
                            result.Reasons.Add("finder is one nested call from XREF function");
                        }
                        result.Score += Scoring.Proximity(finder.Begin, match.InstructionAddress, 0x90, 15, "static return", result.Reasons);
                        result.Score += Scoring.RefsTo(Model, match.Resolved, 15, result.Reasons, result.Validations);
                        if (match.HasTrait("tls-init-context"))
                        {
                            result.Score += 15;
                            result.Reasons.Add("matched FileRootFinder TLS-init context");
                        }
                        result.Validations.Add("finder function: " + Fmt(finder));
                        candidates.Add(result);
                    }
                }
            }
            return candidates;
        }

        private OffsetMatch FindStaticQwordReturn(PdataFunction function)
        {
            foreach (Instruction instruction in Model.InstructionsInWindow(function, function.Begin, 0x180))
            {
                if (!Insn.IsStaticMovIntoRax(instruction) || !Model.HasNearbyRet(instruction.IP, 0x18))
                {
                    continue;
                }

                bool tls = HasThreadLocalSetupNearEntry(function) && instruction.IP - function.Begin < 0x80;
                if (!tls)
                {
                    continue;
                }
                return RipMatch(instruction.IP, instruction, 3, "static qword return", "tls-init-context");
            }
            return null;
        }
    }

    // anchor "Got Instance Details from login server" -> XREF function ->
    // INC dword ptr [static]  (the area-change counter)
    public sealed class AreaChangeCounterRecipe : RecipeBase
    {
        public AreaChangeCounterRecipe(CodeModel model) : base(model) { }

        public override string Name => "AreaChangeCounter";
        public override string FailureReason => "anchor string, XREF function, or scanner match was not found.";

        public override List<RecoveryResult> Recover(List<StringHit> strings)
        {
            var candidates = new List<RecoveryResult>();
            foreach (StringHit anchor in FindAnchors(strings,
                AnchorSpec.Exact("Got Instance Details from login server"),
                AnchorSpec.Contains("Instance Details from login server")))
            {
                foreach (ulong referenceFrom in Model.Xrefs.To(anchor.Address))
                {
                    PdataFunction xref = Model.FunctionContaining(referenceFrom);
                    if (xref == null)
                    {
                        continue;
                    }

                    OffsetMatch match = FindDwordIncrementAfter(xref, referenceFrom);
                    if (match == null)
                    {
                        continue;
                    }

                    var result = new RecoveryResult
                    {
                        OffsetName = Name,
                        StaticLabel = "AreaChangeCounter_Static",
                        SourceLabel = "HandleLoginServerInstanceDetails",
                        Anchor = anchor,
                        StringReferenceAddress = referenceFrom,
                        XrefFunction = xref,
                        SourceFunction = xref,
                        Match = match,
                        Score = 45,
                    };
                    result.Reasons.Add("found scanner match after anchor XREF");
                    result.Score += Scoring.Proximity(referenceFrom, match.InstructionAddress, 0x180, 25, "match", result.Reasons);
                    if (match.HasTrait("tls-init-context"))
                    {
                        result.Score += 20;
                        result.Reasons.Add("matched area-change TLS-init context");
                    }
                    if (xref.Contains(match.InstructionAddress))
                    {
                        result.Score += 10;
                        result.Validations.Add("match remains inside XREF function body");
                    }
                    candidates.Add(result);
                }
            }
            return candidates;
        }

        private OffsetMatch FindDwordIncrementAfter(PdataFunction function, ulong anchorReference)
        {
            foreach (Instruction instruction in Model.InstructionsInWindow(function, anchorReference, 0x300))
            {
                if (!Insn.IsStaticDwordIncrement(instruction))
                {
                    continue;
                }
                bool tls = HasAreaChangeTlsContext(function, instruction.IP);
                return RipMatch(instruction.IP, instruction, 2, "static dword increment", tls ? "tls-init-context" : null);
            }
            return null;
        }

        private bool HasAreaChangeTlsContext(PdataFunction function, ulong incrementAddress)
        {
            foreach (Instruction instruction in Model.InstructionsInWindow(function, function.Begin, 0x300))
            {
                if (instruction.IP >= incrementAddress)
                {
                    break;
                }
                if (incrementAddress - instruction.IP <= 0x80 && Insn.IsThreadLocalAccess(instruction))
                {
                    return true;
                }
            }
            return false;
        }
    }

    // GameCullSize: SUB EAX,[static] preceded by a call and followed by vector-zero setup.
    public sealed class GameCullSizeRecipe : RecipeBase
    {
        public GameCullSizeRecipe(CodeModel model) : base(model) { }

        public override string Name => "GameCullSize";
        public override string FailureReason => "FOO-result static subtract shape was not found.";

        public override List<RecoveryResult> Recover(List<StringHit> strings)
        {
            var matches = new List<OffsetMatch>();
            foreach (Instruction instruction in Model.Instructions.All)
            {
                if (!Insn.IsStaticSubFromEax(instruction))
                {
                    continue;
                }
                if (!Model.HasCallBefore(instruction.IP, 0x80) || !Model.HasVectorZeroAfter(instruction.IP, 0x40))
                {
                    continue;
                }
                matches.Add(RipMatch(instruction.IP, instruction, 2,
                    "game cull size subtract from FOO result", "call-before", "vector-zero-after"));
            }

            var anchor = new StringHit { Value = "GameCullSize FOO-result subtract shape", Address = Model.Image.ImageBase };
            var candidates = new List<RecoveryResult>();
            foreach (OffsetMatch match in matches)
            {
                PdataFunction function = Model.FunctionContaining(match.InstructionAddress);
                var result = new RecoveryResult
                {
                    OffsetName = Name,
                    StaticLabel = "GameCullSize_Static",
                    SourceLabel = "GameCullSize_Source",
                    Anchor = anchor,
                    StringReferenceAddress = match.InstructionAddress,
                    XrefFunction = function,
                    SourceFunction = function,
                    Match = match,
                    Score = 45,
                };
                result.Reasons.Add("matched FOO-result static subtract shape");
                if (matches.Count == 1)
                {
                    result.Score += 30;
                    result.Reasons.Add("candidate is unique");
                }
                else
                {
                    result.Validations.Add("candidate hit count: " + matches.Count);
                }
                if (function != null && function.Contains(match.InstructionAddress))
                {
                    result.Score += 10;
                    result.Validations.Add("match is inside function body: " + Fmt(function));
                }
                if (Model.CallerCount(function) > 0)
                {
                    result.Score += 10;
                    result.Reasons.Add("containing function has direct callers");
                }
                if (Model.HasCallBefore(match.InstructionAddress, 0x80))
                {
                    result.Score += 15;
                    result.Reasons.Add("match follows a nearby function call");
                }
                if (Model.HasVectorZeroAfter(match.InstructionAddress, 0x40))
                {
                    result.Score += 15;
                    result.Reasons.Add("match is followed by vector-zero setup");
                }
                if (Model.Instructions.TryAt(match.InstructionAddress, out Instruction _))
                {
                    result.Score += 5;
                    result.Validations.Add("match starts on a decoded instruction");
                }
                candidates.Add(result);
            }
            return candidates;
        }
    }

    // Terrain rotation helper/selector: a function with a fixed prologue, two static LEAs
    // (table into RCX, rotator into RAX) and characteristic clamp/tile/scale/bounds constants.
    public sealed class TerrainRecipe : RecipeBase
    {
        private readonly bool _selector;

        public TerrainRecipe(CodeModel model, bool selector) : base(model)
        {
            _selector = selector;
        }

        public override string Name => _selector ? "Terrain Rotation Selector" : "Terrain Rotator Helper";
        public override string FailureReason => "terrain rotation helper function shape was not found.";

        public override List<RecoveryResult> Recover(List<StringHit> strings)
        {
            var matches = new List<OffsetMatch>();
            foreach (PdataFunction function in Model.Functions.Functions)
            {
                OffsetMatch match = Inspect(function);
                if (match != null)
                {
                    matches.Add(match);
                }
            }

            var anchor = new StringHit { Value = Name + " function shape", Address = Model.Image.ImageBase };
            string staticLabel = _selector ? "TerrainRotationSelector_Static" : "TerrainRotatorHelper_Static";
            string sourceLabel = _selector ? "TerrainRotationSelector_Source" : "TerrainRotatorHelper_Source";
            string shapeReason = _selector
                ? "matched Terrain Rotation Selector function shape"
                : "matched Terrain Rotator helper function shape";

            var candidates = new List<RecoveryResult>();
            foreach (OffsetMatch match in matches)
            {
                PdataFunction function = Model.FunctionContaining(match.InstructionAddress);
                var result = new RecoveryResult
                {
                    OffsetName = Name,
                    StaticLabel = staticLabel,
                    SourceLabel = sourceLabel,
                    Anchor = anchor,
                    StringReferenceAddress = match.InstructionAddress,
                    XrefFunction = function,
                    SourceFunction = function,
                    Match = match,
                    Score = 50,
                };
                result.Score += 20;
                result.Reasons.Add(shapeReason);
                if (matches.Count == 1)
                {
                    result.Score += 30;
                    result.Reasons.Add("candidate is unique");
                }
                else
                {
                    result.Validations.Add("candidate hit count: " + matches.Count);
                }
                if (function != null && function.Contains(match.InstructionAddress))
                {
                    result.Score += 10;
                    result.Validations.Add("match is inside function body: " + Fmt(function));
                }
                if (Model.CallerCount(function) == 1)
                {
                    result.Score += 10;
                    result.Reasons.Add(_selector ? "selector helper has a single direct caller" : "helper has a single direct caller");
                }
                if (Model.Instructions.TryAt(match.InstructionAddress, out Instruction _))
                {
                    result.Score += 10;
                    result.Validations.Add("match starts on a decoded instruction");
                }
                candidates.Add(result);
            }
            return candidates;
        }

        private OffsetMatch Inspect(PdataFunction function)
        {
            var window = new List<Instruction>(Model.InstructionsInWindow(function, function.Begin, 0xc0));
            if (window.Count < 40 || window.Count > 80)
            {
                return null;
            }
            if (!HasEntryShape(window))
            {
                return null;
            }

            bool tableFound = false, rotatorFound = false;
            bool clamp = false, tile = false, scale = false, bounds = false, readCall = false;
            Instruction tableLea = default, rotatorLea = default;

            foreach (Instruction instruction in window)
            {
                if (Insn.IsStaticLeaInto(instruction, Register.RCX))
                {
                    tableLea = instruction;
                    tableFound = true;
                }
                if (Insn.IsStaticLeaInto(instruction, Register.RAX))
                {
                    rotatorLea = instruction;
                    rotatorFound = true;
                }
                if (Insn.IsMovRegImm(instruction, Register.EAX, 0x8) || Insn.IsCmpRegReg(instruction, Register.R8D, Register.EAX))
                {
                    clamp = true;
                }
                if (Insn.IsMovRegImm(instruction, Register.EDX, 0x16))
                {
                    tile = true;
                }
                if (Insn.IsLeaIndexScale(instruction, Register.R8, Register.R8, 2))
                {
                    scale = true;
                }
                if (Insn.HasImmediateValue(instruction, 0x17))
                {
                    bounds = true;
                }
                if (instruction.Mnemonic == Mnemonic.Call && instruction.IP - function.Begin > 0x80)
                {
                    readCall = true;
                }
            }

            if (!tableFound || !rotatorFound || !clamp || !tile || !scale || !bounds || !readCall)
            {
                return null;
            }

            return _selector
                ? RipMatch(function.Begin, tableLea, 3, "terrain rotation selector function shape")
                : RipMatch(function.Begin, rotatorLea, 3, "terrain rotator helper function shape");
        }

        private static bool HasEntryShape(List<Instruction> window)
        {
            return window.Count >= 4
                && Insn.IsSubRegImm(window[0], Register.RSP, 0x38)
                && Insn.IsMovzx(window[1], Register.EAX, Register.R8L)
                && Insn.IsMovRegReg(window[2], Register.R10, Register.RCX)
                && Insn.IsMovRegReg(window[3], Register.R9, Register.RDX);
        }
    }
}
