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
        public OffsetMatch Match;
        public int Score;
        public readonly List<string> Reasons = new List<string>();
        public readonly List<string> Validations = new List<string>();
    }

    // Port of the Ghidra GameStatesRecipe:
    //   anchor string "Unable to get InGameState" -> XREF caller
    //     -> provider call before the error branch
    //       -> CMP qword ptr [static], RBP/0  (the global game-state pointer)
    public sealed class GameStatesRecipe
    {
        private const int MaxProviderScanBytes = 0x180;

        private readonly CodeModel _model;

        private static readonly AnchorSpec[] Anchors =
        {
            AnchorSpec.Exact("Unable to get InGameState"),
            AnchorSpec.Contains("InGameState"),
        };

        public GameStatesRecipe(CodeModel model)
        {
            _model = model;
        }

        public string Name => "Game States";

        public List<RecoveryResult> Recover(List<StringHit> strings)
        {
            var candidates = new List<RecoveryResult>();
            foreach (StringHit anchor in FindAnchors(strings))
            {
                foreach (ulong referenceFrom in _model.Xrefs.To(anchor.Address))
                {
                    PdataFunction xref = _model.FunctionContaining(referenceFrom);
                    if (xref == null)
                    {
                        continue;
                    }

                    foreach (PdataFunction provider in _model.DirectCallsBefore(xref, referenceFrom))
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

                        result.Score += Scoring.Proximity(
                            provider.Begin, match.InstructionAddress, 0x40, 25, "null-check", result.Reasons);
                        if (provider.Begin < xref.Begin)
                        {
                            result.Score += 10;
                            result.Reasons.Add("provider is a lower-address helper function");
                        }
                        result.Score += Scoring.RefsTo(_model, match.Resolved, 15, result.Reasons, result.Validations);
                        if (match.HasTrait("provider-prologue"))
                        {
                            result.Score += 10;
                            result.Reasons.Add("matched provider prologue context");
                        }
                        result.Validations.Add("provider function: " + provider.Name + " @ " + Hex(provider.Begin));

                        candidates.Add(result);
                    }
                }
            }
            return candidates;
        }

        private OffsetMatch FindStaticQwordNullCheck(PdataFunction function)
        {
            ulong end = Math.Min(function.Begin + MaxProviderScanBytes, function.End);
            foreach (Instruction instruction in _model.Instructions.Range(function.Begin, end))
            {
                if (!IsStaticQwordNullCheck(instruction))
                {
                    continue;
                }

                bool prologue = HasPreviousInstructionText(function, instruction.IP,
                    inst => inst.Mnemonic == Mnemonic.Xor
                        && inst.Op0Register == Register.EBP
                        && inst.Op1Register == Register.EBP);

                int length = instruction.Length;
                if (_model.Instructions.TryAfter(instruction.IP, out Instruction next)
                    && function.Contains(next.IP)
                    && next.FlowControl == FlowControl.ConditionalBranch)
                {
                    length += next.Length;
                }

                var match = new OffsetMatch
                {
                    MatchStart = instruction.IP,
                    InstructionAddress = instruction.IP,
                    Resolved = instruction.IPRelativeMemoryAddress,
                    BytesToSkip = 3,
                    PatternLength = length,
                    Kind = "static qword null-check",
                };
                if (prologue)
                {
                    match.Traits.Add("provider-prologue");
                }
                return match;
            }
            return null;
        }

        private static bool IsStaticQwordNullCheck(Instruction instruction)
        {
            if (instruction.Mnemonic != Mnemonic.Cmp || !instruction.IsIPRelativeMemoryOperand)
            {
                return false;
            }
            if (instruction.MemorySize != MemorySize.UInt64 && instruction.MemorySize != MemorySize.Int64)
            {
                return false;
            }
            if (instruction.Op1Kind == OpKind.Register && instruction.Op1Register == Register.RBP)
            {
                return true;
            }
            return IsImmediate(instruction.Op1Kind) && instruction.GetImmediate(1) == 0;
        }

        private bool HasPreviousInstructionText(PdataFunction function, ulong address, Func<Instruction, bool> predicate)
        {
            return _model.Instructions.TryBefore(address, out Instruction previous)
                && function.Contains(previous.IP)
                && predicate(previous);
        }

        private List<StringHit> FindAnchors(List<StringHit> strings)
        {
            var hits = new List<StringHit>();
            var seen = new HashSet<ulong>();
            foreach (AnchorSpec anchor in Anchors)
            {
                foreach (StringHit hit in strings)
                {
                    if (seen.Contains(hit.Address))
                    {
                        continue;
                    }
                    if (anchor.Matches(hit.Value))
                    {
                        hits.Add(hit);
                        seen.Add(hit.Address);
                    }
                }
            }
            return hits;
        }

        private static bool IsImmediate(OpKind kind)
        {
            switch (kind)
            {
                case OpKind.Immediate8:
                case OpKind.Immediate8_2nd:
                case OpKind.Immediate16:
                case OpKind.Immediate32:
                case OpKind.Immediate64:
                case OpKind.Immediate8to16:
                case OpKind.Immediate8to32:
                case OpKind.Immediate8to64:
                case OpKind.Immediate32to64:
                    return true;
                default:
                    return false;
            }
        }

        private static string Hex(ulong value) => "0x" + value.ToString("x");
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
}
