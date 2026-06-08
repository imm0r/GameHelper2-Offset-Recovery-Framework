using System;
using System.Collections.Generic;
using System.Text;
using Iced.Intel;

namespace PoEformance
{
    // Builds a SigMaker-style byte pattern and proves it is unique in executable
    // memory. Faithful port of the Ghidra script's ripPattern / makeUniquePattern /
    // makeBestUniquePattern / countExecutableMatches.
    public sealed class SignatureMaker
    {
        private const int MaxPatternBytes = 0x80;

        private readonly PeImage _image;
        private readonly InstructionIndex _index;
        private readonly FunctionTable _functions;

        public SignatureMaker(CodeModel model)
        {
            _image = model.Image;
            _index = model.Instructions;
            _functions = model.Functions;
        }

        public sealed class Pattern
        {
            public byte[] Bytes;
            public bool[] Mask;     // true = fixed byte, false = wildcard
            public int BytesToSkip; // offset of the resolved address inside the pattern
            public ulong Start;     // VA the pattern begins at
            public int MatchCount;

            public int FixedCount
            {
                get
                {
                    int n = 0;
                    foreach (bool m in Mask)
                    {
                        if (m) n++;
                    }
                    return n;
                }
            }

            public string Render()
            {
                var sb = new StringBuilder();
                for (int i = 0; i < Bytes.Length; i++)
                {
                    if (i > 0) sb.Append(' ');
                    if (i == BytesToSkip) sb.Append("^ ");
                    sb.Append(Mask[i] ? Bytes[i].ToString("X2") : "??");
                }
                return sb.ToString();
            }
        }

        // Try several start addresses (the match start, the target instruction, earlier
        // instructions, the function entry) and keep the shortest unique pattern. This is
        // what lets a match anchored at a function entry (terrain recipes) still produce a
        // compact signature around the target instruction.
        public Pattern MakeBestUnique(OffsetMatch match)
        {
            int minimumLength = match.PatternLength;
            int originalInstructionOffset = (int)(match.InstructionAddress - match.MatchStart);
            int displacementOffsetInInstruction = match.BytesToSkip - originalInstructionOffset;
            int originalTailLength = minimumLength - originalInstructionOffset;

            Pattern best = null;
            foreach (ulong start in StartCandidates(match))
            {
                if (start > match.InstructionAddress)
                {
                    continue;
                }

                int instructionOffset = (int)(match.InstructionAddress - start);
                int bytesToSkip = instructionOffset + displacementOffsetInInstruction;
                int candidateMinimumLength = Math.Max(instructionOffset + originalTailLength, bytesToSkip + 4);
                if (bytesToSkip < 0 || candidateMinimumLength > MaxPatternBytes)
                {
                    continue;
                }

                Pattern candidate = MakeUnique(start, candidateMinimumLength, bytesToSkip);
                if (best == null || IsBetter(candidate, best))
                {
                    best = candidate;
                }
                if (candidate.MatchCount == 1 && candidate.Bytes.Length <= minimumLength)
                {
                    return candidate;
                }
            }

            return best ?? MakeUnique(match.MatchStart, minimumLength, match.BytesToSkip);
        }

        private List<ulong> StartCandidates(OffsetMatch match)
        {
            var starts = new List<ulong>();
            var seen = new HashSet<ulong>();

            void Add(ulong address)
            {
                if (seen.Add(address))
                {
                    starts.Add(address);
                }
            }

            Add(match.MatchStart);
            Add(match.InstructionAddress);

            PdataFunction function = _functions.Containing(match.InstructionAddress);
            ulong cursor = match.InstructionAddress;
            int count = 0;
            while (count < 16
                && _index.TryBefore(cursor, out Instruction previous)
                && match.InstructionAddress - previous.IP <= 0x60
                && (function == null || function.Contains(previous.IP)))
            {
                Add(previous.IP);
                cursor = previous.IP;
                count++;
            }

            if (function != null)
            {
                Add(function.Begin);
            }
            return starts;
        }

        // Extend the pattern instruction-by-instruction until it is unique.
        public Pattern MakeUnique(ulong start, int minimumLength, int bytesToSkip)
        {
            int length = AlignLengthToInstruction(start, minimumLength);
            Pattern best = null;

            while (length <= MaxPatternBytes)
            {
                Pattern candidate = Build(start, length, bytesToSkip);
                candidate.MatchCount = CountExecutableMatches(candidate, 2);
                if (best == null || IsBetter(candidate, best))
                {
                    best = candidate;
                }
                if (candidate.MatchCount == 1)
                {
                    return candidate;
                }

                int next = NextInstructionAlignedLength(start, length);
                if (next <= length)
                {
                    break;
                }
                length = next;
            }
            return best ?? Build(start, minimumLength, bytesToSkip);
        }

        public Pattern Build(ulong start, int length, int bytesToSkip)
        {
            byte[] bytes = _image.ReadBytes(start, length);
            bool[] mask = new bool[length];
            for (int i = 0; i < length; i++)
            {
                mask[i] = true;
            }

            Wildcard(mask, bytesToSkip, 4);
            MarkReferencedDisplacements(start, length, mask);

            return new Pattern { Bytes = bytes, Mask = mask, BytesToSkip = bytesToSkip, Start = start };
        }

        private void MarkReferencedDisplacements(ulong start, int length, bool[] mask)
        {
            ulong end = start + (ulong)length;
            foreach (Instruction instruction in _index.Range(start, end))
            {
                int instructionOffset = (int)(instruction.IP - start);
                ulong nextIp = instruction.IP + (ulong)instruction.Length;

                if (instruction.IsIPRelativeMemoryOperand)
                {
                    int displacement = (int)(long)(instruction.IPRelativeMemoryAddress - nextIp);
                    MarkValueBytes(instruction, instructionOffset, displacement, mask);
                }

                bool isBranch = instruction.FlowControl == FlowControl.Call
                    || instruction.FlowControl == FlowControl.ConditionalBranch
                    || instruction.FlowControl == FlowControl.UnconditionalBranch;
                if (isBranch && instruction.Op0Kind == OpKind.NearBranch64)
                {
                    int relative = (int)(long)(instruction.NearBranchTarget - nextIp);
                    MarkValueBytes(instruction, instructionOffset, relative, mask);
                }
            }
        }

        // Find the 4-byte little-endian occurrence of 'value' inside the instruction
        // and wildcard it (the displacement / relative target shifts every build).
        private void MarkValueBytes(Instruction instruction, int instructionOffset, int value, bool[] mask)
        {
            byte[] bytes = _image.ReadBytes(instruction.IP, instruction.Length);
            for (int i = 0; i + 4 <= bytes.Length; i++)
            {
                if (bytes[i] == (byte)(value & 0xff)
                    && bytes[i + 1] == (byte)((value >> 8) & 0xff)
                    && bytes[i + 2] == (byte)((value >> 16) & 0xff)
                    && bytes[i + 3] == (byte)((value >> 24) & 0xff))
                {
                    Wildcard(mask, instructionOffset + i, 4);
                    return;
                }
            }
        }

        private static void Wildcard(bool[] mask, int offset, int length)
        {
            for (int i = Math.Max(0, offset); i < offset + length && i < mask.Length; i++)
            {
                mask[i] = false;
            }
        }

        public int CountExecutableMatches(Pattern pattern, int stopAfter)
        {
            int firstFixed = -1;
            for (int i = 0; i < pattern.Mask.Length; i++)
            {
                if (pattern.Mask[i])
                {
                    firstFixed = i;
                    break;
                }
            }
            if (firstFixed < 0)
            {
                return stopAfter; // all wildcards: treat as non-unique
            }

            byte anchor = pattern.Bytes[firstFixed];
            int count = 0;
            foreach (PeImage.Section section in _image.Sections)
            {
                if (!section.Executable)
                {
                    continue;
                }
                byte[] data = section.Raw;
                int last = data.Length - pattern.Bytes.Length;
                for (int p = 0; p <= last; p++)
                {
                    if (data[p + firstFixed] != anchor)
                    {
                        continue;
                    }
                    if (Matches(data, p, pattern))
                    {
                        count++;
                        if (count >= stopAfter)
                        {
                            return count;
                        }
                    }
                }
            }
            return count;
        }

        private static bool Matches(byte[] data, int position, Pattern pattern)
        {
            for (int i = 0; i < pattern.Bytes.Length; i++)
            {
                if (pattern.Mask[i] && data[position + i] != pattern.Bytes[i])
                {
                    return false;
                }
            }
            return true;
        }

        private int AlignLengthToInstruction(ulong start, int minimumLength)
        {
            int aligned = 0;
            ulong cursor = start;
            while (aligned < minimumLength && _index.TryAt(cursor, out Instruction instruction))
            {
                aligned = (int)(instruction.IP - start) + instruction.Length;
                cursor = instruction.IP + (ulong)instruction.Length;
            }
            return Math.Max(minimumLength, aligned);
        }

        private int NextInstructionAlignedLength(ulong start, int currentLength)
        {
            ulong currentEnd = start + (ulong)currentLength - 1;
            if (!_index.TryAfter(currentEnd, out Instruction instruction))
            {
                return -1;
            }
            return (int)(instruction.IP - start) + instruction.Length;
        }

        private static bool IsBetter(Pattern candidate, Pattern other)
        {
            if (candidate.MatchCount != other.MatchCount)
            {
                return candidate.MatchCount < other.MatchCount;
            }
            if (candidate.Bytes.Length != other.Bytes.Length)
            {
                return candidate.Bytes.Length < other.Bytes.Length;
            }
            return candidate.FixedCount > other.FixedCount;
        }
    }
}
