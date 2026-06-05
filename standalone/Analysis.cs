using System;
using System.Collections.Generic;
using Iced.Intel;

namespace OffsetRecovery.Standalone
{
    // Function recovered from the PE exception directory (.pdata). On x64 Windows
    // this gives us accurate [begin, end) bounds without any heuristic analysis,
    // which is exactly what Ghidra's getFunctionContaining/getBody provided.
    public sealed class PdataFunction
    {
        public ulong Begin;
        public ulong End;
        public string Name => "FUN_" + Begin.ToString("x");
        public bool Contains(ulong va) => va >= Begin && va < End;
    }

    public sealed class FunctionTable
    {
        private readonly PdataFunction[] _functions; // sorted by Begin
        private readonly HashSet<ulong> _entries = new HashSet<ulong>();

        public FunctionTable(PeImage image)
        {
            var list = new List<PdataFunction>();
            foreach (PeImage.RuntimeFunction rf in image.RuntimeFunctions)
            {
                list.Add(new PdataFunction { Begin = rf.Begin, End = rf.End });
                _entries.Add(rf.Begin);
            }
            list.Sort((a, b) => a.Begin.CompareTo(b.Begin));

            // .pdata can contain multiple chunks per function; collapse exact-duplicate begins.
            var deduped = new List<PdataFunction>();
            ulong lastBegin = ulong.MaxValue;
            foreach (PdataFunction fn in list)
            {
                if (fn.Begin != lastBegin)
                {
                    deduped.Add(fn);
                    lastBegin = fn.Begin;
                }
            }
            _functions = deduped.ToArray();
        }

        public IReadOnlyList<PdataFunction> Functions => _functions;

        public PdataFunction Containing(ulong va)
        {
            int lo = 0;
            int hi = _functions.Length - 1;
            while (lo <= hi)
            {
                int mid = (lo + hi) >> 1;
                PdataFunction fn = _functions[mid];
                if (va < fn.Begin)
                {
                    hi = mid - 1;
                }
                else if (va >= fn.End)
                {
                    lo = mid + 1;
                }
                else
                {
                    return fn;
                }
            }
            return null;
        }

        public PdataFunction At(ulong va)
        {
            PdataFunction fn = Containing(va);
            return fn != null && fn.Begin == va ? fn : null;
        }

        public bool IsEntry(ulong va) => _entries.Contains(va);
    }

    // Linear disassembly index built per-function from .pdata bounds. Decoding each
    // function range separately avoids desync on data-in-code between functions.
    public sealed class InstructionIndex
    {
        private readonly ulong[] _ips;       // sorted instruction addresses
        private readonly Instruction[] _all; // parallel to _ips

        public InstructionIndex(List<Instruction> instructions)
        {
            instructions.Sort((a, b) => a.IP.CompareTo(b.IP));
            _all = instructions.ToArray();
            _ips = new ulong[_all.Length];
            for (int i = 0; i < _all.Length; i++)
            {
                _ips[i] = _all[i].IP;
            }
        }

        public IReadOnlyList<Instruction> All => _all;

        private int IndexOf(ulong va) => Array.BinarySearch(_ips, va);

        public bool TryAt(ulong va, out Instruction instruction)
        {
            int idx = IndexOf(va);
            if (idx >= 0)
            {
                instruction = _all[idx];
                return true;
            }
            instruction = default;
            return false;
        }

        public bool TryAfter(ulong va, out Instruction instruction)
        {
            int idx = IndexOf(va);
            int next = idx >= 0 ? idx + 1 : ~idx;
            if (next >= 0 && next < _all.Length)
            {
                instruction = _all[next];
                return true;
            }
            instruction = default;
            return false;
        }

        public bool TryBefore(ulong va, out Instruction instruction)
        {
            int idx = IndexOf(va);
            int prev = idx >= 0 ? idx - 1 : ~idx - 1;
            if (prev >= 0 && prev < _all.Length)
            {
                instruction = _all[prev];
                return true;
            }
            instruction = default;
            return false;
        }

        // Instructions with IP in [start, endExclusive).
        public IEnumerable<Instruction> Range(ulong start, ulong endExclusive)
        {
            int idx = IndexOf(start);
            int i = idx >= 0 ? idx : ~idx;
            for (; i < _all.Length && _ips[i] < endExclusive; i++)
            {
                yield return _all[i];
            }
        }
    }

    // address -> instruction addresses that reference it (data refs and branch/call targets).
    // This reconstructs Ghidra's getReferencesTo / getReferencesFrom for our needs.
    public sealed class XrefMap
    {
        private readonly Dictionary<ulong, List<ulong>> _to = new Dictionary<ulong, List<ulong>>();

        public void Add(ulong target, ulong fromInstruction)
        {
            if (!_to.TryGetValue(target, out List<ulong> list))
            {
                list = new List<ulong>();
                _to[target] = list;
            }
            list.Add(fromInstruction);
        }

        public IReadOnlyList<ulong> To(ulong target)
        {
            return _to.TryGetValue(target, out List<ulong> list) ? list : Array.Empty<ulong>();
        }

        public int CountTo(ulong target) => To(target).Count;
    }

    // Facade that ties the PE image, function table, instruction index and xref map
    // together — the standalone equivalent of Ghidra's analysed program database.
    public sealed class CodeModel
    {
        public PeImage Image { get; }
        public FunctionTable Functions { get; }
        public InstructionIndex Instructions { get; }
        public XrefMap Xrefs { get; }

        private CodeModel(PeImage image, FunctionTable functions, InstructionIndex instructions, XrefMap xrefs)
        {
            Image = image;
            Functions = functions;
            Instructions = instructions;
            Xrefs = xrefs;
        }

        public static CodeModel Build(PeImage image)
        {
            var functions = new FunctionTable(image);
            var decoded = new List<Instruction>();
            var xrefs = new XrefMap();

            foreach (PdataFunction fn in functions.Functions)
            {
                int length = (int)(fn.End - fn.Begin);
                if (length <= 0 || length > 0x100000)
                {
                    continue;
                }

                byte[] bytes = image.ReadBytes(fn.Begin, length);
                var decoder = Decoder.Create(64, new ByteArrayCodeReader(bytes), fn.Begin);
                while (decoder.IP < fn.End)
                {
                    Instruction instruction = decoder.Decode();
                    if (instruction.IsInvalid)
                    {
                        break;
                    }
                    decoded.Add(instruction);
                    RecordReferences(instruction, xrefs);
                }
            }

            var index = new InstructionIndex(decoded);
            return new CodeModel(image, functions, index, xrefs);
        }

        private static void RecordReferences(Instruction instruction, XrefMap xrefs)
        {
            if (instruction.IsIPRelativeMemoryOperand)
            {
                xrefs.Add(instruction.IPRelativeMemoryAddress, instruction.IP);
            }

            switch (instruction.FlowControl)
            {
                case FlowControl.Call:
                case FlowControl.ConditionalBranch:
                case FlowControl.UnconditionalBranch:
                    if (instruction.Op0Kind == OpKind.NearBranch64)
                    {
                        xrefs.Add(instruction.NearBranchTarget, instruction.IP);
                    }
                    break;
            }
        }

        public PdataFunction FunctionContaining(ulong va) => Functions.Containing(va);

        // Instructions starting within [start, start + maxBytes], capped at the function end.
        public IEnumerable<Instruction> InstructionsInWindow(PdataFunction function, ulong start, int maxBytes)
        {
            ulong end = start + (ulong)maxBytes + 1;
            if (end > function.End)
            {
                end = function.End;
            }
            return Instructions.Range(start, end);
        }

        // Direct CALLs to known function entries within [function, beforeAddress).
        public List<PdataFunction> DirectCallsBefore(PdataFunction function, ulong beforeAddress)
        {
            var result = new List<PdataFunction>();
            var seen = new HashSet<ulong>();
            foreach (Instruction instruction in Instructions.Range(function.Begin, function.End))
            {
                if (beforeAddress != 0 && instruction.IP >= beforeAddress)
                {
                    break;
                }
                if (instruction.FlowControl != FlowControl.Call || instruction.Op0Kind != OpKind.NearBranch64)
                {
                    continue;
                }

                ulong target = instruction.NearBranchTarget;
                PdataFunction called = Functions.At(target);
                if (called != null && seen.Add(called.Begin))
                {
                    result.Add(called);
                }
            }
            return result;
        }

        public List<PdataFunction> DirectCalls(PdataFunction function) => DirectCallsBefore(function, 0);

        public List<PdataFunction> DirectCallsToDepth(PdataFunction root, int maxDepth)
        {
            var result = new List<PdataFunction>();
            var seen = new HashSet<ulong>();
            var frontier = new List<KeyValuePair<PdataFunction, int>> { new KeyValuePair<PdataFunction, int>(root, 0) };

            for (int i = 0; i < frontier.Count; i++)
            {
                KeyValuePair<PdataFunction, int> current = frontier[i];
                if (current.Value >= maxDepth)
                {
                    continue;
                }
                foreach (PdataFunction called in DirectCalls(current.Key))
                {
                    if (seen.Add(called.Begin))
                    {
                        result.Add(called);
                        frontier.Add(new KeyValuePair<PdataFunction, int>(called, current.Value + 1));
                    }
                }
            }
            return result;
        }

        public int CallDepth(PdataFunction root, PdataFunction target, int maxDepth)
        {
            if (target == null)
            {
                return -1;
            }
            if (root.Begin == target.Begin)
            {
                return 0;
            }

            var seen = new HashSet<ulong>();
            var frontier = new List<KeyValuePair<PdataFunction, int>> { new KeyValuePair<PdataFunction, int>(root, 0) };
            for (int i = 0; i < frontier.Count; i++)
            {
                KeyValuePair<PdataFunction, int> current = frontier[i];
                if (current.Value >= maxDepth)
                {
                    continue;
                }
                foreach (PdataFunction called in DirectCalls(current.Key))
                {
                    if (called.Begin == target.Begin)
                    {
                        return current.Value + 1;
                    }
                    if (seen.Add(called.Begin))
                    {
                        frontier.Add(new KeyValuePair<PdataFunction, int>(called, current.Value + 1));
                    }
                }
            }
            return -1;
        }

        public int CallerCount(PdataFunction function)
        {
            if (function == null)
            {
                return 0;
            }
            int count = 0;
            foreach (ulong fromIp in Xrefs.To(function.Begin))
            {
                if (Instructions.TryAt(fromIp, out Instruction instruction) && instruction.FlowControl == FlowControl.Call)
                {
                    count++;
                }
            }
            return count;
        }

        public bool HasCallBefore(ulong address, int maxBytes)
        {
            PdataFunction function = FunctionContaining(address);
            if (function == null)
            {
                return false;
            }
            foreach (Instruction instruction in Instructions.Range(function.Begin, address))
            {
                if (instruction.Mnemonic == Mnemonic.Call && address - instruction.IP <= (ulong)maxBytes)
                {
                    return true;
                }
            }
            return false;
        }

        public bool HasNearbyRet(ulong address, int maxBytes)
        {
            foreach (Instruction instruction in Instructions.Range(address, address + (ulong)maxBytes + 1))
            {
                if (instruction.FlowControl == FlowControl.Return)
                {
                    return true;
                }
            }
            return false;
        }

        public bool HasVectorZeroAfter(ulong address, int maxBytes)
        {
            if (!Instructions.TryAfter(address, out Instruction instruction))
            {
                return false;
            }
            while (instruction.IP - address <= (ulong)maxBytes)
            {
                if (Insn.IsVectorZero(instruction))
                {
                    return true;
                }
                if (!Instructions.TryAfter(instruction.IP, out instruction))
                {
                    break;
                }
            }
            return false;
        }
    }
}
