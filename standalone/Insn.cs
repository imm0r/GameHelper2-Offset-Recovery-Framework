using Iced.Intel;

namespace OffsetRecovery.Standalone
{
    // Structural instruction predicates. The Ghidra script matched on formatted
    // text (e.g. startsWith("MOV RAX,")); here we match on decoded structure
    // (mnemonic, operand kinds, registers, memory size), which is more robust.
    public static class Insn
    {
        // CMP qword ptr [rip+x], RBP   /   CMP qword ptr [rip+x], 0
        public static bool IsStaticQwordNullCheck(Instruction i)
        {
            if (i.Mnemonic != Mnemonic.Cmp || !i.IsIPRelativeMemoryOperand)
            {
                return false;
            }
            if (i.MemorySize != MemorySize.UInt64 && i.MemorySize != MemorySize.Int64)
            {
                return false;
            }
            if (i.Op1Kind == OpKind.Register && i.Op1Register == Register.RBP)
            {
                return true;
            }
            return IsImmediate(i.Op1Kind) && i.GetImmediate(1) == 0;
        }

        // MOV RAX, qword ptr [rip+x]
        public static bool IsStaticMovIntoRax(Instruction i)
        {
            return i.Mnemonic == Mnemonic.Mov
                && i.IsIPRelativeMemoryOperand
                && i.Op0Kind == OpKind.Register
                && i.Op0Register == Register.RAX;
        }

        // INC dword ptr [rip+x]
        public static bool IsStaticDwordIncrement(Instruction i)
        {
            return i.Mnemonic == Mnemonic.Inc
                && i.IsIPRelativeMemoryOperand
                && (i.MemorySize == MemorySize.UInt32 || i.MemorySize == MemorySize.Int32);
        }

        // SUB EAX, dword ptr [rip+x]
        public static bool IsStaticSubFromEax(Instruction i)
        {
            return i.Mnemonic == Mnemonic.Sub
                && i.Op0Kind == OpKind.Register
                && i.Op0Register == Register.EAX
                && i.IsIPRelativeMemoryOperand;
        }

        // LEA <reg>, [rip+x]
        public static bool IsStaticLeaInto(Instruction i, Register register)
        {
            return i.Mnemonic == Mnemonic.Lea
                && i.IsIPRelativeMemoryOperand
                && i.Op0Kind == OpKind.Register
                && i.Op0Register == register;
        }

        // TLS access: gs:[0x58] or fs:[0x58]
        public static bool IsThreadLocalAccess(Instruction i)
        {
            if (i.SegmentPrefix != Register.GS && i.SegmentPrefix != Register.FS)
            {
                return false;
            }
            return i.MemoryDisplacement64 == 0x58;
        }

        public static bool IsVectorZero(Instruction i)
        {
            return i.Mnemonic == Mnemonic.Xorps
                || i.Mnemonic == Mnemonic.Pxor
                || i.Mnemonic == Mnemonic.Xorpd;
        }

        public static bool IsMovRegReg(Instruction i, Register dst, Register src)
        {
            return i.Mnemonic == Mnemonic.Mov
                && i.Op0Kind == OpKind.Register && i.Op0Register == dst
                && i.Op1Kind == OpKind.Register && i.Op1Register == src;
        }

        public static bool IsMovRegImm(Instruction i, Register dst, ulong imm)
        {
            return i.Mnemonic == Mnemonic.Mov
                && i.Op0Kind == OpKind.Register && i.Op0Register == dst
                && IsImmediate(i.Op1Kind) && i.GetImmediate(1) == imm;
        }

        public static bool IsMovzx(Instruction i, Register dst, Register src)
        {
            return i.Mnemonic == Mnemonic.Movzx
                && i.Op0Kind == OpKind.Register && i.Op0Register == dst
                && i.Op1Kind == OpKind.Register && i.Op1Register == src;
        }

        public static bool IsSubRegImm(Instruction i, Register dst, ulong imm)
        {
            return i.Mnemonic == Mnemonic.Sub
                && i.Op0Kind == OpKind.Register && i.Op0Register == dst
                && IsImmediate(i.Op1Kind) && i.GetImmediate(1) == imm;
        }

        public static bool IsCmpRegReg(Instruction i, Register a, Register b)
        {
            return i.Mnemonic == Mnemonic.Cmp
                && i.Op0Kind == OpKind.Register && i.Op0Register == a
                && i.Op1Kind == OpKind.Register && i.Op1Register == b;
        }

        // LEA <dst>, [base + index*scale]
        public static bool IsLeaIndexScale(Instruction i, Register dst, Register index, int scale)
        {
            return i.Mnemonic == Mnemonic.Lea
                && i.Op0Kind == OpKind.Register && i.Op0Register == dst
                && i.MemoryIndex == index && i.MemoryIndexScale == scale;
        }

        // Any immediate operand equal to value (Ghidra script matched text "0X17").
        public static bool HasImmediateValue(Instruction i, ulong value)
        {
            for (int op = 0; op < i.OpCount; op++)
            {
                if (IsImmediate(i.GetOpKind(op)) && i.GetImmediate(op) == value)
                {
                    return true;
                }
            }
            return false;
        }

        public static bool IsImmediate(OpKind kind)
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
    }
}
