using Iced.Intel;
using OffsetRecovery.Standalone;
using Xunit;

namespace OffsetRecovery.Tests
{
    // Decode known opcode bytes and assert the structural predicates that drive the
    // recipes. These are the heuristics that decide what each offset matches.
    public class InsnTests
    {
        private static Instruction Decode(params byte[] code)
        {
            var decoder = Decoder.Create(64, new ByteArrayCodeReader(code), 0x140001000UL);
            return decoder.Decode();
        }

        [Fact]
        public void StaticMovIntoRax()
        {
            Instruction i = Decode(0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00); // MOV RAX,[rip+0]
            Assert.True(Insn.IsStaticMovIntoRax(i));
            Assert.False(Insn.IsStaticQwordNullCheck(i));
        }

        [Fact]
        public void QwordNullCheckAgainstRbp()
        {
            Assert.True(Insn.IsStaticQwordNullCheck(Decode(0x48, 0x39, 0x2D, 0, 0, 0, 0))); // CMP [rip],RBP
        }

        [Fact]
        public void QwordNullCheckAgainstZero()
        {
            Assert.True(Insn.IsStaticQwordNullCheck(Decode(0x48, 0x83, 0x3D, 0, 0, 0, 0, 0x00))); // CMP qword [rip],0
        }

        [Fact]
        public void DwordIncrement()
        {
            Assert.True(Insn.IsStaticDwordIncrement(Decode(0xFF, 0x05, 0, 0, 0, 0))); // INC dword [rip]
        }

        [Fact]
        public void SubFromEax()
        {
            Assert.True(Insn.IsStaticSubFromEax(Decode(0x2B, 0x05, 0, 0, 0, 0))); // SUB EAX,[rip]
        }

        [Fact]
        public void StaticLeaIntoRegister()
        {
            Instruction i = Decode(0x48, 0x8D, 0x0D, 0, 0, 0, 0); // LEA RCX,[rip]
            Assert.True(Insn.IsStaticLeaInto(i, Register.RCX));
            Assert.False(Insn.IsStaticLeaInto(i, Register.RAX));
        }

        [Fact]
        public void ThreadLocalAccess()
        {
            // MOV RAX, gs:[0x58]
            Assert.True(Insn.IsThreadLocalAccess(Decode(0x65, 0x48, 0x8B, 0x04, 0x25, 0x58, 0, 0, 0)));
        }

        [Fact]
        public void MovRegImmediate()
        {
            Instruction i = Decode(0xB8, 0x08, 0x00, 0x00, 0x00); // MOV EAX,8
            Assert.True(Insn.IsMovRegImm(i, Register.EAX, 0x8));
            Assert.False(Insn.IsMovRegImm(i, Register.EAX, 0x9));
        }

        [Fact]
        public void SubRegImmediateAndImmediateValue()
        {
            Instruction i = Decode(0x48, 0x83, 0xEC, 0x38); // SUB RSP,0x38
            Assert.True(Insn.IsSubRegImm(i, Register.RSP, 0x38));
            Assert.True(Insn.HasImmediateValue(i, 0x38));
            Assert.False(Insn.HasImmediateValue(i, 0x99));
        }

        [Fact]
        public void VectorZero()
        {
            Assert.True(Insn.IsVectorZero(Decode(0x0F, 0x57, 0xFF))); // XORPS XMM7,XMM7
        }
    }
}
