using System.Collections.Generic;
using System.IO;
using Iced.Intel;
using PoEformance;
using Xunit;

namespace PoEformance.Tests
{
    public class PeImageTests
    {
        [Fact]
        public void ParsesHeadersSectionsAndPdata()
        {
            PeImage image = TestPe.LoadImage();

            Assert.Equal(TestPe.ImageBase, image.ImageBase);
            Assert.Equal(TestPe.ImageBase + TestPe.TextRva, image.EntryPoint);
            Assert.Equal(2, image.RuntimeFunctions.Count);
            Assert.Equal(3, image.Sections.Count);
        }

        [Fact]
        public void ReadsBytesAndExecutability()
        {
            PeImage image = TestPe.LoadImage();

            Assert.Equal(0x48, image.ReadByte(TestPe.FuncA));
            byte[] head = image.ReadBytes(TestPe.FuncA, 3);
            Assert.Equal((byte)0x48, head[0]);
            Assert.Equal((byte)0x8B, head[1]);
            Assert.Equal((byte)0x05, head[2]);
            Assert.True(image.IsExecutable(TestPe.FuncA));
            Assert.False(image.IsExecutable(TestPe.ModsString));
            Assert.Equal(".rdata", image.SectionForVa(TestPe.ModsString).Name);
            Assert.Equal(-1, image.ReadByte(0x130000000UL)); // unmapped
        }

        [Fact]
        public void RejectsGarbage()
        {
            Assert.Throws<InvalidDataException>(() => TestPe.LoadBytes(new byte[0x100]));

            byte[] badLfanew = TestPe.Build();
            badLfanew[0x3C] = 0xFF;
            badLfanew[0x3D] = 0xFF;
            badLfanew[0x3E] = 0xFF;
            badLfanew[0x3F] = 0x7F; // huge e_lfanew
            Assert.Throws<InvalidDataException>(() => TestPe.LoadBytes(badLfanew));
        }
    }

    public class FunctionTableTests
    {
        private static FunctionTable Build()
        {
            return new FunctionTable(new List<PdataFunction>
            {
                new PdataFunction { Begin = 0x2000, End = 0x2010 },
                new PdataFunction { Begin = 0x1000, End = 0x1010 }, // out of order on purpose
                new PdataFunction { Begin = 0x1000, End = 0x1010 }, // duplicate begin
            });
        }

        [Fact]
        public void SortsAndDeduplicates()
        {
            FunctionTable table = Build();
            Assert.Equal(2, table.Functions.Count);
            Assert.Equal(0x1000UL, table.Functions[0].Begin);
            Assert.Equal(0x2000UL, table.Functions[1].Begin);
        }

        [Fact]
        public void ContainingAtAndEntry()
        {
            FunctionTable table = Build();
            Assert.Equal(0x1000UL, table.Containing(0x1008).Begin);
            Assert.Null(table.Containing(0x1010));  // exclusive end
            Assert.Null(table.Containing(0x0fff));
            Assert.NotNull(table.At(0x2000));
            Assert.Null(table.At(0x2008));           // inside, not entry
            Assert.True(table.IsEntry(0x1000));
            Assert.False(table.IsEntry(0x1234));
        }
    }

    public class CodeModelTests
    {
        [Fact]
        public void DiscoversPdataFunctionsAndSweptCallTarget()
        {
            CodeModel model = CodeModel.Build(TestPe.LoadImage());

            Assert.Equal(1, model.SyntheticFunctionCount);      // C, missing from .pdata
            Assert.Equal(3, model.Functions.Functions.Count);   // A, B (.pdata) + C (sweep)
            Assert.Equal(TestPe.FuncA, model.FunctionContaining(TestPe.FuncA).Begin);
            Assert.Equal(TestPe.FuncA + 0x12, model.FunctionContaining(TestPe.FuncA).End);
            Assert.Equal(TestPe.FuncC, model.FunctionContaining(TestPe.FuncC).Begin);
        }

        [Fact]
        public void BuildsXrefsAndCallGraph()
        {
            CodeModel model = CodeModel.Build(TestPe.LoadImage());

            Assert.Contains(TestPe.FuncA, model.Xrefs.To(TestPe.QwordData)); // MOV reads the qword
            Assert.Equal(1, model.Xrefs.CountTo(TestPe.FuncB));              // A calls B once
            Assert.Equal(1, model.CallerCount(model.Functions.At(TestPe.FuncB)));

            PdataFunction a = model.Functions.At(TestPe.FuncA);
            Assert.Equal(2, model.DirectCallsToDepth(a, 2).Count);          // B and C
            Assert.Single(model.DirectCallsBefore(a, TestPe.FuncA + 0x0C)); // only B before the 2nd CALL
            Assert.Equal(1, model.CallDepth(a, model.Functions.At(TestPe.FuncB), 2));
        }

        [Fact]
        public void WindowAndProximityHelpers()
        {
            CodeModel model = CodeModel.Build(TestPe.LoadImage());
            PdataFunction a = model.Functions.At(TestPe.FuncA);

            var window = new List<Instruction>(model.InstructionsInWindow(a, a.Begin, 0x40));
            Assert.Equal(4, window.Count); // MOV, CALL, CALL, RET
            Assert.True(model.HasNearbyRet(TestPe.FuncA, 0x20));
            Assert.True(model.HasCallBefore(TestPe.FuncA + 0x11, 0x80));
        }
    }

    public class InstructionIndexTests
    {
        [Fact]
        public void NavigatesByAddress()
        {
            CodeModel model = CodeModel.Build(TestPe.LoadImage());
            InstructionIndex index = model.Instructions;

            Assert.True(index.TryAt(TestPe.FuncA, out Instruction mov));
            Assert.Equal(Mnemonic.Mov, mov.Mnemonic);

            Assert.True(index.TryAfter(TestPe.FuncA, out Instruction call));
            Assert.Equal(Mnemonic.Call, call.Mnemonic);
            Assert.Equal(TestPe.CallBSite, call.IP);

            Assert.False(index.TryBefore(TestPe.FuncA, out _)); // nothing precedes A

            var first = new List<Instruction>(index.Range(TestPe.FuncA, TestPe.FuncA + 7));
            Assert.Single(first); // just the MOV
        }
    }

    public class StringScannerAndAnchorTests
    {
        [Fact]
        public void FindsAsciiStrings()
        {
            List<StringHit> strings = StringScanner.Scan(TestPe.LoadImage());

            Assert.Contains(strings, s => s.Value == "Mods.dat" && s.Address == TestPe.ModsString);
            Assert.Contains(strings, s => s.Value == "Hello" && s.Address == TestPe.HelloString);
        }

        [Fact]
        public void AnchorSpecMatching()
        {
            Assert.True(AnchorSpec.Exact("InGameState").Matches("InGameState"));
            Assert.False(AnchorSpec.Exact("InGameState").Matches("Unable to get InGameState"));
            Assert.True(AnchorSpec.Contains("InGameState").Matches("Unable to get InGameState"));
            Assert.True(AnchorSpec.FileName("Mods.dat").Matches("Mods.dat"));
            Assert.True(AnchorSpec.FileName("Mods.dat").Matches("Art/2DItems/Foo/Mods.dat"));
            Assert.True(AnchorSpec.FileName("Mods.dat").Matches(@"C:\games\Mods.dat"));
            Assert.False(AnchorSpec.FileName("Mods.dat").Matches("NotMods.dat.bak"));
        }
    }
}
