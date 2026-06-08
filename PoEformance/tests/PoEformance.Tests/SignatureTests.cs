using System.Collections.Generic;
using PoEformance;
using Xunit;

namespace PoEformance.Tests
{
    public class SignatureMakerTests
    {
        [Fact]
        public void ProducesUniquePatternForRipInstruction()
        {
            PeImage image = TestPe.LoadImage();
            CodeModel model = CodeModel.Build(image);
            var sig = new SignatureMaker(model);

            var match = new OffsetMatch
            {
                MatchStart = TestPe.FuncA,
                InstructionAddress = TestPe.FuncA,
                Resolved = TestPe.QwordData,
                BytesToSkip = 3,
                PatternLength = 7,
                Kind = "test",
            };

            SignatureMaker.Pattern pattern = sig.MakeBestUnique(match);

            Assert.Equal(1, pattern.MatchCount);
            Assert.Equal(TestPe.FuncA, pattern.Start);
            Assert.Equal(3, pattern.BytesToSkip);
            Assert.Contains("^", pattern.Render());
        }

        [Fact]
        public void RenderMarksBytesToSkipAndWildcards()
        {
            var pattern = new SignatureMaker.Pattern
            {
                Bytes = new byte[] { 0x48, 0x39, 0x2D, 0, 0, 0, 0 },
                Mask = new bool[] { true, true, true, false, false, false, false },
                BytesToSkip = 3,
                Start = 0x140001000,
            };

            Assert.Equal("48 39 2D ^ ?? ?? ?? ??", pattern.Render());
        }
    }

    public class PatternSelfCheckTests
    {
        [Fact]
        public void AcceptsConsistentResult()
        {
            PeImage image = TestPe.LoadImage();
            var match = new OffsetMatch
            {
                PatternStart = TestPe.FuncA,
                BytesToSkip = 3,
                Resolved = TestPe.QwordData,
            };
            var result = new RecoveryResult { OffsetName = "test", Match = match };

            Assert.True(PatternSelfCheck.Verify(image, result, out string detail));
            Assert.Contains("0x140002000", detail);
        }

        [Fact]
        public void RejectsInconsistentResult()
        {
            PeImage image = TestPe.LoadImage();
            var match = new OffsetMatch
            {
                PatternStart = TestPe.FuncA,
                BytesToSkip = 3,
                Resolved = 0xDEAD, // wrong on purpose
            };
            var result = new RecoveryResult { OffsetName = "test", Match = match };

            Assert.False(PatternSelfCheck.Verify(image, result, out _));
        }
    }

    public class SupportTests
    {
        [Fact]
        public void ConfidenceThresholds()
        {
            Assert.Equal("high", Confidence.Label(85));
            Assert.Equal("medium", Confidence.Label(65));
            Assert.Equal("low", Confidence.Label(64));
        }

        [Fact]
        public void ProximityScoring()
        {
            var reasons = new List<string>();
            Assert.Equal(25, Scoring.Proximity(100, 110, 0x40, 25, "x", reasons));
            Assert.Single(reasons);
            Assert.Equal(0, Scoring.Proximity(100, 0x500, 0x40, 25, "x", new List<string>()));
        }

        [Fact]
        public void RefsToBelowThresholdScoresZero()
        {
            CodeModel model = CodeModel.Build(TestPe.LoadImage());
            // QwordData is referenced once -> below the >=2 threshold -> no score.
            Assert.Equal(0, Scoring.RefsTo(model, TestPe.QwordData, 15, new List<string>(), new List<string>()));
        }

        [Fact]
        public void JsonExportContainsOffsetFields()
        {
            var match = new OffsetMatch
            {
                Resolved = 0x140002000,
                PatternStart = 0x140001000,
                Pattern = "48 8B 05 ^ ?? ?? ?? ??",
                BytesToSkip = 3,
                PatternMatchCount = 1,
            };
            var result = new RecoveryResult
            {
                OffsetName = "Game States",
                StaticLabel = "GameStates_Static",
                Score = 95,
                Match = match,
                SourceFunction = new PdataFunction { Begin = 0x140001000, End = 0x140001010 },
            };

            string json = JsonExport.Build("PathOfExile.exe", 0x140000000,
                new List<RecoveryResult> { result }, new List<string>());

            Assert.Contains("\"name\": \"Game States\"", json);
            Assert.Contains("\"resolvedAddress\": \"0x140002000\"", json);
            Assert.Contains("\"patternMatches\": 1", json);
            Assert.Contains("\"confidence\": \"high\"", json);
        }
    }
}
