using System.Collections.Generic;
using OffsetRecovery.Standalone;
using Xunit;

namespace OffsetRecovery.Tests
{
    public class GameHelperPatcherTests
    {
        private static RecoveryResult Result(string name, string pattern)
        {
            return new RecoveryResult
            {
                OffsetName = name,
                Match = new OffsetMatch { Pattern = pattern, BytesToSkip = 3 },
            };
        }

        [Fact]
        public void UpdatesUnchangedAndMissingEntries()
        {
            const string gsOld = "48 39 2D ^ ?? ?? ?? ?? 11 11";
            const string gsNew = "48 39 2D ^ ?? ?? ?? ?? 22 22";
            const string frPat = "FF 05 ^ ?? ?? ?? ??";

            string source =
                "internal struct StaticOffsetsPatterns {\n" +
                "  static Pattern[] P = {\n" +
                "    new Pattern(\"Game States\", \"" + gsOld + "\"),\n" +
                "    new Pattern(\"File Root\", \"" + frPat + "\"),\n" +
                "  };\n" +
                "}\n";

            var successes = new List<RecoveryResult>
            {
                Result("Game States", gsNew),  // changed -> Updated
                Result("File Root", frPat),     // identical -> Unchanged
                Result("Ghost", "AA BB"),       // absent -> NotFound
            };

            PatchOutcome outcome = GameHelperPatcher.Patch(source, successes);

            Assert.Equal(1, outcome.UpdatedCount);
            Assert.Equal(1, outcome.UnchangedCount);
            Assert.Equal(1, outcome.NotFoundCount);
            Assert.Contains("new Pattern(\"Game States\", \"" + gsNew + "\")", outcome.NewText);
            Assert.DoesNotContain(gsOld, outcome.NewText);
            Assert.Contains("new Pattern(\"File Root\", \"" + frPat + "\")", outcome.NewText);

            Assert.Equal(PatchStatus.Updated, Find(outcome, "Game States").Status);
            Assert.Equal(gsOld, Find(outcome, "Game States").OldPattern);
            Assert.Equal(PatchStatus.Unchanged, Find(outcome, "File Root").Status);
            Assert.Equal(PatchStatus.NotFound, Find(outcome, "Ghost").Status);
        }

        [Fact]
        public void HandlesExplicitBytesToSkipArgument()
        {
            string source = "new Pattern(\"GameCullSize\", \"2B 05 ^ ?? ?? ?? ?? OLD\", 14)";
            var successes = new List<RecoveryResult> { Result("GameCullSize", "2B 05 ^ ?? ?? ?? ?? NEW") };

            PatchOutcome outcome = GameHelperPatcher.Patch(source, successes);

            Assert.Equal(1, outcome.UpdatedCount);
            // The explicit ", 14" is dropped; the "^" form re-derives BytesToSkip.
            Assert.Equal("new Pattern(\"GameCullSize\", \"2B 05 ^ ?? ?? ?? ?? NEW\")", outcome.NewText);
        }

        private static PatchEntry Find(PatchOutcome outcome, string name)
        {
            return outcome.Entries.Find(p => p.Name == name);
        }
    }

    public class OffsetsJsonAndDiffTests
    {
        private static RecoveryResult Result(string name, ulong resolved, string pattern, int skip = 3)
        {
            return new RecoveryResult
            {
                OffsetName = name,
                Match = new OffsetMatch { Resolved = resolved, Pattern = pattern, BytesToSkip = skip, PatternMatchCount = 1 },
            };
        }

        [Fact]
        public void RoundTripsJsonExport()
        {
            RecoveryResult r = Result("Game States", 0x14443c958, "48 39 2D ^ ?? ?? ?? ??");
            string json = JsonExport.Build("PathOfExile.exe", 0x140000000,
                new List<RecoveryResult> { r }, new List<string>());

            List<ReferenceOffset> parsed = OffsetsJson.Parse(json);

            Assert.Single(parsed);
            Assert.Equal("Game States", parsed[0].Name);
            Assert.Equal("0x14443c958", parsed[0].ResolvedAddress);
            Assert.Equal("48 39 2D ^ ?? ?? ?? ??", parsed[0].Pattern);
            Assert.Equal(3, parsed[0].BytesToSkip);
        }

        [Fact]
        public void ClassifiesEveryDiffStatus()
        {
            var reference = new List<ReferenceOffset>
            {
                new ReferenceOffset { Name = "Game States", ResolvedAddress = "0x111", Pattern = "P1" },
                new ReferenceOffset { Name = "File Root", ResolvedAddress = "0x222", Pattern = "P2" },
                new ReferenceOffset { Name = "AreaChangeCounter", ResolvedAddress = "0x333", Pattern = "P3" },
                new ReferenceOffset { Name = "Gone", ResolvedAddress = "0x555", Pattern = "P5" },
            };
            var current = new List<RecoveryResult>
            {
                Result("Game States", 0x111, "P1"),        // same addr + pattern -> Unchanged
                Result("File Root", 0x222, "P2b"),          // same addr, new pattern -> PatternChanged
                Result("AreaChangeCounter", 0x999, "P3"),   // addr moved -> AddressMoved
                Result("BrandNew", 0x444, "PX"),            // no reference -> New
            };

            List<DiffRow> rows = OffsetDiff.Compare(current, reference);

            Assert.Equal(5, rows.Count);
            Assert.Equal(DiffStatus.Unchanged, Find(rows, "Game States").Status);
            Assert.Equal(DiffStatus.PatternChanged, Find(rows, "File Root").Status);
            Assert.Equal(DiffStatus.AddressMoved, Find(rows, "AreaChangeCounter").Status);
            Assert.Equal(DiffStatus.New, Find(rows, "BrandNew").Status);
            Assert.Equal(DiffStatus.Missing, Find(rows, "Gone").Status);
        }

        private static DiffRow Find(List<DiffRow> rows, string name)
        {
            return rows.Find(r => r.Name == name);
        }
    }
}
