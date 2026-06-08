using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace PoEformance
{
    public enum PatchStatus
    {
        Updated,
        Unchanged,
        NotFound,
    }

    public sealed class PatchEntry
    {
        public string Name;
        public string OldPattern;
        public string NewPattern;
        public PatchStatus Status;
    }

    public sealed class PatchOutcome
    {
        public string NewText;
        public readonly List<PatchEntry> Entries = new List<PatchEntry>();
        public int UpdatedCount;
        public int UnchangedCount;
        public int NotFoundCount;
    }

    // Updates a GameHelper2 static-pattern file in place, matching each recovered offset by
    // name and replacing only its pattern string. Two formats are supported:
    //   * C#  (StaticOffsetsPatterns.cs):  new Pattern("Name", "48 39 2D ^ ?? ?? ?? ?? ...")
    //   * AHK (StaticOffsetsPatterns.ahk): Map("name", "Name", "pattern", "48 39 2D ^ ?? ...")
    // Our Render() output already uses the same "^"/"??" format, so the patterns map 1:1.
    // Comments, layout, and unrelated entries are preserved.
    public static class GameHelperPatcher
    {
        public static PatchOutcome Patch(string source, IReadOnlyList<RecoveryResult> successes)
        {
            var outcome = new PatchOutcome { NewText = source };

            foreach (RecoveryResult result in successes)
            {
                string name = result.OffsetName;
                string newPattern = result.Match.Pattern;
                var entry = new PatchEntry { Name = name, NewPattern = newPattern };
                string esc = Regex.Escape(name);

                // C#: new Pattern("Name", "..."[, skip]) — normalised to the 2-argument "^" form.
                var csharp = new Regex(
                    "new\\s+Pattern\\s*\\(\\s*\"" + esc + "\"\\s*,\\s*\"(?<pat>[^\"]*)\"(\\s*,\\s*\\d+)?\\s*\\)");

                // AHK: Map("name", "Name", "pattern", "...") — only the pattern string is rewritten.
                var ahk = new Regex(
                    "(?<head>Map\\s*\\(\\s*\"name\"\\s*,\\s*\"" + esc
                        + "\"\\s*,\\s*\"pattern\"\\s*,\\s*\")(?<pat>[^\"]*)(?<tail>\")");

                if (TryUpdate(outcome, entry, csharp, newPattern,
                        m => "new Pattern(\"" + name + "\", \"" + newPattern + "\")"))
                {
                    continue;
                }
                if (TryUpdate(outcome, entry, ahk, newPattern,
                        m => m.Groups["head"].Value + newPattern + m.Groups["tail"].Value))
                {
                    continue;
                }

                entry.Status = PatchStatus.NotFound;
                outcome.NotFoundCount++;
                outcome.Entries.Add(entry);
            }

            return outcome;
        }

        private static bool TryUpdate(PatchOutcome outcome, PatchEntry entry, Regex regex, string newPattern,
            MatchEvaluator evaluator)
        {
            Match m = regex.Match(outcome.NewText);
            if (!m.Success)
            {
                return false;
            }

            entry.OldPattern = m.Groups["pat"].Value;
            if (entry.OldPattern == newPattern)
            {
                entry.Status = PatchStatus.Unchanged;
                outcome.UnchangedCount++;
                outcome.Entries.Add(entry);
                return true;
            }

            outcome.NewText = regex.Replace(outcome.NewText, evaluator, 1);
            entry.Status = PatchStatus.Updated;
            outcome.UpdatedCount++;
            outcome.Entries.Add(entry);
            return true;
        }
    }
}
