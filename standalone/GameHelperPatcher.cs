using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace OffsetRecovery.Standalone
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

    // Updates a GameHelper2 StaticOffsetsPatterns.cs / StaticPattern.cs in place: for each
    // recovered offset it finds the matching `new Pattern("Name", "...")` constructor call
    // and replaces the pattern string with the freshly recovered one. Our Render() output
    // already uses GameHelper's "^"/"??" format, so the 2-argument constructor re-derives
    // BytesToSkip from the "^" marker. Other arguments, comments and layout are preserved.
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

                var regex = new Regex(
                    "new\\s+Pattern\\s*\\(\\s*\"" + Regex.Escape(name)
                        + "\"\\s*,\\s*\"(?<pat>[^\"]*)\"(\\s*,\\s*\\d+)?\\s*\\)");

                Match m = regex.Match(outcome.NewText);
                if (!m.Success)
                {
                    entry.Status = PatchStatus.NotFound;
                    outcome.NotFoundCount++;
                    outcome.Entries.Add(entry);
                    continue;
                }

                entry.OldPattern = m.Groups["pat"].Value;
                if (entry.OldPattern == newPattern)
                {
                    entry.Status = PatchStatus.Unchanged;
                    outcome.UnchangedCount++;
                    outcome.Entries.Add(entry);
                    continue;
                }

                string replacement = "new Pattern(\"" + name + "\", \"" + newPattern + "\")";
                outcome.NewText = regex.Replace(outcome.NewText, _ => replacement, 1);
                entry.Status = PatchStatus.Updated;
                outcome.UpdatedCount++;
                outcome.Entries.Add(entry);
            }

            return outcome;
        }
    }
}
