using System;
using System.Collections.Generic;
using System.Text.Json;

namespace OffsetRecovery.Standalone
{
    // One offset parsed from a previously written offsets.json (the diff reference).
    public sealed class ReferenceOffset
    {
        public string Name;
        public string ResolvedAddress;
        public string Pattern;
        public int BytesToSkip;
    }

    public static class OffsetsJson
    {
        // Parse an offsets.json (as written by JsonExport) back into reference rows.
        public static List<ReferenceOffset> Parse(string json)
        {
            var list = new List<ReferenceOffset>();
            using (JsonDocument doc = JsonDocument.Parse(json))
            {
                if (!doc.RootElement.TryGetProperty("offsets", out JsonElement offsets)
                    || offsets.ValueKind != JsonValueKind.Array)
                {
                    return list;
                }
                foreach (JsonElement o in offsets.EnumerateArray())
                {
                    list.Add(new ReferenceOffset
                    {
                        Name = GetString(o, "name"),
                        ResolvedAddress = GetString(o, "resolvedAddress"),
                        Pattern = GetString(o, "outputPattern"),
                        BytesToSkip = GetInt(o, "bytesToSkip"),
                    });
                }
            }
            return list;
        }

        private static string GetString(JsonElement e, string name)
        {
            return e.TryGetProperty(name, out JsonElement v) && v.ValueKind == JsonValueKind.String
                ? v.GetString() : null;
        }

        private static int GetInt(JsonElement e, string name)
        {
            return e.TryGetProperty(name, out JsonElement v) && v.ValueKind == JsonValueKind.Number
                ? v.GetInt32() : 0;
        }
    }

    public enum DiffStatus
    {
        Unchanged,
        AddressMoved,
        PatternChanged,
        New,
        Missing,
    }

    public sealed class DiffRow
    {
        public string Name { get; set; }
        public DiffStatus Status { get; set; }
        public string OldAddress { get; set; }
        public string NewAddress { get; set; }
        public string OldPattern { get; set; }
        public string NewPattern { get; set; }
        public int OldBytesToSkip { get; set; }
        public int NewBytesToSkip { get; set; }

        public string StatusText
        {
            get
            {
                switch (Status)
                {
                    case DiffStatus.Unchanged: return "unchanged";
                    case DiffStatus.AddressMoved: return "address moved";
                    case DiffStatus.PatternChanged: return "pattern changed";
                    case DiffStatus.New: return "new";
                    default: return "missing";
                }
            }
        }
    }

    // Compares a fresh recovery against a reference offsets.json: which offsets moved,
    // which patterns changed, what is new, and what the reference had that we no longer
    // recover. Exactly the patch-day question.
    public static class OffsetDiff
    {
        public static List<DiffRow> Compare(IReadOnlyList<RecoveryResult> current,
            IReadOnlyList<ReferenceOffset> reference)
        {
            var rows = new List<DiffRow>();
            var refByName = new Dictionary<string, ReferenceOffset>();
            foreach (ReferenceOffset r in reference)
            {
                if (r.Name != null)
                {
                    refByName[r.Name] = r;
                }
            }

            var seen = new HashSet<string>();
            foreach (RecoveryResult c in current)
            {
                string newAddr = "0x" + c.Match.Resolved.ToString("x");
                var row = new DiffRow
                {
                    Name = c.OffsetName,
                    NewAddress = newAddr,
                    NewPattern = c.Match.Pattern,
                    NewBytesToSkip = c.Match.BytesToSkip,
                };

                if (refByName.TryGetValue(c.OffsetName, out ReferenceOffset rf))
                {
                    seen.Add(c.OffsetName);
                    row.OldAddress = rf.ResolvedAddress;
                    row.OldPattern = rf.Pattern;
                    row.OldBytesToSkip = rf.BytesToSkip;

                    bool sameAddr = string.Equals(rf.ResolvedAddress, newAddr, StringComparison.OrdinalIgnoreCase);
                    bool samePattern = string.Equals(rf.Pattern, c.Match.Pattern, StringComparison.Ordinal);
                    if (sameAddr && samePattern)
                    {
                        row.Status = DiffStatus.Unchanged;
                    }
                    else if (!sameAddr)
                    {
                        row.Status = DiffStatus.AddressMoved;
                    }
                    else
                    {
                        row.Status = DiffStatus.PatternChanged;
                    }
                }
                else
                {
                    row.Status = DiffStatus.New;
                }
                rows.Add(row);
            }

            foreach (ReferenceOffset r in reference)
            {
                if (r.Name != null && !seen.Contains(r.Name))
                {
                    rows.Add(new DiffRow
                    {
                        Name = r.Name,
                        Status = DiffStatus.Missing,
                        OldAddress = r.ResolvedAddress,
                        OldPattern = r.Pattern,
                        OldBytesToSkip = r.BytesToSkip,
                    });
                }
            }
            return rows;
        }
    }
}
