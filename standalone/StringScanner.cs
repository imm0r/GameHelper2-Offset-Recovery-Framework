using System;
using System.Collections.Generic;

namespace OffsetRecovery.Standalone
{
    public sealed class StringHit
    {
        public string Value;
        public ulong Address;
    }

    // Scans readable, non-executable sections for ASCII and UTF-16LE strings.
    // Equivalent to iterating Ghidra's defined string data, minus the analysis:
    // we just find printable, NUL-terminated runs in the data sections.
    public static class StringScanner
    {
        private const int MinLength = 4;

        public static List<StringHit> Scan(PeImage image)
        {
            var hits = new List<StringHit>();
            foreach (PeImage.Section section in image.Sections)
            {
                if (section.Executable || !section.Readable)
                {
                    continue;
                }
                ScanAscii(section, hits);
                ScanUtf16(section, hits);
            }
            return hits;
        }

        private static void ScanAscii(PeImage.Section section, List<StringHit> hits)
        {
            byte[] data = section.Raw;
            int i = 0;
            while (i < data.Length)
            {
                if (!IsPrintable(data[i]))
                {
                    i++;
                    continue;
                }
                int start = i;
                while (i < data.Length && IsPrintable(data[i]))
                {
                    i++;
                }
                int length = i - start;
                if (length >= MinLength && i < data.Length && data[i] == 0)
                {
                    hits.Add(new StringHit
                    {
                        Value = System.Text.Encoding.ASCII.GetString(data, start, length),
                        Address = section.VirtualStart + (ulong)start,
                    });
                }
            }
        }

        private static void ScanUtf16(PeImage.Section section, List<StringHit> hits)
        {
            byte[] data = section.Raw;
            int i = 0;
            while (i + 1 < data.Length)
            {
                if (!(IsPrintable(data[i]) && data[i + 1] == 0))
                {
                    i++;
                    continue;
                }
                int start = i;
                while (i + 1 < data.Length && IsPrintable(data[i]) && data[i + 1] == 0)
                {
                    i += 2;
                }
                int charCount = (i - start) / 2;
                if (charCount >= MinLength)
                {
                    hits.Add(new StringHit
                    {
                        Value = System.Text.Encoding.Unicode.GetString(data, start, charCount * 2),
                        Address = section.VirtualStart + (ulong)start,
                    });
                }
            }
        }

        private static bool IsPrintable(byte b) => b >= 0x20 && b < 0x7f;
    }

    public enum MatchType
    {
        Exact,
        Contains,
        FileName,
    }

    public sealed class AnchorSpec
    {
        public readonly string Value;
        public readonly MatchType Type;

        private AnchorSpec(string value, MatchType type)
        {
            Value = value;
            Type = type;
        }

        public static AnchorSpec Exact(string value) => new AnchorSpec(value, MatchType.Exact);
        public static AnchorSpec Contains(string value) => new AnchorSpec(value, MatchType.Contains);
        public static AnchorSpec FileName(string value) => new AnchorSpec(value, MatchType.FileName);

        public bool Matches(string candidate)
        {
            switch (Type)
            {
                case MatchType.Exact:
                    return Value == candidate;
                case MatchType.Contains:
                    return candidate.Contains(Value);
                default:
                    return Value == LastPathComponent(candidate);
            }
        }

        private static string LastPathComponent(string candidate)
        {
            int slash = candidate.LastIndexOf('/');
            int backslash = candidate.LastIndexOf('\\');
            int separator = Math.Max(slash, backslash);
            return separator >= 0 ? candidate.Substring(separator + 1) : candidate;
        }
    }
}
