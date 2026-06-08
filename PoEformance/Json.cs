using System.Collections.Generic;
using System.Text;

namespace PoEformance
{
    // Minimal hand-rolled JSON writer (no dependency). Replaces the Ghidra-DB
    // bookmarks/labels with a machine-readable file GameHelper2 can consume.
    public static class JsonExport
    {
        public static string Build(string program, ulong imageBase, List<RecoveryResult> successes, List<string> failures)
        {
            var sb = new StringBuilder();
            sb.Append("{\n");
            sb.Append("  \"program\": ").Append(Str(program)).Append(",\n");
            sb.Append("  \"imageBase\": ").Append(Str("0x" + imageBase.ToString("x"))).Append(",\n");
            sb.Append("  \"offsets\": [\n");

            for (int i = 0; i < successes.Count; i++)
            {
                RecoveryResult r = successes[i];
                sb.Append("    {\n");
                sb.Append("      \"name\": ").Append(Str(r.OffsetName)).Append(",\n");
                sb.Append("      \"staticLabel\": ").Append(Str(r.StaticLabel)).Append(",\n");
                sb.Append("      \"resolvedAddress\": ").Append(Str("0x" + r.Match.Resolved.ToString("x"))).Append(",\n");
                sb.Append("      \"patternStart\": ").Append(Str("0x" + r.Match.PatternStart.ToString("x"))).Append(",\n");
                sb.Append("      \"outputPattern\": ").Append(Str(r.Match.Pattern)).Append(",\n");
                sb.Append("      \"bytesToSkip\": ").Append(r.Match.BytesToSkip).Append(",\n");
                sb.Append("      \"patternMatches\": ").Append(r.Match.PatternMatchCount).Append(",\n");
                sb.Append("      \"confidence\": ").Append(Str(Confidence.Label(r.Score))).Append(",\n");
                sb.Append("      \"score\": ").Append(r.Score).Append(",\n");
                sb.Append("      \"sourceFunction\": ").Append(Str(FunctionName(r.SourceFunction)));
                sb.Append('\n');
                sb.Append("    }").Append(i + 1 < successes.Count ? "," : "").Append('\n');
            }

            sb.Append("  ],\n");
            sb.Append("  \"failures\": [\n");
            for (int i = 0; i < failures.Count; i++)
            {
                sb.Append("    ").Append(Str(failures[i])).Append(i + 1 < failures.Count ? "," : "").Append('\n');
            }
            sb.Append("  ]\n");
            sb.Append("}\n");
            return sb.ToString();
        }

        private static string FunctionName(PdataFunction function)
        {
            return function == null ? "" : function.Name + " @ 0x" + function.Begin.ToString("x");
        }

        private static string Str(string value)
        {
            if (value == null)
            {
                return "null";
            }
            var sb = new StringBuilder("\"");
            foreach (char c in value)
            {
                switch (c)
                {
                    case '\\': sb.Append("\\\\"); break;
                    case '"': sb.Append("\\\""); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\t': sb.Append("\\t"); break;
                    default:
                        if (c < 0x20)
                        {
                            sb.Append("\\u").Append(((int)c).ToString("x4"));
                        }
                        else
                        {
                            sb.Append(c);
                        }
                        break;
                }
            }
            sb.Append('"');
            return sb.ToString();
        }
    }
}
