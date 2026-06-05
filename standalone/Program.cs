using System;
using System.Collections.Generic;

namespace OffsetRecovery.Standalone
{
    // Ghidra-free proof of concept: recover the GameHelper2 "Game States" offset
    // straight from PathOfExile.exe using a PE parser + iced-x86 + the .pdata
    // function table, then emit a SigMaker-style unique pattern.
    public static class Program
    {
        private const int HighConfidence = 85;

        public static int Main(string[] args)
        {
            if (args.Length < 1)
            {
                Console.Error.WriteLine("usage: OffsetRecovery.Standalone <path-to-game.exe> [--verbose]");
                return 2;
            }

            string path = args[0];
            bool verbose = Array.IndexOf(args, "--verbose") >= 0;

            Console.WriteLine("GameHelper2 Offset Recovery Framework (standalone PoC)");
            Console.WriteLine("Program: " + path);
            Console.WriteLine();

            PeImage image = PeImage.Load(path);
            Console.WriteLine("Image base   : 0x" + image.ImageBase.ToString("x"));
            Console.WriteLine("pdata funcs  : " + image.RuntimeFunctions.Count);

            CodeModel model = CodeModel.Build(image);
            List<StringHit> strings = StringScanner.Scan(image);
            Console.WriteLine("Functions    : " + model.Functions.Functions.Count);
            Console.WriteLine("Strings      : " + strings.Count);
            Console.WriteLine();

            var recipe = new GameStatesRecipe(model);
            Console.WriteLine("== " + recipe.Name + " ==");

            List<RecoveryResult> candidates = recipe.Recover(strings);
            candidates.Sort((a, b) => b.Score.CompareTo(a.Score));

            if (candidates.Count == 0)
            {
                Console.WriteLine("FAILED: anchor string, XREF caller, or provider null-check was not found.");
                return 1;
            }

            RecoveryResult best = candidates[0];
            var sigMaker = new SignatureMaker(model);
            SignatureMaker.Pattern pattern = sigMaker.MakeUnique(
                best.Match.MatchStart, best.Match.PatternLength, best.Match.BytesToSkip);

            best.Match.Pattern = pattern.Render();
            best.Match.PatternMatchCount = pattern.MatchCount;
            best.Match.BytesToSkip = pattern.BytesToSkip;
            if (pattern.MatchCount == 1)
            {
                best.Score = Math.Min(100, best.Score + 5);
                best.Validations.Add("output pattern is unique in executable memory");
            }
            else
            {
                best.Score = 0;
                best.Validations.Add("output pattern match count: " + pattern.MatchCount);
            }

            if (best.Match.PatternMatchCount != 1)
            {
                Console.WriteLine("FAILED: output pattern is not unique in executable memory; matches="
                    + best.Match.PatternMatchCount);
                return 1;
            }

            PrintResult(best, verbose);
            return 0;
        }

        private static void PrintResult(RecoveryResult result, bool verbose)
        {
            Console.WriteLine("Anchor string       : 0x" + result.Anchor.Address.ToString("x") + "  \"" + result.Anchor.Value + "\"");
            Console.WriteLine("String reference    : 0x" + result.StringReferenceAddress.ToString("x"));
            Console.WriteLine("XREF function       : " + Format(result.XrefFunction));
            Console.WriteLine("Source function     : " + Format(result.SourceFunction));
            Console.WriteLine("Target instruction  : 0x" + result.Match.InstructionAddress.ToString("x") + "  " + result.Match.Kind);
            Console.WriteLine("Resolved address    : 0x" + result.Match.Resolved.ToString("x"));
            Console.WriteLine("Output pattern      : " + result.Match.Pattern);
            Console.WriteLine("BytesToSkip         : " + result.Match.BytesToSkip);
            Console.WriteLine("Pattern matches     : " + result.Match.PatternMatchCount);
            Console.WriteLine("Confidence          : " + ConfidenceLabel(result.Score) + " (" + result.Score + "/100)");

            if (verbose)
            {
                PrintList("Score reasons", result.Reasons);
                PrintList("Validations", result.Validations);
            }
        }

        private static void PrintList(string title, List<string> values)
        {
            if (values.Count == 0)
            {
                return;
            }
            Console.WriteLine(title + "       :");
            foreach (string value in values)
            {
                Console.WriteLine("  - " + value);
            }
        }

        private static string Format(PdataFunction function)
        {
            return function == null ? "<none>" : function.Name + " @ 0x" + function.Begin.ToString("x");
        }

        private static string ConfidenceLabel(int score)
        {
            if (score >= HighConfidence) return "high";
            if (score >= 65) return "medium";
            return "low";
        }
    }
}
