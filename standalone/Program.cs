using System;
using System.Collections.Generic;
using System.IO;

namespace OffsetRecovery.Standalone
{
    // Ghidra-free offset recovery: read PathOfExile.exe with a PE parser + iced-x86
    // + the .pdata function table, run all recipes, and emit SigMaker-style unique
    // patterns plus a machine-readable offsets.json.
    public static class Program
    {
        public static int Main(string[] args)
        {
            if (args.Length < 1)
            {
                Console.Error.WriteLine("usage: OffsetRecovery.Standalone <path-to-game.exe> [--verbose]");
                return 2;
            }

            string path = args[0];
            bool verbose = Array.IndexOf(args, "--verbose") >= 0;

            Console.WriteLine("GameHelper2 Offset Recovery Framework (standalone)");
            Console.WriteLine("Program: " + path);
            Console.WriteLine();

            PeImage image = PeImage.Load(path);
            CodeModel model = CodeModel.Build(image);
            List<StringHit> strings = StringScanner.Scan(image);
            Console.WriteLine("Image base   : 0x" + image.ImageBase.ToString("x"));
            Console.WriteLine("pdata funcs  : " + image.RuntimeFunctions.Count);
            Console.WriteLine("Functions    : " + model.Functions.Functions.Count);
            Console.WriteLine("Strings      : " + strings.Count);
            Console.WriteLine();

            var recipes = new IOffsetRecipe[]
            {
                new GameStatesRecipe(model),
                new FileRootRecipe(model),
                new AreaChangeCounterRecipe(model),
                new TerrainRecipe(model, false),
                new TerrainRecipe(model, true),
                new GameCullSizeRecipe(model),
            };

            var sigMaker = new SignatureMaker(model);
            var successes = new List<RecoveryResult>();
            var failures = new List<string>();

            foreach (IOffsetRecipe recipe in recipes)
            {
                Console.WriteLine("== " + recipe.Name + " ==");
                try
                {
                    RunRecipe(recipe, strings, sigMaker, successes, failures, verbose);
                }
                catch (Exception e)
                {
                    string reason = e.GetType().Name + ": " + e.Message;
                    Console.WriteLine("FAILED: " + reason);
                    failures.Add(recipe.Name + ": " + reason);
                }
                Console.WriteLine();
            }

            PrintSummary(successes, failures);

            string jsonPath = Path.Combine(Directory.GetCurrentDirectory(), "offsets.json");
            File.WriteAllText(jsonPath, JsonExport.Build(path, image.ImageBase, successes, failures));
            Console.WriteLine();
            Console.WriteLine("JSON written to: " + jsonPath);

            return failures.Count == 0 ? 0 : 1;
        }

        private static void RunRecipe(IOffsetRecipe recipe, List<StringHit> strings, SignatureMaker sigMaker,
            List<RecoveryResult> successes, List<string> failures, bool verbose)
        {
            List<RecoveryResult> candidates = recipe.Recover(strings);
            candidates.Sort((a, b) => b.Score.CompareTo(a.Score));

            if (candidates.Count == 0)
            {
                Console.WriteLine("FAILED: " + recipe.FailureReason);
                failures.Add(recipe.Name + ": " + recipe.FailureReason);
                return;
            }

            RecoveryResult best = candidates[0];
            best.CandidateCount = candidates.Count;

            SignatureMaker.Pattern pattern = sigMaker.MakeBestUnique(best.Match);
            best.Match.Pattern = pattern.Render();
            best.Match.PatternStart = pattern.Start;
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
                string reason = "output pattern is not unique in executable memory; matches=" + best.Match.PatternMatchCount;
                Console.WriteLine("FAILED: " + reason);
                failures.Add(recipe.Name + ": " + reason);
                return;
            }

            PrintResult(best, verbose);
            successes.Add(best);
        }

        private static void PrintResult(RecoveryResult result, bool verbose)
        {
            Console.WriteLine("Anchor string       : 0x" + result.Anchor.Address.ToString("x") + "  \"" + result.Anchor.Value + "\"");
            Console.WriteLine("String reference    : 0x" + result.StringReferenceAddress.ToString("x"));
            Console.WriteLine("XREF function       : " + Fmt(result.XrefFunction));
            Console.WriteLine("Source function     : " + Fmt(result.SourceFunction));
            if (result.CallDepth >= 0)
            {
                Console.WriteLine("Call depth          : " + result.CallDepth);
            }
            Console.WriteLine("Target instruction  : 0x" + result.Match.InstructionAddress.ToString("x") + "  " + result.Match.Kind);
            Console.WriteLine("Resolved address    : 0x" + result.Match.Resolved.ToString("x"));
            Console.WriteLine("Output pattern      : " + result.Match.Pattern);
            Console.WriteLine("BytesToSkip         : " + result.Match.BytesToSkip);
            Console.WriteLine("Pattern matches     : " + result.Match.PatternMatchCount);
            Console.WriteLine("Confidence          : " + Confidence.Label(result.Score) + " (" + result.Score + "/100)");

            if (verbose)
            {
                PrintList("Score reasons", result.Reasons);
                PrintList("Validations", result.Validations);
            }
        }

        private static void PrintSummary(List<RecoveryResult> successes, List<string> failures)
        {
            Console.WriteLine("== Summary ==");
            Console.WriteLine("Recovered: " + successes.Count + " / " + (successes.Count + failures.Count));
            foreach (RecoveryResult result in successes)
            {
                Console.WriteLine("  OK   " + result.OffsetName
                    + " -> 0x" + result.Match.Resolved.ToString("x")
                    + " [" + Confidence.Label(result.Score) + ", candidates=" + result.CandidateCount + "]");
            }
            foreach (string failure in failures)
            {
                Console.WriteLine("  FAIL " + failure);
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

        private static string Fmt(PdataFunction function)
        {
            return function == null ? "<none>" : function.Name + " @ 0x" + function.Begin.ToString("x");
        }
    }
}
