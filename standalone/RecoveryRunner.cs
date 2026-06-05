using System;
using System.Collections.Generic;

namespace OffsetRecovery.Standalone
{
    // Structured result of a full recovery run, shared by the console app and the GUI.
    public sealed class RecoveryReport
    {
        public string ProgramName;
        public ulong ImageBase;
        public int PdataCount;
        public int FunctionCount;
        public int SyntheticFunctionCount;
        public int StringCount;
        public int SelfCheckConsistent;
        public readonly List<RecoveryResult> Successes = new List<RecoveryResult>();
        public readonly List<string> Failures = new List<string>();
        public string Json;
    }

    // Shared orchestration: load the PE, build the model, run every recipe through the
    // SigMaker pass, self-check, and produce a structured report plus the JSON payload.
    // All human-readable output goes through the optional log callback so each front-end
    // (console, GUI) can render it however it likes.
    public static class RecoveryRunner
    {
        public static RecoveryReport Run(string exePath, Action<string> log = null, bool verbose = false)
        {
            void Log(string line) => log?.Invoke(line ?? string.Empty);

            var report = new RecoveryReport { ProgramName = exePath };

            Log("GameHelper2 Offset Recovery Framework (standalone)");
            Log("Program: " + exePath);
            Log("");

            PeImage image = PeImage.Load(exePath);
            CodeModel model = CodeModel.Build(image);
            List<StringHit> strings = StringScanner.Scan(image);

            report.ImageBase = image.ImageBase;
            report.PdataCount = image.RuntimeFunctions.Count;
            report.FunctionCount = model.Functions.Functions.Count;
            report.SyntheticFunctionCount = model.SyntheticFunctionCount;
            report.StringCount = strings.Count;

            Log("Image base   : 0x" + image.ImageBase.ToString("x"));
            Log("pdata funcs  : " + report.PdataCount);
            Log("Functions    : " + report.FunctionCount + " (+" + report.SyntheticFunctionCount + " via CALL sweep)");
            Log("Strings      : " + report.StringCount);
            Log("");

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
            foreach (IOffsetRecipe recipe in recipes)
            {
                Log("== " + recipe.Name + " ==");
                try
                {
                    RunRecipe(recipe, strings, sigMaker, report, verbose, Log);
                }
                catch (Exception e)
                {
                    string reason = e.GetType().Name + ": " + e.Message;
                    Log("FAILED: " + reason);
                    report.Failures.Add(recipe.Name + ": " + reason);
                }
                Log("");
            }

            RunSelfChecks(image, report, Log);
            PrintSummary(report, Log);

            report.Json = JsonExport.Build(exePath, image.ImageBase, report.Successes, report.Failures);
            return report;
        }

        private static void RunRecipe(IOffsetRecipe recipe, List<StringHit> strings, SignatureMaker sigMaker,
            RecoveryReport report, bool verbose, Action<string> log)
        {
            List<RecoveryResult> candidates = recipe.Recover(strings);
            candidates.Sort((a, b) => b.Score.CompareTo(a.Score));

            if (candidates.Count == 0)
            {
                log("FAILED: " + recipe.FailureReason);
                report.Failures.Add(recipe.Name + ": " + recipe.FailureReason);
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
                log("FAILED: " + reason);
                report.Failures.Add(recipe.Name + ": " + reason);
                return;
            }

            PrintResult(best, verbose, log);
            report.Successes.Add(best);
        }

        private static void PrintResult(RecoveryResult result, bool verbose, Action<string> log)
        {
            log("Anchor string       : 0x" + result.Anchor.Address.ToString("x") + "  \"" + result.Anchor.Value + "\"");
            log("String reference    : 0x" + result.StringReferenceAddress.ToString("x"));
            log("XREF function       : " + Fmt(result.XrefFunction));
            log("Source function     : " + Fmt(result.SourceFunction));
            if (result.CallDepth >= 0)
            {
                log("Call depth          : " + result.CallDepth);
            }
            log("Target instruction  : 0x" + result.Match.InstructionAddress.ToString("x") + "  " + result.Match.Kind);
            log("Resolved address    : 0x" + result.Match.Resolved.ToString("x"));
            log("Output pattern      : " + result.Match.Pattern);
            log("BytesToSkip         : " + result.Match.BytesToSkip);
            log("Pattern matches     : " + result.Match.PatternMatchCount);
            log("Confidence          : " + Confidence.Label(result.Score) + " (" + result.Score + "/100)");

            if (verbose)
            {
                PrintList("Score reasons", result.Reasons, log);
                PrintList("Validations", result.Validations, log);
            }
        }

        private static void RunSelfChecks(PeImage image, RecoveryReport report, Action<string> log)
        {
            int consistent = 0;
            foreach (RecoveryResult result in report.Successes)
            {
                if (PatternSelfCheck.Verify(image, result, out string detail))
                {
                    result.Validations.Add("self-check: " + detail);
                    consistent++;
                }
                else
                {
                    log("WARN  " + result.OffsetName + " self-check failed: " + detail);
                }
            }
            report.SelfCheckConsistent = consistent;
            log("Self-check: " + consistent + " / " + report.Successes.Count
                + " patterns resolve to their static address");
            log("");
        }

        private static void PrintSummary(RecoveryReport report, Action<string> log)
        {
            log("== Summary ==");
            log("Recovered: " + report.Successes.Count + " / " + (report.Successes.Count + report.Failures.Count));
            foreach (RecoveryResult result in report.Successes)
            {
                log("  OK   " + result.OffsetName
                    + " -> 0x" + result.Match.Resolved.ToString("x")
                    + " [" + Confidence.Label(result.Score) + ", candidates=" + result.CandidateCount + "]");
            }
            foreach (string failure in report.Failures)
            {
                log("  FAIL " + failure);
            }
        }

        private static void PrintList(string title, List<string> values, Action<string> log)
        {
            if (values.Count == 0)
            {
                return;
            }
            log(title + "       :");
            foreach (string value in values)
            {
                log("  - " + value);
            }
        }

        private static string Fmt(PdataFunction function)
        {
            return function == null ? "<none>" : function.Name + " @ 0x" + function.Begin.ToString("x");
        }
    }
}
