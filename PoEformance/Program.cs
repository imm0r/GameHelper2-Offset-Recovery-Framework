using System;
using System.IO;

namespace PoEformance
{
    // Thin CLI front-end over RecoveryRunner. The GUI (gui/PoEformance.Gui) is the
    // other front-end and calls the same RecoveryRunner.Run.
    public static class Program
    {
        public static int Main(string[] args)
        {
            if (args.Length < 1)
            {
                Console.Error.WriteLine("usage: PoEformance <path-to-game.exe> [--verbose]");
                return 2;
            }

            string path = args[0];
            bool verbose = Array.IndexOf(args, "--verbose") >= 0;

            RecoveryReport report = RecoveryRunner.Run(path, Console.WriteLine, verbose);

            string jsonPath = Path.Combine(Directory.GetCurrentDirectory(), "offsets.json");
            File.WriteAllText(jsonPath, report.Json);
            Console.WriteLine();
            Console.WriteLine("JSON written to: " + jsonPath);

            return report.Failures.Count == 0 ? 0 : 1;
        }
    }
}
