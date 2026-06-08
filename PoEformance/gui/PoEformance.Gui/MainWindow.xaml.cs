using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;
using PoEformance;

namespace PoEformance.Gui
{
    public partial class MainWindow : Window
    {
        private readonly ObservableCollection<OffsetRow> _rows = new ObservableCollection<OffsetRow>();
        private readonly ObservableCollection<DiffRow> _diffRows = new ObservableCollection<DiffRow>();
        private RecoveryReport _lastReport;
        private List<ReferenceOffset> _reference;

        public MainWindow()
        {
            InitializeComponent();
            ResultsGrid.ItemsSource = _rows;
            DiffGrid.ItemsSource = _diffRows;
        }

        private void BrowseClick(object sender, RoutedEventArgs e)
        {
            var dialog = new OpenFileDialog
            {
                Title = "Select game executable",
                Filter = "Executable (*.exe)|*.exe|All files (*.*)|*.*",
            };
            if (dialog.ShowDialog() == true)
            {
                PathBox.Text = dialog.FileName;
            }
        }

        private async void RecoverClick(object sender, RoutedEventArgs e)
        {
            string path = PathBox.Text == null ? null : PathBox.Text.Trim();
            if (string.IsNullOrEmpty(path) || !File.Exists(path))
            {
                MessageBox.Show(this, "Please choose an existing .exe file first.", "No file",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            bool verbose = VerboseCheck.IsChecked == true;
            SetBusy(true);
            _rows.Clear();
            LogBox.Clear();
            StatsText.Text = "Analyzing…";

            try
            {
                RecoveryReport report = await Task.Run(() => RecoveryRunner.Run(path, AppendLog, verbose));
                _lastReport = report;

                foreach (RecoveryResult result in report.Successes)
                {
                    _rows.Add(OffsetRow.From(result));
                }

                StatsText.Text = string.Format(
                    "Recovered {0}/{1}   ·   functions {2} (+{3} sweep)   ·   strings {4}   ·   self-check {5}/{0}",
                    report.Successes.Count,
                    report.Successes.Count + report.Failures.Count,
                    report.FunctionCount,
                    report.SyntheticFunctionCount,
                    report.StringCount,
                    report.SelfCheckConsistent);

                RefreshDiff();
            }
            catch (Exception ex)
            {
                StatsText.Text = "Failed.";
                AppendLog("ERROR: " + ex.GetType().Name + ": " + ex.Message);
                MessageBox.Show(this, ex.Message, "Recovery failed", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                SetBusy(false);
            }
        }

        private void CopyPatternClick(object sender, RoutedEventArgs e)
        {
            if (ResultsGrid.SelectedItem is OffsetRow row && !string.IsNullOrEmpty(row.Pattern))
            {
                Clipboard.SetText(row.Pattern);
            }
        }

        private void CopyAddressClick(object sender, RoutedEventArgs e)
        {
            if (ResultsGrid.SelectedItem is OffsetRow row && !string.IsNullOrEmpty(row.ResolvedAddress))
            {
                Clipboard.SetText(row.ResolvedAddress);
            }
        }

        private void SaveJsonClick(object sender, RoutedEventArgs e)
        {
            if (_lastReport == null || _lastReport.Json == null)
            {
                return;
            }
            var dialog = new SaveFileDialog
            {
                Title = "Save offsets.json",
                Filter = "JSON (*.json)|*.json",
                FileName = "offsets.json",
            };
            if (dialog.ShowDialog() == true)
            {
                File.WriteAllText(dialog.FileName, _lastReport.Json);
            }
        }

        // GameHelper2 integration: pick StaticPattern.cs / StaticOffsetsPatterns.cs and
        // rewrite each `new Pattern("Name", "...")` with the freshly recovered pattern.
        private void UpdateGameHelperClick(object sender, RoutedEventArgs e)
        {
            if (_lastReport == null || _lastReport.Successes.Count == 0)
            {
                MessageBox.Show(this, "Run a recovery first.", "Nothing to write",
                    MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            var dialog = new OpenFileDialog
            {
                Title = "Select GameHelper2 StaticOffsetsPatterns (.cs or .ahk)",
                Filter = "GameHelper patterns (*.cs;*.ahk)|*.cs;*.ahk|All files (*.*)|*.*",
            };
            if (dialog.ShowDialog() != true)
            {
                return;
            }

            string path = dialog.FileName;
            string source;
            try
            {
                source = File.ReadAllText(path);
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.Message, "Read failed", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            PatchOutcome outcome = GameHelperPatcher.Patch(source, _lastReport.Successes);

            var log = new StringBuilder();
            log.AppendLine("== Update " + Path.GetFileName(path) + " ==");
            foreach (PatchEntry entry in outcome.Entries)
            {
                log.AppendLine("  " + StatusLabel(entry.Status) + "  " + entry.Name);
            }
            AppendLog(log.ToString().TrimEnd());

            if (outcome.UpdatedCount == 0 && outcome.NotFoundCount == 0)
            {
                MessageBox.Show(this, "All patterns already match — nothing to update.", "Up to date",
                    MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            string summary = string.Format(
                "{0} updated, {1} unchanged, {2} not found.\n\nA backup ({3}.bak) will be created.\nWrite changes to:\n{4}?",
                outcome.UpdatedCount, outcome.UnchangedCount, outcome.NotFoundCount,
                Path.GetFileName(path), path);

            MessageBoxResult answer = MessageBox.Show(this, summary, "Update GameHelper patterns",
                MessageBoxButton.YesNo,
                outcome.NotFoundCount > 0 ? MessageBoxImage.Warning : MessageBoxImage.Question);
            if (answer != MessageBoxResult.Yes)
            {
                return;
            }

            try
            {
                File.WriteAllText(path + ".bak", source);
                File.WriteAllText(path, outcome.NewText);
                AppendLog("Wrote " + outcome.UpdatedCount + " pattern(s); backup at " + path + ".bak");
                MessageBox.Show(this,
                    "Updated " + outcome.UpdatedCount + " pattern(s).\nBackup: " + path + ".bak",
                    "Done", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.Message, "Write failed", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void LoadReferenceClick(object sender, RoutedEventArgs e)
        {
            var dialog = new OpenFileDialog
            {
                Title = "Load reference offsets.json",
                Filter = "JSON (*.json)|*.json|All files (*.*)|*.*",
            };
            if (dialog.ShowDialog() != true)
            {
                return;
            }

            try
            {
                string json = File.ReadAllText(dialog.FileName);
                _reference = OffsetsJson.Parse(json);
                ReferencePathText.Text = dialog.FileName + "   (" + _reference.Count + " offsets)";
                RefreshDiff();
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.Message, "Load failed", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void DiffSelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (!(DiffGrid.SelectedItem is DiffRow row))
            {
                DiffDetails.Clear();
                return;
            }

            var sb = new StringBuilder();
            sb.AppendLine(row.Name + "   [" + row.StatusText + "]");
            sb.AppendLine();
            sb.AppendLine("old address : " + (row.OldAddress ?? "—"));
            sb.AppendLine("new address : " + (row.NewAddress ?? "—"));
            sb.AppendLine("old skip    : " + row.OldBytesToSkip);
            sb.AppendLine("new skip    : " + row.NewBytesToSkip);
            sb.AppendLine();
            sb.AppendLine("old pattern : " + (row.OldPattern ?? "—"));
            sb.AppendLine("new pattern : " + (row.NewPattern ?? "—"));
            DiffDetails.Text = sb.ToString();
        }

        private void RefreshDiff()
        {
            _diffRows.Clear();
            DiffDetails.Clear();
            if (_lastReport == null || _reference == null)
            {
                return;
            }
            foreach (DiffRow row in OffsetDiff.Compare(_lastReport.Successes, _reference))
            {
                _diffRows.Add(row);
            }
        }

        // Called from the background recovery thread; marshal onto the UI thread.
        private void AppendLog(string line)
        {
            Dispatcher.Invoke(() =>
            {
                LogBox.AppendText(line + Environment.NewLine);
                LogBox.ScrollToEnd();
            });
        }

        private void SetBusy(bool busy)
        {
            RecoverButton.IsEnabled = !busy;
            BrowseButton.IsEnabled = !busy;
            Progress.IsIndeterminate = busy;
        }

        private static string StatusLabel(PatchStatus s)
        {
            switch (s)
            {
                case PatchStatus.Updated: return "UPDATED  ";
                case PatchStatus.Unchanged: return "unchanged";
                default: return "NOT FOUND";
            }
        }
    }

    // Row shown in the results DataGrid.
    public sealed class OffsetRow
    {
        public string Name { get; set; }
        public string ResolvedAddress { get; set; }
        public string Confidence { get; set; }
        public int Matches { get; set; }
        public int BytesToSkip { get; set; }
        public string Pattern { get; set; }

        public static OffsetRow From(RecoveryResult r)
        {
            return new OffsetRow
            {
                Name = r.OffsetName,
                ResolvedAddress = "0x" + r.Match.Resolved.ToString("x"),
                Confidence = PoEformance.Confidence.Label(r.Score) + " (" + r.Score + ")",
                Matches = r.Match.PatternMatchCount,
                BytesToSkip = r.Match.BytesToSkip,
                Pattern = r.Match.Pattern,
            };
        }
    }
}
