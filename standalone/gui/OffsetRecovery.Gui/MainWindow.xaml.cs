using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Threading.Tasks;
using System.Windows;
using Microsoft.Win32;
using OffsetRecovery.Standalone;

namespace OffsetRecovery.Gui
{
    public partial class MainWindow : Window
    {
        private readonly ObservableCollection<OffsetRow> _rows = new ObservableCollection<OffsetRow>();
        private RecoveryReport _lastReport;

        public MainWindow()
        {
            InitializeComponent();
            ResultsGrid.ItemsSource = _rows;
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
                Confidence = OffsetRecovery.Standalone.Confidence.Label(r.Score) + " (" + r.Score + ")",
                Matches = r.Match.PatternMatchCount,
                BytesToSkip = r.Match.BytesToSkip,
                Pattern = r.Match.Pattern,
            };
        }
    }
}
