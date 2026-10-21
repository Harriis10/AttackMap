using Microsoft.UI.Xaml;
using Windows.ApplicationModel.DataTransfer;
using AttackMap.NativeSpike.ExportPrep;

namespace AttackMap.NativeSpike;

public sealed partial class MainWindow
{
    private async void ExportSarif(object sender, RoutedEventArgs args)
    {
        var selected = exportSelection;
        if (selected?.Verified != true) { Status.Text = "Open a verified report generation before exporting SARIF."; return; }
        var workspace = new SelectedExportWorkspace(); workspace.Select(selected);
        try
        {
            var picker = new Windows.Storage.Pickers.FileSavePicker { SuggestedFileName = "attackmap-" + ExportSelection.SafeName(selected.RunId!) };
            picker.FileTypeChoices.Add("Selected generation SARIF", new List<string> { ".sarif" });
            WinRT.Interop.InitializeWithWindow.Initialize(picker, WinRT.Interop.WindowNative.GetWindowHandle(this));
            var file = await picker.PickSaveFileAsync();
            if (file == null || actionLifetime.IsCancellationRequested) { workspace.Cancel(); return; }
            var intent = workspace.Request(SelectedExportFormat.Sarif, SelectedExportOperation.Save, file.Path, overwriteApproved: File.Exists(file.Path));
            string text = await workspace.ReadSarif();
            if (intent == null || !workspace.Validate(intent)) throw new InvalidDataException("Captured export identity or destination changed.");
            await WriteSelectedBytes(file.Path, System.Text.Encoding.UTF8.GetBytes(text));
            Status.Text = "Exported selected report SARIF. " + selected.Disclosure;
        }
        catch (Exception) { workspace.SaveFailed(); if (!actionLifetime.IsCancellationRequested) Status.Text = "SARIF export unavailable or selection changed. Reopen the report and retry; source artifacts are preserved."; }
    }

    private async void SaveSelectedArtifact(object sender, RoutedEventArgs args)
    {
        var selected = exportSelection;
        if (selected?.Verified != true || ArtifactRows.SelectedItem is not ArtifactRecord record) { ArtifactStatus.Text = "Select a verified artifact first."; return; }
        try
        {
            var picker = new Windows.Storage.Pickers.FileSavePicker { SuggestedFileName = Path.GetFileNameWithoutExtension(record.FullPath) };
            string extension = Path.GetExtension(record.FullPath); if (extension.Length == 0) extension = ".txt";
            picker.FileTypeChoices.Add("Selected artifact", new List<string> { extension });
            WinRT.Interop.InitializeWithWindow.Initialize(picker, WinRT.Interop.WindowNative.GetWindowHandle(this));
            var destination = await picker.PickSaveFileAsync();
            if (destination == null || actionLifetime.IsCancellationRequested) return;
            selected.EnsureExportDestination(destination.Path, record.FullPath);
            if (!SelectedArtifacts.List(selected).Contains(record)) throw new InvalidDataException("Artifact is no longer bound to the captured generation.");
            await using var source = File.OpenRead(record.FullPath);
            if (source.Length > 64 * 1024 * 1024) throw new InvalidDataException("Artifact exceeds the 64 MiB export limit.");
            byte[] bytes = new byte[(int)source.Length]; await source.ReadExactlyAsync(bytes);
            if (await source.ReadAsync(new byte[1]) != 0 || ExportSelection.Hash(bytes) != record.Checksum) throw new InvalidDataException("Selected artifact changed.");
            await WriteSelectedBytes(destination.Path, bytes);
            ArtifactStatus.Text = "Saved captured artifact bytes. " + selected.Disclosure;
        }
        catch (Exception) { if (!actionLifetime.IsCancellationRequested) ArtifactStatus.Text = "Artifact save failed or captured generation changed. Reopen the report and retry."; }
    }

    private async void CopySelectedArtifact(object sender, RoutedEventArgs args)
    {
        var selected = exportSelection;
        if (selected?.Verified != true || ArtifactRows.SelectedItem is not ArtifactRecord record) { ArtifactStatus.Text = "Select a verified text artifact first."; return; }
        try
        {
            string text = await SelectedArtifacts.ReadText(selected, record);
            if (actionLifetime.IsCancellationRequested || exportSelection != selected || !Equals(ArtifactRows.SelectedItem, record)) return;
            var package = new DataPackage(); package.SetText(text); Clipboard.SetContent(package);
            ArtifactStatus.Text = "Copied selected artifact text. " + selected.Disclosure;
        }
        catch (Exception) { if (!actionLifetime.IsCancellationRequested) ArtifactStatus.Text = "Artifact text could not be copied. Verify the selected generation and preview size."; }
    }
    private async void RevealSelectedArtifact(object sender, RoutedEventArgs args)
    {
        var selected = exportSelection;
        if (selected?.Verified != true || ArtifactRows.SelectedItem is not ArtifactRecord record) return;
        try
        {
            if (!SelectedArtifacts.List(selected).Contains(record)) throw new InvalidDataException("Artifact identity changed.");
            var folder = await Windows.Storage.StorageFolder.GetFolderFromPathAsync(Path.GetDirectoryName(record.FullPath)!);
            if (!actionLifetime.IsCancellationRequested) await Windows.System.Launcher.LaunchFolderAsync(folder);
        }
        catch (Exception) { if (!actionLifetime.IsCancellationRequested) ArtifactStatus.Text = "Artifact folder unavailable or captured generation changed."; }
    }
    private static async Task WriteSelectedBytes(string destination, byte[] bytes)
    {
        ExportSelection.EnsureDestinationPath(destination);
        string temporary = destination + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try { await File.WriteAllBytesAsync(temporary, bytes); ExportSelection.EnsureDestinationPath(destination); File.Move(temporary, destination, overwrite: true); }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }
}
