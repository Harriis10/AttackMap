using System.Text.Json;

namespace AttackMap.NativeSpike;

public sealed record VerifiedReportSnapshot(
    ImportedReport Report,
    ReportSections Sections,
    ParityOverview Overview,
    ExportSelection Selection)
{
    private const int MaxBytes = 64 * 1024 * 1024;
    public string ReadHash => Report.ReadHash;
    public int ProjectionThreadId { get; internal init; }

    public static Task<VerifiedReportSnapshot> Load(
        string path, RunIdentity? identity, CancellationToken cancellationToken = default) =>
        Load(path, identity, OpenRead, null, cancellationToken);

    internal static async Task<VerifiedReportSnapshot> Load(
        string path, RunIdentity? identity,
        Func<string, FileStream> openRead,
        Func<Task>? afterRead = null,
        CancellationToken cancellationToken = default,
        Action? afterProjection = null)
    {
        path = Path.GetFullPath(path);
        using var stream = openRead(path);
        if (stream.Length > MaxBytes) throw new InvalidDataException("Report exceeds the 64 MiB preview limit.");
        byte[] bytes = new byte[(int)stream.Length];
        await stream.ReadExactlyAsync(bytes, cancellationToken).ConfigureAwait(false);
        if (afterRead != null) await afterRead().ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (await stream.ReadAsync(new byte[1], cancellationToken).ConfigureAwait(false) != 0)
            throw new InvalidDataException("Report changed while being read. Reopen it before continuing.");
        return await Task.Run(() =>
        {
            var selection = identity == null
                ? ExportSelection.CaptureSavedGeneration(path, bytes, ReportRepository(bytes))
                : ExportSelection.Capture(path, bytes, identity);
            cancellationToken.ThrowIfCancellationRequested();
            using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 64 });
            cancellationToken.ThrowIfCancellationRequested();
            var root = document.RootElement;
            var report = ReportAdapter.Read(root, selection.ReportHash);
            afterProjection?.Invoke();
            cancellationToken.ThrowIfCancellationRequested();
            var sections = ReportSectionAdapter.Read(root, selection.ReportHash, selection.RunId);
            afterProjection?.Invoke();
            cancellationToken.ThrowIfCancellationRequested();
            var overview = ParityOverviewAdapter.Read(root, sections);
            afterProjection?.Invoke();
            cancellationToken.ThrowIfCancellationRequested();
            return new VerifiedReportSnapshot(report, sections, overview, selection) { ProjectionThreadId = Environment.CurrentManagedThreadId };
        }).ConfigureAwait(false);
    }

    private static string ReportRepository(byte[] bytes)
    {
        using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 64 });
        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object || !root.TryGetProperty("scan", out var scan) ||
            scan.ValueKind != JsonValueKind.Object || !scan.TryGetProperty("root", out var repository) ||
            repository.ValueKind != JsonValueKind.String)
            throw new InvalidDataException("Expected a canonical legacy report with scan.root and findings.");
        return repository.GetString()!;
    }

    private static FileStream OpenRead(string path) => new(path, new FileStreamOptions
    {
        Mode = FileMode.Open,
        Access = FileAccess.Read,
        Share = FileShare.Read,
        Options = FileOptions.Asynchronous | FileOptions.SequentialScan
    });
}
