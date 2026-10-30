namespace AttackMap.GraphExplorer;

/// <summary>Latest-request publication gate with one MSAGL worker and cancellation of superseded waiters.</summary>
public sealed class LayoutSession : IAsyncDisposable
{
    private readonly object sync = new();
    private readonly MsaglLayoutAdapter adapter = new();
    private readonly HashSet<Task<LayoutSnapshot?>> pending = [];
    private CancellationTokenSource? latest;
    private bool disposed;

    public void CancelPending() { lock (sync) latest?.Cancel(); }

    public Task<LayoutSnapshot?> ReplaceAsync(LayoutRequest request, CancellationToken cancellationToken = default)
    {
        lock (sync)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            latest?.Cancel();
            var source = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            latest = source;
            var task = Run(request, source, cancellationToken);
            pending.Add(task);
            _ = task.ContinueWith(completed => { lock (sync) pending.Remove(completed); }, CancellationToken.None,
                TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
            return task;
        }
    }

    private async Task<LayoutSnapshot?> Run(LayoutRequest request, CancellationTokenSource source, CancellationToken external)
    {
        try
        {
            var result = await adapter.LayoutAsync(request, source.Token).ConfigureAwait(false);
            lock (sync) return !disposed && ReferenceEquals(latest, source) ? result : null;
        }
        catch (OperationCanceledException) when (!external.IsCancellationRequested) { return null; }
        finally
        {
            lock (sync) { if (ReferenceEquals(latest, source)) latest = null; }
            source.Dispose();
        }
    }

    public async ValueTask DisposeAsync()
    {
        Task<LayoutSnapshot?>[] work;
        lock (sync)
        {
            if (disposed) return;
            disposed = true;
            latest?.Cancel();
            work = pending.ToArray();
        }
        // Completion here means worker work ended, rather than merely a timeout on waiting.
        try { await Task.WhenAll(work).ConfigureAwait(false); }
        catch (OperationCanceledException) { }
    }
}
