using AttackMap.NativeSpike;
using System.Collections.Concurrent;

int checks = 0;
void Check(bool value, string name) { if (!value) throw new Exception(name); checks++; }
string testBase = Path.GetFullPath(args.FirstOrDefault() ?? Path.GetTempPath());
string testRoot = Path.Combine(testBase, "fleet-watch-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(testRoot);
try
{
    var roots = Enumerable.Range(1, 3).Select(i => Path.Combine(testRoot, $"repo {i} žluťoučký")).ToArray();
    foreach (string root in roots) Directory.CreateDirectory(root);
    var outputs = roots.Select(root => Path.Combine(root, "generated")).ToArray();
    foreach (string output in outputs) Directory.CreateDirectory(output);
    using var watch = new FleetRepositoryWatchCoordinator();
    Check(!watch.Enabled && !watch.Pending && watch.WatchedRoots.Count == 0, "explicit default off");
    Check(!watch.Start([roots[0]]), "at least two roots required");
    Check(!watch.Start([roots[0], roots[0]]), "duplicate roots rejected");
    Check(!watch.Start([roots[0], "relative"]), "relative roots rejected");
    Check(!watch.Start(Enumerable.Range(0, 17).Select(i => Path.Combine(testRoot, "too-many-" + i))), "at most sixteen subscriptions");
    if (!OperatingSystem.IsWindows()) { Console.WriteLine("SKIP actual multi-root filesystem checks: Windows required."); return; }
    var received = new ConcurrentQueue<FleetRepositoryWatchRequest>();
    watch.ScanRequested += received.Enqueue;
    TimeSpan debounce = TimeSpan.FromMilliseconds(150);
    Check(watch.Start(roots, outputs, debounce), "three actual Windows child watchers start");
    Check(watch.WatchedRoots.Count == 3 && watch.Limitations.Count == 0 && !watch.Pending, "no auto fleet on enable");
    async Task AwaitCount(int count)
    {
        var deadline = DateTime.UtcNow.AddSeconds(10);
        while (received.Count < count && DateTime.UtcNow < deadline) await Task.Delay(40);
        Check(received.Count == count, $"request count {count}, got {received.Count}");
    }
    async Task Quiet(int expected)
    { await Task.Delay(650); Check(received.Count == expected, $"quiet request count {expected}, got {received.Count}"); }
    void Write(int index, string name) => File.WriteAllText(Path.Combine(roots[index], name), Guid.NewGuid().ToString());
    Write(1, "second.js"); await AwaitCount(1);
    var first = received.Last(); long epoch = first.Epoch;
    Check(watch.IsCurrent(first) && first.FullRescan && first.RepositoryRoots.SequenceEqual(roots), "captured stable selected-set order/epoch");
    Check(first.ChangedRepositoryRoots.SequenceEqual([roots[1]]), "second root change not lost");
    watch.SetFleetRunning(true);
    for (int i = 0; i < 20; i++) { Write(0, "first.js"); Write(2, "third.js"); }
    await Quiet(1);
    Check(watch.Pending && watch.PendingRepositoryCount is >= 2 and <= 3, "bounded per-root pending during fleet");
    watch.FleetCompleted(epoch, true); await AwaitCount(2);
    var followup = received.Last();
    Check(followup.ChangedRepositoryRoots.Contains(roots[0]) && followup.ChangedRepositoryRoots.Contains(roots[2]), "first/third burst retained in one followup");
    Check(!watch.FleetCompleted(first, true) && watch.IsCurrent(followup), "old completion token cannot clear newer dispatch");
    watch.FleetCompleted(epoch, true); await Quiet(2);
    Check(!watch.Pending && !watch.IsCurrent(first) && !watch.IsCurrent(followup), "no duplicate burst replay or stale admission");
    File.Move(Path.Combine(roots[2], "third.js"), Path.Combine(roots[2], "renamed.js")); await AwaitCount(3);
    watch.FleetCompleted(epoch, true);
    File.Delete(Path.Combine(roots[2], "renamed.js")); await AwaitCount(4);
    watch.FleetCompleted(epoch, true);
    foreach (string output in outputs) File.WriteAllText(Path.Combine(output, "report.json"), "owned output");
    Directory.CreateDirectory(Path.Combine(roots[1], "node_modules"));
    File.WriteAllText(Path.Combine(roots[1], "node_modules", "dependency.js"), "ignored");
    await Quiet(4); Check(!watch.Pending, "owned outputs and WP020 skip policy do not loop");
    Write(2, "busy.js"); await AwaitCount(5); var busy = received.Last();
    watch.SetFleetRunning(true); watch.Requeue(busy); await Quiet(5);
    Check(watch.Pending && !watch.IsCurrent(busy), "busy dispatcher requeues without loss or overlap");
    watch.SetFleetRunning(false); await AwaitCount(6);
    Check(received.Last().ChangedRepositoryRoots.Contains(roots[2]), "busy retry keeps changed root");
    watch.FleetCompleted(epoch, true);
    var handler = new Action<FleetRepositoryWatchRequest>(request => { received.Enqueue(request); throw new IOException("fixture dispatch failure"); });
    watch.ScanRequested -= received.Enqueue;
    watch.ScanRequested += handler;
    Write(0, "failure.js"); await AwaitCount(7);
    watch.ScanRequested -= handler; watch.ScanRequested += received.Enqueue;
    await AwaitCount(8); Check(received.Last().ChangedRepositoryRoots.Contains(roots[0]), "throwing dispatch automatically retries");
    var stale = received.Last();
    var switched = roots.Take(2).ToArray();
    Check(watch.Start(switched, outputs, debounce), "set switch replaces subscriptions");
    Check(watch.Epoch != epoch && !watch.IsCurrent(stale) && !watch.Pending && watch.WatchedRoots.Count == 2, "switch invalidates old set and pending");
    watch.Requeue(stale); watch.FleetCompleted(epoch, true);
    Write(2, "old-root.js"); await Quiet(8);
    Write(1, "new-set.js"); await AwaitCount(9);
    watch.Stop(); Write(0, "after-stop.js"); Write(1, "after-stop-2.js"); await Quiet(9);
    Check(!watch.Enabled && !watch.Pending && watch.WatchedRoots.Count == 0, "Stop disposes all subscriptions");
    string missing = Path.Combine(testRoot, "missing");
    Check(watch.Start([roots[0], missing], outputs, debounce), "supported child can remain watched with inaccessible sibling");
    Check(watch.WatchedRoots.Count == 1 && watch.Limitations.Single().RepositoryRoot == missing && watch.Notice.Contains("manual"), "unavailable sibling explicitly limited");
    Write(0, "limited.js"); await AwaitCount(10);
    Check(received.Last().RepositoryRoots.Contains(missing), "watch does not silently remove selected full-fleet scope");
    watch.Dispose(); watch.Dispose(); Write(0, "after-dispose.js"); await Quiet(10);
    Check(!watch.Enabled && !watch.Pending && watch.WatchedRoots.Count == 0, "close disposes idempotently with no orphan callbacks");
    try { watch.Start(roots); Check(false, "disposed Start must reject"); } catch (ObjectDisposedException) { Check(true, "disposed terminal"); }
}
finally
{
    string resolved = Path.GetFullPath(testRoot);
    if (!resolved.StartsWith(Path.TrimEndingDirectorySeparator(testBase) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)
        || !System.Text.RegularExpressions.Regex.IsMatch(Path.GetFileName(resolved), "^fleet-watch-[a-f0-9]{32}$"))
        throw new IOException("Refusing cleanup outside owned GUID test directory");
    if (Directory.Exists(resolved)) Directory.Delete(resolved, true);
}
Console.WriteLine($"PASS {checks} fleet watch checks including actual Windows multi-root filesystem; no engine, GUI or provider calls.");
