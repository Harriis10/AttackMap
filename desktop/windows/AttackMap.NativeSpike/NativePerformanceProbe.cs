using System.Diagnostics;
using System.Text.Json;
using Microsoft.UI.Dispatching;
namespace AttackMap.NativeSpike;

public static class NativePerformanceProbe
{
    public static async Task Run(string reportPath,string outputPath,Func<string,Task<bool>> load,Action<string> filter,Action<int> select,Func<(int Total,int Filtered,string Detail)> snapshot,Func<Task>? closeReport = null)
    {
        using var process = Process.GetCurrentProcess();
        DateTimeOffset entered = DateTimeOffset.UtcNow;
        double processToLoadedMs = (entered.UtcDateTime - process.StartTime.ToUniversalTime()).TotalMilliseconds;
        int trials = Count("ATTACKMAP_PERF_LOAD_TRIALS",30);
        int samples = Count("ATTACKMAP_PERF_SAMPLES",100);
        int cycles = Count("ATTACKMAP_PERF_CYCLES",100);
        int warmups = 10;
        var loadTimes = new List<double>(); var filterTimes = new List<double>(); var detailTimes = new List<double>();
        var failures = new List<string>();
        var expected = new List<(string Id,string Title)>();
        byte[] bytes = await File.ReadAllBytesAsync(reportPath);
        string hash = ExportSelection.Hash(bytes);
        int observations;
        using (var report = JsonDocument.Parse(bytes))
        {
            foreach (var finding in report.RootElement.GetProperty("findings").EnumerateArray()) expected.Add((finding.GetProperty("id").GetString()!,finding.GetProperty("title").GetString()!));
            observations = report.RootElement.GetProperty("scan").GetProperty("signals").GetArrayLength();
        }
        long fixtureBytes = bytes.Length;
        bytes = [];
        bool referenceFixture = expected.Count == 10000 && observations == 50000 && fixtureBytes == 20 * 1024 * 1024 && hash == "612d12c9b56bfa98ccb7061e81b67120bc738759e9731737ab1fe9d1ada658ba";
        if (!referenceFixture) failures.Add("Fixture does not match the versioned C26 reference counts/size/hash.");
        double cpuStart = process.TotalProcessorTime.TotalMilliseconds;
        try
        {
            for (int i=0;i<trials;i++)
            {
                var watch = Stopwatch.StartNew();
                bool loaded = await load(reportPath);
                await Barrier();
                var state = snapshot();
                watch.Stop();
                if (!loaded || state.Total != expected.Count || state.Filtered != expected.Count || !state.Detail.Contains(expected[0].Id,StringComparison.Ordinal)) throw new InvalidDataException($"Load trial {i}: list/first detail not usable.");
                loadTimes.Add(watch.Elapsed.TotalMilliseconds);
            }
            for (int i=-warmups;i<samples;i++)
            {
                var finding = expected[(i+warmups)%expected.Count];
                var watch = Stopwatch.StartNew();
                filter(finding.Title);
                await Barrier();
                watch.Stop();
                if (snapshot().Filtered != 1) throw new InvalidDataException($"Filter trial {i}: unique expected title did not yield one record.");
                if (i>=0) filterTimes.Add(watch.Elapsed.TotalMilliseconds);
            }
            filter(""); await Barrier();
            for (int i=-warmups;i<samples;i++)
            {
                int index = ((i+warmups+1)*97)%expected.Count;
                var watch = Stopwatch.StartNew();
                select(index); await Barrier();
                watch.Stop();
                if (!snapshot().Detail.Contains(expected[index].Id,StringComparison.Ordinal)) throw new InvalidDataException($"Detail trial {i}: selected ID was not displayed.");
                if (i>=0) detailTimes.Add(watch.Elapsed.TotalMilliseconds);
            }
        }
        catch (Exception error) { failures.Add(error.GetType().Name + ": " + error.Message); }
        process.Refresh();
        long loadedWorkingSet = process.WorkingSet64, loadedPrivateBytes = process.PrivateMemorySize64;
        long? baselineWorkingSet = null, finalWorkingSet = null, baselinePrivate = null, finalPrivate = null;
        int completedCycles = 0;
        if (closeReport != null && failures.Count == 0)
        {
            try
            {
                await closeReport(); await Barrier();
                if (snapshot().Total != 0) throw new InvalidDataException("Close callback did not clear the report.");
                Collect(); process.Refresh(); baselineWorkingSet = process.WorkingSet64; baselinePrivate = process.PrivateMemorySize64;
                for (int i=0;i<cycles;i++)
                {
                    if (!await load(reportPath)) throw new InvalidDataException($"Cycle {i}: load failed.");
                    await Barrier();
                    if (snapshot().Total != expected.Count) throw new InvalidDataException($"Cycle {i}: wrong loaded finding count.");
                    await closeReport(); await Barrier();
                    if (snapshot().Total != 0) throw new InvalidDataException($"Cycle {i}: close did not clear report.");
                    completedCycles++;
                }
                Collect(); process.Refresh(); finalWorkingSet = process.WorkingSet64; finalPrivate = process.PrivateMemorySize64;
            }
            catch (Exception error) { failures.Add(error.GetType().Name + ": " + error.Message); }
        }
        bool completeSamples = trials==30 && samples==100 && loadTimes.Count==30 && filterTimes.Count==100 && detailTimes.Count==100 && completedCycles==100;
        var result = new {
            probeVersion="native-performance/v1", measuredAt=entered, processId=Environment.ProcessId,
            os=Environment.OSVersion.VersionString, osBuild=Environment.OSVersion.Version.Build,
            platformQualifying=Environment.OSVersion.Version.Build>=22000,
            appVersion=typeof(NativePerformanceProbe).Assembly.GetName().Version?.ToString(),
            appBinarySha256=ExportSelection.Hash(await File.ReadAllBytesAsync(typeof(NativePerformanceProbe).Assembly.Location)),
            fixturePath=Path.GetFullPath(reportPath), fixtureSha256=hash, fixtureBytes, findings=expected.Count, observations, referenceFixture,
            processStartToLoadedMilliseconds=processToLoadedMs,
            appReadyAcceptance="Loaded marker only; primary-action task acceptance remains separate.",
            loadMilliseconds=loadTimes, filterMilliseconds=filterTimes, detailMilliseconds=detailTimes,
            p95LoadMilliseconds=P95(loadTimes), p95FilterMilliseconds=P95(filterTimes), p95DetailMilliseconds=P95(detailTimes),
            warmups, requestedLoadTrials=trials, requestedSamples=samples, requestedCycles=cycles, completedCycles,
            loadedWorkingSetBytes=loadedWorkingSet, loadedPrivateBytes, baselineWorkingSetBytes=baselineWorkingSet, finalWorkingSetBytes=finalWorkingSet,
            baselinePrivateBytes=baselinePrivate, finalPrivateBytes=finalPrivate,
            retainedWorkingSetGrowthBytes=finalWorkingSet-baselineWorkingSet, retainedPrivateGrowthBytes=finalPrivate-baselinePrivate,
            cpuMilliseconds=process.TotalProcessorTime.TotalMilliseconds-cpuStart, failures, completeSamples,
            limitations=new[] { "Windows 10 runs are provisional; hardware/SSD qualification supplied by external harness.", "Working set/private bytes include probe and native UI; no worker/web renderer runs in this report-only probe.", "Cycle baseline/final use forced GC normalization; latency samples never force GC or sleep.", closeReport==null ? "Open/close cycles unmeasured: host supplied no close callback." : "Close callback verified through zero findings; retained non-list app state requires separate review.", "No acceptance claim from timing alone." }
        };
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(outputPath))!);
        await File.WriteAllTextAsync(outputPath,JsonSerializer.Serialize(result,new JsonSerializerOptions { WriteIndented=true }));
    }
    public static double? P95(IReadOnlyCollection<double> values) => values.Count==0 ? null : values.OrderBy(value=>value).ElementAt((int)Math.Ceiling(values.Count*.95)-1);
    private static int Count(string variable,int fallback) => int.TryParse(Environment.GetEnvironmentVariable(variable),out int value) && value is >=1 and <=1000 ? value : fallback;
    private static void Collect() { GC.Collect(); GC.WaitForPendingFinalizers(); GC.Collect(); }
    private static Task Barrier()
    {
        var queue=DispatcherQueue.GetForCurrentThread() ?? throw new InvalidOperationException("Performance probe must run on the native UI thread.");
        var completion=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        if (!queue.TryEnqueue(DispatcherQueuePriority.Low,() => {
            if (!queue.TryEnqueue(DispatcherQueuePriority.Low,() => completion.SetResult())) completion.SetException(new InvalidOperationException("UI dispatcher stopped."));
        })) completion.SetException(new InvalidOperationException("UI dispatcher stopped."));
        return completion.Task;
    }
}
