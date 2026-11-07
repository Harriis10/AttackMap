# Native performance probe handoff

Root hook from the Loaded event:

```csharp
await NativePerformanceProbe.Run(reportPath, outputPath, path => LoadReport(path),
    query => Search.Text = query, index => Findings.SelectedIndex = index,
    () => (all.Count, Findings.Items.Count, Detail.Text), closeReport: ClearDisplayedReport);
```

The load callback must reset filters and select the first detail. Close must clear
all report/list/export/presentation backing references and return a zero Total
snapshot. A missing close callback leaves cycles explicitly unmeasured.
MainWindow and its command flag remain root-owned.

Run tools/measure_native_windows.ps1 after --performance-smoke is integrated. Use
a fresh output directory; stale outputs are rejected. -Quick -Launches 1 runs
one load/sample/cycle with ten interaction warmups and is diagnostic only. Full
mode launches 30 fresh processes. The first process runs 30 load trials, ten
warmups and 100 filter/detail samples plus 100 actual open/close cycles; the other
29 processes contribute fresh startup samples with short profiles. All latencies
retain raw samples and nearest-rank p95. Successful IDs/counts are checked for
every interaction. CPU, working set/private bytes and GC-normalized cycle growth
are recorded. No fixed-delay synchronization or latency-phase forced GC is used.

Process-creation UTC to Loaded is a marker measurement, not verified primary-action
readiness. Two low-priority dispatcher turns settle binding/selection events;
visual capture and manual usability remain separate. Hardware queries preserve
unknowns. SSD presence does not establish the data's physical storage placement.
Windows 10 runs and incomplete/quick profiles cannot qualify C26. No C26 target
is accepted merely because a threshold comparison is true.

Only PowerShell syntax has been verified in this handoff. Root owns native build,
hook validation and measured runs before any result claims.
