# WP043 Detail + Root Render Probe Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an isolated, non-mutating F7 A/D/T/B diagnostic that compares live presentation with immediate Detail and root RTB output in five WP043 rounds.

**Architecture:** Keep F8 and production rendering unchanged. Add one native F7 handler that emits a bound D/T PNG pair, and a separate runner mode that brackets it with ordinary ImageGrab captures and validates identity, structure, and failure behavior. Build one diagnostic candidate and inspect all 20 targeted images before drawing any mechanism conclusion.

**Tech Stack:** C# / WinUI 3 `RenderTargetBitmap`, Windows PNG imaging APIs, Python 3 `unittest`/`pytest`, existing `tools/capture_wp043_live.py` backend, offline `dotnet publish --no-restore`.

## Global Constraints

- Work only in `C:\Projects\INPROGRESS\AttackMap`; preserve the dirty worktree and unrelated files.
- Do not commit, push, package, restore SDKs, call providers, start scans, or run parallel UI builds/captures.
- No UI property mutation, `UpdateLayout`, `Task.Delay`, explicit frame settling, scrolling, resource, or theme change in F7.
- Existing F8 behavior remains unchanged. F7 is opt-in and cannot be combined with other capture/intervention modes.
- A/D/T/B are ordered observations, not simultaneous snapshots. Anomaly non-reproduction is `not-reproduced`, not a negative mechanism result.
- No repair, root-cause, promotion, or V01/V02/V03 acceptance claim follows from capture success alone.
- Do not use Git commits from the generic plan template; the owner has not authorized them.

## File Structure

- Modify `desktop/windows/AttackMap.NativeSpike/MainWindow.RenderDiagnostics.cs`: F7 registration, bound D/T capture, native validation, and diagnostics.
- Modify `tools/capture_wp043_live.py`: F7 key dispatch, pair ACK/parser, mode exclusion, PNG validation, and A/D/T/B manifest.
- Modify `tests/test_wp043_live_capture.py`: fake F7 events/PNGs, behavioral regressions, and native source gate.
- Create `artifacts/diagram-integration-20261024/wp043-continuation-20261025/ordinary-candidate-08/`: offline diagnostic binaries plus the frozen engine.
- Create `artifacts/diagram-integration-20261024/wp043-continuation-20261025/detail-root-render-probe-live-28/`: one live evidence directory; use no retry unless a separately recorded harness/foreground failure requires owner-facing disposition.
- Modify `artifacts/diagram-integration-20261024/wp043-continuation-20261025/PROGRESS-20261025.md`, `docs/windows-parity-todo.md`, `docs/roadmap-windows-parity-2026-10-20.md`, and `docs/windows-parity-backlog.json`: final observed evidence only.

---

### Task 1: Native F7 Detail + Root Pair

**Files:**
- Modify: `desktop/windows/AttackMap.NativeSpike/MainWindow.RenderDiagnostics.cs`
- Test: `tests/test_wp043_live_capture.py`

**Interfaces:**
- Consumes: existing `Detail`, `Content`, `FindingsPanel`, `Findings`, `generation`, `findingRevision`, `RenderDiagnosticsWrite`, `CaptureOracle.MaxBytes`.
- Produces: `RenderDiagnosticsDetailRootRender()` and events `detail-root-render-capture-started`, `detail-root-render-capture-completed`, `detail-root-render-capture-failed`. Completed metadata contains `probeId`, `detailFileName`, `rootFileName`, `detailWidth`, `detailHeight`, `rootWidth`, `rootHeight`, `scale`, `renderingFrames`, and bound context fields.

- [ ] **Step 1: Add the failing native source-gate test**

Append this test beside the F8 source gate:

```python
def test_detail_root_render_probe_rasterizes_both_targets_without_settling_or_mutation(self):
    source = (Path(__file__).parents[1] / "desktop/windows/AttackMap.NativeSpike/MainWindow.RenderDiagnostics.cs").read_text(encoding="utf-8")
    self.assertIn("private async Task RenderDiagnosticsDetailRootRender()", source)
    method = source.split("private async Task RenderDiagnosticsDetailRootRender()", 1)[1]
    method = method.split("private void RenderDiagnosticsSnapshot", 1)[0]
    self.assertIn("await bitmap.RenderAsync(target);", method)
    self.assertIn("await Capture(Detail, \"detail\");", method)
    self.assertIn("await Capture(root, \"root\");", method)
    self.assertEqual(method.count("await bitmap.GetPixelsAsync();"), 1)
    self.assertIn("CompositionTarget.Rendering -= rendering;", method)
    for forbidden in (
        "UpdateLayout", "Task.Delay", "Detail.Text =", "Detail.Foreground =",
        "Detail.CharacterSpacing =", "Detail.Visibility =", "Detail.Opacity =",
        "root.Visibility =", "root.Opacity =", "ChangeView(",
    ):
        self.assertNotIn(forbidden, method)
```

- [ ] **Step 2: Verify RED**

Run: `./.venv/Scripts/python.exe -B -m pytest tests/test_wp043_live_capture.py -q -k detail_root_render_probe_rasterizes`
Expected: one failure because `RenderDiagnosticsDetailRootRender` does not exist.

- [ ] **Step 3: Register F7 without changing F8**

Immediately before the existing F8 accelerator registration, add:

```csharp
var detailRootRenderAccelerator = new KeyboardAccelerator { Key = VirtualKey.F7, ScopeOwner = root };
TypedEventHandler<KeyboardAccelerator, KeyboardAcceleratorInvokedEventArgs> detailRootRenderInvoked = async (_, args) =>
{
    args.Handled = true;
    await RenderDiagnosticsDetailRootRender();
};
detailRootRenderAccelerator.Invoked += detailRootRenderInvoked;
root.KeyboardAccelerators.Add(detailRootRenderAccelerator);
renderDiagnosticsCleanup.Add(() =>
{
    detailRootRenderAccelerator.Invoked -= detailRootRenderInvoked;
    root.KeyboardAccelerators.Remove(detailRootRenderAccelerator);
});
```

Add `private bool renderDiagnosticsDetailRootRenderActive;` beside the F8 active flag. Extend only the `enabled` metadata with `f7 = "Non-mutating direct Detail and root RenderTargetBitmap pair; QA observation only"` and update the scope string to mention F7 D/T PNG pixels. Do not edit the F8 handler or method.

- [ ] **Step 4: Implement the bounded pair capture**

Insert this method immediately before `RenderDiagnosticsSnapshot`. It intentionally uses one local helper so Detail and root share exactly the same validation and encoding path:

```csharp
private async Task RenderDiagnosticsDetailRootRender()
{
    if (renderDiagnosticsStopped || renderDiagnosticsLog == null || renderDiagnosticsDetailRootRenderActive || actionLifetime.IsCancellationRequested) return;
    renderDiagnosticsDetailRootRenderActive = true;
    long currentGeneration = generation, currentFindingRevision = findingRevision;
    string probeId = Guid.NewGuid().ToString("N");
    int renderingFrames = 0;
    EventHandler<object> rendering = (_, _) => ++renderingFrames;
    var root = (FrameworkElement)Content;
    double scale = Detail.XamlRoot?.RasterizationScale ?? 0;
    string directory = "";
    try
    {
        RenderDiagnosticsWrite("detail-root-render-capture-started", new { probeId,
            generation = currentGeneration, displayedRun, displayedReadHash,
            navigationRevision = renderDiagnosticsNavigationRevision, findingRevision = currentFindingRevision,
            detailLoaded = Detail.IsLoaded, detailWidth = Detail.ActualWidth, detailHeight = Detail.ActualHeight,
            rootLoaded = root.IsLoaded, rootWidth = root.ActualWidth, rootHeight = root.ActualHeight, scale });
        CompositionTarget.Rendering += rendering;
        if (!Detail.DispatcherQueue.HasThreadAccess || !Detail.IsLoaded || Detail.XamlRoot == null ||
            !root.IsLoaded || root.XamlRoot == null || Detail.ActualWidth <= 0 || Detail.ActualHeight <= 0 ||
            root.ActualWidth <= 0 || root.ActualHeight <= 0 || root.Visibility != Visibility.Visible ||
            FindingsPanel.Visibility != Visibility.Visible || Findings.SelectedItem is not FixtureFinding ||
            !double.IsFinite(scale) || scale <= 0)
            throw new InvalidOperationException("Detail/root render requires loaded visible bound content on the owning dispatcher.");
        directory = Path.GetDirectoryName(renderDiagnosticsLog.BaseStream is FileStream stream ? stream.Name : null)
            ?? throw new InvalidOperationException("Diagnostics output directory is unavailable.");

        void RequireContext()
        {
            if (generation != currentGeneration || findingRevision != currentFindingRevision || renderDiagnosticsStopped ||
                actionLifetime.IsCancellationRequested || !Detail.IsLoaded || Detail.XamlRoot == null || !root.IsLoaded || root.XamlRoot == null)
                throw new InvalidOperationException("Detail/root render context changed.");
        }

        async Task<(string FileName, int Width, int Height)> Capture(FrameworkElement target, string targetKind)
        {
            string? temporary = null;
            try
            {
                RequireContext();
                var bitmap = new RenderTargetBitmap();
                await bitmap.RenderAsync(target);
                int width = bitmap.PixelWidth, height = bitmap.PixelHeight;
                if (width <= 0 || height <= 0 || width > 16384 || height > 16384 ||
                    (long)width * height * 4 > CaptureOracle.MaxBytes)
                    throw new InvalidDataException("Rendered target is empty or exceeds the bounded capture size.");
                var pixels = await bitmap.GetPixelsAsync();
                if (pixels.Length != (long)width * height * 4) throw new InvalidDataException("Unexpected BGRA8 buffer size.");
                RequireContext();
                var raw = new byte[(int)pixels.Length];
                using (var reader = DataReader.FromBuffer(pixels)) reader.ReadBytes(raw);
                using var encoded = new InMemoryRandomAccessStream();
                var encoder = await BitmapEncoder.CreateAsync(BitmapEncoder.PngEncoderId, encoded);
                encoder.SetPixelData(BitmapPixelFormat.Bgra8, BitmapAlphaMode.Premultiplied,
                    (uint)width, (uint)height, 96 * scale, 96 * scale, raw);
                await encoder.FlushAsync();
                if (encoded.Size > CaptureOracle.MaxBytes) throw new InvalidDataException("Encoded PNG exceeds the capture limit.");
                var png = new byte[(int)encoded.Size];
                using (var reader = new DataReader(encoded.GetInputStreamAt(0)))
                {
                    if (await reader.LoadAsync((uint)png.Length) != png.Length) throw new IOException("Encoded PNG read was incomplete.");
                    reader.ReadBytes(png);
                }
                RequireContext();
                string fileName = $"detail-root-render-{targetKind}-{probeId}.png";
                temporary = Path.Combine(directory, $".detail-root-render-{targetKind}-{probeId}.tmp");
                using (var file = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                { await file.WriteAsync(png); file.Flush(flushToDisk: true); }
                File.Move(temporary, Path.Combine(directory, fileName), overwrite: false);
                temporary = null;
                return (fileName, width, height);
            }
            finally
            {
                if (temporary != null)
                    try { if (File.Exists(temporary)) File.Delete(temporary); } catch (Exception) { }
            }
        }

        var detail = await Capture(Detail, "detail");
        RequireContext();
        var tree = await Capture(root, "root");
        RequireContext();
        RenderDiagnosticsWrite("detail-root-render-capture-completed", new { probeId,
            generation = currentGeneration, displayedRun, displayedReadHash,
            navigationRevision = renderDiagnosticsNavigationRevision, findingRevision = currentFindingRevision,
            detailFileName = detail.FileName, rootFileName = tree.FileName,
            detailWidth = detail.Width, detailHeight = detail.Height,
            rootWidth = tree.Width, rootHeight = tree.Height, scale, renderingFrames });
    }
    catch (Exception error)
    {
        RenderDiagnosticsWrite("detail-root-render-capture-failed", new { probeId,
            generation = currentGeneration, displayedRun, displayedReadHash,
            navigationRevision = renderDiagnosticsNavigationRevision, findingRevision = currentFindingRevision,
            errorType = error.GetType().Name, renderingFrames });
    }
    finally
    {
        CompositionTarget.Rendering -= rendering;
        renderDiagnosticsDetailRootRenderActive = false;
    }
}
```

- [ ] **Step 5: Verify GREEN and unchanged F8 tests**

Run: `./.venv/Scripts/python.exe -B -m pytest tests/test_wp043_live_capture.py -q -k "detail_root_render_probe_rasterizes or detail_render_probe_directly"`
Expected: 2 passed. Compile is deferred until runner tests are green; no live process is started.

---

### Task 2: Runner Protocol, Validation, and Regressions

**Files:**
- Modify: `tools/capture_wp043_live.py`
- Test: `tests/test_wp043_live_capture.py`

**Interfaces:**
- Consumes: Task 1 event names and completed metadata.
- Produces: `_detail_root_render_terminal(...) -> dict | None`, `_detail_root_png(...) -> tuple[Path, int, int, float]`, CLI `--detail-root-render-probe`, manifest `detailRootRenderProbe`, and B destination `FindingDetailRootRenderAfter`.

- [ ] **Step 1: Add failing fake-backend and five-round tests**

Add `import base64`, `import struct` where needed, `detail_root_render_probe_failed = None` and `detail_root_render_probe = False` defaults. Add this F7 branch to `FakeBackend.send_key` before F8:

```python
elif key == "F7":
    context = dict(
        probeId=f"root-probe-{self.finding_revision}", generation=1,
        displayedReadHash=self.report_hash, navigationRevision=self.navigation_revision,
        findingRevision=self.finding_revision,
    )
    self._append("detail-root-render-capture-started", **context)
    if self.detail_root_render_probe_failed is not None:
        self._append("detail-root-render-capture-failed", **context, errorType="IOException")
        return
    png = base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=")
    detail_name = f"detail-root-render-detail-r{self.finding_revision:02d}.png"
    root_name = f"detail-root-render-root-r{self.finding_revision:02d}.png"
    (self.diagnostics_dir / detail_name).write_bytes(png)
    (self.diagnostics_dir / root_name).write_bytes(png)
    self._append(
        "detail-root-render-capture-completed", **context,
        detailFileName=detail_name, rootFileName=root_name,
        detailWidth=1, detailHeight=1, rootWidth=1, rootHeight=1, scale=1.0,
    )
```

Add the main regression:

```python
def test_detail_root_render_probe_retains_five_a_d_t_b_sets(self):
    with tempfile.TemporaryDirectory() as temporary:
        args = self.make_args(Path(temporary))
        args.detail_root_render_probe = True
        backend = FakeBackend()
        evidence = run(args, backend)
        self.assertEqual(evidence["status"], "independent-live-window-captured")
        self.assertEqual(len(evidence["captures"]), 80)
        self.assertEqual(backend.keys.count("F7"), 5)
        self.assertEqual(backend.keys.count("F8"), 0)
        self.assertEqual(len(evidence["detailRootRenderProbe"]), 5)
        for round_number, probe in enumerate(evidence["detailRootRenderProbe"], 1):
            self.assertEqual(probe["round"], round_number)
            self.assertEqual(probe["beforeCapture"], f"r{round_number:02d}-02-FindingDetail")
            self.assertEqual(probe["afterCapture"], f"r{round_number:02d}-02-FindingDetail-root-render-after")
            for key in ("detailRenderCapture", "rootRenderCapture"):
                item = probe[key]
                path = args.output / item["path"]
                self.assertEqual((item["width"], item["height"]), (1, 1))
                self.assertEqual(item["sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
            self.assertGreater(probe["terminalSequence"], probe["afterSequence"])
        self.assertFalse(evidence["diagnosticInterventions"])
```

- [ ] **Step 2: Add failing safety regressions**

Add tests using the same `make_args` pattern:

```python
def test_detail_root_render_probe_rejects_other_modes_and_ack_anomalies(self):
    modes = ("detail_render_probe", "diagnostic_interventions", "detail_spacing_probe_round",
             "detail_brush_probe_round", "print_window_detail_capture")
    for mode in modes:
        with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
            args = self.make_args(Path(temporary))
            args.detail_root_render_probe = True
            setattr(args, mode, 1 if mode.endswith("_round") else True)
            with self.assertRaisesRegex(ValueError, "cannot be combined"):
                run(args, FakeBackend())
            self.assertFalse(args.output.exists())
    for failure in ("detail", "root"):
        with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
            args = self.make_args(Path(temporary))
            args.detail_root_render_probe = True
            backend = FakeBackend()
            backend.detail_root_render_probe_failed = failure
            evidence = run(args, backend)
            self.assertEqual(evidence["status"], "failed")
            self.assertFalse(any(x["destination"] == "FindingDetailRootRenderAfter" for x in evidence["captures"]))
            self.assertFalse(evidence["detailRootRenderProbe"])


def test_stale_detail_root_ack_cannot_release_after_capture(self):
    class StaleAckBackend(FakeBackend):
        def send_key(self, key):
            if key == "F7" and self.keys.count("F7") == 0:
                self._append("detail-root-render-capture-completed", probeId="stale", generation=1,
                    displayedReadHash=self.report_hash, navigationRevision=self.navigation_revision,
                    findingRevision=self.finding_revision, detailFileName="d.png", rootFileName="t.png",
                    detailWidth=1, detailHeight=1, rootWidth=1, rootHeight=1, scale=1.0)
                self.keys.append(key)
                return
            super().send_key(key)
    with tempfile.TemporaryDirectory() as temporary:
        args = self.make_args(Path(temporary))
        args.detail_root_render_probe = True
        evidence = run(args, StaleAckBackend())
        self.assertEqual(evidence["status"], "failed")
        self.assertFalse(evidence["detailRootRenderProbe"])
```

Reuse `ChangingFindingBackend` from the F8 test with `args.detail_root_render_probe = True` and assert failure contains `finding revision` with an empty `detailRootRenderProbe`. Add a malformed PNG test by subclassing `FakeBackend`, appending `b"broken"` to the first F7 Detail file after `super().send_key(key)`, and asserting failure with no B capture.

- [ ] **Step 3: Verify RED**

Run: `./.venv/Scripts/python.exe -B -m pytest tests/test_wp043_live_capture.py -q -k "detail_root or stale_detail_root"`
Expected: failures because F7 arguments, protocol handling, and manifest support do not exist.

- [ ] **Step 4: Implement pair ACK and structural PNG validation**

Add `import struct` to the runner, then add both complete helpers:

```python
def _detail_root_render_terminal(
    events: list[dict], after_sequence: int, expected_run_id: str,
    expected_report_hash: str, navigation_revision: int, finding_revision: int,
) -> dict | None:
    started = {
        event["detail"].get("probeId")
        for event in events
        if _sequence(event) > after_sequence
        and event.get("kind") == "detail-root-render-capture-started"
        and event.get("runId") == expected_run_id
        and isinstance(event.get("detail"), dict)
        and event["detail"].get("displayedReadHash") == expected_report_hash
        and event["detail"].get("navigationRevision") == navigation_revision
        and event["detail"].get("findingRevision") == finding_revision
        and isinstance(event["detail"].get("probeId"), str)
        and bool(event["detail"]["probeId"])
    }
    for event in events:
        if (_sequence(event) <= after_sequence
            or event.get("kind") not in {"detail-root-render-capture-completed", "detail-root-render-capture-failed"}
            or event.get("runId") != expected_run_id or not isinstance(event.get("detail"), dict)):
            continue
        detail = event["detail"]
        if (detail.get("probeId") in started
            and detail.get("displayedReadHash") == expected_report_hash
            and detail.get("navigationRevision") == navigation_revision
            and detail.get("findingRevision") == finding_revision):
            return event
    return None


def _detail_root_png(diagnostics_dir: Path, event: dict, prefix: str) -> tuple[Path, int, int, float]:
    file_name = event.get(prefix + "FileName")
    width = event.get(prefix + "Width")
    height = event.get(prefix + "Height")
    scale = event.get("scale")
    if (not isinstance(file_name, str) or Path(file_name).name != file_name
        or Path(file_name).suffix.lower() != ".png"
        or not isinstance(width, int) or isinstance(width, bool)
        or not isinstance(height, int) or isinstance(height, bool)
        or not 0 < width <= 16384 or not 0 < height <= 16384
        or width * height * 4 > 128 * 1024 * 1024
        or not isinstance(scale, (int, float)) or isinstance(scale, bool)
        or not 0 < scale < float("inf")):
        raise ValueError("F7 Detail/root render metadata exceeds capture bounds")
    path = _strict_file(diagnostics_dir / file_name, "F7 Detail/root render PNG")
    if path.parent != diagnostics_dir.resolve() or not 24 <= path.stat().st_size <= 128 * 1024 * 1024:
        raise ValueError("F7 Detail/root render PNG escaped its directory or exceeds capture bounds")
    with path.open("rb") as stream:
        header = stream.read(24)
    if (header[:8] != b"\x89PNG\r\n\x1a\n" or header[12:16] != b"IHDR"
        or struct.unpack(">II", header[16:24]) != (width, height)):
        raise ValueError("F7 Detail/root render PNG header or dimensions are invalid")
    return path, width, height, float(scale)
```

- [ ] **Step 5: Wire mode, F7, and manifest**

In `run`, reject either render probe combined with any other capture/intervention mode, including the other render probe. Add:

```python
"detailRootRenderProbe": None if not args.detail_root_render_probe else [],
```

Add `"F7": "{F7}"` and:

```python
parser.add_argument("--detail-root-render-probe", action="store_true",
    help="Add non-mutating ImageGrab/Detail-RTB/root-RTB/ImageGrab comparisons for each FindingDetail")
```

After the unchanged F8 branch, add this complete branch:

```python
if args.detail_root_render_probe:
    window, events = require_safe_after_transient(window, run_id)
    _require_finding_revision(events, finding_revision)
    after = _latest_sequence(events)
    try:
        backend.send_key("F7")
        terminal = _wait_for(
            lambda: _detail_root_render_terminal(
                fresh_events(run_id), after, run_id, report_hash,
                navigation_revision, finding_revision,
            ),
            args.action_timeout, poll_interval, "F7 Detail/root render terminal acknowledgment",
        )
        if terminal.get("kind") != "detail-root-render-capture-completed":
            raise RuntimeError("F7 Detail/root render failed before after-capture")
        detail_path, detail_width, detail_height, scale = _detail_root_png(
            diagnostics_dir, terminal["detail"], "detail")
        root_path, root_width, root_height, root_scale = _detail_root_png(
            diagnostics_dir, terminal["detail"], "root")
        if root_scale != scale:
            raise ValueError("F7 Detail/root render scales differ")
    except Exception:
        raise RuntimeError("F7 Detail/root render did not produce valid bound PNGs") from None
    window = capture(
        window, detail_capture + "-root-render-after", round_number,
        "FindingDetailRootRenderAfter", run_id,
        expected_finding_revision=finding_revision,
    )
    evidence["detailRootRenderProbe"].append({
        "round": round_number,
        "findingRevision": finding_revision,
        "beforeCapture": detail_capture,
        "detailRenderCapture": {
            "name": detail_path.stem, "path": (Path("diagnostics") / detail_path.name).as_posix(),
            "bytes": detail_path.stat().st_size, "sha256": _sha256(detail_path),
            "width": detail_width, "height": detail_height, "scale": scale,
        },
        "rootRenderCapture": {
            "name": root_path.stem, "path": (Path("diagnostics") / root_path.name).as_posix(),
            "bytes": root_path.stat().st_size, "sha256": _sha256(root_path),
            "width": root_width, "height": root_height, "scale": root_scale,
        },
        "afterCapture": evidence["captures"][-1]["name"],
        "afterSequence": after,
        "terminalSequence": _sequence(terminal),
        "status": "captured-awaiting-visual-review",
    })
```

- [ ] **Step 6: Run the complete focused harness**

Run: `./.venv/Scripts/python.exe -B -m pytest tests/test_wp043_live_capture.py -q`
Expected: all existing 49 tests plus new F7/source/failure tests and all eight existing subtests pass. If anything fails, fix only the F7 change or its tests; do not weaken F8 or safety checks.

---

### Task 3: Offline Candidate, One Live Run, and Evidence-Led Review

**Files:**
- Create: `artifacts/diagram-integration-20261024/wp043-continuation-20261025/ordinary-candidate-08/`
- Create: `artifacts/diagram-integration-20261024/wp043-continuation-20261025/detail-root-render-probe-live-28/`
- Modify: active WP043 progress/roadmap/TODO/backlog documents listed above.

**Interfaces:**
- Consumes: green Task 1/2 source and the frozen engine in `ordinary-candidate-07/engine`.
- Produces: hashed diagnostic candidate, one bound evidence manifest, actual visual review of all five A/D/T/B sets, and a narrowly stated next diagnostic gate.

- [ ] **Step 1: Publish offline and preserve the frozen engine**

Run:

```bash
out="artifacts/diagram-integration-20261024/wp043-continuation-20261025/ordinary-candidate-08"
winpwd=$(pwd -W)
export DOTNET_CLI_HOME="$winpwd/.tools/dotnet-home"
export NUGET_PACKAGES="$winpwd/.tools/nuget-packages"
./.tools/dotnet/dotnet.exe publish desktop/windows/AttackMap.NativeSpike/AttackMap.NativeSpike.csproj -c Release --no-restore -o "$out"
cp -a artifacts/diagram-integration-20261024/wp043-continuation-20261025/ordinary-candidate-07/engine "$out/engine"
./.venv/Scripts/python.exe -B -c "from pathlib import Path; import hashlib; p=Path(r'artifacts/diagram-integration-20261024/wp043-continuation-20261025/ordinary-candidate-08'); print('DLL', hashlib.sha256((p/'AttackMap.NativeSpike.dll').read_bytes()).hexdigest()); print('ENGINE', hashlib.sha256((p/'engine/attackmap-engine.exe').read_bytes()).hexdigest())"
```

Expected: publish succeeds without restore/network access; engine SHA-256 is `792184c584895bab68e4260447fe89543486ae228bd8ad85234ae3ca87ce8bba`. Record the actual new DLL hash. If the frozen engine filename differs, enumerate the candidate directory and hash the actual executable rather than inventing a path.

- [ ] **Step 2: Run one serialized live capture**

Use the retained report, new candidate, and fresh output:

```bash
./.venv/Scripts/python.exe -B tools/capture_wp043_live.py \
  --executable artifacts/diagram-integration-20261024/wp043-continuation-20261025/ordinary-candidate-08/AttackMap.NativeSpike.exe \
  --report artifacts/diagram-integration-20261024/source-render-audit-20261025/saved-generation/attackmap-report.json \
  --output artifacts/diagram-integration-20261024/wp043-continuation-20261025/detail-root-render-probe-live-28 \
  --native-only --theme dark --detail-root-render-probe
```

Expected on a completed capture: five `detailRootRenderProbe` entries, 80 accepted ordinary captures plus two RTB PNGs per round, `diagnosticInterventions=false`, and clean process exit. A foreground/occlusion or protocol failure is a harness/diagnostic failure, not a visual sample; do not blindly retry or relabel it as `not-reproduced`.

- [ ] **Step 3: Inspect every A/D/T/B image**

For each round, open A and B at native size, D at its viewport-equivalent top region, and T at native size or inspect full-resolution crops when downscaling would hide glyphs. Check file size before every media read; resize images over 3 MB into a separate workspace review directory without modifying originals. Record actual per-image states in `visual-review/manual-review.json`, including run ID, PID, DLL/report hashes, all 20 images, and exact review scope. Do not derive visual state from hashes or UIA text.

- [ ] **Step 4: Update active evidence without overclaiming**

Append the exact test/build/run/review results to `PROGRESS-20261025.md` and align only WP043 entries in the active TODO, roadmap, and JSON backlog. Validate the JSON after editing. Keep WP043 `IN_PROGRESS`, rendering acceptance `FAILED`, and V01/V02/V03 blocked unless independently observed evidence supports a different state. If an A-blank round occurs, report D/T according to the approved interpretation matrix. If none occurs, mark the targeted anomaly `not-reproduced`. Do not claim a repair, workaround, root cause, or candidate promotion.

## Self-Review

- Spec coverage: Tasks 1 and 2 cover F7 isolation, D/T ordering, identity, atomic bounded PNGs, failure behavior, and regressions; Task 3 covers offline build, one live run, all 20 image reviews, and truthful documentation.
- Placeholder scan: no unresolved placeholders or deferred implementation steps. Runtime hashes and visual states must be measured, not prefilled.
- Type consistency: native `detailFileName`/`rootFileName` and dimension keys map to runner prefixes `detail`/`root`; manifest names `detailRenderCapture`/`rootRenderCapture` match the tests; B destination and CLI names are consistent.
