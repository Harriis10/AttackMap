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

