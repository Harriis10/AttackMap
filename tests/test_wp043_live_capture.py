import argparse
import base64
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from tools.capture_wp043_live import (
    LiveBackend,
    WindowsLiveBackend,
    FrameSafetyError,
    ClientModalInspectionError,
    NativeWindowSafetyError,
    NavigationFocusError,
    WindowEnumerationError,
    WindowInfo,
    choose_owned_window,
    diagram_activation_acknowledged,
    diagram_content_ready,
    diagnostics_snapshot_ready,
    finding_selection_acknowledged,
    intervention_acknowledged,
    intersecting_occluders,
    navigation_acknowledged,
    run,
    validate_capture_name,
    validate_new_output,
    _png_quality,
    _detail_root_png,
    _require_safe,
    _error_details,
    _native_window_snapshot,
    _owned_transient_only,
    _window_details,
)


RUN_ID = "ui-run-1"
REPORT_HASH = "a" * 64


def make_event(sequence, kind, **detail):
    return {"sequence": sequence, "runId": RUN_ID, "kind": kind, "detail": detail}


def navigation_event(sequence, label, revision=1, report_hash=REPORT_HASH, theme="Dark"):
    return make_event(
        sequence,
        "navigation-after-turn",
        rootTheme=theme,
        selectedDestination=label,
        headingText=label,
        generation=1,
        displayedRun="saved-run",
        displayedReadHash=report_hash,
        navigationRevision=revision,
        navigation=[],
        heading={},
    )


def owned_window(pid=4242, **changes):
    values = {
        "hwnd": 100,
        "pid": pid,
        "title": "AttackMap",
        "visible": True,
        "minimized": False,
        "cloaked": False,
        "rect": (40, 40, 1640, 1040),
        "z_order": 10,
    }
    values.update(changes)
    return WindowInfo(**values)


class FakeImage:
    def __init__(self, payload):
        self.payload = payload


class FakeBackend(LiveBackend):
    def __init__(self, report_hash=REPORT_HASH):
        self.pid = None
        self.alive = False
        self.window = owned_window()
        self.windows = [self.window]
        self.foreground = 0
        self.events = []
        self.keys = []
        self.operations = []
        self.kill_calls = []
        self.pending_label = None
        self.focused_navigation = None
        self.selected_label = "Findings"
        self.navigation_revision = 0
        self.finding_revision = 0
        self.report_hash = report_hash
        self.fail_dispatch_label = None
        self.ack_shortcuts = True
        self.close_cleanly = True
        self.on_grab = None
        self.capture_count = 0
        self.launch_environment = None
        self.diagram_view = "Interactive architecture"
        self.diagram_legacy_available = True
        self.diagram_activation_available = True
        self.diagnostics_dir = None
        self.detail_render_probe_failed = False
        self.detail_root_render_probe_failed = None
        self.finding_detail_text = "finding-1\nFirst finding\n\nEvidence (engine supplied; classification shown above)\nproof"
        self.finding_detail_visible = True

    def _append(self, kind, **detail):
        self.events.append(make_event(len(self.events) + 1, kind, **detail))

    def launch(self, command, environment, cwd, stdout_path, stderr_path, diagnostics_dir):
        self.pid = 4242
        self.alive = True
        self.report_hash = hashlib.sha256(Path(command[2]).read_bytes()).hexdigest()
        self.launch_environment = dict(environment)
        self.diagnostics_dir = Path(diagnostics_dir)
        Path(stdout_path).write_bytes(b"")
        Path(stderr_path).write_bytes(b"")
        self._append("enabled", processId=self.pid)
        self._append(
            "loaded",
            rootTheme="Dark",
            selectedDestination="Findings",
            headingText="Findings",
            generation=1,
            displayedRun="saved-run",
            displayedReadHash=self.report_hash,
            navigationRevision=0,
            navigation=[],
            heading={},
        )
        return self.pid

    def read_events(self):
        return list(self.events)

    def wait_for_window(self, pid, timeout):
        return choose_owned_window(self.windows, pid)

    def list_windows(self):
        return list(self.windows)

    def process_alive(self):
        return self.alive

    def foreground_hwnd(self):
        return self.foreground

    def restore(self, window):
        self.operations.append("restore")
        self.window.minimized = False

    def activate(self, window):
        self.operations.append("activate")
        self.foreground = window.hwnd

    def move_resize(self, window, width, height):
        self.operations.append("resize")
        if self.window.minimized:
            raise AssertionError("resized while minimized")
        self.window.rect = (40, 40, 40 + width, 40 + height)

    def focus_navigation(self, window, label):
        self.operations.append(("focus", label))
        self.pending_label = label
        self.focused_navigation = (window.hwnd, label)

    def require_navigation_focus(self, window, label):
        self.operations.append(("verify-focus", label))
        if self.focused_navigation != (window.hwnd, label):
            raise NavigationFocusError({"api": "UIAutomation", "failureStage": "navigation-keyboard-focus"})

    def select_first_finding(self, window):
        self.operations.append("select-first-finding")
        self.finding_revision += 1
        self._append(
            "finding-selection",
            generation=1,
            displayedRun="saved-run",
            displayedReadHash=self.report_hash,
            navigationRevision=self.navigation_revision,
            findingRevision=self.finding_revision,
            hasFinding=True,
        )

    def _navigate(self, label):
        if label == self.fail_dispatch_label:
            return
        self.selected_label = label
        self.navigation_revision += 1
        self.events.append(navigation_event(len(self.events) + 1, label, self.navigation_revision, self.report_hash))
        if label == "Diagrams" and self.diagram_activation_available:
            self._append(
                "activation-completed",
                generation=1,
                displayedRun="saved-run",
                displayedReadHash=self.report_hash,
                navigationRevision=self.navigation_revision,
                viewKind="interactive",
                selectionRevision=1,
            )

    def select_diagram_view(self, window, label):
        self.operations.append(("diagram-view", label))
        self.diagram_view = label

    def read_diagram_content(self, window):
        legacy = self.diagram_view == "Report diagrams and summary"
        return {
            "selectedView": self.diagram_view,
            "notice": "" if legacy or not self.diagram_activation_available else "Captured run saved-run. 40 nodes; 39 original relationships.",
            "reportArchitectureVisible": not legacy and self.diagram_activation_available,
            "legacyText": "Complete supplied source:\nartifact" if legacy and self.diagram_legacy_available else "",
        }

    def read_finding_detail(self, window):
        return {"text": self.finding_detail_text, "visible": self.finding_detail_visible}

    def send_key(self, key):
        self.keys.append(key)
        if key == "ENTER" and self.pending_label is not None:
            self._navigate(self.pending_label)
        elif key == "CTRL+H" and self.ack_shortcuts:
            self._navigate("History")
        elif key == "CTRL+COMMA" and self.ack_shortcuts:
            self._navigate("Settings")
        elif key == "F9":
            self._append("f9-before-local-brush")
            self._append("f9-after-local-brush")
        elif key == "F10":
            self._append("f10-before-local-spacing")
            self._append("f10-after-local-spacing")
        elif key == "F11":
            self._append("f11-before-detail-spacing")
            self._append("f11-detail-spacing-changed", targetName="Detail", oldSpacing=0, newSpacing=1)
            self._append("f11-after-detail-spacing")
        elif key == "F12":
            self._append("f12-before-detail-brush")
            self._append("f12-detail-brush-replaced", targetName="Detail", mutationApplied=True)
            self._append("f12-after-detail-brush")
        elif key == "CTRL+ALT+SHIFT+R":
            context = dict(
                probeId=f"root-probe-{self.finding_revision}", generation=1,
                displayedReadHash=self.report_hash, navigationRevision=self.navigation_revision,
                findingRevision=self.finding_revision,
            )
            self._append("detail-root-render-capture-started", **context)
            if self.detail_root_render_probe_failed is not None:
                self._append("detail-root-render-capture-failed", **context, errorType="IOException")
                return
            from PIL import Image
            import io
            raster = Image.new("RGBA", (2, 1), (255, 255, 255, 255))
            raster.putpixel((1, 0), (255, 255, 255, 128))
            stream = io.BytesIO()
            raster.save(stream, format="PNG")
            png = stream.getvalue()
            detail_name = f"detail-root-render-detail-r{self.finding_revision:02d}.png"
            root_name = f"detail-root-render-root-r{self.finding_revision:02d}.png"
            (self.diagnostics_dir / detail_name).write_bytes(png)
            (self.diagnostics_dir / root_name).write_bytes(png)
            self._append(
                "detail-root-render-capture-completed", **context,
                detailFileName=detail_name, rootFileName=root_name,
                detailWidth=2, detailHeight=1, rootWidth=2, rootHeight=1, scale=1.0,
            )
        elif key == "F8":
            context = dict(
                probeId=f"probe-{self.finding_revision}", generation=1,
                displayedReadHash=self.report_hash, navigationRevision=self.navigation_revision,
                findingRevision=self.finding_revision,
            )
            self._append("detail-render-capture-started", **context)
            if self.detail_render_probe_failed:
                self._append("detail-render-capture-failed", **context, errorType="IOException")
                return
            file_name = f"detail-render-r{self.finding_revision:02d}.png"
            (self.diagnostics_dir / file_name).write_bytes(
                b"\x89PNG\r\n\x1a\nfake-" + file_name.encode("ascii"))
            self._append(
                "detail-render-capture-completed", **context, fileName=file_name,
                width=624, height=2412, scale=1.0,
            )

    def grab(self, window):
        self.capture_count += 1
        image = FakeImage(f"capture-{self.capture_count}".encode("ascii"))
        if self.on_grab is not None:
            self.on_grab()
        return image

    def grab_print_window(self, window):
        self.capture_count += 1
        return FakeImage(f"print-window-{self.capture_count}".encode("ascii"))

    def client_modal_details(self, window):
        return []

    def save_image(self, image, path):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_bytes(image.payload)

    def close(self, window):
        self.operations.append("close")
        if self.close_cleanly:
            self.alive = False

    def wait_exit(self, timeout):
        return self.alive is False

    def kill_owned_tree(self):
        self.kill_calls.append(self.pid)
        self.alive = False


class WP043LiveCaptureTests(unittest.TestCase):
    def test_diagram_activation_before_navigation_ack_is_bound_to_dispatch(self):
        for failed in (False, True):
            with self.subTest(failed=failed), tempfile.TemporaryDirectory() as temporary:
                class EarlyActivationBackend(FakeBackend):
                    def _navigate(self, label):
                        super()._navigate(label)
                        if label == "Diagrams":
                            activation = self.events.pop()
                            if failed:
                                activation["kind"] = "activation-failed"
                                activation["detail"].update(
                                    errorType="InvalidDataException", errorMessage="engine unavailable",
                                )
                            self.events.insert(len(self.events) - 1, activation)
                            for index, event in enumerate(self.events, 1):
                                event["sequence"] = index

                evidence = run(self.make_args(Path(temporary)), EarlyActivationBackend())
                if failed:
                    self.assertEqual(evidence["status"], "failed")
                    self.assertIn("engine unavailable", str(evidence["error"]))
                    self.assertNotIn("Timed out", str(evidence["error"]))
                else:
                    self.assertEqual(evidence["status"], "independent-live-window-captured")

    def test_explicit_engine_is_seeded_only_in_isolated_profile_before_launch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args = self.make_args(root)
            args.engine = Path(__file__).resolve()
            backend = FakeBackend()
            original_launch = backend.launch

            def launch(command, environment, *other):
                settings_path = Path(environment["LOCALAPPDATA"]) / "AttackMap" / "NativePreview" / "settings.json"
                self.assertTrue(settings_path.is_relative_to(args.output))
                self.assertEqual(json.loads(settings_path.read_text()), {
                    "SchemaVersion": 1, "PythonPath": str(args.engine),
                })
                return original_launch(command, environment, *other)

            backend.launch = launch
            evidence = run(args, backend)
            self.assertEqual(evidence["status"], "independent-live-window-captured")
            self.assertEqual(evidence["inputs"]["engine"]["sha256"], hashlib.sha256(args.engine.read_bytes()).hexdigest())

    def test_relative_engine_is_rejected_before_output_creation(self):
        with tempfile.TemporaryDirectory() as temporary:
            args = self.make_args(Path(temporary))
            args.engine = Path("engine.exe")
            with self.assertRaisesRegex(ValueError, "absolute"):
                run(args, FakeBackend())
            self.assertFalse(args.output.exists())

    def make_args(self, root, backend=None):
        # FakeBackend never executes this file; the harness only resolves and hashes it.
        executable = Path(__file__).resolve()
        report = root / "attackmap-report.json"
        report.write_bytes(b'{"findings": [{"id": "finding-1", "title": "First finding"}]}')
        return argparse.Namespace(
            executable=executable,
            report=report,
            output=root / "fresh-output",
            native_only=True,
            theme="dark",
            width=1600,
            height=1000,
            rounds=5,
            diagnostic_interventions=False,
            detail_spacing_probe_round=0,
            detail_brush_probe_round=0,
            detail_render_probe=False,
            detail_root_render_probe=False,
            print_window_detail_capture=False,
            window_timeout=0.02,
            action_timeout=0.02,
            exit_timeout=0.02,
            poll_interval=0,
            layout_delay=0,
            placement_delay=0,
        )

    def test_owned_window_requires_pid_visible_and_unique(self):
        self.assertEqual(choose_owned_window([owned_window()], 4242).hwnd, 100)
        with self.assertRaisesRegex(RuntimeError, "visible"):
            choose_owned_window([owned_window(visible=False)], 4242)
        with self.assertRaisesRegex(RuntimeError, "exactly one"):
            choose_owned_window([owned_window(), owned_window(hwnd=101)], 4242)

    def test_wrong_pid_or_duplicate_window_fails_before_input(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            backend = FakeBackend()
            backend.window.pid = 999
            evidence = run(self.make_args(root), backend)
            self.assertEqual(evidence["status"], "failed")
            self.assertEqual(backend.keys, [])
        with self.assertRaisesRegex(RuntimeError, "exactly one"):
            choose_owned_window([owned_window(), owned_window(hwnd=101)], 4242)

    def test_minimized_window_is_restored_before_resize(self):
        with tempfile.TemporaryDirectory() as temporary:
            backend = FakeBackend()
            backend.window.minimized = True
            evidence = run(self.make_args(Path(temporary)), backend)
            self.assertEqual(evidence["status"], "independent-live-window-captured")
            self.assertLess(backend.operations.index("restore"), backend.operations.index("resize"))

    def test_failed_foreground_reacquisition_identifies_actual_window(self):
        class ForeignForegroundBackend(FakeBackend):
            def activate(self, window):
                super().activate(window)
                self.foreground = 200

        with tempfile.TemporaryDirectory() as temporary:
            backend = ForeignForegroundBackend()
            backend.foreground = 200
            backend.windows.append(owned_window(hwnd=200, pid=777, title="Actual foreground"))
            evidence = run(self.make_args(Path(temporary)), backend)
            self.assertEqual(evidence["status"], "failed")
            self.assertIn("hwnd=200", evidence["error"]["message"])
            self.assertIn("pid=777", evidence["error"]["message"])
            self.assertIn("Actual foreground", evidence["error"]["message"])

    def test_unenumerated_foreground_failure_retains_numeric_hwnd(self):
        class ForeignForegroundBackend(FakeBackend):
            def activate(self, window):
                super().activate(window)
                self.foreground = 200

        with tempfile.TemporaryDirectory() as temporary:
            evidence = run(self.make_args(Path(temporary)), ForeignForegroundBackend())
            self.assertEqual(evidence["status"], "failed")
            self.assertIn("hwnd=200", evidence["error"]["message"])
            self.assertIn("not enumerated", evidence["error"]["message"])

    def test_occluding_visible_higher_z_window_discards_frame(self):
        occluder = owned_window(hwnd=200, pid=777, title="Overlay", z_order=1, rect=(40, 40, 500, 500))
        self.assertEqual(intersecting_occluders([owned_window(), occluder], owned_window()), [occluder])
        with tempfile.TemporaryDirectory() as temporary:
            backend = FakeBackend()
            backend.on_grab = lambda: backend.windows.append(occluder)
            evidence = run(self.make_args(Path(temporary)), backend)
            self.assertEqual(evidence["status"], "failed")
            self.assertEqual(evidence["discardedCaptures"][0]["status"], "discarded-invalid")
            self.assertIn("occlud", evidence["discardedCaptures"][0]["reason"])

    def test_owned_transient_appearing_before_capture_is_dismissed_once(self):
        class RacingTransientBackend(FakeBackend):
            def __init__(self):
                super().__init__()
                self.acknowledgment_observed = False
                self.race_injected = False

            def read_events(self):
                events = super().read_events()
                if self.selected_label == "Overview" and self.capture_count == 0:
                    if not self.acknowledgment_observed:
                        self.acknowledgment_observed = True
                    elif not self.race_injected:
                        self.race_injected = True
                        self.windows.append(owned_window(
                        hwnd=200,
                        title="Hostitel místní nabídky",
                        z_order=1,
                        rect=(818, 25, 861, 67),
                    ))
                return events

            def close(self, window):
                if window.title == "Hostitel místní nabídky":
                    self.operations.append("close-owned-transient")
                    self.windows = [item for item in self.windows if item.hwnd != window.hwnd]
                    return
                super().close(window)

        with tempfile.TemporaryDirectory() as temporary:
            backend = RacingTransientBackend()
            evidence = run(self.make_args(Path(temporary)), backend)
            self.assertEqual(evidence["status"], "independent-live-window-captured")
            self.assertEqual(len(evidence["captures"]), 75)
            self.assertEqual(evidence["captures"][0]["name"], "r01-01-Overview-after-transient")
            self.assertEqual(backend.operations.count("close-owned-transient"), 1)

    def _transient_recovery_race(self, phase, original_failure, recovery_change=None):
        def changed_target(change):
            target = owned_window()
            if change == "geometry":
                target.rect = (60, 40, 1660, 1040)
            elif change == "identity":
                target.hwnd = 101
            return target

        class LaterTransientBackend(FakeBackend):
            def __init__(self):
                super().__init__()
                self.recovery_reads = None
                self.recursive_blocker_observations = 0

            def list_windows(self):
                windows = super().list_windows()
                if self.recovery_reads is not None:
                    self.recovery_reads += 1
                    # The first read confirms the allowed close cleared. The
                    # next is the recursive entry precheck; this blocker has
                    # disappeared before the following full safety inspection.
                    if self.recovery_reads == 2:
                        self.recursive_blocker_observations += 1
                        windows.append(owned_window(hwnd=200, pid=777, title="External", z_order=1))
                        if recovery_change == "mixed-recursive-precheck":
                            windows.append(owned_window(
                                hwnd=202, title="Hostitel místní nabídky", z_order=0))
                return windows

            def close(self, window):
                if window.title == "Hostitel místní nabídky":
                    self.operations.append("close-owned-transient")
                    self.windows = [self.window]
                    if recovery_change in {"external-recursive-precheck", "mixed-recursive-precheck"}:
                        self.recovery_reads = 0
                    if recovery_change and recovery_change.endswith("-after-close"):
                        change = recovery_change.removesuffix("-after-close")
                        self.windows = [changed_target(change)]
                        if change == "foreground":
                            self.foreground = 200
                    return
                super().close(window)

        backend = LaterTransientBackend()
        injected = False

        def inspect(current_backend, current, run_id, report_hash, *, inspection_context=None):
            nonlocal injected
            if injected or inspection_context["actionPhase"] != phase:
                return _require_safe(current_backend, current, run_id, report_hash,
                                     inspection_context=inspection_context)
            injected = True
            transient = owned_window(hwnd=201, title="Hostitel místní nabídky", z_order=0)
            external = owned_window(hwnd=200, pid=777, title="External", z_order=1)
            target = owned_window()
            if original_failure == "geometry":
                # A same-size position change is not rejected by the first native
                # check, but must never qualify that occlusion for recovery.
                target.rect = (60, 40, 1660, 1040)
            elif original_failure == "identity":
                target.hwnd = 101
            elif original_failure == "foreground":
                backend.foreground = external.hwnd
            blockers = [external] if original_failure in {"external", "mixed"} else [transient]
            if original_failure == "mixed":
                blockers.append(transient)
            backend.windows = [target, *blockers]
            try:
                if original_failure == "generic":
                    raise FrameSafetyError("Unclassified safety failure")
                if original_failure == "unknown":
                    raise NativeWindowSafetyError("Incomplete native safety provenance", {
                        "failureStage": "occlusion", "occlusion": {
                            "status": "blocked", "blockers": [_window_details(transient)]},
                    })
                return _require_safe(current_backend, current, run_id, report_hash,
                                     inspection_context=inspection_context)
            finally:
                # The original blocker/error has disappeared before recovery
                # sees a different, valid owned transient. It cannot erase it.
                backend.windows = [backend.window, transient]
                backend.foreground = backend.window.hwnd
                if recovery_change in {"geometry", "identity"}:
                    backend.windows[0] = changed_target(recovery_change)
                elif recovery_change == "foreground":
                    backend.foreground = 200
                elif recovery_change == "external":
                    backend.windows.append(external)

        with tempfile.TemporaryDirectory() as temporary:
            with patch("tools.capture_wp043_live._require_safe", side_effect=inspect):
                evidence = run(self.make_args(Path(temporary)), backend)
        self.assertTrue(injected)
        return evidence, backend

    def test_later_owned_transient_cannot_recover_original_unsafe_failure(self):
        for phase in ("navigation-before-enter", "capture-before-grab", "capture-after-grab"):
            for failure in ("external", "mixed", "generic", "unknown", "geometry", "identity", "foreground"):
                with self.subTest(phase=phase, failure=failure):
                    evidence, backend = self._transient_recovery_race(phase, failure)
                    self.assertEqual(evidence["status"], "failed")
                    self.assertEqual(evidence["captures"], [])
                    self.assertEqual(len(evidence["discardedCaptures"]), int(phase == "capture-after-grab"))
                    self.assertNotIn("close-owned-transient", backend.operations)
                    if failure in {"external", "mixed"}:
                        source = (evidence["discardedCaptures"][0]["error"]
                                  if phase == "capture-after-grab" else evidence["error"])
                        self.assertEqual(source["failureStage"], "occlusion")
                        self.assertEqual(len(source["occlusion"]["blockers"]), 2 if failure == "mixed" else 1)
                        self.assertEqual(source["occlusion"]["blockers"][0]["pid"], 777)

    def test_original_owned_transient_recovers_all_safety_branches(self):
        for phase in ("navigation-before-enter", "capture-before-grab", "capture-after-grab"):
            with self.subTest(phase=phase):
                evidence, backend = self._transient_recovery_race(phase, "owned")
                self.assertEqual(evidence["status"], "independent-live-window-captured")
                self.assertEqual(len(evidence["captures"]), 75)
                self.assertEqual(backend.operations.count("close-owned-transient"), 1)
                self.assertEqual(len(evidence["discardedCaptures"]), int(phase == "capture-after-grab"))

    def test_owned_transient_recovery_rejects_changed_target_or_new_external_blocker(self):
        for phase in ("navigation-before-enter", "capture-before-grab", "capture-after-grab"):
            for change in ("geometry", "identity", "foreground", "external",
                           "geometry-after-close", "identity-after-close", "foreground-after-close"):
                with self.subTest(phase=phase, change=change):
                    evidence, backend = self._transient_recovery_race(phase, "owned", change)
                    self.assertEqual(evidence["status"], "failed")
                    self.assertEqual(evidence["captures"], [])
                    self.assertEqual(len(evidence["discardedCaptures"]), int(phase == "capture-after-grab"))
                    self.assertEqual(backend.operations.count("close-owned-transient"), int(change.endswith("-after-close")))

    def test_recursive_recovery_precheck_rejects_a_fleeting_external_or_mixed_blocker(self):
        for phase in ("navigation-before-enter", "capture-before-grab", "capture-after-grab"):
            for change in ("external-recursive-precheck", "mixed-recursive-precheck"):
                with self.subTest(phase=phase, change=change):
                    evidence, backend = self._transient_recovery_race(phase, "owned", change)
                    self.assertEqual(backend.recursive_blocker_observations, 1)
                    self.assertEqual(backend.operations.count("close-owned-transient"), 1)
                    self.assertEqual(evidence["status"], "failed")
                    self.assertIn("external or mixed occlusion", evidence["error"]["message"])
                    self.assertEqual(evidence["captures"], [])
                    self.assertEqual(len(evidence["discardedCaptures"]), int(phase == "capture-after-grab"))

    def test_repeated_owned_transients_get_bounded_safe_capture_retries(self):
        class RepeatedTransientBackend(FakeBackend):
            def __init__(self):
                super().__init__()
                self.transient_closes = 0

            def close(self, window):
                if window.title != "Hostitel místní nabídky":
                    super().close(window)
                    return
                self.operations.append("close-owned-transient")
                self.transient_closes += 1
                self.windows = [item for item in self.windows if item.hwnd != window.hwnd]

        with tempfile.TemporaryDirectory() as temporary:
            backend = RepeatedTransientBackend()
            def inject_repeated_transient():
                if backend.capture_count <= 2:
                    backend.windows.append(owned_window(
                        hwnd=200 + backend.capture_count, title="Hostitel místní nabídky",
                        z_order=1, rect=(818, 25, 861, 67)))
            backend.on_grab = inject_repeated_transient
            evidence = run(self.make_args(Path(temporary)), backend)
            self.assertEqual(evidence["status"], "independent-live-window-captured")
            self.assertEqual(len(evidence["captures"]), 75)
            self.assertEqual(backend.operations.count("close-owned-transient"), 2)
            self.assertEqual(evidence["captures"][0]["name"], "r01-01-Overview-after-transient-after-transient")
            self.assertEqual(len(evidence["discardedCaptures"]), 2)

    def test_navigation_gets_three_bounded_owned_transient_retries(self):
        class RepeatedNavigationTransientBackend(FakeBackend):
            def __init__(self):
                super().__init__()
                self.transients_remaining = 0
                self.transient_closes = 0
                self.replacement_pending = False

            def read_events(self):
                if self.replacement_pending:
                    self.replacement_pending = False
                    self._inject_transient()
                return super().read_events()

            def focus_navigation(self, window, label):
                super().focus_navigation(window, label)
                if label == "Architecture" and self.capture_count == 3 and not self.transient_closes:
                    self.transients_remaining = 3
                    self._inject_transient()

            def _inject_transient(self):
                self.windows.append(owned_window(
                    hwnd=200 + self.transient_closes,
                    title="Hostitel místní nabídky", z_order=1,
                    rect=(818, 25, 861, 67)))

            def close(self, window):
                if window.title != "Hostitel místní nabídky":
                    super().close(window)
                    return
                self.operations.append("close-owned-transient")
                self.transient_closes += 1
                self.transients_remaining -= 1
                self.windows = [item for item in self.windows if item.hwnd != window.hwnd]
                if self.transients_remaining:
                    self.replacement_pending = True

        with tempfile.TemporaryDirectory() as temporary:
            backend = RepeatedNavigationTransientBackend()
            evidence = run(self.make_args(Path(temporary)), backend)
            self.assertEqual(evidence["status"], "independent-live-window-captured")
            self.assertEqual(len(evidence["captures"]), 75)
            self.assertEqual(backend.operations.count("close-owned-transient"), 3)

    def test_owned_transient_disappearing_before_dismissal_retries_capture(self):
        class DisappearingTransientBackend(FakeBackend):
            def __init__(self):
                super().__init__()
                self.race_reads = 0

            def list_windows(self):
                windows = super().list_windows()
                if self.race_reads:
                    self.race_reads -= 1
                    if self.race_reads == 0:
                        windows.append(owned_window(
                            hwnd=200, title="Hostitel místní nabídky",
                            z_order=1, rect=(818, 25, 861, 67)))
                return windows

        with tempfile.TemporaryDirectory() as temporary:
            backend = DisappearingTransientBackend()
            def inject_race_once():
                if backend.capture_count == 1:
                    backend.race_reads = 2
            backend.on_grab = inject_race_once
            evidence = run(self.make_args(Path(temporary)), backend)
            self.assertEqual(evidence["status"], "independent-live-window-captured")
            self.assertEqual(len(evidence["captures"]), 75)
            self.assertEqual(evidence["captures"][0]["name"], "r01-01-Overview-after-transient")
            self.assertEqual(len(evidence["discardedCaptures"]), 1)

    def test_owned_transient_appearing_before_finding_selection_is_dismissed_once(self):
        class RacingTransientBackend(FakeBackend):
            def __init__(self):
                super().__init__()
                self.post_capture_reads = 0
                self.race_injected = False

            def read_events(self):
                events = super().read_events()
                if self.selected_label == "Findings" and self.capture_count == 2 and not self.race_injected:
                    self.post_capture_reads += 1
                    if self.post_capture_reads == 2:
                        self.race_injected = True
                        self.windows.append(owned_window(
                            hwnd=200,
                            title="Hostitel místní nabídky",
                            z_order=1,
                            rect=(818, 25, 861, 67),
                        ))
                return events

            def close(self, window):
                if window.title == "Hostitel místní nabídky":
                    self.operations.append("close-owned-transient")
                    self.windows = [item for item in self.windows if item.hwnd != window.hwnd]
                    return
                super().close(window)

        with tempfile.TemporaryDirectory() as temporary:
            backend = RacingTransientBackend()
            evidence = run(self.make_args(Path(temporary)), backend)
            self.assertEqual(evidence["status"], "independent-live-window-captured")
            self.assertEqual(len(evidence["captures"]), 75)
            self.assertEqual(backend.operations.count("close-owned-transient"), 1)

    def test_settings_navigation_uses_localization_independent_automation_id(self):
        item = self._navigation_item(name="Nastavení", automation_id="SettingsItem")
        backend = self._navigation_backend([item])
        backend.focus_navigation(owned_window(), "Settings")
        self.assertTrue(item.focused)
        backend.require_navigation_focus(owned_window(), "Settings")

    @staticmethod
    def _navigation_item(*, name="Overview", automation_id="", focus_error=None, keyboard_value=True):
        item = SimpleNamespace(
            CurrentName=name, CurrentAutomationId=automation_id,
            CurrentClassName="Microsoft.UI.Xaml.Controls.NavigationViewItem", CurrentControlType=50007,
            focused=False,
        )

        def focus():
            if focus_error is not None:
                raise focus_error
            item.focused = True

        def keyboard_focus(property_id):
            if property_id != 30008:
                raise AssertionError("Read the direct HasKeyboardFocus property")
            if isinstance(keyboard_value, Exception):
                raise keyboard_value
            return keyboard_value

        item.SetFocus = focus
        item.GetCurrentPropertyValue = keyboard_focus
        return item

    def _navigation_backend(self, items):
        return self._modal_backend([items])

    def test_navigation_set_focus_errors_are_fatal_and_keep_hresult(self):
        failure = self._uia_error(0x80070005)
        backend = self._navigation_backend([self._navigation_item(focus_error=failure)])
        with self.assertRaises(NavigationFocusError) as raised:
            backend.focus_navigation(owned_window(), "Overview")
        details = _error_details(raised.exception)
        self.assertEqual(details["failureStage"], "navigation-set-focus")
        self.assertEqual(details["cause"]["hresultHex"], "0x80070005")
        self.assertIsNone(backend._navigation_focus)

    def test_navigation_keyboard_focus_false_invalid_or_unreadable_is_fatal(self):
        for value in (False, 2, self._uia_error(0x80040201)):
            with self.subTest(value=value):
                backend = self._navigation_backend([self._navigation_item(keyboard_value=value)])
                with self.assertRaises(NavigationFocusError) as raised:
                    backend.focus_navigation(owned_window(), "Overview")
                self.assertEqual(raised.exception.diagnostics["failureStage"], "navigation-keyboard-focus")
                self.assertEqual(raised.exception.diagnostics["propertyId"], 30008)
                self.assertEqual(backend.scan_count, 1)

    def test_keyboard_focus_loss_after_transient_dismissal_prevents_global_enter(self):
        class FocusLostAfterDismissal(FakeBackend):
            injected = False

            def client_modal_details(self, window):
                if self.pending_label == "Overview" and not self.injected:
                    self.injected = True
                    self.windows.append(owned_window(hwnd=200, title="Hostitel místní nabídky", z_order=1))
                return []

            def close(self, window):
                if window.hwnd == 200:
                    self.windows = [item for item in self.windows if item.hwnd != 200]
                    self.focused_navigation = None
                    self.operations.append("close-owned-transient")
                    return
                super().close(window)

        with tempfile.TemporaryDirectory() as temporary:
            backend = FocusLostAfterDismissal()
            evidence = run(self.make_args(Path(temporary)), backend)
        self.assertEqual(evidence["status"], "failed")
        self.assertEqual(evidence["error"]["failureStage"], "navigation-keyboard-focus")
        self.assertEqual(backend.keys, [])
        self.assertEqual(backend.operations.count("close-owned-transient"), 1)
        self.assertEqual(evidence["captures"], [])

    def test_native_snapshot_uses_one_enumeration_for_target_and_blocker_z_order(self):
        backend = FakeBackend()
        backend.alive, backend.foreground = True, 100
        target = owned_window(z_order=30, class_name="ActualTargetClass")
        blocker = owned_window(hwnd=200, pid=777, title="External", z_order=20, class_name="ActualBlockerClass")
        # A second enumeration would reverse the relationship. It must remain unused.
        with patch.object(backend, "list_windows", side_effect=[[target, blocker],
                          [owned_window(z_order=10), blocker]]) as enumerate_windows:
            with self.assertRaises(NativeWindowSafetyError) as raised:
                _native_window_snapshot(backend, owned_window(), "test")
        enumerate_windows.assert_called_once_with()
        details = _error_details(raised.exception)
        self.assertEqual(details["failureStage"], "occlusion")
        self.assertEqual(details["targetAfter"]["zOrder"], 30)
        self.assertEqual(details["occlusion"]["blockers"][0]["zOrder"], 20)
        self.assertEqual(details["targetAfter"]["className"], "ActualTargetClass")
        self.assertEqual(details["occlusion"]["blockers"][0]["className"], "ActualBlockerClass")

    def test_native_snapshot_distinguishes_geometry_foreground_identity_and_occlusion(self):
        for failure in ("geometry", "foreground", "identity"):
            backend = FakeBackend()
            backend.alive, backend.foreground = True, 100
            current = owned_window(rect=(60, 40, 1660, 1040) if failure == "geometry" else (40, 40, 1640, 1040),
                                   cloaked=failure == "identity")
            backend.windows = [current]
            if failure == "foreground":
                backend.foreground = 200
                backend.windows.append(owned_window(hwnd=200, pid=777, title="Elsewhere", z_order=20))
            with self.subTest(failure=failure), self.assertRaises(NativeWindowSafetyError) as raised:
                _native_window_snapshot(backend, owned_window(), "test", require_same_rect=True)
            details = raised.exception.diagnostics
            self.assertEqual(details["failureStage"], failure)
            self.assertEqual(details[failure]["status"], "failed")
            self.assertEqual(details["occlusion"]["status"], "clear")
            self.assertEqual(details["geometry"]["beforeRect"], [40, 40, 1640, 1040])
            self.assertEqual(details["foreground"]["beforeHwnd"], backend.foreground)
            self.assertEqual(details["foreground"]["afterHwnd"], backend.foreground)

    def test_uia_retry_external_and_mixed_occlusion_is_fatal_with_context_and_one_snapshot(self):
        for mixed in (False, True):
            with self.subTest(mixed=mixed):
                stale = self._modal_item(fail_property=30174, error=self._uia_error(0x80040201))
                backend = self._modal_backend([[self._modal_item(), stale], []])
                backend.modal_inspection_context = {"actionPhase": "navigation-before-enter",
                    "destination": "Overview", "diagnosticsSequence": 42}
                target = owned_window(z_order=30)
                blockers = [owned_window(hwnd=200, pid=777, title="External", z_order=20)]
                if mixed:
                    blockers.append(owned_window(hwnd=201, title="Hostitel místní nabídky", z_order=10))
                with patch.object(backend, "list_windows", return_value=[target, *blockers]) as enumeration:
                    with self.assertRaises(ClientModalInspectionError) as raised:
                        backend.client_modal_details(owned_window())
                enumeration.assert_called_once_with()
                details = _error_details(raised.exception)
                self.assertEqual(details["inspectionInvocationId"], 1)
                self.assertEqual(details["actionPhase"], "navigation-before-enter")
                self.assertEqual(details["destination"], "Overview")
                self.assertEqual(details["diagnosticsSequence"], 42)
                self.assertEqual(details["attempt"], 2)
                self.assertEqual(details["attempts"][0]["descendantCount"], 2)
                self.assertEqual(details["failureStage"], "owned-target-recheck")
                safety = details["cause"]["nativeWindowSafety"]
                self.assertEqual(safety["failureStage"], "occlusion")
                self.assertEqual(len(safety["occlusion"]["blockers"]), 2 if mixed else 1)
                self.assertEqual(backend.scan_count, 1)

    def test_wrapped_uia_retry_recovers_only_the_exact_owned_native_snapshot(self):
        class WrappedRetryTransientBackend(FakeBackend):
            def __init__(self, blocker_pid=4242, blocker_title="Hostitel místní nabídky"):
                super().__init__()
                self.blocker_pid = blocker_pid
                self.blocker_title = blocker_title
                self.injected = False

            def client_modal_details(self, window):
                if self.injected:
                    return []
                self.injected = True
                self.windows = [self.window, owned_window(
                    hwnd=200, pid=self.blocker_pid, title=self.blocker_title, z_order=1)]
                try:
                    _native_window_snapshot(
                        self, window, "uia-retry-after-descendants", require_same_rect=True
                    )
                except NativeWindowSafetyError as native_error:
                    raise ClientModalInspectionError({
                        "api": "UIAutomation", "failureStage": "owned-target-recheck",
                        "attempt": 2, "classification": "inspection-failure", "status": "failed",
                    }) from native_error
                raise AssertionError("The injected popup must block the native target recheck")

            def close(self, window):
                if window.hwnd == 200:
                    self.operations.append("close-owned-transient")
                    self.windows = [self.window]
                    return
                super().close(window)

        with tempfile.TemporaryDirectory() as temporary:
            backend = WrappedRetryTransientBackend()
            evidence = run(self.make_args(Path(temporary)), backend)
        self.assertEqual(evidence["status"], "independent-live-window-captured")
        self.assertEqual(len(evidence["captures"]), 75)
        self.assertEqual(backend.operations.count("close-owned-transient"), 1)

        for blocker_pid, blocker_title in ((777, "External"), (777, "Hostitel místní nabídky")):
            with self.subTest(blocker_pid=blocker_pid, blocker_title=blocker_title), tempfile.TemporaryDirectory() as temporary:
                backend = WrappedRetryTransientBackend(blocker_pid, blocker_title)
                evidence = run(self.make_args(Path(temporary)), backend)
            self.assertEqual(evidence["status"], "failed")
            self.assertNotIn("close-owned-transient", backend.operations)
            self.assertEqual(evidence["error"]["failureStage"], "owned-target-recheck")

    def test_wrapped_uia_retry_requires_direct_second_attempt_native_provenance(self):
        backend = FakeBackend()
        target = owned_window()
        backend.alive = True
        backend.foreground = target.hwnd
        backend.windows = [target, owned_window(hwnd=200, title="Hostitel místní nabídky", z_order=1)]
        with self.assertRaises(NativeWindowSafetyError) as raised:
            _native_window_snapshot(backend, target, "uia-retry-after-descendants", require_same_rect=True)
        native_error = raised.exception

        for stage, attempt, modal_confirmed, phase in (
            ("owned-target-recheck", 2, False, "uia-retry-after-descendants"),
            ("descendants", 2, False, "uia-retry-after-descendants"),
            ("owned-target-recheck", 1, False, "uia-retry-after-descendants"),
            ("owned-target-recheck", 2, True, "uia-retry-after-descendants"),
            ("owned-target-recheck", 2, False, "after-client-inspection"),
        ):
            with self.subTest(stage=stage, attempt=attempt, modal_confirmed=modal_confirmed, phase=phase):
                candidate = NativeWindowSafetyError(
                    str(native_error), {**native_error.diagnostics, "phase": phase}
                )
                wrapped = ClientModalInspectionError({
                    "api": "UIAutomation", "failureStage": stage, "attempt": attempt,
                    "modalConfirmed": modal_confirmed,
                })
                wrapped.__cause__ = candidate
                self.assertEqual(
                    _owned_transient_only(wrapped, target),
                    stage == "owned-target-recheck" and attempt == 2 and not modal_confirmed
                    and phase == "uia-retry-after-descendants",
                )

    @unittest.skipUnless(__import__("os").name == "nt", "Windows HWND signatures")
    def test_windows_foreground_api_preserves_native_hwnd_width(self):
        from ctypes import wintypes
        from tools.capture_wp043_live import WindowsLiveBackend

        user32 = WindowsLiveBackend._user32()
        self.assertEqual(user32.GetForegroundWindow.restype, wintypes.HWND)
        self.assertEqual(user32.GetForegroundWindow.argtypes, [])
        for name in ("GetWindowTextLengthW", "GetWindowTextW", "IsWindowVisible", "IsIconic"):
            self.assertEqual(getattr(user32, name).argtypes[0], wintypes.HWND)

    def _enumerate_test_windows(self, *, callback_error=None, completed=True, winerror=0):
        import ctypes

        handles = (0x123456789, 0x23456789A)

        def process_id(hwnd, pid):
            pid._obj.value = 4242
            return 1

        def text_length(hwnd):
            if hwnd == handles[1] and callback_error is not None:
                raise callback_error
            return 9

        def text(hwnd, buffer, length):
            buffer.value = "AttackMap"
            return 9

        def rectangle(hwnd, rect):
            rect._obj.left, rect._obj.top = 40, 40
            rect._obj.right, rect._obj.bottom = 1640, 1040
            return True

        def enumerate_windows(callback, parameter):
            self.assertEqual(parameter, 0)
            self.assertEqual(ctypes.get_last_error(), 0)
            for hwnd in handles:
                if not callback(hwnd, parameter):
                    ctypes.set_last_error(winerror)
                    return False
            ctypes.set_last_error(winerror)
            return completed

        user32 = SimpleNamespace(
            GetWindowThreadProcessId=process_id, GetWindowTextLengthW=text_length,
            GetWindowTextW=text, GetClassNameW=text, GetWindowRect=rectangle,
            IsWindowVisible=lambda hwnd: True, IsIconic=lambda hwnd: False,
        )
        backend = WindowsLiveBackend.__new__(WindowsLiveBackend)
        backend._user32 = lambda: user32
        last_error = [999]
        with (
            patch.object(ctypes, "WinDLL", return_value=SimpleNamespace(EnumWindows=enumerate_windows), create=True) as loader,
            patch.object(ctypes, "WINFUNCTYPE", getattr(ctypes, "WINFUNCTYPE", ctypes.CFUNCTYPE), create=True),
            patch.object(ctypes, "set_last_error", lambda error: last_error.__setitem__(0, error), create=True),
            patch.object(ctypes, "get_last_error", lambda: last_error[0], create=True),
        ):
            windows = backend.list_windows()
            loader.assert_called_once_with("user32", use_last_error=True)
        return windows

    def test_window_enumeration_preserves_pointer_width_and_z_order(self):
        windows = self._enumerate_test_windows()
        self.assertEqual([window.hwnd for window in windows], [0x123456789, 0x23456789A])
        self.assertEqual([window.z_order for window in windows], [0, 1])
        self.assertEqual([window.class_name for window in windows], ["AttackMap", "AttackMap"])

    def test_window_enumeration_callback_exception_rejects_partial_list(self):
        original = ValueError("callback inspection failed")
        with self.assertRaises(WindowEnumerationError) as raised:
            self._enumerate_test_windows(callback_error=original, winerror=5)
        self.assertEqual(raised.exception.stage, "callback")
        self.assertEqual(raised.exception.hwnd, 0x23456789A)
        self.assertIs(raised.exception.__cause__, original)
        self.assertIn("ValueError: callback inspection failed", str(raised.exception))

    def test_window_enumeration_os_failure_rejects_partial_list_and_preserves_error(self):
        for code in (0, 5):
            with self.subTest(winerror=code), self.assertRaises(WindowEnumerationError) as raised:
                self._enumerate_test_windows(completed=False, winerror=code)
            self.assertEqual(raised.exception.stage, "OS call")
            self.assertEqual(raised.exception.winerror, code)
            self.assertIsNone(raised.exception.__cause__)
            self.assertIn(f"GetLastError={code}", str(raised.exception))

    def test_window_enumeration_failure_is_structured_failed_live_evidence(self):
        class EnumerationFailureBackend(FakeBackend):
            def list_windows(self):
                cause = ValueError("callback inspection failed")
                raise WindowEnumerationError("callback", 0, hwnd=123, cause=cause) from cause

        with tempfile.TemporaryDirectory() as temporary:
            evidence = run(self.make_args(Path(temporary)), EnumerationFailureBackend())
        self.assertEqual(evidence["status"], "failed")
        self.assertEqual(evidence["captures"], [])
        self.assertEqual(evidence["error"]["api"], "EnumWindows")
        self.assertEqual(evidence["error"]["failureStage"], "callback")
        self.assertEqual(evidence["error"]["winerror"], 0)
        self.assertEqual(evidence["error"]["cause"]["type"], "ValueError")

    def test_window_enumeration_safety_failure_retains_structured_evidence(self):
        for fail_after_grab in (False, True):
            with self.subTest(fail_after_grab=fail_after_grab), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                args = self.make_args(root)
                backend = FakeBackend()
                cause = ValueError("callback inspection failed during safety check")
                failure = WindowEnumerationError("callback", 5, hwnd=123, cause=cause)
                failure.__cause__ = cause

                def check_safety(*arguments, **keywords):
                    if backend.capture_count == int(fail_after_grab):
                        with patch.object(backend, "list_windows", side_effect=failure):
                            return _require_safe(*arguments, **keywords)
                    return _require_safe(*arguments, **keywords)

                with patch("tools.capture_wp043_live._require_safe", side_effect=check_safety):
                    evidence = run(args, backend)

                self.assertEqual(evidence["status"], "failed")
                self.assertEqual(evidence["captures"], [])
                self.assertEqual(backend.capture_count, int(fail_after_grab))
                self.assertEqual(len(evidence["discardedCaptures"]), int(fail_after_grab))
                self.assertEqual(evidence["error"]["api"], "EnumWindows")
                self.assertEqual(evidence["error"]["failureStage"], "callback")
                self.assertEqual(evidence["error"]["winerror"], 5)
                self.assertEqual(evidence["error"]["hwnd"], 123)
                self.assertEqual(evidence["error"]["cause"], {
                    "type": "ValueError", "message": str(cause),
                })
                self.assertEqual(
                    json.loads((args.output / "evidence.json").read_text(encoding="utf-8"))["error"],
                    evidence["error"],
                )

    def test_error_details_terminates_explicit_cause_cycles_and_ignores_context(self):
        for chain in ("self-cycle", "mutual-cycle", "unrelated"):
            with self.subTest(chain=chain):
                outer = RuntimeError("outer failure")
                inner = ValueError("unrelated cause")
                outer.__cause__ = outer if chain == "self-cycle" else inner
                if chain == "mutual-cycle":
                    inner.__cause__ = outer
                outer.__context__ = WindowEnumerationError("OS call", 5)
                self.assertEqual(_error_details(outer), {
                    "type": "RuntimeError", "message": "outer failure",
                })

    def test_error_details_retains_outer_failure_and_wrapped_enumeration_fields(self):
        cause = ValueError("callback inspection failed")
        enumeration = WindowEnumerationError("callback", 5, hwnd=123, cause=cause)
        enumeration.__cause__ = cause
        wrapper = RuntimeError("safety wrapper")
        wrapper.__cause__ = enumeration
        outer = RuntimeError("discarded frame")
        outer.__cause__ = wrapper
        self.assertEqual(_error_details(outer), {
            "type": "RuntimeError", "message": "discarded frame",
            "api": "EnumWindows", "failureStage": "callback", "winerror": 5, "hwnd": 123,
            "cause": {"type": "ValueError", "message": "callback inspection failed"},
        })

    def test_windows_process_id_reads_unenumerated_window_directly(self):
        from types import SimpleNamespace
        from tools.capture_wp043_live import WindowsLiveBackend

        def get_process_id(hwnd, pid):
            pid._obj.value = 777
            return 55
        backend = WindowsLiveBackend.__new__(WindowsLiveBackend)
        backend._user32 = lambda: SimpleNamespace(GetWindowThreadProcessId=get_process_id)
        self.assertEqual(backend.window_process_id(461196), 777)

    def test_cloaked_higher_z_window_does_not_count_as_occluder(self):
        cloaked = owned_window(hwnd=200, pid=777, title="Cloaked", z_order=1, cloaked=True)
        self.assertEqual(intersecting_occluders([owned_window(), cloaked], owned_window()), [])

    def test_foreground_changes_between_check_and_capture_discards_frame(self):
        with tempfile.TemporaryDirectory() as temporary:
            backend = FakeBackend()
            backend.on_grab = lambda: setattr(backend, "foreground", 0)
            evidence = run(self.make_args(Path(temporary)), backend)
            self.assertEqual(evidence["status"], "failed")
            self.assertIn("foreground", evidence["discardedCaptures"][0]["reason"])

    def test_navigation_requires_new_matching_diagnostics_sequence(self):
        events = [make_event(1, "enabled"), navigation_event(2, "Overview", revision=4)]
        self.assertTrue(navigation_acknowledged(events, 1, "Overview", expected_run_id=RUN_ID, expected_report_hash=REPORT_HASH, minimum_navigation_revision=4))
        wrong_heading = navigation_event(3, "Overview", revision=5)
        wrong_heading["detail"]["headingText"] = "Findings"
        self.assertFalse(navigation_acknowledged([wrong_heading], 1, "Overview"))

    def test_localized_settings_destination_still_requires_settings_content(self):
        settings = navigation_event(3, "Nastavení", revision=5)
        settings["detail"]["headingText"] = "Settings"
        self.assertTrue(navigation_acknowledged(
            [settings], 1, "Settings", expected_run_id=RUN_ID,
            expected_report_hash=REPORT_HASH, minimum_navigation_revision=5))

        missing_destination = navigation_event(4, "", revision=6)
        missing_destination["detail"]["headingText"] = "Settings"
        self.assertFalse(navigation_acknowledged([missing_destination], 1, "Settings"))
        wrong_heading = navigation_event(5, "Nastavení", revision=7)
        wrong_heading["detail"]["headingText"] = "Findings"
        self.assertFalse(navigation_acknowledged([wrong_heading], 1, "Settings"))

    def test_old_matching_navigation_event_does_not_acknowledge_new_key(self):
        events = [navigation_event(7, "Overview", revision=4)]
        self.assertFalse(navigation_acknowledged(events, 7, "Overview"))
        self.assertTrue(navigation_acknowledged(events, 6, "Overview"))

    def test_diagram_activation_requires_current_bound_graph(self):
        event = make_event(
            8, "activation-completed", generation=1, displayedRun="saved-run",
            displayedReadHash=REPORT_HASH, navigationRevision=4,
            viewKind="interactive", selectionRevision=1,
        )
        self.assertTrue(diagram_activation_acknowledged([event], 7, RUN_ID, REPORT_HASH, 4))
        self.assertFalse(diagram_activation_acknowledged([event], 8, RUN_ID, REPORT_HASH, 4))
        self.assertFalse(diagram_activation_acknowledged([event], 7, RUN_ID, REPORT_HASH, 5))
        stale = make_event(9, "activation-completed", displayedReadHash="stale", navigationRevision=4)
        self.assertFalse(diagram_activation_acknowledged([stale], 7, RUN_ID, REPORT_HASH, 4))

    def test_bound_diagram_failure_reports_cause_without_waiting_for_timeout(self):
        event = make_event(
            8, "activation-failed", displayedReadHash=REPORT_HASH,
            navigationRevision=4, viewKind="interactive",
            errorType="InvalidDataException",
            errorMessage="Choose an existing absolute engine executable path.",
        )
        with self.assertRaisesRegex(RuntimeError, "InvalidDataException: Choose an existing absolute engine"):
            diagram_activation_acknowledged([event], 7, RUN_ID, REPORT_HASH, 4)
        for change in (
            {"runId": "other"}, {"sequence": 7},
            {"detail": {**event["detail"], "displayedReadHash": "stale"}},
            {"detail": {**event["detail"], "navigationRevision": 3}},
            {"detail": {**event["detail"], "viewKind": "legacy"}},
        ):
            with self.subTest(change=change):
                self.assertFalse(diagram_activation_acknowledged(
                    [{**event, **change}], 7, RUN_ID, REPORT_HASH, 4,
                ))

    def test_diagram_inner_content_must_be_loaded_not_merely_selected(self):
        interactive = {
            "selectedView": "Interactive architecture",
            "notice": "Captured run saved-run. 40 nodes; 39 original relationships.",
            "reportArchitectureVisible": True,
            "legacyText": "",
        }
        self.assertTrue(diagram_content_ready(interactive, "Interactive architecture"))
        self.assertFalse(diagram_content_ready({**interactive, "notice": "Loading architecture"}, "Interactive architecture"))
        legacy = {"selectedView": "Report diagrams and summary", "legacyText": "Complete supplied source:\nartifact"}
        self.assertTrue(diagram_content_ready(legacy, "Report diagrams and summary"))
        self.assertFalse(diagram_content_ready({**legacy, "legacyText": ""}, "Report diagrams and summary"))
        placeholder = "Select a manifest-bound report to view its diagrams.\n\nComplete supplied source:\n"
        self.assertFalse(diagram_content_ready({**legacy, "legacyText": placeholder}, "Report diagrams and summary"))

    def test_windows_backend_reads_editor_by_its_explicit_uia_name(self):
        backend = WindowsLiveBackend()
        expected = "Complete supplied source:\nartifact"
        editor = SimpleNamespace(
            element_info=SimpleNamespace(
                control_type="Edit",
                name="Complete diagram nodes, edges and original source; selectable read-only text",
            ),
            get_value=lambda: expected,
        )
        native_window = SimpleNamespace(descendants=lambda: [editor])
        backend._uia_window = lambda window: native_window
        backend._diagram_view_selector = lambda window: SimpleNamespace(
            selected_text=lambda: "Report diagrams and summary",
        )

        content = backend.read_diagram_content(object())

        self.assertEqual(content["legacyText"], expected)
        self.assertTrue(diagram_content_ready(content, "Report diagrams and summary"))

    def test_conflicting_diagram_editors_report_bounded_uia_metadata(self):
        backend = WindowsLiveBackend()
        secret = "Complete supplied source:\nmust-not-leak"
        editors = [
            SimpleNamespace(
                element_info=SimpleNamespace(
                    control_type="Edit",
                    name="Complete diagram nodes, edges and original source; selectable read-only text",
                    automation_id=f"Editor{index}",
                    class_name="TextBox",
                    handle=100 + index,
                    rectangle=f"rect-{index}",
                ),
                is_visible=lambda index=index: index == 1,
                get_value=lambda index=index: secret if index == 0 else "conflicting",
            )
            for index in range(2)
        ]
        backend._uia_window = lambda window: SimpleNamespace(descendants=lambda: editors)

        with self.assertRaises(RuntimeError) as raised:
            backend.read_diagram_content(object())

        message = str(raised.exception)
        self.assertIn("'visible': False", message)
        self.assertIn("'visible': True", message)
        self.assertIn("Editor0", message)
        self.assertNotIn("must-not-leak", message)

    def test_identical_duplicate_diagram_editors_have_one_truthful_value(self):
        backend = WindowsLiveBackend()
        expected = "Complete supplied source:\nartifact"
        editors = [
            SimpleNamespace(
                element_info=SimpleNamespace(
                    control_type="Edit",
                    name="Complete diagram nodes, edges and original source; selectable read-only text",
                ),
                get_value=lambda: expected,
            )
            for _ in range(2)
        ]
        backend._uia_window = lambda window: SimpleNamespace(descendants=lambda: editors)
        backend._diagram_view_selector = lambda window: SimpleNamespace(
            selected_text=lambda: "Report diagrams and summary",
        )

        content = backend.read_diagram_content(object())

        self.assertEqual(content["legacyText"], expected)
        self.assertTrue(diagram_content_ready(content, "Report diagrams and summary"))

    def test_diagrams_capture_loads_summary_and_restores_interactive_view(self):
        with tempfile.TemporaryDirectory() as temporary:
            backend = FakeBackend()
            evidence = run(self.make_args(Path(temporary)), backend)
            self.assertEqual(evidence["status"], "independent-live-window-captured")
            self.assertEqual(len(evidence["captures"]), 75)
            self.assertEqual(len(evidence["diagramContent"]), 5)
            self.assertTrue(all(item["legacyCharacters"] > 0 for item in evidence["diagramContent"]))
            self.assertEqual(backend.diagram_view, "Interactive architecture")
            self.assertEqual(backend.operations.count(("diagram-view", "Report diagrams and summary")), 5)
            self.assertEqual(backend.operations.count(("diagram-view", "Interactive architecture")), 5)

    def test_empty_diagram_summary_fails_instead_of_capturing_empty_content(self):
        with tempfile.TemporaryDirectory() as temporary:
            backend = FakeBackend()
            backend.diagram_legacy_available = False
            evidence = run(self.make_args(Path(temporary)), backend)
            self.assertEqual(evidence["status"], "failed")
            self.assertIn("Report diagrams and summary", evidence["error"]["message"])
            self.assertFalse(any("DiagramsSummary" in item["name"] for item in evidence["captures"]))

    def test_unacknowledged_ctrl_h_is_not_history_coverage(self):
        with tempfile.TemporaryDirectory() as temporary:
            backend = FakeBackend()
            backend.ack_shortcuts = False
            evidence = run(self.make_args(Path(temporary)), backend)
            self.assertEqual(evidence["status"], "failed")
            self.assertNotEqual(evidence["shortcuts"].get("CTRL+H"), "acknowledged")

    def test_f9_requires_invocation_and_application_events(self):
        f9 = [make_event(2, "f9-before-local-brush"), make_event(3, "f9-after-local-brush")]
        self.assertFalse(intervention_acknowledged(f9[:1], 1, "F9"))
        self.assertTrue(intervention_acknowledged(f9, 1, "F9", expected_run_id=RUN_ID))
        f10 = [make_event(4, "f10-before-local-spacing"), make_event(5, "f10-after-local-spacing")]
        self.assertTrue(intervention_acknowledged(f10, 3, "F10", expected_run_id=RUN_ID))
        self.assertFalse(intervention_acknowledged(f9, 1, "F10"))

    def test_detail_spacing_probe_is_one_shot_and_retains_after_pixels(self):
        with tempfile.TemporaryDirectory() as temporary:
            backend = FakeBackend()
            args = self.make_args(Path(temporary))
            args.detail_spacing_probe_round = 2
            evidence = run(args, backend)
            self.assertEqual(evidence["status"], "independent-live-window-captured")
            self.assertEqual(backend.keys.count("F11"), 1)
            self.assertEqual(len(evidence["captures"]), 76)
            self.assertEqual(evidence["interventions"]["F11"], "acknowledged")
            self.assertEqual(evidence["detailSpacingProbe"]["round"], 2)
            self.assertEqual(evidence["detailSpacingProbe"]["beforeCapture"], "r02-02-FindingDetail")
            self.assertEqual(evidence["detailSpacingProbe"]["afterCapture"], "r02-02-FindingDetail-spacing-after")
            after = [item for item in evidence["captures"] if item["destination"] == "FindingDetailSpacingAfter"]
            self.assertEqual(len(after), 1)
            self.assertTrue((args.output / after[0]["path"]).is_file())

    def test_detail_brush_probe_is_one_shot_and_retains_after_pixels(self):
        with tempfile.TemporaryDirectory() as temporary:
            backend = FakeBackend()
            args = self.make_args(Path(temporary))
            args.detail_brush_probe_round = 1
            evidence = run(args, backend)
            self.assertEqual(evidence["status"], "independent-live-window-captured")
            self.assertEqual(backend.keys.count("F12"), 1)
            self.assertEqual(len(evidence["captures"]), 76)
            self.assertEqual(evidence["interventions"]["F12"], "acknowledged")
            self.assertEqual(evidence["detailBrushProbe"]["round"], 1)
            self.assertEqual(evidence["detailBrushProbe"]["beforeCapture"], "r01-02-FindingDetail")
            self.assertEqual(evidence["detailBrushProbe"]["afterCapture"], "r01-02-FindingDetail-brush-after")
            after = [item for item in evidence["captures"] if item["destination"] == "FindingDetailBrushAfter"]
            self.assertEqual(len(after), 1)
            self.assertTrue((args.output / after[0]["path"]).is_file())

    def test_detail_probes_cannot_combine_two_variables(self):
        with tempfile.TemporaryDirectory() as temporary:
            args = self.make_args(Path(temporary))
            args.detail_spacing_probe_round = 1
            args.detail_brush_probe_round = 1
            with self.assertRaisesRegex(ValueError, "cannot be combined"):
                run(args, FakeBackend())
            self.assertFalse(args.output.exists())

    def test_print_window_detail_capture_retains_five_independent_comparisons(self):
        with tempfile.TemporaryDirectory() as temporary:
            args = self.make_args(Path(temporary))
            args.print_window_detail_capture = True
            evidence = run(args, FakeBackend())
            self.assertEqual(evidence["status"], "independent-live-window-captured")
            self.assertEqual(len(evidence["captures"]), 80)
            comparisons = [item for item in evidence["captures"] if item["destination"] == "FindingDetailPrintWindow"]
            self.assertEqual(len(comparisons), 5)
            self.assertTrue(all(item["captureMethod"] == "PrintWindow" for item in comparisons))
            self.assertTrue(all((args.output / item["path"]).is_file() for item in comparisons))
            self.assertTrue(all(
                item["diagnosticsBeforeSequence"] <= item["diagnosticsSequence"]
                for item in evidence["captures"]
            ))
            detail_images = [item for item in evidence["captures"] if item["destination"] == "FindingDetail"]
            for ordinary, comparison in zip(detail_images, comparisons, strict=True):
                self.assertEqual(comparison["diagnosticsBeforeSequence"], ordinary["diagnosticsSequence"])
            self.assertFalse(evidence["diagnosticInterventions"])

    def test_detail_render_probe_retains_five_before_render_after_triplets(self):
        with tempfile.TemporaryDirectory() as temporary:
            args = self.make_args(Path(temporary))
            args.detail_render_probe = True
            backend = FakeBackend()
            evidence = run(args, backend)
            self.assertEqual(evidence["status"], "independent-live-window-captured")
            self.assertEqual(len(evidence["captures"]), 80)
            self.assertEqual(backend.keys.count("F8"), 5)
            self.assertEqual(len(evidence["detailRenderProbe"]), 5)
            for round_number, probe in enumerate(evidence["detailRenderProbe"], start=1):
                self.assertEqual(probe["round"], round_number)
                self.assertEqual(probe["beforeCapture"], f"r{round_number:02d}-02-FindingDetail")
                self.assertEqual(probe["afterCapture"], f"r{round_number:02d}-02-FindingDetail-render-after")
                self.assertEqual(probe["status"], "captured-awaiting-visual-review")
                render = probe["renderCapture"]
                render_path = args.output / render["path"]
                self.assertEqual(render["path"], f"diagnostics/detail-render-r{round_number:02d}.png")
                self.assertTrue(render_path.is_file())
                self.assertEqual(render["sha256"], hashlib.sha256(render_path.read_bytes()).hexdigest())
                self.assertGreater(probe["terminalSequence"], probe["afterSequence"])
            self.assertFalse(evidence["diagnosticInterventions"])

    def test_detail_render_probe_rejects_other_capture_modes_before_output(self):
        modes = (
            "diagnostic_interventions", "detail_spacing_probe_round",
            "detail_brush_probe_round", "print_window_detail_capture",
        )
        for mode in modes:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                args = self.make_args(Path(temporary))
                args.detail_render_probe = True
                setattr(args, mode, 1 if mode.endswith("_round") else True)
                with self.assertRaisesRegex(ValueError, "cannot be combined"):
                    run(args, FakeBackend())
                self.assertFalse(args.output.exists())

    def test_detail_render_probe_failure_never_claims_an_after_capture(self):
        with tempfile.TemporaryDirectory() as temporary:
            args = self.make_args(Path(temporary))
            args.detail_render_probe = True
            backend = FakeBackend()
            backend.detail_render_probe_failed = True
            evidence = run(args, backend)
            self.assertEqual(evidence["status"], "failed")
            self.assertIn("F8 Detail render", evidence["error"]["message"])
            self.assertFalse(any(
                item["destination"] == "FindingDetailRenderAfter"
                for item in evidence["captures"]
            ))

    def test_stale_detail_render_ack_cannot_release_after_capture(self):
        class StaleAckBackend(FakeBackend):
            def send_key(self, key):
                if key == "F8" and self.keys.count("F8") == 0:
                    self._append(
                        "detail-render-capture-completed", probeId="stale", generation=1,
                        displayedReadHash=self.report_hash, navigationRevision=self.navigation_revision,
                        findingRevision=self.finding_revision, fileName="stale.png", width=1, height=1, scale=1.0,
                    )
                    self.keys.append(key)
                    return
                super().send_key(key)

        with tempfile.TemporaryDirectory() as temporary:
            args = self.make_args(Path(temporary))
            args.detail_render_probe = True
            evidence = run(args, StaleAckBackend())
            self.assertEqual(evidence["status"], "failed")
            self.assertFalse(any(
                item["destination"] == "FindingDetailRenderAfter"
                for item in evidence["captures"]
            ))

    def test_finding_change_during_triplet_invalidates_render_probe(self):
        class ChangingFindingBackend(FakeBackend):
            def __init__(self):
                super().__init__()
                self.changed = False

            def grab(self, window):
                image = super().grab(window)
                if self.capture_count == 3 and not self.changed:
                    self.changed = True
                    self.select_first_finding(window)
                return image

        with tempfile.TemporaryDirectory() as temporary:
            args = self.make_args(Path(temporary))
            args.detail_render_probe = True
            evidence = run(args, ChangingFindingBackend())
            self.assertEqual(evidence["status"], "failed")
            self.assertIn("finding revision", evidence["error"]["message"])
            self.assertFalse(evidence["detailRenderProbe"])

    def test_diagnostic_raster_quality_ignores_hidden_rgb_and_accepts_alpha_glyphs(self):
        from PIL import Image
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "raster.png"
            raster = Image.new("RGBA", (2, 1), (0, 0, 0, 0))
            raster.putpixel((1, 0), (255, 30, 80, 0))
            raster.save(path)
            self.assertEqual(_png_quality(path)["classification"], "empty")
            raster = Image.new("RGBA", (2, 1), (255, 255, 255, 255))
            raster.save(path)
            self.assertEqual(_png_quality(path)["classification"], "uniform")
            raster.putpixel((1, 0), (255, 255, 255, 128))
            raster.save(path)
            self.assertEqual(_png_quality(path)["classification"], "nonuniform")
            raster.putpixel((1, 0), (20, 40, 60, 0))
            raster.save(path)
            self.assertEqual(_png_quality(path)["classification"], "nonuniform")

    def test_root_quality_rejection_prevents_b_and_preserves_pngs(self):
        from PIL import Image
        for rgba in ((0, 0, 0, 0), (15, 15, 15, 255)):
            class BlankRoot(FakeBackend):
                def send_key(self, key):
                    super().send_key(key)
                    if key == "CTRL+ALT+SHIFT+R":
                        Image.new("RGBA", (2, 1), rgba).save(
                            self.diagnostics_dir / self.events[-1]["detail"]["rootFileName"])
            with self.subTest(rgba=rgba), tempfile.TemporaryDirectory() as temporary:
                args = self.make_args(Path(temporary))
                args.detail_root_render_probe = True
                evidence = run(args, BlankRoot())
                self.assertEqual(evidence["status"], "failed")
                self.assertTrue(evidence["rejectedDetailRootRenderProbes"])
                self.assertFalse(evidence["detailRootRenderProbe"])
                self.assertFalse(any(item["destination"] == "FindingDetailRootRenderAfter" for item in evidence["captures"]))
                self.assertTrue(list((args.output / "diagnostics").glob("*.png")))

    def test_transparent_detail_with_meaningful_root_remains_negative_observation(self):
        from PIL import Image
        class EmptyDetail(FakeBackend):
            def send_key(self, key):
                super().send_key(key)
                if key == "CTRL+ALT+SHIFT+R":
                    Image.new("RGBA", (2, 1)).save(self.diagnostics_dir / self.events[-1]["detail"]["detailFileName"])
        with tempfile.TemporaryDirectory() as temporary:
            args = self.make_args(Path(temporary))
            args.detail_root_render_probe = True
            evidence = run(args, EmptyDetail())
            self.assertEqual(evidence["status"], "independent-live-window-captured")
            self.assertTrue(all(p["detailQuality"]["classification"] == "empty" for p in evidence["detailRootRenderProbe"]))

    def test_startup_restore_finishes_before_harness_placement(self):
        class DelayedRestore(FakeBackend):
            restored = False

            def read_events(self):
                if not self.restored:
                    self.window.rect = (320, 120, 1600, 920)
                    self.operations.append("startup-restore-at-report-ready")
                    self.restored = True
                return super().read_events()

        with tempfile.TemporaryDirectory() as temporary:
            backend = DelayedRestore()
            evidence = run(self.make_args(Path(temporary)), backend)
            self.assertEqual(evidence["status"], "independent-live-window-captured")
            self.assertLess(backend.operations.index("startup-restore-at-report-ready"), backend.operations.index("resize"))
            self.assertEqual(backend.operations.count("resize"), 1)
            self.assertTrue(all(frame["rect"] == [40, 40, 1640, 1040] for frame in evidence["captures"]))

    def test_successful_move_without_observed_geometry_never_navigates(self):
        class IgnoredResize(FakeBackend):
            def move_resize(self, window, width, height):
                self.operations.append("resize")
                self.window.rect = (320, 120, 1600, 920)

        with tempfile.TemporaryDirectory() as temporary:
            backend = IgnoredResize()
            evidence = run(self.make_args(Path(temporary)), backend)
            self.assertEqual(evidence["status"], "failed")
            self.assertFalse(evidence["captures"])
            self.assertFalse(backend.keys)
            self.assertFalse(any(isinstance(op, tuple) and op[0] == "focus" for op in backend.operations))
            self.assertEqual(backend.operations.count("resize"), 1)

    def test_client_modal_and_geometry_fail_before_accepted_capture(self):
        for condition in ("modal", "inspection", "geometry"):
            class UnsafeClient(FakeBackend):
                def client_modal_details(self, window):
                    if condition == "inspection":
                        raise RuntimeError("UIA unavailable")
                    return [{"className": "ContentDialog"}] if condition == "modal" else []
                def move_resize(self, window, width, height):
                    super().move_resize(window, width, height)
                    if condition == "geometry":
                        self.window = owned_window(rect=(40, 40, 1320, 840))
                        self.windows = [self.window]
            with self.subTest(condition=condition), tempfile.TemporaryDirectory() as temporary:
                evidence = run(self.make_args(Path(temporary)), UnsafeClient())
                self.assertEqual(evidence["status"], "failed")
                self.assertFalse(evidence["captures"])

    @staticmethod
    def _modal_item(*, class_name="TextBlock", visible=True, properties=None, fail_property=None, error=None):
        queries = []
        values = {30022: not visible, 30174: False, 30044: False, 30077: False, **(properties or {})}

        def read_property(property_id):
            queries.append(property_id)
            if property_id == fail_property:
                raise error
            return values[property_id]

        return SimpleNamespace(
            CurrentClassName=class_name, CurrentAutomationId="dialog-id", CurrentName="Dialog",
            CurrentControlType=50032, GetCurrentPropertyValue=read_property, queries=queries,
        )

    @staticmethod
    def _modal_backend(scans):
        backend = WindowsLiveBackend()
        remaining = iter(scans)
        backend.scan_count = 0

        def find_all(scope, condition):
            backend.scan_count += 1
            if scope != 4 or condition is not true_condition:
                raise AssertionError("Require all descendants without a filtering condition")
            value = next(remaining)
            if isinstance(value, Exception):
                raise value
            value = value() if callable(value) else value
            if isinstance(value, list):
                return SimpleNamespace(Length=len(value), GetElement=value.__getitem__)
            return value

        true_condition = object()
        root = SimpleNamespace(FindAll=find_all)
        backend._uia_automation = lambda: SimpleNamespace(
            iuia=SimpleNamespace(ElementFromHandle=lambda hwnd: root), tree_scope={"descendants": 4},
            true_condition=true_condition, known_control_type_ids={50032: "Window"},
        )
        backend._user32 = lambda: SimpleNamespace(IsWindow=lambda hwnd: True, IsWindowVisible=lambda hwnd: True,
                                                  IsIconic=lambda hwnd: False)
        backend.process_alive = lambda: True
        backend.window_process_id = lambda hwnd: 4242
        backend.foreground_hwnd = lambda: 100
        backend.list_windows = lambda: [owned_window()]
        return backend

    @staticmethod
    def _uia_error(hresult):
        from _ctypes import COMError

        return COMError(hresult, "UIA provider property failed", None)

    def test_modal_inspection_uses_availability_without_masking_pattern_errors(self):
        ordinary = self._modal_item()
        hidden = self._modal_item(visible=False, fail_property=30174, error=RuntimeError("must not inspect"))
        backend = self._modal_backend([[ordinary, hidden]])
        self.assertEqual(backend.client_modal_details(owned_window()), [])
        self.assertEqual(ordinary.queries, [30022, 30174, 30044])
        self.assertEqual(hidden.queries, [30022])
        self.assertEqual(backend.modal_inspection_diagnostics, [])

    def test_modal_inspection_recognizes_all_three_positive_signals(self):
        for signal in ("class", "is-dialog", "window-pattern"):
            with self.subTest(signal=signal):
                item = self._modal_item(
                    class_name="ContentDialog" if signal == "class" else "CustomPanel",
                    properties={30174: signal == "is-dialog", 30044: True, 30077: signal == "window-pattern"},
                )
                backend = self._modal_backend([[item]])
                details = backend.client_modal_details(owned_window())
                self.assertEqual(len(details), 1)
                self.assertEqual(details[0]["automationId"], "dialog-id")
                self.assertEqual(backend.modal_inspection_diagnostics[0]["status"], "modal-present")

    def test_stale_modal_element_requires_complete_fresh_scan_and_finds_new_modal(self):
        for second_scan_modal in (False, True):
            with self.subTest(second_scan_modal=second_scan_modal):
                stale = self._modal_item(fail_property=30174, error=self._uia_error(-2147220991))
                fresh = self._modal_item(class_name="ContentDialog" if second_scan_modal else "TextBlock")
                backend = self._modal_backend([[self._modal_item(), stale], [fresh]])
                details = backend.client_modal_details(owned_window())
                self.assertEqual(bool(details), second_scan_modal)
                self.assertEqual(backend.scan_count, 2)
                diagnostic = backend.modal_inspection_diagnostics[0]
                self.assertEqual(diagnostic["failureStage"], "is-dialog")
                self.assertEqual(diagnostic["elementIndex"], 1)
                self.assertEqual(diagnostic["cause"]["hresultHex"], "0x80040201")
                self.assertEqual(diagnostic["status"], "retry-fresh-scan")
                self.assertEqual(backend.modal_inspection_diagnostics[-1]["status"],
                                 "modal-present" if second_scan_modal else "recovered-fresh-scan")

    def test_exhausted_stale_modal_scan_is_fatal_with_original_hresult(self):
        failure = self._uia_error(0x80040201)
        stale = self._modal_item(fail_property=30174, error=failure)
        backend = self._modal_backend([[stale], [stale]])
        with self.assertRaises(ClientModalInspectionError) as raised:
            backend.client_modal_details(owned_window())
        self.assertIs(raised.exception.__cause__, failure)
        self.assertEqual(backend.scan_count, 2)
        details = _error_details(raised.exception)
        self.assertEqual(details["status"], "failed")
        self.assertEqual(details["classification"], "stale-element-race")
        self.assertEqual(len(details["attempts"]), 2)
        self.assertEqual(details["cause"]["hresultHex"], "0x80040201")

    def test_unknown_modal_inspection_errors_are_fatal_without_retry(self):
        for property_id, stage in ((30174, "is-dialog"), (30044, "window-pattern-available"), (30077, "window-is-modal")):
            for hresult in (0x80070005, 0x80010108, 0x80040204):
                with self.subTest(property_id=property_id, hresult=hresult):
                    error = self._uia_error(hresult)
                    item = self._modal_item(properties={30044: True}, fail_property=property_id, error=error)
                    backend = self._modal_backend([[item]])
                    with self.assertRaises(ClientModalInspectionError) as raised:
                        backend.client_modal_details(owned_window())
                    self.assertEqual(backend.scan_count, 1)
                    details = _error_details(raised.exception)
                    self.assertEqual(details["failureStage"], stage)
                    self.assertEqual(details["cause"]["hresult"], hresult)
                    self.assertEqual(details["classification"], "inspection-failure")

    def test_modal_scan_invalid_property_and_enumeration_failure_remain_fatal(self):
        for scan, stage in (([self._modal_item(properties={30174: object()})], "is-dialog"),
                            (RuntimeError("provider enumeration unavailable"), "descendants")):
            with self.subTest(stage=stage):
                backend = self._modal_backend([scan])
                with self.assertRaises(ClientModalInspectionError) as raised:
                    backend.client_modal_details(owned_window())
                self.assertEqual(_error_details(raised.exception)["failureStage"], stage)
                self.assertEqual(backend.scan_count, 1)

    def test_invalid_hwnd_race_rechecks_owned_target_before_and_after_rescan(self):
        for invalid_phase in (None, "before", "after"):
            with self.subTest(invalid_phase=invalid_phase):
                invalid_handle = OSError("Window already destroyed")
                invalid_handle.winerror = 1400
                checks = []
                backend = self._modal_backend([invalid_handle, [self._modal_item()]])

                def is_window(hwnd):
                    checks.append(hwnd)
                    return not ((invalid_phase == "before" and len(checks) == 1)
                                or (invalid_phase == "after" and len(checks) == 2))

                backend._user32 = lambda: SimpleNamespace(IsWindow=is_window, IsWindowVisible=lambda hwnd: True,
                                                          IsIconic=lambda hwnd: False)
                if invalid_phase is None:
                    self.assertEqual(backend.client_modal_details(owned_window()), [])
                    self.assertEqual(len(checks), 2)
                else:
                    with self.assertRaises(ClientModalInspectionError) as raised:
                        backend.client_modal_details(owned_window())
                    self.assertEqual(_error_details(raised.exception)["failureStage"], "owned-target-recheck")
                self.assertEqual(backend.scan_count, 1 if invalid_phase == "before" else 2)
                self.assertEqual(backend.modal_inspection_diagnostics[0]["cause"]["winerror"], 1400)

    def test_modal_inspection_failure_is_structured_in_persisted_live_evidence(self):
        failure = self._uia_error(0x80070005)
        inspector = self._modal_backend([[self._modal_item(fail_property=30044, error=failure)]])
        backend = FakeBackend()
        backend.client_modal_details = inspector.client_modal_details
        backend.modal_inspection_diagnostics = inspector.modal_inspection_diagnostics
        with tempfile.TemporaryDirectory() as temporary:
            args = self.make_args(Path(temporary))
            evidence = run(args, backend)
            retained = json.loads((args.output / "evidence.json").read_text(encoding="utf-8"))
        self.assertEqual(evidence["status"], "failed")
        self.assertEqual(evidence["captures"], [])
        self.assertEqual(evidence["error"]["failureStage"], "window-pattern-available")
        self.assertEqual(evidence["error"]["cause"]["hresultHex"], "0x80070005")
        self.assertEqual(evidence["error"]["propertyId"], 30044)
        self.assertEqual(evidence["failureSnapshot"]["status"], "rejected-diagnostic-only")
        self.assertEqual(retained["error"], evidence["error"])
        self.assertEqual(retained["clientModalInspections"], inspector.modal_inspection_diagnostics)

    def test_direct_enumeration_and_visibility_failures_never_accept_a_capture(self):
        for stage in ("descendants", "visibility"):
            for failure in (self._uia_error(0x80070005), self._uia_error(0x80010108),
                            self._uia_error(0x80004005), ValueError("Invalid UIA provider result")):
                with self.subTest(stage=stage, failure=failure):
                    scan = failure if stage == "descendants" else [
                        self._modal_item(), self._modal_item(fail_property=30022, error=failure),
                    ]
                    inspector = self._modal_backend([scan])
                    backend = FakeBackend()
                    backend.client_modal_details = inspector.client_modal_details
                    backend.modal_inspection_diagnostics = inspector.modal_inspection_diagnostics
                    with tempfile.TemporaryDirectory() as temporary:
                        args = self.make_args(Path(temporary))
                        evidence = run(args, backend)
                        retained = json.loads((args.output / "evidence.json").read_text(encoding="utf-8"))
                    self.assertEqual(evidence["status"], "failed")
                    self.assertEqual(evidence["captures"], [])
                    self.assertEqual(evidence["error"]["failureStage"], stage)
                    self.assertEqual(evidence["error"]["classification"], "inspection-failure")
                    self.assertEqual(evidence["error"]["cause"]["type"], type(failure).__name__)
                    self.assertEqual(inspector.scan_count, 1)
                    if stage == "visibility":
                        self.assertEqual(evidence["error"]["elementIndex"], 1)
                        self.assertEqual(evidence["error"]["propertyId"], 30022)
                    if hasattr(failure, "hresult"):
                        self.assertEqual(evidence["error"]["cause"]["hresult"], failure.hresult)
                    self.assertEqual(retained["error"], evidence["error"])
                    self.assertEqual(retained["clientModalInspections"], inspector.modal_inspection_diagnostics)

    def test_direct_enumeration_and_visibility_stale_failures_get_one_complete_rescan(self):
        invalid_handle = OSError("Window already destroyed")
        invalid_handle.winerror = 1400
        for stage in ("descendants", "visibility"):
            for failure in (self._uia_error(0x80040201), self._uia_error(0x80070578), invalid_handle):
                for fresh_modal in (False, True):
                    with self.subTest(stage=stage, failure=failure, fresh_modal=fresh_modal):
                        scan = failure if stage == "descendants" else [
                            self._modal_item(), self._modal_item(fail_property=30022, error=failure),
                        ]
                        fresh = self._modal_item(class_name="ContentDialog" if fresh_modal else "TextBlock")
                        inspector = self._modal_backend([scan, [fresh]])
                        details = inspector.client_modal_details(owned_window())
                        self.assertEqual(bool(details), fresh_modal)
                        self.assertEqual(inspector.scan_count, 2)
                        diagnostic = inspector.modal_inspection_diagnostics[0]
                        self.assertEqual(diagnostic["failureStage"], stage)
                        self.assertEqual(diagnostic["status"], "retry-fresh-scan")
                        self.assertEqual(inspector.modal_inspection_diagnostics[-1]["status"],
                                         "modal-present" if fresh_modal else "recovered-fresh-scan")

    def test_direct_stale_retry_exhaustion_fails_before_any_capture(self):
        for stage in ("descendants", "visibility"):
            with self.subTest(stage=stage):
                failure = self._uia_error(0x80040201)
                scan = failure if stage == "descendants" else [self._modal_item(fail_property=30022, error=failure)]
                inspector = self._modal_backend([scan, scan, []])
                backend = FakeBackend()
                backend.client_modal_details = inspector.client_modal_details
                backend.modal_inspection_diagnostics = inspector.modal_inspection_diagnostics
                with tempfile.TemporaryDirectory() as temporary:
                    evidence = run(self.make_args(Path(temporary)), backend)
                self.assertEqual(evidence["status"], "failed")
                self.assertEqual(evidence["captures"], [])
                self.assertEqual(inspector.scan_count, 2)
                self.assertEqual(len(evidence["error"]["attempts"]), 2)
                self.assertEqual(evidence["error"]["cause"]["hresultHex"], "0x80040201")
                self.assertEqual(evidence["error"]["status"], "failed")

    def test_direct_root_and_array_failures_remain_structured(self):
        for boundary in ("root", "length", "element"):
            with self.subTest(boundary=boundary):
                failure = self._uia_error(0x80070005)

                class UnreadableArray:
                    @property
                    def Length(self):
                        if boundary == "length":
                            raise failure
                        return 1

                    def GetElement(self, index):
                        raise failure

                inspector = self._modal_backend([UnreadableArray()])
                if boundary == "root":
                    def element_from_handle(hwnd):
                        raise failure
                    automation = inspector._uia_automation()
                    automation.iuia.ElementFromHandle = element_from_handle
                    inspector._uia_automation = lambda: automation
                with self.assertRaises(ClientModalInspectionError) as raised:
                    inspector.client_modal_details(owned_window())
                self.assertIs(raised.exception.__cause__, failure)
                self.assertEqual(raised.exception.diagnostics["failureStage"],
                                 "element-info" if boundary == "element" else "descendants")
                self.assertEqual(inspector.scan_count, 0 if boundary == "root" else 1)

    def test_direct_class_and_confirmed_modal_metadata_failures_never_clear_modality(self):
        for attribute in ("CurrentClassName", "CurrentAutomationId", "CurrentName", "CurrentControlType"):
            for hresult in (0x80070005, 0x80040201):
                with self.subTest(attribute=attribute, hresult=hresult):
                    failure = self._uia_error(hresult)
                    item = self._modal_item(class_name="ContentDialog")

                    class UnreadableElement:
                        def __getattr__(self, name):
                            if name == attribute:
                                raise failure
                            return getattr(item, name)

                    inspector = self._modal_backend([[UnreadableElement()], []])
                    if attribute == "CurrentClassName" and hresult == 0x80040201:
                        self.assertEqual(inspector.client_modal_details(owned_window()), [])
                        self.assertEqual(inspector.scan_count, 2)
                        continue
                    with self.assertRaises(ClientModalInspectionError) as raised:
                        inspector.client_modal_details(owned_window())
                    self.assertIs(raised.exception.__cause__, failure)
                    diagnostic = raised.exception.diagnostics
                    self.assertEqual(diagnostic["failureStage"],
                                     "class-name" if attribute == "CurrentClassName" else "modal-metadata")
                    self.assertEqual(inspector.scan_count, 1)
                    if attribute != "CurrentClassName":
                        self.assertTrue(diagnostic["modalConfirmed"])

    def test_modal_failures_do_not_enter_owned_transient_recovery(self):
        for inspection_failure in (False, True):
            for after_grab in (False, True):
                with self.subTest(inspection_failure=inspection_failure, after_grab=after_grab):
                    class ModalWithTransient(FakeBackend):
                        def client_modal_details(self, window):
                            if self.capture_count < int(after_grab):
                                return []
                            self.windows = [self.window, owned_window(
                                hwnd=200, title="Hostitel místní nabídky", z_order=0)]
                            if inspection_failure:
                                raise RuntimeError("UIA unavailable")
                            return [{"className": "ContentDialog"}]

                        def close(self, window):
                            if window.hwnd == 200:
                                self.windows = [self.window]
                                return
                            super().close(window)

                    backend = ModalWithTransient()
                    with tempfile.TemporaryDirectory() as temporary:
                        evidence = run(self.make_args(Path(temporary)), backend)
                    self.assertEqual(evidence["status"], "failed")
                    self.assertEqual(evidence["captures"], [])
                    self.assertEqual(len(evidence["discardedCaptures"]), int(after_grab))
                    self.assertFalse(any(action["type"] == "dismiss-owned-transient" for action in evidence["actions"]))
                    self.assertEqual(evidence["failureSnapshot"]["status"], "not-captured")

    def test_modal_appearing_during_grab_is_discarded(self):
        class ModalDuringGrab(FakeBackend):
            def client_modal_details(self, window):
                return [{"className": "ContentDialog"}] if self.capture_count else []
        with tempfile.TemporaryDirectory() as temporary:
            evidence = run(self.make_args(Path(temporary)), ModalDuringGrab())
            self.assertEqual(evidence["status"], "failed")
            self.assertFalse(evidence["captures"])
            self.assertTrue(evidence["discardedCaptures"])

    def test_probe_chord_has_no_bare_f7_runner_mapping(self):
        import inspect
        source = inspect.getsource(WindowsLiveBackend.send_key)
        self.assertIn('"CTRL+ALT+SHIFT+R": "^%+r"', source)
        self.assertNotIn("{F7}", source)
        self.assertNotIn('"F7":', source)

    def test_root_hides_global_accelerator_tooltips_from_uia_focus(self):
        source = (
            Path(__file__).resolve().parents[1]
            / "desktop" / "windows" / "AttackMap.NativeSpike" / "MainWindow.xaml"
        ).read_text(encoding="utf-8")
        root_grid = source.split("<Grid", 1)[1].split(">", 1)[0]
        self.assertIn('KeyboardAcceleratorPlacementMode="Hidden"', root_grid)

    def test_modal_after_probe_prevents_b_without_dismissal(self):
        class ModalAfterProbe(FakeBackend):
            def client_modal_details(self, window):
                return [{"className": "ContentDialog"}] if "CTRL+ALT+SHIFT+R" in self.keys else []
        with tempfile.TemporaryDirectory() as temporary:
            args = self.make_args(Path(temporary))
            args.detail_root_render_probe = True
            backend = ModalAfterProbe()
            evidence = run(args, backend)
            self.assertEqual(evidence["status"], "failed")
            self.assertEqual(evidence["failureSnapshot"]["status"], "rejected-diagnostic-only")
            self.assertTrue((args.output / evidence["failureSnapshot"]["path"]).is_file())
            self.assertEqual(len(evidence["captures"]), 3)
            self.assertFalse(evidence["detailRootRenderProbe"])
            self.assertFalse(any(c["destination"] == "FindingDetailRootRenderAfter" for c in evidence["captures"]))
            self.assertNotIn("ESC", backend.keys)

    def test_modal_failure_snapshot_rejects_external_occluder_without_grab(self):
        class ModalWithOccluder(FakeBackend):
            def client_modal_details(self, window):
                self.windows.append(owned_window(pid=777, hwnd=200, z_order=0))
                return [{"className": "ContentDialog"}]

        with tempfile.TemporaryDirectory() as temporary:
            backend = ModalWithOccluder()
            evidence = run(self.make_args(Path(temporary)), backend)
            self.assertEqual(evidence["failureSnapshot"]["status"], "not-captured")
            self.assertIn("occluder", evidence["failureSnapshot"]["reason"])
            self.assertEqual(backend.capture_count, 0)
            self.assertFalse(evidence["captures"])

    def test_failure_review_keeps_target_and_external_blocker_in_one_snapshot(self):
        class ModalWithChangedZ(FakeBackend):
            review_enumerations = 0
            review = False

            def client_modal_details(self, window):
                self.review = True
                return [{"className": "ContentDialog"}]

            def list_windows(self):
                if not self.review:
                    return super().list_windows()
                self.review_enumerations += 1
                return [owned_window(z_order=30, class_name="TargetNativeClass"),
                        owned_window(hwnd=200, pid=777, title="External", z_order=20,
                                     class_name="ExternalNativeClass")]

        with tempfile.TemporaryDirectory() as temporary:
            backend = ModalWithChangedZ()
            args = self.make_args(Path(temporary))
            evidence = run(args, backend)
            retained = json.loads((args.output / "evidence.json").read_text(encoding="utf-8"))
        self.assertEqual(backend.review_enumerations, 1)
        self.assertEqual(backend.capture_count, 0)
        safety = evidence["failureSnapshot"]["safetyError"]
        self.assertEqual(safety["failureStage"], "occlusion")
        self.assertEqual(safety["targetAfter"]["zOrder"], 30)
        blocker = safety["occlusion"]["blockers"][0]
        self.assertEqual((blocker["hwnd"], blocker["pid"], blocker["title"], blocker["className"], blocker["zOrder"]),
                         (200, 777, "External", "ExternalNativeClass", 20))
        self.assertEqual(retained["failureSnapshot"], evidence["failureSnapshot"])

    def test_failure_review_geometry_change_keeps_before_and_after_observations(self):
        class ModalThenMoved(FakeBackend):
            def client_modal_details(self, window):
                return [{"className": "ContentDialog"}]

            def grab(self, window):
                image = super().grab(window)
                self.windows = [owned_window(rect=(60, 40, 1660, 1040))]
                return image

        with tempfile.TemporaryDirectory() as temporary:
            backend = ModalThenMoved()
            evidence = run(self.make_args(Path(temporary)), backend)
        snapshot = evidence["failureSnapshot"]
        self.assertEqual(snapshot["status"], "not-captured")
        self.assertEqual(snapshot["nativeChecks"][0]["geometry"]["afterRect"], [40, 40, 1640, 1040])
        self.assertEqual(snapshot["safetyError"]["failureStage"], "geometry")
        self.assertEqual(snapshot["safetyError"]["geometry"]["afterRect"], [60, 40, 1660, 1040])
        self.assertNotEqual(snapshot["nativeChecks"][0]["snapshotId"], snapshot["safetyError"]["snapshotId"])
        self.assertFalse(evidence["captures"])

    def test_valid_idat_payload_with_bad_crc_is_rejected(self):
        from PIL import Image
        import struct
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "crc.png"
            Image.new("RGBA", (2, 1), "white").save(path)
            raw = bytearray(path.read_bytes())
            offset = raw.index(b"IDAT")
            length = struct.unpack(">I", raw[offset - 4:offset])[0]
            raw[offset + 4 + length] ^= 1  # CRC only; compressed pixels unchanged.
            path.write_bytes(raw)
            with Image.open(path) as image:
                image.load()  # Demonstrate that load alone does not enforce CRC.
            with self.assertRaises(Exception):
                _png_quality(path)

    def test_decoded_corrupt_png_is_rejected(self):
        from PIL import Image
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            path = directory / "bad.png"
            Image.new("RGBA", (2, 1), "white").save(path)
            raw = bytearray(path.read_bytes())
            raw[raw.index(b"IDAT") + 5] ^= 255
            path.write_bytes(raw)
            with self.assertRaises(Exception):
                _png_quality(path)

    def test_detail_root_render_probe_retains_five_a_d_t_b_sets(self):
        with tempfile.TemporaryDirectory() as temporary:
            args = self.make_args(Path(temporary))
            args.detail_root_render_probe = True
            backend = FakeBackend()
            evidence = run(args, backend)
            self.assertEqual(evidence["status"], "independent-live-window-captured")
            self.assertEqual(len(evidence["captures"]), 80)
            self.assertEqual(backend.keys.count("CTRL+ALT+SHIFT+R"), 5)
            self.assertEqual(backend.keys.count("F8"), 0)
            self.assertEqual(len(evidence["detailRootRenderProbe"]), 5)
            for round_number, probe in enumerate(evidence["detailRootRenderProbe"], 1):
                self.assertEqual(probe["round"], round_number)
                self.assertEqual(probe["beforeCapture"], f"r{round_number:02d}-02-FindingDetail")
                self.assertEqual(probe["afterCapture"], f"r{round_number:02d}-02-FindingDetail-root-render-after")
                for key in ("detailRenderCapture", "rootRenderCapture"):
                    item = probe[key]
                    path = args.output / item["path"]
                    self.assertEqual((item["width"], item["height"]), (2, 1))
                    self.assertEqual(item["sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
                self.assertGreater(probe["terminalSequence"], probe["afterSequence"])
            self.assertFalse(evidence["diagnosticInterventions"])

    def test_detail_root_render_probe_rejects_other_modes_and_ack_anomalies(self):
        modes = (
            "detail_render_probe", "diagnostic_interventions", "detail_spacing_probe_round",
            "detail_brush_probe_round", "print_window_detail_capture",
        )
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
                self.assertFalse(any(
                    item["destination"] == "FindingDetailRootRenderAfter"
                    for item in evidence["captures"]
                ))
                self.assertFalse(evidence["detailRootRenderProbe"])

    def test_stale_detail_root_ack_cannot_release_after_capture(self):
        class StaleAckBackend(FakeBackend):
            def send_key(self, key):
                if key == "CTRL+ALT+SHIFT+R" and self.keys.count("CTRL+ALT+SHIFT+R") == 0:
                    self._append(
                        "detail-root-render-capture-completed", probeId="stale", generation=1,
                        displayedReadHash=self.report_hash, navigationRevision=self.navigation_revision,
                        findingRevision=self.finding_revision, detailFileName="d.png", rootFileName="t.png",
                        detailWidth=2, detailHeight=1, rootWidth=2, rootHeight=1, scale=1.0,
                    )
                    self.keys.append(key)
                    return
                super().send_key(key)

        with tempfile.TemporaryDirectory() as temporary:
            args = self.make_args(Path(temporary))
            args.detail_root_render_probe = True
            evidence = run(args, StaleAckBackend())
            self.assertEqual(evidence["status"], "failed")
            self.assertFalse(evidence["detailRootRenderProbe"])
            self.assertFalse(any(
                item["destination"] == "FindingDetailRootRenderAfter"
                for item in evidence["captures"]
            ))

    def test_detail_root_completed_before_started_cannot_release_after_capture(self):
        class CompletedBeforeStartedBackend(FakeBackend):
            def send_key(self, key):
                super().send_key(key)
                if key == "CTRL+ALT+SHIFT+R" and self.keys.count("CTRL+ALT+SHIFT+R") == 1:
                    started, completed = self.events[-2:]
                    self.events[-2] = {**completed, "sequence": started["sequence"]}
                    self.events[-1] = {**started, "sequence": completed["sequence"]}

        with tempfile.TemporaryDirectory() as temporary:
            args = self.make_args(Path(temporary))
            args.detail_root_render_probe = True
            evidence = run(args, CompletedBeforeStartedBackend())
            self.assertEqual(evidence["status"], "failed")
            self.assertFalse(evidence["detailRootRenderProbe"])
            self.assertFalse(any(
                item["destination"] == "FindingDetailRootRenderAfter"
                for item in evidence["captures"]
            ))

    def test_finding_change_during_triplet_invalidates_detail_root_render_probe(self):
        class ChangingFindingBackend(FakeBackend):
            def __init__(self):
                super().__init__()
                self.changed = False

            def grab(self, window):
                image = super().grab(window)
                if self.capture_count == 3 and not self.changed:
                    self.changed = True
                    self.select_first_finding(window)
                return image

        with tempfile.TemporaryDirectory() as temporary:
            args = self.make_args(Path(temporary))
            args.detail_root_render_probe = True
            evidence = run(args, ChangingFindingBackend())
            self.assertEqual(evidence["status"], "failed")
            self.assertIn("finding revision", evidence["error"]["message"])
            self.assertFalse(evidence["detailRootRenderProbe"])

    def test_context_change_failure_keeps_original_ack_identity_and_never_releases_b(self):
        class ContextChangedBackend(FakeBackend):
            def send_key(self, key):
                if key != "CTRL+ALT+SHIFT+R":
                    return super().send_key(key)
                self.keys.append(key)
                context = dict(
                    probeId="changed-context", generation=1, displayedReadHash=self.report_hash,
                    navigationRevision=self.navigation_revision, findingRevision=self.finding_revision,
                )
                self._append("detail-root-render-capture-started", **context)
                self.navigation_revision += 1
                self._append(
                    "detail-root-render-capture-failed", **context,
                    failureReason="capture-context-changed", captureTarget="detail", captureStage="after-render",
                    observation={"navigationRevision": self.navigation_revision, "hostVisible": False},
                )

        with tempfile.TemporaryDirectory() as temporary:
            args = self.make_args(Path(temporary))
            args.detail_root_render_probe = True
            backend = ContextChangedBackend()
            evidence = run(args, backend)
            self.assertEqual(evidence["status"], "failed")
            self.assertIn("capture-context-changed", evidence["error"]["message"])
            rejection = evidence["rejectedDetailRootRenderProbes"][0]
            self.assertEqual(rejection["terminal"]["detail"]["captureStage"], "after-render")
            self.assertEqual(backend.keys.count("CTRL+ALT+SHIFT+R"), 1)
            self.assertFalse(evidence["detailRootRenderProbe"])
            self.assertFalse(any(item["destination"] == "FindingDetailRootRenderAfter" for item in evidence["captures"]))

    def test_malformed_detail_root_png_never_claims_after_capture(self):
        class MalformedPngBackend(FakeBackend):
            def send_key(self, key):
                super().send_key(key)
                if key == "CTRL+ALT+SHIFT+R" and self.keys.count("CTRL+ALT+SHIFT+R") == 1:
                    detail_name = f"detail-root-render-detail-r{self.finding_revision:02d}.png"
                    with (self.diagnostics_dir / detail_name).open("ab") as stream:
                        stream.write(b"broken")

        with tempfile.TemporaryDirectory() as temporary:
            args = self.make_args(Path(temporary))
            args.detail_root_render_probe = True
            evidence = run(args, MalformedPngBackend())
            self.assertEqual(evidence["status"], "failed")
            self.assertFalse(any(
                item["destination"] == "FindingDetailRootRenderAfter"
                for item in evidence["captures"]
            ))
            self.assertFalse(evidence["detailRootRenderProbe"])

    def test_round_trip_selection_binds_triplet_to_final_ack_revision(self):
        class RoundTripBackend(FakeBackend):
            def select_first_finding(self, window):
                super().select_first_finding(window)
                super().select_first_finding(window)

        with tempfile.TemporaryDirectory() as temporary:
            args = self.make_args(Path(temporary))
            args.detail_render_probe = True
            evidence = run(args, RoundTripBackend())
            self.assertEqual(evidence["status"], "independent-live-window-captured")
            self.assertEqual([item["findingRevision"] for item in evidence["detailRenderProbe"]], [2, 4, 6, 8, 10])

    def test_dark_theme_requires_matching_diagnostics_snapshot(self):
        events = [make_event(1, "enabled"), navigation_event(2, "Findings", revision=0)]
        self.assertTrue(diagnostics_snapshot_ready(events, RUN_ID, REPORT_HASH, "Findings"))
        self.assertFalse(diagnostics_snapshot_ready([navigation_event(2, "Findings", theme="Light")], RUN_ID, REPORT_HASH, "Findings"))
        self.assertFalse(diagnostics_snapshot_ready([navigation_event(2, "Findings", report_hash="")], RUN_ID, REPORT_HASH, "Findings"))

    def test_finding_detail_requires_new_bound_selection_event(self):
        event = make_event(
            9,
            "finding-selection",
            generation=1,
            displayedRun="saved-run",
            displayedReadHash=REPORT_HASH,
            navigationRevision=3,
            findingRevision=2,
            hasFinding=True,
        )
        self.assertTrue(finding_selection_acknowledged([event], 8, RUN_ID, REPORT_HASH, 3))
        self.assertFalse(finding_selection_acknowledged([event], 9, RUN_ID, REPORT_HASH, 3))
        self.assertFalse(finding_selection_acknowledged([event], 8, RUN_ID, REPORT_HASH, 4))

    def test_empty_finding_detail_uia_is_rejected_and_pixels_are_retained(self):
        with tempfile.TemporaryDirectory() as temporary:
            backend = FakeBackend()
            backend.finding_detail_text = ""
            evidence = run(self.make_args(Path(temporary)), backend)
            self.assertEqual(evidence["status"], "failed")
            self.assertEqual(evidence["actions"][-1]["status"], "failed")
            self.assertIn("Finding detail UIA content", evidence["error"]["message"])
            rejected = [item for item in evidence["captures"] if item["destination"] == "FindingDetailContentRejected"]
            self.assertEqual(len(rejected), 1)
            self.assertTrue((Path(temporary) / "fresh-output" / rejected[0]["path"]).is_file())

    def test_output_must_be_new_local_empty_nonreparse_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "new-output"
            self.assertEqual(validate_new_output(output), output)
            output.mkdir()
            with self.assertRaisesRegex(ValueError, "existing"):
                validate_new_output(output)

    def test_unc_existing_output_and_traversal_names_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "UNC"):
            validate_new_output(Path(r"\\server\share\wp043-fresh"))
        with tempfile.TemporaryDirectory() as temporary:
            existing = Path(temporary)
            with self.assertRaisesRegex(ValueError, "existing"):
                validate_new_output(existing)
        for name in ("../Overview", "..\\Overview", "nested/Overview", "nested\\Overview"):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "capture name"):
                validate_capture_name(name)
        seen = set()
        validate_capture_name("Overview", seen)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            validate_capture_name("Overview", seen)

    def test_discarded_capture_retains_reason_and_hashes(self):
        with tempfile.TemporaryDirectory() as temporary:
            backend = FakeBackend()
            backend.on_grab = lambda: setattr(backend, "foreground", 0)
            evidence = run(self.make_args(Path(temporary)), backend)
            discarded = evidence["discardedCaptures"][0]
            image = Path(temporary) / "fresh-output" / discarded["path"]
            self.assertEqual(discarded["sha256"], hashlib.sha256(image.read_bytes()).hexdigest())
            self.assertEqual(discarded["bytes"], image.stat().st_size)
            self.assertTrue(discarded["reason"])
            self.assertEqual(evidence["inputs"]["executable"], {
                "path": str(Path(__file__).resolve()),
                "sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            })
            self.assertEqual(len(evidence["inputs"]["report"]["sha256"]), 64)

    def test_process_timeout_kills_only_owned_tree(self):
        with tempfile.TemporaryDirectory() as temporary:
            backend = FakeBackend()
            backend.close_cleanly = False
            evidence = run(self.make_args(Path(temporary)), backend)
            self.assertEqual(evidence["status"], "failed")
            self.assertEqual(backend.kill_calls, [4242])

    def test_success_still_has_manual_review_not_run_and_acceptance_not_established(self):
        with tempfile.TemporaryDirectory() as temporary:
            backend = FakeBackend()
            args = self.make_args(Path(temporary))
            args.diagnostic_interventions = True
            evidence = run(args, backend)
            self.assertEqual(evidence["status"], "independent-live-window-captured")
            self.assertEqual(evidence["manual_review"], "not-run")
            self.assertEqual(evidence["rendering_acceptance"], "not-established")
            self.assertEqual(len(evidence["captures"]), 75)
            self.assertEqual(evidence["completedRounds"], 5)
            self.assertEqual(evidence["interventions"], {"F9": "acknowledged", "F10": "acknowledged"})
            profile = args.output / "profile"
            local_app_data = profile / "AppData" / "Local"
            roaming_app_data = profile / "AppData" / "Roaming"
            self.assertTrue((local_app_data / "AttackMap" / "NativePreview" / "theme.json").is_file())
            self.assertTrue(local_app_data.is_dir())
            self.assertTrue(roaming_app_data.is_dir())
            self.assertEqual(backend.launch_environment["USERPROFILE"], str(profile))
            self.assertEqual(backend.launch_environment["LOCALAPPDATA"], str(local_app_data))
            self.assertEqual(backend.launch_environment["APPDATA"], str(roaming_app_data))
            self.assertEqual(backend.launch_environment["WEBVIEW2_USER_DATA_FOLDER"], str(args.output / "webview-profile"))

    def test_detail_lifecycle_probe_waits_for_a_visible_selected_finding(self):
        source = (Path(__file__).parents[1] / "desktop/windows/AttackMap.NativeSpike/MainWindow.RenderDiagnostics.cs").read_text(encoding="utf-8")
        lifecycle = source.split("private void RenderDiagnosticsDetailLifecycle", 1)[1]
        prologue = lifecycle.split("++renderDiagnosticsLifecycleCount;", 1)[0]
        self.assertIn("FindingsPanel.Visibility != Visibility.Visible", prologue)
        self.assertIn("Findings.SelectedItem is not FixtureFinding", prologue)

    def test_navigation_snapshot_records_overview_text_and_scroll_state_without_body_text(self):
        source = (Path(__file__).parents[1] / "desktop/windows/AttackMap.NativeSpike/MainWindow.RenderDiagnostics.cs").read_text(encoding="utf-8")
        snapshot = source.split("private void RenderDiagnosticsSnapshot", 1)[1].split("private TextBlock RenderDiagnosticsTarget", 1)[0]
        self.assertIn("overview = RenderDiagnosticsText(OverviewText, root, includeText: false)", snapshot)
        self.assertIn("overviewPanel = new", snapshot)
        self.assertIn("OverviewPanel.ExtentHeight", snapshot)
        self.assertIn("OverviewPanel.ViewportHeight", snapshot)
        self.assertNotIn("RenderDiagnosticsText(OverviewText, root)", snapshot)

    def test_detail_render_probe_directly_rasterizes_without_settling_or_mutation(self):
        source = (Path(__file__).parents[1] / "desktop/windows/AttackMap.NativeSpike/MainWindow.RenderDiagnostics.cs").read_text(encoding="utf-8")
        self.assertIn("private async Task RenderDiagnosticsDetailRender()", source)
        method = source.split("private async Task RenderDiagnosticsDetailRender()", 1)[1]
        method = method.split("private void RenderDiagnosticsSnapshot", 1)[0]
        self.assertIn("await bitmap.RenderAsync(Detail);", method)
        self.assertIn("await bitmap.GetPixelsAsync();", method)
        self.assertIn("CompositionTarget.Rendering -= rendering;", method)
        self.assertNotIn("UpdateLayout", method)
        self.assertNotIn("Task.Delay", method)
        self.assertNotIn("Detail.Text =", method)
        self.assertNotIn("Detail.Foreground =", method)
        self.assertNotIn("Detail.CharacterSpacing =", method)

    def test_detail_root_render_probe_rasterizes_both_targets_without_settling_or_mutation(self):
        source = (Path(__file__).parents[1] / "desktop/windows/AttackMap.NativeSpike/MainWindow.RenderDiagnostics.cs").read_text(encoding="utf-8")
        self.assertIn("private async Task RenderDiagnosticsDetailRootRender()", source)
        accelerator = source.split("var detailRootRenderAccelerator =", 1)[1].split("var detailRenderAccelerator =", 1)[0]
        self.assertIn("Key = VirtualKey.R", accelerator)
        self.assertNotIn("VirtualKey.F7", source)
        self.assertIn("Modifiers = VirtualKeyModifiers.Control | VirtualKeyModifiers.Menu | VirtualKeyModifiers.Shift", accelerator)
        self.assertLess(accelerator.index("args.Handled = true;"), accelerator.index("await RenderDiagnosticsDetailRootRender();"))
        method = source.split("private async Task RenderDiagnosticsDetailRootRender()", 1)[1]
        method = method.split("private void RenderDiagnosticsSnapshot", 1)[0]
        self.assertIn("await bitmap.RenderAsync(target);", method)
        write = method.index("await file.WriteAsync(png);")
        commit = method.index("File.Move(temporary,")
        self.assertIn("RequireContext();", method[write:commit])
        self.assertIn("await Capture(Detail, \"detail\");", method)
        self.assertIn("await Capture(root, \"root\");", method)
        self.assertEqual(method.count("await bitmap.GetPixelsAsync();"), 1)
        self.assertIn("CompositionTarget.Rendering -= rendering;", method)
        # Async RTB work must fail under the invocation identity, even if the
        # currently selected destination, host, dimensions or scale have changed.
        self.assertIn("renderDiagnosticsNavigationRevision != currentNavigationRevision", method)
        self.assertIn("!ReferenceEquals(Findings.SelectedItem, currentFinding)", method)
        self.assertIn("!xamlRoot.IsHostVisible || !AppWindow.IsVisible", method)
        self.assertIn("xamlRoot.RasterizationScale != scale", method)
        self.assertIn('failureReason = "capture-context-changed";', method)
        self.assertIn('TargetStage("after-render");\n                    RequireContext();', method)
        terminal = method.split('RenderDiagnosticsWrite("detail-root-render-capture-failed"', 1)[1]
        self.assertIn("navigationRevision = currentNavigationRevision", terminal)
        self.assertIn("observation = Observation()", terminal)
        for forbidden in (
            "UpdateLayout", "Task.Delay", "Detail.Text =", "Detail.Foreground =",
            "Detail.CharacterSpacing =", "Detail.Visibility =", "Detail.Opacity =",
            "root.Visibility =", "root.Opacity =", "ChangeView(",
        ):
            self.assertNotIn(forbidden, method)

    def test_any_failed_dispatch_fails_run_without_erasing_prior_captures(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            backend = FakeBackend()
            backend.fail_dispatch_label = "Architecture"
            args = self.make_args(root)
            evidence = run(args, backend)
            self.assertEqual(evidence["status"], "failed")
            self.assertEqual(len(evidence["captures"]), 3)
            self.assertTrue((args.output / "evidence.json").is_file())
            retained = json.loads((args.output / "evidence.json").read_text(encoding="utf-8"))
            self.assertEqual(len(retained["captures"]), 3)
            for capture in retained["captures"]:
                self.assertTrue((args.output / capture["path"]).is_file())


if __name__ == "__main__":
    unittest.main()
