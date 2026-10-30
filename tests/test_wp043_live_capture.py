import argparse
import base64
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace

from tools.capture_wp043_live import (
    LiveBackend,
    WindowsLiveBackend,
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
    def make_args(self, root, backend=None):
        executable = root / "AttackMap.NativeSpike.exe"
        report = root / "attackmap-report.json"
        executable.write_bytes(b"fake executable")
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
        from types import SimpleNamespace
        from tools.capture_wp043_live import WindowsLiveBackend

        item = SimpleNamespace(
            element_info=SimpleNamespace(
                name="Nastavení",
                automation_id="SettingsItem",
                class_name="Microsoft.UI.Xaml.Controls.NavigationViewItem",
                control_type="ListItem",
            ),
            focused=False,
        )
        item.set_focus = lambda: setattr(item, "focused", True)
        native_window = SimpleNamespace(descendants=lambda: [item])
        backend = WindowsLiveBackend.__new__(WindowsLiveBackend)
        backend._uia_window = lambda window: native_window
        backend.focus_navigation(owned_window(), "Settings")
        self.assertTrue(item.focused)

    @unittest.skipUnless(__import__("os").name == "nt", "Windows HWND signatures")
    def test_windows_foreground_api_preserves_native_hwnd_width(self):
        from ctypes import wintypes
        from tools.capture_wp043_live import WindowsLiveBackend

        user32 = WindowsLiveBackend._user32()
        self.assertEqual(user32.GetForegroundWindow.restype, wintypes.HWND)
        self.assertEqual(user32.GetForegroundWindow.argtypes, [])

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
                if key == "F7" and self.keys.count("F7") == 0:
                    self._append(
                        "detail-root-render-capture-completed", probeId="stale", generation=1,
                        displayedReadHash=self.report_hash, navigationRevision=self.navigation_revision,
                        findingRevision=self.finding_revision, detailFileName="d.png", rootFileName="t.png",
                        detailWidth=1, detailHeight=1, rootWidth=1, rootHeight=1, scale=1.0,
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
                if key == "F7" and self.keys.count("F7") == 1:
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

    def test_malformed_detail_root_png_never_claims_after_capture(self):
        class MalformedPngBackend(FakeBackend):
            def send_key(self, key):
                super().send_key(key)
                if key == "F7" and self.keys.count("F7") == 1:
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
            self.assertEqual(len(evidence["inputs"]["executable"]["sha256"]), 64)
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
