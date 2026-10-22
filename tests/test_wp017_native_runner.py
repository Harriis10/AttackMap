"""Runner negative gates and owned Python-process cleanup; no GUI/model dispatch."""
from contextlib import redirect_stdout
import ctypes
from io import StringIO
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tools import run_wp017_native_modes as runner


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="wp017-runner-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.package = self.base / "package"
        self.package.mkdir()
        for name in runner.REQUIRED_FILES:
            path = self.package / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"synthetic fixture; never executable: " + name.encode())
        self.manifest = dict(schema_version=1, architecture="x64", kind="portable-development-preview",
            release_candidate=False, native_build="fixture-native", engine_build="fixture-engine",
            runtime=dict(dotnet_self_contained=True, python_embedded=True, external_python_required=False, engine="engine/attackmap.exe"),
            files={name: dict(size_bytes=(self.package / name).stat().st_size, sha256=runner.sha(self.package / name))
                   for name in runner.REQUIRED_FILES})
        self.write_manifest()
        self.app = self.package / runner.APP_NAME
        self.seed = self.base / "seed/report.json"
        self.seed.parent.mkdir()
        self.seed.write_text(json.dumps({"scan": {"root": "fixture"}}))
        self.repository = self.base / "repository"
        self.repository.mkdir()
        repository_patch = patch.object(runner, "REPOSITORY", self.repository)
        repository_patch.start()
        self.addCleanup(repository_patch.stop)
        self.output = self.base / "new-output"

    def write_manifest(self):
        (self.package / "portable-manifest.json").write_text(json.dumps(self.manifest), encoding="utf-8")

    def args(self):
        return ["--app", str(self.app), "--seed", str(self.seed), "--output", str(self.output)]

    def plan(self, **kwargs):
        return runner.preflight(self.app, self.seed, self.output, **kwargs)

    def test_default_preflight_does_not_launch_or_contact_provider_or_write_output(self):
        with patch.object(runner, "run") as run, patch.object(runner, "check_local_model") as connection, \
             patch.object(subprocess, "Popen") as process, redirect_stdout(StringIO()) as out:
            code = runner.main(self.args())
        self.assertEqual(code, 0, out.getvalue())
        self.assertEqual(json.loads(out.getvalue())["modes"], list(runner.gate.MODES))
        run.assert_not_called()
        connection.assert_not_called()
        process.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_run_without_reviewed_pin_cannot_launch(self):
        with patch.object(runner, "run") as run, redirect_stdout(StringIO()) as out:
            code = runner.main(self.args() + ["--run"])
        self.assertEqual(code, 1)
        self.assertIn("reviewed --manifest-sha256", out.getvalue())
        run.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_explicit_single_mode_keeps_acceptance_open(self):
        plan = self.plan(mode="hunt_verify")
        self.assertEqual(plan["modes"], ["hunt_verify"])
        self.assertEqual(plan["package"]["files_verified"], len(runner.REQUIRED_FILES))
        self.assertTrue(all(plan[key] is False for key in runner.ACCEPTANCE))

    def test_actual_portable_winui_runtime_casing_is_supported(self):
        name = "Microsoft.UI.Xaml.dll"
        actual = "Microsoft.ui.xaml.dll"
        (self.package / name).rename(self.package / "winui-case-temporary")
        (self.package / "winui-case-temporary").rename(self.package / actual)
        self.manifest["files"][actual] = self.manifest["files"].pop(name)
        self.write_manifest()
        self.assertTrue(self.plan()["passed"])

    def test_payload_tamper_is_rejected_even_without_a_pin(self):
        self.app.write_bytes(b"changed fixture")
        with self.assertRaisesRegex(ValueError, "Payload tamper"):
            self.plan()

    def test_modified_manifest_cannot_reuse_previous_package_pin(self):
        pin = self.plan()["package"]["manifest"]["sha256"]
        self.app.write_bytes(b"changed fixture")
        self.manifest["files"][runner.APP_NAME] = dict(size_bytes=self.app.stat().st_size, sha256=runner.sha(self.app))
        self.write_manifest()
        with self.assertRaisesRegex(ValueError, "reviewed pin"):
            self.plan(manifest_sha256=pin)

    def test_stale_package_proof_fails_before_any_model_request(self):
        plan = self.plan()
        self.manifest["native_build"] = "later-build"
        self.write_manifest()
        with patch.object(runner, "check_local_model") as connection, patch.object(runner, "launch") as launch:
            with self.assertRaisesRegex(ValueError, "reviewed pin"):
                runner.run(plan)
        connection.assert_not_called()
        launch.assert_not_called()
        self.assertFalse(json.loads((self.output / "failure.json").read_text())["passed"])

    def test_extra_payload_or_empty_directory_is_rejected(self):
        for name in ("unlisted.dll", "unlisted-folder"):
            with self.subTest(name=name):
                path = self.package / name
                path.mkdir() if name.endswith("folder") else path.write_bytes(b"extra")
                with self.assertRaisesRegex(ValueError, "Unexpected portable"):
                    self.plan()
                path.rmdir() if path.is_dir() else path.unlink()

    def test_missing_payload_and_incomplete_manifest_are_rejected(self):
        (self.package / "coreclr.dll").unlink()
        with self.assertRaisesRegex(ValueError, "Missing portable"):
            self.plan()
        del self.manifest["files"]["coreclr.dll"]
        self.write_manifest()
        with self.assertRaisesRegex(ValueError, "Incomplete portable"):
            self.plan()

    def test_wrong_app_rejects_component_preview_or_engine(self):
        for name in ("WP017Preview.exe", "engine/attackmap.exe", "AttackMap.NativeSpike.dll"):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "full AttackMap.NativeSpike.exe"):
                runner.preflight(self.package / name, self.seed, self.output)

    def test_unsafe_manifest_names_are_rejected(self):
        for name in ("../outside", "/absolute", "nested\\file", "C:/escape", "engine//alias", "CON.txt", "a:stream", "tail.", "./alias"):
            with self.subTest(name=name):
                self.manifest["files"][name] = dict(size_bytes=1, sha256="a" * 64)
                self.write_manifest()
                with self.assertRaises(ValueError):
                    self.plan()
                del self.manifest["files"][name]

    def test_case_alias_and_duplicate_json_properties_are_rejected(self):
        self.manifest["files"]["attackmap.nativespike.exe"] = self.manifest["files"][runner.APP_NAME]
        self.write_manifest()
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            self.plan()
        (self.package / "portable-manifest.json").write_text('{"schema_version":1,"schema_version":1}')
        with self.assertRaisesRegex(ValueError, "Duplicate JSON"):
            self.plan()

    def test_existing_output_and_output_inside_inputs_are_rejected(self):
        self.output.mkdir()
        with self.assertRaisesRegex(ValueError, "stale proof roots"):
            self.plan()
        for output in (self.package / "new-output", self.repository / "new-output", self.seed.parent / "new-output"):
            with self.subTest(output=output), self.assertRaisesRegex(ValueError, "separate"):
                runner.preflight(self.app, self.seed, output)

    def test_unc_traversal_and_reparse_inputs_are_rejected(self):
        for value in (r"\\server\share\app.exe", "//server/share/app.exe", str(self.base) + "/../alias"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                runner.local_path(value)
        with patch.object(Path, "lstat", return_value=SimpleNamespace(st_mode=stat.S_IFDIR, st_file_attributes=0x400)):
            with self.assertRaisesRegex(ValueError, "reparse"):
                runner.no_link(self.package)

    def test_hard_linked_payload_is_rejected(self):
        alias = self.base / "outside-alias"
        os.link(self.app, alias)
        with self.assertRaisesRegex(ValueError, "Hard-linked"):
            self.plan()

    def test_child_environment_drops_provider_python_proxy_and_qa_overrides(self):
        windows = self.base / "Windows"
        (windows / "System32").mkdir(parents=True)
        environment = runner.child_environment(self.output, dict(SystemRoot=str(windows), PATH="python;remote-tool",
            OPENAI_API_KEY="fixture-secret", ANTHROPIC_API_KEY="fixture-secret", PYTHONPATH="outside",
            VIRTUAL_ENV="outside", ATTACKMAP_QA_HTTP_AUDIT_NONCE="old", HTTP_PROXY="http://proxy",
            SSL_CERT_FILE="outside", OPENAI_BASE_URL="https://remote.invalid", HOME="outside"))
        self.assertEqual(environment["PATH"], str(windows / "System32") + ";" + str(windows))
        self.assertTrue(set(environment) <= {"SYSTEMROOT", "PATH", "APPDATA", "LOCALAPPDATA", "USERPROFILE", "TEMP", "TMP"})
        self.assertTrue(Path(environment["APPDATA"]).is_relative_to(self.output))

    def test_redirect_guard_never_follows_other_endpoint(self):
        with self.assertRaisesRegex(ValueError, "Redirect rejected"):
            runner.NoRedirect().redirect_request(None, None, 302, "", {}, "https://remote.invalid")


@unittest.skipUnless(os.name == "nt", "Windows job API")
class OwnedProcessTests(unittest.TestCase):
    def test_child_error_mode_restores_parent_even_when_creation_fails(self):
        previous = ctypes.windll.kernel32.GetErrorMode()
        with self.assertRaisesRegex(OSError, "synthetic creation failure"):
            with runner.inherited_error_mode():
                self.assertEqual(ctypes.windll.kernel32.GetErrorMode(), 0x8003)
                raise OSError("synthetic creation failure")
        self.assertEqual(ctypes.windll.kernel32.GetErrorMode(), previous)

    def test_launch_assigns_suspended_process_then_records_verified_exit(self):
        with tempfile.TemporaryDirectory(prefix="wp017-launch-") as folder:
            output = Path(folder)
            environment = runner.child_environment(output)
            runner.launch([sys.executable, "-c", "print('owned fixture process')"], output, environment, 10)
            started = json.loads((output / "started.json").read_text())
            result = json.loads((output / "process.json").read_text())
            self.assertTrue(started["suspended_before_job_assignment"])
            self.assertTrue(result["owned_job_assigned"] and result["owned_tree_cleanup_verified"] and result["exited"])
            self.assertEqual(result["exit_code"], 0)

    def test_owned_job_terminates_parent_and_child_without_name_based_kills(self):
        job = runner.WindowsJob()
        child = subprocess.Popen([sys.executable, "-c",
            "import sys,subprocess,time; sys.stdin.readline(); "
            "p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)']); "
            "print(p.pid,flush=True); time.sleep(30)"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
        try:
            job.assign(child)
            child.stdin.write("start\n")
            child.stdin.flush()
            self.assertTrue(child.stdout.readline().strip().isdigit())
            # Windows virtualenv launchers can contribute additional owned processes.
            self.assertGreaterEqual(job.active(), 2)
            job.cleanup()
            child.wait(timeout=5)
            self.assertEqual(job.active(), 0)
            self.assertIsNotNone(child.returncode)
        finally:
            job.close()
            child.wait(timeout=5)
            child.stdin.close()
            child.stdout.close()


if __name__ == "__main__":
    unittest.main()
