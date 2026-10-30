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
import textwrap
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

    def production_package(self):
        stage = self.base / "production"
        stage.mkdir()
        self.package.rename(stage / "app")
        self.package = stage / "app"
        self.app = self.package / runner.APP_NAME
        (self.package / "portable-manifest.json").unlink()
        # Production packages do not manufacture portable provenance files.
        for path in (self.package / "provenance").iterdir():
            path.unlink()
        (self.package / "provenance").rmdir()
        self.lock_values = dict(source_checksums_sha256="1" * 64, release_inputs_sha256="2" * 64,
                                analyzer_requirements_sha256="3" * 64)
        self.lock_path = self.base / "release-lock.json"
        self.lock_path.write_text(json.dumps({**self.lock_values,
            "toolchain": {tool: {"version": "fixture-1"} for tool in ("python", "pyinstaller", "dotnet_sdk")}}))
        inputs_patch = patch.object(runner.release_lock_tool, "release_inputs", return_value=dict(self.lock_values))
        self.current_inputs = inputs_patch.start()
        self.addCleanup(inputs_patch.stop)
        for name in ("Install-AttackMap.ps1", "Install-AttackMap.cmd"):
            (stage / name).write_text("fixture installer; never executed")
        self.production_manifest = dict(schema_version=1, architecture="win-x64", profile="RequiredBundled",
            package_id="dev-20261022000000-1234abcd",
            native_runtime=dict(dotnet_self_contained=True, windows_app_sdk_self_contained=True),
            engine=dict(bundled=True, runtime_kind="Frozen", executable="app/engine/attackmap.exe",
                        release_lock_sha256=runner.sha(self.lock_path), **self.lock_values),
            files=[dict(path=name, **value) for name, value in self.manifest["files"].items()
                   if not name.startswith("provenance/")],
            deployment_files=[dict(path=name, size_bytes=(stage / name).stat().st_size, sha256=runner.sha(stage / name))
                              for name in ("Install-AttackMap.ps1", "Install-AttackMap.cmd")])
        self.production_manifest_path = stage / "package-manifest.json"
        self.write_production_manifest()

    def write_production_manifest(self):
        self.production_manifest_path.write_text(json.dumps(self.production_manifest))

    def test_required_bundled_preflight_binds_real_layout_and_source_lock_without_dispatch(self):
        self.production_package()
        with patch.object(runner, "run") as run, patch.object(runner, "check_local_model") as connection, \
             patch.object(subprocess, "Popen") as process, redirect_stdout(StringIO()) as out:
            code = runner.main(self.args() + ["--release-lock", str(self.lock_path)])
        self.assertEqual(code, 0, out.getvalue())
        proof = json.loads(out.getvalue())["package"]
        self.assertEqual(proof["package_id"], self.production_manifest["package_id"])
        self.assertEqual(proof["manifest"]["path"], str(self.production_manifest_path))
        self.assertEqual(proof["release_lock"]["sha256"], runner.sha(self.lock_path))
        self.assertEqual(proof["identities"][runner.APP_NAME]["path"], str(self.app))
        self.assertTrue(all(proof[key] is False for key in runner.ACCEPTANCE))
        run.assert_not_called(); connection.assert_not_called(); process.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_required_bundled_missing_or_changed_release_lock_rejected(self):
        self.production_package()
        with self.assertRaisesRegex(ValueError, "requires --release-lock"):
            self.plan()
        self.lock_path.write_text(self.lock_path.read_text() + " ")
        with self.assertRaisesRegex(ValueError, "release-lock hash mismatch"):
            self.plan(release_lock=self.lock_path)

    def test_required_bundled_stale_source_or_unknown_toolchain_rejected(self):
        self.production_package()
        for key in self.lock_values:
            with self.subTest(key=key):
                self.current_inputs.return_value = {**self.lock_values, key: "f" * 64}
                with self.assertRaisesRegex(ValueError, "Stale package/source lock"):
                    self.plan(release_lock=self.lock_path)
        self.current_inputs.return_value = self.lock_values
        lock = json.loads(self.lock_path.read_text())
        lock["toolchain"]["python"]["version"] = "unknown"
        self.lock_path.write_text(json.dumps(lock))
        self.production_manifest["engine"]["release_lock_sha256"] = runner.sha(self.lock_path)
        self.write_production_manifest()
        with self.assertRaisesRegex(ValueError, "Unknown release toolchain"):
            self.plan(release_lock=self.lock_path)

    def test_required_bundled_rejects_external_profile_and_wrong_engine(self):
        self.production_package()
        self.production_manifest["profile"] = "ExternalEngine"
        self.write_production_manifest()
        with self.assertRaisesRegex(ValueError, "RequiredBundled"):
            self.plan(release_lock=self.lock_path)
        self.production_manifest["profile"] = "RequiredBundled"
        self.production_manifest["engine"]["executable"] = "app/cmd.exe"
        self.write_production_manifest()
        with self.assertRaisesRegex(ValueError, "Complete bundled"):
            self.plan(release_lock=self.lock_path)

    def test_required_bundled_deployment_tamper_extra_and_duplicate_inventory_rejected(self):
        self.production_package()
        launcher = self.package.parent / "Install-AttackMap.cmd"
        original = launcher.read_bytes()
        launcher.write_bytes(b"modified")
        with self.assertRaisesRegex(ValueError, "Payload tamper"):
            self.plan(release_lock=self.lock_path)
        launcher.write_bytes(original)
        extra = self.package.parent / "extra.dll"
        extra.write_bytes(b"extra")
        with self.assertRaisesRegex(ValueError, "Unexpected portable file"):
            self.plan(release_lock=self.lock_path)
        extra.unlink()
        self.production_manifest["files"].append(dict(self.production_manifest["files"][0]))
        self.write_production_manifest()
        with self.assertRaisesRegex(ValueError, "Duplicate production"):
            self.plan(release_lock=self.lock_path)

    def test_required_bundled_manifest_pin_and_ambiguous_manifests_rejected(self):
        self.production_package()
        plan = self.plan(release_lock=self.lock_path)
        self.production_manifest["package_id"] = "dev-20261022000001-1234abcd"
        self.write_production_manifest()
        with self.assertRaisesRegex(ValueError, "reviewed pin"):
            self.plan(release_lock=self.lock_path, manifest_sha256=plan["package"]["manifest"]["sha256"])
        (self.package / "portable-manifest.json").write_text("{}")
        with self.assertRaisesRegex(ValueError, "Ambiguous"):
            self.plan(release_lock=self.lock_path)

    def test_required_bundled_output_cannot_modify_package_root(self):
        self.production_package()
        with self.assertRaisesRegex(ValueError, "separate"):
            runner.preflight(self.app, self.seed, self.package.parent / "new-output", release_lock=self.lock_path)

    def test_required_bundled_rechecks_lock_before_and_after_each_mode(self):
        self.production_package()
        plan = self.plan(release_lock=self.lock_path)
        with patch.object(runner, "package_identity", wraps=runner.package_identity) as identity, \
             patch.object(runner, "check_local_model"), patch.object(runner, "launch"), \
             patch.object(runner, "collect", side_effect=lambda plan, mode, folder, nonce: {"mode": mode, "passed": True}):
            result = runner.run(plan)
        self.assertTrue(result["passed"])
        self.assertEqual(identity.call_count, 2 * len(runner.gate.MODES))
        for call in identity.call_args_list:
            self.assertEqual(call.args, (str(self.app), plan["package"]["manifest"]["sha256"], str(self.lock_path)))

    def test_required_bundled_changed_lock_after_launch_stops_evidence_collection(self):
        self.production_package()
        plan = self.plan(release_lock=self.lock_path)
        with patch.object(runner, "check_local_model"), \
             patch.object(runner, "launch", side_effect=lambda *args: self.lock_path.write_text("changed")) as launch, \
             patch.object(runner, "collect") as collect:
            with self.assertRaisesRegex(ValueError, "release-lock hash mismatch"):
                runner.run(plan)
        self.assertEqual(launch.call_count, 1)
        collect.assert_not_called()
        self.assertEqual(json.loads((self.output / "failure.json").read_text())["completed_modes"], [])

    def test_default_preflight_does_not_launch_or_contact_provider_or_write_output(self):
        with patch.object(runner, "run") as run, patch.object(runner, "check_local_model") as connection, \
             patch.object(subprocess, "Popen") as process, redirect_stdout(StringIO()) as out:
            code = runner.main(self.args())
        self.assertEqual(code, 0, out.getvalue())
        self.assertEqual(json.loads(out.getvalue())["modes"], list(runner.gate.MODES))
        self.assertEqual(runner.plan_timeouts(json.loads(out.getvalue())), runner.timeout_budget(900, 1200, 1500))
        run.assert_not_called()
        connection.assert_not_called()
        process.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_long_timeout_preflight_is_explicit_and_inert(self):
        with patch.object(runner, "run") as run, patch.object(runner, "check_local_model") as connection, \
             patch.object(subprocess, "Popen") as process, redirect_stdout(StringIO()) as out:
            code = runner.main(self.args() + ["--provider-timeout", "3600", "--scan-timeout", "4200", "--process-timeout", "4500"])
        self.assertEqual(code, 0, out.getvalue())
        plan = json.loads(out.getvalue())
        self.assertEqual(runner.plan_timeouts(plan), runner.timeout_budget(3600, 4200, 4500))
        self.assertEqual((plan["max_calls"], plan["output_token_limit"]), (8, 32000))
        self.assertEqual(plan["modes"], list(runner.gate.MODES))
        run.assert_not_called(); connection.assert_not_called(); process.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_invalid_timeout_triplets_fail_before_preflight_io_or_dispatch(self):
        for values in ((0, 1200, 1500), (3601, 4200, 4500), (900, 0, 1500),
                       (900, 86401, 7200), (900, 1200, 7201), (1201, 1200, 1500),
                       (900, 1200, 1200), (900, 1200, 1199), (True, 1200, 1500),
                       (900, 1200.5, 1500), (900, 1200, "4500")):
            with self.subTest(values=values), patch.object(runner, "local_path") as paths:
                with self.assertRaises(ValueError):
                    self.plan(provider_timeout=values[0], scan_timeout=values[1], process_timeout=values[2])
                paths.assert_not_called()
        self.assertEqual(runner.timeout_budget(3600, 3600, 3601)["scan_timeout_seconds"], 3600)
        self.assertEqual(runner.timeout_budget(3600, 7199, 7200)["harness_timeout_seconds"], 7200)

    def test_long_timeout_run_preserves_exact_argv_launcher_and_saved_budget(self):
        plan = self.plan(mode="hunt_verify", provider_timeout=3600, scan_timeout=4200, process_timeout=4500)
        with patch.object(runner, "check_local_model"), patch.object(runner, "launch") as launch, \
             patch.object(runner, "collect", return_value={"mode": "hunt_verify", "passed": True}):
            result = runner.run(plan)
        argv, folder, _, actual_timeout = launch.call_args.args
        self.assertEqual(actual_timeout, 4500)
        for flag, wanted in (("--qa-provider-timeout", "3600"), ("--qa-scan-timeout", "4200"), ("--qa-harness-timeout", "4500")):
            self.assertEqual(argv[argv.index(flag) + 1], wanted)
        self.assertEqual(argv[argv.index("--ai-mode") + 1], "hunt_verify")
        self.assertEqual(runner.read(folder / "inputs.json")["timeout_budget"], runner.plan_timeouts(plan))
        self.assertEqual(result["timeout_budget"], runner.plan_timeouts(plan))
        self.assertEqual(runner.plan_timeouts(runner.read(self.output / "preflight.json")), runner.plan_timeouts(plan))

    def test_run_rejects_conflicting_override_or_invalid_plan_before_dispatch(self):
        plan = self.plan(provider_timeout=3600, scan_timeout=4200, process_timeout=4500)
        with patch.object(runner, "check_local_model") as connection, patch.object(runner, "launch") as launch:
            with self.assertRaisesRegex(ValueError, "override differs"):
                runner.run(plan, 1500)
            plan["process_timeout_seconds"] = 4200
            with self.assertRaisesRegex(ValueError, "provider <= scan < process"):
                runner.run(plan)
        connection.assert_not_called(); launch.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_timeout_collection_requires_exact_native_request_and_actual_launcher_proof(self):
        for provider, scan, process in ((900, 1200, 1500), (3600, 4200, 4500)):
            with self.subTest(provider=provider):
                plan = self.plan(provider_timeout=provider, scan_timeout=scan, process_timeout=process)
                budget = runner.plan_timeouts(plan)
                status = {"timeoutBudget": dict(budget)}
                request = {"options": {"timeout_seconds": scan, "provider": {"timeout_seconds": provider}}}
                launched = {"timeout_seconds": process}
                self.assertEqual(runner.verify_timeout_evidence(plan, status, request, launched), budget)
                for key in budget:
                    bad = {"timeoutBudget": {**budget, key: budget[key] - 1}}
                    with self.subTest(key=key), self.assertRaisesRegex(ValueError, "Native QA timeout proof"):
                        runner.verify_timeout_evidence(plan, bad, request, launched)
                with self.assertRaisesRegex(ValueError, "legacy/missing"):
                    runner.verify_timeout_evidence(plan, {}, request, launched)
                for bad in ({"options": {"timeout_seconds": scan - 1, "provider": {"timeout_seconds": provider}}},
                            {"options": {"timeout_seconds": scan, "provider": {"timeout_seconds": provider - 1}}}):
                    with self.assertRaisesRegex(ValueError, "Emitted request timeouts"):
                        runner.verify_timeout_evidence(plan, status, bad, launched)
                for bad in ({}, {"timeout_seconds": process - 1}, {"timeout_seconds": str(process)}):
                    with self.assertRaisesRegex(ValueError, "Actual launcher timeout"):
                        runner.verify_timeout_evidence(plan, status, request, bad)

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
    def test_child_known_folders_resolve_inside_isolated_profile(self):
        probe = textwrap.dedent("""
            import ctypes, json, os, uuid
            from pathlib import Path
            resolve = ctypes.windll.shell32.SHGetKnownFolderPath
            resolve.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p,
                                ctypes.POINTER(ctypes.c_void_p)]
            resolve.restype = ctypes.c_long
            free = ctypes.windll.ole32.CoTaskMemFree
            free.argtypes = [ctypes.c_void_p]
            free.restype = None
            rows = {}
            for key, identifier in (
                ('LOCALAPPDATA', 'F1B32785-6FBA-4FCF-9D55-7B8E7F157091'),
                ('APPDATA', '3EB685DB-65F9-4CF6-A03A-E3EF65729F3D')):
                guid = ctypes.create_string_buffer(uuid.UUID(identifier).bytes_le)
                pointer = ctypes.c_void_p()
                result = resolve(guid, 0, None, ctypes.byref(pointer))
                try:
                    path = ctypes.wstring_at(pointer) if pointer.value else ''
                    rows[key] = dict(hresult=result, path=path, expected=os.environ[key],
                                     exists=bool(path) and Path(path).is_dir())
                finally:
                    free(pointer)
            print(json.dumps(rows))
        """)
        with tempfile.TemporaryDirectory(prefix="wp017-known-folders-") as folder:
            output = Path(folder)
            environment = runner.child_environment(output)
            runner.launch([sys.executable, "-c", probe], output, environment, 10)
            rows = json.loads((output / "stdout.log").read_text())
            process = json.loads((output / "process.json").read_text())
            print(json.dumps(dict(known_folders=rows, process=process)))
            self.assertTrue(process["owned_tree_cleanup_verified"] and process["exited"])
            self.assertEqual(process["exit_code"], 0)
            for key, row in rows.items():
                with self.subTest(folder=key):
                    self.assertEqual(row["hresult"], 0, row)
                    self.assertTrue(row["path"] and row["exists"], row)
                    path = Path(row["path"])
                    self.assertTrue(path.is_absolute())
                    self.assertEqual(path, Path(environment[key]))
                    self.assertTrue(path.is_relative_to(Path(environment["USERPROFILE"])))
                    self.assertTrue(path.is_relative_to(output))

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
            self.assertEqual(result["timeout_seconds"], 10)

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
