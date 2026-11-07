"""Fixture/gate unit tests only: no native GUI, engine, provider or real model."""
import copy
import hashlib
import http.client
import importlib.util
import io
import json
from pathlib import Path
import shutil
import socket
import threading
import time
import unittest
import uuid
from unittest.mock import patch
from urllib.parse import urlsplit

MODULE = Path(__file__).with_name("provider_fault_fixture.py")
spec = importlib.util.spec_from_file_location("wp017_provider_fault_fixture", MODULE)
f = importlib.util.module_from_spec(spec)
spec.loader.exec_module(f)


class OwnedTempTests(unittest.TestCase):
    def setUp(self):
        self.parent = Path(__file__).parent / "test-temp"
        self.parent.mkdir(exist_ok=True)
        self.root = self.parent / ("case-" + uuid.uuid4().hex)
        self.root.mkdir()  # Inherit workspace ACL; Python3.13 mkdtemp's private DACL is incompatible with this sandbox.
        self.addCleanup(self.remove_owned)

    def remove_owned(self):
        if self.root.resolve().parent != self.parent.resolve():
            raise ValueError("Test cleanup escaped its owned parent")
        shutil.rmtree(self.root)


class FixtureTests(OwnedTempTests):

    def request(self, fixture, body=None, path="/v1/responses"):
        endpoint = urlsplit(fixture.endpoint)
        connection = http.client.HTTPConnection(endpoint.hostname, endpoint.port, timeout=5)
        try:
            connection.request("POST", path, json.dumps(body or {"model": f.MODEL, "input": "private-source-sentinel"}),
                               {"Content-Type": "application/json", "Authorization": "private-auth-sentinel"})
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()

    def test_service_unavailable_is_one_observed_post_and_owned_socket_closes(self):
        fixture = f.Fixture(self.root, "unavailable", "a" * 32)
        self.addCleanup(fixture.close)
        status, body = self.request(fixture)
        self.assertEqual(status, 503)
        self.assertIn("controlled fixture unavailable", body.decode())
        proof = fixture.close()
        self.assertTrue(proof["server_thread_joined"] and proof["handler_threads_joined"])
        self.assertEqual(len([r for r in proof["events"] if r["kind"] == "received"]), 1)
        self.assertNotEqual(urlsplit(fixture.endpoint).port, 1234)
        self.assertNotIn("private-source-sentinel", json.dumps(proof))
        self.assertNotIn("private-auth-sentinel", json.dumps(proof))
        self.assertEqual(proof["events"][-1]["response_sha256"], hashlib.sha256(body).hexdigest())

    def test_malformed_response_is_exactly_invalid_json(self):
        fixture = f.Fixture(self.root, "malformed", "b" * 32)
        self.addCleanup(fixture.close)
        self.assertEqual(self.request(fixture), (200, b"{"))
        fixture.close()
        marker = f.h.read(self.root / "received.json")
        self.assertEqual(marker["nonce"], "b" * 32)
        self.assertEqual(marker["path"], "/v1/responses")

    def test_pending_response_waits_for_native_release_and_threads_join(self):
        fixture = f.Fixture(self.root, "pending-cancel", "c" * 32)
        self.addCleanup(fixture.close)
        result = []
        client = threading.Thread(target=lambda: result.append(self.request(fixture)))
        client.start()
        try:
            self.assertTrue(fixture.received.wait(5))
            self.assertTrue(client.is_alive())
            f.h.save(self.root / "release-fixture.json", {"nonce": "c" * 32})
            client.join(5)
            self.assertFalse(client.is_alive())
            self.assertIn(b"CONTROLLED FIXTURE ONLY", result[0][1])
        finally:
            fixture.close()
            client.join(5)
        self.assertTrue(fixture.closed)

    def test_wrong_model_and_path_do_not_count_as_generation(self):
        fixture = f.Fixture(self.root, "malformed", "d" * 32)
        self.addCleanup(fixture.close)
        self.assertEqual(self.request(fixture, {"model": "wrong"})[0], 400)
        self.assertEqual(self.request(fixture, path="/v1/chat/completions")[0], 404)
        proof = fixture.close()
        self.assertFalse(any(r["kind"] == "received" for r in proof["events"]))
        self.assertFalse((self.root / "received.json").exists())

    def test_unknown_case_rejected_before_socket(self):
        with patch.object(f.socket, "socket", side_effect=AssertionError("socket must not open")):
            with self.assertRaisesRegex(ValueError, "Unknown"):
                f.Fixture(self.root, "real-model", "e" * 32)

    def test_incomplete_headers_cannot_hold_owned_fixture_cleanup(self):
        fixture = f.Fixture(self.root, "malformed", "d" * 32)
        self.addCleanup(fixture.close)
        endpoint = urlsplit(fixture.endpoint)
        connection = socket.create_connection((endpoint.hostname, endpoint.port), timeout=5)
        self.addCleanup(connection.close)
        connection.sendall(b"POST /v1/responses HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Incomplete: ")
        until = time.monotonic() + 5
        while not fixture.server.connections and time.monotonic() < until:
            time.sleep(.01)
        self.assertTrue(fixture.server.connections)
        started = time.monotonic()
        proof = fixture.close()
        self.assertLess(time.monotonic() - started, 8)  # Includes Windows' bounded accepted-socket read timeout.
        self.assertTrue(proof["handler_threads_joined"])

    def test_cli_default_has_no_socket_process_or_output_creation(self):
        package = self.root / "package"
        (package / "engine").mkdir(parents=True)
        app = package / f.h.APP_NAME
        app.write_bytes(b"unit fixture, never executable")
        (package / "engine/attackmap.exe").write_bytes(b"unit fixture")
        seed = self.root / "seed/attackmap-report.json"
        seed.parent.mkdir()
        f.h.save(seed, {"scan": {}, "findings": []})
        output = self.root / "new-output"
        manifest = package / "portable-manifest.json"
        manifest.write_bytes(b"unit fixture")
        with patch.object(f.h, "package_identity", return_value={"manifest": {"path": str(manifest)}}), \
             patch.object(f.socket, "socket", side_effect=AssertionError("default must not bind")), \
             patch.object(f.h, "launch", side_effect=AssertionError("default must not launch")), patch("sys.stdout", new=io.StringIO()) as stdout:
            f.main(["--app", str(app), "--seed", str(seed), "--output", str(output), "--case", "malformed"])
        result = json.loads(stdout.getvalue())
        self.assertEqual(result["stage"], "preflight-only")
        self.assertEqual(result["provider_requests_started"], 0)
        self.assertFalse(output.exists())


class PreviewBindingTests(OwnedTempTests):
    def setUp(self):
        super().setUp()
        self.app = self.root / "native" / f.h.APP_NAME
        self.app.parent.mkdir()
        self.app.write_bytes(b"never-executed synthetic native app")
        (self.app.parent / "AttackMap.NativeSpike.dll").write_bytes(b"synthetic DLL")
        self.engine = self.root / "engine/attackmap.exe"
        (self.engine.parent / "_internal").mkdir(parents=True)
        self.engine.write_bytes(b"never-executed synthetic engine")
        (self.engine.parent / "_internal/python313.dll").write_bytes(b"synthetic runtime")
        self.engine_proof = self.root / "build-proof.json"
        self.lock = self.root / "release-lock.json"
        self.lock.write_bytes(b"synthetic retained lock")
        payload = [dict(path=p.relative_to(self.engine.parent).as_posix(), size_bytes=p.stat().st_size, sha256=f.h.sha(p))
                   for p in self.engine.parent.rglob("*") if p.is_file()]
        f.h.save(self.engine_proof, dict(exe_sha256=f.h.sha(self.engine), payload_files=payload, release_lock_sha256=f.h.sha(self.lock)))
        self.native_proof = self.root / "native-build.json"
        self.current = dict(release_inputs={"unit-fixture": "synthetic"}, release_inputs_sha256="synthetic-source-digest")
        f.h.save(self.native_proof, dict(inputs_unchanged=True, inputs=self.current["release_inputs"], release_inputs_sha256=self.current["release_inputs_sha256"],
            native_extra_inputs={"desktop/windows/AttackMap.NativeSpike/MainWindow.ProviderFaultSmoke.cs": f.h.sha(f.REPO / "desktop/windows/AttackMap.NativeSpike/MainWindow.ProviderFaultSmoke.cs")},
            artifacts={name: dict(sha256=f.h.sha(self.app.parent / name), bytes=(self.app.parent / name).stat().st_size)
                       for name in (f.h.APP_NAME, "AttackMap.NativeSpike.dll")}))
        self.binding = dict(native_build_proof=str(self.native_proof), native_build_proof_sha256=f.h.sha(self.native_proof),
            engine=str(self.engine), engine_sha256=f.h.sha(self.engine), engine_build_proof=str(self.engine_proof), engine_build_proof_sha256=f.h.sha(self.engine_proof))

    def verify(self, app=None):
        with patch("tools.generate_release_lock.release_inputs", return_value=self.current):
            return f.preview_identity(app or self.app, self.binding)

    def test_explicit_synthetic_preview_binding_has_no_package_or_live_acceptance(self):
        result = self.verify()
        self.assertEqual(result["payload_files_verified"], 2)
        self.assertFalse(result["accepted_wp017_live"])
        self.assertNotIn("package_id", result)

    def test_selected_executable_must_itself_be_bound(self):
        other = self.app.with_name("arbitrary.exe")
        other.write_bytes(b"unbound executable")
        with self.assertRaisesRegex(ValueError, "full native app"):
            self.verify(other)

    def test_current_source_and_full_retained_payload_are_checked(self):
        self.current["release_inputs_sha256"] = "changed"
        with self.assertRaisesRegex(ValueError, "current source"):
            self.verify()
        self.current["release_inputs_sha256"] = "synthetic-source-digest"
        (self.engine.parent / "_internal/python313.dll").write_bytes(b"tampered runtime")
        with self.assertRaisesRegex(ValueError, "payload mismatch"):
            self.verify()

    def test_both_build_proofs_require_explicit_hash_pins(self):
        for field in ("native_build_proof_sha256", "engine_build_proof_sha256"):
            with self.subTest(field=field):
                old = self.binding[field]
                self.binding[field] = "0" * 64
                with self.assertRaisesRegex(ValueError, "pin mismatch"):
                    self.verify()
                self.binding[field] = old


class GateTests(OwnedTempTests):
    """Synthetic artifacts test gate rejection; they do not establish a native PASS."""
    def setUp(self):
        super().setUp()
        self.case = "malformed"
        self.plan = {"case": self.case, "output": str(self.root)}
        self.config = {"nonce": "f" * 32, "endpoint": "http://127.0.0.1:49153/v1"}
        fixture_repo = self.root / "fixture-repository"
        fixture_repo.mkdir()
        self.plan["seed"] = self.write("seed.json", {"scan": {}, "findings": []})
        self.plan["engine"] = self.write("not-executable-engine.json", {"unit_fixture": True})
        baseline = self.selection("baseline-reports", "baseline")
        selected = self.selection("fault-reports", "fault")
        self.proof = dict(scope=f.SCOPE, case=self.case, nonce=self.config["nonce"], endpoint=self.config["endpoint"],
            failure=None, personalSettingsRead=False, baseline=baseline, selected=selected, aiState="unavailable",
            checks={name: True for name in ("nativeTerminal", "cleanupRestoresAdmission", "seedAndEngineUnchanged", "baselineBytesUnchanged",
                "deterministicGenerationPublished", "newGenerationBound", "reportsShowsUnavailable", "selectedExportMatches")})
        self.write("native-proof.json", self.proof)
        self.process = dict(exited=True, exit_code=0, timed_out=False, owned_job_assigned=True, owned_tree_cleanup_verified=True)
        self.write("process.json", self.process)
        provider = dict(enable_ai=True, provider="openai", endpoint=self.config["endpoint"], model=f.MODEL,
                        max_calls=1, timeout_seconds=30, output_token_limit=32000, mode="review", speed="standard", backend="api")
        request = dict(repository_path=str(fixture_repo), output_path=str(self.root / "fault-reports"), modules=["python-web", "config"],
                       options=dict(timeout_seconds=120, provider=provider))
        self.write("fault-reports/native-request.json", request)
        baseline_request = copy.deepcopy(request)
        baseline_request["options"]["provider"]["enable_ai"] = False
        self.write("baseline-reports/native-request.json", baseline_request)
        self.manifest = {"desktop_ai": dict(mode="review", status="unavailable", model_output_available=False,
                            allowance=dict(calls_reserved=1, max_calls=1, unknown_output_usage_calls=1, usage_status="partial_or_unknown"))}
        self.write("fault-reports/generations/fault/run-manifest.json", self.manifest)
        self.transport = dict(closed=True, server_thread_joined=True, handler_threads_joined=True, endpoint=self.config["endpoint"],
            events=[dict(kind="received", method="POST", path="/v1/responses", request_number=1), dict(kind="response", status=200, write_completed=True,
                method="POST", path="/v1/responses", request_number=1,
                response_sha256=hashlib.sha256(f.MALFORMED_BODY).hexdigest(), response_bytes=len(f.MALFORMED_BODY))])
        self.write("fixture-transport.json", self.transport)
        (self.root / "selected-report-export.json").write_bytes(Path(selected["path"]).read_bytes())

    def write(self, relative, value):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value), encoding="utf-8")
        return f.h.record(path)

    def selection(self, base, run):
        report = self.write(f"{base}/generations/{run}/attackmap-report.json", {"scan": {}, "findings": []})
        manifest = self.write(f"{base}/generations/{run}/artifact-manifest.json", {"generation_id": run})
        return dict(path=report["path"], sha256=report["sha256"], run=run, artifactManifestPath=manifest["path"], artifactManifestSha256=manifest["sha256"])

    def test_synthetic_gate_shape_pass_is_explicitly_not_live_acceptance(self):
        result = f.collect(self.plan, self.config, self.transport)
        self.assertTrue(result["passed"])
        self.assertFalse(result["accepted_wp017_live"])
        self.assertEqual(result["completed_real_model_responses"], 0)

    def test_reservations_without_observed_http_are_rejected(self):
        self.transport["events"] = []
        with self.assertRaisesRegex(ValueError, "observed generation POST"):
            f.collect(self.plan, self.config, self.transport)

    def test_retry_or_unexpected_endpoint_is_rejected(self):
        self.transport["events"].append(dict(kind="received", method="POST", path="/v1/responses"))
        with self.assertRaisesRegex(ValueError, "exactly one"):
            f.collect(self.plan, self.config, self.transport)

    def test_fixture_body_identity_is_required(self):
        self.transport["events"][1]["response_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "response body identity"):
            f.collect(self.plan, self.config, self.transport)

    def test_response_must_correlate_to_observed_generation_post(self):
        self.transport["events"][1]["request_number"] = 2
        with self.assertRaisesRegex(ValueError, "uncorrelated"):
            f.collect(self.plan, self.config, self.transport)

    def test_no_orphan_confirmation_is_required_for_both_owners(self):
        for field in ("owned_tree_cleanup_verified", "owned_job_assigned", "exited"):
            with self.subTest(field=field):
                broken = dict(self.process, **{field: False})
                self.write("process.json", broken)
                with self.assertRaisesRegex(ValueError, "process cleanup"):
                    f.collect(self.plan, self.config, self.transport)
        self.write("process.json", self.process)
        for field in ("closed", "server_thread_joined", "handler_threads_joined"):
            with self.subTest(field=field):
                with self.assertRaisesRegex(ValueError, "fixture cleanup"):
                    f.collect(self.plan, self.config, dict(self.transport, **{field: False}))

    def test_completed_claim_and_known_zero_usage_are_rejected(self):
        for patcher in (lambda ai: ai.update(status="completed", model_output_available=True),
                        lambda ai: ai["allowance"].update(unknown_output_usage_calls=0, usage_status="reported")):
            manifest = copy.deepcopy(self.manifest)
            patcher(manifest["desktop_ai"])
            self.write("fault-reports/generations/fault/run-manifest.json", manifest)
            with self.assertRaises(ValueError):
                f.collect(self.plan, self.config, self.transport)

    def test_changed_generation_or_export_bytes_are_rejected(self):
        (self.root / "selected-report-export.json").write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "exported bytes"):
            f.collect(self.plan, self.config, self.transport)
        Path(self.proof["selected"]["path"]).write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "artifact hash"):
            f.collect(self.plan, self.config, self.transport)

    def test_settings_read_or_missing_native_checks_are_rejected(self):
        self.proof["personalSettingsRead"] = True
        self.write("native-proof.json", self.proof)
        with self.assertRaisesRegex(ValueError, "settings isolation"):
            f.collect(self.plan, self.config, self.transport)
        self.proof["personalSettingsRead"] = False
        self.proof["checks"].pop("newGenerationBound")
        self.write("native-proof.json", self.proof)
        with self.assertRaisesRegex(ValueError, "checks incomplete"):
            f.collect(self.plan, self.config, self.transport)

    def test_pending_cancel_preserves_previous_report_and_rejects_current_pointer(self):
        self.plan["case"] = "pending-cancel"
        self.proof.update(case="pending-cancel", selected=self.proof["baseline"], aiState=None,
                          progressState="cancelled", cancelRequestedAfterHttp=True)
        self.proof["checks"] = {key: True for key in ("nativeTerminal", "cleanupRestoresAdmission", "seedAndEngineUnchanged", "baselineBytesUnchanged",
            "cancelledAfterObservedPost", "previousSelectionPreserved")}
        self.write("native-proof.json", self.proof)
        self.write("release-fixture.json", {"nonce": self.config["nonce"]})
        result = f.collect(self.plan, self.config, self.transport)
        self.assertTrue(result["passed"])
        self.write("fault-reports/current-generation.json", {"generation_id": "cancelled-should-not-publish"})
        with self.assertRaisesRegex(ValueError, "published a generation"):
            f.collect(self.plan, self.config, self.transport)


if __name__ == "__main__":
    (Path(__file__).parent / "test-temp").mkdir(exist_ok=True)
    unittest.main(verbosity=2)
