"""Synthetic verifier tests; these do not prove live provider integration."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from verify_wp017_live import ENDPOINT, MODEL, verify


class VerificationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="wp017-verifier-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        def file(name, value):
            data = value if isinstance(value, bytes) else json.dumps(value).encode()
            (self.base / name).write_bytes(data)
            return {"path": name, "sha256": hashlib.sha256(data).hexdigest()}
        self.file = file
        provider = {"endpoint": ENDPOINT, "model": MODEL, "mode": "review", "backend": "api", "speed": "standard",
                    "max_calls": 8, "max_output_tokens": 32000, "timeout_seconds": 900}
        self.evidence = dict(mode="review", engine_kind="source-native", engine=file("engine.exe", b"synthetic, never executed"),
            smoke=file("smoke.json", {"failure": None, "result": dict(passed=True, capabilitiesChecked=True, scanCompleted=True,
                progressTerminal=True, progressState="completed", personalSettingsRead=False, run="generation", reportHash="report-hash")}),
            request=file("request.json", {"provider": provider}), emitted_provider=provider, provider_pointer="/provider",
            provider_fields={key: key for key in provider}, isolated_output=True,
            run_manifest=file("run-manifest.json", {"desktop_ai": dict(mode="review", status="completed", model_output_available=True)}),
            artifact=file("defensive-review-llm.md", b"Synthetic fixture model prose"),
            metadata=file("defensive-review-llm.meta.json", dict(backend="api", model=MODEL, stop_reason="completed")),
            displayed_mode="review", displayed_generation="generation", selected_report_sha256="report-hash",
            capture=file("capture.png", b"synthetic capture fixture"), export=file("export.md", b"Synthetic fixture model prose"),
            provider_log=file("server.log", b"request-1 completed synthetic response"), provider_event_source="lm-studio-server-log",
            provider_events=[dict(request_id="request-1", route="/v1/responses", model=MODEL, completed=True,
                nonempty_output=True, response_sha256=hashlib.sha256(b"synthetic response").hexdigest(),
                response=file("response.txt", b"synthetic response"), raw_excerpt="request-1 completed synthetic response")],
            actual_http_requests=1, completed_responses=1)

    def test_interim_is_not_packaged_acceptance(self):
        result = verify(self.evidence, self.base)
        self.assertTrue(result["passed"], result)
        self.assertIn("interim only", result["verdict"])
        self.assertFalse(result["accepted_manual_ui"])

    def test_reservations_do_not_prove_http_responses(self):
        self.evidence.update(provider_events=[], actual_http_requests=0, completed_responses=0, calls_reserved=8)
        self.assertFalse(verify(self.evidence, self.base)["passed"])

    def test_tampered_export_rejected(self):
        (self.base / "export.md").write_text("changed")
        result = verify(self.evidence, self.base)
        self.assertFalse(result["passed"])
        self.assertIn("selected artifact export hash mismatch", result["failures"])

    def test_wrong_displayed_mode_and_fallback_rejected(self):
        self.evidence["displayed_mode"] = "hunt"
        self.evidence["metadata"] = self.file("fallback.json", dict(backend="deterministic", model=MODEL, stop_reason="completed"))
        result = verify(self.evidence, self.base)
        self.assertFalse(result["passed"])
        self.assertIn("metadata provider mismatch/fallback", result["failures"])

    def test_packaged_requires_separate_proof(self):
        self.evidence["engine_kind"] = "packaged"
        self.assertFalse(verify(self.evidence, self.base)["passed"])

    def test_server_excerpt_must_exist_in_hashed_observation(self):
        self.evidence["provider_events"][0]["raw_excerpt"] = "invented"
        self.assertFalse(verify(self.evidence, self.base)["passed"])

    def test_response_hash_alone_does_not_prove_completed_output(self):
        del self.evidence["provider_events"][0]["response"]
        self.assertFalse(verify(self.evidence, self.base)["passed"])

    def own_audit(self):
        attempt = "a" * 32
        data = b"Synthetic fixture model prose"
        self.file(f"output-{attempt}.utf8", data)
        common = dict(schema_version="1.0", nonce="fixture", pid=123, utc="2026-10-21T01:00:00Z")
        events = [dict(event="audit_started", endpoint=ENDPOINT, model=MODEL),
                  dict(event="attempted_dispatch", attempt_id=attempt, method="POST", path="/v1/responses", origin="http://127.0.0.1:1234", model=MODEL),
                  dict(event="http_response_received", attempt_id=attempt, method="POST", path="/v1/responses", status=200),
                  dict(event="observation_complete", attempt_id=attempt, parse_status="json", body_bytes=100,
                       body_sha256="b" * 64, completed=True, model=MODEL, status=200,
                       output_file=f"output-{attempt}.utf8", output_sha256=hashlib.sha256(data).hexdigest(), output_bytes=len(data))]
        for i, event in enumerate(events, 1):
            event.update(common, sequence=i, monotonic_ns=i)
        self.evidence.update(provider_event_source="attackmap-httpx-audit", audit_nonce="fixture",
            provider_audits=[self.file("audit.jsonl", ("\n".join(json.dumps(e) for e in events)+"\n").encode())])
        return events

    def test_own_observer_generated_bytes_are_valid_evidence(self):
        self.own_audit()
        result = verify(self.evidence, self.base)
        self.assertTrue(result["passed"], result)
        self.assertFalse(result["accepted_wp017"])

    def test_own_observer_unsettled_attempt_rejected(self):
        events = self.own_audit()
        self.evidence["provider_audits"] = [self.file("audit.jsonl", ("\n".join(json.dumps(e) for e in events[:2])+"\n").encode())]
        self.assertFalse(verify(self.evidence, self.base)["passed"])

    def test_own_observer_output_tamper_rejected(self):
        self.own_audit()
        (self.base / ("output-" + "a" * 32 + ".utf8")).write_bytes(b"changed")
        self.assertFalse(verify(self.evidence, self.base)["passed"])


if __name__ == "__main__":
    unittest.main()
