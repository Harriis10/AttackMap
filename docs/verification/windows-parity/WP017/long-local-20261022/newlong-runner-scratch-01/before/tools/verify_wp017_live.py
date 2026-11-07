"""Offline WP017 evidence gate. Never dispatches a provider or trusts call reservations.

Input is a collector-authored JSON object described by --help. Server events must
be independently extracted from the hashed raw LM Studio log, not engine metadata.
Passing validates evidence consistency, not the truth of an untrusted collector.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re

MODES = {"review": "defensive-review-llm.md", "hunt": "vulnerability-hypotheses.md",
         "hunt_verify": "vulnerability-hypotheses.md", "remediate": "remediation.md", "triage": "triage.md"}
ENDPOINT = "http://127.0.0.1:1234/v1"
MODEL = "cyberstag-security-26b-a4b-v1"


def verify(evidence: dict, base: Path) -> dict:
    failures: list[str] = []
    def require(condition, reason):
        if not condition:
            failures.append(reason)
    def bound(record, label):
        try:
            path = Path(record["path"])
            path = path if path.is_absolute() else base / path
            data = path.read_bytes()
            require(hashlib.sha256(data).hexdigest() == record["sha256"], label + " hash mismatch")
            return data
        except (KeyError, TypeError, OSError):
            failures.append(label + " missing/unreadable hash-bound file")
            return b""
    def document(record, label):
        try:
            value = json.loads(bound(record, label))
            require(isinstance(value, dict), label + " must be object")
            return value if isinstance(value, dict) else {}
        except (ValueError, UnicodeError):
            failures.append(label + " invalid JSON")
            return {}

    mode = evidence.get("mode")
    require(mode in MODES, "unknown mode")
    kind = evidence.get("engine_kind")
    require(kind in ("source-native", "packaged"), "engine_kind must be source-native or packaged")
    bound(evidence.get("engine", {}), "engine executable")
    if kind == "packaged":
        proof = document(evidence.get("package_proof", {}), "package verification proof")
        require(proof.get("passed") is True, "package verification proof did not pass")
        # Packaging proof format/identity remains separately governed by WP024.
        require(bool(evidence.get("package_id")), "packaged evidence requires exact package_id")
    smoke = document(evidence.get("smoke", {}), "native smoke")
    result = smoke.get("result") or {}
    require(smoke.get("failure") is None, "native smoke failure")
    for key in ("passed", "capabilitiesChecked", "scanCompleted", "progressTerminal"):
        require(result.get(key) is True, "native smoke missing " + key)
    require(result.get("progressState") == "completed", "native progress did not complete")
    require(result.get("personalSettingsRead") is False, "personal settings isolation not recorded")
    require(evidence.get("isolated_output") is True, "private output root not recorded")
    request = document(evidence.get("request", {}), "native request")
    # Collector exposes the emitted provider object directly; no guessed nesting.
    provider = evidence.get("emitted_provider") or {}
    require(provider and evidence.get("provider_pointer"), "emitted provider requires JSON pointer into request")
    pointer = evidence.get("provider_pointer", "")
    actual = request
    try:
        require(pointer.startswith("/"), "provider_pointer must be an absolute JSON pointer")
        for part in pointer.split("/")[1:]:
            actual = actual[part.replace("~1", "/").replace("~0", "~")]
        require(actual == provider, "provider does not match emitted request")
    except (KeyError, TypeError):
        failures.append("provider_pointer missing in emitted request")
    # Retained default-budget evidence predates timeout provenance. New evidence
    # must bind the requested, emitted and actual launcher budgets independently.
    provider_timeout = 900
    if any(key in evidence for key in ("timeout_budget", "preflight", "process")) or "timeoutBudget" in result:
        budget = evidence.get("timeout_budget")
        keys = {"provider_timeout_seconds", "scan_timeout_seconds", "harness_timeout_seconds"}
        valid_budget = isinstance(budget, dict) and set(budget) == keys and all(type(budget[key]) is int for key in keys)
        require(valid_budget, "timeout budget must contain exactly three integer seconds")
        preflight = document(evidence.get("preflight", {}), "timeout preflight")
        process = document(evidence.get("process", {}), "native process")
        requested = {"provider_timeout_seconds": preflight.get("provider_budget_seconds"),
                     "scan_timeout_seconds": preflight.get("native_scan_timeout_seconds"),
                     "harness_timeout_seconds": preflight.get("process_timeout_seconds")}
        native = result.get("timeoutBudget")
        options = request.get("options")
        options = options if isinstance(options, dict) else {}
        if valid_budget:
            provider_timeout = budget["provider_timeout_seconds"]
            scan_timeout, harness_timeout = budget["scan_timeout_seconds"], budget["harness_timeout_seconds"]
            require(1 <= provider_timeout <= 3600 and 1 <= scan_timeout <= 86400
                    and provider_timeout <= scan_timeout < harness_timeout <= 7200, "timeout budget bounds/order invalid")
            require(requested == budget and all(type(value) is int for value in requested.values()), "preflight timeout budget mismatch")
            require(isinstance(native, dict) and native == budget and all(type(value) is int for value in native.values()),
                    "native timeout budget mismatch")
            require(type(options.get("timeout_seconds")) is int and options["timeout_seconds"] == scan_timeout,
                    "emitted scan timeout mismatch")
            emitted_timeout_key = (evidence.get("provider_fields") or {}).get("timeout_seconds")
            require(type(provider.get(emitted_timeout_key)) is int and isinstance(actual, dict)
                    and type(actual.get(emitted_timeout_key)) is int, "emitted provider timeout must be integer seconds")
            require(type(process.get("timeout_seconds")) is int and process["timeout_seconds"] == harness_timeout,
                    "actual launcher timeout mismatch")
        require(process.get("exited") is True and process.get("exit_code") == 0 and process.get("timed_out") is False
                and process.get("owned_job_assigned") is True and process.get("owned_tree_cleanup_verified") is True,
                "native process exit/owned cleanup incomplete")
    # Names below are collector-neutral values verified against explicit request paths.
    expected = {"endpoint": ENDPOINT, "model": MODEL, "mode": mode,
                "backend": "api", "speed": "standard", "max_calls": 8,
                "max_output_tokens": 32000, "timeout_seconds": provider_timeout}
    fields = evidence.get("provider_fields") or {}
    for key, wanted in expected.items():
        require(key in fields and provider.get(fields.get(key)) == wanted, "provider setting mismatch: " + key)
    manifest = document(evidence.get("run_manifest", {}), "run manifest")
    ai = manifest.get("desktop_ai") or {}
    require(ai.get("mode") == mode and ai.get("status") == "completed" and ai.get("model_output_available") is True,
            "requested AI mode did not complete with model output")
    artifact = evidence.get("artifact") or {}
    require(Path(artifact.get("path", "")).name == MODES.get(mode), "wrong mode artifact filename")
    prose = bound(artifact, "mode artifact")
    require(bool(prose.strip()), "empty model output")
    meta = document(evidence.get("metadata", {}), "mode metadata")
    require(meta.get("backend") == "api" and meta.get("model") == MODEL, "metadata provider mismatch/fallback")
    require(meta.get("stop_reason") in ("stop", "end_turn", "completed"), "model response completion unknown/partial")
    require(not meta.get("failed_passes", 0), "failed model passes")
    require(evidence.get("displayed_mode") == mode and evidence.get("displayed_generation") == result.get("run"),
            "Reports mode/generation binding missing")
    bound(evidence.get("capture", {}), "full-shell Reports capture")
    exported = bound(evidence.get("export", {}), "selected artifact export")
    require(exported == prose and bool(prose), "selected export differs from captured artifact")
    require(result.get("reportHash") == evidence.get("selected_report_sha256") and bool(result.get("reportHash")),
            "selected report hash not bound")
    if evidence.get("provider_event_source") == "attackmap-httpx-audit":
        actual, completed = verify_transport_audits(evidence, base, require, bound)
    else:
        raw = bound(evidence.get("provider_log", {}), "independent provider log")
        require(evidence.get("provider_event_source") == "lm-studio-server-log", "independent server observation missing")
        events = evidence.get("provider_events") or []
        require(isinstance(events, list) and bool(events), "no actual provider request evidence")
        ids = set()
        completed = 0
        for event in events if isinstance(events, list) else []:
            request_id = event.get("request_id")
            require(bool(request_id) and request_id not in ids, "missing/duplicate provider request identity")
            ids.add(request_id)
            require(event.get("route") == "/v1/responses" and event.get("model") == MODEL, "unexpected request route/model")
            excerpt = event.get("raw_excerpt", "").encode("utf-8")
            require(bool(excerpt) and excerpt in raw, "provider event excerpt absent from raw log")
            require(isinstance(request_id, str) and request_id.encode("utf-8") in excerpt, "provider excerpt lacks request identity")
            if event.get("completed") is True:
                completed += 1
                require(event.get("nonempty_output") is True and bool(event.get("response_sha256")), "completed response lacks output evidence")
                response = bound(event.get("response", {}), "completed provider response")
                require(bool(response.strip()) and hashlib.sha256(response).hexdigest() == event.get("response_sha256"),
                        "completed provider response bytes/hash missing")
        actual = len(events)
    require(completed > 0, "no completed nonempty provider responses")
    require(evidence.get("actual_http_requests") == actual, "actual HTTP count mismatch")
    require(evidence.get("completed_responses") == completed, "completed-response count mismatch")
    return {"passed": not failures, "mode": mode, "engine_kind": kind,
            "verdict": ("packaged evidence consistent; WP024 package identity approval remains separate" if kind == "packaged"
                        else "source-native interim only; packaged-engine WP017 acceptance remains open"),
            "actual_http_requests": actual, "completed_responses": completed,
            "collector_truth_independently_audited": False, "accepted_manual_ui": False,
            "accepted_wp017": False,
            "failures": failures}


def verify_transport_audits(evidence, base, require, bound):
    """Validate own locally trusted observer records and generated bytes only."""
    records = evidence.get("provider_audits") or []
    require(bool(records), "no own transport audit logs")
    nonce = evidence.get("audit_nonce")
    require(isinstance(nonce, str) and bool(re.fullmatch(r"[A-Za-z0-9_-]{1,64}", nonce)), "invalid audit nonce")
    attempts, received, observed = set(), set(), set()
    completed = 0
    logs = set()
    for record in records:
        raw = bound(record, "own transport audit")
        path = Path(record.get("path", ""))
        path = path if path.is_absolute() else base / path
        require(path.resolve() not in logs, "duplicate audit log")
        logs.add(path.resolve())
        try:
            events = [json.loads(line) for line in raw.splitlines()]
        except (ValueError, UnicodeError):
            require(False, "invalid transport JSONL")
            continue
        require(bool(events) and events[0].get("event") == "audit_started", "audit start missing")
        previous = -1
        for sequence, event in enumerate(events, 1):
            require(event.get("sequence") == sequence and event.get("nonce") == nonce and event.get("schema_version") == "1.0", "audit sequence/identity mismatch")
            stamp = event.get("monotonic_ns", -1)
            require(type(stamp) is int and stamp >= previous and bool(event.get("utc")), "invalid audit timing")
            previous = stamp
            kind, attempt = event.get("event"), event.get("attempt_id")
            if kind == "audit_started":
                require(sequence == 1 and event.get("endpoint") == ENDPOINT and event.get("model") == MODEL, "unexpected audited provider")
                continue
            valid_id = isinstance(attempt, str) and bool(re.fullmatch("[a-f0-9]{32}", attempt))
            require(valid_id, "invalid attempt identity")
            if kind == "attempted_dispatch":
                require(attempt not in attempts and event.get("method") == "POST" and event.get("path") == "/v1/responses" and event.get("origin") == "http://127.0.0.1:1234" and event.get("model") == MODEL, "unexpected/duplicate audited request")
                attempts.add(attempt)
            elif kind == "http_response_received":
                require(attempt in attempts and attempt not in received and event.get("method") == "POST" and event.get("path") == "/v1/responses", "unpaired/duplicate HTTP response")
                received.add(attempt)
            elif kind == "observation_complete":
                require(attempt in received and attempt not in observed, "unpaired/duplicate completion observation")
                observed.add(attempt)
                require(event.get("parse_status") == "json" and type(event.get("body_bytes")) is int and event["body_bytes"] > 0 and bool(re.fullmatch("[a-f0-9]{64}", event.get("body_sha256", ""))), "unknown/malformed response observation")
                if event.get("completed") is True:
                    completed += 1
                    status = event.get("status")
                    require(type(status) is int and 200 <= status < 300 and event.get("model") == MODEL, "failed/wrong-model response marked completed")
                    name = event.get("output_file")
                    require(valid_id and name == f"output-{attempt}.utf8", "unsafe generated-output filename")
                    if valid_id and name == f"output-{attempt}.utf8":
                        output = bound({"path": str(path.parent / name), "sha256": event.get("output_sha256")}, "observed generated output")
                        require(bool(output.strip()) and len(output) == event.get("output_bytes"), "completed generated output missing/empty")
            else:
                require(False, "unknown transport event")
    require(bool(attempts) and attempts == received == observed, "incomplete own transport observation; attempts are not HTTP completion proof")
    return len(received), completed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", type=Path, help="Collector JSON: mode, engine_kind; hash-bound {path,sha256} engine/smoke/request/run_manifest/artifact/metadata/capture/export/provider_log; emitted_provider, provider_pointer, provider_fields mapping normalized setting names to actual emitted keys; displayed_mode/generation, selected_report_sha256, isolated_output; actual_http_requests/completed_responses; provider_events with request_id/route/model/completed/nonempty_output/response_sha256/raw_excerpt; provider_event_source=lm-studio-server-log. Packaged adds package_proof and package_id.")
    args = parser.parse_args()
    try:
        result = verify(json.loads(args.evidence.read_text(encoding="utf-8")), args.evidence.resolve().parent)
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as error:
        result = {"passed": False, "failures": [str(error)]}
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["passed"] else 1)


if __name__ == "__main__":
    main()
