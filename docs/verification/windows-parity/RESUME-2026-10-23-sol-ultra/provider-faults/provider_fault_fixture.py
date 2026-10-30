"""Opt-in native provider fault journeys; never contacts LM Studio or a real model.

Default CLI is read-only preflight: no socket, process, fixture or output creation.
--run owns an ephemeral literal-loopback HTTP fixture and uses the existing
Windows Job launcher. These negative results cannot satisfy WP017 live success.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import sys
import threading
import time
import uuid

sys.dont_write_bytecode = True  # Preserve the default preflight's read-only behavior on first import too.
REPO = next(parent for parent in Path(__file__).resolve().parents
            if (parent / "tools/run_wp017_native_modes.py").is_file())
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))
from tools import run_wp017_native_modes as h

CASES = ("unavailable", "malformed", "pending-cancel")
MODEL = "attackmap-fixture-no-model"
SCOPE = "controlled-provider-fault-fixture"
UNAVAILABLE_BODY = b'{"error":{"message":"controlled fixture unavailable","type":"server_error"}}'
MALFORMED_BODY = b"{"
APP_SOURCE = ("from flask import Flask, request\napp = Flask(__name__)\n"
              "@app.route('/records')\ndef records():\n"
              "    return {'query': request.args.get('q', '')}\n"
              "if __name__ == '__main__':\n    app.run(debug=True)\n")
SOURCE_FILES = ("desktop/windows/AttackMap.NativeSpike/MainWindow.ProviderFaultSmoke.cs",
                "desktop/windows/AttackMap.NativeSpike/MainWindow.xaml.cs",
                "desktop/windows/AttackMap.NativeSpike/MainWindow.Parity.cs",
                "tools/run_wp017_native_modes.py", "tools/verify_wp017_live.py")
ACCEPTANCE = dict(accepted_wp017_live=False, accepted_manual_ui=False,
                  accepted_release=False, completed_real_model_responses=0)


def publish_marker(path, value):
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    h.save(temporary, value)
    temporary.rename(path)


def source_identity():
    return [h.record(REPO / name) for name in SOURCE_FILES] + [h.record(Path(__file__))]


def preview_identity(app, binding):
    """Current native publish + explicitly retained older frozen engine; no package claim."""
    from tools import generate_release_lock as lock_tool
    h.require(app.name == h.APP_NAME and app.is_file(), "Source preview must select the full native app executable")
    proof_path = h.local_path(binding["native_build_proof"])
    proof_record = h.record(proof_path)
    h.require(proof_record["sha256"] == binding["native_build_proof_sha256"], "Native build proof pin mismatch")
    proof = h.read(proof_path)
    current = lock_tool.release_inputs(REPO)
    h.require(proof.get("inputs_unchanged") is True and proof.get("inputs") == current["release_inputs"] and
              proof.get("release_inputs_sha256") == current["release_inputs_sha256"], "Native publish/current source binding mismatch")
    for name, wanted in proof.get("native_extra_inputs", {}).items():
        h.require(h.sha(h.local_path(REPO / h.relative_name(name))) == wanted, "Native resolved extra input changed")
    h.require(proof.get("native_extra_inputs"), "Native resolved extra inputs missing")
    for name in (h.APP_NAME, "AttackMap.NativeSpike.dll"):
        path = h.local_path(app.parent / name)
        wanted = proof.get("artifacts", {}).get(name, {})
        h.require(h.sha(path) == wanted.get("sha256") and path.stat().st_size == wanted.get("bytes"), "Native publish artifact mismatch")
    engine = h.local_path(binding["engine"])
    engine_proof_path = h.local_path(binding["engine_build_proof"])
    engine_proof_record = h.record(engine_proof_path)
    h.require(engine.name == "attackmap.exe" and h.sha(engine) == binding["engine_sha256"] and
              engine_proof_record["sha256"] == binding["engine_build_proof_sha256"], "Retained engine/proof pin mismatch")
    engine_proof = h.read(engine_proof_path)
    h.require(engine_proof.get("exe_sha256") == binding["engine_sha256"], "Retained engine proof identity mismatch")
    wanted = {h.relative_name(row["path"]): row for row in engine_proof.get("payload_files", [])}
    h.require(wanted and len(wanted) == len(engine_proof["payload_files"]) and "attackmap.exe" in wanted and
              "_internal/python313.dll" in wanted, "Complete retained frozen payload proof missing")
    actual = {}
    for directory, names, files in os.walk(engine.parent, followlinks=False):
        for name in names + files:
            h.no_link(Path(directory) / name)
        for name in files:
            path = Path(directory) / name
            relative = path.relative_to(engine.parent).as_posix()
            h.require(relative in wanted and path.stat().st_nlink == 1, "Unexpected/linked retained engine payload")
            actual[relative] = dict(path=relative, size_bytes=path.stat().st_size, sha256=h.sha(path))
    h.require(actual == wanted, "Retained engine payload mismatch")
    release_lock = h.local_path(engine_proof_path.parent / "release-lock.json")
    h.require(h.sha(release_lock) == engine_proof.get("release_lock_sha256"), "Retained engine source-lock identity mismatch")
    h.require(h.record(proof_path) == proof_record and h.record(engine_proof_path) == engine_proof_record, "Build proof changed during validation")
    return dict(scope="Current native source preview with hash-bound retained older frozen engine; no same-source/package acceptance",
                native_build_proof=proof_record, engine_build_proof=engine_proof_record,
                engine_release_lock=h.record(release_lock), payload_files_verified=len(actual), engine=h.record(engine),
                native={name: h.record(app.parent / name) for name in (h.APP_NAME, "AttackMap.NativeSpike.dll")}, **ACCEPTANCE)


def preflight(app, seed, output, case, manifest_sha256=None, release_lock=None, preview_binding=None):
    h.require(case in CASES, "Unknown controlled fault case")
    app, seed, output = map(h.local_path, (app, seed, output))
    h.require(seed.is_file() and isinstance(h.read(seed).get("scan"), dict), "Canonical seed report required")
    h.require(not output.exists() and output.parent.is_dir(), "Use a fresh output under an existing parent")
    package = preview_identity(app, preview_binding) if preview_binding else h.package_identity(app, manifest_sha256, release_lock)
    engine = package["engine"] if preview_binding else h.record(app.parent / "engine/attackmap.exe")
    package_root = app.parent if preview_binding else Path(package["manifest"]["path"]).parent
    for path in (package_root, seed.parent, Path(engine["path"]).parent):
        h.require(not output.is_relative_to(path) and not path.is_relative_to(output), "Output overlaps package or seed")
    return dict(scope=SCOPE, stage="preflight-only", case=case, app=str(app), seed=h.record(seed),
                engine=engine, output=str(output), package=package, preview_binding=preview_binding,
                source=source_identity(), sockets_started=0, processes_started=0, provider_requests_started=0,
                manifest_pin=manifest_sha256, release_lock=str(release_lock) if release_lock else None, **ACCEPTANCE)


class Fixture:
    """One owned HTTP server; no forwarding, auth logging, source body logging or TLS."""
    def __init__(self, root, case, nonce):
        h.require(case in CASES, "Unknown controlled fault case")
        self.root, self.case, self.nonce = Path(root), case, nonce
        self.events, self.lock = [], threading.Lock()
        self.release, self.received = threading.Event(), threading.Event()
        self.closed = False
        owner = self

        class OwnedServer(ThreadingHTTPServer):
            def __init__(self, *args, **kwargs):
                self.connections, self.connection_lock = set(), threading.Lock()
                super().__init__(*args, **kwargs)

            def get_request(self):
                connection, peer = super().get_request()
                connection.settimeout(5)  # Includes the request line and headers.
                with self.connection_lock:
                    self.connections.add(connection)
                return connection, peer

            def shutdown_request(self, connection):
                try:
                    super().shutdown_request(connection)
                finally:
                    with self.connection_lock:
                        self.connections.discard(connection)

            def close_connections(self):
                with self.connection_lock:
                    connections = tuple(self.connections)
                for connection in connections:
                    try:
                        connection.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                    connection.close()

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"

            def log_message(self, *_args):
                pass

            def do_GET(self):
                self.respond(405, b'{"error":"fixture accepts generation POST only"}')

            def do_POST(self):
                if self.path != "/v1/responses":
                    self.respond(404, b'{"error":"unexpected fixture path"}')
                    return
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    h.require(0 < length <= 2 * 1024 * 1024, "Invalid fixture request length")
                    self.connection.settimeout(10)
                    body = json.loads(self.rfile.read(length))
                    h.require(isinstance(body, dict) and body.get("model") == MODEL, "Unexpected fixture model")
                except (ValueError, OSError):
                    self.respond(400, b'{"error":"invalid fixture request"}')
                    return
                # Only retain safe transport metadata. Never persist request bodies,
                # instructions, input/source excerpts, cookies or authorization.
                with owner.lock:
                    number = sum(row["kind"] == "received" for row in owner.events) + 1
                    owner.events.append(dict(kind="received", method="POST", path=self.path,
                                             request_number=number, utc=datetime.now(timezone.utc).isoformat()))
                    if number == 1:
                        publish_marker(owner.root / "received.json", dict(nonce=owner.nonce, endpoint=owner.endpoint,
                               method="POST", path=self.path, model=MODEL))
                    owner.received.set()
                if owner.case == "pending-cancel":
                    until = time.monotonic() + 150
                    while not owner.release.wait(.05) and time.monotonic() < until:
                        marker = owner.root / "release-fixture.json"
                        if marker.exists() and h.read(marker).get("nonce") == owner.nonce:
                            break
                    payload = json.dumps({"id": "fixture-late", "object": "response", "status": "completed", "model": MODEL,
                        "output": [{"type": "message", "id": "fixture-message", "role": "assistant", "status": "completed",
                            "content": [{"type": "output_text", "text": "CONTROLLED FIXTURE ONLY: late cancellation sentinel.", "annotations": []}]}]}).encode()
                    self.respond(200, payload, number)
                elif owner.case == "unavailable":
                    self.respond(503, UNAVAILABLE_BODY, number)
                else:
                    self.respond(200, MALFORMED_BODY, number)

            def respond(self, status, body, number=None):
                delivered = False
                try:
                    self.send_response(status)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.wfile.write(body)
                    self.wfile.flush()
                    delivered = True
                except OSError:
                    pass  # Cancellation may have already closed the client's socket.
                finally:
                    self.close_connection = True
                    with owner.lock:
                        owner.events.append(dict(kind="response", method=self.command, path=self.path if self.path == "/v1/responses" else "unexpected-path",
                            request_number=number, status=status, response_sha256=hashlib.sha256(body).hexdigest(),
                            response_bytes=len(body), write_completed=delivered, utc=datetime.now(timezone.utc).isoformat()))

        reservation = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            if os.name == "nt":
                reservation.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            reservation.bind(("127.0.0.1", 0))
            address, port = reservation.getsockname()
            h.require(address == "127.0.0.1" and port > 1024 and port != 1234, "Fixture must own a private non-1234 loopback port")
            self.endpoint = f"http://127.0.0.1:{port}/v1"
            self.server = OwnedServer((address, port), Handler, bind_and_activate=False)
            self.server.socket.close()
            self.server.socket = reservation
            self.server.server_address = (address, port)
            self.server.daemon_threads = False
            self.server.block_on_close = True
            self.server.server_activate()
            self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": .05},
                                           name="AttackMap-owned-provider-fault", daemon=False)
            self.thread.start()
        except BaseException:
            reservation.close()
            raise

    def close(self):
        if not self.closed:
            self.release.set()
            self.server.shutdown()
            self.thread.join(timeout=10)
            self.server.close_connections()  # Unblock partial headers/bodies and slow clients before joining handlers.
            self.server.server_close()  # Joins every non-daemon request handler.
            h.require(not self.thread.is_alive(), "Owned fixture server thread remains active")
            h.require(not self.server.connections, "Owned fixture connections remain active")
            self.closed = True
        return dict(endpoint=self.endpoint, case=self.case, closed=self.closed,
                    server_thread_joined=not self.thread.is_alive(), handler_threads_joined=True,
                    events=list(self.events), **ACCEPTANCE)


def fixture_config(plan, fixture, nonce):
    root = Path(plan["output"])
    return dict(schema_version=1, scope=SCOPE, execution_scope="source-preview" if plan.get("preview_binding") else "packaged", root=str(root), case=plan["case"], nonce=nonce,
                endpoint=fixture.endpoint, engine=plan["engine"]["path"], engine_sha256=plan["engine"]["sha256"],
                seed=plan["seed"]["path"], seed_sha256=plan["seed"]["sha256"],
                fixture_sha256=hashlib.sha256(APP_SOURCE.encode()).hexdigest())


def checked_record(value, root):
    path = h.local_path(value["path"])
    h.require(path.is_relative_to(root), "Native evidence escaped the owned root")
    h.require(h.sha(path) == value["sha256"], "Native artifact hash mismatch")
    return path


def collect(plan, config, transport):
    """Strict negative-result gate; fixture metadata never enters live evidence."""
    root = h.local_path(plan["output"])
    proof = h.read(root / "native-proof.json")
    h.require(proof.get("scope") == SCOPE and proof.get("case") == plan["case"] and
              proof.get("nonce") == config["nonce"] and proof.get("endpoint") == config["endpoint"], "Native proof identity mismatch")
    h.require(proof.get("failure") is None and proof.get("personalSettingsRead") is False, "Native fixture journey failed or settings isolation missing")
    expected = {"nativeTerminal", "cleanupRestoresAdmission", "seedAndEngineUnchanged", "baselineBytesUnchanged"}
    if plan["case"] == "pending-cancel":
        expected |= {"cancelledAfterObservedPost", "previousSelectionPreserved"}
    else:
        expected |= {"deterministicGenerationPublished", "newGenerationBound", "reportsShowsUnavailable", "selectedExportMatches"}
    checks = proof.get("checks")
    h.require(isinstance(checks, dict) and set(checks) == expected and all(value is True for value in checks.values()), "Native negative checks incomplete")
    process = h.read(root / "process.json")
    h.require(process.get("exited") is True and process.get("exit_code") == 0 and process.get("timed_out") is False and
              process.get("owned_job_assigned") is True and process.get("owned_tree_cleanup_verified") is True, "Owned native process cleanup unverified")
    h.require(transport.get("closed") is True and transport.get("server_thread_joined") is True and
              transport.get("handler_threads_joined") is True and transport.get("endpoint") == config["endpoint"], "Owned fixture cleanup unverified")
    received = [row for row in transport["events"] if row.get("kind") == "received"]
    responses = [row for row in transport["events"] if row.get("kind") == "response"]
    h.require(len(received) == 1 and received[0].get("method") == "POST" and received[0].get("path") == "/v1/responses" and
              received[0].get("request_number") == 1, "Require exactly one observed generation POST; reservations are not HTTP counts")
    h.require(len(responses) == 1 and responses[0].get("status") == (503 if plan["case"] == "unavailable" else 200) and
              responses[0].get("method") == "POST" and responses[0].get("path") == "/v1/responses" and
              responses[0].get("request_number") == received[0]["request_number"], "Unexpected or uncorrelated fixture response")
    if plan["case"] != "pending-cancel":
        h.require(responses[0].get("write_completed") is True, "Malformed/unavailable HTTP response was not written")
        expected_body = UNAVAILABLE_BODY if plan["case"] == "unavailable" else MALFORMED_BODY
        h.require(responses[0].get("response_sha256") == hashlib.sha256(expected_body).hexdigest() and
                  responses[0].get("response_bytes") == len(expected_body), "Fixture response body identity mismatch")
    request = h.read(root / "fault-reports/native-request.json")
    options, provider = request.get("options", {}), request.get("options", {}).get("provider", {})
    h.require(request.get("repository_path") == str(root / "fixture-repository") and request.get("output_path") == str(root / "fault-reports") and
              request.get("modules") == ["python-web", "config"], "Native request fixture/output/analyzer binding mismatch")
    h.require(provider == dict(enable_ai=True, provider="openai", endpoint=config["endpoint"], model=MODEL,
              max_calls=1, timeout_seconds=30, output_token_limit=32000, mode="review", speed="standard", backend="api") and options.get("timeout_seconds") == 120,
              "Emitted controlled provider configuration mismatch")
    baseline, selected = proof["baseline"], proof["selected"]
    before, after = checked_record(baseline, root), checked_record(selected, root)
    for captured in (baseline, selected):
        checked_record(dict(path=captured["artifactManifestPath"], sha256=captured["artifactManifestSha256"]), root)
    h.require(h.record(Path(plan["seed"]["path"])) == plan["seed"] and h.record(Path(plan["engine"]["path"])) == plan["engine"], "Seed/engine changed")
    baseline_request = h.read(root / "baseline-reports/native-request.json")
    h.require(baseline_request.get("repository_path") == request.get("repository_path") and baseline_request.get("modules") == request.get("modules") and
              baseline_request.get("options", {}).get("provider", {}).get("enable_ai") is False, "Matched AI-off native baseline missing")
    baseline_report, selected_report = h.read(before), h.read(after)
    h.require(isinstance(baseline_report.get("findings"), list) and baseline_report["findings"] == selected_report.get("findings"), "Deterministic findings changed")
    manifest = None
    if plan["case"] == "pending-cancel":
        h.require(baseline == selected and proof.get("progressState") == "cancelled" and proof.get("cancelRequestedAfterHttp") is True, "Previous report was not retained after cancellation")
        h.require(h.read(root / "release-fixture.json").get("nonce") == config["nonce"], "Native cancellation release marker missing")
        # The engine keeps diagnostic/partial files in flat per-run directories.
        # Publication is committed only by this actual atomic current pointer.
        h.require(not (root / "fault-reports/current-generation.json").exists(), "Cancelled fixture scan published a generation")
    else:
        h.require(before != after and proof.get("aiState") == "unavailable", "New deterministic generation/AI unavailable view missing")
        manifest_path = h.local_path(after.parent / "run-manifest.json")
        manifest = h.read(manifest_path)
        ai = manifest.get("desktop_ai", {})
        allowance = ai.get("allowance") or {}
        h.require(ai.get("mode") == "review" and ai.get("status") == "unavailable" and ai.get("model_output_available") is False,
                  "Provider failure was incorrectly claimed as model completion")
        h.require(allowance.get("calls_reserved") == 1 and allowance.get("max_calls") == 1 and
                  allowance.get("unknown_output_usage_calls") == 1 and allowance.get("usage_status") == "partial_or_unknown", "Failed usage must remain unknown")
        h.require(h.sha(root / "selected-report-export.json") == selected["sha256"], "Selected exported bytes changed")
    return dict(passed=True, scope=SCOPE, case=plan["case"], endpoint=config["endpoint"],
                observed_fixture_generation_posts=len(received), http_status=responses[0]["status"],
                native_proof=h.record(root / "native-proof.json"), request=h.record(root / "fault-reports/native-request.json"),
                process=h.record(root / "process.json"), baseline=baseline, selected=selected,
                findings_equal=True, manifest=h.record(after.parent / "run-manifest.json") if manifest else None,
                transport=h.record(root / "fixture-transport.json"), source=source_identity(), **ACCEPTANCE)


def run(plan):
    h.require(os.name == "nt", "Native run requires Windows")
    h.require(plan.get("manifest_pin") or plan.get("preview_binding"), "--run requires reviewed package or explicit source-preview proof pins")
    # Revalidate just before opening any socket or creating any output.
    current = preflight(plan["app"], plan["seed"]["path"], plan["output"], plan["case"], plan["manifest_pin"], plan["release_lock"], plan.get("preview_binding"))
    h.require(current == plan, "Preflight/source/package input changed")
    root = Path(plan["output"])
    root.mkdir()
    h.save(root / "preflight.json", plan)
    repository = root / "fixture-repository"
    repository.mkdir()
    (repository / "app.py").write_bytes(APP_SOURCE.encode())
    (repository / "config.yaml").write_bytes(b"debug: true\nhost: 127.0.0.1\n")
    fixture_before = {path.name: h.sha(path) for path in repository.iterdir()}
    environment = h.child_environment(root)
    nonce = uuid.uuid4().hex
    fixture = Fixture(root, plan["case"], nonce)
    try:
        config = fixture_config(plan, fixture, nonce)
        h.save(root / "fixture-owner.json", dict(nonce=nonce, endpoint=fixture.endpoint, scope=SCOPE))
        h.save(root / "fault-config.json", config)
        h.launch([plan["app"], "--provider-fault-smoke", str(root / "fault-config.json")], root, environment, 360)
    finally:
        transport = fixture.close()
        h.save(root / "fixture-transport.json", transport)
    identity = preview_identity(Path(plan["app"]), plan["preview_binding"]) if plan.get("preview_binding") else h.package_identity(Path(plan["app"]), plan["manifest_pin"], plan["release_lock"])
    h.require(identity == plan["package"] and
              source_identity() == plan["source"], "Package/source changed during fault journey")
    h.require({path.name: h.sha(path) for path in repository.iterdir()} == fixture_before, "Owned scan fixture changed")
    result = collect(plan, config, transport)
    h.save(root / "summary.json", result)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("app", "seed", "output", "case"):
        parser.add_argument("--" + name, required=True, **({"choices": CASES} if name == "case" else {}))
    parser.add_argument("--manifest-sha256")
    parser.add_argument("--release-lock")
    parser.add_argument("--source-preview", action="store_true", help="Current native publish plus explicitly pinned retained older engine; no package acceptance")
    for name in ("native-build-proof", "native-build-proof-sha256", "engine", "engine-sha256", "engine-build-proof", "engine-build-proof-sha256"):
        parser.add_argument("--" + name)
    parser.add_argument("--run", action="store_true", help="Explicitly launch native app + owned HTTP fault fixture; never a real model")
    args = parser.parse_args(argv)
    keys = ("native_build_proof", "native_build_proof_sha256", "engine", "engine_sha256", "engine_build_proof", "engine_build_proof_sha256")
    binding = {key: getattr(args, key) for key in keys}
    if args.source_preview:
        h.require(all(binding.values()) and not args.manifest_sha256 and not args.release_lock, "Source preview requires explicit native/engine proof pins and no package flags")
    else:
        h.require(not any(binding.values()), "Preview binding flags require --source-preview")
    plan = preflight(args.app, args.seed, args.output, args.case, args.manifest_sha256, args.release_lock, binding if args.source_preview else None)
    print(json.dumps(run(plan) if args.run else plan, indent=2))


if __name__ == "__main__":
    main()
