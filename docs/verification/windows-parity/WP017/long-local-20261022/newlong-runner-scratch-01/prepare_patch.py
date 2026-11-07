"""Prepare only scratch copies and a reviewable patch; never import or run them."""
import ast
import difflib
import hashlib
import json
from pathlib import Path

ROOT = Path.cwd().resolve()
OUT = Path(__file__).resolve().parent
FILES = ["tools/run_wp017_native_modes.py", "tools/verify_wp017_live.py",
         "tests/test_wp017_native_runner.py", "tools/test_verify_wp017_live.py"]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def replace(text, old, new):
    assert old in text, old
    return text.replace(old, new)


original = {name: (ROOT / name).read_bytes() for name in FILES}
texts = {name: data.decode("utf-8").replace("\r\n", "\n") for name, data in original.items()}
runner = texts[FILES[0]]
runner = replace(runner, '1 <= provider <= 3600, "Provider timeout must be 1..3600 whole seconds"',
                 '1 <= provider <= 7200, "Provider timeout must be 1..7200 whole seconds"')
runner = replace(runner, '1 <= process <= 7200, "Process timeout must be 1..7200 whole seconds"',
                 '1 <= process <= 10800, "Process timeout must be 1..10800 whole seconds"')
runner = replace(runner, '    require(provider <= scan < process, "Timeouts require provider <= scan < process")',
'''    require(provider <= 3600 or gate.ENDPOINT == "http://127.0.0.1:1234/v1",
            "Extended AI allowance requires the fixed loopback endpoint")
    require(provider <= scan < process, "Timeouts require provider <= scan < process")''')
runner = replace(runner, 'QA AI allowance in seconds, 1..3600 (default 900)',
                 'QA total AI allowance for the fixed loopback target, 1..7200 seconds (default 900)')
runner = replace(runner, 'at most 7200 seconds; provider <= scan < process (default 1500)',
                 'at most 10800 seconds; provider <= scan < process (default 1500)')
texts[FILES[0]] = runner

verifier = texts[FILES[1]]
verifier = replace(verifier, '1 <= provider_timeout <= 3600 and 1 <= scan_timeout <= 86400',
                   '1 <= provider_timeout <= 7200 and 1 <= scan_timeout <= 86400')
verifier = replace(verifier, 'provider_timeout <= scan_timeout < harness_timeout <= 7200',
                   'provider_timeout <= scan_timeout < harness_timeout <= 10800')
texts[FILES[1]] = verifier

tests = texts[FILES[2]]
tests = replace(tests, '(3601, 4200, 4500)', '(7201, 7800, 8100)')
tests = replace(tests, '(900, 1200, 7201)', '(900, 1200, 10801)')
tests = replace(tests, '(900, 1200, "4500")):', '(900, 1200, "4500"), (7200.0, 7800, 8100),\n                       (7200, 7800, 8100.0), (7200, 7199, 8100), (7200, 7800, 7800)):')
tests = replace(tests, '((900, 1200, 1500), (3600, 4200, 4500)):',
                 '((900, 1200, 1500), (3600, 4200, 4500), (7200, 7800, 8100)):')
start = tests.index('    def test_long_timeout_preflight_is_explicit_and_inert(self):')
end = tests.index('    def test_invalid_timeout_triplets', start)
extended_preflight = tests[start:end].replace('test_long_timeout_preflight_', 'test_extended_local_timeout_preflight_')
extended_preflight = extended_preflight.replace('3600', '7200').replace('4200', '7800').replace('4500', '8100')
start = tests.index('    def test_long_timeout_run_preserves_exact_argv_launcher_and_saved_budget(self):')
end = tests.index('    def test_run_rejects_conflicting_override', start)
extended_run = tests[start:end].replace('test_long_timeout_run_', 'test_extended_local_timeout_run_')
extended_run = extended_run.replace('3600', '7200').replace('4200', '7800').replace('4500', '8100')
extra = '''    def test_extended_local_timeout_bounds_and_fixed_target(self):
        self.assertEqual(runner.timeout_budget(7200, 7200, 7201)["provider_timeout_seconds"], 7200)
        self.assertEqual(runner.timeout_budget(7200, 10799, 10800)["harness_timeout_seconds"], 10800)
        for endpoint in ("https://api.openai.com/v1", "https://127.0.0.1:1234/v1",
                         "http://127.0.0.1.evil.invalid:1234/v1"):
            with self.subTest(endpoint=endpoint), patch.object(runner.gate, "ENDPOINT", endpoint), \\
                 patch.object(runner, "local_path") as paths:
                with self.assertRaisesRegex(ValueError, "fixed loopback endpoint"):
                    self.plan(provider_timeout=7200, scan_timeout=7800, process_timeout=8100)
                paths.assert_not_called()

'''
tests = replace(tests, '    def test_run_without_reviewed_pin_cannot_launch(self):',
                 extended_preflight + extended_run + extra + '    def test_run_without_reviewed_pin_cannot_launch(self):')
texts[FILES[2]] = tests

tests = texts[FILES[3]]
tests = replace(tests, '((900, 1200, 1500), (3600, 4200, 4500), (3600, 3600, 3601)):',
                 '((900, 1200, 1500), (3600, 4200, 4500), (3600, 3600, 3601),\n                        (7200, 7800, 8100), (7200, 7200, 7201), (7200, 10799, 10800)):')
tests = replace(tests, '"provider_timeout_seconds": 3601', '"provider_timeout_seconds": 7201')
tests = replace(tests, '"harness_timeout_seconds": 7201', '"harness_timeout_seconds": 10801')
start = tests.index('    def test_each_bound_timeout_source_must_match(self):')
end = tests.index('    def test_malformed_collector_budgets_fail_closed(self):', start)
extended_provenance = tests[start:end].replace('test_each_bound_timeout_source_must_match',
                                             'test_extended_each_bound_timeout_source_must_match')
extended_provenance = extended_provenance.replace('self.budget_evidence()', 'self.budget_evidence(7200, 7800, 8100)')
extended_provenance = extended_provenance.replace('3600.0', '7200.0').replace('4500.0', '8100.0')
extra = '''    def test_extended_budget_cannot_promote_legacy_or_remote_evidence(self):
        self.evidence["emitted_provider"]["timeout_seconds"] = 7200
        self.evidence["request"] = self.file("request.json", {"provider": self.evidence["emitted_provider"]})
        self.assertFalse(verify(self.evidence, self.base)["passed"])
        self.budget_evidence(7200, 7800, 8100)
        self.evidence["emitted_provider"]["endpoint"] = "https://api.openai.com/v1"
        self.evidence["request"] = self.file("request.json", {"options": {
            "provider": self.evidence["emitted_provider"], "timeout_seconds": 7800}})
        result = verify(self.evidence, self.base)
        self.assertFalse(result["passed"])
        self.assertIn("provider setting mismatch: endpoint", result["failures"])

'''
tests = replace(tests, '    def test_reservations_do_not_prove_http_responses(self):',
                 extended_provenance + extra + '    def test_reservations_do_not_prove_http_responses(self):')
texts[FILES[3]] = tests

patches, pins = [], {}
for name in FILES:
    ast.parse(texts[name], filename=name)  # Static syntax only, no imports/test execution.
    before, after = OUT / "before" / name, OUT / "after" / name
    before.parent.mkdir(parents=True, exist_ok=True)
    after.parent.mkdir(parents=True, exist_ok=True)
    with before.open("xb") as stream:
        stream.write(original[name])
    proposed = texts[name].replace("\n", "\r\n") if b"\r\n" in original[name] else texts[name]
    proposed_bytes = proposed.encode("utf-8")
    with after.open("xb") as stream:
        stream.write(proposed_bytes)
    patches.append("diff --git a/" + name + " b/" + name + "\n")
    patches.extend(difflib.unified_diff(original[name].decode("utf-8").replace("\r\n", "\n").splitlines(True),
                   texts[name].splitlines(True), fromfile="a/" + name, tofile="b/" + name))
    pins[name] = dict(source_before_sha256=sha(original[name]),
                      source_after_sha256=sha((ROOT / name).read_bytes()), proposed_sha256=sha(proposed_bytes))
    assert pins[name]["source_before_sha256"] == pins[name]["source_after_sha256"]
patch = OUT.parent / "newlong-budget-runner.patch"
with patch.open("x", encoding="utf-8", newline="\n") as stream:
    stream.write("".join(patches))
proof = dict(scope="scratch-copy patch preparation only; not applied or tested", source_files_unchanged=True,
             static_ast_parse=True, tests_executed=False, gui_provider_build_executed=False,
             patch_sha256=sha(patch.read_bytes()), files=pins)
with (OUT / "preparation-proof.json").open("x", encoding="utf-8") as stream:
    json.dump(proof, stream, indent=2)
print(json.dumps(proof, indent=2))
