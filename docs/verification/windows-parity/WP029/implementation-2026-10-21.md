# WP029 local CI preparation — 2026-10-21

Status: IMPLEMENTATION PREPARED / actual CI and Swift/frozen gates OPEN. No remote run, push, publication or platform acceptance is claimed.

Before this patch, client-contract-fixtures.yml ran Python adapters on Ubuntu only. The existing main CI runs Python across three OSes and a frozen Windows smoke job, but Python running on macOS does not exercise the Swift consumer. The dated audit identifies no newer run-envelope/current-generation adapter in the examined Mac app. WP028's actual Mac consumer implementation remains a dependency; a generic `swift test` cannot substitute for a known fixture target.

## Changes

The named workflow now runs on every main PR/push (no path-filter absence for required checks), checking out exactly github.sha. Existing Python shared contract suites remain, including previous/current and incompatible schema fixtures. A Windows job compiles/runs the actual EngineProtocol.cs and ReportAdapter.cs source consumers through their existing console harnesses. Linux has explicit Node, PHP and Python extraction jobs plus existing expected-signal/negative-control suites. Required registered base/overlay analyzers must detect their assigned fixture and emit structured signals; missing registration, inapplicable fixture, errors or empty output fail. The corpus job runs the existing evaluation harness and retains every metric; scan failure cannot become a clean negative. It does not enforce invented maturity thresholds or change labels/holdout.

tools/ci_contract_evidence.py binds evidence to GitHub run/attempt, core checkout revision, exact raw source/schema/fixture/corpus/consumer/helper/test hashes, Python/platform and installed package versions/direct-URL metadata. Cache is dependency-only pip keyed on pyproject.toml; extraction/evaluation results are never reused from cache. Artifact names contain github.sha and run attempt. Artifacts fail if absent; native logs and Python JUnit are retained. Source/frozen equivalence is not inferred from matching source hashes.

Root review hardening: actual CLI execution now rejects preloaded core modules (fresh process required), checks core package/submodule import paths against the exact checkout's src/attackmap both before/after execution, compares the full input inventory before/after, and refuses evidence output inside input scope. A foreign PYTHONPATH snapshot cannot borrow the current checkout's identity. Negative tests cover foreign/preloaded core, output scope and input mutation with no evidence publication. These checks do not authenticate Python bytecode or malicious same-user imports; they prevent accidental stale/foreign local-environment evidence. Earlier raw extraction remains its recorded checkpoint; no full matrix was repeated to prove the helper change.

Final helper hardening verification:10focused helper/workflow cases passed in the combined30-case fleet/helper run (67.16s total). Identity-only rerun passed after those changes, with input digest `ff200f129c0f8e979731e8b47477bbcc0c4ebaf565c4f8349f4ce5a1cec97496`; see local-identity.json. Actual extraction/corpus CI was not rerun for this change.

No core, native source, corpus, pyproject or release-hashed tooling was edited. After explicit root release, the three small fixture extraction checks ran serially in one process while the WP03410k campaign remained active. Corpus evaluation, fullscan, C# builds and remoteCI were not run. Workflow validation and local extraction are not completed CI evidence.

## Verification and remaining commands

Local helper tests: `.venv/Scripts/python.exe -m pytest docs/verification/windows-parity/WP029/test_ci_contract_evidence.py -q --tb=short -p no:cacheprovider --basetemp .tmp-wp029-helper-final-20261021`: **7 PASS in2.17s**, including final workflow structure. Initial restricted temp-ACL failures were environmental; approved retry passed. Identity-only mode ran successfully and wrote local-identity.json; it performs no analyzer scan. Identity was regenerated after final helper/workflow edits. No workflow job itself ran.

The equivalent standalone fixture commands are below; the actual recorded run used one process for all three groups, the prepared `.tools/wp024-freeze-venv/Scripts/python.exe`, PYTHONPATH=repo/src, exact21discovered modules and asserted unchanged src/attackmap+pyproject raw-byte inventory before/after. See `actual-three-fixtures-2026-10-21.json` for raw models, versions, scope and input identities. All seven required base/overlay analyzers detected their assigned fixture and emitted nonempty structured signals: Node base1route/overlay7routes; PHP base12entrypoints, Laminas4routes, Omeka4routes; Python base8routes/overlay10routes. Concurrent WP034 load makes this unsuitable for speed or memory comparisons. Expected-signal full suites and corpus were not run in this checkpoint.

Standalone prepared commands (corpus remains queued until separately released):

```powershell
foreach ($group in 'node','php','python') {
  .venv/Scripts/python.exe tools/ci_contract_evidence.py --mode analyzers --group $group --output ".tmp-wp029/$group.json"
  if ($LASTEXITCODE -ne 0) { throw "Analyzer fixture failed: $group" }
}
.venv/Scripts/python.exe tools/ci_contract_evidence.py --mode corpus --output .tmp-wp029/corpus.json
```

Proposed required check names (repository owner must configure and verify branch protection): `Python shared contract consumer`, `Windows CSharp source contract consumer`, all three `Linux applicable analyzer fixture (...)`, `Linux seed corpus raw evaluation`. A green seed evaluation only proves scans executed and metrics exist; corpus remains below WP030 maturity and awaits independent human label review.

## External gates before WP029 completion

* Completed CI URLs for actual Python, Windows C# and Swift consumers at the same pinned fixture/core revision, and an approved immutable Mac revision. The audit's Mac5f2e8b4d84f9dff06e0f87c69c861a434981bd6a is only an inspected historical candidate; do not silently treat it as an implemented consumer or newer acceptance.
* WP028 owner identifies/adds the real Swift fixture target, exact command and input mechanism in the Mac repository. Checkout core/fixtures at the chosen40-character SHA and Mac at its approved40-character SHA; hash the same fixture inventory; pass that absolute fixture path into the actual target. Record xcodebuild/swift version, command, emitted evidence and CI URL. No known target/adapter means gate unavailable, not skipped PASS. No invented Mac workflow was added here.
* Deliberate broken-consumer experiment: in an isolated throwaway CI branch change one required current fixture's schema major to an incompatible value while retaining its acceptance expectation. Python and C#/Swift jobs must fail. Restore the exact committed fixture and show green runs. Expected rejection fixtures alone prove reader rejection, not that a broken accepted fixture blocks all consumers. No shared fixtures were mutated in this patch.
* Source/frozen artifact qualification: run the same pinned fixture acceptance/rejection matrix against the actual WP024 frozen engine and installed native consumer, record executable/package hashes and compare semantic outcomes to source results. Existing main CI smoke is insufficient proof of identical fixture matrix; prepare that integration after stable engine/package lease.

Actual remote execution and repository required-check settings are intentionally not changed by local preparation. WP029 stays open until those gates have evidence.
