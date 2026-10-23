# Independent timeout repair review — 2026-10-22

Verdict: **CLEAR for the scoped timeout repair. No blocking source defect found.** This closes this independent source-review step only. WP017 live five-mode completion, a fresh source-bound native/frozen candidate, GUI review, and release acceptance remain open.

Reviewer: independent Sol agent. Reviewed the current working-tree diff and relevant current implementations, after reading AGENTS.md and the active docs index and using CodeGraph first. No source edits, builds, tests, model calls, GUI launch, or old evidence changes were performed in this review. The only authored artifact is this review.

## Findings

- `llm_review.py` permits a ceiling of 3600 seconds only for an HTTP literal loopback/localhost endpoint with an existing allowance, no URL credentials, and a valid nonzero port when specified. Remote, HTTPS-local, deceptive hostname, invalid-port, and unbudgeted paths retain the 900-second ceiling/default deadline. An injected client's actual endpoint takes precedence over the ambient environment.
- `_provider_timeout` bounds each constructor/options/request timeout by both the inherited reservation and the ledger's remaining time. The repair does not create or reset a longer ledger. Construction and option setup consume the same deadline. Retry settings remain zero; token and call accounting are unchanged.
- `hunt_harness.py` raises only its reservation ceiling to 3600. Its implicit ledger remains 900 seconds. Generation and all planned verification passes use the same ledger; remote adapters still cap requests at 900. Jury counts, abstention behavior, output tokens, and pass coverage are unchanged by this diff.
- Native QA parsing retains defaults 900/1200/1500 and accepts explicit 3600/4200/4500. It requires whole seconds, provider 1..3600, product scan validation 1..86400, and provider <= scan < harness <= 7200. Duplicate, equals-form, missing, fractional, overflowing, and out-of-order inputs are rejected. The native smoke uses the values in its serialized request and emits `timeoutBudget`; the single-watch path restores the requested scan allowance before a following native scan.
- The runner validates the triplet before preflight I/O/output creation, passes the exact native flags, records the actual launcher timeout, and requires matching native/request/process values. Existing profile and RequiredBundled provenance changes in the working diff remain preserved; no attribution of those unrelated edits is made here.
- The offline verifier requires exact integer values and hash-bound preflight/process proof for the new provenance path. It checks bounds/order, emitted scan/provider values, native values, actual launcher timeout, successful exit, and owned-tree cleanup. The earlier `3600.0 == 3600` provider-request gap is closed by explicit type checks and a focused negative test. Legacy evidence retains the historical 900-second gate; it cannot establish a 3600-second run.

The timeout supplied to the SDK is an SDK/transport operation timeout. It is **not** a newly implemented hard global wall-clock cutoff for an in-flight request. The ledger blocks late dispatches and shrinks subsequent calls; native scan and owned harness process deadlines provide separate outer limits. Nothing in this review promises model completion within the AI allowance.

## Retained verification checked

- `core/result.json` and `core/focused-02.xml`: 135 tests, zero failures/errors/skips (25 new timeout cases plus 110 existing regressions). These are offline fake-clock/fake-SDK checks. All six `tested_inputs` SHA-256 values matched the current files during review.
- `native/README.md`, `native-build.log`, `native-tests.log`, and `python-tests-retry.log`: console build succeeded with zero warnings/errors; 69 native assertions passed; 47 focused Python tests passed. The initial sandbox ACL failure remains separately recorded and is not counted as PASS. The owned harmless process check is not provider/model integration.
- Every file entry in `native/source-and-proof-hashes.json`, including source files, retained logs, and the console test DLL, matched its recorded SHA-256 during review.

No new runtime evidence was produced. The full WinUI application and frozen engine must be rebuilt from the reviewed sources before a new pinned candidate/live campaign. Captures and completed local HTTP responses must come from that new candidate; fixture results cannot substitute for them.

## Pinned reviewed source SHA-256

The table below records on-disk bytes at review time. A later source change invalidates this verdict for the changed file and requires a focused follow-up review.

| File | SHA-256 |
| --- | --- |
| src/attackmap/llm_review.py | c0bdf059eea8a76befcb7a2c05a2349a99f2bcc10619ee4c6e6866c1bb2bde7e |
| src/attackmap/hunt_harness.py | ceede0a0f80ca6e7e5b1c04d98ea1ffdfe2915b258d7d8bb3cb805917de160f9 |
| src/attackmap/ai_budget.py | 98527c906c139a6211a8e6b0bec353ca4a09032ba3625f59113767509ca08f28 |
| tests/test_local_provider_timeouts.py | ef74f01083aba50ee4c2d69e3d7b9e8847e2502ffcaaedf50407cb594cf1da75 |
| tests/test_ai_budget.py | 692e7fdc70610e762516a9608dc5ec577173de1d6062cffb6a46f8d1b9655c8d |
| tests/test_llm_review.py | 91b424f802cff79e6a2a9572baa0d0fbaaa2b0d79b260c989f5be6dede8232b2 |
| tests/test_hunt_harness.py | 5dfcd4c40218d9b371b034f2e0425b7d826d74d6c4e285cd68d649ce0fe88477 |
| desktop/windows/AttackMap.NativeSpike/MainWindow.ParitySmoke.cs | 0a6de2d0351e3390bd9123ddb016edbdffe324454ee3148bea894adebd210bd7 |
| desktop/windows/AttackMap.NativeSpike/ParitySmokeTimeouts.cs | c428d3081f0ae8d442302948078289bec38a61f09cec8690ae59d78a16546bc1 |
| desktop/windows/NativeAiOptions.Tests/NativeAiOptions.Tests.csproj | 46a592d07e8e6e916e6209d89720e6053ba9f267c5b2f3f00180129625fd5605 |
| desktop/windows/NativeAiOptions.Tests/Program.cs | ad0765e09773fbb1c4d772dd5038d3ff23fc9882c3181b0ae575d20f68709bd2 |
| tools/run_wp017_native_modes.py | da2d34c55ad4237ac1a1b586ab59cfd13d056073d657ead75ebfe92758199fcc |
| tests/test_wp017_native_runner.py | e209c2069001cc330acea867d1015c74c2bbb6e0821c6298fd447d854b7163a7 |
| tools/verify_wp017_live.py | d921acd61a5c5f81e717db8e63d9231cc9bc3c5b5cf105d18227979808cfad72 |
| tools/test_verify_wp017_live.py | e671bf44253b21c497053b40fff3f7519f4435dd381a9b415ad10b331134f532 |

## Separate installed-candidate helper follow-up

Verdict: **CLEAR for a new explicit-engine developer-host installation/scan attempt.** Independently read the new evidence-only `docs/verification/windows-parity/WP024/astra-long-local-20261022/verify_installed_candidate.py`; SHA-256 `1692d9c7b072f3b453f962954483a5dc49e44564a637fa2fdd0df470f5667a32` matched its owner's final ready pin. No helper execution was performed here.

The helper now requires caller-supplied native build proof, reviewed engine SHA-256, and its own reviewed SHA-256, rather than retaining the former candidate's engine pin. It binds the package manifest/source lock, native EXE/DLL and linked input hashes; requires fresh, disjoint workspace installation/evidence roots; verifies the installed inventory and atomic generation artifacts; and checks installed/source payload stability afterwards. The installer and native journey use owned process cleanup. The actual native scan explicitly selects the installed bundled engine with AI/CVE disabled.

Its claims correctly exclude automatic normal-startup engine discovery, private Windows profile acceptance, human GUI/accessibility, clean-host installation, signing, and release acceptance. These remain separate gates. This helper review does not expand the product timeout repair verdict or authorize any historical evidence rewrite.
