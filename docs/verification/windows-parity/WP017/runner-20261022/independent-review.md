# WP017 runner independent review — 2026-10-22

Verdict: **no actionable blockers found** in the reviewed preparation runner and focused tests. The default preflight is read-only; explicit execution requires a reviewed portable-manifest pin. The runner consistently keeps `accepted_wp017`, `accepted_manual_ui`, `accepted_same_source`, `accepted_release` and `accepted_clean_host` false. Five real native AI modes have not been run by this preparation or review, and WP017 acceptance remains open.

Reviewer: `/root/ultra_taint_review`. Base: `18fc9b2ae711bf0b39d93c996ae2ab220cc9a82d`. Only this review document was written. No tests, native application, process fixtures, model request, build, package or background workload was launched by this reviewer. CodeGraph was used before source lookup; final changed source and test hashes were checked directly after the owner's error-mode adjustment.

## Reviewed behavior

| Area | Source and assessment |
| --- | --- |
| No launch/HTTP without `--run` | `tools/run_wp017_native_modes.py:475-488` selects `preflight` unless `--run` is present and requires the pin before calling `run`. Preflight reads input/package files and returns a plan without creating its output directory. `check_local_model`, `child_environment` and `launch` are reachable through explicit execution only. Imports of the existing offline verifier introduce no HTTP or process dispatch. |
| Actual package pin versus current-source acceptance | `package_identity` at line 112 hashes the selected app folder's `portable-manifest.json`, checks an optional exact lowercase SHA256 pin, inventories every payload file, and returns an explicitly byte-consistency-only proof. `run` rechecks the complete package before each mode and after native exit. It does not turn historical package labels or a passing byte inventory into a fresh-source proof. Every summary/verification result retains the false acceptance fields. |
| Windows paths and exact manifest inventory | `local_path` rejects UNC/device/network roots, relative/traversal/reserved components, reparse points and links; Windows paths must be on a fixed local drive. Portable entries require canonical forward-slash relative names, unique JSON keys, no case aliases, exact actual inventory spelling, no unexpected files/directories, single-link payload files, and matching sizes/hashes. Required marker presence alone is case-insensitive, allowing the real `Microsoft.ui.xaml.dll`; the inventory still matches its actual spelling exactly. This resolves the initial required-marker casing failure without weakening byte checks. |
| Existing native defaults | The runner passes the existing `--parity-smoke`, explicit packaged `--engine`, native scan, fixed Juice Shop repository and mode arguments. The existing `MainWindow.ParitySmoke.cs:57-66` and `ProviderConfiguration.cs` retain the original native settings: loopback endpoint, exact CyberStag model, API/standard, 8 calls, 900 provider seconds, 32,000 output tokens and 1,200 scan seconds. The collector compares the actual emitted request to those values. No native/provider source was changed by the runner patch. |
| Isolated environment and local transport | `child_environment` at line 181 uses an OS allowlist and a Windows/System32-only PATH, with mode-local AppData/profile/temp directories. Ambient provider, endpoint, Python, proxy and QA settings are omitted; a fresh per-mode audit nonce is added explicitly. `check_local_model` at line 203 uses only the fixed loopback `/models` URL, disables inherited proxies and rejects redirects. Its GET proves model listing, not a generated response. Completion is separately checked through the existing audited transport gate. |
| Suspended process ownership | `launch` at line 327 creates the app suspended, assigns its exact process handle to a kill-on-close Windows Job, then resumes the one owned primary thread. This prevents child work before ownership. No process-name kill is used. The unassigned failure fallback targets only that owned PID tree and cannot claim successful Job cleanup. |
| Error mode and cleanup | `inherited_error_mode` at line 315 sets `0x8003` only around suspended `Popen` and restores the prior parent mode in `finally`, before Job assignment and also when creation fails. Normal exit/timeout cleanup terminates remaining owned Job processes, requires zero active processes, waits for the child and records exit/timeout/ownership status. Cleanup failure or nonzero exit cannot pass, and later modes stop. Job closure provides the final kill-on-close fallback. |
| Run/generation/artifact/export binding | `collect` at line 372 requires the requested completed visible mode; matching request run, repository, output and provider configuration; a report in the fresh reports root whose parent is the displayed run and whose hash matches the smoke result; the same generation ID and succeeded artifact manifest; checksum/size verification of every listed section/export; and membership of the selected report, artifact, metadata and run manifest. The displayed artifact must be the expected mode file in that generation, with a bound hash; its export must be the expected mode-root path and byte-equal through the offline gate. The PNG signature, capture path/hash and per-mode nonce-bound transport logs are also checked. |

The offline gate additionally requires completed nonempty generated output, matching request mode/model/budgets, successful run metadata, paired request/HTTP/completion observations, response/output hashes and export equality. These are local evidence-consistency checks, not proof that model claims are correct or that a human reviewed the native screen. A capture remains visual-review material, and the runner never grants manual UI acceptance.

## Evidence inspected

- Final runner SHA256: `f0b6df2edafb9b752a799635f141ce8030302b95b16d3e11a0a584f54b5b7f8c`.
- Final focused test SHA256: `5cd815833bcf51d0cc2ab72e8e295a95676553b81a290c3aab628e8d65acd219`.
- `focused-tests.xml` SHA256: `882f8a0c297dd1be40edc8c1cc46caa40a4290ad8c7e0c6271e33539c1a3cc2b`. It has 50 JUnit entries with no failures, errors or skips: **30 tests plus 20 subtests**, not 50 distinct test functions. The retained terminal log reports `30 passed, 20 subtests passed in 2.22s`, exit 0. This includes 20 runner tests and 10 existing offline verifier tests.
- Reviewed the test bodies, including default no-launch/no-HTTP/no-output behavior; missing/stale pins; synthetic payload/path/case/tamper gates; environment isolation; redirect rejection; and the owner's harmless actual Windows Job/process and error-mode restoration checks. No live GUI/model result is inferred from them. The restricted-shell attempt and later approved focused run are described separately in the retained log.
- Root reported a successful real read-only FINISHED preflight over all **824** manifest entries. This reviewer directly read that manifest, confirmed its 824 entries and SHA256 `3be444f31b8e6200d04f89be39b47863e9821ac27b2df6cc41f2e6dd52edb02e`, and checked the retained account; it did not independently rerun the full payload inventory. The manifest identifies native build `integrated-20261022-portable-startscan-fix` and engine build `fresh-B-J-20261021-01`.
- The integrator identifies that engine as the historical B–J source package with 12 modules differing from current source. This runner does not verify or repair that source parity. Consequently, that real preflight is evidence only for the selected existing package's bytes; `accepted_same_source` and `accepted_wp017` must remain false, as implemented.
- Existing native parity/provider defaults and `tools/verify_wp017_live.py` have no current diff from this runner change. Source diff checks found no whitespace error; final source/test hashes match the owner's frozen handoff.

No new collector-specific dynamic run was performed. The first actual execution must still establish that this package produces the expected native request, fresh generation, artifact manifests, audit records and export for each of the five modes. Same-source packaging, actual completed HTTP/model work, visual review and final acceptance require their own evidence; this review does not substitute for them.

## Handoff

- `task_id`: WP017 native runner bounded independent review.
- `owner`: `/root/ultra_taint_review`.
- `base_commit`: `18fc9b2ae711bf0b39d93c996ae2ab220cc9a82d`.
- `final_commit_or_diff_hash`: uncommitted review; frozen runner/test SHA256 values recorded above.
- `paths_changed`: `docs/verification/windows-parity/WP017/runner-20261022/independent-review.md` only.
- `leases_released`: review-document lease released on delivery; no source/test lease held.
- `tests_executed`: none by reviewer; read-only source, hash, manifest, XML and log inspection.
- `tests_not_executed`: tests/process fixtures, native modes, HTTP/model, broad regression, build/package and UI workloads.
- `live_provider_calls`: 0 by reviewer; no five-mode live acceptance supplied by preparation.
- `manual_checks`: static code/evidence review only; no manual GUI acceptance.
- `package_id`: portable manifest SHA256 `3be444f31b8e6200d04f89be39b47863e9821ac27b2df6cc41f2e6dd52edb02e`, byte-consistency scope only.
- `run_ids`: retained `runner-20261022` focused evidence and root's real preflight; no reviewer execution run.
- `evidence`: reviewed runner/tests; focused XML/log; existing verifier/native defaults; real manifest; this note.
- `limitations`: no real five-mode execution, independent full-inventory rerun, current-source package acceptance, model-quality proof or manual visual acceptance.
- `next_action`: integrator may accept the bounded runner preparation. Establish the approved same-source package before using it for final WP017 work; retain separate per-mode live and visual evidence and keep all acceptance fields false until the responsible acceptance process decides otherwise.
