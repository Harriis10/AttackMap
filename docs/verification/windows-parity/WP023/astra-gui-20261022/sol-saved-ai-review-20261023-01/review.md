# Independent saved-AI capture helper review — 2026-10-23

Verdict: **CLEAR for the scoped saved-generation capture helper. No blocking defect found.** This is source review and offline fixture verification; no GUI, scan, provider, build, candidate acceptance, or visual acceptance was performed.

Reviewed `saved_ai_capture.py` and `test_saved_ai_capture.py`, the reused `captures_check`/PNG validation, and native `CaptureLoaded` plus startup routing. Used CodeGraph first; its broad matches did not return the requested new helper, so reviewed its actual on-disk source. Read AGENTS.md and the active docs index. No source changes were made.

## Assessment

- Preflight defaults to no process launch and requires a fresh output root separated from the package, saved generation, release-lock directory and targeted real repository. It binds the reviewed RequiredBundled manifest/source lock through the shared package guard.
- Generation validation checks the successful generation identity and all listed section/export sizes and SHA-256 values. It rejects path traversal, duplicate/case-aliased records, self-reference and missing canonical report/run/selected-mode artifact/metadata. Before/after input checks retain package, generation, helper, capture guard and runner identities.
- The command selects the saved report and AI mode using the existing native capture route. Native startup routes this flag before personal settings/provider restoration; native CaptureLoaded loads the saved report, selects the requested artifact and limits captures to Reports. There is no requested scan/provider invocation in this path.
- Capture verification requires four completed records for the selected mode and pinned report hash, `providerCalled=false`, and no failure proof. The reused guard requires unique Light/Dark size pairs, consistent actual dimensions/scale, hash-bound PNGs, increasing actual viewports and decoded visible/nonuniform pixels. Owned process exit and tree cleanup are checked before summary success.
- The result keeps requested scan/provider counts at zero and visual, accessibility, WP017, WP023 and release acceptance false. `providerCalled=false` is native diagnostic evidence, not an independent network trace. Pixel checks cannot establish that the selected prose is readable/correct; human visual review remains required. Successful saved capture cannot establish a new model completion or clear existing content-quality findings.

## Verification

Ran only the seven small offline tests in `test_saved_ai_capture.py`, covering generation inventory binding, same-size tamper, wrong generation, duplicate path, traversal, missing metadata and wrong mode before pixel validation.

Initial sandbox attempt: exit 1, temporary-fixture setup/cleanup denied by Windows ACLs; log retained as `pytest.log` and not counted as PASS. The authorized bounded `require_escalated` retry used a separate fresh temporary root and logs: **7 PASS in 0.44s**, exit 0, `pytest-retry.log` / `retry-results.xml`. These fixtures do not exercise actual UI captures, successful preflight against a candidate, real process dispatch, or the full run lifecycle.

Command (retry):

```powershell
.\.venv\Scripts\python.exe -B -m pytest docs/verification/windows-parity/WP023/astra-gui-20261022/test_saved_ai_capture.py -q -p no:cacheprovider --basetemp=docs/verification/windows-parity/WP023/astra-gui-20261022/sol-saved-ai-review-20261023-01/retry-test-temp --junitxml=docs/verification/windows-parity/WP023/astra-gui-20261022/sol-saved-ai-review-20261023-01/retry-results.xml
```

No product source edits, build, GUI/provider invocation, historical evidence rewrite, ACL change or cleanup was performed. Test-created fixture directories remain retained. Root owns the candidate and actual runtime review.

## Reviewed on-disk SHA-256

| File | SHA-256 |
| --- | --- |
| docs/verification/windows-parity/WP023/astra-gui-20261022/saved_ai_capture.py | 75e60d18e12923e95c6d4cf07f78921c193a22798c3180efd9e5618d6937cb66 |
| docs/verification/windows-parity/WP023/astra-gui-20261022/test_saved_ai_capture.py | 0419cce83adf25da41eae452dd72dbd0fea2637d41bcd08f98845792ee21551e |
| docs/verification/windows-parity/WP023/astra-gui-20261022/run-gui-checkpoint.py | 571cd1de30b8cad91e895f739bc7e46303fecfd34f57653ca57f85ab32c004dd |
| tools/run_wp017_native_modes.py | da2d34c55ad4237ac1a1b586ab59cfd13d056073d657ead75ebfe92758199fcc |
| desktop/windows/AttackMap.NativeSpike/MainWindow.Capture.cs | 8004034c228c596d9eddf0378daa73391b4ec27febae559f7dc232343984f231 |
| desktop/windows/AttackMap.NativeSpike/MainWindow.xaml.cs | caf33b7d20e835a70bf8c8e8fd4da5a3dd4f15e04586861d03227101972a2663 |
