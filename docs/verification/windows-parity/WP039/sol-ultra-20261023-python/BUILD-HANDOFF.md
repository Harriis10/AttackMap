# SOURCE FROZEN — analyzer lane ready for combined capture

Confirmed 23 October 2026, 13:56 Europe/Prague (11:56 UTC).
Chat `01a167fe-5c83-7613-b5fc-55755fe39ce1`; HEAD
`507bddacd72a246a136ca2d46faad2aa661806c1` plus preserved uncommitted changes.

**SOURCE FROZEN.** This chat and its three completed Sol 6.1 ultra agents have
no pending product edits. From this handoff until the combined build owner
releases the freeze, this lane will not write `src/`, root `README.md`,
`pyproject.toml`, `installer/`, production native sources, or packaging inputs.
Documentation/review outside shipping inputs may continue. This is our lane's
freeze commitment, not a claim that the fleet owner's final layout edit has
already stopped. No reset, checkout restoration, lease or status edit was made
for this handoff. The fleet lease is preserved; live WP043/WP044 are IN_PROGRESS.

## Checkpoint and evidence

- All 13 shipping files below were freshly hashed in the live checkout and
  exactly match the tested analyzer checkpoint: **zero mismatches**.
- WP042 IMPLEMENTED; WP039 IN_PROGRESS for documented unsupported scope,
  dependencies and C27/C38. No outstanding analyzer implementation/review blocker.
- 338 integrated Python tests PASS; 164 captured native model checks PASS.
- Actual fresh frozen Python profile: 17 Django + 8 mount/auth cases PASS.
- Same-environment Juice Shop before/after: source Automatic 266 routes,
  frozen Automatic 270, native Node profile 281; each 18 findings. Whole reports
  match after removing only the three identical ledger copies.
- Same native03/frozen candidate: real native scan/profile persistence PASS,
  eight nonblank Light/Dark captures at two sizes independently reviewed.
- Actual package inventory: 15 official distributions / 21 effective analyzers /
  24 candidates / 3 PHP shadowed; 4 profiles. SBOM verifies 776 payload files;
  all 779 ZIP entries match. All final owned jobs cleaned up; all agents completed.

Authoritative details: [batch README](README.md), [completion](completion.json),
[integrated tests](integration-test-proof.json),
[native checks](native-discovery-handoff.md),
[package proof](packaged-catalog-final-verification.json),
[visual review](python-django-native-visual-review.md).
Raw test/source, native build, scan, package and capture outputs remain intact.

## Exact shipping file SHA-256

Paths are relative to the repository root. The matching machine maps are
[Python inputs](candidate-python-inputs.json) and
[native inputs](candidate-native-final-inputs.json).

| File | SHA-256 |
| --- | --- |
| src/attackmap/ecosystem_python.py | fc0f091d9ffc7c43eac6001e0ca4ae99d399a7e0ec48d40690b4171b1a9dc722 |
| src/attackmap/python_route_binding.py | 53e61053dc955ae06de865ab39307153c4ed6391f687a095f6eda34e4df549c9 |
| src/attackmap/python_django_routes.py | faabbe10d84c4366c1891e6a2f93b2268a0121237c6af682170fe56af1ae6fd7 |
| src/attackmap/scanner.py | 5be41db7b72246efe048b01267bac008ed14119e65f9d1f896aa725502ead8ff |
| src/attackmap/analyzer_run_ledger.py | f817d9051644c97c5dc7cbe35139802ca4073c23a09794c787d592d3cc0fd5f5 |
| src/attackmap/analyzers.py | fac2d9f0ccc35ab56b68339dc388b286f7de0dba6e8b637aa79795a85bd1a9f1 |
| src/attackmap/pipeline.py | 54cb1fb4083b83eaf8ab4b02bae465325945d6a4d3ca45b4cf2a8d1ab69cc5b6 |
| desktop/windows/AttackMap.NativeSpike/AnalyzerSelectionModel.cs | 73c8738b7dab2d5ed68d47399d1df2e1ebd5aadb84b7d6a27a0b926806709318 |
| desktop/windows/AttackMap.NativeSpike/AnalyzerSelectionView.cs | 08cfbb05a571ca3c03f1630569671cefe46d5a1d9e0ab2a1413086b1c53e1c88 |
| desktop/windows/AttackMap.NativeSpike/ScanProgressModel.cs | 5dceac9f5bf5b9366c077f57a428f94a8d94ed5bb05ee0785cf824622becc157 |
| desktop/windows/AttackMap.NativeSpike/ScanProgressView.cs | 582f9c3d5224fe5bdcb527d79914f2a5e099a47d1916dccd7a82d48d41543059 |
| desktop/windows/AttackMap.NativeSpike/MainWindow.AnalyzerSmoke.cs | cdc8f48e5097de91626c02c5470b9c8c5abeaf4214246a91b6ebeb470ba152dc |
| desktop/windows/AttackMap.NativeSpike/NativeCaptureProbe.cs | 7a81751ede6bd5ffcb2ebf55943f948e71889d5d3e89eb61b4a7dbfb8cd00429 |

## Combined-build cautions

Capture the **current shared checkout after the fleet layout agent releases**;
preserve all completed analyzer changes, including earlier catalog/profile and
request 1.5 work. Do not restore our old captured tree over it. Our standalone
engine `6045194b77c0957166a6eb9fece45dbfd9c42441bb9e32cec6d040db6c419b05`
and ZIP `1ea81929733bf6bd1204af0d06de82a6f625f00d83b738d772be7b7dc3299bde`
exclude the concurrent fleet additions and are reference evidence only for the
combined product. The new combined binary needs its own source-bound proof.

Use one captured version of the release-lock/package/SBOM tools consistently.
Our older producer omitted `desktop/windows/fixtures/findings.json` from its
release digest; the moving root tool includes it. Our wrapper separately bound
that fixture. This caused a retained qualification mismatch, not a source-code
change. The combined capture should use its current tool algorithm and include
the fixture; do not reuse/rewrite our old lock to qualify a new binary.

The helpers here have fixed analyzer-candidate paths/output labels. Adapt the
logic to new immutable combined paths rather than rerunning them unchanged or
overwriting retained evidence. Ledger 1.1 adds nullable durations, pre-merge
counts and bounded lifecycle events; legacy 1.0 remains readable. Actual runtime
checks should retain report/manifest ledger equality, the four available
profiles, inventory identities and native profile persistence.

Manual keyboard/Narrator/scroll acceptance, clean-host/signing/macOS and C27/C38
remain separate. Pinned Python plugin false/duplicate Django surfaces and
unsupported general dynamic routing/class auth remain documented. No plugin
pin, default precedence or automatic installation policy changed.
