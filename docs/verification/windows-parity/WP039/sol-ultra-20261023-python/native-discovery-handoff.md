# Native discovery failure details — source handoff

The native model now exposes `DiscoveryIssues` separately from usable inventory
and report execution. It preserves load, initialization, metadata, contract,
trusted-policy and entry-point-enumeration outcomes. Each display record contains
only a safe identifier/package, known reason and optional exception type. Raw
exception messages, source paths, wheel URLs and unknown data are not rendered.
Path-shaped name/package values become explicit unknown labels. Malformed
details fail as an incompatible optional catalog, without partial or stale rows.

The view adds the named `AnalyzerDiscoveryIssues` expander, collapsed when empty.
It renders at most64 issues with an explicit omitted count. Its text identifies
the current engine discovery scope and does not imply applicability or execution.
Unavailable candidates have no selection checkbox; saved missing selections
remain separately visible and blocked. A failed same-name plugin does not remove
the usable builtin. Engine switch, refresh and incompatible payload clear old
discovery issue records. Current ledger1.0/1.1 timing/count/lifecycle behavior is
preserved.

Captured-source console verification:

```powershell
.venv/Scripts/python.exe -B docs/verification/windows-parity/WP039/sol-ultra-20261023-python/verify_native.py native-discovery-issues-stable-20261023
```

**164 checks PASS**; process exit0, owned Windows Job assigned, cleanup verified,
1.408s model execution. Restore/build/runtime logs and input-bound build proof
are under that label. The initial `native-discovery-issues-20261023` build failed
on two C# local-name shadow declarations; the named source correction was made
before the stable captured build. It is retained as a failed build, not PASS.
No shared moving fleet tree was built.

Released source hashes are in `native-discovery-source-hashes.json`:

- AnalyzerSelectionModel.cs: `73c8738b7dab2d5ed68d47399d1df2e1ebd5aadb84b7d6a27a0b926806709318`
- AnalyzerSelectionView.cs: `08cfbb05a571ca3c03f1630569671cefe46d5a1d9e0ab2a1413086b1c53e1c88`
- ScanProgress.Tests/Program.cs: `cc97c4cf59a687281b7b71b0edb8504e938c1ca39167b86d3e088205bb2da7a2`

The explicit `fixture_only:true` data for separate visual QA is
`native-discovery-issues-fixture.json`. It has one usable fixture analyzer, four
failure stages, a trusted-policy skip and an enumeration error. It is not actual
engine inventory and must not replace the model used for real scan evidence.
Root owns the final captured native build, visible preview and visual review.
Model/compile checks alone do not establish appearance, manual accessibility,
clean-host, package or release acceptance.
