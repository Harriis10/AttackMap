### Task 3: Offline Candidate, One Live Run, and Evidence-Led Review

**Files:**
- Create: `artifacts/diagram-integration-20261024/wp043-continuation-20261025/ordinary-candidate-08/`
- Create: `artifacts/diagram-integration-20261024/wp043-continuation-20261025/detail-root-render-probe-live-28/`
- Modify: active WP043 progress/roadmap/TODO/backlog documents listed above.

**Interfaces:**
- Consumes: green Task 1/2 source and the frozen engine in `ordinary-candidate-07/engine`.
- Produces: hashed diagnostic candidate, one bound evidence manifest, actual visual review of all five A/D/T/B sets, and a narrowly stated next diagnostic gate.

- [ ] **Step 1: Publish offline and preserve the frozen engine**

Run:

```bash
out="artifacts/diagram-integration-20261024/wp043-continuation-20261025/ordinary-candidate-08"
winpwd=$(pwd -W)
export DOTNET_CLI_HOME="$winpwd/.tools/dotnet-home"
export NUGET_PACKAGES="$winpwd/.tools/nuget-packages"
./.tools/dotnet/dotnet.exe publish desktop/windows/AttackMap.NativeSpike/AttackMap.NativeSpike.csproj -c Release --no-restore -o "$out"
cp -a artifacts/diagram-integration-20261024/wp043-continuation-20261025/ordinary-candidate-07/engine "$out/engine"
./.venv/Scripts/python.exe -B -c "from pathlib import Path; import hashlib; p=Path(r'artifacts/diagram-integration-20261024/wp043-continuation-20261025/ordinary-candidate-08'); print('DLL', hashlib.sha256((p/'AttackMap.NativeSpike.dll').read_bytes()).hexdigest()); print('ENGINE', hashlib.sha256((p/'engine/attackmap-engine.exe').read_bytes()).hexdigest())"
```

Expected: publish succeeds without restore/network access; engine SHA-256 is `792184c584895bab68e4260447fe89543486ae228bd8ad85234ae3ca87ce8bba`. Record the actual new DLL hash. If the frozen engine filename differs, enumerate the candidate directory and hash the actual executable rather than inventing a path.

- [ ] **Step 2: Run one serialized live capture**

Use the retained report, new candidate, and fresh output:

```bash
./.venv/Scripts/python.exe -B tools/capture_wp043_live.py \
  --executable artifacts/diagram-integration-20261024/wp043-continuation-20261025/ordinary-candidate-08/AttackMap.NativeSpike.exe \
  --report artifacts/diagram-integration-20261024/source-render-audit-20261025/saved-generation/attackmap-report.json \
  --output artifacts/diagram-integration-20261024/wp043-continuation-20261025/detail-root-render-probe-live-28 \
  --native-only --theme dark --detail-root-render-probe
```

Expected on a completed capture: five `detailRootRenderProbe` entries, 80 accepted ordinary captures plus two RTB PNGs per round, `diagnosticInterventions=false`, and clean process exit. A foreground/occlusion or protocol failure is a harness/diagnostic failure, not a visual sample; do not blindly retry or relabel it as `not-reproduced`.

- [ ] **Step 3: Inspect every A/D/T/B image**

For each round, open A and B at native size, D at its viewport-equivalent top region, and T at native size or inspect full-resolution crops when downscaling would hide glyphs. Check file size before every media read; resize images over 3 MB into a separate workspace review directory without modifying originals. Record actual per-image states in `visual-review/manual-review.json`, including run ID, PID, DLL/report hashes, all 20 images, and exact review scope. Do not derive visual state from hashes or UIA text.

- [ ] **Step 4: Update active evidence without overclaiming**

Append the exact test/build/run/review results to `PROGRESS-20261025.md` and align only WP043 entries in the active TODO, roadmap, and JSON backlog. Validate the JSON after editing. Keep WP043 `IN_PROGRESS`, rendering acceptance `FAILED`, and V01/V02/V03 blocked unless independently observed evidence supports a different state. If an A-blank round occurs, report D/T according to the approved interpretation matrix. If none occurs, mark the targeted anomaly `not-reproduced`. Do not claim a repair, workaround, root cause, or candidate promotion.

## Self-Review

- Spec coverage: Tasks 1 and 2 cover F7 isolation, D/T ordering, identity, atomic bounded PNGs, failure behavior, and regressions; Task 3 covers offline build, one live run, all 20 image reviews, and truthful documentation.
- Placeholder scan: no unresolved placeholders or deferred implementation steps. Runtime hashes and visual states must be measured, not prefilled.
- Type consistency: native `detailFileName`/`rootFileName` and dimension keys map to runner prefixes `detail`/`root`; manifest names `detailRenderCapture`/`rootRenderCapture` match the tests; B destination and CLI names are consistent.
