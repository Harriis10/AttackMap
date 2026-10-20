<!-- ATTACKMAP_DOC_STATUS: HISTORICAL_REFERENCE -->
> **STARÝ DOKUMENT — pro agenty nerelevantní jako aktuální plán nebo zadání (20. 10. 2026).**
> Práci řídí pouze dokumenty v [aktuálním rozcestníku](README.md). Tento text je historická reference: neobnovovat jeho TODO, priority ani statusy dokončení. Technické podklady a kritéria použít jen v rozsahu potřebném pro aktivní WP úkol a ověřit proti aktuálnímu kódu.

# Windows 11 development-preview validation (optional historical runbook)

**Scope change — 15 October 2026, user decision:** C26 performance qualification is removed from Windows M3 acceptance. A Windows 11 performance host and repeated performance campaign are not required; no replacement Windows 10 performance gate is introduced. Existing measurements remain optional diagnostics, not a performance pass. Other requirements retain their evidence status; the later Windows M3 closure moves remaining manual UX/accessibility and participant validation to M4. macOS C26 is unchanged. Historical Windows C26 blockers below are superseded by this decision.

This runbook is retained for optional future diagnostics. Its Windows 11 campaign is not a prerequisite for Windows M3; remaining manual usability/accessibility checks can be performed on the available Windows host.

Windows 11 is currently unavailable for this project. This is a portable runbook,
not a qualification result. Existing Windows 10 measurements remain diagnostic.
Use a newly reviewed package containing the C22 nonzero-exit guard; historical
packages produced before that fix are not the candidate for this campaign.

The latest immutable **pending development candidate** on 2026-10-15 is
`dev-20261015153700-2ef7b386.zip`, archive SHA-256
`b8fcb9ec291b6831ab33fc784285365e85be3ba1dc8c70276d12e21aa4f7241a`.
Native DLL SHA-256:
`a7201cb2ecddd9eaeabd3481566e7237ce2c4298883c383a5a38fe2f92f5dce9`.
Bundled engine SHA-256:
`b5f839a26d3f2f0bb93a77a555e75fb0b48583b89b30e85688a746f2ee43a7dd`.
Its isolated installed startup, 18-finding saved-report import, tiny actual
engine UTC scan with all 19 artifact hashes, rollback/rollforward and uninstall
checks passed. Evidence: `desktop/windows/verification/native-final-source-candidate-package-2026-10-15.json`.
These checks do not promote it to M3 or establish manual/Windows 11 acceptance.
The user-open historical preview remains separate and untouched.

The original sealed Windows full runs are preserved: Python 3.11 passed 3,214
with four skips; Python 3.13 passed 3,213 with one PID-file synchronization test
failure and four skips; Python 3.12 had three wall-clock-limit failures and four
skips. The unchanged three 3.12 timing cases passed in isolation (23.59s).
Corrective full 3.12 session 58170 and corrected 3.13 50-cycle target session
86238 are **active at this checkpoint**, not passes. See
`desktop/windows/verification/final-source-windows-matrix-2026-10-15.json`.
Final copied-source Linux 3.12 passed 3,213 with five explicit skips in 146.53s;
source/test inventories stayed unchanged. Evidence:
`desktop/windows/verification/final-source-linux312-full-2026-10-15.json`.
Do not merge these results into an all-green Windows matrix.

A source audit found History retains old comparison rows when its baseline
changes. A narrow native correction is in progress; it is **not included in
this candidate**. Retain the candidate identity when recording that journey;
a separately reviewed build is required to test the correction.
The gate map is `docs/windows-m3-gate-status.json`; supporting records are under
`desktop/windows/verification/`. Old frozen fleet/cancellation proofs remain
bound to their recorded executables, not automatically to this candidate.

M2 and C19 prerequisite decisions and participant outcomes remain separate open
requirements. This Windows-only exercise does not establish macOS acceptance or
the native-direction decision. Public signing/distribution and the four-week
study belong to M4; installing an unsigned development ZIP does not satisfy them.

## Review kit and host

Bring these existing artifacts to the Windows 11 x64 host:

- The reviewed development ZIP, its adjacent `.sha256`, and the package ID and
  native/engine build hashes approved by the maintainer.
- `tools/measure_native_windows.ps1`, unchanged from that reviewed source.
- `tools/measure_native_readiness.ps1`, for the separate bounded readiness probe.
- The three generated reference files: `attackmap-report.json`,
  `attackmap-report.sha256`, and `desktop-reference-manifest.json`.
- An authorized real repository and matching canonical baseline/current reports
  for workflow checks. Keep scan output outside that repository.

The reference report is synthetic: 10,000 findings, 50,000 observations,
20,971,520 bytes, and SHA-256:

```text
612d12c9b56bfa98ccb7061e81b67120bc738759e9731737ab1fe9d1ada658ba
```

If needed, the maintainer can generate it on the existing development host with
`.venv\Scripts\python.exe tools/generate_desktop_reference.py --output .pytest_cache/m3-desktop-reference`
and transfer the three files. The tester does not need Python or a .NET SDK when
the reviewed ZIP bundles the frozen engine. PowerShell 7.2 or later is required
by the existing installer. Do not add new test tools for this runbook.

For C26, record Windows 11 build, at least four physical CPU cores, at least
16 GiB RAM, SSD, and the volume actually holding the app/report/results. The
measurement script captures CIM and physical-disk information, but merely having
an SSD somewhere does not prove the selected paths reside on it. Missing hardware
data or `qualifyingHost=false` leaves qualification open. Record concurrent work,
power mode and scaling; avoid other intentional CPU-intensive campaigns.

## Verify and install the reviewed candidate

Run in PowerShell 7.2. Replace the review-drop filenames with the maintainer's
new C22-corrected candidate; do not substitute a superseded historical ZIP.

```powershell
$archive = (Get-Item -LiteralPath 'C:\ReviewDrop\attackmap-development.zip').FullName
$checksum = (Get-Content -LiteralPath ($archive + '.sha256') -Raw).Split()[0]
if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -ne $checksum) {
    throw 'Archive checksum mismatch'
}
$review = Join-Path $env:TEMP ('attackmap-win11-' + [Guid]::NewGuid().ToString('N'))
$drop = Join-Path $review 'extracted'
$install = Join-Path $review 'install'
Expand-Archive -LiteralPath $archive -DestinationPath $drop
$manifest = Get-Content -LiteralPath (Join-Path $drop 'package-manifest.json') -Raw | ConvertFrom-Json
if (!$manifest.engine.bundled -or $manifest.engine.runtime_kind -ne 'Frozen') {
    throw 'This campaign requires the reviewed bundled-engine candidate'
}
& (Join-Path $drop 'Install-AttackMap.ps1') -InstallRoot $install
$app = Join-Path $install ('versions/' + $manifest.package_id + '/app')
$native = Join-Path $app 'AttackMap.NativeSpike.exe'
$engine = Join-Path $app 'engine/attackmap.exe'
Get-FileHash -LiteralPath $archive,$native,(Join-Path $app 'AttackMap.NativeSpike.dll'),$engine -Algorithm SHA256 |
    ConvertTo-Json | Set-Content -LiteralPath (Join-Path $review 'installed-build-hashes.json')
```

The installer validates payload hashes, uses a fresh owned directory and does
not register shortcuts or delete settings. Checksums are integrity records, not
authentication or signing. If host policy blocks the reviewed unsigned package,
record that block rather than changing global policy or claiming installation.

## Isolated first-run check

The existing startup hook injects a fresh workspace settings path and does not
restore personal provider settings. It writes its result outside the installed
payload. This checks the real restore handler, not manual dialog acceptance.

```powershell
$settings = Join-Path $review 'fresh-settings.json'
if (Test-Path -LiteralPath $settings) { throw 'Use a fresh settings path' }
$startup = Start-Process -FilePath $native -ArgumentList @('--startup-smoke',$settings) `
    -WorkingDirectory $app -WindowStyle Hidden -PassThru
if (!$startup.WaitForExit(60000)) { throw "Original PID $($startup.Id) remains active; inspect before retrying" }
$result = Get-Content -LiteralPath ($settings + '.result.json') -Raw | ConvertFrom-Json
if ($startup.ExitCode -ne 0 -or !$result.passed -or $result.bundledEngine -ne $engine -or
    $result.automaticScan -or $result.aiEnabled -or $result.cveEnabled -or
    $result.personalSettingsRead -or (Test-Path -LiteralPath $settings)) {
    throw 'First-run isolation or bundled selection failed'
}
& $engine --version
& $engine modules --json | Set-Content -LiteralPath (Join-Path $review 'installed-modules.json')
```

Record each command's exit code. Module count must match this candidate's
manifest, not a guessed universal count. Retain the startup result and exact
process ID. Do not restart because an observation timed out; establish what
happened to that original process first.

## Full reference campaign

Copy the reviewed measurement script and reference files into the review drop.
Check the report before launching; keep the source fixture unchanged.

```powershell
$reference = (Get-Item -LiteralPath 'C:\ReviewDrop\reference\attackmap-report.json').FullName
if ((Get-Item -LiteralPath $reference).Length -ne 20971520 -or
    (Get-FileHash -LiteralPath $reference -Algorithm SHA256).Hash -ne
    '612d12c9b56bfa98ccb7061e81b67120bc738759e9731737ab1fe9d1ada658ba') {
    throw 'Reference fixture mismatch'
}
$measure = (Get-Item -LiteralPath 'C:\ReviewDrop\measure_native_windows.ps1').FullName
$performance = Join-Path $review ('performance-' + [Guid]::NewGuid().ToString('N'))
& $measure -Executable $native -Report $reference -OutputDirectory $performance `
    -Launches 30 -TimeoutSeconds 1800
```

Do not use `-Quick` or `-Launches 1` for the full campaign. The first process runs
30 loads, ten warmups followed by 100 filter samples and 100 detail samples,
then 100 open/close cycles. The other processes supply fresh-launch samples.
Keep all `launch-00.json` through `launch-29.json`, `summary.json`, hardware
details and build hashes. Use a new output directory for another justified run;
the harness refuses stale trial paths. On a timeout, retain the reported
original PID/cleanup result and incomplete artifacts; do not label it a pass.

Review these fields without changing the probe or its GC behavior:

| Result | Required measurement |
| --- | --- |
| `exactProtocolCounts`, fixture checks, failures | Exact counts, reference match, no failed assertions |
| `qualifyingHost` | True, supported host and independently confirmed storage placement |
| Report p95 | At most 2,000 ms |
| Filter p95 | At most 150 ms |
| Detail p95 | At most 100 ms |
| Loaded UI working set | At most 500 MiB; retain private-byte measurements too |
| Retained working-set growth | At most 50 MiB after 100 cycles; retain private growth too |

Process-to-Loaded p95 is a diagnostic marker. The C26 three-second **primary
action ready** requirement needs a separately recorded readiness measurement;
this harness does not certify it. Its `acceptance` field intentionally remains
unaccepted. A qualifying host and passing numeric fields alone cannot accept
C26, accessibility or the full desktop workflow.

The existing separate readiness harness can record the actual Start scan
AutomationPeer response to a missing repository after layout and two render
frames. This invokes the primary control; it does not open the repository picker
or start a scan, and it is not a manual first-scan journey:

```powershell
$readinessTool = (Get-Item -LiteralPath 'C:\ReviewDrop\measure_native_readiness.ps1').FullName
$readiness = Join-Path $review ('readiness-' + [Guid]::NewGuid().ToString('N'))
& $readinessTool -NativeExe $native -OutputDirectory $readiness -Launches 30
```

Keep all trial results and the summary with the exact DLL hash. The recorded
Windows 10 campaign had 30 visible windows and 30 successful responses, p95
1,575.7296 ms, with `acceptedC26=false`. Repeat on the qualifying Windows 11 host;
this narrow response test does not replace report, memory, interaction, picker
or manual workflow requirements.

## Native workflow and appearance records

Use the actual controls and record task outcome, selected run/repository,
previous-report behavior, screenshots and any blocked step. Keep automated hook
results distinct from these manual journeys.

Use `C:\tmp\juice-shop` for the real-repository journey, with output outside
that repository. Use owned disposable copies/fixtures for mutation, suppression
and failure cases; preserve the real repository and original report files.

| C21 workflow | Actual controls and expected result |
| --- | --- |
| Open repository | Choose repository (File menu or workspace button); select `C:\tmp\juice-shop`. Cancel the picker and confirm the prior selection remains. |
| Run default scan | Start scan with AI/CVE off. Expand Run identity and report coverage; verify repository, client request time separately from supplied engine UTC start/end, stage, artifact readiness and coverage. |
| Configure advanced options | Configure scan options, installed analyzer names, timeout and local history count; Save local settings, restart and verify restore. Invalid module selection must fail clearly and preserve the prior report. |
| Browse/filter findings | Findings: Filter findings, select rows and inspect long/Unicode text. Record list/detail usability and retained selection. |
| Inspect evidence | Inspect live source locations, select a location and Reveal selected source folder. An owned source changed since scan must show changed/unknown-hash warning; static evidence must not become runtime proof. Missing sources remain explicit. |
| Explore architecture/inventory | Overview, Architecture and Inventory: supplied actions/strengths/records and relationship limitations remain visible without invented associations. Scroll bounded lists/details. |
| Compare runs | History: Choose baseline report, then Compare with displayed report. Verify exact baseline/current paths and partial-coverage uncertainty. Change baseline after a comparison; record the pending candidate's stale-row defect rather than accepting old rows as new results. |
| Manage reasoned suppression | Use the finding suppression controls in an owned disposable repo: supply a reason, Preview suppression, Apply reviewed suppression, rescan, Undo last change (or Recover / Undo). Verify recovery/provenance and absence of unintended repository changes. |
| Export selected run | Reports or File menu: Export displayed JSON / Export displayed review Markdown. Cancel/error in the save dialog preserves displayed data; exported bytes/labels identify the selected run. Inspect listed artifacts read-only. |
| Configure optional provider | Settings: explicit local LM Studio endpoint/model below, Save provider settings and Test connection (sends request) only with authorization. Verify disabled defaults, opt-in and restore; failed credentials remain protected and no request occurs automatically. |

For each workflow, record keyboard-only completion, focus/order and Narrator
output separately. Test light/dark, 100/150/200% display scaling, 200% text and
high contrast; current in-process content captures do not certify these.

For cancellation/failure/retry, use Cancel, the run-details diagnostic path,
Reveal last scan folder and Retry scan with current settings. Previous valid
results must remain explicitly previous, cleanup must finish before restart,
and diagnostics must exclude credentials. A completed envelope with a nonzero
broker exit must be rejected. Preserve the original process/PID if a timeout
occurs; do not restart or broaden process termination. Record unavailable
fault injection as untested rather than inventing a manual outcome.

The authorized local AI test endpoint is `http://127.0.0.1:1234/v1`, model
`cyberstag-security-26b-a4b-v1`. Do not substitute a remote provider. Provider
generation and external CVE calls are not part of the reference campaign.

Capture failures and scoped conclusions in a new validation record with package
ID, archive/native/engine hashes, OS/hardware, fixture hash, result directory,
completed and blocked journeys, and remaining gates. Leave C19/M2, unavailable
host requirements, manual readiness or workflow gaps explicitly open.

## Rollback and uninstall

The extracted installer supports `-Mode Rollback -Version <installed-package-id>`
with the same `-InstallRoot`. It changes the version selection record, not saved
settings compatibility. Launch the chosen version's executable explicitly.

```powershell
& (Join-Path $drop 'Install-AttackMap.ps1') -Mode Uninstall -InstallRoot $install
```

Uninstall validates owned payloads and refuses unexpected or modified files.
Preserve diagnostic files before reviewing any refusal; do not recursively delete
an arbitrary target to bypass it. User settings, reports, action recovery
snapshots and protected credentials under AppData remain untouched. Keep the
external validation results for review.
