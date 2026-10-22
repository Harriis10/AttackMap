# WP017 native mode runner preparation — 22 October 2026

`tools/run_wp017_native_modes.py` prepares or explicitly runs the existing full
`AttackMap.NativeSpike/MainWindow` parity smoke journey. The default is a read-only
preflight: it starts no process, makes no HTTP request, and creates no output
directory. Preparation does not close WP017 or WP024.

The runner uses the fixed repository `C:\tmp\juice-shop`, endpoint
`http://127.0.0.1:1234/v1` and model `cyberstag-security-26b-a4b-v1`. It offers no
repository, endpoint or model override. `--mode all` selects sequential `review`,
`hunt`, `hunt_verify`, `remediate`, and `triage`; one mode can also be selected.

Before using `--run`, root must hold the exclusive LM Studio/native app lease and
separately establish the approved WP024 package/source identity. The historical
B–J development preview can establish consistency for its exact bytes, but cannot
become a current-source package or final WP017 acceptance through this script.

## Read-only preflight

Use absolute paths. Replace the app and output placeholders with the separately
reviewed package and a new caller-owned evidence root. The seed below is an
existing report used only to initialize the full window before its fresh scan.

```powershell
.venv\Scripts\python.exe tools\run_wp017_native_modes.py `
  --app "C:\Projects\INPROGRESS\AttackMap\desktop\windows\artifacts\<reviewed-package>\AttackMap-Windows\AttackMap.NativeSpike.exe" `
  --seed "C:\Projects\INPROGRESS\AttackMap\docs\verification\windows-parity\WP024\portable-20261022\native-scan\reports\5e1602ef6ff941038c36d31a0e87b4d7\attackmap-report.json" `
  --output "C:\Projects\INPROGRESS\AttackMap\docs\verification\windows-parity\WP017\<new-run-id>" `
  --mode all
```

Review the returned `package.manifest.sha256`, `package.identities`, build labels,
scope and all five planned modes. A successful preflight verifies every file's
size and SHA-256 against the complete portable manifest, required bundled runtime
files, no extra files/directories, and no links, reparse points, hard-linked payload
files, unsafe Windows names or path aliases. Manifest property and case aliases are
rejected. Required runtime markers accept Windows casing, including the actual
`Microsoft.ui.xaml.dll` spelling; exact inventoried names and bytes still match.

The output must not exist and must be separate from the package, seed directory
and target repository. Preflight is available without a pin; supplying
`--manifest-sha256` also checks that immutable reviewed identity.

## Explicit execution, after the package gate

Repeat the same command with both these additional options:

```text
--manifest-sha256 <the-reviewed-64-character-lowercase-sha256> --run
```

`--run` without that pin fails before dispatch. Package bytes and the seed hash
are checked before each mode; package bytes are checked again after the app exits.
Each mode uses a fresh subdirectory and the existing `--parity-smoke` settings,
recent-repository, native scan, selected Reports mode, export and capture path.
Ambient provider/Python/proxy/endpoint/QA variables are dropped through an OS
allowlist; the child PATH contains only Windows and System32. AppData, user profile
and temporary paths are isolated within that mode's output. Personal settings are
not used by this journey.

A model-list GET verifies the exact local model before each native launch.
Redirects and proxy inheritance are disabled. This GET proves no generation.
The existing production HTTP observer enforces the exact loopback Responses URL,
model and nonstreaming request before dispatch and records a unique per-mode nonce.
The existing local SDK transport disables redirects and proxy inheritance.

Configured limits remain 8 calls, 900 provider budget seconds, 32,000 output tokens
and a 1,200-second native scan timeout. The outer app wall timeout defaults to
1,500 seconds, with `--process-timeout` bounded to 1,200–1,800 seconds. Timeout,
fallback, partial or failed transport observations fail the mode and stop later
modes. Earlier completed modes remain available in the fresh evidence directory.

The app starts suspended, joins an owned Windows Job Object, then resumes.
Windows crash/error dialog suppression (`SetErrorMode(0x8003)`) is scoped to
process creation so the child inherits it; the parent's previous mode is restored
immediately, including failed process creation.
Cleanup targets only that job/PID tree. Normal exit and timeout both verify zero
remaining owned job processes; PID, arguments, app exit, timeout and cleanup status
are retained. Closing the job also terminates its remaining descendants.

## Collected evidence and limits

The runner writes root `preflight.json`, `package-verification.json`, and either
`summary.json` or `failure.json`. The package proof concerns manifest/payload byte
consistency only; it is not an invented WP024 same-source approval.

Each mode retains `inputs.json`, `started.json`, `process.json`, native stdout and
stderr, the model-list response, native request and report generation, artifact
manifest, AI artifact and metadata, selected artifact export, native Reports PNG,
and raw transport observations with observed generated-output bytes. The collector
binds these identities/hashes into `evidence.json`, checks request mode and budgets,
generation/manifest checksums, capture metadata, export equality and successful
transport completion, then calls the existing offline `tools/verify_wp017_live.py`
gate. Its result is saved in `verification.json`.

The offline gate can be repeated without provider traffic:

```powershell
.venv\Scripts\python.exe tools\verify_wp017_live.py "<absolute-new-run-root>\review\evidence.json"
```

No result sets `accepted_wp017`, manual UI, same-source, release or clean-host
acceptance to true. Native RenderTargetBitmap captures are visual review material;
they do not prove a human reviewed the displayed window, keyboard use, Narrator or
OS appearance. Completed generated output does not prove the model's claims true.
Full current-source package qualification and manual acceptance remain separate.

## Focused verification performed

```powershell
.venv\Scripts\python.exe -m pytest tests\test_wp017_native_runner.py tools\test_verify_wp017_live.py -q -p no:cacheprovider --junitxml=docs\verification\windows-parity\WP017\runner-20261022\focused-tests.xml
```

30 tests and 20 subtests passed: 20 runner checks and 10 existing offline verifier
checks. These cover synthetic package/input negative
gates, stale manifest/proof roots, wrong app identity, actual WinUI filename casing,
no launch without explicit execution and pin, environment isolation, redirects,
and harmless real Python process Job assignment/owned parent-child cleanup and
parent error-mode restoration. The [test log](focused-tests.txt) and
[JUnit result](focused-tests.xml) record that focused run.
The test run required the normal test execution context because the restricted
shell denied access inside Python-created temporary directories. No native GUI,
build, LM Studio HTTP request or model generation was run for this preparation.

Root separately executed a real read-only preflight against the corrected existing
`C:\Projects\FINISHED\AttackMap-Windows-Portable-20261022\AttackMap.NativeSpike.exe`.
The first attempt exposed a required-marker casing mismatch (`Microsoft.UI.Xaml.dll`
versus the actual `Microsoft.ui.xaml.dll`), which was fixed with the regression
above. The repeated actual preflight passed all **824** manifest entries with pin
`3be444f31b8e6200d04f89be39b47863e9821ac27b2df6cc41f2e6dd52edb02e`.
It created no output directory, launched no process and made no provider request.
That existing preview's byte-consistency result is separate from synthetic tests,
current-source qualification, native execution and live five-mode acceptance.
