# WP017 runner review and WP024 preflight — 22 October 2026

Owner: `/root/astra_runner_review`, Astra/high. Base:
`258adf66a9ec3c5a691868ae67c3a73b08b92c4a`.
Active roadmap/TODO/backlog and RESUME/astra-high govern this work.

## Review verdict

One concrete integration blocker was found: `run_wp017_native_modes.py`
only understood `portable-manifest.json` beside the native executable.
`package_native_windows.ps1` produces a `RequiredBundled` stage with
`package-manifest.json` above `app/`, a list inventory and different runtime
metadata. The portable preview builder also hardcodes historical B-J labels.
Using that builder unchanged for a fresh engine would mislabel its provenance.

Root authorized a narrow edit lease for the runner and its tests. The patch
accepts the production layout directly; it does not create portable provenance.
It requires the explicit release lock, binds its bytes to the manifest,
recomputes current source/release/analyzer requirement identities, and retains
exact payload/deployment inventories, pinning, safe paths and no-link checks.
Portable input remains supported. All acceptance booleans remain false.

No other blocking defect was found in the inspected normal run path:

- A fresh root, seed hash and manifest pin bind each mode. Package/source-lock
  consistency is rechecked before and after each launched native application.
- The allowlisted child environment isolates profile/temp and removes Python,
  proxy/provider overrides. Only the fixed loopback model is permitted.
- The complete MainWindow parity journey invokes the selected bundled engine,
  runs a new scan, selects its AI page, reads the manifest-bound selected
  artifact, exports identical bytes and captures the Reports view.
- Collector/verifier bind request settings, run/generation, artifact inventory,
  capture hash, export equality and nonce/attempt-paired completed responses.
  Connection success, reservations and fallback are insufficient.
- The native process starts suspended, is assigned to a private Windows Job,
  and is resumed only after assignment. Cleanup verifies zero owned job
  processes; failure does not become a successful result.

Limits: the transport observer is a locally trusted observation of the real SDK
response, not independent server attestation. Visual inspection of every actual
capture remains mandatory. Automated export does not prove a file-picker journey.
The runner does not independently establish native build provenance; root must
approve the WP024 native build and engine proof before using the pinned package.
This review does not mark WP017, WP024, K3 or release acceptance complete.

## Verification

`git diff --check -- tools/run_wp017_native_modes.py tests/test_wp017_native_runner.py`
passed. After the broad Python run ended and root explicitly released the slot,
the focused suite completed with exit 0: **39 tests and 23 subtests PASS in 3.43s**.
The log, JUnit XML and final source/evidence hashes are in `focused-tests.txt`,
`focused-tests.xml` and `focused-result.json`. This includes nine added production
layout cases, per-mode before/after lock forwarding, and rejection of changed
lock bytes after a mocked launch. The existing harmless Python Job tests verify
owned child cleanup; no native app, provider request, frozen engine, package build
or installer was executed. The test slot was immediately returned to root.

```powershell
& .venv/Scripts/python.exe -m pytest tests/test_wp017_native_runner.py tools/test_verify_wp017_live.py -q -p no:cacheprovider --basetemp .tmp/wp017-astra-runner-20261022-01 --junitxml docs/verification/windows-parity/WP017/astra-review-20261022/focused-tests.xml
```

The run used the authorized normal execution context because the retained prior
suite documented restricted-shell TemporaryDirectory ACL failures. Root separately
reviewed the small implementation diff before this focused execution.

Read-only current toolchain/cache preflight: `.tools/wp024-freeze-venv/Scripts/python.exe`
and `.tools/dotnet/dotnet.exe` exist; venv metadata says Python 3.13.15,
installed PyInstaller metadata is 6.22.3, and the local SDK directory is 8.0.426.
These version observations are filesystem metadata, not executed version probes.
All 15 task wheelhouse hashes match the retained audit, and the current pyproject
SHA256 matches its audited value
`da60833ff11e6f9b84299fd7c5c6deb8a33fef5eae3964df693adc29a65830af`.
The freeze helper must still recheck installed analyzer bytes and probe toolchain.

## Ordered commands for root

All paths below are repository-relative examples; choose fresh output names.
Do not invoke the historical installer BAT: it deletes shared build/dist paths.

1. Stabilize source and finish relevant Python/native checkpoint. Freeze helpers
   refuse changed release inputs; do not copy current digests onto old proofs.
2. Capture native inputs, publish, capture again, and **assert** `inputs_unchanged`
   is true and both EXE/DLL artifacts exist. The fingerprint helper only records
   this boolean and does not fail its exit code on false.

```powershell
$env:DOTNET_ROOT = [IO.Path]::GetFullPath('.tools/dotnet')
$env:DOTNET_CLI_HOME = [IO.Path]::GetFullPath('.tools/dotnet-home')
$env:NUGET_PACKAGES = [IO.Path]::GetFullPath('.tools/nuget-packages')
& .venv/Scripts/python.exe .tmp/native_build_fingerprint.py before <new-native-evidence> <new-native-publish>
& .tools/dotnet/dotnet.exe publish desktop/windows/AttackMap.NativeSpike/AttackMap.NativeSpike.csproj -c Release -r win-x64 --self-contained true --no-restore -p:UseSharedCompilation=false -o <new-native-publish>
& .venv/Scripts/python.exe .tmp/native_build_fingerprint.py after <new-native-evidence> <new-native-publish>
```

3. Prepare and freeze immutable source inputs with the existing helper:

```powershell
& .venv/Scripts/python.exe docs/verification/windows-parity/WP024/fresh_freeze.py --root-released --repo . --output <new-freeze-root> --freeze-python .tools/wp024-freeze-venv/Scripts/python.exe --dotnet .tools/dotnet/dotnet.exe --analyzer-audit docs/verification/windows-parity/WP024/cached-analyzer-audit-2026-10-21.json --wheelhouse .tools/wp024-wheelhouse --build
```

The helper copies exact source/native/package inputs, checks wheel and installed
bytes, generates the lock, builds via `installer/attackmap.spec`, verifies core
TOC origins, and checks source stability. It produces `build-proof.json`, not
runtime `engine-verification.json`.

4. Execute fresh frozen `--version`, `modules`, capabilities and actual broker
   scan/compare with isolated profile and no external Python on child PATH.
   Capture full capabilities and terminal responses. A fresh engine-verification
   record must carry the actual version/exe/payload hashes; modules count >=15;
   native broker command presence; completed scan with ready artifacts; completed
   compare; and exact release/source/analyzer/lock digests. Root prepared
   `RESUME-2026-10-22/astra-high/qualify_fresh_engine.py` during this review:

```powershell
& .venv/Scripts/python.exe docs/verification/windows-parity/RESUME-2026-10-22/astra-high/qualify_fresh_engine.py --freeze <new-freeze-root> --output <new-runtime-proof>
```

Read-only review confirms the current CLI supports its network-free `modules
--json`, capabilities identity, current-generation pointer and compare result
hash formats. The command owns suspended process trees in Jobs and keeps stdin
open for the broker protocol. Review recommended binding every terminal identity
field and terminal artifact path, and rechecking the release-lock bytes at the
end. Actual execution/results remain root-owned.
5. Package the approved fresh pair and generate SBOM outside the immutable stage:

```powershell
pwsh -NoProfile -File tools/package_native_windows.ps1 -Profile RequiredBundled -PublishDirectory <new-native-publish> -OutputDirectory <new-packages> -EngineDirectory <new-freeze-root>/dist/attackmap -EngineVerificationPath <new-runtime-proof>/engine-verification.json -ReleaseLockPath <new-freeze-root>/release-lock.json -SourceRoot C:/Projects/INPROGRESS/AttackMap -PythonExecutable C:/Projects/INPROGRESS/AttackMap/.venv/Scripts/python.exe
& .venv/Scripts/python.exe tools/generate_release_sbom.py --package <new-stage> --output <new-sbom-root> --engine-venv .tools/wp024-freeze-venv
```

The SBOM engine-venv override is necessary: the historical default is absent.
6. Complete isolated installed bundled scan qualification. Then use WP017
   preflight against `<new-stage>/app/AttackMap.NativeSpike.exe`, with absolute
   seed/output paths and `--release-lock <new-freeze-root>/release-lock.json`.
   Review the returned identity, then add `--manifest-sha256 <reviewed-pin> --run`.
   Retain each mode's terminal/process/export/audit evidence and visually review
   every Reports capture. Keep FINISHED and retained packages unchanged.
