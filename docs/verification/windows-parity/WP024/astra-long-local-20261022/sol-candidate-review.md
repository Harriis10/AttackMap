# Fresh long-local candidate helper review — 2026-10-22

Reviewer: GPT-6.1 Sol / medium. Static review only. No build, installer, native app, provider request, GUI, or retained-evidence mutation was performed by this reviewer.

## Verdict

`build_engine.py`, reused `publish_fresh_native.py`, and reused `qualify_fresh_engine.py` are suitable for root-owned sequential execution with the exact new paths below, after source integration is stable. Packaging remains conditional on the freshly produced runtime and native proofs. This is readiness evidence, not runtime acceptance.

All five original helper locations use `Path(__file__).resolve().parents[5]`, which resolves to `C:\Projects\INPROGRESS\AttackMap` from their current locations. The new installed verifier is at the same directory depth.

The original installed verifier cannot qualify this candidate: it pins the previous engine SHA and defaults to the previous native build proof. A new `verify_installed_candidate.py` preserves its checks and default read-only preflight, requires explicit `--engine-sha256` and `--native-proof`, and adds required `--helper-sha256` validation plus helper/engine identity records. Original helper unchanged. New helper SHA-256 at review: `1692d9c7b072f3b453f962954483a5dc49e44564a637fa2fdd0df470f5667a32`. Independent review remains required before root execution. Static AST parsing passed; no helper was executed.

## Safeguards and limitations

- Freeze: refuses existing freeze and evidence roots; snapshots release inputs, verifies original and copied bytes, attests installed analyzers against pinned cached wheel bytes, checks TOC module origins, and compares current/snapshot input inventories after building. The wrapper gives its process and descendants a suspended-before-assignment Windows Job, a 1200-second deadline, and verified owned-job cleanup.
- Native publish: refuses existing output roots and requires workspace containment. Binds source release inventory, linked fixture, resolved project assets, and produced EXE/DLL hashes; before/after input equality is mandatory.
- Runtime qualification: checks current source digests against the freeze lock, lock/build binding, complete engine payload before/after, executable identity, real Juice Shop scan artifact checksums/current pointer, and frozen compare result identity. Every broker command has its own Job and cleanup verification. This scan disables AI and CVE.
- Package: refuses existing output/package roots, requires workspace containment, binds current release digests to lock/native proof, verifies published and staged native artifacts, validates manifest/package identity and archive digest, and requires known SBOM Python dependencies. Package/source equality is checked after packaging; package identity is checked again after SBOM.
- Installed candidate: preserves no-link/hardlink and exact installed-tree inventory checks, new-only/disjoint workspace install/evidence roots, reviewed manifest pin for `--run`, explicit bundled engine, source/native proof binding, isolated scan settings, exact report/artifact/pointer identity, installed/original package unchanged checks, and Job-owned installer/native execution.
- Existing limitations: `qualify_fresh_engine.py` does not itself enforce workspace containment or disjoint input/output roots. Build/publish/package helpers use simpler resolved-path checks rather than the installed helper's comprehensive link checks; publish/package do not reject nested output roots. Use exactly the distinct workspace paths below and do not substitute aliases/junctions. A malicious/racing workspace is outside this static approval.
- Qualification's 660-second deterministic broker timeout is unrelated to the later explicit long AI budget. Packaging's SBOM subprocess does not repeat the source inventory check after SBOM, though package identity is repeated; preserve the source lease through that step.
- `native.launch` owns only its created process/descendants, never process names or the LM Studio server. It assigns the suspended process before resume, terminates the owned job, waits for active count zero, and records assignment/exit/cleanup in `process.json`. Successful parent exit alone is insufficient; inspect those records before proceeding.

## Root-only sequential commands

Run from the workspace. Stop at any failed command or missing/false proof. These commands do not authorize changing old candidates, the FINISHED copy, or retained WP024 DONE evidence. Do not reuse partially created output directories; choose and review a new suffix after failure.

```powershell
$repo = 'C:\Projects\INPROGRESS\AttackMap'
$python = Join-Path $repo '.venv\Scripts\python.exe'
$proof = Join-Path $repo 'docs\verification\windows-parity\WP024\astra-long-local-20261022'
$helpers = Join-Path $repo 'docs\verification\windows-parity\RESUME-2026-10-22\astra-high'
$freeze = Join-Path $repo '.tmp\wp024-astra-long-local-20261022-01'
$publish = Join-Path $repo 'desktop\windows\artifacts\integrated-20261022-astra-long-local'

# 1. Freeze after final source review and integration lease release.
& $python (Join-Path $proof 'build_engine.py')
if ($LASTEXITCODE -ne 0) { throw 'Freeze failed' }

# 2. Actual direct frozen broker qualification, with AI disabled.
& $python (Join-Path $helpers 'qualify_fresh_engine.py') --freeze $freeze --output (Join-Path $proof 'runtime')
if ($LASTEXITCODE -ne 0) { throw 'Frozen runtime qualification failed' }

# 3. Full product publish from the unchanged source state.
& $python (Join-Path $helpers 'publish_fresh_native.py') --publish $publish --output (Join-Path $proof 'native-build')
if ($LASTEXITCODE -ne 0) { throw 'Native publish failed' }

# 4. New unsigned RequiredBundled package and SBOM.
& $python (Join-Path $proof 'package_candidate.py') --output (Join-Path $proof 'package-evidence') --packages (Join-Path $proof 'package-stages') --freeze $freeze --proof $proof --publish $publish
if ($LASTEXITCODE -ne 0) { throw 'Package qualification failed' }

# 5. Review these generated records and pin their exact bytes before executing.
$package = Get-Content -LiteralPath (Join-Path $proof 'package-evidence\summary.json') -Raw | ConvertFrom-Json
$engineBuild = Get-Content -LiteralPath (Join-Path $freeze 'build-proof.json') -Raw | ConvertFrom-Json
$stage = $package.package
$manifestPin = $package.manifest.sha256
$enginePin = $engineBuild.exe_sha256
$helper = Join-Path $proof 'verify_installed_candidate.py'
$helperPin = '1692d9c7b072f3b453f962954483a5dc49e44564a637fa2fdd0df470f5667a32'
$seedFiles = @(Get-ChildItem -LiteralPath (Join-Path $proof 'runtime\reports') -Filter 'attackmap-report.json' -File -Recurse)
if ($seedFiles.Count -ne 1) { throw 'Expected exactly one qualified runtime seed' }
$seed = $seedFiles[0].FullName
$install = Join-Path $repo '.tmp\wp024-astra-long-local-installed-20261022-01'
$installedProof = Join-Path $proof 'installed-native'
$verifyArgs = @('--stage', $stage, '--release-lock', (Join-Path $freeze 'release-lock.json'), '--seed', $seed, '--install-root', $install, '--output', $installedProof, '--native-proof', (Join-Path $proof 'native-build\native-build.json'), '--manifest-sha256', $manifestPin, '--engine-sha256', $enginePin, '--helper-sha256', $helperPin)

# Read-only preflight first; it starts no installer, native app, or provider.
& $python $helper @verifyArgs
if ($LASTEXITCODE -ne 0) { throw 'Installed candidate preflight failed' }

# 6. Only after independent helper review and pin/proof review above.
& $python $helper @verifyArgs --run
if ($LASTEXITCODE -ne 0) { throw 'Installed native qualification failed' }
```

The installed/native gate does not complete the remaining Hunt+verify, Remediate, Triage, Reports appearance, normal-startup, keyboard/Narrator, 200-percent text, signing, clean-host, macOS, or human beta gates. Root retains the exclusive local-provider and GUI slots for subsequent work.
