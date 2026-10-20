# WP001 baseline — 20 October 2026

This directory distinguishes the dirty source tree, the 19 October audit candidate, the newer retained candidate, the default installation selection, and the accepted 15 October M3 binary. These roles must not be collapsed into a single "current package" claim. `baseline.json` and adjacent command outputs are the execution record.

Reproduce from the repository root with:

```powershell
python docs/verification/windows-parity/WP001/capture.py
```

The Python capture independently validates every listed file size and SHA-256, inventories extra files, and compares each ZIP against its adjacent checksum. Checksum validation establishes local integrity, not publisher authentication. No package is rebuilt or installed.

The existing-tool check was also executed with `pwsh -NoProfile -File docs/verification/windows-parity/WP001/capture.ps1`. That script parses the audit candidate's existing `Install-AttackMap.ps1` and executes only `Assert-NoLinks` and `Validate-Payload`; installer top-level code is never executed. Both retained candidates passed its strict validation. It then rejected the default installed folder with `Unrecognized file in owned version; refusing deletion or activation.` Independent inventory identified `app/engine-guard-smoke.json` and `app/scan-smoke.json` as extra files. Every listed installed payload file matches its hash; strict installed validation remains **FAIL**, and these two files were preserved. This command intentionally still reproduces the strict rejection and exits nonzero before writing its baseline. `capture.py` is the successful complete evidence recorder.

The audit candidate is `dev-20261019192050-b678aee2`; the newer retained candidate is `dev-20261019201436-7d3584c4`. Default `%LOCALAPPDATA%/Programs/AttackMapDevelopment/current.json` is inspected independently. This does not enumerate arbitrary custom installation roots or prove which process a user last launched. Engine `--version` and `modules --json` probes use the audit candidate's exact bundled executable and write their raw output here; no scan/provider/model call is made.

Source version is defined by `src/attackmap/__init__.py`, not a package manifest. Package engine verification and source-checksum digests are preserved as manifest assertions; those assertions do not prove the frozen engine was built from this dirty checkout. The source status and pre-existing `tools/package_native_windows.ps1` diff are captured without editing that file. A concurrent roadmap wave may add files during this snapshot; the UTC timestamp and exact status inventory bound the observation.

Historical M3 acceptance remains bounded to `dev-20261015190038-5667bbbf`, accepted 15 October as a Windows functional beta with limitations on the development host. Participant C19, manual workflow/UX C21/C25, and manual accessibility/Narrator C24 remain unverified and carried forward. Windows C26 was removed by user decision. No acceptance transfers to either 19 October binary; no clean-host, signed release, macOS, or complete original-prerequisite acceptance is implied.

The historical acceptance ledger and retained relocation manifest are checked for existence and hashed before reference. Historical old paths may have been moved: the retained relocation map is the locator. Existing archived operational documents contain conflicting dated roles (for example the 15 October "Current package" heading versus the later audit candidate); this directory supplies explicit dates/roles without rewriting immutable historical evidence. Root-owned active tracker links should point here.

Focused evidence validation:

```powershell
python docs/verification/windows-parity/WP001/test_baseline.py
```

This check verifies the recorded role separation, source identity, package inventory counts, runtime probe output digests, and installed/package engine identity. It does not run product acceptance tests. `early-modules.json` is an additional successful preflight probe taken while full payload validation ran; the canonical count and exact probe outputs are those referenced by `baseline.json`.

