# WP024 read-only packaging preflight — 2026-10-20

WP024 remains IN_PROGRESS. No product package was built, no installer/current install/retained package was edited, and the pre-existing user diff is preserved.

This records the initial read-only slice, before the subsequently authorized implementation. See [implementation.md](implementation.md) for the new behavior and separate implementation verification; the initial findings below are not claims that those gaps remain unpatched.

## Existing user diff

`tools/package_native_windows.ps1` adds `Validate-Payload -TolerateExtras`, file-specific mismatch diagnostics and extra-file warnings. Only incoming extraction-source validation passes the switch. Required files still require matching size/hash, and staged/owned versions, rollback and uninstall remain strict. Only app and package manifest are copied into owned staging, followed by strict validation. Preserve this intent when leasing the script. WP001 records two installed smoke JSON extras failing strict validation; this audit neither removes them nor calls that release acceptance.

## Current behavior and gaps

| Area | Current behavior | Minimal follow-up |
| --- | --- | --- |
| Profile | EngineDirectory optional; omission produces bundled=false and Python-selection instructions. | Explicit required-bundled profile; refuse absent engine/proof before staging. Name external-engine profile explicitly. |
| Identity | Unique dev timestamp/random suffix; unsigned-development channel. | Keep unique ID, bind source/toolchain/analyzer identities. |
| Freeze | Checks executable/payload hashes, minimum 15 modules, scan/action readiness. Copies source_checksums_sha256 without comparison to current lock. | Refuse stale-but-byte-valid freeze using independent current source/analyzer lock. |
| Tamper | Refuses changed/missing listed bytes, unexpected engine files, reparse points and missing proof entries. | Sentinel alteration/deletion/addition tests, preserving prior current selector. |
| Lock | generate_release_lock covers src, installer, pyproject, README; records Python/PyInstaller/.NET versions. Unknown tools and reference mismatch are reported rather than package-enforced. | Include relevant desktop/package scripts and exact analyzer dependency/source identity; define required-profile failure policy. |
| SBOM | Verifies listed payload and optional Install-AttackMap.ps1, rejects other files. | Current Install-AttackMap.cmd is rejected as unexpected. Add exact launcher inventory/hash, retain strict extra refusal. |
| Signing | Honest unsigned limitations; no certificate/signing step in builder. | Explicit unsigned/signed seam, sign before final hashes/SBOM/archive, verify signer policy. Actual signing is WP025. |
| PS5.1 | Generated cmd prefers pwsh then powershell; installer avoids Core-only path/move overloads; builder requires PS7.2. | Actual generated installer run under PS5.1; preserve child exit code through echo/pause and allow scripted noninteractive use. |
| Self-exe | EngineLaunchSpec rejects Environment.ProcessPath and marker-free Python-kind binaries before spawning. | Existing tests use marker-free Python fake EXEs, so fixtures conflict with current guard. Add marker fixture and self-exe/unrelated-exe rejection assertions; do not weaken guard. |

Hashes against an unsigned manifest prove byte agreement, not publisher authenticity. Minimum module count does not lock analyzer identity. A valid old frozen tree can pass byte checks while differing from current source.

## Tests and exact proposed leases

`tools/test_native_windows_package.ps1` was inspected but not run: it builds synthetic packages and performs isolated install/repeat/upgrade/rollback/tamper/uninstall, outside this no-package-build slice. Its engine case checks unverified optional engine refusal, not required-engine absence, stale source, PS5.1 launcher, bundled scan without Python in PATH, signing or exact analyzer inventory.

For root lease decision, propose:

1. `tools/package_native_windows.ps1`: preserve incoming-extra policy; add explicit profiles and required-engine/current-lock preflight before staging, launcher exit propagation and unsigned metadata.
2. `tools/generate_release_lock.py`, `tools/generate_release_sbom.py`, `tests/test_release_tooling.py`: source/analyzer bindings, launcher inventory and focused mismatch/tamper cases.
3. `desktop/windows/EngineLaunchSpec.Tests/Program.cs`: valid Python marker fixture and self-exe guard coverage. No production EngineLaunchSpec change justified yet.
4. `tools/test_native_windows_package.ps1`: required-engine/freshness/sentinel/PS5.1 cases, executed only after approval of isolated package-building scope.

No implementation lease is claimed by this report. Full DoD still requires a new unsigned package ID and installed bundled scan without Python in PATH in an isolated test root, preserving all retained packages.

## Focused verification record

Initial command: `.venv/Scripts/python.exe -m pytest tests/test_release_tooling.py tests/test_windows_release.py tests/test_installer_entry.py -q --basetemp docs/verification/windows-parity/WP024/pytest-temp`: **1 failed, 10 passed, 14 errors**. Setup errors were WinError3 because the evidence parent had not yet been created; these are not release-tooling test failures. `test_actual_cli_help_with_forced_legacy_redirected_output` timed out after 30 seconds. No pass is inferred for that test. Initial PATH `dotnet run` failed because PATH dotnet has no SDK. Bundled SDK harness result recorded separately when available. Directory creation required approved execution after apply_patch could not create the parent.

After creating the evidence directory, the approved focused retry of `tests/test_release_tooling.py tests/test_windows_release.py` with the same isolated basetemp and `--junitxml docs/verification/windows-parity/WP024/pytest-results.xml` passed **21 tests in 24.98 seconds**. This validates existing synthetic release-helper/spec behavior; it does not cover the new gaps above or constitute package/install acceptance.

The repository SDK compiled the existing EngineLaunchSpec harness into `WP024/dotnet-artifacts`. `dotnet run --artifacts-path` then attempted the default bin launch path, so the compiled DLL was executed directly. It reproduced `InvalidDataException: 'renamed.exe' is not a recognized engine executable` at `EngineLaunchSpec.cs:36`, called by `EngineLaunchSpec.Tests/Program.cs:17`. This is the predicted fixture/marker mismatch; it is not a reason to weaken the product guard.
