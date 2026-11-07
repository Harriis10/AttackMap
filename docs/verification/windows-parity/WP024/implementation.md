# WP024 implementation slice

The builder now defaults to `RequiredBundled`. `ExternalEngine` is an explicit development profile for a desktop requiring a separately selected engine; it rejects EngineDirectory. Neither profile signs or publishes anything.

For `RequiredBundled`, generate a release lock from the intended immutable source snapshot and exact freeze toolchain with `tools/generate_release_lock.py`. The freshly verified frozen-engine proof must additionally record `source_checksums_sha256`, `release_inputs_sha256`, `analyzer_requirements_sha256`, and `release_lock_sha256` (the SHA-256 of the exact lock file). These are part of the freeze's provenance contract; do not add them to an old retained proof to make it pass. The builder recomputes current inputs from disk, including additions, and refuses mismatches or unknown required toolchain versions before creating the package output. The analyzer requirements digest binds the configured pinned dependency requirements; it is not an independent audit of installed analyzer source provenance. The frozen payload inventory binds the actual packaged bytes.

Example for a **new** freeze only:

```powershell
./.venv/Scripts/python.exe tools/generate_release_lock.py --output <new-evidence-root> --engine-venv <exact-freeze-venv> --dotnet .tools/dotnet/dotnet.exe
./tools/package_native_windows.ps1 -Profile RequiredBundled -PublishDirectory <new-native-publish> -EngineDirectory <new-verified-freeze> -ReleaseLockPath <new-evidence-root>/release-lock.json -OutputDirectory <new-package-root>
```

Do not use angle-bracket placeholders literally. Build and verify the freeze against that lock before packaging. A supplied unsigned proof remains an attestation by the local build process; hashes do not authenticate a publisher. The signing seam records unsigned status and requires signing before final hashes/SBOM/archive when WP025 adds a signed profile.

The cmd launcher preserves child status and skips its interactive pause when `ATTACKMAP_INSTALL_NONINTERACTIVE=1`. New manifests record exact deployment script and launcher hashes. SBOM generation verifies those hashes while continuing to reject unrelated extra files. The user-authored incoming-extraction TolerateExtras behavior remains intact; installed/staged/rollback/uninstall validation stays strict.

The expanded packaging smoke uses only synthetic executables and a synthetic source/lock/proof under a unique test root. Its claimed scan/action flags are explicitly synthetic fixture inputs, not executed scans. It exercises missing-required-engine refusal, stale source, changed/deleted/extra frozen sentinels, successful bundled-profile packaging, Windows PowerShell 5.1 installer execution, and cmd success/failure exit propagation. Its package ID/hash are written to `package-smoke.json` in that root. It does not prove a real bundled engine scan without Python in PATH, clean-machine acceptance, or signing.

Production EngineLaunchSpec is unchanged. Its tests supply a static Python-layout marker, then remove it to verify rejection, and explicitly reject the currently running test executable as an engine.

Verification: 23 focused Python release tests passed, 24 EngineLaunchSpec checks passed, the isolated synthetic packaging smoke passed, and the actual SBOM generator verified the new fixture package. After adding the exact release-lock digest to SBOM metadata, the two relevant SBOM tests passed again and the fixture SBOM was refreshed. The Windows PowerShell executable used for installation reports version 5.1.19041.7802. See `implementation-verification.json`, `focused-final.xml`, `package-smoke.log`, and `smoke-20261020-implementation/package-smoke.json` for scope and package identity. WP024 remains IN_PROGRESS; no real bundled scan without Python in PATH is claimed.
