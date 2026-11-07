<!-- ATTACKMAP_DOC_STATUS: HISTORICAL_REFERENCE -->
> **STARÝ DOKUMENT — pro agenty nerelevantní jako aktuální plán nebo zadání (20. 10. 2026).**
> Práci řídí pouze dokumenty v [aktuálním rozcestníku](README.md). Tento text je historická reference: neobnovovat jeho TODO, priority ani statusy dokončení. Technické podklady a kritéria použít jen v rozsahu potřebném pro aktivní WP úkol a ověřit proti aktuálnímu kódu.

# Windows development package

> **20 October 2026 clarification:** package descriptions below include the historical October 15 M3 baseline. The [current audit](windows-parity-audit-2026-10-20.md) records the newer `dev-20261019192050-b678aee2` manifest (bundled engine, unsigned development channel) and October 19 delivery record for the Windows PowerShell 5.1-compatible installer plus `Install-AttackMap.cmd`. This audit did not rerun clean-host qualification. Packaging and release follow-up is in WP024/WP025 of the [new TODO](windows-parity-todo.md).

**Workspace cleanup (2026-10-16):** only the latest accepted Windows package is retained. Final raw evidence was moved without changing its bytes to `desktop/windows/verification/retained-m3/`; its relocation manifest maps the historical paths below. Older builds and disposable raw QA campaigns were removed. The local .NET SDK/NuGet toolchain now lives under `.tools/`. See `desktop/windows/README.md` for current development commands.

Accepted Windows M3 functional beta (2026-10-15, user-scoped acceptance): `dev-20261015190038-5667bbbf.zip`, containing the
native shell and frozen engine. Exact identities and acceptance scope are in the
[Windows acceptance ledger](windows-m3-acceptance.md). Windows 11 performance
qualification is not a Windows M3 prerequisite. Remaining participant/manual UX
and accessibility validation is scheduled in M4, not reported as passed.

This is an unsigned, unpackaged x64 development preview for Windows 10 build
19041 or later. It is not the signed public release installer (C29), and does
not establish clean-machine compatibility.

Use PowerShell 7.2 or later to package an existing, completed native publish:

```powershell
pwsh -File tools/package_native_windows.ps1 -PublishDirectory desktop/windows/artifacts/native-spike
```

The output ZIP, adjacent SHA-256 file and `package-manifest.json` describe the
exact copied payload. The manifest records individual file hashes and sizes,
the included .NET framework version, Windows App SDK 2.4.0, architecture and
engine requirements. Smoke diagnostics, logs and PDBs are excluded. Checksums
detect accidental modification; they do not authenticate this unsigned package.

The native publish includes .NET and Windows App SDK runtime files. The package
has not been checked on a clean Windows installation; remaining native OS,
Visual C++ or WebView2 prerequisites have not been independently audited.
Self-contained publish flags alone do not prove that every prerequisite is bundled.
Without `-EngineDirectory`, the package
does **not** bundle Python, AttackMap core, analyzers, AI SDKs or models. Select
an absolute Python executable with compatible `attackmap.desktop_worker` and
`attackmap.desktop_actions` modules installed. The current development checkout
is the verified engine; compatibility with an arbitrary released wheel is not
claimed. Installation neither searches PATH nor downloads an engine. AI remains
optional and off by default. A local provider must be installed separately.

An optional verified frozen engine can be included:

```powershell
pwsh -File tools/package_native_windows.ps1 -EngineDirectory .pytest_cache/m3-frozen-engine/dist/attackmap
```

The engine directory must contain `attackmap.exe` and `engine-verification.json`
(or supply `-EngineVerificationPath`). Verification must record successful version,
analyzer discovery, frozen scan publication and comparison-action checks, plus
the executable hash and every payload file's hash and size. Missing, extra or
changed files are refused. This is local development evidence, not a signature.
The manifest records the exact `app/engine/attackmap.exe` path, frozen runtime
kind, source-checksum digest and verification digest. Frozen payloads include
their Python runtime, core, pinned analyzers and dependencies; models are not
included. The native app selects the exact bundled path only when no engine
path is configured, and does not execute it until the user requests an action.
An explicit saved engine path remains the user's choice.

Native launch uses argument lists: Python receives `-m attackmap.desktop_worker`
or `-m attackmap.desktop_actions`; a frozen executable receives `desktop-worker`
or `desktop-action`. An explicit runtime kind wins. For compatibility, only the
exact executable name `attackmap.exe` implies frozen mode when the kind is
omitted; other names default to Python. There is no binary probing or PATH lookup.

After extracting the ZIP, install without elevation or shell registration:

```powershell
pwsh -File ./Install-AttackMap.ps1
```

The default destination is `%LOCALAPPDATA%/Programs/AttackMapDevelopment`.
`-InstallRoot` selects another new directory, useful for isolated verification.
Existing unowned directories, redirects and modified application payloads are
refused. The script prints the installed executable path; launch that executable.
There are no desktop shortcuts, Start menu entries, file associations or registry
changes.

Each installation keeps a separate immutable `versions/<package-id>` payload.
`current.json` selects the installed version only after checksum validation.
Prior versions remain available; updates do not migrate or delete settings.
If copy or verification fails, the prior current selection remains. An incomplete
`.stage-*` folder may remain for inspection and will block uninstall until the
user reviews it. There is no automatic garbage collection.

To select a retained version, run the extracted installer with:

```powershell
pwsh -File ./Install-AttackMap.ps1 -Mode Rollback -Version dev-YYYYMMDDHHMMSS-xxxxxxxx
```

Launch the executable in that selected version directory. `current.json` is an
installation selection record, not a launcher or report publication pointer.

To uninstall, use the same installation root:

```powershell
pwsh -File ./Install-AttackMap.ps1 -Mode Uninstall
```

Uninstall verifies every owned payload before deleting application versions.
Unexpected or modified files cause refusal. It leaves empty installation folders
and unrelated root files. It preserves `%LOCALAPPDATA%/AttackMap`, including
settings, protected credentials, reports and action recovery snapshots. Rollback
changes only the application version selection, so compatibility with settings
written by a newer version must be checked before downgrading.

Validation covers isolated directory install, repeated install, upgrade,
rollback, tamper refusal and uninstall preservation. Real per-user desktop
installation, clean Windows VM behavior, signing, SmartScreen reputation and
public update delivery remain separate release work.

## Release readiness tooling (AM041 / C29 preparation)

Three offline, deterministic tools prepare the unsigned development channel
for release review. None of them signs anything: no certificate exists, and
every output records that limitation honestly. Checksums verify content only;
they never authenticate origin, and no signed or notarized status is claimed
(notarization is not applicable on Windows).

- `tools/generate_release_sbom.py --package <package-dir> --output <target-dir>`
  re-verifies every size and SHA-256 recorded in `package-manifest.json`, then
  writes `release-sbom.json` into the caller-chosen target directory, which
  must live outside the immutable package. The SBOM lists the package identity,
  channel, architecture, the .NET and Windows App SDK versions, the bundled
  frozen engine identity (version, analyzer count, verification and
  source-checksum digests), every packaged file with size and SHA-256, and the
  Python dependency inventory from the freeze venv's `pip freeze`
  (`.pytest_cache/am043-package/engine-venv` by default, overridable with
  `--engine-venv`). When the venv is absent, or the package bundles no engine,
  it records the dependency inventory as unknown with the reason instead of
  guessing. Tampered payloads, edited manifests, redirected entries or
  unexpected files are refused and nothing is written.
- `tools/generate_release_lock.py --output <target-dir>` captures the exact
  build inputs: a file-by-file SHA-256 inventory over `src/`, `installer/`,
  `pyproject.toml` and `README.md` (excluding `__pycache__` and `*.egg-info`),
  serialized in the same canonical form as the frozen-engine
  `source-checksums.json`, so its `source_checksums_sha256` digest compares
  directly with engine verification digests. It also records the freeze venv's
  Python and PyInstaller versions and the local .NET SDK version from
  `.tools/dotnet` when present, reporting unknown with a reason otherwise.
  `--reference-source-checksums` compares the current inventory against a prior
  snapshot and records whether they match.
- `tools/test_release_rollback.ps1` builds two synthetic fixture packages with
  the real packager and drives the installer's own modes: install v1, create a
  user file in the install root, install v2, rollback to v1 (current.json
  points at v1 again, the user file survives and both version payloads are
  retained), rollback to an unknown ID is refused, and uninstall after rollback
  removes both versions while preserving the user file. It prints its test root
  and writes `rollback-test-result.json` there.

`tests/test_release_tooling.py` validates both generators against a synthetic
package and repository built in `tmp_path`: schema shape, recomputed hash
correctness, refusal of tampered payloads and manifests, refusal to write
inside the immutable package, deterministic reruns, the unknown-dependency
fallback, and byte-exact reproduction of the am043 canonical checksum format.

Remaining C29 gaps: no code-signing certificate (everything stays unsigned and
must state so), no clean-machine validation, SmartScreen reputation untested,
and no upgrade-from-a-previous-real-release test with production settings.
