# Release checklist

Use this checklist before tagging a release or publishing a Windows build.

## Reproducible core baseline

The core CI matrix covers Ubuntu, macOS, and Windows with Python 3.11, 3.12,
and 3.13. Node.js 22 is required for the shipped frontend cache regression
tests; it is a development/test dependency, not an engine runtime dependency.
Install the checkout in an isolated environment so CLI subprocess tests import
the same source tree:

```powershell
py -3.13 -m venv .venv
.venv\Scripts\python.exe -m pip install -e ".[llm,dev]"
node --version
.venv\Scripts\python.exe -m pytest --collect-only -q
.venv\Scripts\python.exe -m pytest -q -ra
```

Record the interpreter/dependency versions, commit plus local changes, and every
skip reason. A local Windows run does not establish that the full CI matrix or
frozen package passed. Keep pytest temporary directories outside a Git checkout
when testing behavior for non-Git directories. For live AI testing, follow the
local LM Studio configuration and Juice Shop target in
[project facts](project_notes/key_facts.md#current-source-and-targeted-testing-2026-10-15).

## Version identity

- [ ] `src/attackmap/__init__.py` contains the intended version.
- [ ] `CHANGELOG.md` has a section for that version (or `[Unreleased]` if cutting a pre-release).
- [ ] `README.md` status badge and any inline version strings match.
- [ ] `docs/project_notes/key_facts.md` reflects the same version.
- [ ] `python -m attackmap --version` prints the same version from source.
- [ ] Frozen Windows build: `dist\attackmap\attackmap.exe --version` prints the same version.

## Analyzer count

- [ ] `README.md` and `docs/project_notes/key_facts.md` agree on the number of analyzer plugins.
- [ ] `pyproject.toml` `[project.optional-dependencies] all` contains that many analyzer packages.

## Smoke tests (source)

```bash
python -m attackmap --version
python -m attackmap capabilities
python -m attackmap modules --json
python -m pytest tests/test_ui.py tests/test_cli_validation.py tests/test_fleet.py tests/test_main_module.py tests/test_scan_service.py tests/test_ui_spawn.py tests/test_suppress_write.py -q
```

## Smoke tests (Windows build)

```powershell
dist\attackmap\attackmap.exe --version
dist\attackmap\attackmap.exe capabilities
dist\attackmap\attackmap.exe modules --json
# minimal scan
New-Item -ItemType Directory -Path C:\tmp\smoke-repo | Out-Null
"x = 1" | Out-File -Encoding utf8 C:\tmp\smoke-repo\app.py
.\dist\attackmap\attackmap.exe analyze C:\tmp\smoke-repo --format json
# cancellation: start a larger scan and interrupt via GUI or taskkill
# clean shutdown: ensure no attackmap.exe remain after the window closes
taskkill /IM attackmap.exe /F 2>$null
```

## Artifacts

- [ ] Windows onedir build succeeded: `dist\attackmap\attackmap.exe` exists.
- [ ] Installer/distribution folder includes the whole `dist\attackmap` directory.
- [ ] Hashes or signatures are generated if this is a public release.

## Documentation

- [ ] `CHANGELOG.md` entry added/updated.
- [ ] `README.md` install instructions and version strings updated.
- [ ] `CONTRIBUTING.md` Windows build steps still match `installer/build-installer.bat`.
