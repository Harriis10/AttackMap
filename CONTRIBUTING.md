# Contributing to AttackMap

Thanks for your interest in improving AttackMap. This document describes how to
set up a development environment, run the tests, and submit changes.

## Code of Conduct

This project adheres to the [Code of Conduct](CODE_OF_CONDUCT.md). By
participating, you agree to uphold it. Report unacceptable behavior to
[mlaify@mlaify.io](mailto:mlaify@mlaify.io).

## Getting started

AttackMap is a Python package. Development requires Python 3.11+.

```bash
git clone https://github.com/mlaify/AttackMap.git
cd AttackMap
python -m venv .venv
source .venv/bin/activate  # On Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -e ".[llm]"
```

On Windows, use the equivalent PowerShell steps:

```powershell
git clone https://github.com/mlaify/AttackMap.git
cd AttackMap
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e ".[llm]"
```

### Verifying the setup (machine-measured path)

Roadmap criterion C37 ("Delivery efficiency") expects a new contributor to
build the core and run its focused suite within 30 minutes, excluding
prerequisite tool downloads. [`scripts/verify_setup.py`](scripts/verify_setup.py)
walks that path and times each stage:

```bash
python scripts/verify_setup.py            # use the existing .venv
python scripts/verify_setup.py --fresh    # create a new .venv first
```

It checks the Python version (3.11–3.13, the CI-tested range), optionally
creates a fresh virtualenv, installs the project editable with the `dev`
extra, runs a fast representative focused-suite subset (`tests/test_run_contract.py`,
`tests/test_ui_contract_adapter.py`, `tests/test_desktop_workflow_fixtures.py`,
`tests/test_desktop_reference.py`, `tests/test_finding_identity.py`) and writes a JSON
timing record under `.pytest_cache/setup-verification/`. Useful flags:
`--skip-install` (reuse an already-installed environment), `--skip-suite`,
`--venv PATH`, `--budget-minutes N`.

Measured on 2026-10-18 (Windows 10 19045 x64, Python 3.13.15, existing
`.venv`, install stage skipped because dependencies were already installed):
python-check plus the focused subset (81 tests) completed in about 3–6
seconds of measured stage time, and creating a fresh venv in a temp directory
took about 15 seconds. First-time dependency installation needs network
access and is not part of those local numbers; the
[client contract fixtures](.github/workflows/client-contract-fixtures.yml)
CI workflow records the full fresh-venv flow on a clean runner. See
[`docs/delivery-efficiency.md`](docs/delivery-efficiency.md) for the honest
breakdown of what is machine-verified versus documented-only.

### Desktop development (Windows native app)

The proven Windows desktop build recipe (workspace-local .NET SDK, the
`dotnet publish` command, the synthetic fixture generator) is maintained in
[docs/project_notes/HANDOFF.md](docs/project_notes/HANDOFF.md) §8 and
[desktop/windows/README.md](desktop/windows/README.md). The fixture-backed
app verification modes (`--menu-smoke`, `--capture-smoke`,
`--readiness-smoke`, `--history-baseline-smoke`, `--retention-smoke`) are
implemented in `desktop/windows/AttackMap.NativeSpike/MainWindow.xaml.cs`,
with acceptance evidence in
[docs/windows-m3-acceptance.md](docs/windows-m3-acceptance.md). These steps
are documented from the retained M3 toolchain and its verification records;
they were not re-timed for this page.

To build the Windows GUI executable, install PyInstaller and run:

```powershell
installer\build-installer.bat
.\dist\attackmap\attackmap.exe --version
.\dist\attackmap\attackmap.exe ui
```

The build requires a Windows environment with Python 3.11+ on PATH and enough
privileges to create junctions/symlinks for `safe_write_text` tests (those tests
skip automatically if symlinks are not permitted).

To run the analyzer plugins locally, install each one editable from its sibling
repo:

```bash
pip install -e ../attackmap-analyzer-python
pip install -e ../attackmap-analyzer-rust
# ...and so on for the analyzers you want to develop against
```

## Running the tests

```bash
pytest
```

Analyzer plugins each carry their own `pytest` suite in their respective
repos. The full core suite is large, so while iterating on a change, run the
smallest relevant subset instead (for example the files listed in
`scripts/verify_setup.py`). Contract-relevant changes additionally trigger
the dedicated
[client contract fixtures](.github/workflows/client-contract-fixtures.yml)
CI workflow, which runs the run-contract golden corpus plus the desktop
client fixture suites; the main [CI matrix](.github/workflows/ci.yml) runs
the full suite on every push and pull request.

To accumulate per-run pass/fail records for flaky-test tracking
(roadmap C37), see [`tools/flaky_tracker.py`](tools/flaky_tracker.py):
record `pytest -q -rA --tb=no` outputs and print a per-test summary with
`python tools/flaky_tracker.py record <output.txt>` and
`python tools/flaky_tracker.py summary`.

## Eval harness

To grade a generated review against a golden fixture:

```bash
python -m attackmap.review_eval \
  --fixture evals/fixtures/bluesky-atproto-review-v1.json \
  --review evals/samples/bluesky-atproto-good-review.md
```

Suite mode:

```bash
python -m attackmap.review_eval \
  --fixtures-dir evals/fixtures \
  --reviews-dir evals/samples
```

## How to contribute

### Reporting bugs

Open a [bug report](https://github.com/mlaify/AttackMap/issues/new?template=bug_report.md)
using the issue template. Please include:

- AttackMap version (`attackmap --version` once available, otherwise commit SHA)
- Python version and OS
- Reproduction steps
- Expected vs. actual behavior

### Suggesting enhancements

Open a [feature request](https://github.com/mlaify/AttackMap/issues/new?template=feature_request.md).
For larger design changes, please open an issue *before* writing code so we can
align on direction.

### Submitting changes

1. Fork the repository.
2. Create a topic branch from `main`.
3. Make your change, including tests.
4. Run `pytest` and confirm everything is green.
5. Add a CHANGELOG.md entry under `[Unreleased]` for any user-facing change.
6. Open a pull request using the [PR template](.github/PULL_REQUEST_TEMPLATE.md).

### Code style

- Match the surrounding style; the project does not currently enforce a single
  formatter, but new code should be type-annotated and pass `python -m compileall`.
- Keep changes focused. Smaller, scoped PRs review faster.
- Every signal-emitting code path should carry a `file:line` citation, an
  evidence-text snippet, and a confidence score. See `src/attackmap/sdk/` for
  the analyzer SDK contract.

### Adding a new detector rule

Every rule id that `attackmap rules` lists needs a taxonomy entry: at least
one CWE and one OWASP category (Top 10 2021 or API Security Top 10 2023), plus
optional ASVS 4.0.3 and ATT&CK ids. Add one line to `RULE_TAXONOMY` in
[`src/attackmap/taxonomy.py`](src/attackmap/taxonomy.py); the module docstring
explains the fields. `tests/test_taxonomy.py` fails for any unregistered rule.
Look the ids up at cwe.mitre.org, owasp.org and attack.mitre.org rather than
from memory, and add any new CWE or technique to the catalogs in that file.

### Adding a new analyzer plugin

The full developer cookbook — scaffolding, the contract, testing, and
releasing — is in [`docs/external-analyzers.md`](docs/external-analyzers.md).
Use one of the existing plugin repos (Python or Go are the most thorough) as
a working template.

## Reporting security issues

Please do **not** open public issues for security vulnerabilities. Email
[mlaify@mlaify.io](mailto:mlaify@mlaify.io) — see
[SECURITY.md](SECURITY.md) for the full disclosure policy.

## License

By contributing to AttackMap, you agree that your contributions will be licensed
under the [MIT License](LICENSE).
