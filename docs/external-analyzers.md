<!-- ATTACKMAP_DOC_STATUS: HISTORICAL_REFERENCE -->
> **STARÝ DOKUMENT — pro agenty nerelevantní jako aktuální plán nebo zadání (20. 10. 2026).**
> Práci řídí pouze dokumenty v [aktuálním rozcestníku](README.md). Tento text je historická reference: neobnovovat jeho TODO, priority ani statusy dokončení. Technické podklady a kritéria použít jen v rozsahu potřebném pro aktivní WP úkol a ověřit proti aktuálnímu kódu.

# Writing an external AttackMap analyzer

This is the developer-facing guide for building an analyzer plugin that ships as
its own Python package in its own repo. If you only want to *use* analyzers, run
`pip install "attackmap[all] @ git+https://github.com/mlaify/AttackMap.git"` and stop reading.

The contract itself is documented in code at
[`attackmap.sdk`](../src/attackmap/sdk/__init__.py); this guide is the
"how to build one" companion. The two should always agree — if they don't,
the docstring is canonical and this file is wrong.

## What you're building

A small Python package that:

1. exposes a class satisfying [`AnalyzerProtocol`](../src/attackmap/sdk/contracts.py),
2. registers it under the `attackmap.analyzers` entry-point group, and
3. depends on `attackmap` for the contract types.

When a user runs `attackmap analyze /path/to/repo`, core discovers your plugin
via the entry-point group, asks each plugin's `detect()` whether it should run,
merges the `analyze()` outputs (per the rules in
[`merge.MERGE_SCHEMA`](../src/attackmap/merge.py)), and then owns everything
downstream: findings, attack paths, threat-model output, reports.

## Ownership boundary

| Owned by analyzers | Owned by core |
|---|---|
| `detect()` — is this a repo I should run on? | Discovering and loading analyzers |
| `analyze()` — emit structured signals with file/line citations | Merging results across analyzers |
| Surface-level normalization (path canonicalization, etc.) | Building the system graph |
|  | Generating findings + severity scores |
|  | Generating attack paths and threat-model output |
|  | Rendering CLI / JSON / markdown reports |

If you find yourself wanting to add finding generation, severity scoring, or
report rendering to an analyzer: emit a richer signal and let core do the
reasoning. That's how the system stays composable.

## Quick start

```
mkdir attackmap-analyzer-myframework
cd attackmap-analyzer-myframework
mkdir -p src/attackmap_analyzer_myframework tests
```

### `pyproject.toml`

```toml
[build-system]
requires = ["setuptools>=68", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "attackmap-analyzer-myframework"
version = "0.1.0"
description = "MyFramework analyzer plugin for AttackMap."
readme = "README.md"
requires-python = ">=3.11"
license = {text = "MIT"}
dependencies = [
  "pydantic>=2.7.0",
]

[project.optional-dependencies]
core = ["attackmap>=0.1.0"]
dev  = ["attackmap>=0.1.0", "pytest>=8.0.0", "build>=1.2.0"]

# This is what makes AttackMap discover your plugin.
[project.entry-points."attackmap.analyzers"]
myframework = "attackmap_analyzer_myframework:MyFrameworkAnalyzer"

[tool.setuptools]
package-dir = {"" = "src"}

[tool.setuptools.packages.find]
where = ["src"]
```

### `src/attackmap_analyzer_myframework/__init__.py`

```python
from .analyzer import MyFrameworkAnalyzer
__all__ = ["MyFrameworkAnalyzer"]
```

### `src/attackmap_analyzer_myframework/analyzer.py`

```python
from __future__ import annotations
from pathlib import Path

from attackmap.sdk import (
    AnalyzerMetadata,
    AnalyzerResult,
    Route,
)


class MyFrameworkAnalyzer:
    metadata = AnalyzerMetadata(
        name="myframework",
        display_name="MyFramework Analyzer",
        version="0.1.0",
        description="Detects MyFramework routes and config.",
        languages=["python"],
        targets=["myframework"],
        priority=200,           # higher = runs later in discovery order
        experimental=False,
        enabled_by_default=True,
    )

    @property
    def name(self) -> str:
        return self.metadata.name

    def detect(self, root: str | Path) -> bool:
        # Return True iff this repo looks like something we should run on.
        # Keep it fast — this is called on every scan.
        return (Path(root) / "myframework.yaml").exists()

    def analyze(self, root: str | Path) -> AnalyzerResult:
        result = AnalyzerResult(root=str(root))
        # Walk the tree, extract routes/secrets/hints with file:line citations,
        # populate the relevant ScanResult fields.
        # Example:
        # result.routes.append(Route(path="/api/v1/foo", method="GET", file="app/routes.py", line=42))
        return result
```

That's the whole contract.

## Testing

External analyzers typically test against small fixture repos. Pattern:

```
tests/
├── fixtures/
│   ├── myframework-app/        # a small but realistic example
│   │   ├── myframework.yaml
│   │   └── app/routes.py
│   └── not-myframework/        # negative case for detect()
│       └── README.md
└── test_analyzer.py
```

`test_analyzer.py`:

```python
from pathlib import Path
from attackmap_analyzer_myframework import MyFrameworkAnalyzer

FIXTURES = Path(__file__).parent / "fixtures"


def test_detect_finds_myframework_repo() -> None:
    assert MyFrameworkAnalyzer().detect(FIXTURES / "myframework-app") is True


def test_detect_rejects_non_myframework_repo() -> None:
    assert MyFrameworkAnalyzer().detect(FIXTURES / "not-myframework") is False


def test_analyze_emits_expected_routes() -> None:
    result = MyFrameworkAnalyzer().analyze(FIXTURES / "myframework-app")
    assert ("/api/v1/foo", "GET") in {(r.path, r.method) for r in result.routes}
```

Reference: the official analyzers ([`mlaify/attackmap-analyzer-python`](https://github.com/mlaify/attackmap-analyzer-python),
[`mlaify/attackmap-analyzer-rust`](https://github.com/mlaify/attackmap-analyzer-rust), and the
others listed below) all follow this pattern.

### CI tip: install attackmap from git

`attackmap` is distributed from GitHub, not a package index, so install it
from git in CI so `pip install -e ".[dev]"` doesn't fail resolving the
constraint:

```yaml
- name: Install attackmap core from main
  run: pip install "attackmap @ git+https://github.com/mlaify/AttackMap@main"

- name: Install package
  run: pip install -e ".[dev]"
```

## Merge semantics — what to expect when other analyzers also run

Two analyzers can emit overlapping signals. Core deduplicates by the keys
declared in [`merge.MERGE_SCHEMA`](../src/attackmap/merge.py):

| Field | Dedup key |
|---|---|
| `routes` | `(path, method, file)` |
| `external_calls` | `(target, file)` |
| `databases` | `(kind, file)` |
| `auth_hints` / `service_hints` / `edge_hints` / `entrypoint_hints` / `protocol_hints` / `framework_hints` | `(hint, file)` |
| `secret_hints` | `(name, file)` |

**First-seen wins.** If your analyzer emits `Route("/health", "GET", "app.py")`
and another analyzer emits the same triple, only the first one is kept. So a
"specialty" analyzer running after a "generic" one will *not* clobber the
generic's signal — design accordingly. If you want your signal to win, emit
with a different `file` granularity (e.g. cite the framework config file, not
the route file).

## Dependencies (SBOM entries)

Emit third-party dependencies as `DependencyHint`s in `result.dependencies`.
`ecosystem` must be one of `attackmap.sdk.DEPENDENCY_ECOSYSTEMS` (the
`DependencyEcosystem` literal). `--cve` maps each one to its OSV.dev ecosystem:

| `ecosystem` | OSV ecosystem | `name` |
|---|---|---|
| `pypi` / `npm` / `go` / `cargo` / `composer` | PyPI / npm / Go / crates.io / Packagist | package name |
| `maven` | Maven | `groupId:artifactId` |
| `nuget` | NuGet | package id |
| `gem` / `hex` / `pub` | RubyGems / Hex / Pub | package name |
| `conan` / `vcpkg` | ConanCenter / vcpkg | recipe / port name |
| `swiftpm` | SwiftURL | package identity; put the source **repository URL** in `evidence_text` (OSV keys Swift packages by URL) |
| `cocoapods` | — | inventory only: no OSV database, reported as not CVE-checked |

Set `resolved=True` when `version` is an exact pin (lockfile), and
`direct` / `via` when you know the resolution path. Core already parses the
`package.json`, `pyproject.toml`, `requirements.txt`, `go.mod`, `Cargo.toml`
and `composer.json` manifests, and the `package-lock.json`, `pnpm-lock.yaml`,
`poetry.lock`, `uv.lock`, `Cargo.lock`, `composer.lock`, `packages.lock.json`
and `gradle.lockfile` lockfiles. Don't re-emit them.

## Contributing taint sinks

Analyzers can add sink signatures to core's taint pass through the
`attackmap.taint_sinks` entry-point group (#240), for example a framework's
file-serving helper or an ORM's raw-SQL escape hatch:

```toml
[project.entry-points."attackmap.taint_sinks"]
myframework = "attackmap_analyzer_myframework.sinks:SINKS"
```

```python
SINKS = [
    {"id": "myframework-raw-sql", "kind": "sql_execute", "langs": ["python"],
     "regex": r"\bRaw\.sql\s*\(", "gate": "tainted", "args": [0], "cwe": 89},
]
```

The entry point may also resolve to a callable returning that list, or to a
path to a YAML file with a `sinks:` list. The schema is the same one core uses
for `src/attackmap/taint_sinks.yaml`:

- `cwe` is required.
- `kind` must be one of `attackmap.sdk.TAINT_SINK_KINDS`.
- `regex` must scale linearly.

Validate entries in your tests with `attackmap.sdk.validate_taint_sink`. At
scan time an invalid entry is skipped with a warning. Core still decides
reachability, the intra-procedural flow, sanitizers and severity.

## What analyzers may not do

- **No subprocess calls** to other tools (linters, language servers, etc.).
  Analyzers must be self-contained Python.
- **No network access** during `detect()` or `analyze()`. Scans are offline.
- **No finding generation, severity scoring, or report rendering.** Emit
  signals; core does the reasoning.
- **No mutation of `root`.** Read-only.
- **No global state.** Multiple analyzers run in one process; instances are
  reused across calls.

## The extraction protocol (version 1.0)

The analyzer I/O contract is versioned in code:
[`attackmap.analyzer_contracts.EXTRACTION_PROTOCOL_VERSION`](../src/attackmap/analyzer_contracts.py)
(currently `"1.0"`, with a machine-readable summary via
`describe_extraction_protocol()` and a live compatibility check via
`check_extraction_compatibility(analyzer)`).

| | Contract |
|---|---|
| **Input** | `analyze(root)` — the absolute repository root path. Read-only expectation. Core may additionally forward optional `progress` / `recall` / `index` keyword arguments to analyzers whose signature accepts them; plugins written against plain `analyze(root)` are called unchanged. |
| **Output** | An `AnalyzerResult` (`attackmap.sdk.ScanResult`), or a `dict` coercible to one. Core validates, stamps provenance and merges per `merge.MERGE_SCHEMA`. |
| **Metadata** | A static `AnalyzerMetadata` attribute (the schema in `analyzer_contracts.py`). |
| **Failure** | Raising or returning an invalid value records an `analyzer_errors` entry and the scan continues (#220). In the optional isolated host (below) a crash, timeout, output-size or memory breach yields a *named* partial-coverage `analyzer_errors` entry plus a `limitations` note. |

Protocol 1.0 formalizes the contract every current official analyzer already
satisfies — it is purely additive. `tests/test_analyzer_host.py` runs the
compatibility check over all registered analyzers (built-ins and any
installed plugins). A breaking change to input or output shape bumps the
major version and gets a deprecation window like any SDK change.

## Isolated analyzer host (optional, opt-in)

By default analyzers run **in-process**: one analyzer raising or returning
garbage is already skipped with an `analyzer_errors` entry (#220) — but a
hang, a memory leak or a native crash can still take the process down.

`analyze_repository(..., isolated_analyzers=True)` (API-level opt-in; a
`--isolated-analyzers` CLI flag is the intended front-end for it) runs every
**non-builtin** analyzer inside a supervised subprocess instead:

- The worker is spawned via the same machinery as the desktop scan workers
  (`attackmap.execution`: Windows Job Objects with kill-on-close and
  verified process-tree termination; POSIX process groups).
- Each analyzer's result travels through a size-capped file, never through
  shared memory, so one analyzer cannot corrupt another's output namespace:
  results are collected per-analyzer and merged by core's merge rules.
- Built-in core analyzers always stay in-process.
- Limits (`attackmap.analyzer_host.HostLimits`): time (default 300 s),
  stdout/stderr bytes (default 8 MB), result payload bytes (default 64 MB),
  and — on Windows only — a job-wide commit cap (default 1 GiB).
- On breach the worker is force-terminated and the scan records a **named
  partial-coverage result**: `analyzer_errors.error_type` is one of
  `AnalyzerHostTimeout`, `AnalyzerHostOutputLimit`,
  `AnalyzerHostMemoryLimit`, `AnalyzerHostCrash`,
  `AnalyzerHostInvalidOutput`, `AnalyzerHostLaunchFailed`,
  `AnalyzerHostStuck`, plus a `limitations` note saying the analyzer's
  signals are missing — a clean report is never mistaken for full coverage.
  Sibling analyzers are unaffected. `strict=True` re-raises instead.

### What the host actually enforces — and what it does not

**This is fault containment, not a security sandbox.** Subprocess
separation alone must not be marketed as a sandbox. Specifically:

| Limit | Enforced how | Platform |
|---|---|---|
| Time | Supervisor timeout → graceful signal, then verified process-tree kill (Job Object terminate / `killpg`) | Windows, POSIX |
| Process-tree escape | Job Object `KILL_ON_JOB_CLOSE` + suspended-start containment | Windows; POSIX uses session/process groups |
| stdout/stderr size | Worker interposes on file descriptors 1/2 and counts every byte (including raw `os.write` and inherited child processes); over the cap the worker exits immediately. The parent additionally retains only a bounded 50-line tail, so core memory is safe even if the counter is bypassed. | All (in-worker interposition) |
| Result payload size | Worker refuses to write past the cap; parent re-checks the file size before parsing | All |
| Memory | Job-wide commit policy (`JOB_OBJECT_LIMIT_JOB_MEMORY`) configured before creating/assigning/resuming the child; setup failure prevents launch. A reported `MemoryError` is named explicitly, without claiming the cap caused it. Native crashes without that report stay crashes; a near-cap peak alone is not a breach. | **Windows only** |

**Not restricted:** network access (a worker can open sockets exactly like
core), filesystem access (a worker can read and write anything the invoking
user can — the test fixture `evil_escape.py` proves a write outside the
working directory succeeds and documents it), and any other OS capability.
The memory policy is now installed before the suspended child is created;
the earlier post-resume race and swallowed setup failure are removed. On other
platforms an explicit memory request remains functional but is recorded as
unenforced (`IsolatedOutcome.resource_policy`, with a result limitation); no
non-Windows memory enforcement is claimed. A deliberately evasive
analyzer can also re-dup its own descriptors to bypass the stream counter
(core stays memory-safe via bounded retention, but the stream cap itself is
cooperative interposition, not kernel enforcement). For isolated output the
parent binds typed and normalized producer fields to the selected analyzer and
its explicitly declared version. Legacy aliases and conflicting producer,
version or classification claims remain bounded, redacted `untrusted_claimed_*`
metadata. Static path classification and observation identities are recomputed.
This attributes the returned statement; it does not authenticate source claims,
prove SDK use, restrict direct filesystem/network access, or establish runtime
verification. In-process legacy producer stamping retains its existing policy.

## Trusted-analyzer policy (explicit)

- `attackmap`'s plugin lock (`src/attackmap/plugins_lock.py`, generated by
  `scripts/update_plugin_lock.py`) records, per official analyzer: the repo,
  the package name, the version, **the pinned git commit SHA**, and its
  entry points. Auto-install (`--install-missing`) only ever installs these
  packages at these immutable commits.
- **A lockfile entry is pinning, not authenticity and not a sandbox.** It
  pins *which commit* pip fetches over TLS; it does not cryptographically
  verify the artifact you actually have installed, and it says nothing
  about what the analyzer does at runtime. Review the code you install.
- Default policy when scanning: any installed distribution may register an
  analyzer and it will run (with a warning naming the distribution if it is
  not an official plugin). Setting `ATTACKMAP_TRUSTED_ANALYZERS_ONLY=1`
  (the GitHub Action's default, also `--trusted-analyzers-only`) loads only
  lock-pinned official plugins. Installing a third-party analyzer is an
  explicit trust decision made by whoever ran `pip install`.

## Publishing

Analyzers are installed straight from their git repos, so publishing is just
pushing to GitHub:

1. Copy `.github/workflows/ci.yml` from any of the
   [`mlaify/attackmap-analyzer-*`](https://github.com/orgs/mlaify/repositories?q=attackmap-analyzer)
   repos so every push runs the test suite.

2. Tag releases (`v0.1.0`, …) so users can pin a version:
   `pip install "git+https://github.com/<you>/<repo>.git@v0.1.0"`.

3. Document the install line in your README:
   `pip install git+https://github.com/<you>/<repo>.git`.

## Reference: the 14 official analyzers

Each of these lives in its own repo under [`mlaify/`](https://github.com/orgs/mlaify/repositories?q=attackmap-analyzer)
and installs from git. Source-read any of them for a real, working analyzer.

| Plugin | Ecosystem |
|---|---|
| [`attackmap-analyzer-python`](https://github.com/mlaify/attackmap-analyzer-python) | Django, Starlette, AIOHTTP, Sanic, Litestar, DRF, SQLAlchemy/asyncpg, passlib/PyJWT, httpx |
| [`attackmap-analyzer-rust`](https://github.com/mlaify/attackmap-analyzer-rust) | axum, actix-web, rocket; sqlx, diesel, sea-orm; jsonwebtoken, argon2 |
| [`attackmap-analyzer-go`](https://github.com/mlaify/attackmap-analyzer-go) | net/http, chi, gin, echo, fiber; database/sql, gorm; golang-jwt |
| [`attackmap-analyzer-java-spring`](https://github.com/mlaify/attackmap-analyzer-java-spring) | Spring Boot, JAX-RS, Ktor; Spring Data; Spring Security |
| [`attackmap-analyzer-dotnet`](https://github.com/mlaify/attackmap-analyzer-dotnet) | ASP.NET Core, EF Core, Identity, JwtBearer |
| [`attackmap-analyzer-terraform`](https://github.com/mlaify/attackmap-analyzer-terraform) | AWS/Azure/GCP, IAM wildcards, open SGs, secrets |
| [`attackmap-analyzer-iac`](https://github.com/mlaify/attackmap-analyzer-iac) | Dockerfile, docker-compose, GitHub Actions, `.env` templates, shell installers |
| [`attackmap-analyzer-c`](https://github.com/mlaify/attackmap-analyzer-c) | libmicrohttpd, civetweb, mongoose; libcurl; OpenSSL/libsodium |
| [`attackmap-analyzer-cpp`](https://github.com/mlaify/attackmap-analyzer-cpp) | Crow, Pistache, Drogon, cpprestsdk; libcurl/cpr; libpqxx/mongocxx |
| [`attackmap-analyzer-node-service`](https://github.com/mlaify/attackmap-analyzer-node-service) | Node.js / TypeScript service ecosystems |
| [`attackmap-analyzer-atproto`](https://github.com/mlaify/attackmap-analyzer-atproto) | AT Protocol (Bluesky) services |
| [`attackmap-analyzer-php-web`](https://github.com/mlaify/attackmap-analyzer-php-web) | Generic PHP web |
| [`attackmap-analyzer-php-laminas`](https://github.com/mlaify/attackmap-analyzer-php-laminas) | Laminas / Zend MVC |
| [`attackmap-analyzer-omeka-s`](https://github.com/mlaify/attack-map-analyzer-omeka-s) | Omeka-S |

## Versioning

The SDK surface (`attackmap.sdk`) is stable across minor releases of the
`attackmap` package. Breaking changes only happen on a major-version bump;
deprecations get one release of overlap. Pin a lower bound in your
`pyproject.toml`:

```toml
[project.optional-dependencies]
core = ["attackmap>=0.1.0,<1.0.0"]
```

When you upgrade your lower bound, bump your analyzer's minor version.

## Where to ask for help

- Open an issue at [`mlaify/AttackMap`](https://github.com/mlaify/AttackMap/issues) tagged `analyzer`.
- Tag `@mlaify/maintainers` on PRs that touch the SDK surface.
