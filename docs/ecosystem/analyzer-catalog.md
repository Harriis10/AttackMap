# Effective analyzer catalog

WP042 adds an offline discovery view alongside the existing module array:

```powershell
python -m attackmap modules --catalog-json
python -m attackmap modules --profiles-json
python -m attackmap analyze C:\path\to\repo --analyzer-profile php-laminas-omeka@1.0
```

Run these commands with the executable that will perform the scan. The host
Python environment and a frozen executable may contain different plugins.
`modules --json` retains its existing array format. `capabilities` also exposes
the additive `analyzer_catalog` and `analyzer_profiles` objects. The native picker
does not yet display these new fields or offer profile selection.

The catalog records every discovered candidate, including effective and shadowed
implementations, trusted-only policy exclusions, and load, initialization,
metadata or contract errors. Discovery enumeration failure is recorded separately.
It does not run `detect()` or analyze a repository. An installed or effective
analyzer therefore cannot be reported as applicable, selected or executed from
this document alone. Per-run selection and execution accounting remains a later
WP042 integration step.

Registry policy is unchanged: a built-in wins a same-name collision before run
ordering. Effective analyzers subsequently run in `(priority, name)` order.
Route merge still preserves the first record with its existing exception for
upgrading unknown auth from later evidence; this batch does not change auth fusion.
The `php-web`, `php-laminas` and `omeka-s` plugins therefore remain shadowed when
the corresponding built-ins are present. This policy is now inspectable.

Each catalog envelope identifies its executable. Python identity additionally
hashes the relevant core, analyzer and profile sources. Catalog and profile
digests capture changes in discovered implementations and selection contracts.
Readable analyzer class source files have a bounded observed-file hash; missing
or frozen source is explicitly unavailable. A class-file hash is not a hash of
all transitive plugin dependencies or an attestation of loaded bytecode.

Installed package name/version and sanitized `direct_url.json` evidence are
separate from the declared official Git pin. A wheel URL or matching VCS metadata
does not prove installed content matches that commit. `content_verified` remains
false; package verification must bind cached wheels, installed bytes and the
build manifest separately. Neither an executable hash nor an official package
name establishes publisher authenticity or plugin sandboxing.

See [versioned profiles](analyzer-profiles.md) for exact membership, required
base layers and explicit experimental/opt-in choices. Missing profile modules
fail without installation or substitution. Bare `-m` keeps its exact-list meaning;
Automatic keeps existing default-enabled behavior and runtime detection.

## First update decision

Changing an external PHP plugin pin cannot fix the effective built-in routing
implementation under the preserved collision policy. That update is a **no-go
for the parent-prefix defect**. The WP039 alternative is a focused correction in
`ecosystem_php.py` with paired parent/child and wrong-parent extraction checks.
No official plugin pin or installer policy changes in this batch. Python's
immutable pinned/candidate/current-source comparison is also a **no-go**:
newer route extraction introduces foreign-wrapper auth false positives and
does not resolve FastAPI/Flask mounts. The qualified local alternative adds
bounded import binding and Django URLconf extraction under WP039. See the
[27-case source comparison](../verification/windows-parity/WP039/sol-ultra-20261023-python/upstream-qualification.md).

| Capability | Scope after this batch | Remaining qualification |
| --- | --- | --- |
| Catalog and collisions | Effective implementation and discovery failures; native profile/provenance view and per-run ledger; fresh packaged inventory/SBOM verified 23 October | Human accessibility, clean-host/release acceptance and dependent maturity gates |
| Node/ATProto profile | Required JavaScript, config, fallback and overlay selection; local WS subscription and route-specific auth corrections | External representation coexistence, generated registration forms and C27/C38 evidence |
| PHP/Laminas/Omeka | Static returned `router.routes` hierarchy and controller/action evidence | Dynamic configs, middleware/auth binding and corpus maturity |
| Python profile | Required Python plugin/base/config/fallback/overlay; bound mount hints/auth and static Django URLconf/class-view surfaces | Plugin raw/local duplicate route observations, general regex/dynamic graphs, class/mixin auth and corpus maturity; upstream update no-go documented |
| Kubernetes posture | Existing deployment/config extraction remains | RBAC, NetworkPolicy and workload-specific candidate scope |
| OpenAPI/protobuf/gRPC | Candidate expansion only | Structured extraction contract and paired evaluation |

Source tests, frozen execution, package acceptance, native visual review and
macOS acceptance are separate gates. The active WP042/WP039 cards remain the
authority for completion.

## Per-run observations

`scan.analyzer_run_ledger` and `run-manifest.json.analyzer_run_ledger` share
schema 1.1; persisted schema 1.0 remains readable with unknown timing/counts.
Each candidate records selection, applicability and execution
separately. `unmatched`, `detect_error`, `opt_in` and a pipeline deadline are
distinct skip reasons. Analysis failures and isolated-host failures record a
safe error type/stage. `analysis_started: null` means a failed isolated host
could not prove whether analyzer code started. A selected analyzer is not
reported as succeeded before its returned result is accepted.

Each entry additionally records finite nonnegative `detect_duration_ms` and
`analysis_duration_ms`, a bounded ordered `lifecycle_events` sequence with
elapsed time from selection-plan creation, and `signal_counts` for routes,
external calls, databases, auth hints and secret hints before merge. Missing
observations are null, not zero. An isolated host request is `requested`, not
proof that analyzer code started; its measured duration includes parent wait
and processing overhead, not child CPU time. Error events retain only safe
types, not exception text, target source or secrets. Strict failures finalize
their available observations before raising; pending siblings remain pending.

The native selected-report view shows these recorded observations separately
from the installed catalog. The live scan view retains the latest 200 distinct
stage/state updates for the selected run and reports any omitted earlier count.
Switching run or repository clears that live history. Analyzer stage updates
use the existing progress protocol and never imply a terminal run result.

Automatic covers registered candidates; an explicit list/profile has
`inventory_scope: supplied_candidates`. The latter does not imply discovery of
every installed or shadowed implementation. Discovery/load failures and shadowed
packages remain in the separate discovery catalog. Legacy manifest `analyzers`
continues to mean selected analyzers for compatibility; consumers needing
execution outcomes must use the ledger. `execution_complete` means all candidate
outcomes were recorded, including failures/skips, not complete repository coverage.

The selection plan belongs to one repository capture and can execute once. The
pipeline reuses it instead of calling `detect()` again. Recorded implementation
identities omit absolute source paths and source snippets. Their SHA-256 binds
observed implementation/package provenance, not complete dependencies, runtime
security or publisher authenticity.
