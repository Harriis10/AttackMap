<!-- ATTACKMAP_DOC_STATUS: HISTORICAL_REFERENCE -->
> **STARÝ DOKUMENT — pro agenty nerelevantní jako aktuální plán nebo zadání (20. 10. 2026).**
> Práci řídí pouze dokumenty v [aktuálním rozcestníku](README.md). Tento text je historická reference: neobnovovat jeho TODO, priority ani statusy dokončení. Technické podklady a kritéria použít jen v rozsahu potřebném pro aktivní WP úkol a ověřit proti aktuálnímu kódu.

# Run contract foundation (AM009 / C08)

## WP004 additive contract — 20 October 2026

Current schema is **1.2**; **1.0 and 1.1 remain accepted**. The old `ScanOptions`
model and the exact serialization/default behavior for those requests are retained.
`ScanOptionsV12` is selected only by a 1.2 request. Progress and terminal messages
echo the request's schema, so an existing native client sending 1.1 does not receive
an unsupported 1.2 response. The original frozen WP002 fixture corpus is unchanged;
the additive corpus is `tests/fixtures/desktop-options-v12/`.

| New 1.2 field | Default | Validation / unit | Service and pipeline meaning | Network impact |
| --- | --- | --- | --- | --- |
| `baseline` | null | Absolute local file path; existing file before dispatch | `ScanRequest.baseline` → `AnalyzeOptions.baseline`; core owns comparison | None |
| `suppress_file` | null | Absolute local file path; existing file before dispatch | Selected local suppression file | None |
| `fail_on_new_high` | false | Boolean; baseline required | Core baseline policy | None |
| `fail_on_new_suppression` | false | Boolean; baseline required | Core baseline policy | None |
| `strict_suppressions` | false | Boolean; incompatible with `no_suppress` | Core suppression validation policy | None |
| `isolated_analyzers` | false | Boolean | Existing analyzer isolation path | None |
| `time_budget_seconds` | null | Integer 1..86400 seconds, also strictly below `timeout_seconds` | Soft deterministic between-stage ceiling | None |

Path validation accepts fully absolute Windows drive or POSIX paths, rejects
relative/drive-relative paths, control characters and UNC/network path forms.
Filesystem checks use the executing host. A synthetic Windows path fixture does
not establish that the file exists on another platform. `no_suppress` conflicts
with an explicit suppression file or strict suppression policy; such requests
fail before scan/provider dispatch. The new fields themselves introduce no AI,
CVE, remote lookup or download. Existing opt-in provider/CVE options retain their
existing network semantics.

The soft budget checks between deterministic stages and cannot interrupt an
in-flight stage. The existing supervisor `timeout_seconds` is the hard execution
deadline. Neither field establishes memory/process-count ceilings. Null soft
budget retains the existing core environment/default resolution. Reaching a soft
budget uses core partial-coverage diagnostics; the adapter does not invent success
or duplicate policy/scoring.

`scan_request_from_run` is the single explicit conversion to the neutral
application `ScanRequest`. The engine worker invokes `execute_scan_request`;
`_analyze_options` retains the shared mapping into the pipeline. Existing provider
limits and the active shared budget scope remain intact. The supervisor still
owns generation publication/retention, with `atomic_output=false` for its child.

Capability document schema remains **1**. It advertises run schema versions,
per-schema accepted option names, and support/unit/network metadata for each new
field. Raw desktop admission rejects unsupported explicit options before the
permissive metadata model can drop them. Additive envelope metadata remains
compatible. Schemas describe shape; Python also enforces schema-to-options,
cross-field, path and outcome semantics.

Fleet identities/dispatch, AI modes beyond the existing enable-review behavior,
jury/effort/fast/backend tuning, incremental and memory/worker knobs are absent
from 1.2 options and rejected at admission. `ScanRequest.incremental` currently
has no explicit `AnalyzeOptions` field: the CLI activates it through an environment
flag. WP004 does not advertise that as a working desktop option. Those additions
need their owning task's service mapping, nondefault fixture and capability update.

The older foundation description below is historical context for 1.0/1.1.

The transport-neutral models in `attackmap.run_contract` publish schema **1.1**
and accept **1.0–1.1**, independently of the application version. Both versions
are established together by the shared fixtures; 1.0 has the same required wire
fields and semantics. This does not claim compatibility with an earlier released
run protocol. Unknown additive fields are ignored. Unknown minor versions and
incompatible majors are rejected with an upgrade/export instruction.

`schemas/run-*.schema.json` and `fixtures/run-contract/` are the shared corpus.
Schemas describe wire shape; Python model validators additionally enforce state,
policy, counter and artifact-path consistency. Consumers must implement those
semantic checks as well. No JSON schema validation dependency is added.

All envelopes carry schema version, run ID, repository ID, generation and a
monotonic revision. Repository identity is an opaque ID assigned by the caller,
not a basename. A producer assigns one generation per admitted run and increases
revision for every externally visible state change. A consumer selects a new run
explicitly and then uses `accepts_update` to reject foreign identities, duplicate
or reordered events, state regression and updates after terminal state. Progress
and manifest messages are separate channels: compare manifest identity against
the selected terminal result, rather than applying it as a state update.

A request carries repository/output paths, analyzer modules and an additive
`options` object. Local options include recall, strict analyzers, suppression
disablement and bounded Git secret-history depth (0–10,000 commits). CVE
enrichment is explicitly opt-in and sends dependency names/versions to OSV;
it defaults off. The desktop supervisor defaults to a 600-second timeout,
configurable from 1 to 86,400 seconds. A timeout fails the run and preserves
the previous published result. Requests without options use these defaults.
AI is not enabled by this options object. The typed request deliberately
does not yet replace the existing CLI ScanRequest or all its options. Progress
states are queued, running and cancelling. A sub-analyzer done notification is a
stage update, never a terminal result. Unknown totals remain null; consumers
must not invent percentages or ETA. Terminal states are completed, failed and
cancelled. Completed means execution succeeded; a policy breach remains completed
with policy_outcome failed. A process exit code alone cannot establish this.
Artifact readiness is separate from execution and policy; ready means the
publisher validated the complete generation. The manifest includes relative
paths, sizes and SHA-256 values. Constructing a model does not verify files or
provide atomic publication: the publisher must do that before announcing ready.

`parse_run_message` requires an explicit version. `import_legacy_report` accepts
only schema-less saved reports with a scan object and root string. The caller
supplies import identity; the adapter preserves the original payload and records
that policy and artifact integrity are unverified. It never declares artifacts
ready and does not claim that legacy report evidence has been revalidated.

The consumer-compatibility matrix is pinned by tests for all four kinds: a
consumer accepts the current and immediately preceding supported versions,
ignores injected additive unknown fields on current-version payloads (top level
and nested options/artifact entries), and rejects an incompatible major version
with an error naming the supported range and the upgrade/export action. The
range text in that error is derived from the contract constants so it cannot
drift. The Windows desktop `/api/state` adapter publishes its supported range
from the same constants on every snapshot, independently of the application
version; a test asserts that publication and that each emitted message stays
inside the advertised range.

Integration requires adapters at CLI/progress, supervisor, artifact publisher,
and each desktop consumer. Existing unversioned progress and final reports are
not automatically migrated by this module. Full C08 remains open: the CLI and
supervisor do not yet emit or consume these envelopes end-to-end, the macOS
consumer is untested, and the scenario corpus under
`fixtures/run-contract/faults/` is not yet wired to a consumer harness; this
foundation alone does not establish Windows or macOS beta readiness.
