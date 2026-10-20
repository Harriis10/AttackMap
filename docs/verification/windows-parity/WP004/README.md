# WP004 options integration

Schema decision: additive **1.2**, retaining supported **1.0/1.1** and their exact
old option defaults/serialization. Separate `ScanOptionsV12` fields have explicit
service/pipeline mappings, nondefault sentinels and support/unit/network metadata.
Frozen WP002 fixture bytes are preserved. New fixtures live under
`tests/fixtures/desktop-options-v12/`.

The child worker maps through `scan_request_from_run` → `ScanRequest` →
`execute_scan_request` → `_analyze_options`; core retains scoring, suppression,
baseline policy and budget behavior. Parent broker retains generation publication.
Responses echo the request schema to preserve old native clients. Existing
analyzer preflight/diagnostic ownership remains before service dispatch.

New supported fields: baseline/suppress file, baseline high/new-suppression policy,
strict suppressions, isolated analyzers and deterministic between-stage time
budget. Details and invalid combinations are in `docs/run-contract.md`. These
fields add no network service calls. AI/fleet/advanced tuning remain absent and
fail-fast. Incremental was deliberately not advertised: current source has no
explicit AnalyzeOptions field, and its CLI environment path is not a desktop
service mapping.

Narrow WP003 changes were reported to the parent before implementation: current
schema/options advertising, per-schema field names, new-field metadata and raw
validator selection. Reserved top-level feature aliases also fail rather than
being mistaken for additive metadata. CLI capability document schema remains 1;
no CLI command/action behavior was otherwise changed.

Early mapping verification: **17 passed**, 10 deselected. Each new field was
tested with a nondefault sentinel from typed request through neutral service
request to actual pipeline options before advertising the field. Frozen WP002
read-only validation: **266 checks passed** (`frozen-contract.log`).

Focused regression command and final results are recorded separately. No live
provider call, real repository scan, package rebuild/install, GUI, C#/Swift
consumer execution or release acceptance is claimed.

Final core verification: **169 passed in 413.15 seconds**, exit 0, across required
run-contract/options/worker/application-boundary tests plus WP003 capability/action,
diagnostic and service regressions (`pytest-focused.log`). Final added alias and
broker schema-echo checks: **10 passed, 36 deselected in 15.91 seconds**, exit 0
(`pytest-final-additions.log`). Python syntax and changed-file whitespace checks
also passed. Exact commands/source hashes are in `verification.json`.

Native consumer integration is root-owned; see `native-consumer-handoff.md` for
the exact producer/consumer/test seam. This evidence does not independently
close the native consumer or K1 acceptance gate.
