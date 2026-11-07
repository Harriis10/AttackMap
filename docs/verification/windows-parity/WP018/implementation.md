# WP018 implementation candidate — not accepted

Resume verification on 2026-10-20: see
[the final resumed test record](resume-verification-2026-10-20.md).
The corrected fixture setup now has 38 focused PASS plus 29 fleet regression
PASS / 1 Windows skip. Frozen and real process-cleanup acceptance remain open;
the earlier verification history below is retained as history.

This slice adds explicit schema 1.4 desktop fleet transport. Default schema
remains 1.2; single-repository 1.0–1.3 mapping and CLI complete-only parent
publication remain in place. No native EXE, preview or real repository scan was
launched. Work requires root review and completed deterministic verification.

## Contract for WP019 / WP006

- Discover `desktop.fleet_by_schema["1.4"]`. The legacy `multi_repo: false`
  describes the single-request path; fleet is an explicit capability and request
  kind. Maximum 16 repositories, minimum two, maximum four workers.
- Send `kind: "fleet_request"`, `schema_version: "1.4"`, existing parent
  `run_id`, `generation`, `revision`, `output_path`, `modules`, `options`, plus
  `repositories: [{repository_id, repository_path}]` and `max_workers`.
- Parent `repository_id` is `fleet:` plus SHA256 of ASCII JSON, compact separators,
  of sorted pairs `[explicit repository ID, normalized absolute local root]`.
  Python `repository_set_id` is authoritative. Windows roots use
  `ntpath.normcase(ntpath.normpath(root))`; other local paths use native normalized
  case/path. IDs and roots must each be unique; resolved duplicate aliases are
  rejected before analyzer selection or process admission.
- AI, baseline/policy, custom suppression file and secret-history combinations
  are rejected before admission. Ordinary suppression/no-suppress, strict flags,
  CVE, recall, analyzer isolation and soft/hard time budgets retain exact neutral
  mappings. No plugin installation or network discovery is added.
- Consume parent `progress` plus `fleet_child` and final `fleet_terminal`.
  Every envelope carries parent run/repository-set/generation and a broker-owned
  increasing revision. Reject stale parent identities/revisions before UI work.
- Child rows contain `child_repository_id`, exact `child_repository_path`,
  `child_run_id`, and explicit `child_output_id` (core fleet slug). The last field
  supplies the mapping to core cross-repository link IDs; never join basenames.
  A child run ID hashes parent run ID, generation and explicit child ID.
- Child states are queued/running/completed/failed/cancelled/skipped. Only a
  validated exact child generation can carry completed and its manifest path/hash.
  Progress done/total remains optional. No global percentage/ETA is inferred.
- `fleet_terminal.fleet_outcome` is succeeded/partial/failed/cancelled. Partial
  means at least one verified successful child and an incomplete sibling; parent
  state remains failed and artifact readiness unavailable. Policy failure is
  unsupported for fleet admission, not reinterpreted as execution failure.
- Final `children` preserve request order. `index_path/index_sha256` refer to
  `desktop-fleet.json`, containing exact identity and child rows. Successful
  parents bind that index in their artifact manifest. Partial/cancelled indexes
  are non-current diagnostic results; successful siblings remain individually
  manifest-bound. Consumers must check hash and captured identity before loading.
- Send `cancel` or close control stdin to cancel the entire owned engine branch.
  Supervisor cleanup precedes terminal callback. Engine signal handlers request
  cancellation, workers drain and the bounded scheduler stops further admission.
  Source broker uses Python `-m attackmap.desktop_worker`; frozen broker invokes
  its own `desktop-worker` command, never treats a frozen executable as Python.

## Changes and limits

New `desktop_fleet.py` owns admission, identity, event/index validation, engine
adapter and broker. Minimal hooks in `scan_service.py` reuse existing child
workers and core link generation. Scheduling admits at most the effective worker
count and replenishes completed slots. Successes are collected even if
cancellation arrives while they complete. Existing CLI serial execution is
unchanged; desktop worker-count one uses the supervised subprocess route.

`desktop_worker.py` dispatches only explicit fleet requests. Capability discovery
adds source identity binding and fleet-specific fields. The publisher includes
`desktop-fleet.json` when present and still rejects unsuccessful parent publication.
No C# consumer, scoring, cross-repository linking policy or tracker was edited.

Prepared tests cover admission, Unicode/spaces, duplicate basenames/roots,
source/frozen argv, manifest tampering, old child generations, cancellation
admission bounds, deterministic order, siblings, parent broker cancellation,
stale progress, neutral option mapping and old request serialization defaults.
Tests are fixture/seam tests; they do not prove a built frozen artifact or actual
Windows process-tree cancellation.

## Verification status

- Initial Python syntax compilation completed before later tightening changes;
  final compile has not run.
- Final schema generation completed using the repository `.venv` interpreter:
  `sync_schemas.py --write` returned exit 0 and "Seven run/fleet schemas
  synchronized." This imported the tightened fleet models successfully; it did
  not launch tests, a broker, scan, native EXE or preview. Existing four model
  schema enums include 1.4. Runtime behavior remains unverified.
- First pytest attempt used the wrong default interpreter (no pytest), and did
  not run tests. The absent global executable attempt also ran no tests.
- Approved `.venv` run of five focused files produced repeated setup errors and
  was interrupted (owned session 45381, returned exit 1) before diagnostic detail
  was printed. Do not count any passes. Root was asked to rerun with a dedicated
  approved basetemp rather than modify temp ACLs.
- Root then requested Python tests remain stopped following a user-reported popup
  and explicitly authorized only the final deterministic schema regeneration.
  No native EXE or preview was launched by WP018. Final test results, schema
  regeneration, source/frozen runtime evidence and root acceptance remain open.

Suggested root command when verification is authorized again:

```powershell
& .\.venv\Scripts\python.exe docs/verification/windows-parity/WP018/sync_schemas.py --write
& .\.venv\Scripts\python.exe -m pytest tests/test_desktop_fleet.py tests/test_fleet_parallelism.py tests/test_fleet_publication.py tests/test_desktop_worker.py tests/test_run_contract.py tests/test_desktop_capabilities.py tests/test_desktop_options.py -q --basetemp .tmp-wp018-approved-final -p no:cacheprovider
```

The historical schema unsupported sentinel changed narrowly from 1.4 to 1.5;
new tests explicitly accept fleet 1.4 and compare legacy request bytes/defaults.
No closure or GUI acceptance is asserted.
