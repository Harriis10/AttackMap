# WP033 captured inputs and explicit incremental activation

Status: implemented focused source slice; acceptance remains PARTIAL pending the boundaries below and integrator review. Base commit: `620210ed52dc1f20b72d4da91a6594fd45a1e6a9`. Worker: `/root/roadmap_completion_audit`. No native shell, provider, retained package or fixture corpus was modified by this task.

## Changes

- `RepoIndex` captures original bounded bytes in immutable `CapturedSource` records shared with SDK readers. UTF-8 core text keeps its existing universal-newline transform; SDK text retains UTF-8 BOM handling, cp1252/latin1 fallback, original newlines and binary rejection. SDK enumeration still exposes binary names. Raw and core accepted counts are separate; applying the existing SDK capture count bound does not tighten the existing core UTF-8 accepted count. Limits are visible through typed existing `repo_index` resource events and explicit limitations. A file growing between stat and read cannot exceed the aggregate capture budget silently.
- `PassSources` provides captured enumeration, virtual directory children, existence and size. SBOM, lockfiles, workflows, supply-chain, GraphQL authorization and deployment-alias enumeration use this basis. A newly created lockfile cannot silently change a captured manifest's interpretation; deletion/rename cannot hide a captured source. Taint Go-module and PHP PSR4 reads and PHP applicability helpers use captured content.
- Native/core application requests carry the existing explicit `ScanRequest.incremental` boolean into `AnalyzeOptions`, analyzer dispatch and scanner. Explicit False overrides inherited `ATTACKMAP_INCREMENTAL=1`; True enables caching. An omitted direct low-level scanner argument retains legacy environment behavior. CLI flag/environment requests normalize into the existing request field; public default stays off. No desktop option or capability was added, and watch continues to request full scans.
- Pipeline capture precedes analyzer detection and is reused rather than rebuilt. Its elapsed-time budget begins before capture. Builtin JS/config/Python-service/ATProto detection and cooperating SDK analyzers enumerate the same captured input.
- `ScanSnapshotIdentity.raw_files` is additive exact-byte metadata. New snapshot IDs bind normalized content plus original bytes; CRLF-only changes therefore cannot masquerade as the same SDK input. Legacy identities with no raw map retain their old hash semantics. Raw hashes validate against already captured relative paths. Existing frozen parity fixtures remain untouched. Publication verification also detects a newly added exclusion marker changing captured source scope.
- Cache identity includes extractor, analyzer metadata, model/recon schema and cache implementation sources, plus Python/Pydantic runtime versions. Unreadable/source-less identity raises an uncacheable condition; no stable placeholder can replay stale entries. The scanner recomputes safely when caching cannot prove identity.

Raw accounting APIs for WP034: `len(index.files)` / `index.total_bytes` describe the existing core text inventory; `len(index.sources)` / `index.captured_source_bytes` describe raw capture. `index.sources` records expose `rel`, `raw`, `mtime_ns` and `size`. Raw bytes and decoded core text coexist; peak memory must be measured. There is no speed or memory improvement claim.

## Verification

The dedicated `tests/test_snapshot_inputs.py` campaign compares exact serialized scan fields, derived findings, normalized observation provenance and coverage after each of 100 deterministic edits. Operations include source edits/add/delete/rename, dependency and analyzer configuration edits, actual source-role inclusion toggles, output exclusion changes, extractor identity upgrades and corrupt cache storage. It asserts a nonempty baseline and the actual inclusion/exclusion of the test route. Other tests prohibit live source reads/enumeration after capture; exercise deleted manifests/workflows, preserved legacy bytes/newlines, raw identity negatives, visible sidecar limits, aggregate-budget growth, model identity invalidation and explicit application False overriding CLI env.

Verification progression (not interchangeable):

- Initial dedicated slice before additive raw identity: 11 PASS, including the 100-edit derived-findings campaign.
- Raw identity/index/SDK/CLI/snapshot compatibility run: 71 PASS, 1 FAIL, 1 explicit Windows symlink-privilege SKIP. The failure was duplicate missing-file warning presentation from core/raw views; it was fixed without suppressing the mutation evidence.
- Final targeted raw identity / exclusion marker / capture-growth negatives: 3 PASS.
- Broader relevant regression: **272 PASS, 1 explicit Windows symlink-privilege SKIP**, exit 0, 740.34 seconds. This 14-suite run began before additive raw identity was finalized; it proves the migrated extractor/cache/ecosystem/application slices, not final raw metadata by itself.
- Final focused acceptance: **51 PASS, 1 explicit Windows symlink-privilege SKIP**, exit 0, 148.00 seconds, covering final snapshot inputs (including the meaningful 100-edit findings campaign), index, SDK filesystem and CLI incremental behavior. The duplicate missing-file warning regression is included and passes. The earlier raw run separately passed snapshot-consistency/publication/excerpt/fingerprint phases; its only failure was the corrected duplicate index warning.
- `git diff --check` passed for task-owned source/tests/evidence; `py_compile` passed for the initial plumbing slice. No skip is counted as a passing platform test.

Final focused command:

```powershell
& ./.venv/Scripts/python.exe -m pytest tests/test_snapshot_inputs.py tests/test_index.py tests/test_sdk_fs.py tests/test_cli_incremental.py -q --basetemp .tmp-wp033-acceptance-final-20261021
```

The larger command added `tests/test_snapshot_consistency.py`, `tests/test_incremental.py`, `tests/test_sbom.py`, `tests/test_lockfiles.py`, `tests/test_supply_chain.py`, `tests/test_workflow_scanner.py`, `tests/test_ecosystem_php.py`, `tests/test_ecosystem_python.py`, `tests/test_ecosystem_node_atproto.py` and `tests/test_application_boundary.py`, using `.tmp-wp033-stable-regression-20261021`.

Final principal source hashes (SHA-256; repository-relative paths):

Tracked core-file binary diff SHA-256 at handoff: `9bb3e70e85f11aae8ce10b213636f937128e2a008d5c1940d11637ac9e3246fb`. It covers the 18 source paths named by this record (including the shared `config_scanner.py`, whose separate WP032 endpoint change is preserved); the new untracked test is bound separately below. Final commit and independent review remain integrator-owned.

| Path | SHA-256 |
| --- | --- |
| `src/attackmap/index.py` | `AD94A6B1CEA9B919229D05BDB9620D07A6C4BDECCBD744D94C493997C6FE21D2` |
| `src/attackmap/incremental.py` | `C8C5EDAAE46F28DE7FF3E0B87494E258BAC6BEDBEC18EEB8AC6638AAEE60ED1F` |
| `src/attackmap/models.py` | `CC8F4A00C47E5EF3C9B371464C381B6F42EF80FD3516460C7E5E4AA4E365DA81` |
| `tests/test_snapshot_inputs.py` | `8DE91DF2D5EE0B0815D45982496E942B319820A43B0DF85C1499FBE7EE4B8582` |

Commands use the repository venv and isolated approved basetemp directories. Relevant suites include snapshot inputs/consistency, index, SDK filesystem, incremental cache/CLI, migrated whole-repository passes, all three builtin ecosystem layers and application boundary. No GUI, live model response, real product scan or performance campaign was executed by this worker.

## Remaining acceptance boundaries

1. Arbitrary external analyzers can bypass SDK and directly access the live filesystem. The in-process SDK capture contract is implemented; it is not an OS filesystem sandbox. Rootless SDK reads outside the pinned root retain their general legacy API behavior. Isolated analyzers currently have no captured-input transport; source/frozen host input qualification belongs with the remaining WP035 work. Neither is certified snapshot-pinned here.
2. Taint import target resolution still uses live `Path.resolve` for symlink structural metadata beyond the narrow content-read slice. Direct Python/ATProto overlay calls without an explicit index can still take their legacy live fallback, although production builtin dispatch supplies an index. These are concrete further audit/refinement items.
3. A plugin requesting an SDK per-file cap larger than the captured core cap cannot receive uncaptured bytes through a hidden fallback. Existing capture-limit events/limitations disclose the bounded input. Qualifying such plugin requirements requires explicit input-cap planning rather than silent live reads.
4. New native option UI/capability for incremental mode was not introduced. A real native/source/frozen round trip, the original C34 20-repeat reference performance campaign and broader platform evidence remain separate gates. The old 100-per-file campaign passed in the larger regression; the new 100-derived-findings campaign passed again in the final focused raw-identity run. Source/frozen/native qualification is not implied by either source campaign.

The integrator owns final diff identity, independent review, backlog/checkpoint status and release claims. This slice does not close WP033/K8 or substitute for WP034 measurements.
