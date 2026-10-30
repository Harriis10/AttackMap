# Broker-bound partial fleet summary — staged only

`staged/desktop_fleet.py` is a copy of production `src/attackmap/desktop_fleet.py` with one optional diagnostic index binding. Production/shared source is unchanged. `desktop_fleet.partial-index.patch` contains the focused diff against the recorded source SHA256 in `hashes.json`.

The optional field is:

```json
"fleet_summary": {"path":"fleet-summary.json","sha256":"<64 lower-case hex characters>"}
```

The relative path is fixed by the broker, never supplied by an engine event or browser. Missing summary preserves the exact old index payload shape. Available summary bytes are bounded to 64 MiB, must be a regular file, and are hashed through one held descriptor. Existing `_safe` checks every ancestor for symlinks/reparse points before and after reading. Path/descriptor identity, size, modification time and same-API ctime are compared before/after; `O_NOFOLLOW` is used where provided. The same `_index_payload` helper produces `write_index` output and the successful broker's `expected_index`, so tampering or disappearance between engine indexing and completion fails the existing exact comparison.

## Ordering and publication

The inspected `_run_fleet_generation` path calls `_finalize_fleet` (summary exists), then `fleet_finished` (engine `write_index`), then successful-only `write_fleet_manifest`. Broker `serve.complete` collects independently validated child generations. Complete success still requires exit code 0, every validated child complete, no cancellation, exact expected index, `validate_generation`, and `publish_generation`. Partial/cancel/failure still rewrites only the broker diagnostic index, remains `failed`/`cancelled` with artifact readiness `unavailable`, and never commits the parent current-generation pointer. No publication predicate or parent manifest validation was weakened.

The summary reference binds currently available bytes. It is **not** a completed fleet result, manifest acceptance, content authenticity claim, valid graph claim, or proof of all requested child coverage. Native must validate the terminal's index hash and captured run/generation/selection identity, fixed summary path, bounded no-reparse read and summary SHA256 before parsing, then retain explicit partial/unavailable status. Missing/corrupt graph remains unknown, not zero relationships.

An already modified summary can be newly bound by a partial broker rewrite; that is the diagnostic snapshot the broker observed. Modification after that binding cannot satisfy its recorded hash. Full success additionally requires the existing parent and child manifest validations. Partial diagnostic references never make a parent current.

## Verification

`pytest-results.txt`: **12 PASS**, no skipped tests. Focused staged import via `importlib` keeps production modules unchanged.

- Old payload unchanged without summary; exact bytes/hash with one verified child and one skipped child.
- Tampered/missing summary disagrees with recorded index.
- Oversized/directory summaries refused; actual Windows junction ancestor refused.
- Mutation during descriptor read refused.
- Actual broker partial completion emits a hash-bound index, preserves previous current pointer, retains failed execution/unavailable artifact, and never invokes publish.
- Actual valid full manifest path still publishes.
- Tampered/missing summary in normal completion preserves previous pointer and cannot publish.

```powershell
.\.venv\Scripts\python.exe -B -m pytest .tmp\wp043-fleet16-20261023\web\partial-index-tests\test_partial_fleet_index.py -q -p no:cacheprovider --basetemp=<fresh directory within this staging area>
```

Normal sandbox execution could not access pytest's own new temporary directory; the verified run used approved filesystem access. No real process workers/scans, native GUI, provider requests or production edits were performed.

## Limitations

This reuses the repository's no-reparse path-validation policy and adds descriptor checks; it is not a cross-platform transactional filesystem snapshot. Windows does not expose `O_NOFOLLOW` through this `os.open` path, so arbitrary concurrent ancestor replacement by another local process is not proved impossible by this fixture suite. Broker completion already owns a stopped engine branch, and native must revalidate both identity and bytes when reading. A stricter hostile-local-process guarantee would require platform-specific directory/file handles and is separate work.

Oversized/unsafe summaries now refuse an index binding; an existing otherwise successful fleet exceeding 64 MiB would fail closed before publication rather than silently accept an unbounded diagnostic read. This explicit cap requires root acceptance during integration. Summary JSON/schema validity belongs to native/core readers; the binding helper deliberately does not invent or alter graph facts.
