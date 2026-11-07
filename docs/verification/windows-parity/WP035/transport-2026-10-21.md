# WP035 captured-input transport partial checkpoint — 2026-10-21

Scope: new snapshot_transport.py; narrow index scoped/process pin helpers; host
input/output identity binding; one shared bundle in analyze_repository. No index
prefetch/build changes, source selection changes, native edits or schema changes.
Whole WP035 remains OPEN/PARTIAL. Parent-authoritative producer admission follows
this transport checkpoint; supported-OS/frozen qualification remains separate.

## Input and lifetime contract

`SnapshotBundle(index)` writes one ZIP_STORED archive from accepted captured raw
records and core-only normalized UTF8 text. It never recaptures the repository,
extracts archive paths, base64-encodes bytes or holds a second parent aggregate of
raw/text payloads. SDK/core ordering and acceptance remain distinct. The manifest
preserves source hashes, original sizes/mtime, typed partial resource metadata,
snapshot/config identity and original byte encodings/newlines, including binary
enumeration and SDK legacy decoding. Per-file core-only encoding is required when
the SDK capture cap left that accepted core file without a raw SDK record.

The immutable descriptor carries parent-known root, snapshot/config identities,
archive SHA256 and exact count/byte/path/member bounds derived from the actual
capture and serialized overhead. There is no new arbitrary tighter source cap.
The reader checks archive size and streaming SHA on one open descriptor before
ZIP parsing, then bounded member reads, exact membership, compression/encryption,
duplicate fields/members, paths, aggregate/per-file bounds, raw/text hashes and
reconstructed snapshot/config identity. No archive extraction occurs. ZIP directory
and JSON/model memory overhead still need measured admission; a large capture may
fail the existing child job cap as an explicit named partial result. This is not
a memory-safety proof or a security boundary against malicious same-user mutation.

`pinned_index_scope` restores the prior ContextVar pin. A dedicated isolated child
also calls `install_process_snapshot` before plugin IMPORT. This immutable process
pin reaches plugin-created threads and persists through interpreter shutdown;
conflicting second installation fails. Parent/default execution never installs it.
Legacy analyze(root) SDK plugins continue to work; index is forwarded only when
the callable accepts it. Missing capture entries never fall back to live repo data
in these cooperating SDK calls. Explicit direct filesystem/network access remains
unrestricted; the output snapshot declares offered captured inputs, not authenticated
proof that arbitrary plugin code used only those inputs.

One archive is shared over isolated siblings. Reader leases release only after
the supervisor's verified entire-tree completion, or verified no-child launch
failure. Bundle close waits for every lease. Host quarantine strongly retains
uncertain workers/workdirs and their bundle through callbacks, blocking unsafe
later host admission until verified cleanup. Foreign result root or an explicit
conflicting result snapshot/config is a named invalid-output failure for that
analyzer; an absent legacy snapshot is bound to the parent capture.

## Verification actually run

* Initial transport suite:23PASS/48.81s, including actual child import-time SDK read
  after deleting the original repo, and actual malformed input rejecting before
  the plugin's import marker.
* Expanded suite plus existing good/crashing sibling integration:33PASS/1fixture
  failure168.58s. The deliberately rewritten foreign-root plugin had the same
  size/timestamp as its cached Python bytecode, so its original code ran. The
  fixture now changes size to invalidate that bytecode. This was a fixture failure,
  not evidence that a foreign root was accepted.
* Final targeted current-source command selected foreign-root/snapshot sibling
  rejection/recovery, actual background shutdown and thread SDK reads after repo
  deletion, stale bundle identity, quarantine archive lifetime and10malformed
  sealed-input cases: **17PASS/131.03s**. Duplicate ZIP member warning is expected
  from the adversarial fixture. No full matrix was repeated.

Actual small Windows child evidence is separate from injected quarantine/lease
seams. The expanded passing checks also cover core-only partial SDK acceptance,
empty captures and identity/resource metadata roundtrip. Concurrent immutable
WP034 campaign load means no speed/memory comparison is claimed. No provider,
GUI, remote CI, macOS/Linux or frozen-engine run was performed for this slice.

Remaining: producer/version/classification authority with legacy aliases,
cross-platform actual host suites, source/frozen equivalence and real working-memory
qualification. Subprocess supervision and hashes are not an OS sandbox or
cryptographic authenticity.
