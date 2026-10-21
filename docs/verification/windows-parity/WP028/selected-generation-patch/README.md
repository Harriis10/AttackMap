# WP028 additive selected-generation patch — review preparation

Target: `mlaify/AttackMap-mac` commit
`5f2e8b4d84f9dff06e0f87c69c861a434981bd6a`. This adds four Swift files and owned
fixtures only. It does not modify the previous negotiation patch, Mac host/UI,
canonical Windows/core/tools, or shared fixtures. The pinned upstream MIT license
is retained. `pinned-tree-check.json` records that the four Swift paths are absent
from the complete pinned tree listing obtained read-only earlier in this task.
No local pinned Git object/checkout was available; no fetch/clone/remote write
was performed. `git apply --check` against the retained base proves only additive
patch applicability, not compilation or runtime behavior.

## API and intended behavior

`SelectedGenerationReader.capture(reportURL:displayedReport:expectedRepository:expectedGeneration:)`
takes the exact bytes the host decoded. It binds their hash and file identity,
the complete captured manifest hash, schema/type, generation ID, repository,
unique listed paths/names, and the displayed report's compatibility-export entry.
Artifacts retain the producer's order. Its manifest projection accepts current
schema `1.0.0`, type `attackmap_artifact_manifest`, ordered `sections` and
`compatibility_exports` entries with name/path/format/role/checksum. It does not
invent a new schema or deserialize unknown fields into executable behavior.

An absent manifest permits only an explicit `legacyUnverified` JSON selection.
An expected live generation cannot downgrade. A present invalid, unreadable,
redirected, unsupported, oversized, or duplicate-key manifest fails. Legacy
selection exposes only the captured JSON, even if adjacent Markdown exists.
`read(_:from:)` rejects artifacts from another selection and rechecks the captured
report/manifest before and after reading bounded artifact bytes. Replacing a path
with identical bytes but another file identity is stale. Newly appearing manifests
invalidate legacy selections. Checksums express local integrity, not authorship,
authenticity, action completion, freshness of a scan, or evidence quality.

`SelectedGenerationExport.copy(_:from:to:)` verifies bytes before staging, rejects
destinations within the source directory, writes an exclusive staging file in the
opened destination directory, rechecks destination/source identity, and uses
descriptor-relative rename for atomic replacement. Existing destinations are
preserved on errors before rename. It does not report a post-commit durability
failure as though the old destination were preserved. No save picker, rendering,
process launch, shell interpolation, or provider request occurs in these files.

Filesystem operations traverse absolute local file URLs through Darwin directory
descriptors with `O_NOFOLLOW`; regular source files require link count one.
Actual file IDs detect aliases on case-sensitive and case-insensitive volumes
without guessing their case rules. Bounds: 1 MiB manifest, 512 records, 64 MiB
report/artifact, JSON nesting 64. Unsafe path components/controls, nonregular
files, ancestor/leaf symlinks, hardlinks, duplicate paths/names, missing files,
and changed inode/size/mtime/ctime/hash are rejected. Opening a directory does not
require its timestamp to remain stable, because staging legitimately changes the
destination directory. Content reads recheck their leaf identity after reading.

## Fixture provenance and preparation

`prepare_selected_generation_patch.py` creates new owned fixtures through the
actual current `attackmap.artifact_manifest.write_artifact_manifest` producer.
It copies `fixtures/desktop-parity/report-empty.json` byte-for-byte, writes clearly
synthetic review/run-manifest contents, and fixes only the producer's fixture clock
to `2026-10-21T00:00:00Z`. No scan/provider executes. `fixture-provenance.json`
records producer/helper/shared-report hashes and every output hash. Existing owned
fixtures are hash-verified rather than silently regenerated against a newer core.
The shared `desktop-parity/manifest.json` is an inventory manifest and is not used
as an artifact-generation manifest. Generation and repository identity in these
fixtures are synthetic, not evidence of a completed engine action.

The generator emits `selected-generation.patch` and `patch-provenance.json`.
On Windows, only producer fixture generation/hash checks and patch applicability
are verified. The 17 XCTest methods are prepared source, **not run or passed**.
They cover selected identity/order, explicit legacy handling, invalid manifests,
duplicate/unsafe paths, stale replacement/tamper/missing files, symlink/hardlink/
nonregular paths, size bounds, destination alias restrictions, exact copying,
replacement, and preserving existing destinations on validation failure.

## Explicit limits and next acceptance

- Swift type checking, CryptoKit/Darwin API compatibility, and XCTest execution
  remain unverified. No Swift/Xcode compiler is available on this Windows host.
- All Mac filesystem behavior, APFS volume case/Unicode handling, concurrent
  mutation/race behavior, permission failures after staging, and crash cleanup
  require actual Mac testing. Tests currently do not inject mid-read growth,
  post-staging I/O faults, or a concurrent destination swap. Atomic visibility is
  intended on a local filesystem; power-loss durability and remote/network-volume
  guarantees are not claimed. Failed cleanup after an OS error may leave an
  owned `.attackmap-export-<UUID>.tmp` file, never an unrelated file deletion.
- Rejecting all symlink ancestors/hardlinks is deliberately strict; trusted
  system aliases such as `/tmp` must be resolved by the future trusted picker
  boundary before capture. The component never resolves an untrusted artifact
  symlink as a fallback. Source inputs must remain within the stated bounds.
- The caller must supply successfully decoded report bytes and any expected
  live repository/generation. This is an integrity projection, not validation of
  every report or additive manifest field, nor proof of terminal/exit agreement.
  A fleet child requires its own independently captured manifest selection.
- ProcessRunner, ScanViewModel, and ReportExporter integration is intentionally
  absent. The old raw-path APIs still behave as before. Host async epoch/Stop/
  cancellation and picker selection-switch protection are not implemented here;
  these files cannot alone close WP028 or justify a product safety claim.

Review/apply on the exact Mac checkout with `git apply --check` then `git apply`
using this patch's absolute path. Run the existing pinned XcodeGen route:

```sh
xcodegen generate
xcodebuild test -project AttackMap.xcodeproj -scheme AttackMap -destination 'platform=macOS' CODE_SIGNING_ALLOWED=NO
```

After component review and actual XCTest results, lease host integration and
native rendered report/select/export journeys separately. WP028 remains open.
