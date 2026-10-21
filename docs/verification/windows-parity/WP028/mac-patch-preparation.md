# WP028 pinned macOS negotiation patch preparation

Prepared against `mlaify/AttackMap-mac` commit `5f2e8b4d84f9dff06e0f87c69c861a434981bd6a`.
No attached worktree or local Git object was available. No fetch, clone, remote write,
Mac compilation, or Mac runtime was performed. This is a reviewable patch artifact,
not an integrated macOS implementation or WP028 acceptance.

`pinned-base/AttackMap/Services/CLILocator.swift` matches Git blob
`265bccaa895e71e2dcffbbfa637e45f34383cd74`. The upstream MIT license is retained.
`prepare_patch.py` verifies that blob, copies the unchanged shared request fixtures,
and emits `mac-desktop-negotiation.patch` plus `patch-provenance.json`.
`git apply --check --directory=docs/verification/windows-parity/WP028/pinned-base
docs/verification/windows-parity/WP028/mac-desktop-negotiation.patch` passed on Windows.
That verifies patch applicability, not Swift type correctness.

The Foundation decoder preserves complete engine identity, handles bounded JSON and
duplicate keys, rejects unknown required schemas/missing commands, keeps schema 1.4
fleet distinct from single-repository support, and refuses to infer advanced AI
support from global mode lists. It constructs inert preflight payloads and decodes
explicit preflight status. Neither method executes or attests an engine action.
CLILocator attaches this result separately from its unchanged legacy CLI flags and
help fallback. No ProcessRunner, ScanViewModel, export, Windows, core, or shared
fixture source changed. XCTest source covers negotiation failures, advanced mode
support, fleet separation, preserved shared request objects, complete identity, and
preflight truth. The frozen shared `request-current` fixture is schema 1.1; it is
not relabeled as a newer contract. Schema 1.3/1.4 negotiation cases are local test
data, not claims of a shared fixture or executed engine response.

On a pinned macOS checkout, review and apply with `git apply --check` followed by
`git apply` using the absolute patch path. The existing XcodeGen route is:

```sh
xcodegen generate
xcodebuild test -project AttackMap.xcodeproj -scheme AttackMap -destination 'platform=macOS' CODE_SIGNING_ALLOWED=NO
```

The pinned project targets macOS 15 and Swift 6. These commands were not run on
this Windows host, which has no Swift/Xcode toolchain. Next work requires an
explicit lease for ProcessRunner/action framing, captured manifest generation,
ViewModel publication/staleness, selected-artifact export, and actual Mac runtime
acceptance. Existing raw-path/export-existence behavior is not made safe by this
decoder preparation alone.
