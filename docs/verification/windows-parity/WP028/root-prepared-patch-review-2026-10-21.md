# Prepared macOS patches — integration review

These are prepared changes against macOS HEAD
`5f2e8b4d84f9dff06e0f87c69c861a434981bd6a`, not an integrated Mac client.
Windows apply checks do not establish Swift type checking, Xcode tests, native
behavior, accessibility or release acceptance. No Mac checkout or toolchain was
available for this review.

The capability decoder patch preserves the old CLI path and adds a narrow
desktop-capability projection. Its six prepared XCTest methods still need to
run on the actual Mac project. The separate selected-generation patch adds a
descriptor-based reader and staged exporter with seventeen prepared XCTest
methods and current producer fixtures. The shared fixture inventory manifest is
not an artifact manifest; the latter fixtures were emitted by the current
Python producer and have independent recorded provenance.

The selected-generation implementation was read in full. It binds decoded
report bytes/hash, manifest bytes/hash, repository and generation; refuses an
invalid present manifest rather than downgrading it; restricts section paths;
checks regular-file identity before and after artifact reads; and stages export
under an opened parent before rename. Integrity does not establish authorship,
successful broker completion or a trusted origin. Legacy missing-manifest JSON
remains an explicitly separate case.

Before promotion, the host must pass repository identity from the exact decoded
report and preserve the selected-workspace epoch. Broker terminal/generation
agreement must remain mandatory for live results. ProcessRunner, ViewModel and
the existing ReportExporter have not been wired by these additive files.

Native compatibility review must check the 64 MiB report/artifact cap, 1 MiB
manifest cap, 512 section cap, depth/duplicate-key limits, strict hardlink and
symlink rejection, Darwin openat behavior and trusted-picker path resolution
(including normal `/var` aliases). The basename restrictions include Windows
compatibility characters and trailing dot/space; verify their appropriateness
against actual supported Mac exports before adopting them.

Run XcodeGen/project integration and xcodebuild tests against the pinned source,
then collect Mac UI and installation evidence separately. Neither prepared
patch closes WP028 or WP038. Existing immutable patch/provenance hashes must not
be relabeled as integrated Mac proof.
