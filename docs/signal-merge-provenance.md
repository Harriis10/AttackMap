# Normalized signal merge provenance (AM012 / C11 foundation)

`ScanResult.signals` preserves observations in the existing normalized `Signal`
model before the typed hint merge loses duplicate information. `all_signals()`
uses those preserved records and adds observations from later typed passes.
Typed hints retain their existing first-representative behavior, including auth
upgrades, but merged objects are deep copies: downstream changes no longer
modify the original analyzer result.

Each normalized observation has a deterministic SHA-256 identity derived from
its signal kind, intrinsic value and source location (routes use the existing
method/path/file identity). Outbound methods and distinct secret locations stay
separate. Canonical normalized ordering and representatives are independent of
analyzer order. Origins preserve producer name, evidence, location, and property
values; conflicting property values remain explicit and attributable. Missing
file/line information has an explicit reason. The core adapter captures a
producer's explicitly declared `AnalyzerMetadata.version` in its normalized
origins. An omitted version stays `legacy_unknown`: the metadata model's default
version is not treated as observed producer metadata. More-specific producer
names/versions supplied by a plugin are preserved; the outer analyzer's version
is never assigned to a different producer. Analyzer results are deep-copied
before attribution, so the producer's returned objects are not modified.
No version or runtime observation is invented.

When every input enumerates `scanned_files`, merged coverage counts the unique
union. If any input omits enumeration, the legacy aggregate remains available
with an overlap limitation, including a single legacy analyzer; hint locations
never stand in for scan coverage. Slash-normalized coverage paths are deduplicated
without changing their case.

Built-in source and config scanners now enumerate the relative files they actually
accept from their read/indexed inputs. A file with no emitted signal is still
included. Unsupported source suffixes, excluded config filenames, skipped
directories, unreadable/undecodable files, over-size files and index-budget
exclusions are not enumerated. Config's standalone and shared-index paths use
the same acceptance filters. Empty known coverage is `[]`; unknown older-plugin
coverage remains `None`. Numerical counts cannot stand in for enumerated files.
This records source inclusion, not universal language/rule coverage or runtime
verification. Snapshot mutation limitations remain separately visible.

This bounded slice covers the twelve signal kinds already synthesized by
`all_signals()`. Other typed weakness collections retain the legacy merge rules.
Whole legacy typed-result ordering is intentionally unchanged; permutation
invariance applies to the normalized observations. Provenance propagation into
findings, ownership relationships, older-plugin metadata upgrades, and client
presentation remain necessary before declaring C11 complete.

Focused fixtures cover accepted files without observations, both config paths,
unreadable and undecodable files, oversize and byte-budget exclusions, overlapping
coverage, legacy unknown coverage, declared vs default metadata versions,
producer ownership and JSON round-trip preservation. Whole-repository core passes
that do not supply a producer/version retain explicitly unknown provenance.

On 2026-10-15 a deterministic built-in-only scan of `C:\tmp\juice-shop`
(engine 1.5.1; no AI, CVE lookup or network operation) enumerated 862 unique
accepted files and 2,596 normalized observations. 2,385 origins carried declared
producer versions (`config` 0.1.0 and `javascript-web` 0.2.0); 218 later/core
origins retained unknown versions. There were no analyzer errors. The canonical
coverage-list SHA-256 was
`10d2801ae9ae534a152885848f04146772539a99717b24334e7d76242155dadb`.
The local proof is saved outside that repository in
`.pytest_cache/m3-coverage-proof/juice-shop.json`. This verifies the targeted
source snapshot and built-in scope; it does not certify third-party enumeration
or close the remaining C11 ownership/consumer work.
