# WP035 isolated provenance checkpoint — 2026-10-21

Scope: parent-authoritative emitter attribution after sealed input/root/snapshot admission. This is a partial WP035 checkpoint, not OS sandbox or cross-platform acceptance.

The parent selects producer name and explicitly declared normalized version. Unknown parent version remains unknown even when a child claims one. Typed output producer hints are canonicalized; normalized origin aliases and conflicting producer/version/classification/property claims are retained only as bounded redacted `untrusted_claimed_*` metadata. Static path classification and semantic observation IDs are recomputed. Existing in-process producer/version policy is unchanged. Model-returning children materialize normalized origins before JSON serialization because legacy typed producer hints are excluded from the wire model; this preserves aliases without trusting them. Dictionary-returning legacy output remains accepted.

Focused checks: tests/test_isolated_provenance_admission.py exercises legacy aliases, forged producer/version/static classification/identity, unknown version, bounded claims and missing locations, including a real Windows child. Existing evil-namespace child proves a forged sibling producer cannot gain canonical isolated attribution while the builtin first-seen typed representative and sibling result survive. Trusted specific-producer/version regression is included. Initial failures identified an invalid fixture kind and the real model-serialization alias gap; the latter was corrected in the worker before final proof.

No source truth/authorship, runtime verification, SDK compliance, filesystem/network restriction, Mac/Linux actual execution, frozen-engine execution or large-repository performance acceptance is claimed. Direct filesystem/network calls remain outside the cooperating SDK snapshot guarantee. C's actual 10k campaign uses its separate sealed source and is unaffected. Nested generated output remains a separate QA qualification, not a demonstrated ingestion defect: watcher ignores alone do not establish scanner policy, but safe_fs already recognizes legacy output markers and excludes individually checksummed modern generated artifacts while preserving added/replaced user sources. A concrete ingested artifact or focused reproducer is required before choosing a change. Clean QA reports are kept outside selected roots.

Production checkpoint hashes:
- snapshot_transport.py E9E077BDCCE994FA962343273D4497B45B1B9C93330B3CE32A09804E2C097148
- index.py E08F80130C293ABDF8A6C9D12715DE5EF1198EE75884A96ED7432765CB977633
- analyzers.py 25AC4E4A574AC5FF668AB1F3C5B090077C712929AF657B031EC4521A6022B766
- analyzer_host.py 9FB7EEA190F7C029C3F782590ED447FB2FC62F3778241E2B0F51ECF96A602553
- signal_provenance.py 97514FA63458E20D0623EF7D4852343BD89653C4BFACBE9BDBC02DFCCD475C1D

Final focused verification: `.venv/Scripts/python.exe -m pytest tests/test_isolated_provenance_admission.py tests/test_analyzer_host.py::test_forged_namespace_cannot_corrupt_sibling_output tests/test_scanned_coverage.py::test_specific_producer_version_is_not_fabricated_from_outer_analyzer -q --tb=short -p no:cacheprovider --basetemp .tmp-wp035-provenance-seal-20261021` — **7 passed in 41.67s**. Separate declared-version/trusted producer checks — **3 passed in 12.11s**. Focused diff whitespace check passed (line-ending conversion warnings only). Production source frozen after these checks; root owns the next broad stable checkpoint and frozen packaging gates. Concurrent campaign load means these durations are evidence timestamps, not performance comparisons.

