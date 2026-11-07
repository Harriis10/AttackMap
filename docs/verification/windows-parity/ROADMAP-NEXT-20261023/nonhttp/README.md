# WP044: prepared shared-datastore contract

**96 deterministic tests PASS. Contract preparation only.** Existing scanner
signals cannot establish qualified non-HTTP identity or operation. Production
shared-datastore, producer/consumer and RPC/schema connectivity remain
`unanalysed`; WP044 remains IN_PROGRESS.

The separate pure helper validates explicitly supplied declarations and projects
only undirected `declared` shared-resource associations, with both sides' source
references. All identity dimensions must match. Conflicts are ambiguous and
excluded; lone resources are unmatched. It accepts no snippets or connection
strings, exposes safe errors, and limits input to 256 declarations / 16 roots.

- [Contract and remaining extraction work](CONTRACT.md).
- [Generated JSON Schema](shared-datastore-declaration.schema.json); semantic
  validators in Python additionally enforce host/path/identifier policy.
- Paired synthetic fixtures: [matching](fixture-paired.json),
  [different port](fixture-different-port.json), [ambiguous](fixture-ambiguous.json).
- [Final JUnit](tests-03.xml): 96 PASS, zero failures/errors/skips. This comprises
  66 helper cases and 30 fleet architecture cases. Earlier JUnit files are
  intermediate runs: 85 PASS with shared cache ACL warning, then 95 PASS.
- [Verification](verification.json): complete saved fleet16 graph equality after
  removing only the additive prepared-contract metadata. Every original node,
  edge, ID, evidence reference, HTTP/proxy leg and coverage fact is preserved.
  [Before](fleet16-before.json) / [after](fleet16-after.json) are deterministic
  unit fixtures, not scanner or provider results.
- [Before source hashes](source-before.json), [after source hashes](source-after.json),
  [machine-readable handoff](HANDOFF.json).

Final commands from repository root:

```powershell
.venv/Scripts/python.exe -m pytest tests/test_fleet_resource_identity.py tests/test_fleet_architecture.py -q -p no:cacheprovider --basetemp=.tmp/roadmap-next-20261023-nonhttp-03 --junitxml=docs/verification/windows-parity/ROADMAP-NEXT-20261023/nonhttp/tests-03.xml
.venv/Scripts/python.exe docs/verification/windows-parity/ROADMAP-NEXT-20261023/nonhttp/verify_contract.py
```

The verifier's first attempt used the wrong repository-parent depth and exited
before writing results. The depth was corrected and the saved final verification
passed. No production patch changed after the final focused test run.

No actual repository scan, LM Studio call, native build, visual/manual check or
package qualification was performed. The helper is not called by scanners or
the fleet pipeline. Current production fleet output adds only
`coverage.protocols.shared_datastore.extraction_contract`; it does not accept
these declarations yet. Representative production fleet, child snapshot binding,
real extraction, runtime integration, native mapping, release/clean-host and
macOS gates remain open. No commits or shared tracker edits were made.
