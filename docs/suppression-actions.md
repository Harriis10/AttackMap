# Reviewed suppression actions

`attackmap.suppression_actions` provides a transport-neutral JSON boundary for
`suppression_preview`, `suppression_apply`, `suppression_undo`, and
`suppression_recover`. `execute_suppression_action(operation, payload)` returns
`status`, a local message, and a plan or receipt where appropriate. The native
`SuppressionPanel` emits operation/payload requests; its host owns process dispatch.
The panel itself never starts a subprocess.

Preview is read-only and requires a nonempty bounded reason. It shows the exact
ID, identity scheme, governance fields, provenance, and file diff. Apply is a
separate user action. The writer uses the existing repository-root
`.attackmap-suppress.yaml` / `.yml` preference and exact finding ID selectors.
An aggregate ID can cover multiple current or future instances of that rule/entity;
it is not a line-specific exception. Legacy title IDs or rule-less findings require
explicit identity review, and unknown recorded IDs are refused rather than guessed.

Existing reasons, provenance and other YAML settings are retained semantically.
YAML is reserialized, so formatting/comments can change; the preview shows those
changes. The receipt retains the exact original UTF-8 bytes as text, including
line endings, for exact Undo. New entries retain action ID, origin, report run,
recorded identity, creation time and identity scheme in `provenance`, plus optional
owner/ticket/expiry. Existing suppression matching and governance remain in the
core engine; extra action provenance is retained in the file/receipt, while legacy
report adapters may expose only their existing reason/declaration-source fields.

Apply validates and reconstructs the complete plan, checks current file SHA-256,
writes a sibling temporary file, flushes it, checks the destination again, and
atomically replaces it. Paths outside the repository suppression filenames,
symlinks, junctions, malformed plans and changed destinations are refused. Undo
requires the exact applied snapshot; it restores the prior bytes or removes a
new file. It never overwrites intervening user changes. The host must serialize
actions for one repository; checksum checks do not establish a general filesystem
compare-and-swap primitive against arbitrary concurrent external writers.

Plans/receipts contain local configuration snapshots and are not authorization
tokens. The caller must retain a plan durably **before** applying it and retain
the receipt for ordinary Undo. `suppression_recover` with `{"plan": plan}` checks
the current before/after hash and reports `applied`, `not_applied`, or
`review_required`. `suppression_undo` can also accept that retained plan to recover
and undo an interrupted action. An apply retry is idempotent when the exact after
snapshot is already present. Process cancellation after commit cannot promise
rollback; recovery inspects the actual saved state. Rescan after apply or Undo to
update findings; the action does not silently rewrite the loaded report.

Fixture tests cover engine matching, existing reason/provenance retention, stable
and legacy identities, invalid/tampered plans, postcommit recovery, interrupted
replace, concurrent file changes, and redirected paths. Native compile and live
workflow checks are separate from those core tests.
