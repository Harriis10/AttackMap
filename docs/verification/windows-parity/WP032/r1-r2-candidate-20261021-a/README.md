# WP032 R1/R2 isolated candidate

**Not applied to canonical source.** `candidate.patch` changes only contracts.py,
crossrepo.py, and one new focused test file. The complete candidate files and
their hashes are retained beside the patch. Patch applicability check exited 0.

Baseline pure reproducers ran against the unchanged owned source copy and
confirmed both defects: reversing same-line authority calls changed the single
emitted resolution; wrong-handler taint/BOLA evidence supplied a flow for a link
bound to another file. Actual results/import paths are in
`baseline-pure-reproducers.json`. `candidate-pure-reproducers.json` shows both
authority seams retained in stable order and both wrong-file flows rejected.

The candidate dedup key retains normalized destination authority, normalized
scheme and caller verb while preserving same-authority instance-URL collapse.
Tie sorting retains distinct destination/verb legs in stable order. Existing
observed/candidate/proxy resolution logic remains unchanged. Cross-boundary
taint/BOLA selection now also requires exact producer route_file equality with
the link's server_file; case-sensitive path and method checks remain in place.

Focused result: **139 distinct cases passed (109 existing + 30 new)**. Initial
attempt:136 passed,3 sandbox Windows temp ACL setup errors, no assertion failure.
Only those three failed fixture setups reran under approved filesystem access in
a fresh owned directory:3 passed. Both attempts' XML/stdout/stderr/commands are
retained; no failure was relabeled as a pass. No full suites, scan-service run,
real repository scan, model/provider, GUI, or credential operation occurred.
The existing bare-fetch unit fixture invokes deterministic scanner parsing on
its tiny synthetic source; it is not a product scan acceptance result.

All **139 captured canonical source/test inputs** stayed byte-identical. Owned
copy changes were exactly the two production files plus the new test. The tests
ran with PYTHONPATH and cwd pointing to the owned copy, disabled bytecode/cache
writes, and no package installation. `candidate-summary.json` records exact
counts, hashes, patch status and scope. Root must explicitly release the
canonical lease before applying this patch and running canonical focused checks.

R3 score/reference and R5 fleet snapshot designs are separate documents in the
parent WP032 directory; no model/schema/snapshot changes are bundled here.
