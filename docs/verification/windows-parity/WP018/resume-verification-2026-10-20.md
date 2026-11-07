# WP018 resumed verification — 2026-10-20

Base: `a8c4786` on `main`. Resume owner: `/root/wp018_resume`.
This record supplements the checkpoint implementation notes; it does not claim
frozen, native desktop, provider, or release acceptance.

## Minimal correction

`generation_dir` validates the destination, creates the generation directory,
and rejects a finalized generation. Two broker fixture tests then called
`folder.mkdir(parents=True)` on that allocated directory. Removed only those
two redundant calls in `tests/test_desktop_fleet.py`:

- `test_broker_partial_preserves_previous_current_and_rejects_stale_progress`
- `test_parent_publication_failure_with_complete_children_is_failed_not_partial`

No production source was changed in this resume slice. In particular,
`collect_children` retains the checkpoint's read-only path lookup and exact
manifest validation; the missing-child test still asserts no allocation.
The fixture tests still exercise finalized child generations, stale progress,
partial/failure outcomes, and preservation of the previous current pointer.

## Commands and actual results

All pytest commands use the workspace `.venv` interpreter. Each basetemp name
was new for its invocation. Denied and historical temp directories were preserved.

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_desktop_fleet.py -q --basetemp .tmp-wp018-resume-focus-20261020-a -p no:cacheprovider -x
```

Sandbox attempt: exit 1, `PermissionError: [WinError 5]` accessing the newly
created basetemp during pytest setup/cleanup. No usable pass result. The denial
was handled by normal command escalation; no ACL or filesystem bypass was used.

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_desktop_fleet.py -q --basetemp .tmp-wp018-resume-focus-approved-20261020-b -p no:cacheprovider -x
```

Approved run: **38 passed in 92.25s**, exit 0. This verifies the previously
failing fixture setup and the checkpoint read-only collector tests.

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_fleet_parallelism.py tests/test_fleet_publication.py tests/test_unreadable_and_fleet_failures.py -q --basetemp .tmp-wp018-resume-regression-approved-20261020-c -p no:cacheprovider -x
```

Approved regression run: **29 passed, 1 skipped in 496.13s (0:08:16)**,
exit 0. The skipped check is
`test_unreadable_file_is_skipped_and_reported`: its `needs_chmod` marker
explicitly skips Windows/root because `chmod 000` is not enforced there.
This is an unexecuted unreadable-file assertion, not a pass.

The three real source-worker parity cases (`all`, `json`, `markdown`) passed.
They use generated `service one` / `služba dvě` roots and compare serial/parallel
scan models, findings, attack paths and suppressed counts. Other passing checks
cover bounded worker scheduling, frozen-argv simulation, sibling preservation,
stale interchange, cancellation/publication races and fatal usage errors.

`git diff --check -- tests/test_desktop_fleet.py`: exit 0. Git emitted only its
existing Windows line-ending normalization warning. The test diff removes two
lines and adds none.

## Remaining acceptance

The focused suite is fixture/seam evidence. Real source Python workers in the
regression suite use tiny generated repositories; they are not a production
installed/frozen engine or `C:\tmp\juice-shop` acceptance run. Frozen argv checks
are simulations, not an executed fresh frozen artifact.

No native EXE, GUI preview, provider HTTP, production scan, schema regeneration,
commit, push, broad cleanup, or shared source/tracker edit was performed by this
resume owner. A scoped WMI ownership read was denied; no independent system-wide
process audit is claimed.

WP018 must not be DONE from these checks alone: fresh frozen serial/parallel
equivalence across output formats and real owned-process cancellation/cleanup
acceptance remain open, along with root review of the final evidence.

Recommendation: **IMPLEMENTED**, subject to root review, with the above runtime
gates retained explicitly. Combined completed checks in this resume:
**67 passed / 1 deliberate platform skip** across two approved pytest runs.
This does not include the sandbox ACL attempt as a passed verification.
