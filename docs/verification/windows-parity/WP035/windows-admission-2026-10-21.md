# WP035 Windows memory admission partial checkpoint — 2026-10-21

Whole WP035 remains OPEN/PARTIAL. This slice fixes job setup ordering and cleanup
ownership only. It does not implement snapshot transport/pre-import SDK pinning,
parent-authoritative provenance, filesystem/network isolation, or supported-OS
qualification. WP034 working-memory measurements remain a prerequisite.

## Source/API

`WindowsProcessJob(memory_bytes=0)` validates a native-sized nonnegative integer
and sets KILL_ON_JOB_CLOSE plus optional JOB_MEMORY in one job configuration call.
Failure closes the created job and preserves the original Windows error. The
supervisor's additive `start(..., job_memory_bytes=0)` configures that job BEFORE
Popen(CREATE_SUSPENDED), assignment and resume. Default callers still pass no new
job constructor argument. No failure is swallowed or retried without the cap.

`ProcessSupervisor.memory_policy` distinguishes requested/enforced bytes and
disabled/enforced/setup_failed/unsupported_on_platform status. Positive requests
on non-Windows keep existing functional behavior with explicit unsupported policy;
the host adds an unenforced-memory limitation to successful results. There was no
Linux/macOS OS enforcement test in this Windows run.

`retry_cleanup()` can recover a pending run only by acting on the stored owned
Popen/job objects and verifying leader exit plus job/process-tree emptiness.
Callbacks and slot release occur once, after proof. A stale run's numerical PID
cannot release a newer owned object. The isolated host strongly retains uncertain
supervisors and their work directories; later isolated calls are refused until
wait/recovery proves cleanup. No forced cleanup bypass or acknowledgement-based
refund exists. A failed cap setup with verified no-child state is an ordinary
named host launch failure; uncertain launch cleanup is HOST_STUCK/quarantined.

The host no longer treats95% of a requested cap as proof of a breach. A worker
reporting MemoryError produces the existing named memory error with explicit
unverified cap causality and known/unknown peak context. A valid high-peak result
stays valid. A native crash without a MemoryError report remains a named crash;
the classifier does not invent its cause. Producer identity/worker reports are not
authenticated; provenance admission is a separate pending slice.

Frozen source hashes:

* execution/windows.py: CF48E34DF56BBF2E945501ADB3CE89CBBDAAC202B5F3F3FB94908774653B25C3
* execution/__init__.py: DC1C69E5061B820A79B44D31F87B792A5DA079DB689B46DA5E689528B377EDE5
* analyzer_host.py: ED632E9B454086F4F81F91DD434CBA7145EEFFA883362C3B2796329A887ACBA5

These production files were frozen before root authorized the next immutable10k
campaign. Later edits in this checkpoint are tests/docs only.

## Verification actually run

Initial focused test command selected `test_windows_memory_admission.py`, the
existing host memory-hog and good roundtrip cases, and existing supervisor timeout
and stdin checks: **19 PASS in26.34s**.

Final command:

`.venv/Scripts/python.exe -m pytest tests/test_execution_supervision.py::test_failed_cleanup_retains_admission tests/test_windows_memory_admission.py tests/test_fleet_admission.py::test_actual_small_supervised_children_keep_results_and_reservations tests/test_fleet_admission.py::test_unknown_supervisor_cleanup_blocks_then_late_verified_callback_releases -q --tb=short -p no:cacheprovider --basetemp .tmp-wp035-memory-final-20261021`

**18 PASS in23.55s**. This includes actual Windows64MiB job policy with immediate
8MiB allocation accepted and96MiB allocation denied as MemoryError,128MiB policy
with a256MiB request denied, actual descendant reaping, a subsequent good sibling,
and actual recovery after an injected cleanup-uncertainty branch. The existing
host256MiB memory-hog case passed in the initial command. Ordering/setup-denial,
stale-PID object and concurrent completion tests use injected seams; they are
separate from actual OS evidence. Tests request finite small caps, not host-wide
memory exhaustion. No full repository scan, provider, UI or remote CI was run.

`py_compile` and scoped diff whitespace check passed. Focused commands used the
approved escalation required for reliable Windows temporary fixture ACLs. No
full50-cycle regression matrix was repeated for this narrow source change.

Remaining gates: bounded versioned snapshot transport, cooperating SDK pin before
plugin import, trusted parent provenance policy with legacy compatibility and
forgery negatives, source/frozen equivalence, macOS/Linux tests and explicit
unsupported boundaries. Subprocess containment and hashes remain **not a security
sandbox or cryptographic authenticity**.
