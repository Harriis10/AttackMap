# Shared worker process supervision on Windows

The Windows desktop runner now admits one scan at a time under a lock. Admission
remains occupied during cancellation and completion publication. Only verified
worker exit and an empty Windows job permit release. Failed cleanup keeps the
slot occupied and the HTTP adapter shows a generic cancellation error.

`WindowsProcessJob` in `execution/windows.py` is a small containment seam. The worker starts
suspended, is assigned to a Windows Job Object, then resumes. Descendants remain
in that job even if the original worker exits. Job handles use kill-on-close;
workers are not permitted to escape the job. The implementation uses Windows
Job Object APIs and `NtResumeProcess` on the suspended process handle. Failure
to establish containment fails the launch instead of running an uncontained
worker. Native Windows runtime checks are required for every shipped target.

`ScanRunner.cancel()` attempts a graceful control-break request, waits up to
three seconds for the worker and job to exit, then terminates the job and allows
two seconds for verified exit. A windowless worker may not accept a console
control event, so forced cleanup remains necessary. `cancel()` returns a boolean
verification result; it does not release admission itself. `request_cancel()`
provides a nonblocking runner API, and `on_done` remains the completion signal.
`attackmap.execution.ProcessSupervisor` now owns these controls. It accepts an
explicit argv/environment, optional timeout, a raw progress-dictionary callback,
and an `on_done(code, diagnostic_tail)` callback. `wait(timeout)` signals only
after verified cleanup and completion callback return. The UI `ScanRunner` is
a thin command/environment/report adapter; core execution imports no UI or Typer.
The admission slot is per supervisor instance; callers must share an instance
when they require an exclusive slot. POSIX uses a new session and process-group
signals; macOS runtime acceptance is still outstanding.

The `/api/cancel` adapter changes `RUNNING` to `CANCELLING` once under the app
lock, dispatches cleanup on a background thread, and immediately returns its
snapshot. A false result or exception shows a generic error and leaves restart
blocked. Cleanup errors are guarded by run identity so an old callback cannot
change a newer run. Terminal cancellation still comes from the worker's verified
completion callback; an HTTP acknowledgement alone is not a terminal outcome.

Both output streams drain concurrently in bounded 4,096-character chunks. The
diagnostic tail retains at most 50 chunks, including unterminated output. A
progress callback exception does not abandon a still-running worker. Progress
events exceeding one chunk are not decoded as an event; this is a current
protocol limitation. The larger worker-native run protocol remains separate.

## Verification and limits

`tests/test_ui_supervision.py` exercises 20 simultaneous start requests with
exactly one spawned worker, an actual parent/child fixture that ignores graceful
signals, forced job cleanup with both PIDs verified dead, blocked admission on
unverified exit, job-query failure, bounded 1 MB output, callback failure,
invalid launch arguments, asynchronous HTTP acknowledgement with delayed
cleanup, generic error handling, and stale cancellation identity protection.

The controlled Windows fixture checks acknowledgement below 250 ms and cleanup
within a 6.5-second test envelope. That single test is not the p95 evidence; the separate 50-cycle core
test below supplies that measurement. Parallel fleet workers now use the same
supervisor, bounded stderr tail, cancellation cleanup and a 600-second timeout.
The desktop broker uses it with a validated configurable timeout (600 seconds
by default). Real serial/parallel fleet tests agree for all presentation formats
and Unicode paths. Exceptional cancellation callbacks wait for verified cleanup
before their exception escapes. This does not close AM010/C09: foreground CLI
lifecycle parity, the full lifecycle cycle matrix,
resource measurements and packaged Windows acceptance remain outstanding.
No macOS runtime, Windows ARM64, or clean-install support is established here.

`tests/test_execution_supervision.py` separately checks shared timeout cleanup,
failed cleanup retaining admission, and 50 real Windows parent/child cancellation
cycles. The cycle test reports nearest-rank p95 acknowledgement and tree-exit
latency and requires every tree to exit within five seconds. This controlled
fixture does not establish packaged clean-install, handle/memory drift, or
Windows ARM64 acceptance.

On the current Windows host (2026-10-15), the 50-cycle controlled fixture passed:
acknowledgement p95 0.000933 s, verified tree-exit p95 3.043700 s, maximum
exit 3.065347 s. Both parent and ignoring child were checked dead every cycle.
The three shared supervisor tests completed in 170.57 s. These are local
source-run measurements, not packaged-release or cross-platform certification.
