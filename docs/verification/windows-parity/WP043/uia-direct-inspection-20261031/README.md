# WP043 direct UIA modal inspection — 2026-10-31

This bounded harness correction removes two failure-masking dependency paths
identified by independent review. It does not repair native rendering. WP043
remains IN_PROGRESS, rendering acceptance FAILED, and V01–V03 blocked. No new
live capture was run; final independent source/test review is the next gate.

`pywinauto` catches COM errors and returns an empty descendant list or false
visibility. Its class-name and other metadata getters also suppress COM errors.
Those defaults cannot establish that a frame is free of a client modal.

The guarded inspection now calls raw UIA `ElementFromHandle`, `FindAll`, array
`Length`/`GetElement`, and Boolean `IsOffscreen` property 30022. It reads raw
class-name and modal metadata properties. Enumeration or unreadable-element
failures therefore retain their actual exception/HRESULT as structured fatal
evidence rather than being mistaken for no modal or an invisible element.

Only explicitly recognized UIA element-unavailable / invalid-HWND errors allow
one complete fresh scan, with the existing owned-process, foreground, geometry
and occlusion rechecks. Access, RPC, unknown and invalid-result failures remain
fatal without retry. Once a visible modal is confirmed, a later metadata error
is fatal even if classified stale, with `modalConfirmed=true`; it cannot erase
the confirmed modal by rescanning it into a clear result. No unreadable element
is skipped and no exception-context traversal is added.

The expanded tests inject actual COMError instances at direct enumeration and
visibility boundaries, assert no accepted capture and persisted structured
evidence for access/RPC/unknown failures, cover one allowed complete rescan and
retry exhaustion, and verify raw root, array, class-name and confirmed-modal
metadata failures. Existing modal recognition and transient-recovery tests remain.

Exact full harness command, executed through elevated `cmd.exe` with ordinary
temporary-file access:

```text
C:\Projects\INPROGRESS\AttackMap\.venv\Scripts\python.exe -m pytest tests/test_wp043_live_capture.py -q -p no:cacheprovider --junitxml=docs/verification/windows-parity/WP043/uia-direct-inspection-20261031/harness-tests.xml
```

Exit code 0: **90 passed, 83 subtests passed in 8.22s**. The retained
[JUnit report](harness-tests.xml) contains 173 cases, zero failures/errors/skips.
`git diff --check` passed for the scoped harness, tests and evidence paths.
The [verification record](verification.json) binds the exact source and JUnit
SHA-256 values to this run. These deterministic tests use raw-API fakes; they do
not execute a real UIA provider, native rendering, model calls or live pixels.
