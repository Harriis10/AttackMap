# Prepared GUI checkpoint runner

`run-gui-checkpoint.py` is prepared and syntax-checked only. It has not been
imported, preflighted or executed. No app, GUI, provider, product build or test
was launched while preparing it. Root owns independent review and execution.

Default invocation is read-only preflight: full original package inventory and
current release-lock/source binding, explicit manifest path and SHA-256 pin,
seed checksum, safe separate fresh output, and exact planned argv. It prints
JSON and creates no output/profile directory. Add `--run` only after root approval
of the concrete candidate and resource slot. The original package app is required;
this runner does not label package execution as installed-path acceptance.

```powershell
& .venv/Scripts/python.exe -B docs/verification/windows-parity/WP023/astra-gui-20261022/run-gui-checkpoint.py `
  --app 'C:\Projects\INPROGRESS\AttackMap\desktop\windows\artifacts\astra-packages-20261022\dev-20261022113134-4de136c6\app\AttackMap.NativeSpike.exe' `
  --release-lock 'C:\Projects\INPROGRESS\AttackMap\.tmp\wp024-astra-fresh-20261022-01\release-lock.json' `
  --pinned-manifest 'C:\Projects\INPROGRESS\AttackMap\desktop\windows\artifacts\astra-packages-20261022\dev-20261022113134-4de136c6\package-manifest.json' `
  --manifest-sha256 d62a6c7f432cfab616cafda64978eb4cfc7a5b0e2167151737c9df848f4af087 `
  --seed '<absolute canonical JSON from root accepted current-candidate run>' `
  --output '<absolute fresh output under an existing parent>' `
  --phase all
```

Replace seed/output placeholders with actual bound paths. Never reuse an output
directory, including after failure. `--phase basic`, `watch` or `capture` can run
an independently selected phase into its own new output; default `all` executes
the following seven processes sequentially and stops on the first failure:

- basic: startup captures, readiness, menu, history-baseline, retention;
- watch: actual engine single-watch journey on owned synthetic roots;
- capture: full saved-seed capture, no new scan or provider mode.

There is no fleet-watch phase, repeated Juice Shop scan, model check or generation
call. The existing helper supplies corrected isolated known-folder paths and its
suspended-process Windows Job launch/cleanup. Timeouts are 180 seconds for startup
captures, 120 for each simple control assertion, 1,500 for the existing watch
journey, and 600 for full captures. Internal watch limits remain unchanged.

Before and after every launch the runner revalidates exact package/source/lock
identity, seed, helper and runner hashes. It requires exit 0, no timeout, process
exit and verified owned-tree cleanup. Native JSON success fields are checked
explicitly against current source, not inferred from logs or exit status.

Capture checks validate metadata/path ownership, SHA-256, PNG IHDR dimensions,
positive finite scale/logical dimensions, pixel rounding, actual theme, complete
size/theme pairs, and strictly increasing actual logical width **and** height
for every view. Collapsed dimensions write `capture-validation.json` with measured
values and errors, then fail the phase; they never become a PASS. Full captures
also require Architecture/Inventory row diagnostics. Images still need human
review: no pixel/layout quality or Narrator acceptance is inferred.

Evidence is exclusive-create: preflight, per-launch process/stdout/stderr,
before/after identity, native raw proofs, capture validation, per-case verification
with file hashes, and final summary or preserved failure. Existing outputs are
never overwritten and no cleanup deletion is performed. Profiles/reports remain
in their owned evidence directories after the verified process cleanup.

Syntax validation performed with Python `compile(source, path, 'exec')`: PASS.
That check neither imports this runner nor calls its CLI. Source review used
CodeGraph for `MainWindow.Capture.cs`, `MainWindow.xaml.cs` SmokeLoaded,
`MainWindow.ReadinessSmoke.cs`, `MainWindow.SingleWatchSmoke.cs`, and the existing
`tools/run_wp017_native_modes.py` identity/profile/launch helpers. No new test
matrix or production implementation was introduced.

The full remaining human/OS/accessibility and fleet gaps are documented in
`../astra-frozen-20261022/resume-gui-plan.md`. All K2/K4/manual/accessibility/release
acceptance fields remain false even after this automated runner passes.
