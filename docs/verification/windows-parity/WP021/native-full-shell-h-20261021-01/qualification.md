# Full native H fleet-watch journey

The full H application completed two real native-to-source-engine fleet runs
after edits in the second and third of three explicitly selected repositories.
Each recomputed the selected three-child fleet. The native smoke also confirmed
default-off/idle opt-in, ignored owned-output writes, removed-root silence and
Stop silence. `parity-smoke.json` records the requests/epochs/run IDs;
`process.json` records PID 19116, exit 0, no timeout. No AI was requested.

The fixture deliberately placed actual output inside repository 2. Watcher
exclusion worked, but independent code review found that core capture does not
generally exclude arbitrary nested output folders. This result proves the
watcher journey only, not clean scanner input isolation or exhaustive coverage.
The next fixture places actual reports outside all selected roots and uses a
separate named canary to exercise watcher ignore behavior. The general nested
output policy remains a WP033 gap.

`Fleet-watch.png` is a solid/empty RenderTargetBitmap capture and is unusable
for appearance review. No visual acceptance is inferred from it or the passing
internal assertions. A later full-shell capture must provide usable frames.

Review also identified a cancellation race: a global generation change could
skip terminal settlement of the owned fleet workspace. A subsequent native
checkpoint includes the fix and a real cancellation journey; H is not evidence
for that fix. No C25/manual/accessibility or complete WP021 acceptance is claimed.
