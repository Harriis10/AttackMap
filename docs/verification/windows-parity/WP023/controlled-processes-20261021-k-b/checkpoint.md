# Controlled broker process checkpoint — 2026-10-21

31 distinct controlled cases passed: EngineSession.Tests 9 in the preserved
`../controlled-processes-20261021-k` run; DesktopActionRunner.Tests 8 and
NativeFaultComposition.Tests 14 in this corrected run. These are fake-broker
protocol/process tests, not real scanner, provider, GUI or manual acceptance.

The initial DesktopActionRunner invocation deliberately preserved in the first
directory failed because its broker was named `ControlledFakeBroker.exe`.
Production EngineLaunchSpec requires `attackmap.exe`; the failure occurred before
broker dispatch. No production guard was relaxed. The corrected invocation copied
each complete compiled broker payload into a new owned directory and additionally
copied its apphost to `attackmap.exe`, retaining the original embedded DLL name,
DLL, deps and runtimeconfig sidecars. See `staged-broker-payloads.json` and the
exact commands in `summary.json`. EngineSession was not repeated.

All corrected child processes exited zero without timeout; their outer owned
Windows jobs were empty before close. All 22 declared C#/project inputs stayed
unchanged. The runner sets inherited process-local error mode 0x8003; no machine
WER policy was changed. A test failure or process exception must be diagnosed
from retained stderr and proof JSON; a zero wrapper exit alone is not proof.

The compiled broker copies are disposable evidence payloads, excluded from Git.
The versioned runner source, hashes, commands, logs and result JSON preserve the
reproduction recipe. Production runner cleanup assertions remain separate from
the outer test-job cleanup check.
