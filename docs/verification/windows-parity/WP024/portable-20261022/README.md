# Portable Windows correction — 22 October 2026

User reported copying the latest native binary to a second PC and being asked
for Python/AttackMap engine. Confirmed packaging defect: integrated L contains
the native UI/runtime but no `engine` directory. An EXE link was an incorrect
portable handoff. No user settings were deleted or rewritten by this repair.

Deliverable: `desktop/windows/artifacts/AttackMap-Windows-Portable-20261022.zip`
(117,614,209 bytes), SHA256
`27dd87f245c23f5f2617d26508822ad9febf73bcf4811ad5a0d7fdf3c6d348d5`.
Extract the entire ZIP; run `AttackMap-Windows/Spustit-AttackMap.bat` or its native
EXE. All runtime/resource/engine subdirectories must accompany the EXE.

The new scoped builder copies511 native files (PDB omitted) and all308 immutable
frozen engine files, including its embedded Python runtime, SDKs and analyzers.
Copied bytes and engine proof inventory were verified, then sources rechecked.
Manifest/provenance describe the previously tested L/B-J development pair;
RequiredBundled's final current-source release gate was not relaxed or bypassed.
Original native/engine directories are unchanged. Eight synthetic builder safety
checks passed; an initial sandbox temp-ACL setup failure is not counted as pass.

Actual extracted verification (`attempt03/verification.json`): all824 manifest
payload files checked. Native GUI initialized from two different relocated paths
containing spaces, with private missing settings paths. It selected each adjacent
`engine/attackmap.exe` automatically. `PATH` contained only Windows/System32 and
Windows, with Python/virtualenv variables removed. Frozen version1.5.1 and both
capability queries exited0;21 analyzers discovered and runtime kind Frozen.

The raw legacy `--startup-smoke` aggregate remains FALSE and is retained. Its
old assertion requires `ReadScanOptions().Provider == null`; current UI retains a
nonnull disabled ProviderConfiguration. Source inspection confirmed this mismatch.
The observed engine-selection/no-auto-scan/AI-off/CVE-off facts passed the scoped
portability checks; no whole-startup aggregate acceptance was invented. This
obsolete test assertion is a separate future test-maintenance item.

Actual stronger follow-up: extracted native GUI → bundled frozen broker → real
`C:/tmp/juice-shop` scan → completed verified report. `native-scan/process.json`
records exit0/70.106s; parity-smoke result passed, capabilitiesChecked and
scanCompleted true, terminal completed, failure null. Generation
`5e1602ef6ff941038c36d31a0e87b4d7`, report SHA256
`bbbcd5cb3551882df76ece27c0a6e5964acce6f3bcbe842ffcd05fd5bc3b00f2`.
No Python was on child PATH; no AI/CVE request was enabled. This scan used an
explicit path to the exact bundled engine, independently of the preceding actual
automatic fresh-start selection checks. Generated reports stay outside target.

The root launcher now selects this complete portable folder and checks its native
EXE/DLL plus bundled engine hash and required embedded runtime files. Explicit
engineering directory mode is unchanged. On a profile with an existing explicit
engine executable, that user choice still wins; choose the local bundled engine
in Scan options when intentionally replacing it. Fresh profiles need no setup.

No clean VM/second physical PC, signing, manual accessibility or general roadmap
acceptance is claimed. This is a self-contained Windows x64 development preview.
The source .NET/runtime and embedded Python supply the application dependencies;
the current-host tests do not prove every possible clean Windows configuration.
