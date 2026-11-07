# Native process fault composition

This standalone console project links production `EngineSession`, `DesktopActionRunner`, `ReportAdapter` and `ExportSelection`. `NativeFaultBroker` is a separate childless executable with no network access. Requests and fake artifacts are created in a fresh system temporary directory.

```powershell
dotnet build desktop/windows/NativeFaultBroker -c Release
dotnet build desktop/windows/NativeFaultComposition.Tests -c Release
dotnet desktop/windows/NativeFaultComposition.Tests/bin/Release/net8.0/NativeFaultComposition.Tests.dll ABSOLUTE_FAULT_BROKER_EXE ABSOLUTE_EVIDENCE_JSON
```

Set `DOTNET_ROOT` for a private SDK installation. The suite records every case and exits 1 if any expected rejection is missing; it does not crash or conceal known gaps. The initial 2026-10-15 run records 12 passing cases and two gaps: a completed broker envelope followed by exit code 7 is accepted by each runner. The engine callback runs before process exit, so a later exit check alone would not undo publication by a host callback. The subsequent production fix requires exit code zero before completed status/callback/result delivery. The exitguard proof records the regression result separately from the original failing evidence.

Passing cases cover malformed and oversized envelopes with observed EOF cleanup; abnormal exit without a terminal; missing/malformed canonical report and manifest; missing/malformed action result; admission release and successful retry after each settled fault. The scan callback uses actual report parsing and selected-generation manifest binding before changing its host state.

Scope limits: prior-report retention here is console host state, not an automated MainWindow assertion. Native failure status, diagnostics/retry navigation, dialogs, source selection during failure, keyboard task completion, Narrator and platform acceptance remain unproven. Cleanup deadline/admission latches are covered by the separate EngineSession and DesktopActionRunner suites. This suite never terminates processes or creates descendants.
