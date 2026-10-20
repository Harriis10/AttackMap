# Engine session process checks

This standalone .NET 8 console project links the production session, protocol and request models. It launches `ControlledFakeBroker`, a test executable that never creates children or accesses the network. Requests and identity markers use a fresh ignored `bin/Release/net8.0/qa-*` directory. The broker apphost and sidecars are privately copied there; the copied apphost is named `attackmap.exe` to exercise the production Frozen launch guard and argument format without weakening recognition.

Run from the repository root:

```powershell
dotnet build desktop/windows/ControlledFakeBroker -c Release
dotnet build desktop/windows/EngineSession.Tests -c Release
./desktop/windows/EngineSession.Tests/Run-Safe.ps1 -Dotnet "$PWD/.tools/dotnet/dotnet.exe" -Broker "$PWD/desktop/windows/ControlledFakeBroker/bin/Release/net8.0/ControlledFakeBroker.exe" -EvidenceDirectory "$PWD/docs/verification/windows-parity/WP006/recovery"
```

Use the repository SDK to build when the system dotnet has no SDK; set `DOTNET_ROOT`, `DOTNET_CLI_HOME` and `NUGET_PACKAGES` to the repository `.tools` paths. The safe runner sets the child runtime root, captures stdout/stderr, checks missing/invalid argument rejection, and bounds the suite to 180 seconds by default (explicit `-SuiteTimeoutSeconds` supports a slower host); negative cases have a 60-second bound. Windows error UI suppression is process-local and restored after launch; machine WER settings are untouched. Never invoke the apphost without arguments. The suite covers both supported schemas, execution success with policy failure, duplicate/regressive messages, structured callback identity/revision/terminal gates, exactly one artifact callback, exclusive admission, invalid-schema EOF cleanup before readmission, and cancellation/disconnection around terminal delivery and exit.

The final case deliberately sends an invalid schema and ignores EOF. After the production cleanup deadline, it checks that further admission is blocked. Cleanup terminates only the childless fake after matching its PID, exact start time and executable path. No production safety state is reset. Temporary snapshots remain available for inspection. These process checks do not certify real Python integration, UI automation, accessibility or platform acceptance.
