# Engine session process checks

This standalone .NET 8 console project links the production session, protocol and request models. It launches `ControlledFakeBroker`, a test executable that never creates children or accesses the network. Requests and identity markers use a fresh system temporary directory outside the checkout.

Run from the repository root:

```powershell
dotnet build desktop/windows/ControlledFakeBroker -c Release
dotnet build desktop/windows/EngineSession.Tests -c Release
dotnet desktop/windows/EngineSession.Tests/bin/Release/net8.0/EngineSession.Tests.dll "$PWD/desktop/windows/ControlledFakeBroker/bin/Release/net8.0/ControlledFakeBroker.exe" "$PWD/desktop/windows/verification/native-engine-session-qa-2026-10-15.json"
```

Set `DOTNET_ROOT` when using a private SDK/runtime installation. The suite covers both supported schemas, execution success with policy failure, duplicate/regressive messages, exactly one terminal callback, exclusive admission, invalid-schema EOF cleanup before readmission, and cancellation/disconnection around terminal delivery and exit.

The final case deliberately sends an invalid schema and ignores EOF. After the production cleanup deadline, it checks that further admission is blocked. Cleanup terminates only the childless fake after matching its PID, exact start time and executable path. No production safety state is reset. Temporary snapshots remain available for inspection. These process checks do not certify real Python integration, UI automation, accessibility or platform acceptance.
