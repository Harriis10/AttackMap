# Action runner process checks

This dependency-free console suite compiles the production `DesktopActionRunner.cs` as a linked source file and launches the separate `ControlledFakeBroker` apphost. The fake broker launches no children and uses no network. All request/result fixtures are placed under a fresh system temporary directory outside the checkout. Credentials are randomly generated test sentinels and are never recorded in evidence.

From the repository root, using an installed .NET 8 SDK:

```powershell
dotnet build desktop/windows/ControlledFakeBroker -c Release
dotnet build desktop/windows/DesktopActionRunner.Tests -c Release
dotnet desktop/windows/DesktopActionRunner.Tests/bin/Release/net8.0/DesktopActionRunner.Tests.dll "$PWD/desktop/windows/ControlledFakeBroker/bin/Release/net8.0/ControlledFakeBroker.exe" "$PWD/desktop/windows/verification/native-action-runner-qa-2026-10-15.json"
```

For a private SDK installation, set `DOTNET_ROOT` to that installation so the child apphost resolves the same runtime.

The final test intentionally leaves production static admission blocked. It verifies the cleanup deadline and refusal to launch another action, then checks the fake's recorded PID, exact start time and executable path before terminating only that childless process. There is no reset of the production safety state. Run this console suite in its own process. Temporary snapshots are retained for inspection.

These checks establish runner process behavior with controlled protocol responses. They do not certify the real Python broker, secure credential storage, UI keyboard operation, accessibility, or Windows platform acceptance.
