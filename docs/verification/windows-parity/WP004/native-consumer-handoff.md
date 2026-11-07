# Native schema integration handoff

`desktop/windows/AttackMap.NativeSpike/NativeScanOptions.cs`,
`NativeScanRequest.Serialize` (observed line 35), currently produces schema **1.1**.
It does not yet serialize the seven new 1.2 option fields. WP006 owns their native
controls/request integration; this Python contract work does not claim that UI.

The Python broker now explicitly places `request.schema_version` in every progress
and terminal envelope, including startup failures. Thus existing 1.0/1.1 requests
receive their own schema rather than the new default 1.2. The parameterized
`test_broker_echoes_request_schema_for_old_and_new_consumers` checks the real
broker envelope construction for 1.0, 1.1 and 1.2 with a controlled rejected-launch
seam and validates each message through the neutral parser. No engine process or
provider is started by that check.

Native consumer seam required for 1.2: `EngineProtocol.cs`, `Accept` schema whitelist
and upgrade/range text (observed line 43), must permit 1.0/1.1/1.2. Existing
`desktop/windows/EngineProtocol.Tests/Program.cs` 1.0/1.1 golden terminal loop stays
unchanged; a separate terminal fixture copy with schema changed to 1.2 must be
accepted with unchanged completed/policy-failed semantics. Unknown major/minor
versions must still fail without mutating prior state. There is no existing
`terminal-policy-failed-1.2.json` in the old frozen fixture corpus, so extending
that filename-driven loop alone would be incorrect.

During this wave, read-only inspection confirmed the root-owned native source
already contains the expanded whitelist and separate 1.2 acceptance block. This
agent made **no C# edits** and did not run C# tests; root records that acceptance
and owns the shared native seam. Python source/fixture tests do not establish
native compilation, visual review or new installed-package acceptance.
