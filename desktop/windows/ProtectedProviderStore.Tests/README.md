# Isolated Windows protected provider storage

This standalone .NET 8 harness links the production action runner and invokes the final frozen engine's `provider_save` action. A random synthetic credential travels only in the transient action environment. `LOCALAPPDATA` is temporarily set to a unique workspace cache directory and restored in `finally`; no personal credential store is accessed.

The production desktop API has no `provider_load` operation. The load step therefore uses the existing Python `load_llm_key("openai", allow_environment=False)` API in a separate process, returning only a boolean comparison against an environment-only expected value. It does not introduce an independent DPAPI implementation. Save/load perform no provider connection, model listing or generation.

```powershell
dotnet build desktop/windows/ProtectedProviderStore.Tests -c Release
dotnet desktop/windows/ProtectedProviderStore.Tests/bin/Release/net8.0/ProtectedProviderStore.Tests.dll ABSOLUTE_FINAL_ATTACKMAP_EXE ABSOLUTE_PRODUCTION_PYTHON ABSOLUTE_FRESH_PROOF_JSON
```

Fourteen checks passed on Windows: the saved blob has the DPAPI header and contains neither UTF-8 nor UTF-16 plaintext nonce; the production loader recovers exactly the synthetic value; AI remains off; configuration/request/result JSON contains no credential; and the owned credential blob is removed afterward. The safe isolated snapshots remain for inspection. No nonce is printed or written to evidence.

Earlier provider roundtrip evidence explicitly excluded DPAPI, so this is additional coverage. Native panel/dialog interaction, keyboard/Narrator, cross-user/device recovery, installer acceptance and cryptographic implementation audit remain outside the proof.
