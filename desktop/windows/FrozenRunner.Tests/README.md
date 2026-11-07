# Frozen engine C# runner integration

This .NET 8 console project links the production engine session, action runner, launch specification, protocol and request models. It verifies the frozen executable's worker and comparison action through those C# callers, independently of native UI.

```powershell
dotnet build desktop/windows/FrozenRunner.Tests -c Release
dotnet desktop/windows/FrozenRunner.Tests/bin/Release/net8.0/FrozenRunner.Tests.dll ABSOLUTE_FRESH_ATTACKMAP_EXE ABSOLUTE_EVIDENCE_JSON
```

An optional third argument runs targeted real-repository parity, for example `C:/tmp/juice-shop`. Both paths use the same frozen executable, automatic analyzer discovery, default local analysis and no AI/CVE opt-in. The second path invokes direct `analyze`. Finding IDs and supplied severity/confidence/score labels are compared; this does not assert byte-identical reports or full semantic equivalence. Reports are outside the analyzed repository in a unique workspace cache directory. The initial synthetic fixture and empty canonical comparison fixtures are in a fresh system temporary directory.

The evidence binds executable, test assembly and linked source hashes, report hash and manifest identity. No files are written inside the frozen package. This is process integration evidence, not installer, manual UI, accessibility or performance acceptance.
