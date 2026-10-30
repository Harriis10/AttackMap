# WP016 scoped AI metadata projection — 2026-10-23

Base HEAD: `507bddacd72a246a136ca2d46faad2aa661806c1`. Direct write lease: `desktop/windows/AttackMap.NativeSpike/AI/**` and AI-specific console tests. Root retains shared shell/build/GUI/provider/tracker ownership. Source files are frozen after the final console build below.

## Current behavior and smallest correction

Before this patch, `AiArtifactProjection.Project` read only artifact `usage_status` and `reference_validation`. Retained Hunt+verify generation `3ceaf435b6f64d06a6717fe76d84409d` supplies neither field. It supplies numeric aggregate usage (`506556` input / `5955` output), shared `allowance.usage_status=reported`, and `citation_context.reference_validity=mechanically_checked`. Therefore the old compact display showed usage/reference validity unknown, without distinguishing these supplied scopes.

Current producer contracts were inspected before editing:

- `ai_budget.py` settles shared output reservations; `usage_status=reported` does not establish input accounting or individual-call provenance.
- `CitationContext.metadata()` describes the captured reference context. It does not validate every reference in a generated output, or establish claim support.
- The jury branch in `pipeline.py` emits aggregate `jury.usage`, shared allowance and captured context; it does not emit the narrative `reference_validation` contract. Narrative validation may itself be scoped to selected producer evidence IDs, with source references unresolved.

The focused patch changes presentation only. Artifact usage keeps its supplied/unknown state, with the scope labeled. Shared output accounting and its unknown-call count are displayed separately, identifying the artifact/run allowance snapshot. Only an explicit `token_allowance_kind=output_tokens` receives the output scope. Matching run allowance takes precedence when present; an absent run allowance no longer erases a supplied artifact allowance. Reference-validation scope is visible; captured citation context is a separate, explicitly context-only line. No status is inferred from token counts or a checked context. Complete supplied metadata and model text are preserved.

The actual retained generation remains **partial**, `failed_passes=0`, `abstained_votes=1`; claim support remains not assessed and output-level reference validity remains unknown. Its existing four HTTP completions are historical evidence. These tests perform no HTTP request.

## Files and identity

| Changed source | Final SHA-256 |
| --- | --- |
| `desktop/windows/AttackMap.NativeSpike/AI/AiArtifactProjection.cs` | `6cc03542e01728c543fefe1fa7213056c8ad94608697d66e96bfa4bcff9ebaa4` |
| `desktop/windows/AiArtifacts.Tests/Program.cs` | `2502a71003c748219a06602536921b0ef058863e1dd8667de376745a61a595a1` |

No project, Python producer, shared shell or saved model artifact was changed. `inputs-before.json` / `inputs-after.json` prove the test project, inspected Python contracts and all three retained generation inputs stayed byte-identical. The source diff is in `source.diff`.

## Verification

The first attempt used system PATH `dotnet`, which has no SDK; it exited `-2147450725` before compilation. `environment-attempt-build.log` and `environment-attempt-build-result.json` preserve this environment failure. Using the repository SDK resolved it. The first successful console restore used a new local empty NuGet feed, then the final build reused only its own fresh artifacts root. No full WinUI build was started.

Environment: `DOTNET_ROOT=<repo>/.tools/dotnet`, `DOTNET_CLI_HOME=<repo>/.tools/dotnet-home`, `NUGET_PACKAGES=<repo>/.tools/nuget-packages`.

Final commands from the repository root:

```powershell
.tools/dotnet/dotnet.exe build desktop/windows/AiArtifacts.Tests/AiArtifacts.Tests.csproj --artifacts-path .tmp/wp016-ai-metadata-sol-ultra-20261023-02 --no-restore -p:NuGetAudit=false -p:UseSharedCompilation=false -nodeReuse:false
.tools/dotnet/dotnet.exe .tmp/wp016-ai-metadata-sol-ultra-20261023-02/bin/AiArtifacts.Tests/debug/AiArtifacts.Tests.dll --saved-hunt-verify docs/verification/windows-parity/WP017/sol-budget7200-20261023-hunt-verify-01/hunt_verify/reports/3ceaf435b6f64d06a6717fe76d84409d docs/verification/windows-parity/RESUME-2026-10-23-sol-ultra/ai-metadata/saved-generation-projection.json
git diff --check -- desktop/windows/AttackMap.NativeSpike/AI/AiArtifactProjection.cs desktop/windows/AiArtifacts.Tests/Program.cs
```

- Final console build: **exit 0, 0 warnings, 0 errors** (`build.log`, `build-result.json`).
- Final tests: **86 offline assertions PASS, exit 0** (`tests.log`, `tests-result.json`): 80 synthetic/workspace assertions and 6 read-only assertions over the retained actual generation. This is not 86 independent test methods.
- Tests cover independent artifact/shared-output usage, aggregate counts without fabricated status, missing scope, malformed unknown-call counts, selected-run allowance precedence, mismatched mode, fallback to supplied artifact allowance, checked-context versus invalid/unknown output references, producer-ID scope, claim support separation, abstention/partial preservation, delayed reads, shutdown and generation/hash binding.
- `saved-generation-projection.json` records the exact new projected summary/notice plus the three unchanged source artifact hashes. It does not copy the model narrative or infer semantic acceptance.
- `git diff --check`: exit 0; only existing Git LF-to-CRLF conversion notices.

## Limits and next gate

No provider/model process, GUI, server, full build, package, stage, commit or cleanup operation was run. This closes the scoped deterministic projection correction only. Root must review the integrated source, build the full product and visually inspect actual wrapping/height with the saved generation. Manual/accessibility, semantic report quality, all-five-mode/same-binary, clean-host/signing and release acceptance remain open. No roadmap status was changed by this agent.
