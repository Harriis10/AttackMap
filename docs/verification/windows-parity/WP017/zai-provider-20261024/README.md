# Z.AI provider and Windows rendering investigation — 2026-10-24

User-requested scope: external OpenAI-compatible API credentials and the missing-text
appearance reported after a scan in the Windows Fleet build. WP017/WP023 remain
IN_PROGRESS; this is not release, macOS, accessibility or clean-host acceptance.

## Findings and changes

- The engine previously used OpenAI Responses for every compatible endpoint. The
  configured Z.AI Coding endpoint documents Chat Completions. Custom remote
  OpenAI-compatible endpoints now use `/chat/completions`; official OpenAI and
  the existing literal-loopback LM Studio path retain Responses. There is no
  automatic retry through another API or host. Compatible Chat requests use the
  provider's default reasoning settings; the Settings label makes this explicit.
- The saved model was `GLM-5.3-Flash`. The live model list instead contains the
  exact ID `glm-5.3-flash`. The provider check previously looked successful even
  when `selected_model_listed` was false. Both engine and native UI now surface
  that warning; the button explicitly says it checks the model list, not generation.
- The user's retained run `6604e2e3a4de45caa11f29747da06f41` contains a completed
  deterministic report, but no completed LLM review or reported LLM usage. A
  completed static scan is therefore not evidence that external AI worked.
- Added an opt-in `--provider-render-smoke <report> <fresh-output> <engine>` native
  QA journey. It isolates settings/actions, imports the saved report, runs an
  actual local Juice Shop scan with AI disabled, verifies terminal controls and
  captures Reports, expanded Scan options and Settings in two themes/two sizes.

## Exact settings

| Field | Value |
| --- | --- |
| Provider / backend | `openai` / `api` |
| Endpoint | `https://api.z.ai/api/coding/paas/v4` |
| Model | `glm-5.3-flash` (exact live model ID, case-sensitive) |
| Credential | Enter API key in Settings; Save uses existing protected storage |

On the user's subsequent explicit request to extend the timeout, both saved
configuration files were backed up and updated to **1200 seconds for AI** and
**1800 seconds for the whole native scan**, and the exact model spelling was
corrected to `glm-5.3-flash`. All other settings, the saved key and the previous
Fleet installation were preserved. Evidence:
`artifacts/provider-render-20261024/settings-timeout-change/proof.json`.
Model-list success does not establish generation or subscription entitlement.
Z.AI's published Coding Plan tool restrictions still apply; this investigation
does not establish AttackMap as an officially supported Coding Plan tool.

Sources checked: [Z.AI tool compatibility](https://docs.z.ai/devpack/tool/others),
[OpenAI-compatible Python SDK usage](https://docs.z.ai/guides/develop/openai/python).

## Verification and its limits

- **79 focused Python tests passed**: `tests/test_openai_compatible.py`,
  `tests/test_llm_review.py`, `tests/test_llm_loopback_privacy.py`,
  `tests/test_ai_budget.py`. Actual SDK MockTransport covers wire URL/body/Bearer,
  usage, empty/failed output and no retry, and preserves existing Responses routes.
  An initial restricted-shell run had temporary-directory cleanup failures;
  rerunning with an owned TEMP directory passed all 79 tests.
- **Real Z.AI connectivity response completed** using the saved key and exact
  lowercase model: `ZAI_CONNECTION_OK`, 29 input / 68 output tokens, stop reason
  `stop`. No repository evidence was included. Evidence:
  `artifacts/provider-render-20261024/zai-live.json`.
- **Fresh frozen engine made one real Z.AI generation** from a newly authored,
  fully known five-line synthetic `/health` fixture. CLI exit 0, AI markdown
  produced, 1993 input / 4096 output tokens. Stop reason `length`: this proves
  transport and report integration, **not a complete review**. Evidence:
  `artifacts/provider-render-20261024/zai-frozen-synthetic/`.
- **Authorized real Juice Shop AI retry completed** in 211.06 seconds total
  with the 600-second AI allowance: model `glm-5.3-flash`, stop reason `stop`,
  75005 input / 9863 output tokens and 22297 bytes of AI Markdown. No output-cap
  truncation. Evidence: `artifacts/provider-render-20261024/zai-frozen-juice-shop-600/`.
  This is transport/generation success, not accepted findings: reference checking
  flagged two invalid references (`insight:asymmetric:` and `asset:secret:`), and
  claim support remains unassessed. The viewer must retain those warnings.
- **Actual native Juice Shop scan completed with AI disabled**, terminal controls
  restored and report populated. The `final-scan/proof.json` preliminary run has
  all five checks true and 16 nonempty native captures. Eight were visually read.
  The delivery run repeats this against the final packaged native/engine pair;
  it passed all five checks and produced 16 nonempty captures. Four delivery
  captures were visually read, including expanded Scan options, Settings and
  Reports; the exact results are recorded in `verification.json`.
- **The actual generated cloud review was displayed in native Reports.** The
  compact light-theme image `cloud-review-capture/1024x700-Light-Reports.png`
  visibly contains the model text, exact usage and invalid-reference warnings.
  The other three captures were blank and are rejected as visual evidence.
  Therefore the AI-expanded view has only one valid visual observation, not a
  four-scenario visual pass. No further provider calls were made to open it.
- The prior Fleet and new native report captures retained visible navigation
  and text. Missing labels from the user's desktop screenshot were **not reliably
  reproduced or proven fixed**. Live Windows Graphics Capture repeatedly timed
  out. Images inspected here are real in-process WinUI RenderTargetBitmap output,
  which excludes window chrome and may differ from desktop composition. This is
  scoped visual evidence, not full live-desktop rendering acceptance.
- A first elevated QA run returned black/transparent captures despite structural
  checks. That run is retained under `after-scan/` and is **not a visual pass**.
  A sandbox scan failure is retained under `after-scan02/`. Final QA isolates
  action output paths and rejects captures with no visible content.

The first proposed whole Juice Shop cloud scan was rejected by automatic approval
review before execution because the concrete repository-derived payload was not
explicitly authorized for transmission. The user subsequently **explicitly
approved** selected source excerpts and analysis context from `C:\tmp\juice-shop`
to the configured Z.AI endpoint. An authorized frozen CLI run with a 240-second AI
budget exited 0 after 248.1 seconds but recorded **Request timed out / LLM review
skipped**; static success is not AI success. Its evidence is retained under
`zai-frozen-juice-shop/`. A separate bounded retry uses 600 seconds (already in
flight when the user requested a future 1200-second limit). The exact AI outcome
and subsequent native saved-report rendering are recorded in `verification.json`.

## Build and evidence

Fresh self-contained .NET publish and freshly frozen engine are packaged in
`artifacts/AttackMap-Windows-zai-20261024-final/`; start `Spustit-AttackMap.bat`.
The delivered archive is `artifacts/AttackMap-Windows-zai-20261024-final-verified.zip`.
`portable-manifest.json` identifies the bundled runtime; `provenance/` contains
independent engine/native source and binary hashes. This is an unsigned
development preview. The engine snapshot matches current Python source; native
QA/Settings changes were published separately after that snapshot, so no combined
release-lock claim is made.

Normal desktop startup exposed an incorrect marker format in the first private
staging package. The marker was corrected to the existing schema 1/runtime
contract, and the full file inventory moved to `provenance/payload-inventory.json`.
No executable bytes changed. The final `-verified.zip` has a checked inventory
and ZIP CRC; the earlier ZIP is not the deliverable. Actual normal startup via
Computer Use then restored `C:\tmp\juice-shop` without an error or scan;
`normal-startup-uia.txt` records that observed state. Windows Graphics Capture
still failed with `window capture timed out: timed out waiting on channel`,
including one retry after refreshing the target window.

Build commands and source:

```text
.tools/dotnet/dotnet.exe publish desktop/windows/AttackMap.NativeSpike/AttackMap.NativeSpike.csproj --artifacts-path artifacts/provider-render-20261024/native-build04 -c Release -r win-x64 --self-contained true -o artifacts/provider-render-20261024/native-delivery -m:1 -p:BuildInParallel=false -p:RestoreFallbackFolders=C:\Projects\INPROGRESS\AttackMap\.tools\nuget-packages -p:NuGetAudit=false -p:UseSharedCompilation=false -nodeReuse:false --ignore-failed-sources
.venv/Scripts/python.exe artifacts/provider-render-20261024/prepare_preview.py
```

Frozen build commands, hashes and exit proof are retained in
`artifacts/provider-render-20261024/engine-freeze/`.
