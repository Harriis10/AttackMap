# Source-bound local-budget candidate — integration checkpoint

2026-10-23. Snapshot after freeze 02, package/install/static scan and the scoped Settings preview; live progress is bounded to the first completed response at **00:45:13 UTC**. All new runtime work was executed by root, not by this documentation update. **No full Hunt+verify, five-mode same-source, semantic, manual or release acceptance is asserted.**

## Candidate identity

| Component | Identity / SHA-256 |
| --- | --- |
| Freeze | `.tmp/wp024-sol-long-budget-20261023-02` |
| Frozen engine | `574497f7c4ae3c8859edb5506c0538c8cba99dc70436f29857dbec6240aa81f5` |
| Full native publish | `integrated-20261023-sol-long-budget` |
| Native DLL | `74471d63ff06f2f0c2b9e85105fc567c6f3d35dd23189a523ecadbc32df14d95` |
| Native EXE | `81ed7619e1ce5ebcbdc905f784a57d55234a2b03d416f46a77a0a57ef7e734fc` |
| RequiredBundled package | `dev-20261023001948-7fa3eaff` |
| ZIP | `73dda701d0fb51a4bbf46e1d7300ba618d8c8e32efd5e71abe4d06b588702256` |
| Package manifest | `3666fe473f69d362671cc67c235a4920ca63fcf1a64a0d8b1ae8ce14d22d61b6` |
| Release lock | `56f6fca19411cba34addbd5440ef3bd906e772fcdee3e6b16da1d36e47aa2075` |
| SBOM | `819c42bf850be17c343bf7a900fd4da1729e9d32580b3b4f85594ce268e5b084` |

The EXE is a launcher whose unchanged hash alone does not identify all native implementation changes; the DLL/package hashes above are part of the identity. Freeze 01 remains preserved as interim after the subsequent provider-budget preview change. Do not substitute its engine or a previous package into this checkpoint.

## Completed scoped gates

- [Freeze 02 process proof](freeze-command02/process.json): completed build, separate immutable output, owned-job cleanup. Actual runtime proof is the next record, not inferred from build exit.
- [Frozen runtime qualification](runtime/engine-verification.json): **21 modules**, expected broker capabilities, real Juice Shop deterministic scan and compare action; atomic/current artifact checks passed. Scan run `0f3638b4153b41f5bb4f766a7c3f9982`, report SHA `919619d6ffe6a8ccdf153f83d9b127ae06aa46c1b68351ee770565edbeb5b8c9`. AI/CVE disabled; no model response is established by this scan.
- [Full native publish proof](native-build/native-build.json): unchanged source/resolved inputs, recorded EXE/DLL bytes. This is the full MainWindow product publish, not a standalone component preview.
- [Package/SBOM summary](package-evidence/summary.json): **PASS** in unsigned RequiredBundled scope, unchanged inputs, pinned ZIP/manifest/lock and **56 known Python dependencies**. [SBOM](package-evidence/sbom/release-sbom.json) is distinct from runtime evidence.
- [Actual installed native scan](installed-native/summary.json): **PASS** on developer Windows; CMD install and the installed full native client used the explicit installed bundled engine. Run `aba2ef632191433498d3edd9b9f0e035`, **19 verified artifacts**. Original stage and installed payload/current pointer were unchanged. [Installer process](installed-native/installer/process.json) and [native process](installed-native/native/process.json) exited 0, no timeout, owned-job cleanup verified. AI/CVE disabled. Explicit engine selection does not prove automatic normal-startup discovery or clean-host installation.
- [Budget preview summary](../../WP023/astra-gui-20261022/sol-budget-preview-7200-01/summary.json), [capture validator](../../WP023/astra-gui-20261022/sol-budget-preview-7200-01/capture-validation.json), and [root visual review](../../WP023/astra-gui-20261022/sol-budget-preview-7200-01/visual-review.md): **scoped PASS**. Root actually viewed the full-product Settings label in Light, 1008x661 content viewport, scale 1. Complete 7200 disclosure and existing 600 value were readable and unclipped. PNG SHA `a26ac7962a51fa11cf4a99196b32fd556be59e0ffd348f52b02a2cdf5b5c6d39`. No provider request/settings save was invoked by that preview. This does not accept all themes/viewports, the whole Settings workflow, Narrator, keyboard or text scaling.

## Live Hunt+verify 7200 — progress only

Root started [the new pinned candidate journey](../../WP017/sol-budget7200-20261023-hunt-verify-01/preflight.json) with explicit provider/scan/process budgets **7200/7800/8100 seconds**, endpoint `http://127.0.0.1:1234/v1`, model `cyberstag-security-26b-a4b-v1`, target `C:\tmp\juice-shop`. The SDK request cap remains 3600 within one shared 7200 deadline.

The initial request's [transport audit](../../WP017/sol-budget7200-20261023-hunt-verify-01/hunt_verify/http-audit/wp017-wp017-hunt_verify-5fb70bc2b6c84882a4e7872a11cda029-13760-d271b050a30f482088720f9345020042/http-audit.jsonl) records dispatch **00:26:14.605607 UTC**, HTTP 200 **00:45:13.013059 UTC**, and `observation_complete/completed=true` **00:45:13.020223 UTC**: approximately **18 min58 s** after dispatch. Body SHA `9bb96eeedea495dc377745ef4f14fceb1fca8bbec3a005da7411f7f37b446d51`; output SHA `6d401f593dcb6dccaa5d4203936aec0140a899bcf5cf962cf0725498917b8fff`. This proves one completed initial Hunt response, not completed jury verification or semantic correctness.

The first jury request [audit](../../WP017/sol-budget7200-20261023-hunt-verify-01/hunt_verify/http-audit/wp017-wp017-hunt_verify-5fb70bc2b6c84882a4e7872a11cda029-13760-23004b0a9628492186b04caba4f85550/http-audit.jsonl) records dispatch **00:45:13.218780 UTC**. At this progress boundary the journey remains **RUNNING**, with final jury, generation metadata, displayed/exported artifact identity, native process exit and owned cleanup still pending. Later events must be evaluated from their actual records; this note does not predict them.

## Remaining acceptance

WP017/WP023 remain IN_PROGRESS; historical WP024 unsigned DONE is not a signed-release approval. Require final full-jury result and exact same-candidate coverage of remaining modes before a five-mode same-source claim. Older Review/Hunt/Remediate responses and Triage-02's HTTP 200/pre-close parity result do not substitute for that gate. Preserve Triage-02's nonzero `0xC000027B` scenario FAIL and its unresolved cause.

The [semantic audit](../../WP017/astra-review-20261022/sol-remediate-triage-20261023-01/README.md) and [earlier Hunt observations](../../WP017/astra-review-20261022/semantic-observations.md) remain open independently of transport success. Complete final-candidate Reports/UI journeys, other visual sizes/themes and the capture anomalies; normal startup, keyboard/Narrator/200-percent text, signing, clean second Windows host, actual macOS and human beta gates remain separate. No source/model/helper correction is performed by this integration note.
