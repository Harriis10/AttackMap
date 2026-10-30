# Independent WP024 installed acceptance review — 2026-10-22

Reviewer: `/root/astra_python_checkpoint`, Astra/high. **Recommend WP024 DONE
only in its defined reproducible unsigned-preflight scope.** No blocking mismatch
was found in the actual installed result or independently recomputed identities.
Canonical task status remains root-owned; this review did not edit it.

This was read-only evidence review plus local hash/JSON comparisons. No installer,
product runtime, provider, GUI, build, broad test or focused test was launched.

## Identity independently checked

| Item | Value |
| --- | --- |
| Package | `dev-20261022113134-4de136c6` |
| Package manifest SHA-256 | `d62a6c7f432cfab616cafda64978eb4cfc7a5b0e2167151737c9df848f4af087` |
| Engine SHA-256 | `f4ce2e74446198e667cef7e134dbd74654d5e03ec9d9efcaa364235c2cf11107` |
| Release inputs SHA-256 | `ce7398c65cf4fb2c402c1f0891151ae2e370226546a93fd0a0c5cebd4a619498` |
| Installed run | `052035254ea84072a7f679fb16872a04` |
| Installed report SHA-256 | `919619d6ffe6a8ccdf153f83d9b127ae06aa46c1b68351ee770565edbeb5b8c9` |
| Reviewed installed summary SHA-256 | `7085b8cc7052de5e867c8e3d7eeb57813c8852682411dc3803dc6a79d010bca1` |

The primary evidence is [installed-profilefix01/summary.json](../installed-profilefix01/summary.json),
its `preflight.json`, `installed-before.json`, installer/native process and start
records, and the referenced request/report/generation manifests. Independently:

- Verified 20 path/SHA records across the summary, preflight and packaging summary,
  including actual process records, original package archive/manifest, release lock,
  native build proof and SBOM.
- Recomputed all **822 installed files**, their lengths and hashes; rejected link
  aliases during the audit. The current inventory matches the recorded expected
  inventory exactly, and `installed-before.json` equals the final installation result.
- Recomputed all **821 original stage inventory entries** and exact file membership
  plus the manifest; original payload/deployment bytes still match.
- Recomputed all **19 declared generation artifact** lengths/hashes. Request run,
  repository `C:\tmp\juice-shop`, successful generation and atomic pointer agree.
  The installed native report hash equals the prior frozen CLI report/seed hash.
- Confirmed emitted AI and CVE options are disabled. This run provides a genuine
  installed native static scan, not evidence for model generation.
- Recomputed **217 current release input hashes** and two extra native linked-input
  hashes. They match the release lock/native build proof. Recorded toolchain:
  Python 3.13.15, PyInstaller 6.22.3, .NET SDK 8.0.426.

## Runtime/cleanup and profile correction

The installer start record invokes actual `cmd.exe /d /c call Install-AttackMap.cmd`
with the explicit new `.tmp/wp024-astra-installed-20261022-02` install root.
Its PATH contains System32, Windows and WindowsPowerShell/v1.0; no Python/pwsh
search path is supplied. Installer PID 25644: exit 0, 36.79 s. Native PID 33288:
exit 0, 61.89 s, explicit installed EXE/engine paths, PATH only System32/Windows.
Both process records report suspended-before-assignment startup, assigned owned
Job, exited process, no timeout and verified owned-tree cleanup. Their recorded
hashes match the summary. This is recorded cleanup evidence, not a new process poll.

The earlier `installed/failure.json` remains `passed: false` / `Native smoke failed`.
It was not overwritten or reclassified. The preserved .NET 8 known-folder probe
isolated the missing `profile/AppData/{Local,Roaming}` directories; the subsequent
WP017 profile-fix record contains red failures followed by **30 PASS + 25 subtests**
using actual Windows known-folder resolution. Current helper/test hashes match
that result. The harness correction is excluded from release inputs; the package
and product source identity remained unchanged. The actual new installed journey
supplies the runtime confirmation after that correction.

## WP024 DoD mapping

- Dependency WP001 is currently DONE.
- Fresh source/toolchain/analyzer-bound RequiredBundled package and SBOM are
  present and hash-verified; SBOM explicitly says unsigned, not authenticated origin.
- Existing synthetic guards remain a separate passing result: required-engine
  absence, stale source, frozen sentinel tamper/missing/extra, installation/repeat/
  upgrade/rollback/uninstall and PS5.1/.cmd exit propagation. Their 18.44 s exit-0,
  empty-owned-Job result and stable source manifests were reviewed earlier; they
  were not repeated here.
- Fresh native consumer evidence includes **46 EngineLaunchSpec assertions PASS**.
  This supersedes citing only the historical 24-check count; it remains a fixture
  guard result, distinct from the actual installed scan.
- The explicit remaining WP024 runtime gate is now supplied: an installed bundled
  full-native scan without Python in PATH, in a new isolated root. Original stage
  and installed payload identity remain intact.

Suggested canonical wording:

> WP024 DONE in reproducible unsigned-preflight scope. RequiredBundled package
> dev-20261022113134-4de136c6 is bound to the fresh source/toolchain/analyzer lock
> and SBOM. Synthetic negative/installer/PS5.1 guards and fresh launcher guard
> assertions pass; the actual CMD-installed full native bundled scan completed
> on the developer Windows host with 822 installed files unchanged, 19 artifact
> hashes verified and owned process cleanup confirmed. Explicit installed-engine
> selection was used. No signing, clean-host or release acceptance is claimed.

WP017 is not a dependency of WP024 and its five AI modes remain separately
root-owned. This verdict does not close WP017, WP023, K5 or a public release.
Normal startup/automatic engine discovery was not executed; explicit `--engine`
is a declared parity-harness requirement. Actual OS dialogs, appearance,
keyboard/Narrator/200% text, signing, a second clean Windows host and full
upgrade/rollback/uninstall campaign, macOS/CI and human beta remain their separate
gates. The synthetic lifecycle checks are not a production clean-host lifecycle.
