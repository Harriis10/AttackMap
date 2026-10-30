# Resumed independent package / WP017 readiness review — 2026-10-22

Reviewer: Astra/high runner-review lane. Scope: read-only review and local identity/hash checks; no build, installation, native application, engine executable, provider request or regression suite was launched. The Python interpreter was used only to read JSON/files and call the existing `package_identity`, `release_inputs` and `preflight` functions with bytecode writes disabled. All three check commands exited 0 (8.39 s, 1.46 s, 1.06 s).

**Verdict: no blocking defect found in the reviewed packaging wrapper or current source/package identity gate. The package is ready to proceed to the separately owned installation verification and five actual native AI modes, subject to the installer helper's independent review. These checks do not accept WP017, WP024, human GUI, clean-host readiness or release readiness.**

## Reviewed inputs

- Wrapper: `docs/verification/windows-parity/RESUME-2026-10-22/astra-high/package_fresh_native.py`, SHA256 `263a1e03901ba2ae25b1c52fa99265bc864d1489fea50a4f0f747ad9787a7f30`.
- Package: `desktop/windows/artifacts/astra-packages-20261022/dev-20261022113134-4de136c6`.
- Manifest SHA256: `d62a6c7f432cfab616cafda64978eb4cfc7a5b0e2167151737c9df848f4af087`.
- Release lock: `.tmp/wp024-astra-fresh-20261022-01/release-lock.json`, SHA256 `6873ddb1cb00af1dc1a91b6337559e7166b4bc7aea6f914d526616d450f33ade`.
- Native proof: `docs/verification/windows-parity/WP024/astra-fresh-20261022/native-build/native-build.json`.
- Engine proof: `docs/verification/windows-parity/WP024/astra-fresh-20261022/runtime/engine-verification.json`; the package's `engine.verification_sha256` matches its current bytes.
- Packaging proof and SBOM: `docs/verification/windows-parity/WP024/astra-fresh-20261022/packaging/summary.json` and its recorded artifact paths.

## Current checks

1. `package_identity(stage/app/AttackMap.NativeSpike.exe, reviewed_manifest_sha256, release_lock)` passed: exactly 821 payload/deployment files, hashes and sizes, expected directories, no links/reparse points or hard-linked payloads. Production manifest discovery uses the package root above `app`; no portable provenance was synthesized.
2. Recomputed current source, complete release input and analyzer requirement digests equal the release lock, package and engine runtime proof. Current release input map also equals the native build proof's complete `inputs` map. Native proof has `inputs_unchanged: true`. Release input digest: `ce7398c65cf4fb2c402c1f0891151ae2e370226546a93fd0a0c5cebd4a619498`.
3. Both linked native extras still match their native build proof: `desktop/windows/fixtures/findings.json` and `desktop/windows/AttackMap.NativeSpike/obj/project.assets.json`.
4. Published and packaged native EXE/DLL bytes and sizes equal native build proof. EXE SHA256: `81ed7619e1ce5ebcbdc905f784a57d55234a2b03d416f46a77a0a57ef7e734fc`; DLL: `12f5e4231138af1c8922fac7787c4c04a41db94c9cc343ae1641bcfe62584289`.
5. All 308 engine inventory rows in the runtime proof exactly equal the packaged engine inventory, including file names, sizes and hashes. Packaged executable SHA256 equals runtime proof: `f4ce2e74446198e667cef7e134dbd74654d5e03ec9d9efcaa364235c2cf11107`.
6. Recomputed archive, manifest, lock and SBOM hashes equal packaging summary. Runtime canonical report, artifact manifest and compare-result hashes equal their recorded proof.
7. Recorded engine terminal is `terminal/completed/succeeded/ready`, with run ID, repository and generation equal the request and artifact path equal the recorded canonical report. Repository is `C:\tmp\juice-shop`. All five recorded engine commands have exit 0 and verified owned-tree cleanup. This is retained direct-engine deterministic runtime evidence, not a newly executed native-pair or AI test.
8. Recomputed `preflight(..., mode='all', manifest_sha256=reviewed_pin, release_lock=lock)` passed for `review`, `hunt`, `hunt_verify`, `remediate`, `triage`; reported zero product processes and zero provider requests. Its disposable target `WP017/astra-review-20261022/read-only-preflight-unused` was not created.

## Review reasoning and execution boundary

`package_fresh_native.py:25-32` checks current release inputs against the lock and native artifact proof before invoking the production RequiredBundled builder. Lines 36-44 pass the actual frozen engine directory, runtime verification, source root and release lock. Lines 48-56 revalidate staged identity/native hashes, archive checksum and unchanged source. Lines 60-65 build the SBOM and repeat complete package identity afterward. Absolute paths make the launcher's executable-directory working directory harmless. The actual two native extra inputs were independently checked above; this wrapper does not itself repeat their specific checks.

The runner's RequiredBundled branch (`tools/run_wp017_native_modes.py:114-214`) fails closed without a matching current source lock and preserves its exact inventory/pin checks. The five-mode runner rechecks package identity with the release-lock argument before and after each mode. Current runner SHA256 is `c6f6e5ebd4e54dfaa425048ab3990a55e4f4e9eaa337cb4a1f545e60d15a0686`; verifier SHA256 is `c6f459bacba6dd247701ca04c1bbdd7489709f0666366a9d96be0da312e13efc`. These match the previously completed focused result (39 passed, 23 subtests); no suite was repeated during this review.

The separate installer helper remains outside this review's execution approval. Native parity smoke currently requires explicit `--engine` for `--native-scan`; use the exact installed bundled engine and disclose that this does not prove automatic discovery. Ordinary startup must not be described as isolated merely because LOCALAPPDATA was overridden: the current normal startup reads Windows known-folder settings. Human visual/accessibility review, actual completed local model responses in all five modes, clean-host installation, signing and release acceptance remain separate gates. No FINISHED or acceptance state was changed by this review.
