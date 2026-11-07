# Commit → full portable: content versus commit identity

2026-10-23, read-only plan. No source/helper changes, imports, tests, freeze, publish, packaging, installation, GUI/model/engine execution, staging or commit performed. CodeGraph was queried before source exploration. Root retains the ongoing HV7200 and final work/GUI/build slots.

## Verified identity rules

**Release inputs and lock do not include Git HEAD.** `tools/generate_release_lock.py:25-26,51-110` inventories on-disk bytes, including untracked source files, rather than `git ls-files` or commit IDs:

- Engine source digest: `src/**` and `installer/**` excluding `__pycache__` / `*.egg-info`, plus `pyproject.toml` and root `README.md`.
- Release digest additionally includes `desktop/windows/AttackMap.NativeSpike/**` excluding bin/obj/cache, and exactly `tools/package_native_windows.ps1`, `tools/generate_release_lock.py`, `tools/generate_release_sbom.py`.
- Analyzer requirement digest comes from pyproject dependency pins. The lock adds probed Python/PyInstaller/.NET identity; `generate_lock:154-191` has no Git/timestamp field and documents deterministic bytes for identical inputs/toolchain.
- Tests, published schemas, most helper tools, docs/verification and Git index/HEAD are outside these source digest scopes. Their own review/test/runner pins remain relevant separately. Committing a previously untracked native .cs file does not add a new release input if the same file bytes were already present during the recursive snapshot.

`tools/package_native_windows.ps1:19-60,114-125` verifies current content digests, exact lock SHA and successful engine/runtime/payload proof. Its manifest records these hashes and payload hashes, not HEAD. It creates a fresh timestamp/random package ID (`:63`) and archive/hash (`:265-268`), so a new packaging operation yields a new package/manifest/SBOM/archive identity even when payload bytes are reused.

**Native publish can include Git HEAD indirectly in DLL bytes.** The actual generated Release `AttackMap.NativeSpike.AssemblyInfo.cs:16` currently contains `AssemblyInformationalVersion("1.0.0+258adf66a9ec3c5a691868ae67c3a73b08b92c4a")`, and its SourceLink JSON maps repository files to the same commit. The project does not override this source-revision behavior. A publish at a new commit can therefore change DLL metadata/hash without changing any release-input source file. The generated files are evidence of the build pipeline; the final packaged binary metadata still must be checked after the later actual publish. Do not assume source equality implies a byte-identical republish.

Python packaging uses the version in `src/attackmap/__init__.py` through setuptools, and the reviewed PyInstaller spec/fresh-freeze source path has no Git HEAD input. Engine capability identity is executable/payload/source content, not a Git version string (`desktop_capabilities.py:42-65`). No independent commit-derived engine input was found.

## Two valid paths

| Step | Same bytes, retained build identity | New native build at final HEAD |
| --- | --- | --- |
| Commit | Final reviewed code/docs commit C, then verify on-disk bytes did not change | Same |
| Post-commit binding | New evidence: C plus exact release/engine/analyzer inputs, original immutable lock/proof hashes and payload inventory equality | Same; also pin new publish command/toolchain/resolved native inputs |
| Python freeze | Reuse qualified immutable freeze if all engine/release/lock/payload/analyzer/toolchain preconditions match | Reuse the same qualified freeze under the same explicit conditions; no HEAD-only engine rebuild is required |
| Frozen direct runtime | Retain original version/modules/deterministic scan/compare proof for the exact same freeze; never rewrite its paths/date/claims | Same; rerun only if stale/missing/changed or a new runtime claim specifically requires it |
| Native publish | Reuse exact qualified native files, honestly retaining their old informational/source-link build revision; do not call them built at C | Actually publish once into a fresh directory after C; inspect resulting commit metadata and pin all new file hashes |
| Package/SBOM/ZIP | Actually assemble a fresh RequiredBundled full package and fresh SBOM/archive/hash after C | Same, from the new native publish plus retained qualified engine |
| Install/native runtime | Fresh root, actual installer plus installed full-native deterministic scan/atomic generation/cleanup, bound to this new package | Same; new native hashes and package ID make old installed/native proofs inapplicable to this artifact |
| Truthful claim | Built earlier; bytes match sources saved at C; full portable assembled after C | Native published at C; bundled frozen engine built earlier from byte-identical committed inputs and retained immutable proofs |

The same-bytes path is technically valid content provenance and is the absolute least work. It must disclose the earlier native build revision rather than changing old proofs or manifest claims. If root wants the final native UI to identify the saved source commit, use the second path.

**Recommended smallest correct path: final commit → verify identical content inputs → reuse the immutable qualified Python freeze and original lock/runtime proof → actual native publish at C → new package/SBOM/ZIP/hash → fresh installed-native deterministic qualification.** This addresses the observed native commit metadata without repeating an unchanged Python freeze or long model run solely because HEAD moved. It still actually constructs the requested full portable, rather than renaming/copying an old ZIP and calling it newly built.

If the requested claim is stronger—“every component was built after C”—then repeat the fresh Python snapshot/freeze and its direct runtime qualification as well. That is an additional temporal build requirement, not a consequence of the current release-lock algorithm. Do not silently assert it for a reused engine.

## Concrete later sequence owned by root

1. Finish HV7200 and other authorized work, preserve actual terminal results/owned cleanup and visual limitations. Keep package bytes immutable. Review the explicit19 source/test/schema and selected docs/evidence paths from the audit, then make the local commit C. No reset/clean or broad staging is needed.
2. Record C and fresh status; independently recompute the release input mappings/digests and compare them to the retained freeze lock and existing qualified inputs. Recheck original lock SHA, build proof SHA, complete engine payload inventory/hash, analyzer/toolchain pins and native linked `fixtures/findings.json` / resolved `obj/project.assets.json`. This is **new comparison evidence**, not a replacement/rebinding of earlier build/runtime records. A Git-only commit should not change content hashes, but stage filters or incidental changes must be measured rather than assumed.
3. If the comparison is equal, retain the engine/lock/proof read-only. Actually run the existing root-reviewed native publish helper into new paths with no restore unless the resolved dependency state changed. Its before/after release inputs and linked-input hashes must match. Capture final assembly/SourceLink revision and EXE/DLL/full publish inventory. Do not alter SDK properties to conceal the earlier revision or manually edit generated metadata.
4. Use the existing parameterized `WP024/sol-long-budget-20261023/package_candidate.py` with fresh output/package roots, retained freeze/runtime proof, and the new native publish/build-proof pair. The helper requires the expected `native-build/native-build.json` and `runtime/engine-verification.json` layout under its proof root. Supply an explicit root-owned new proof aggregation/layout with provenance to the immutable retained runtime record if needed; never edit a retained proof's content to make it appear newly executed. The same engine proof can be referenced by the lower-level packaging script directly if that avoids copying/rebinding an old result.
5. Actually verify the new manifest/full inventory/archive digest and generate a fresh SBOM. Run the reviewed parameterized installed-candidate helper with the new native build proof, exact helper/engine/manifest pins and a new install root. Record real CMD installation, exact installed payload, deterministic native scan/selected generation and verified owned cleanup. No model request is needed merely to establish this portable packaging/install checkpoint.
6. Deliver the new full portable ZIP and hash plus exact committed source ID and scoped result. Retained live AI evidence may remain cited for its actual exact engine/package/run; do not transfer it wholesale to a new native/package identity. If claiming all-five-mode/live GUI acceptance on the final package, that requires separately scoped final-package evidence. User's request to save code/build a portable does not automatically close WP017/WP023, manual/a11y, clean-host or signed-release gates.

## When reuse stops being valid

- Engine source, installer/spec, pyproject/analyzer pins or root README bytes differ: new engine snapshot/freeze and actual direct runtime qualification; then native publish/package/install as required. Current release lock binds root README even if its edit seems merely documentation.
- Native source or the three packaging-tool inputs differ: current combined release digest changes. Existing engine proof/lock binds the old combined digest, so the current strict package gates will reject it. Do not “fix” this by regenerating a lock or editing engine proof around an old binary. Either perform the fresh coordinated snapshot/freeze/runtime chain or introduce a separately reviewed provenance-contract change; the latter is not proposed here.
- Only tests/schema/docs/evidence/other helper files change outside release inventory: source release digests need not change, but affected test/helper identity checks and acceptance evidence must stay accurate. A changed native resolved asset/linked fixture requires the corresponding real publish/qualification checks.
- Freeze/publish payload, toolchain/analyzer identity or retained proof hashes drift: retain the old record and produce the required new build/verification in new directories. A matching Git HEAD does not rescue differing bytes.

No previous result has been rewritten by this plan. All actual rebuild/runtime decisions remain conditional on root's later measured post-commit equality and requested provenance claim.
