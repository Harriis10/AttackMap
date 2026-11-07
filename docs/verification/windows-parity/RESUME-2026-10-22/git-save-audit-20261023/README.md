# Read-only local Git save audit — 2026-10-23

Root owns the eventual commit and full portable Windows build after the task's terminal condition. This audit performed no stage, commit, reset, clean, move/delete, ignore-file change, build, GUI, engine or model action. Existing working-tree changes remain intact. No potentially sensitive settings/credential values were read: only paths, types, sizes and Git metadata were examined.

## Current observed state

- Existing local Git repository at HEAD `258adf6` (`Resume Windows parity with reviewed indexes and native AI verification runner`). Do not initialize another repository.
- 20 tracked modifications; staged index empty. Current tracked diff: 1077 insertions/177 deletions across 20 files at audit time.
- 19 exact code/test/schema paths: 16 tracked modifications plus new `ParitySmokeTimeouts.cs`, `tests/test_local_provider_timeouts.py` and `tests/test_fleet_schema_contract.py`. These are enumerated in `code-path-allowlist.txt`.
- Four modified authoritative/status docs belong to the separate docs/evidence list: roadmap, TODO, JSON backlog and current RESUME README.
- 5220 visible untracked paths, with 128 permission/long-path warning lines. Enumeration is incomplete; counts/sizes are lower bounds. `enumeration-warnings.txt` preserves the limitation. No ACL changes or cleanup were attempted.
- 2629 visible generated entries total 1,094,501,652 bytes. This includes package-stage ZIPs of about 119 MB each, copied native runtimes, build/bin trees and other disposable test outputs. 293 visible capture-image files total 21,390,382 bytes. These are not automatically source-commit candidates.
- 27 potentially sensitive-name candidates are all settings.json paths in retained evidence. Their values were not inspected. The names/metadata are in `inventory.json`; exclude them by default. Their presence is not a claim that they contain secrets.

## Exact recommended commit scope

Use explicit lists, preserving complete current files rather than attempting to split out earlier owners' hunks:

1. **Source/checkpoint commit:** `code-path-allowlist.txt` contains all19 coherent code/test/schema files. It covers the original900→3600 SDK forwarding repair, conditional7200 total local allowance, native preview hook, schema equality test and source-bound runner/verifier. Existing RequiredBundled/package-layout/profile-isolation changes in the runner/tests predate some later edits; retain them and do not claim sole authorship or revert them to create a cleaner-looking diff. The exact first-dirty-turn baseline is not reconstructable solely from HEAD, so this audit does not assert that every current hunk originated in this task.
2. **Documentation/evidence commit or same checkpoint:** `docs-evidence-path-allowlist.txt` contains53 exact currently existing paths,429,629 bytes at audit time. It includes the four modified authoritative docs, selected review/design/patch/source-proof artifacts, actual evidence helper/test source files and the small focused runner-checkpoint result/log/XML/command/hashes. It excludes scratch copies, raw native payload trees, profiles/settings, captures and package archives. Review final status text after all live/build work before staging; update this allowlist explicitly for final terminal summaries and qualified portable manifest/hash references if desired.
3. This audit's own `README.md`, the two path allowlists and concise `summary.json` may be added as explicit extra evidence paths after root reviews them. Do not recursively add the audit directory: inventory/warning detail and generator source are local operational detail, not needed to save product code.

Suggested future staging forms (not executed here):

```powershell
git --literal-pathspecs add --pathspec-from-file=docs/verification/windows-parity/RESUME-2026-10-22/git-save-audit-20261023/code-path-allowlist.txt
git --literal-pathspecs add --pathspec-from-file=docs/verification/windows-parity/RESUME-2026-10-22/git-save-audit-20261023/docs-evidence-path-allowlist.txt
git diff --cached --stat
git diff --cached --name-status
git diff --cached --check
```

Inspect the staged patch before root's commit. Use a title about the delivered behavior/checkpoint, for example `Preserve shared local AI allowances and verified native budget preview`, and describe live/visual limitations honestly. If root wants separate source and evidence commits, stage only the first allowlist for the first commit. Do not use `git add .`, `git add -A`, recursive WP directory adds or `commit -am`; they either collect unrelated/generated material or omit the new tests/source.

## Exclude and preserve locally

Keep package-stage ZIPs/full runtime trees, `artifacts/`, all bin/obj/build/dist output, test/pytest/temp roots, QA profile trees/settings, generated NuGet migration markers and `.zcode/plans/...` outside the proposed commit. The latter plan and three zero-byte NuGet migration files are unrelated local/prior-work candidates, not code changes to sweep into this checkpoint. Do not delete any of them as part of saving code.

Raw model/request/source captures and provider logs may contain repository excerpts or local data; this audit did not content-review them. Keep them retained locally and add only individually reviewed summaries/provenance or selected captures needed for evidence. A final portable artifact belongs in the requested local artifact location with a pinned manifest/hash; it does not need to be embedded in the Git source snapshot.

## Existing ignore coverage

Root `.gitignore` covers Python/cache/venv output plus `.tools/` and `.tmp/`. `desktop/windows/.gitignore` covers bin/, obj/, artifacts/, __pycache__/ and its findings fixture. `git check-ignore -v` confirmed those sample paths.

That nested ignore file does **not** protect matching generated package/build trees under `docs/verification` or root `artifacts/`. Root `.gitignore` has no general `.env`/key/settings exclusion. No ignore files were changed because source/helper inputs are frozen; an explicit allowlist avoids changing the release input set merely for this save. If ignore hygiene is improved later, do it as a separately reviewed change, without retroactively deleting retained evidence or hiding intended fixtures.

Final sequencing: finish and record the current work; root reviews the exact staged sources/docs and commits locally; root then builds the final full portable Windows package from that committed source identity into a fresh artifact directory, verifies it, and records the artifact hash/status. Preserve existing packages and avoid modifying an earlier source-bound candidate in place. A local source commit alone does not establish portable runtime or release acceptance.
