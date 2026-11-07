# Independent installed-native verifier review — 2026-10-22

Reviewer: `/root/astra_python_checkpoint`, Astra/high. **No blocking finding**
for the stated scope: actual CMD installation into a new owned workspace root,
then a full native parity scan using the explicit installed bundled engine.
No helper/source edit, installer, GUI, provider, build or heavy test was performed
by this review. CodeGraph was used first; missing helper/source portions were
read directly. A compile-only Python syntax check passed without executing or
importing the helper.

Reviewed identity:

- `RESUME-2026-10-22/astra-high/verify_installed_native.py` SHA-256
  `56c4f0cdc175ecfa4b81dfe0f9c63ed45937a9a36e79f26b40fe0b2f8a93b32a`.
- Imported `tools/run_wp017_native_modes.py` SHA-256
  `c6f6e5ebd4e54dfaa425048ab3990a55e4f4e9eaa337cb4a1f545e60d15a0686`.

## Findings by requested boundary

| Boundary | Review conclusion |
| --- | --- |
| Syntax/control flow | Read-only preflight is the default; `--run` requires the reviewed manifest pin. Failure preserves artifacts and raises. No cleanup, upgrade or uninstall path is present. |
| Input and write isolation | Workspace-local canonical paths, no reparse/symlink traversal, fresh install/output roots and disjoint input/output roots are checked. Original stage remains an input; install and evidence are separate. |
| Package/source provenance | RequiredBundled production manifest, pinned fresh engine, release lock, native build inputs, EXE/DLL hashes and linked assets are checked. Package and native proof are checked again after execution. |
| CMD/WinPS quoting | `cmd /d /c call` avoids CMD's leading quoted-command special case. Stage/install reject `%!&^()` before CALL reparsing; shared path validation rejects the remaining Windows/control metacharacters. Argument-list serialization keeps space-containing paths together. Installer PATH contains only System32, Windows and WindowsPowerShell/v1.0 and rejects Python/pwsh; noninteractive exit propagation is explicit. This is static review, not a new launcher runtime result. |
| Native settings | `MainWindow.xaml.cs:51` selects private parity settings before initialization; line 67 skips saved theme, and the parity branch at line 80 skips normal settings/provider/recent restore and window-placement persistence. `MainWindow.ParitySmoke.cs:14` selects private recent-repository storage before `LoadReport`. Initial store object construction alone does not perform a read. The helper correctly avoids claiming environment variables create a private Windows known-folder profile. |
| Process ownership | Imported `launch` starts suspended, assigns the Windows Job before resume, and executes owned-tree cleanup in `finally`. Cleanup requires zero active job processes; assignment failure targets only the just-created PID tree. Timeout/process exit/cleanup records are retained. |
| Installed artifact verification | Exact payload/directory inventory, case aliases, reparse/hard-link refusal, byte hashes, owner marker, current pointer and installed manifest are checked. The complete installed result is compared again after the native run. |
| Scan artifact verification | Request run/repository/output identities, AI/CVE disabled, success/progress flags, displayed report hash/root, generation identity, each declared artifact checksum and atomic pointer are checked. Report and run manifest must occur in the inventory. |

No code fix is recommended before the scoped run. Keep the already explicit
limitations: `--engine` is passed because the parity journey requires it;
automatic startup engine discovery is not proved. Normal startup is unexecuted.
This review does not grant production runtime PASS, manual UI/a11y, clean-host,
signing or release acceptance. The actual install/native logs and artifact
checks must supply those runtime facts in their limited scope.

## Retrospective packaging-guard index completion

The previously completed synthetic guard run was **not repeated**. Its recorded
exit 0 / 18.44 s / empty owned Job result remains intact. Added
`packaging-guards/evidence-sha256.json` for 75 existing evidence/fixture files and
`hash-index-completion.json` with relevant script hashes. All 631 before/after
source inputs match, and there are zero differences from the broad Python
checkpoint's final source inventory. The earlier STOP handoff remains historical;
the hash index was completed only after explicit resume.

Synthetic packaging/PS5.1/.cmd/rollback/tamper guards remain distinct from this
helper's future actual installed-native scan and from a clean-host campaign.
