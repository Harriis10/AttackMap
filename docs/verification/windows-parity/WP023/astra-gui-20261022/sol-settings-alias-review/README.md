# Exact localized Settings alias — 2026-10-23

Implemented a focused evidence-validator repair in `run-gui-checkpoint.py`: normalize the exact native capture label `Nastavení` to canonical `Settings`, while preserving the original filename label in `raw_view`. `Settings` remains accepted unchanged. No case folding, substring matching, or other localized labels are introduced.

The native capture loop derives filenames from the actual NavigationView item's content. The retained failed capture manifest contains four Nastavení images; its validation records 56 measured captures and only `Missing required views: ['Settings']`. Read-only inspection of retained `1024x700-Light-Nastavení.png` confirms the Settings heading, provider configuration controls and selected Nastavení navigation item. This narrow label repair is therefore supported by actual capture evidence.

Normalization happens before view/theme/size grouping. Mixed English/Czech records for the same theme/size are duplicates rather than separate coverage. Four distinct Light/Dark and small/large combinations remain required. Original paths and hashes, PNG decoding, visible/nonuniform pixels, metadata, dimensions and viewport growth checks remain in force.

Updated `test_gui_checkpoint.py` with seven focused cases: exact English and Czech labels pass and retain original labels/paths; missing Settings, three captures, mixed-alias duplicate, near-match label and collapsed viewport fail. Existing synthetic PNG corruption/blank/filter/dimension checks remain included.

Verification: **40 offline tests PASS in 2.70 seconds**, exit 0, in `pytest-retry.log` / `retry-results.xml`. Initial sandbox attempt reached temporary-fixture ACL errors and is separately retained as `pytest.log`; it is not counted as PASS. Bounded approved retry used a fresh temporary root. No GUI, engine, model/provider, build or real-capture revalidation was performed by this task.

```powershell
.\.venv\Scripts\python.exe -B -m pytest docs/verification/windows-parity/WP023/astra-gui-20261022/test_gui_checkpoint.py -q -p no:cacheprovider --basetemp=docs/verification/windows-parity/WP023/astra-gui-20261022/sol-settings-alias-review/retry-test-temp --junitxml=docs/verification/windows-parity/WP023/astra-gui-20261022/sol-settings-alias-review/retry-results.xml
```

Failed `sol-newcandidate-capture-01` evidence was only read and remains untouched. Root owns separate read-only revalidation of the existing 56 images and must save its result in fresh evidence. Pixel validation is not visual acceptance: GUI review reported blank controls on large Dark Diagrams/detail captures and a stale navigation indicator. Those issues remain open and must be preserved in any revalidation result; no WP017/WP023, accessibility or release gate closes here.

Concurrency note: the helper edit preceded root's warning that an active watch run had pinned it. Root was notified immediately; that run's identity guard must treat the changed helper as changed, preserve the result and repin/retry as appropriate. No further helper edits followed the published final hash below.

| File | Final SHA-256 |
| --- | --- |
| run-gui-checkpoint.py | ca465bd99194112e77a25eaabd9858687ad6a1dbbbe7191facc1c4e32b268afb |
| test_gui_checkpoint.py | 5cf910ea6c38e69b365b9efdfdfddfdb9a3ea797b0451d04b3e9e2c622e2c0aa |

These are evidence-only Python files. Product/native sources and candidate payload were not modified.
