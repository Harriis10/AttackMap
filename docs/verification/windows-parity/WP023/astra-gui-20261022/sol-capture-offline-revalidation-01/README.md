# Derived offline replay of retained captures — 2026-10-23

**PASS for derived offline guard replay only:** 56 copied captures validated in 121.48 seconds, exit 0. No new native run, renderer, GUI, scan, provider request or build was executed. This is not retroactive PASS for the original failed campaign.

Original input: `../sol-newcandidate-capture-01/capture/`. The original capture manifest SHA-256 is `60c10c8e4763445e0dc1f6481e0debaff418f0a832b83c5e605e0e03586b7fce`. It is preserved byte-for-byte as `original-capture-manifest.json`. `copy-provenance.json` maps original paths to copies with original/copy SHA-256 values.

Copied 56 PNGs and the eight Architecture/Inventory row-diagnostic sidecars into `captures/`. Sidecars were necessary to exercise the existing guard without weakening its structure checks. `derived-capture-manifest.json` preserves the native metadata except for each `captures[].OutputPath`, which points at its copied PNG. No other metadata fields changed.

Imported the frozen guard with SHA-256 `ca465bd99194112e77a25eaabd9858687ad6a1dbbbe7191facc1c4e32b268afb`. Required views remained Architecture, Inventory, Reports, Settings and FindingDetail, with actual theme/size pairs, PNG/metadata hashes, decoded visible/nonuniform pixels and viewport growth checked. The exact Nastavení alias is reflected by canonical `view=Settings` and preserved `raw_view=Nastavení` in the derived validation.

`original-tree-before.json` and `original-tree-after.json` cover every original capture-directory file and are equal. `copy-inputs-before.json` and `copy-inputs-after.json` cover copied input bytes and are equal. All 64 original/copy mappings remain byte-identical after validation. The failed original capture directory and all source/helpers were untouched. The replay ran within its 540-second deadline and needed no sandbox escalation.

The result, complete warnings, false acceptance flags and timing are in `result.json`; measurements are in `captures/capture-validation.json`; command output is in `replay.log`. Reproduction source is the new evidence-only `replay.py`, invoked once as:

```powershell
.\.venv\Scripts\python.exe -B docs/verification/windows-parity/WP023/astra-gui-20261022/sol-capture-offline-revalidation-01/replay.py
```

Visual findings remain open: blank controls in large Dark Diagrams/detail captures and stale navigation indicators. Pixel validation cannot establish appearance or usability. No WP017/WP023, accessibility, candidate or release gate closes here.
