# Retained Windows M3 evidence

Cleanup on 2026-10-16 preserved the final accepted beta's evidence before deleting
old cache directories and duplicate application/runtime copies. This directory
is evidence, not an additional installed build or a new test suite.

- `live/output/da6b4d5767534bcd859d83b68fab8a7c/`: actual Juice Shop generation,
  report, AI response and metadata, with the original generation manifest.
- `live/`: original request, protocol transcript, exit/result data, installed
  native report check and the script used for that recorded run.
- `native/` and `engine/`: final build/report proofs and engine provenance.
- `regression/`: final focused results, including the original failed expectation
  run and its corrected result.
- `visual/`: final application content screenshots, not OS/Narrator acceptance.

`relocation-manifest.json` binds every retained original file by SHA-256 and maps
its old workspace-relative path to its new location. Original proof documents
retain their recorded paths and hashes; paths to removed installations, older
builds or discarded raw campaigns are historical and are no longer runnable.
No missing historical artifact is silently presented as still available.

The active build remains in
`../../artifacts/development-packages/dev-20261015190038-5667bbbf` and its adjacent
ZIP. Manual validation remains deferred to M4; reference validity is not model
claim validation. Keep this evidence separate from disposable new test output.
