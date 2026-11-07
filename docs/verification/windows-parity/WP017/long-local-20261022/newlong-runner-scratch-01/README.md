# Runner patch preparation — 2026-10-23

Prepared `../newlong-budget-runner.patch`, SHA-256 `ac5f30a4973176bcd95c9d4a33187c73af74808eea5f9d079dd8ac268cfac3b1`. It is **not applied or tested**. All work was performed on fresh scratch copies; `preparation-proof.json` records matching before/after hashes for all four actual source files and hashes of proposed files. `before/` and `after/` preserve both forms.

Proposed runner provider total maximum is 7200 for its fixed loopback endpoint, process maximum is 10800, and explicit triplet coverage includes 7200/7800/8100. Defaults remain 900/1200/1500; old 3600/4200/4500 cases remain. A high allowance additionally requires the runner's exact fixed endpoint constant. CLI disclosure says total AI allowance. Strict integer checks, ordering, exact native/request/launcher proof, process ownership, identity pins, calls/tokens, and preflight inertness are preserved.

The offline evidence verifier's extended provenance path accepts the new bounds while requiring all existing hash/type/value/exit/cleanup checks. Its legacy provenance-free default gate remains 900. Tests add new exact-triplet inert preflight/argv/saved-budget coverage, upper boundaries, non-loopback rejection, new provenance tampering including numeric floats, and rejection of legacy/remote evidence promotion. Existing default/old-budget tests remain included.

Static AST parsing of all proposed copies and `git apply --check` succeeded. These are syntax/applicability checks, not test execution. No product imports, source edits, GUI, engine/model/provider, build, or offline tests were performed. Root must release the source lease, independently review/apply the coordinated core/native/runner changes, and run focused checks before any new source-bound candidate.
