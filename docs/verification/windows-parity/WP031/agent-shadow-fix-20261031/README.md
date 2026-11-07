# WP031 corrective lexical-binding guard — 2026-10-31

This evidence supersedes the earlier WP031 imported-handler safety and
coverage claims. The pre-correction `1 TP / 0 FP / 15 FN` increment report is
retained unchanged as historical evidence; it is not the current score.
WP031/C27 remain incomplete and all affected families remain experimental.

## Final result

- [Final focused suite](focused-final7-qualified-final.xml): **414 passed,
  0 failures, 0 errors, 0 skipped**, 29.66 seconds. This comprises 270
  bounded-handler cases and 144 existing authz/auth-fusion/recall/snapshot/
  evaluator/increment-integrity cases. Earlier GREEN runs are superseded,
  not added to this count.
- [Final increment](final-binder-spellings/evaluation-increment/evaluation-report.json):
  **0 TP / 0 FP / 16 FN**, including holdout BOLA **0 TP / 0 FP / 1 FN**.
  All ten explicit negatives and the clean repository remain unviolated.
- [Final baseline](final-binder-spellings/evaluation-baseline/evaluation-report.json):
  exactly JSON-equal to the retained original baseline and pre-correction
  qualified baseline. Its earlier misses and known clean-node violation remain.
- [Final execution ledger](final-binder-spellings/evaluation-execution.json):
  both actual offline CLI commands exited 0, with sources/inputs unchanged
  during the runs. The increment exactly matches its preimplementation freeze.
  No corpus, labels, matcher, evaluator or split was edited.

The loss of the previous basket TP is deliberate conservative coverage loss.
The registration file contains an opaque slash/regex expression with an inline
callback scope delimiter. The existing literal/comment masker cannot establish
that scope structure, so the producer refuses the imported binding. The basket
case remains an honest FN; it was not relabeled or removed to preserve a score.

## Corrected behavior and finite supported syntax

The previous resolver looked up an import name without establishing whether an
enclosing lexical parameter shadowed it. A same-spelling function parameter
could therefore point at unrelated runtime behavior while the producer cited
the imported function's query as route evidence.

The additional guard is bounded and conservative; it is not a JavaScript or
TypeScript parser or a general name-resolution proof:

1. Before the registration expression, structural delimiters must be balanced.
   A registration with an already-open outer parenthesis or bracket is
   unsupported. This excludes parameter-default initializers, nested IIFEs
   inside defaults, and other expression/call contexts. It does not model their
   initialization semantics. The registration call's own parentheses are
   opened after the inspected source position; ordinary multiline `app.get`
   and `asyncHandler` arguments remain supported.
2. For enclosing plain function/method/catch/arrow body headers, any mention of
   the import local in the parameter list vetoes resolution. This includes
   nested closures capturing a shadowing outer parameter. Destructuring keys
   and default expressions may over-veto because their name mentions are
   treated conservatively. Unrelated sibling parameter scopes do not by
   themselves veto an unshadowed registration. Expression-bodied arrow extents
   are conservative; ASI boundaries are not guessed.
3. The existing declaration/write veto remains **file-wide**, independent of
   source order. It now walks all `const`/`let`/`var` declarators, including
   later identifier and nested object/array binding patterns, compact `const{`
   syntax and multiline lists. Balanced initializer parentheses/brackets/braces
   prevent internal commas from becoming declarator boundaries; strings and
   comments are already masked. Unknown, opaque, mismatched, deeper-than-64 or
   longer-than-24,000-character declaration syntax vetoes the binding.
4. File-wide named function binders cover plain, async, generator and async
   generator forms, compact `function*name`, masked comments and named
   generator expressions. Class and TS enum/namespace/module binders of the
   same name are also vetoed. The direct `name = ...` write veto is retained.
   An unrelated sibling declaration/write can conservatively suppress a valid
   import; this is not a complete JavaScript assignment grammar.
5. Escaped identifiers, unknown callable/type headers, opaque hidden scope
   delimiters and unsupported source structures are refused. This finite
   implementation does not interpret arbitrary JS/TS grammar, runtime types,
   dynamic policies or evaluation effects.

Literal named/aliased/namespace ESM imports and the existing exact target
function/zero-argument factory shapes are otherwise preserved. Dynamic imports,
reexports, arbitrary wrappers, argument-bearing/custom factories and ambiguous
module files remain unsupported. No ownership policy, global auth fusion,
source-capture contract or finding schema was changed.

## Reproduced failures and corrective history

All new cases are authored tuning/regression fixtures, not unseen evaluation
holdouts. Named, aliased and namespace variants are exercised with imports
before/after registration and with paired valid sibling/nested controls.

- [Missing enclosing-scope veto RED](red-qualified-final.xml): **54 failed,
  28 passed, 25 deselected**. Only the newly added scope guard was disabled in
  that short-lived process; source files were never restored/reverted. This
  isolates the previous missing check, not an exact checkout of all old code.
- [Later-declarator RED](declarator-red-qualified-final.xml): **36 failed,
  1 passed, 122 deselected**, with the actual intermediate guard enabled.
- [Parameter-default RED](parameter-red-qualified-final.xml): **24 failed,
  2 passed, 204 deselected**, with the actual intermediate guard enabled.
  The two passing controls are ordinary unshadowed multiline registrations.
- [Generator-binder RED](generator-red-qualified-final.xml): **6 failed,
  230 deselected**, with the actual intermediate guard enabled.
- The final GREEN above includes every retained counterexample plus controls
  for compact/spaced unrelated destructuring, nested initializers with string/
  comment commas, ordinary/async/generator binders and multiline registration.

The initial ordinary pytest attempts were invalid environment runs: directory
creation with Python 3.13's Windows mode 0700 made temporary directories
inaccessible to the restricted process. Their logs/XML are retained separately
and do not count as RED/GREEN proof. [run_checks.py](run_checks.py) changes only
`os.mkdir`'s mode to inherited 0777 in its own short-lived process before
`pytest.main`; it does not alter production or shared test-harness code. Two
inaccessible failed-attempt directories may remain; generated successful
test fixtures are disposable and excluded from the evidence manifest.

## Final identities and reproduction

Final SHA256 identities:

- `src/attackmap/authz_js_handlers.py`:
  `eb28da250e243953617cbd5a8350c357454e71623a6b058bb8b6aaa06afd00c1`
- `tests/test_authz_bound_handlers.py`:
  `a77084ca4e128b7dfd6f7e35b7d9087bd5abd8c3e01d50693160952b906a1348`

From the checkout root, use a fresh stage/output name rather than overwriting
the retained evidence:

```powershell
.venv/Scripts/python.exe -B docs/verification/windows-parity/WP031/agent-shadow-fix-20261031/run_checks.py focused-final7
.venv/Scripts/python.exe -B docs/verification/windows-parity/WP031/agent-shadow-fix-20261031/evaluate_frozen.py final-binder-spellings
```

Exact executed commands and arguments are in
[the test execution ledger](focused-final7-execution.json) and the final
evaluation ledger above. `evaluate_frozen.py` refuses to overwrite an existing
report directory. The test runner likewise uses a stage-specific temporary
directory; archive or choose a new stage before repeating retained runs.

No provider/LM Studio calls, GUI/native preview, packaged build, performance
qualification, production-diverse holdout or release acceptance ran. Independent
current-source review is a separate integrator gate; a passing authored matrix
does not establish a complete language resolver or mature BOLA coverage.
