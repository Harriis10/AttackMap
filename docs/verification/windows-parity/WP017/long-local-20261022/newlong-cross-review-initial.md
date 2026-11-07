# Initial independent core/native patch review — 2026-10-23

Reviewed only the proposed evidence patches and current source context; no actual source changes, imports, tests, builds, GUI or provider execution. Core patch SHA-256 `26c8a247a8d852e8822864417c9b36ecbc782d09fd65cf28c7ce524c4b1d5060`; native patch SHA-256 `10e3eae903005708fe5dc9b1222b70cea27b78e9fc539f4a828b9901a4cebed4`.

**Changes requested before integration:** the Python `local_extended_allowance` predicate accepts an empty explicit port, such as `http://localhost:/v1` or `http://127.0.0.1:/v1`. `urlsplit(...).port` is None for an empty port, so the current `port is not None and port <= 0` condition does not reject it. Existing endpoint validation also leaves it accepted. The native proposed original-authority regex rejects this syntax and its tests explicitly cover `http://localhost:/v1`. Align the extension predicates and add both Python model versions to the empty-port negative matrix.

Normalization should also agree: Python's existing endpoint validator strips surrounding whitespace before the new predicate, whereas native's proposed regex sees raw Endpoint even though URI parsing may normalize surrounding whitespace. Reviewers should explicitly resolve this difference rather than claiming equivalent acceptance semantics.

The core patch adds the four 1000-second calls under one 7200-second ledger test but does not yet add the design's consumed-time case with a final timeout below 3600 and eventual deadline exhaustion/abstention. Existing 3600-ledger tests provide related regression evidence, but are not the newly requested 7200-ledger scenario.

Otherwise the intended chain preserves ProviderOptions/native provider default600, QA defaults900/1200/1500, call/token/jury values, no ambient environment promotion, and inherited shared ledger semantics. The core/native patch does not raise SDK constants: individual local SDK ceiling3600 and remote ceiling900 remain unchanged. Native numeric disclosure and saved preference/remote-switch tests are included. These source observations are not executed proof.

This is an initial review of the hashes above, not clearance of a later revised patch. Root has been notified and owns application timing and coordinated follow-up validation.
