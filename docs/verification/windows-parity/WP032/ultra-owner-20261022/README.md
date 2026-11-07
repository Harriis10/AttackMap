# Bounded R10b ownership index — 2026-10-22

The canonical change preserves existing output. It indexes topology service names once per graph build and reuses the ordered per-file names for role attachment and first-owner lookup. Previously every role hint rescanned every auth/service/edge hint. Role count now does not add whole-hint passes; a deterministic operation-count test verifies this without a timing threshold. No runtime speed or memory qualification is claimed.

The sealed `r10b-candidate-20261021-a` ambiguity-policy prototype is **not promoted**. Its deliberate ambiguity blocking and layout-node suppression are held alongside its empty-owner regression. This patch does not choose a new policy for ambiguous owners.

## Preserved consumer rules

- Topology reads auth, service and edge hint families in that order. It lowercases names, preserves exact raw file keys, ignores empty payloads for ownership, uses the first nonempty name for outbound edges, and attaches roles to every distinct nonempty name in first-seen order. Existing rendering separately strips names. Existing layout nodes remain present.
- Threat modeling reads auth and service names only, deduplicates exact raw `(payload, file)` pairs before lowercasing, and uses the last remaining declaration. An empty payload is an explicit mapping value and blocks map-level layout fallback. For example, `alpha, beta, alpha` selects `beta`; `alpha, empty, alpha` retains the empty marker. `threat_model.py` is byte-for-byte unchanged.
- Neither consumer gains stripping, casefolding, path normalization, ambiguity rejection, confidence changes or new provenance claims from this patch.

## Verification

Both commands reached terminal process exit 0:

- Focused canonical tests: **132 passed**, no failures, errors or skips. Four files: `test_topology.py`, `test_threat_model.py`, `test_wp032_unknown_auth_topology.py`, `test_wp032_service_owner.py`. Fresh basetemp `.tmp/wp032-ultra-owner-20261022-01`; no sandbox error or retry.
- Full serialized baseline/current differential: **346 / 346 equal**. Complete maps, per-file service lists, graph nodes/edges, service chains, ATProto chains, generated findings and generated attack paths are compared, including complete evidence and scores. The 324-case matrix crosses three typed hint families, 18 name sequences, HTTP/env/queue targets and slash/backslash file keys. Sixteen mixed-family cases and six separate-sink/no-layout cases extend it. Inputs are hash-verified unchanged.
- Probe negative control: the original sealed candidate is loaded separately and the same empty service hint still changes its threat map from empty to `layout`; the probe detects the complete-output difference. Thus equality is not caused by accidentally comparing the same implementation twice.
- Empty-marker regression has an explicit focused assertion over the entire service chain, including the approximately 0.50 confidence and inferred-layout/elsewhere-in-repo evidence. Exact duplicates, order changes, whitespace-only names, leading/trailing spaces, Unicode lower/casefold distinctions and different consumer families are covered.

`baseline/` preserves the exact pre-edit source bytes; hashes match the preceding resume review. `golden-before.json` contains all complete baseline outputs. `compatibility.json` contains the verdict, source identities, golden hash and complete rejected-candidate negative control. `canonical.patch` is the exact two-file patch and `manifest.json` seals its identities and verification results.

Commands, from the repository root:

```powershell
$env:PYTHONDONTWRITEBYTECODE='1'
$env:PYTHONPATH=Join-Path $PWD 'src'
& ./.venv/Scripts/python.exe -X utf8 docs/verification/windows-parity/WP032/ultra-owner-20261022/compatibility_check.py
& ./.venv/Scripts/python.exe -X utf8 -m pytest tests/test_topology.py tests/test_threat_model.py tests/test_wp032_unknown_auth_topology.py tests/test_wp032_service_owner.py -q -p no:cacheprovider --basetemp .tmp/wp032-ultra-owner-20261022-01 --junitxml docs/verification/windows-parity/WP032/ultra-owner-20261022/focused.xml
& ./.venv/Scripts/python.exe -X utf8 docs/verification/windows-parity/WP032/ultra-owner-20261022/seal.py
```

The recorded focused run is final; reruns require a new basetemp and evidence destination. No broad suite, profile, live provider, GUI, build, package or Git command was run by this lease. This bounded result does not complete WP032 or any release checkpoint.
