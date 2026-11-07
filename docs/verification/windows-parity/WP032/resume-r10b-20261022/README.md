# R10b resume review — 2026-10-22

Status: **candidate retained, no canonical promotion**. Source/test files were not edited. Root granted narrow topology.py/threat_model.py/test_wp032_service_owner.py lease; released at this handoff. contracts.py/crossrepo.py were unrelated and untouched.

## Fresh bounded verification

The exact preserved candidate suite was rerun using the existing candidate src/tests, explicit candidate pytest.ini, fresh basetemp and fresh JUnit. Terminal process exit0: **103 passed in 2.18s**, no failures/errors/skips. See original-candidate.log/xml. This is candidate-only focused verification, not canonical acceptance.

Command (repository cwd):

```powershell
$env:PYTHONPATH=Join-Path $PWD '.tmp/wp032-r10b-candidate-20261021-a/src'
$env:PYTHONDONTWRITEBYTECODE='1'
& ./.venv/Scripts/python.exe -X utf8 -m pytest .tmp/wp032-r10b-candidate-20261021-a/tests/test_topology.py .tmp/wp032-r10b-candidate-20261021-a/tests/test_threat_model.py .tmp/wp032-r10b-candidate-20261021-a/tests/test_wp032_unknown_auth_topology.py .tmp/wp032-r10b-candidate-20261021-a/tests/test_wp032_service_owner.py -q -p no:cacheprovider -c .tmp/wp032-r10b-candidate-20261021-a/pytest.ini --basetemp .tmp/wp032-r10b-resume-approved-20261022-01 --junitxml docs/verification/windows-parity/WP032/resume-r10b-20261022/original-candidate.xml
```

## Compatibility finding blocks promotion

`compatibility_probe.py` ran canonical and sealed candidate consumer functions against the same ScanResult instances, serializing maps, graphs and service chains for21 cases: auth/service/edge typed hint families crossed with absent, empty, case-equivalent duplicate, trailing-space, conflicting, empty-then-name and name-then-empty declarations. Full actual output is compatibility.json; process exit0. These are diagnostic comparisons, not21 passing assertions.

A file `services/layout/app.py` with one empty `service_name:` hint in auth_hints or service_hints has canonical threat owner `""`. The candidate drops that explicit hint and falls back to `"layout"`. With a route and database in that file, canonical chain confidence is approximately0.50 with inferred-layout and elsewhere-in-repo evidence; candidate confidence becomes0.80 and reports **entry service from file-local hint** and **database sink in service layout**. No analyzer actually supplied that owner. This is an unintended evidence/score change outside the intended ambiguous-owner repair and was absent from the103 preserved tests.

Empty-plus-valid combinations also change canonical order-sensitive behavior. A policy for these combinations needs explicit tests before promotion: simply accepting empty values as another owner invents ambiguity; simply dropping them silently changes the historical empty-marker behavior. No speculative canonical policy was introduced.

Case folding remains lower-only in owner collection, while graph rendering separately strips names as before. Raw file keys remain exact. Consumer typed hint families remain distinct: topology reads auth/service/edge; threat ownership reads auth/service only. The candidate intentionally suppresses layout nodes when explicit ownership exists and blocks ownership-derived roles/edges/chains for conflicting names; those intended differences mean full serialized output equality is not the golden condition.

Canonical hashes match sealed baseline: topology.py `28DCF0DE5AD989C8732B66CEFBC907864788D7863031AE14E7CB432B498C3FD3`; threat_model.py `49A08F1A0D3FF348B97B62C0DC44897AB7F4232B177117C967192557CB7CB31F`.

No source coverage or thresholds changed. No GUI, live model, build, package, broad regression or stress run. All commands reached terminal exits; no background work was created.
