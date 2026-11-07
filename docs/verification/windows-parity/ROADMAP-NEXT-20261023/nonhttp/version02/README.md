# WP044 shared-datastore contract: version02

**104 focused tests PASS. Prepared contract only; WP044 remains IN_PROGRESS.**

Independent review found that Windows roots with trailing dots/spaces could
represent the same Win32 repository while appearing different to the prepared
projection, and that IPv4 limited broadcast was accepted as a shared endpoint.
The focused correction rejects every Windows root component ending in a dot or
space before normalization, plus `255.255.255.255` and its IPv4-mapped IPv6 form.
Eight regression cases cover these gaps. No production adapter was added.

The [original contract](../CONTRACT.md) remains the scope definition, with these
stricter Windows path and broadcast rules added. The [original evidence](../README.md)
and its 96-test JUnit remain preserved. This revision contains the final
[104-test JUnit](tests-03.xml), [verification](verification.json),
[source before](source-before.json) / [source after](source-after.json),
[generated schema](shared-datastore-declaration.schema.json), fresh paired
fixtures and [machine handoff](HANDOFF.json).

The exact fleet16 graph comparison passed again: remove only
`coverage.protocols.shared_datastore.extraction_contract` and the whole graph
equals the saved baseline. Existing HTTP/proxy nodes, edges, IDs and evidence
remain unchanged. Pure contract fixtures do not prove actual extraction,
connectivity, provider execution, native mapping or acceptance.

```powershell
.venv/Scripts/python.exe -m pytest tests/test_fleet_resource_identity.py tests/test_fleet_architecture.py -q -p no:cacheprovider --basetemp=.tmp/roadmap-next-20261023-nonhttp-v2-01 --junitxml=docs/verification/windows-parity/ROADMAP-NEXT-20261023/nonhttp/version02/tests-03.xml
.venv/Scripts/python.exe docs/verification/windows-parity/ROADMAP-NEXT-20261023/nonhttp/version02/verify_contract.py
```

Final source/test content SHA-256:
`b87f77a5a02cb615b78a41730d31a3ace03515ce1fa49fa7d5797b3ad2a893fe`.
Production non-HTTP capability statuses remain `unanalysed`; runtime extraction,
snapshot binding, integration, real fleet, native/manual, release/clean-host and
macOS gates remain open. No scans, providers, builds or commits were performed.
