# Applied runner/verifier focused checkpoint — 2026-10-23

**PASS: 55 tests plus120 subtests**, exit0, pytest9.28s. Full focused files `tests/test_wp017_native_runner.py` and `tools/test_verify_wp017_live.py` ran once in an approved context. No first failed attempt was made; direct approved execution was authorized because earlier identical sandbox fixture workflows had Windows temporary-directory ACL failures.

The XML reports175 nodes because120 unittest subtests are represented separately; do not describe this as175 independent test methods. XML counts: failures0, errors0, skips0; XML elapsed9.166s. Outer process elapsed11.409s. `result.json`, `pytest.log`, `results.xml` and `command.json` preserve exact results, interpreter identity, arguments and environment.

Scope: offline runner/verifier fixtures, fake package/provenance checks and a harmless owned Python process/cleanup exercise. No native GUI, source build, engine scan, provider HTTP/model request or new candidate acceptance was executed. Native/core/schema verification is owned by the other assigned agents.

The focused files cover preserved default and old triplets, explicit7200/7800/8100 inert preflight and exact argv/launcher/provenance, bounds/order and strict numeric types, fixed-loopback extension, hash-bound missing/tampered/new/legacy evidence, package/source locks and owned cleanup. These passes establish the scoped runner/verifier checkpoint only.

## Source identity

All four active files were hashed before and after execution and remain byte-identical across the run (`source-before.json` / `source-after.json`). The applied files differ in byte hashes from the earlier proposed scratch copies because application normalized CRLF to LF; `postapply-comparison.json` honestly records those byte mismatches, while `postapply-normalized-comparison.json` confirms exact case-sensitive text equality after newline normalization for every file. No other source changes were found in this comparison.

| File | Tested SHA-256 |
| --- | --- |
| tools/run_wp017_native_modes.py | 63227037d32aa97005be22de30b026418942ef1db1960a848202399efab5018d |
| tools/verify_wp017_live.py | 56ae3a48f4f7c540bdd27c04f8b572f8ba9bd6495f87370e2e6bdf3273f783f0 |
| tests/test_wp017_native_runner.py | a54455dc72705d58a18cb0dc508c62a5f6eec3b44b23c65ada95a6221dfb0fb9 |
| tools/test_verify_wp017_live.py | b8c68a0744b20aa0a947ee5bfaa1517ae9d0016ca329b62931f7ca7290939052 |

Command:

```powershell
.\.venv\Scripts\python.exe -B -m pytest tests/test_wp017_native_runner.py tools/test_verify_wp017_live.py -q -p no:cacheprovider --basetemp=docs/verification/windows-parity/WP017/long-local-20261022/newlong-runner-tests-01/test-temp --junitxml=docs/verification/windows-parity/WP017/long-local-20261022/newlong-runner-tests-01/results.xml
```

Python bytecode/cache output was disabled; PYTHONPATH was absolute tools/src/repository. Source/helper leases remain frozen. No source edits were made and no additional test rerun is needed absent a change/failure/new required gate. Root owns broader integration, new source-bound candidate and subsequent real model/GUI decisions.
