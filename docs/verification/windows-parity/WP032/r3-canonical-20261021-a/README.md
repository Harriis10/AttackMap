# R3 canonical promotion

Root approved the exact six-file candidate; promotion checked all original destination hashes and all candidate hashes before copying. `promoted-inputs.json` preserves those identities. No `report.py` or retained fixture was edited.

Canonical verification covered 84 exploitability/presentation/ranking/identity/reference tests plus five report/schema tests: **89 distinct passes**. The first run retained 72 passes and 17 setup errors caused by sandbox `WinError 5` while enumerating the owned pytest temp directory. Only those 17 nodes were retried using a fresh owned directory with approved escalation; all 17 passed. There were no assertion failures. `focused-run.json` and `setup-retry-run.json` preserve exact commands/results; both recorded unchanged source, report writer and fixture hashes.

The parent candidate README records source association, exact schema/default serialization effects, numeric compatibility and legacy fixture import evidence. This focused verification does not establish broad-suite, native runtime or packaged acceptance.
