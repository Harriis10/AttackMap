# Scanner timing diagnosis disposition - 2026-10-22

Read-only inspection identified the exact historical retry failures: resource-budget overhead 1779.564 ns against <1000 ns; four 200KB long-line cases against <5 s; 6000-route many-match scan against <25 s; taint flow against <20 s. Installer help retry passed. The historical retry remains seven real failures and is not relabeled.

CodeGraph was consulted before source inspection. Current scanner already has word-start/possessive matching for several router/blueprint expressions, so static inspection alone did not justify a behavior-changing regex rewrite. No scanner or test change was made. A bounded long-word profiling script was prepared but never executed; there is no profile output, benchmark result or new performance claim from this worker.

Root reports the other worker's canonical focused campaign completed 275 PASS, including all seven unchanged timing gates. That is newly reported source-test evidence owned by that worker, not an execution by this audit worker and not retroactive repair of the historical failed checkpoint. Root owns the exact run/artifact identity and integration verdict. No further timing/profile repetition is warranted without a new unresolved concern.

Scanner lease released. No native/model/build/package/full-suite execution, canonical tracker edit or Git commit occurred. Differential-pattern tests were unnecessary because no pattern change was proposed or applied.
