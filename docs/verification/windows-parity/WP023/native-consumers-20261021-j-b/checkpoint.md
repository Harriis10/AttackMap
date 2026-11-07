# WP023 native consumer checkpoint

All 26 explicitly named projects passed: **1,125 explicitly reported checks**.
`aggregate.json` records each count with its exact stdout line and stdout hash.
Commands, PIDs, exit status, duration, stdout, and stderr are retained for every
attempt. There were no timeouts or assertion failures.

The initial pass had 21 successes and five NETSDK1004 missing-assets failures.
Those failures remain preserved. Inspection showed all five projects target
net8.0 with no package/project references. The separately authorized follow-up
used only a new owned empty local NuGet feed, the existing SDK/package cache,
`--ignore-failed-sources`, and disabled NuGet audit. Only the five affected
projects were restored and rerun. All five restores and reruns exited zero.
No network/package installation, version change, source change, or repetition
of the original 21 successful projects was performed.

All **804** captured native/project, core/test, installer, and tool inputs stayed
byte-identical within each phase and across the full checkpoint. Generated
bin/obj/artifact/cache directories were excluded. Both wrappers inherited
process-local ErrorMode 0x8003 into owned children and restored the prior parent
mode; no machine error-reporting setting changed. Each owned process was bounded
at 180 seconds; none required termination.

This proves console fixture/model and owned Windows filesystem checks only.
No full native GUI, engine scan, provider request, credential store, controlled
fault broker, or frozen runner was executed. The earlier attempt in sibling
`native-consumers-20261021-j/initial-attempt.json` was interrupted during input
enumeration before tests began; it is not counted as a test pass or failure.
