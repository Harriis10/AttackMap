# Roadmap integration batch — 2026-10-30

Three GPT-6.1 Sol agents and root completed two core vertical functions and a
native diagnostic qualification cycle. Base commit:
`4ea5e49ade229fc0432d68ce0f7e99bcf87b545d`; changes are uncommitted. Existing
source work, historical evidence and paused leases were preserved.

## Delivered scope

| Lane | Implemented and verified | Still open |
|---|---|---|
| WP039 | Isolated analyzer workers reconstruct the exact selected installed entrypoint distribution/version/target. Missing or ambiguous origins fail without falling through to another implementation. Real offline installed pinned Python plugin, collision control and execution ledgers were exercised. | C27/C38 maturity, dynamic/class/DRF coverage, other dependencies, frozen installation and whole-task acceptance. |
| WP044 | Explicit owner-supplied YAML/JSON declaration → config extractor → provenance/merge → production fleet architecture, with exact source evidence on both endpoints. Central identity validation rejects credential-shaped raw/canonical hosts. | Automatic inference from ordinary framework settings, representative production fleet, native mapping, producer/consumer/RPC and whole-task acceptance. |
| WP043 | Startup placement occurs after report readiness and requires observed 1600×1000 geometry. Ctrl+Alt+Shift+R avoids sending F7; modal, PNG CRC/decode and root-quality gates preserve rejected evidence. Candidate-10 was exercised in the native application. | Rendering failure persists. The final live run completed four journeys, then rejected an empty root raster in round 5. No five-round acceptance, root cause, repair or V01–V03 promotion. |

The native diagnostic candidate retains the previous engine. It does not contain
a newly frozen integration of the WP039/WP044 source changes and is not a release
package.

## Core verification

Root's final combined affected suite passed **320 tests in 37.73 s**, after the
credential-host correction. It covers analyzer host/origin/isolation/ledger,
pinned Python route normalization, config extraction, resource identity,
fleet architecture/serialization and desktop graph contracts. Command:

```powershell
.venv/Scripts/python.exe -B -m pytest tests/test_analyzer_host_origin.py tests/test_analyzer_host.py tests/test_analyzer_isolation.py tests/test_analyzer_run_ledger.py tests/test_ecosystem_python_plugin_routes.py tests/test_pipeline_analyzer_ledger.py tests/test_config_datastores.py tests/test_config_scanner.py tests/test_fleet_architecture.py tests/test_fleet_resource_identity.py tests/test_desktop_graph.py tests/test_fleet.py -q -p no:cacheprovider --basetemp artifacts/roadmap-batch-20261030/integrator-core-final-temp --junitxml artifacts/roadmap-batch-20261030/integrator-core-final.xml
```

The earlier 316-test combined run predates the final host-identity rejection;
it is retained as intermediate evidence, not substituted for the final run.
Agent suites overlap this result and are not added as distinct tests:
WP039 69 affected tests, WP044 251 final affected tests. The focused diagnostic
harness is separate: **68 tests and 20 subtests passed** on the final non-F7
source. These are fake-backend/source checks, not live GUI or AI acceptance.

WP039 actually built and installed the retained pinned Python analyzer offline
into a task-owned target. Archive and installed source bytes were checked. Real
entrypoint discovery and worker processes verified Django route normalization,
selected-origin collision behavior and Node-only negative applicability. Actual
Juice Shop in-process and isolated runs have identical languages and all 21
structured signal families, including 266 routes, 1,251 calls and 176 dependencies.
This is execution-mode parity with the same installed plugin, not a claim that
Juice Shop contains no Python files or that local-wheel provenance authenticates
a VCS revision. See the [WP039 handoff](../../../../artifacts/roadmap-batch-20261030/wp039/HANDOFF.md).

WP044 production serial and two-worker fleet runs scanned 16 **synthetic physical
repositories**, verified all 32 child manifest and section checksums, and retained
identical normalized architecture facts. Eight explicit declarations produce one
undirected `declared` association, seven resources and six unmatched declarations.
Architecture coverage is honestly 15 completed + 1 partial because a short-host
declaration is rejected; all 16 child scans succeeded. Real Juice Shop plus a
library control completed with zero shared edges. AI/CVE/install were disabled.
Final rejection-only hardening was followed by the 251-test suite and fresh
16-root extraction/projection checks; the retained full production runs precede
that final rejection change. See the [WP044 handoff](../../../../artifacts/roadmap-batch-20261030/wp044/README.md)
and the [opt-in declaration contract](../../../fleet-datastore-declarations.md).

Independent cross-review found the credential-host defect and rechecked both raw
and uppercase/canonical token-shaped negative controls after the central fix.
Both core reviews then cleared their assigned scopes. Neither reviewer converted
scoped results into whole-WP, native, package or maturity acceptance.

## Native diagnostic evidence

Candidate-09 live-29 passed actual geometry placement and produced meaningful
Detail/root PNGs, but stopped on an unidentified modal before B. Instrumented
live-30 retained a quarantined failure screenshot and UIA descriptors proving
that **Ctrl+Shift+F7 still opens the caret-browsing dialog**. It was not dismissed
or accepted. The trigger was therefore moved entirely away from F7.

Offline candidate-10 publish passed using .NET 8.0.426, existing task-local NuGet
packages and `--no-restore`. Managed DLL SHA-256:
`c10f67dfd9e3dd6d81e6b4cb365ca274daa7c233a5255104265e2b790cfffa93`.
All 308 retained engine files match candidate-09; engine executable SHA-256:
`792184c584895bab68e4260447fe89543486ae228bd8ad85234ae3ca87ce8bba`.
The same retained report hash is
`860343835432b3267da81f4b4124925eeae94ea570ed972cb3c4b040875d581d`.

Live-31: PID **37112**, run ID **a6fcfaec890e414ca6cd389a5646df30**,
**67 accepted ordinary captures, one discarded capture, four complete A/D/T/B
sets**, then `root-raster-empty` in round 5. No B5 was taken or accepted.
All 19 available target images were actually viewed by the independent reviewer;
root separately viewed seven selected native frames. Full image scope, hashes,
revisions and measured dimensions are in the
[manual review](../../../../artifacts/roadmap-batch-20261030/wp043/candidate10-live-31/visual-review/manual-review.json).
This is targeted review, not acceptance of all 67 ordinary captures.

| Round | A live Detail body | D Detail RTB | T root RTB body | B live Detail body |
|---|---|---|---|---|
| 1 | Complete | Complete | Complete | Complete |
| 2 | Absent | Complete | Complete | Complete; other glyphs missing |
| 3 | Absent | Complete | Complete | Complete; other glyphs missing |
| 4 | Complete | Fully transparent | Complete | Complete; other glyphs missing |
| 5 | Absent | Fully transparent | Fully transparent; rejected | Not captured |

No modal was observed in the reviewed live-31 targets, and no modal guard failed
in that run. Rounds 2–3 support a distinction between ordered live presentation
and both RTB paths; subsequent recovery is temporal correlation, not proof of a
repair. Round 4 confirms local RTB is not a live glyph oracle. Round 5 is a real
quality rejection and cannot enter the clean interpretation matrix. This is not
`not-reproduced`, a complete five-round sample, or a rendering mechanism claim.

Owned PIDs 22840, 11464 and 37112 were independently found absent after cleanup.
Original `closedCleanly=false` values remain preserved: normal five-round success
was not reached. No unrelated processes were terminated. No provider calls,
remote installs, commits, publication or package promotion occurred in this batch.

## Evidence and next gate

Raw logs, reports, hashes and local installations are under
`artifacts/roadmap-batch-20261030/`. Root's final verification JSON records the
source and evidence inventories and lease release. Main roadmap/TODO/backlog
retain WP039, WP043 and WP044 as **IN_PROGRESS**; rendering is **FAILED** and
V01/V02/V03 remain blocked.

Next WP043 work must explain the demonstrated live/RTB divergence with a supported
non-mutating mechanism. Do not rerun to obtain favorable pixels, weaken the
root-quality gate, or use the render probe as a production workaround. Separate
native mapping, representative production corpus, frozen integration and release
gates remain necessary for the core changes.
