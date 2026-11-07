# WP042 analyzer profile contract handoff — 2026-10-23

Scope: source-bound preparation under the active WP042 plan and root lease.
Base HEAD: `507bddacd72a246a136ca2d46faad2aa661806c1`. The shared checkout was
already dirty; this agent made no commits, resets, plugin changes, packaging,
provider calls or native UI changes.

## Changed files and API

- `src/attackmap/analyzer_profiles.py`: immutable offline profile definitions,
  deterministic availability serialization, strict resolution and qualified
  `name@version` identity. No discovery/installation/detection/execution inside
  this module. `AnalyzerProfileError` is a `ValueError`;
  `MissingProfileModulesError` exposes the exact missing names.
- `tests/test_analyzer_profiles.py`: 21 focused contracts, including actual
  runner `detect()`/ordering checks with injected analyzers.
- `docs/ecosystem/analyzer-profiles.md`: membership, policy and evidence limits.

API: `get_analyzer_profiles()`,
`analyzer_profile_inventory(installed_metadata)`,
`resolve_analyzer_profile(name, installed_metadata, explicit_modules=None)`.
Installed metadata may be `AnalyzerMetadata` or mapping values. Callers must
provide the effective deduplicated inventory for the selected engine; duplicate
names fail. Both canonical names and `name@1.0` are accepted. Selection exposes
`profile`, `profile_version`, `qualified_name`, `module_names`,
`candidate_module_names`, `experimental_module_names`, `opt_in_module_names`
and `as_dict()`. The inventory schema version is `1.0`.

| Profile revision | Fixed membership |
| --- | --- |
| `automatic@1.0` | Dynamic installed default-enabled universe; returns `module_names=None` |
| `node-atproto@1.0` | `javascript-web`, `node-service`, `config`, `atproto`, `default`, `node-atproto` |
| `php-laminas-omeka@1.0` | `php-web`, `config`, `php-laminas`, `default`, `omeka-s` |
| `python@1.0` | `python`, `python-web`, `config`, `python-service`, `default` |

Named profiles deliberately include experimental layers. Static definition
flags describe this revision; installed flags come from supplied effective
metadata. Membership is not applicability, execution, success or maturity.
Runtime order still uses actual `(priority, name)`; detection still gates even
explicit opt-in modules. Bare `-m` remains an exact list. A simultaneous profile
and nonempty explicit module selection fails. Missing bases or optional plugin
layers fail, with no substitution or installation.

## Verification

Command:

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_analyzer_profiles.py -q --basetemp=.tmp/wp042-profiles-20261023 --junitxml=docs/verification/windows-parity/WP042/sol-ultra-20261023/profiles-tests.xml
```

Result: **21 passed in 0.97 s**, exit 0. The first sandboxed attempt passed 19
contracts but hit WinError 5 in the dedicated temp directory for two `tmp_path`
setups and teardown. The recorded successful attempt used a narrowly scoped
escalation for the same command/temp directory. No broad cleanup was performed.
JUnit evidence: `profiles-tests.xml`.

`profiles-inventory.json` records live source metadata discovery through this
repository's `.venv` and resolution by the new source module: nine modules,
Automatic and PHP available; Node/ATProto misses `node-service` and `atproto`,
Python misses `python`. It also resolves the new definitions over the retained
21-module research inventory from
`RESEARCH-2026-10-23-analyzers-graphs/frozen-module-inventory.json`, carrying its
input SHA-256 and recorded executable hash. All profiles are available against
that supplied historical inventory. This is **not** fresh frozen execution,
new packaging, or proof the old executable contains the new profile code.

## Remaining boundaries

Root owns CLI/capabilities integration and related test evidence. Registry and
catalog ownership remains with the catalog agent. This slice does not close
WP006 manual acceptance or whole WP042. Native profile UI, a per-scan skip/run
ledger, new source-bound frozen candidate evidence, plugin update qualification,
real repository scans, LM Studio HTTP, native visual/accessibility acceptance,
macOS evidence and C27/C38 quality gates remain separate acceptance work.

## Independent integration review

Read-only review covered `cli.py`, `desktop_capabilities.py`, new CLI profile
tests, capability tests, `analyzer_catalog.py` and the `analyzers.py` observer
diff. Named profiles bypass installation/prompt paths; fleet receives the
expanded analyzer instances; legacy module JSON remains an array; new JSON
modes are mutually exclusive; observed capabilities and catalog use one
discovery pass. Source identity includes the new profile/catalog files and
relevant existing analyzer implementations. Registry precedence and successful
collector-record alignment remain unchanged across skips and load failures.
Pin metadata remains explicitly unverified content provenance.

Root identified and owns the Automatic helper correction: validate canonical
or qualified profile identity before discovery, then return the existing None
path for Automatic, avoiding a second plugin discovery/constructor pass. Unknown
profiles should likewise fail before discovery. Root also owns visible stderr
experimental/opt-in names for explicit profiles. No additional actionable
correctness defect was identified in this review. Root's final integration
tests, not this agent's earlier 21-test run, verify those shared-file changes.
