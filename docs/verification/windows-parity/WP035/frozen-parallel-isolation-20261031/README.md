# WP035 — actual frozen ordinary parallel CLI isolation propagation

2026-10-31. Bounded PASS; whole WP035/C36 remains open.

Engine: `.tmp/fleet-e2e-engine-20261031-01/dist/attackmap/attackmap.exe`.
Command: `attackmap.exe analyze <absolute shared_datastores/reader> <absolute shared_datastores/writer> --output <fresh artifacts/.../reports> --format json --fleet-workers 2 --isolated-analyzers --no-progress`.
This is ordinary CLI parallel dispatch, without desktop/fleet-supervised transport.

Fresh actual evidence: `artifacts/wp035-frozen-parallel-isolation-20261031-03/`.
[Raw verification](../../../../../artifacts/wp035-frozen-parallel-isolation-20261031-03/verification.json)
records the actual OS argv and result; earlier failed attempts remain retained
in sibling `...-01` and `...-02` directories.
The accepted observation from this run is **argument forwarding**, not demonstrated
external analyzer isolation. The `execution_mode=in_process` observation is now
explained: these config-only fixtures selected builtins, whose policy deliberately
runs in process; external plugins were unmatched/skipped. The separate
[frozen plugin follow-up](../frozen-plugin-isolation-20261031/README.md) proves
PythonAnalyzer 0.1.0 succeeded in two observed analyzer_host processes across two
parallel repository workers. Its independent raw/hash review retains
`pin_status=unverified`, `content_verified=false`; wheel attestation does not
verify a declared Git pin. OS sandbox, crash/hang containment and whole WP035/C36
remain open. All earlier failed attempts are retained.
`invocation.json` records exact argv and executable SHA-256. `observed-processes.jsonl`
is external Windows CIM observation, without replacing engine functions. It captured
parent PID 32164 and its two immediate children: reader PID 31988 and writer PID 32004.
Both actual child command lines contain exactly one `--isolated-analyzers`, the frozen
executable directly (no Python interpreter), their correct repo/output and private
`--fleet-result` paths. These executable/repository/output/path facts were manually inspected in the captured command lines. `verify.py` automatically asserts only that exactly two observations have the parent PID, that each has exactly one isolation flag, and that each contains `--fleet-result`; it then saves `verification.json`. It does not automatically assert executable identity, repo/output/run-id binding, private path uniqueness, exit status, cleanup or unchanged hashes. The latter completion/cleanup/hash values are recorded by `run.py` in `result.json` and were manually checked, rather than asserted by `verify.py`.
Observation selected this exact executable; parent PID filtering in verification excludes
unrelated runs. No processes outside the owned Job were terminated or modified.

Parent exit 0; stdout records both children done. Published reader and writer `scan.json`
each contains its expected one config file, 21 analyzer ledger entries and no analyzer
errors. In each ledger, only the three built-ins `python-web`, `config` and `default` succeeded, all with `execution_mode=in_process`; all 12 plugin candidates and the other six built-ins were skipped. No external plugin executed. The earlier count of eight was my reporting error: `len(ledger)` counted the eight top-level envelope keys, instead of `len(ledger["entries"])`. The raw scan and verification ledger were correct and unchanged. SHA-256 of every fixture file and inventory matched before/after. The runner
starts the parent suspended, attaches a kill-on-close Windows Job before resume, and
waits for Job accounting: active processes = 0 before close, without forced termination.
`result.json`, stdout/stderr, scan artifacts and the ledger summary are retained.
TEMP/TMP/TMPDIR and all outputs were confined to this fresh artifacts directory.
No GUI, provider, installation, CVE or network feature was requested.

Earlier attempts are retained separately: `...-01` failed in the harness before engine
launch because Python has no named CREATE_SUSPENDED constant (correct value is 0x4).
`...-02` exercised the frozen 2-worker branch but Windows restricted temporary-directory
ACL denied both children before launch; its observer also failed script execution policy.
`...-03` used normal Windows permissions and inline PowerShell observation, with no
production code modifications or altered tempfile implementation.

This proves the specified frozen engine propagates requested isolation to actual ordinary
parallel child argv, completes both fixture scans, preserves inputs and leaves the owned
Job empty. These config fixtures do not prove execution of an external analyzer plugin,
plugin crash/hang containment, OS sandboxing, resource limits, GUI behavior, source/frozen
full parity, mature-family quality, release acceptance or all of WP035/C36.


