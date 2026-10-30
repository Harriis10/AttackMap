# Immutable Python plugin qualification — 2026-10-23

Decision: **NO-GO for advancing the installed Python plugin pin in this slice.**
The candidate and observed main commit improve Django URL composition, but
introduce reproducible false authentication classifications and do not resolve
the FastAPI/Flask mount gaps. Shared venv, cached wheel and lock pins were not
modified. Fixture application/framework code was parsed without execution;
no provider was called.

## Immutable identities and source provenance

Official upstream commits inspected:

- Installed declared pin: [1bcce0dd5d639cb83ada65cc3f5024bb5a1d9782](https://github.com/mlaify/attackmap-analyzer-python/commit/1bcce0dd5d639cb83ada65cc3f5024bb5a1d9782).
- Candidate: [478208fd33b7fa30e2acbb08f184b2e289f7bb0a](https://github.com/mlaify/attackmap-analyzer-python/commit/478208fd33b7fa30e2acbb08f184b2e289f7bb0a).
- Main observed at GitHub API response Date **2026-10-23 10:50:25 UTC**:
  [87e4a8ac3de74e2a6f459af41ddc7c85cc1f3be5](https://github.com/mlaify/attackmap-analyzer-python/commit/87e4a8ac3de74e2a6f459af41ddc7c85cc1f3be5).
  This is an exact observation; main remains volatile.

All report version `0.1.0`; package version does not identify the implementation.
`upstream-fetch.json` retains API metadata, archive URLs, HTTP headers, byte counts
and SHA256. The original archives are retained here as
`upstream-{pinned,candidate,main-observed}-source.zip`:

| Archive | Bytes | SHA256 |
| --- | ---: | --- |
| pinned | 35738 | `913c102365d5b9e4b902683edc022aa6a281cd4d77990f71abbddf6c0bccf536` |
| candidate | 68072 | `5edd9b3c4ff7e19ab2b5087c78152a50b7fd96076cac2d9ccb7f53617a0427a2` |
| observed main | 67790 | `64cfe84b72bfca87aba1d2376bd18ccef177bbb6ed8e16d3a3394ef41514cc20` |

Installed package Python files exactly match the cached wheel bytes. They match
the pinned archive source text after **CRLF to LF normalization only**, but their
raw hashes differ. This is recorded explicitly in
`installed-pin-byte-comparison.json`; it is not an assertion of Git installation
attestation. The cached wheel SHA256 is
`89723ca15a0c42b4818242bc5c9541a9611de623c7939dd78fc240605a7c6320`.
Its `direct_url.json` identifies a local wheel, without a VCS commit attestation.
Per-file source diffs are retained alongside this note.

## Paired extraction observations

`qualify_upstream_direct.py` used four separate processes with source overlays
on the same immutable captured batch2 core. It read **27 identical inert fixture
repositories** (10 routing fixtures and 17 independent Django oracle cases),
checked source origins and fixture hashes, and retained complete structured
analyzer output plus route projections. Installed and exact-pin projections
are identical for every observed role. Raw output is
`upstream-direct-{installed,pinned,candidate,main_observed}.json`; the comparison
is `upstream-direct-comparison.json`.

| Case | Installed/exact pin | Candidate and observed main |
| --- | --- | --- |
| FastAPI imported router, additive prefix and multiple mounts | No plugin mount extraction | Still unsupported |
| Flask imported blueprint and registration prefix override | No plugin mount extraction | Still unsupported |
| Imported Django `DetailView.as_view()` | `/detail/`, auth unknown | Same; this was already supported |
| Literal `re_path(r'^literal/$', ...)` | Raw `^literal/$` route | Normalized `/literal/` route |
| Django include mounted twice | Child and prefix surfaces remain separate | Correct `/v1/item/` and `/v2/item/` |
| Foreign `local_wrappers.login_required` | Auth unknown | **False required** |
| Local identity function named `login_not_required` | Auth unknown | **False anonymous** |
| Canonical Django `login_not_required` | Auth unknown | Anonymous; exclusion from a global login middleware alone does not prove absence of other auth |

The two foreign/local-wrapper errors survive the actual core priority merge with
the captured builtins. The plugin runs at priority10 and a lower-priority
unknown classification cannot erase the incorrect positive. This makes a
blanket pin update unsuitable for the current evidence-first task.

The scoped core alternative is to improve import/object binding and conservative
Django normalization while preserving the installed plugin pin. A later update
must first repair upstream wrapper binding, repeat the adversarial oracle and
qualify coexistence against the final core, then separately build and verify a
frozen artifact.

Framework URL semantics were checked against primary documentation:
[FastAPI larger applications](https://fastapi.tiangolo.com/tutorial/bigger-applications/)
supports additive include prefixes and multiple registrations;
[Flask register_blueprint](https://flask.palletsprojects.com/en/stable/api/#flask.Flask.register_blueprint)
allows registration options to override blueprint defaults. For example blueprint
default `/v1` plus registration `/api` yields `/api/users`, not `/api/v1/users`.

## Boundaries and incomplete attempts

This is direct extraction plus core merge qualification, **not a completed
pipeline scan, frozen/native acceptance, framework runtime test, or release
approval**. Baseline builtins were excluded only for the two FastAPI/Flask
multi-mount cases; plugin extraction was still run. The immutable batch2
`scanner._python_route_prefixes` loops on conflicting prefixes: a retained
90-second faulthandler trace in `upstream-baseline-multimount-timeout.txt`
identifies that loop. The source implementation
agent is replacing it with a bounded worklist. The initial full
`qualify_upstream_routes.py` attempt timed out after120seconds and is incomplete;
it is not a passing integration run. Its direct-extraction replacement avoids
the old multi-mount loop and states each skipped builtin role explicitly.

Commands:

```powershell
.venv/Scripts/python.exe -B docs/verification/windows-parity/WP039/sol-ultra-20261023-python/fetch_upstream_qualification.py
.venv/Scripts/python.exe -B docs/verification/windows-parity/WP039/sol-ultra-20261023-python/compare_upstream_sources.py
.venv/Scripts/python.exe -B docs/verification/windows-parity/WP039/sol-ultra-20261023-python/qualify_upstream_direct.py
```

The fetch used approved read-only network access. Source overlays were added by
`PYTHONPATH`; no package installation, build, pin mutation or provider call ran.
