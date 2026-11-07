# Analyzer selection profiles

WP042 introduces offline selection profiles with schema `1.0`. Each named
profile has its own version and a fixed module membership. A selection records
its qualified identity, for example `node-atproto@1.0`. Both `node-atproto` and
`node-atproto@1.0` resolve to this revision; unknown names and versions fail.
The profile version identifies selection policy, not plugin package versions,
upstream commits, extraction quality, applicability, or a completed scan.

| Profile, version 1.0 | Expanded module membership | Known experimental layers at this revision |
| --- | --- | --- |
| `automatic` | The selected engine's installed default-enabled analyzers | Depends on effective installed metadata |
| `node-atproto` | `javascript-web`, `node-service`, `config`, `atproto`, `default`, `node-atproto` | `node-service`, `atproto`, `node-atproto` |
| `php-laminas-omeka` | `php-web`, `config`, `php-laminas`, `default`, `omeka-s` | `php-laminas`, `omeka-s` |
| `python` | `python`, `python-web`, `config`, `python-service`, `default` | `python-service` |

Named profiles retain the relevant broad language layer, application config,
fallback and local ecosystem overlays. For example, `default` deliberately
does not scan suffixes already owned by the broad web analyzers, so selecting
only a plugin plus `default` would lose that broad language coverage. Profiles
target the listed ecosystem; Automatic remains appropriate for the complete
installed default-enabled universe in a mixed-language repository.

Automatic preserves the existing runner input `analyzers=None`. It neither
hard-codes today's installed module list nor enables opt-in modules. Named
profiles make an explicit selection, including any listed opt-in experimental
layers. Every selected analyzer still passes through its existing `detect()`
gate. Runtime order remains `(metadata.priority, name)`, independent of the
profile's displayed membership order. Existing merge precedence is preserved.
Bare `-m/--module` retains its exact-list meaning and receives no implicit bases.

A profile and nonempty explicit module list conflict. All required names must
exist in the supplied effective installed inventory before selection succeeds.
There is no reduced-profile fallback, optional-layer substitution, plugin
discovery, network request, installation or scan inside the profile module.
CLI integration also rejects `--install-missing` with any profile. With the
nine built-ins alone, PHP resolves, Node/ATProto reports missing `node-service`
and `atproto`, and Python reports missing `python`. Availability must be
recomputed for the selected engine; a richer frozen inventory cannot stand in
for source-environment availability or a different executable.

Inspect the current engine and select a profile through the CLI:

```powershell
attackmap modules --profiles-json
attackmap analyze C:\path\to\repository --analyzer-profile php-laminas-omeka@1.0
```

`modules --json` keeps its existing installed-module array. The additive
`modules --catalog-json` and `modules --profiles-json` formats include engine
identity and cannot be combined with each other or `--json`.

`analyzer_profile_inventory(installed_metadata)` serializes deterministic
definitions and availability. `module_names` is fixed membership;
`expanded_module_names` lists that membership, including missing requirements,
or the dynamic Automatic candidates. `missing_module_names` and `available`
make an incomplete profile explicit. Static `experimental_module_names`
records the profile revision's known experimental layers;
`installed_experimental_module_names` and `opt_in_module_names` use effective
installed metadata. Neither definition nor candidate membership claims that
an analyzer matched, ran, succeeded, or passed a maturity gate.

`resolve_analyzer_profile(name, installed_metadata, explicit_modules=None)`
returns an immutable `AnalyzerProfileSelection`. Its `module_names` can be
passed to the existing explicit selector, while `None` preserves Automatic.
`candidate_module_names` reflects effective runtime priority order before
detection. `profile_version`, `qualified_name`, effective experimental and
opt-in flags, and `as_dict()` support inspection. Duplicate supplied module
names fail: callers must provide the registry's effective deduplicated
inventory, not unresolved builtin/plugin collisions. The resolver does not
cache inventories across engine changes.

The Windows picker consumes profiles from the selected engine's capability
document. A named selection persists its qualified identity and expanded module
set. Missing modules, a removed version, or changed membership for that version
block the next scan until the user chooses a new profile or explicitly switches
to Custom/Automatic. Editing module selection switches to Custom. Changing the
engine invalidates discovery while preserving saved preferences.

Desktop single-run schema **1.5** carries `options.analyzer_profile` as a
qualified name, with an empty `modules` list. Schemas 1.0–1.3 reject this option;
schema 1.4 remains reserved for fleet requests. Existing requests without a
profile retain their prior wire version and behavior. Resolution is offline in
the shared scan service; CLI fleet child processes retain the qualified profile
flag. Profile identity is recorded in `scan.analyzer_run_ledger.profile_id` and
the corresponding run-manifest ledger. Automatic UI selection keeps the legacy
default policy and does not require schema 1.5.

The native view separately presents current installed implementation provenance
and observations from the selected report's ledger. A saved report never claims
that today's selected engine executed it. WP006 manual acceptance, release
qualification, WP039 maturity and wider WP042 completion remain independent of
profile selection. See the current WP042 verification checkpoint for executed
source, frozen and native evidence.
