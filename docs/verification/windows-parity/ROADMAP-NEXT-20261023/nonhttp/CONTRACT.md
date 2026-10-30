# WP044 shared-datastore extraction contract preparation

Status: **prepared contract, production extraction unavailable**. This is one
small WP044 preparation slice. WP044 is IN_PROGRESS. No new scanner detection,
runtime join, native mapping, package or release acceptance is claimed.

The current `DatabaseHint` contains a dialect, file, line, optional snippet and
analyzer provenance. `ScanResult.all_signals()` retains only the dialect in its
database properties. `config_scanner._extract_db_urls()` emits that lossy hint;
it does not preserve the non-secret qualified endpoint or operation. Existing
queue targets identify an implementation and a short queue name. These facts
cannot prove two repositories use the same deployment resource. Parsing their
snippet strings in a graph projector would breach the structured-evidence
boundary and could export credentials.

`src/attackmap/fleet_resource_identity.py` therefore provides a separate strict,
pure contract and fixture projection. No scanner, pipeline or fleet call invokes
it. Production fleet architecture still reports producer/consumer, shared
datastore and RPC/schema connectivity as `unanalysed`; the only production output
change is additive metadata advertising the prepared shared-datastore contract.

`shared-datastore-declaration.schema.json` is generated from `DatastoreDeclaration`.
The semantic validators in the Python model additionally enforce host, path and
identifier rules. JSON Schema alone is not the complete validation policy.

Each declaration requires:

- `schema_version: "1.0"` and an operation `read`, `write` or `read_write`.
- An identity with all six fields: `scope`, `protocol`, `host`, explicit integer
  `port`, `namespace`, `resource`. Protocol is one of `postgresql`, `mysql`,
  `mongodb`, `redis`. Scope identifies the specific deployment context; namespace
  identifies a database/keyspace, and resource identifies a relation, collection
  or key namespace. Extractors must supply literal meanings, not infer a scope
  from repository/service names. Namespace/resource/scope are case-sensitive.
- A source with an absolute local `repository_root`, repository-relative `file`,
  positive integer `line`, `observation_id` and `source_analyzer`. These are source
  references, not snippets. Observation identity is local to repository/analyzer.

Unknown fields are forbidden at every level. Credentials, URI/userinfo/path/query
syntax, placeholders, missing/defaulted ports, short hosts, loopback, unspecified,
link-local and multicast addresses are rejected. IPv6 zone identifiers and
IPv4-mapped loopback are rejected too. A host may be a literal nonlocal IP or
qualified DNS name. DNS case and a terminal dot are normalized; aliases, default
ports and DNS resolution are never inferred. Identifiers accept bounded ASCII
letters/digits/underscore/dot/hyphen and reject unresolved sentinel values and
known redaction matches. Callers must never place secrets in identity fields;
the contract accepts identifiers, not arbitrary evidence or connection strings.
The public `project_shared_datastores()` entry point sanitizes validation failure
to a generic `ValueError` with no input values, cause or exception context.
Direct Pydantic model construction hides values only in rendered error text;
Pydantic `ValidationError.errors()`/`.json()` still include input by default and
must not be logged without explicit removal. Use the projection entry point for
untrusted declarations. The prepared projection is bounded to 256 declarations
and 16 canonical repository roots before producing pairwise associations.

The projector matches the entire explicit identity. It emits a shared-resource
association only for two distinct canonical repository roots, with each side's
operations and its own source evidence. Associations are **undirected** and
`resolution: "declared"`; they never claim observed connectivity or directional
producer/consumer flow. More than two repositories yield deterministic pairwise
associations through the same resource identity, with no service path claim.
Duplicates are idempotent. Conflicting identity, operation or source location for
one source observation is quarantined under
`conflicting_declarations_for_source_observation`; it cannot participate in a
join. A qualified resource declared by only one repository is retained with
`no_other_repository_declares_resource`. An incomplete declaration is rejected,
rather than upgraded from an unknown identity to a candidate or observed edge.

Future extraction must establish these exact structured fields and operation
evidence, preserve source classification/provenance, prove non-secret output,
and attach records to the correct child snapshot. Only then should a separately
reviewed fleet adapter integrate the projection and qualify capability status.
Queue/broker, RPC, protobuf/OpenAPI, runtime connectivity, representative
production fleet, native mapping, clean-host/manual and macOS gates remain open.
