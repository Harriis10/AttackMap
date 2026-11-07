# Explicit datastore declarations

The built-in `config` analyzer accepts an **opt-in AttackMap declaration format**
in YAML and JSON application config files. This is an explicit static assertion
supplied by the repository owner, not automatic ecosystem inference or a runtime
connection check. Ordinary connection URLs, dialect hints, Compose short names,
environment substitutions and generic `datastores` settings do not qualify.

```yaml
attackmap_datastores:
  schema_version: "1.0"
  declarations:
    - identity:
        scope: production-eu
        protocol: postgresql
        host: db.example.internal
        port: 5432
        namespace: public
        resource: orders
      operation: read
```

The JSON form has exactly the same keys, nesting and types. Each declaration
contains exactly `identity` and `operation`. The envelope contains exactly
`schema_version` and `declarations`. Other top-level application settings are
allowed. The built-in config analyzer must be selected or selected automatically;
this feature adds no analyzer, installer or network dependency.

All six identity fields are required and must be explicit non-secret literals.
`scope` identifies the deployment/environment, `namespace` identifies the database
namespace, and `resource` identifies the specific table, collection or other
resource being declared. The owner must choose the same meanings on both sides;
the analyzer does not derive them. Scope, namespace and resource are case-sensitive.
Host names are canonicalized to lowercase and a final dot is removed.

Supported protocols are `postgresql`, `mysql`, `mongodb` and `redis`. A host must
be a qualified DNS name or a non-local unicast IP address. Short names, localhost,
loopback, unspecified, multicast and link-local addresses are rejected. Port is
an integer from 1 through 65535; no default port is supplied. `operation` is
`read`, `write` or `read_write`, and records a declaration, not verified access.
No credentials, connection strings, substitutions or extra declaration fields
are accepted. Keep credentials in the application's separate secret mechanism.

The extractor uses the declaration object's exact starting source line. It
preserves file, line, observation identity and the `config` analyzer origin through
the normal merge, worker serialization and fleet projection. It copies only
validated fields, using a fixed evidence description rather than raw config text.
Path conventions cannot prove production ownership: admitted paths retain
`unknown` role. Declarations under `tests`, `__tests__`, `fixtures`, `mocks`,
`examples` and `generated` directories are not emitted.

YAML aliases, merge keys, duplicate keys, custom tags in declarations, multiple
documents, malformed input and unknown versions are rejected. JSON must also be
valid JSON. The whole declaration file is rejected if any declaration is invalid;
no valid-looking partial set is emitted. Rejection adds a generic limitation,
without rejected values or parser error details. Extraction is bounded to
256,000 UTF-8 bytes, 8,192 parser events, depth 32 and 256 declarations per file.
The fleet consumer separately enforces its existing global bounds: 256 admitted
declarations and 16 repositories. Other analysis remains available on rejection.
TOML, INI, `.env`, and declarations nested under other application keys are not
supported by this extraction format.

Two repositories associate only when all six qualified identity fields match.
Fleet output then includes an undirected `shared_datastore` edge with
`resolution: declared`, endpoint-declared operations, a qualified resource and
source evidence from both repositories. A single declaration remains unmatched;
different scopes, ports, protocols, namespaces or resources never match. No
directed flow, runtime connectivity, exploit reachability or production maturity
is established. A separate [explicit Kafka owner declaration contract](fleet-messaging-declarations.md)
can record declared producer/consumer direction; RPC/schema and general messaging
discovery remain unanalysed.

The physical 16-repository verification corpus is synthetic, even though the
production pipeline scans its files and creates real child manifests. It does
not replace representative production fleet, native mapping, visual, package or
clean-host acceptance gates.
