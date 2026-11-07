# Explicit Kafka topic declarations

The built-in `config` analyzer accepts an opt-in YAML/JSON owner assertion:

```yaml
attackmap_messaging:
  schema_version: "1.0"
  declarations:
    - identity:
        scope: production-eu
        protocol: kafka
        transport: tls
        host: broker.example.internal
        port: 9093
        namespace: orders-cluster
        channel: orders.created
      operation: publish
```

Another repository declares the same identity and `operation: consume`. All
seven identity fields must match. This creates a `producer_consumer` relationship
with `directed: true`, `resolution: declared` and
`direction_basis: declared_publish_to_consume`. Direction records the owners'
stated operations. It does not verify publishing, consuming, delivery, active
subscriptions, ordering, runtime reachability or an end-to-end data flow. It
does not enter the HTTP contract linker or create a cross-boundary trust path.

Only Kafka topic declarations are supported. The namespace is an explicit
owner-supplied cluster identifier, the channel is an explicit topic identifier,
and the host/port is the exact broker endpoint asserted on both sides. Scope is
the owner-supplied deployment context. The analyzer does not inspect broker
metadata, resolve bootstrap lists, verify cluster IDs, expand aliases, infer
consumer groups or model delivery between group members. Different broker
endpoints within the same actual cluster remain separate identities. This
conservative contract can miss real relationships.

`protocol` must be `kafka`; `transport` must be `tls` or `plaintext`. This is an
identity distinction, not a verified transport security control. Scope,
namespace and channel are case-sensitive non-secret identifiers matching
`[A-Za-z0-9][A-Za-z0-9_.-]{0,127}`. Unknown, unresolved and redacted placeholders
are rejected. The host must be a qualified DNS name or a non-local unicast IP;
DNS case and a final dot are canonicalized. Short names, localhost, loopback,
link-local, multicast, substitutions, URLs and credentials are rejected. Port
must be an explicit integer from 1 to 65535; no default is inferred.

The envelope contains exactly `schema_version` and `declarations`. A declaration
contains exactly `identity` and `operation`; the identity contains exactly the
seven shown fields. Operation is exactly `publish` or `consume`. To assert both,
use two declarations. Application settings may coexist at the top level. Other
formats, nested markers, ordinary Kafka config, queue names, AMQP exchange/queue
settings, RPC, protobuf and OpenAPI never become relationships through this
contract. AMQP routing requires a separate qualified contract.

The strict parser is shared with the datastore declaration format. It rejects
aliases, duplicate declaration keys, merge keys, custom declaration tags,
multiple YAML documents, malformed JSON/YAML, unsupported versions and invalid
records. A malformed record rejects that entire messaging declaration file;
rejected values and parser errors are not retained. Bounds are 256,000 UTF-8
bytes, 8,192 parser events, depth 32 and 256 records per file. Known test,
fixture, mock, example and generated paths are not emitted. Other paths retain
`source_role: unknown`; a path does not prove production ownership.

Normalized protocol signals have `producer_consumer_declaration: "1.0"`, a
literal operation and qualified identity properties. The consumer requires a
static extraction, a positive source line, an observation ID and one unambiguous
analyzer origin. Conflicting observations and known non-production roles cannot
create a relationship. Each endpoint retains its own source evidence. Source
locations and metadata follow the existing merge and snapshot pipeline; raw
config and snippets are not exported into the fleet graph.

The pure projection accepts at most 256 declarations and 16 canonical repository
roots. Duplicate observations are idempotent. Conflicting identity, operation
or source location for one repository/analyzer/observation is quarantined as
ambiguous. Pairing requires complementary operations in distinct canonical
roots. Multiple declarations within one repository do not establish a fleet
link. Each matching publisher/consumer repository pair gets a stable relation
ID; reverse declarations, if supplied independently, create a separate declared
direction. Topic resources, evidence and relations have separate ID domains
from datastore resources and ordinary protocol hints.

When messaging declarations are admitted or rejected by the fleet consumer,
`coverage.protocols.producer_consumer` reports bounded support, counts and
projection omission. `producer_consumer_unresolved` retains unmatched and
ambiguous evidence. Exceeding fleet bounds omits that projection while retaining
other architecture. Failed/unavailable children cannot supply missing evidence;
partial children retain their status even when their available declaration is
usable. Without messaging input, the pre-existing fleet/datastore output stays
unchanged and general producer/consumer coverage stays unanalysed.

This source contract has no new UI or frozen/native mapping qualification.
Synthetic physical multi-repository tests do not establish representative
production fleet, delivery, release or whole-WP044 acceptance.
