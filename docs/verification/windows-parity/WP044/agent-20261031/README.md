# WP044 — explicit Kafka producer/consumer declarations — 2026-10-31

This is a bounded additive source contract. WP044 remains IN_PROGRESS. No
runtime delivery, production fleet, native/frozen mapping, UI, package or release
acceptance is claimed. Provider calls: **0**.

## Behavior

- The built-in config analyzer accepts the strict opt-in YAML/JSON
  [`attackmap_messaging` format](../../../../fleet-messaging-declarations.md).
  It reuses the bounded literal parser used for owner datastore assertions.
  A malformed messaging record rejects the entire messaging file without raw
  rejected values. Ordinary broker config and short queue names never qualify.
- Identity is exact scope, `kafka`, explicit transport, qualified broker host,
  port, cluster namespace and topic channel. There is no broker metadata lookup,
  bootstrap/alias expansion, inferred deployment identity or default port.
  AMQP routing, RPC, protobuf and OpenAPI remain unanalysed.
- Only complementary `publish`/`consume` declarations in different canonical
  repository roots can pair. The relationship is directed and **declared**;
  `direction_basis` explicitly identifies owner-declared direction. It is not
  an inferred/observed runtime link, HTTP contract, trust path or verified flow.
- Every endpoint retains its own positive source line, observation ID, analyzer
  provenance and evidence references. Unknown/invalid identities, secrets,
  conflicting source observations, ambiguous analyzer provenance and known
  non-production paths cannot create a relationship. Unmatched and ambiguous
  inputs retain source evidence. Duplicate/permuted input is deterministic.
- Global limits are 256 declarations and 16 canonical roots. Exceeding limits
  omits messaging projection while retaining other architecture. Partial,
  failed and unavailable children retain their status; a missing snapshot cannot
  supply the other half of a pair.

Changed implementation: `config_datastores.py`, `config_scanner.py`,
`fleet_resource_identity.py` and `fleet_architecture.py`. Added paired fixtures,
`test_config_messaging.py`, this qualification harness and format documentation.
Existing pre-task dirty changes were preserved.

## Executed verification

The valid compatibility run used the project Python and an isolated project-local
pytest basetemp with the Windows filesystem permission needed by pytest:

```text
.venv/Scripts/python.exe -B -m pytest tests/test_config_messaging.py tests/test_config_datastores.py tests/test_fleet_resource_identity.py tests/test_config_framework_datastores.py tests/test_fleet_architecture.py tests/test_config_scanner.py tests/test_desktop_graph.py tests/test_fleet.py -q -p no:cacheprovider --basetemp artifacts/wp044-messaging-20261031-tests-04 --junitxml artifacts/wp044-messaging-20261031-tests-04.xml
```

Result: **348 PASS, 25.20 s**. The final explicit fleet ambiguity case was then
added; the final messaging-only suite was **68 PASS, 1.15 s**, recorded in
`artifacts/wp044-messaging-20261031-messaging-final.xml`. These runs overlap and
must not be added together. No product source changed between those runs.

The focused tests include physical YAML/JSON extraction, indexed/walk parity,
merge identity, JSON serialization, stable IDs, reverse input order, exact
identity mismatches, same-operation/same-root negatives, unsafe/secret/malformed
input, bounded rejection, source conflicts and partial/failed snapshots. The
combined owner-datastore/Rails-candidate test removes only the additive messaging
projection and compares the entire remaining graph dictionary, including old
resource/evidence IDs. This proves contract-level separation. There was no
pre-agent full-dictionary byte capture; no historical whole-dictionary equality
claim is made.

Initial sandboxed test setup could not use Windows temporary directories and was
interrupted. A second run had 262 PASS and two setup/teardown errors because a
256 KB parameter value became a Windows environment variable via pytest's
automatic test ID. Explicit short parameter IDs fixed the harness; neither run
was used as the final qualification. The first physical harness run correctly
found source line 4, but its expected line was mistakenly 5; that assertion was
corrected and the full physical run repeated in a separate output folder.

`git diff --check` for scoped source/tests/docs passed.

## Physical source pipeline

Executed:

```text
.venv/Scripts/python.exe -B docs/verification/windows-parity/WP044/agent-20261031/qualify_messaging.py --output artifacts/wp044-messaging-20261031-final
```

[Qualification result](../../../../../artifacts/wp044-messaging-20261031-final/qualification.json):

- Sixteen physical **synthetic** repository roots, including two identical
  basenames, were scanned by the production source pipeline. Serial: 20.964 s;
  parallel (`max_workers=2`): 26.827 s. Facts in nodes, edges, evidence,
  unresolved records, coverage and limitations are identical across both runs.
- Eight valid declarations produce seven topic resources, one directed declared
  producer/consumer relationship and six unmatched endpoints. Exact graph:
  23 nodes, one edge and eight evidence records. Both relationship endpoints
  retain `config.json:4`, `source_analyzer=config`, their own observation IDs and
  their own repository evidence references.
- Thirteen repositories are completed and three partial. The partial cases are
  malformed, unqualified-short-host and unsupported-protocol declarations; they
  produce no relationship. Test/example declarations and ordinary broker
  settings also produce none.
- All 32 child manifests across the serial/parallel runs match parent digests;
  all referenced section checksums were verified. Each child process succeeded;
  partial analysis coverage is preserved separately from process exit status.
- `C:/tmp/juice-shop` paired with a declaration-free library completed a negative
  source integration in 42.851 s, with two additional verified child manifests.
  It produced no producer/consumer edge and retained unanalysed general
  messaging coverage. Reports are outside Juice Shop. No provider or remote
  analyzer installation was enabled.

Full graph and manifest paths are retained beneath
`artifacts/wp044-messaging-20261031-final/`.

## Remaining limits

Matching owner assertions can be incorrect or stale; the engine does not verify
the declaration against broker runtime or owner intent. Different endpoints for
the same Kafka cluster remain separate; group membership, partitions,
transactions, ordering and actual delivery are not modeled. A repository-level
declared edge does not assert a connected path through a concrete service or
broker. General messaging, representative production fleet, native/frozen/UI,
release and whole-WP044 acceptance remain open. The existing WP043 rendering
failure and V01–V03 gates are unchanged.
