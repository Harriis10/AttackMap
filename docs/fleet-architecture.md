# Fleet architecture contract 1.0

`fleet-summary.json.fleet_architecture` is an additive core-owned object. Existing
fleet summary fields and Mermaid/text outputs remain available. It contains
`schema_version: "1.0"`, `kind: "fleet_architecture"`, `repositories`, `nodes`,
`edges`, `evidence`, `coverage`, and `limitations`.

Repository IDs derive from canonical lexical roots, independently of display
names and input order. Core slugs, desktop request GUIDs, and repository IDs are
separate identities. Every requested root has a repository group, including a
failed child. A node's `repo_id` references the qualified repository ID; a
repository's optional `repo_id` retains its core slug.

Nodes have stable IDs, kind, label, parent and evidence references. Edges carry
stable IDs, source/target, kind, boolean `directed`, resolution and evidence
references. References are IDs in the top-level evidence registry. Records retain
available analyzer/observation/source locations. Unknown or invalid line numbers
stay null. Source snippets and secret values are not exported. Local service
ownership distinguishes analyzer hints, layout inference and repository-only
association.

Cross-repository HTTP relationships reuse the core contract linker. Candidate
relationships remain candidates. An observed declared-proxy seam has an explicit
intermediary and two legs; it never becomes a direct service edge. Matching queue
names or database dialects does not establish shared infrastructure. General
cross-repository producer/consumer, datastore and RPC/schema relationships remain
**unanalysed**. Captured data is not complete discovery or runtime reachability.

The Windows host verifies the summary and manifest or broker diagnostic index,
then binds exact roots to transport children. Child snapshot IDs, capture times
and manifest hashes come from separately verified child manifests. The enclosing
run, generation, summary hash and selection revision are host-owned context.
Independent child snapshots do not constitute an atomic fleet snapshot.

The Windows evidence inspector resolves a selected presentation edge back to its
original edge IDs and registry records, including records from both endpoint
repositories. Endpoint-only records are labelled separately and do not establish
the relationship. Unavailable references and unknown line numbers remain visible.
Source inspection verifies the current summary/index and exact child manifest,
repository root and snapshot before checking a bounded relative path with the
existing live-file inspector. The modal offers an explicit folder action and
returns to the same graph selection. A live-file check does not verify connectivity
or imply that the current file equals captured source; no editor is launched.

Collapse/expand is a reversible presentation projection. Aggregates retain every
underlying edge ID and separate direction, resolution, relationship kind and
proxy semantics. Hidden and filtered relationships have explicit counts. An
overview path A→B→C does not prove a continuous path between concrete services in
B. JSON export retains the complete captured model and current view/context
metadata; SVG exports the entire selected projection, including offscreen items,
with an inert vector representation and coverage metadata.

## Windows implementation and bounds

The current product integration offers an interactive Cytoscape overview and a
native Canvas/MSAGL 1.2.1 vector diagram. Both consume the same verified immutable
model. Repository groups, text/list alternatives, selection/evidence, fit, zoom,
scroll, collapse and filters preserve canonical IDs. Native search filters its
list, as its caption states. The vector view supplies entire-diagram SVG export;
both views supply the complete JSON model. The offline web assets and reproducible
comparison harness are in `desktop/windows/GraphExplorer.Web` and
`tools/graph-explorer`.

The interactive host requires an available WebView2 runtime, verifies packaged
asset hashes, and maps only an allowlisted local HTTPS origin. External resources,
navigation, popups, downloads, permissions and external URI schemes are denied.
Messages must match the current page session and host-owned context and contain
known canonical IDs. JavaScript cannot supply a filesystem path or command.
Failure to initialize the runtime switches to the native vector view. No runtime
installation or CDN download is performed. Clean-host runtime/distribution and
manual accessibility acceptance remain separate gates. Native hosted PNG export
is visibly unavailable; SVG is available in the vector view.

Reader limits are 16 MiB, 16 repositories, 10,000 nodes, 30,000 edges, 100,000
evidence records and depth 48. Native layout is capped at 1,000 displayed nodes
and 3,000 displayed edges, with a cooperative 15-second allowance. These ceilings
are safeguards, not qualified performance promises. Oversized or cancelled
layouts retain the native list and canonical model. The same-input benchmark
reached its deadline for 1,000-node expanded native detail; large fleets should
use a collapsed or filtered projection. No claim of responsive 10,000-node
native detail is made.

Fleet UI exposes the whole-run allowance (default 600 seconds) and worker count
(default 1, supported 1–4). Sixteen selected roots does not mean sixteen
unrestricted processes. Existing admission reports memory qualification as
unknown and no OS-enforced memory cap. AI is not enabled by graph exploration.

A partial broker index may include
`fleet_summary: {path: "fleet-summary.json", sha256: "…"}`. This binds diagnostic
bytes after bounded, regular-file/reparse checks. It never authorizes publishing
the failed parent as current. Native partial display verifies the index hash,
child identities/manifests, summary hash and exact requested roots again.

[Implementation and scoped verification](verification/windows-parity/WP043/fleet16-20261023/README.md)
separates synthetic fixtures, source scans, renderer checks, native runtime and
release/manual gates. WP043 and WP044 acceptance is tracked by the active roadmap.

## Prepared shared-datastore extraction contract

`attackmap.fleet_resource_identity.project_shared_datastores` prepares an additive
contract for future analyzers. Existing scanners do not emit it, and the current
fleet pipeline does not call this projection. Production datastore, queue and RPC
coverage remains **unanalysed**. Coverage metadata advertises this preparation
without changing a production relationship or upgrading its resolution.

Each declaration requires an explicit operation (`read`, `write`, `read_write`),
the exact six-part identity (`scope`, `protocol`, `host`, explicit `port`,
`namespace`, `resource`), and repository-relative source evidence with a known
positive line, analyzer and observation ID. Every identity field must match.
Protocols in this prepared contract are PostgreSQL, MySQL, MongoDB and Redis;
this list is not a qualified analyzer-support claim. Credentials, connection
strings, raw snippets, templated/unknown identities and extra fields are rejected.
Loopback, link-local, multicast and limited-broadcast hosts cannot establish
shared identity. The public projection sanitizes validation failures; direct
Pydantic structured errors require the separate logging precautions in the
[contract and paired fixtures](verification/windows-parity/ROADMAP-NEXT-20261023/nonhttp/CONTRACT.md).

The bounded pure projection accepts at most 256 declarations and 16 canonical
repository roots. Duplicate source-observation conflicts are quarantined.
An association is undirected and explicitly `declared`, retains evidence from
both repositories, and proves neither a producer/consumer flow nor runtime
connectivity. Integrating a real extractor, snapshot binding and independently
verified repository cases is a separate required step.
