# Fleet graph rendering — 23 October 2026

Status: implemented development choice; whole-task, clean-host and manual release
acceptance remain open in WP043/WP044.

## Decision

Use the core's versioned fleet architecture object for both surfaces. The default
interactive overview uses pinned local Cytoscape.js 3.34.4 and optional bounded
fCoSE 2.2.0. A native Canvas/MSAGL 1.2.1 vector view provides native controls, a
text/list alternative and entire-projection SVG export. Native evidence and saved
child report navigation resolve only IDs/roots from verified host artifacts.
The native vector view remains available if WebView2 initialization fails.

The shared core supplies facts and evidence. Renderers perform reversible
presentation grouping, never graph extraction, scoring or service identity
inference. Both retain canonical facts, candidate distinctions, explicit proxy
legs and the warning that overview paths do not establish service reachability.

## Evidence behind the choice

Both candidates received the same core oracle and the same SHA-bound 16-group
stress corpora. [Native measurements](../verification/windows-parity/WP043/fleet16-20261023/native/same-input-benchmark.jsonl)
and [actual browser measurements](../verification/windows-parity/WP043/fleet16-20261023/web/browser-measurements-01.json)
have separate timing scopes; JavaScript heap and cumulative native working set
are not directly comparable memory measurements.

| Same captured corpus | Native MSAGL layout | Browser candidate |
| --- | --- | --- |
| 1000 nodes / 3000 edges, 18 collapsed visible nodes / 762 edge groups | About 8.0 s layout | About 0.54 s load through two animation frames; this includes different work |
| Same corpus expanded | 15 s cooperative deadline, worker awaited | About 2.65 s expansion through two frames; grouped geometry; large fCoSE requests explicitly fall back |
| 10000 nodes / 30000 edges, collapsed | 18 nodes / 100 aggregates, about 140 ms layout | About 0.61 s load through two frames |
| Same stress expanded | Refused by explicit display limit | Bounded 1000-node view; omitted counts visible, full canonical model retained |

These are fixture observations, not p95/SLA or production-scale qualification.
Grouped browser geometry is not a successful fCoSE layout at 1000 nodes. Native
layout has a different algorithm and geometry, so these figures do not establish
equivalent layout quality. Native visual inspection also showed long rows of
disconnected repositories when fitting the whole oracle; zoom and the native
list remain useful, while the interactive overview gives a more compact view.

## Dependencies and offline behavior

MSAGL 1.2.1 is MIT; its NuGet package SHA-256 is
`11e3323a7aa654033379b295d2839830f815333c4f27c18ea64107a7a61e9f43`.
The .NET 8 test host executed actual layouts against its .NET Standard assembly,
including its System.Text.Json assembly reference. Package notices ship with the
native payload.

The web closure is Cytoscape 3.34.4, fCoSE 2.2.0, cose-base 2.2.0 and layout-base
2.0.1, all MIT. Official registry tarball integrity, deployed files and license
hashes are retained in the vendor and asset manifests. No runtime Node, npm,
network CDN, external expand/collapse plugin or Archify skill is required.
WebView2 SDK assemblies come from the existing Windows App SDK dependency;
availability of its actual runtime is checked at initialization and is a separate
portable clean-host gate.

## Supported safeguards and remaining acceptance

Native reads are bounded to 16 MiB / 16 repositories / 10000 nodes / 30000 edges;
layout is bounded to 1000 visible nodes / 3000 edges and a cooperative 15-second
allowance. Browser detail defaults to 1000 visible nodes / 3000 edge groups;
fCoSE is limited to 350 visible nodes / 1000 groups. Larger models retain their
canonical JSON and expose filtered/bounded counts. These are protective ceilings,
not performance promises.

Full JSON exports include context and coverage. Native SVG exports the entire
selected projection as inert vector content, including offscreen elements and
view metadata. Browser host JSON uses verified canonical facts and an explicitly
untrusted, allowlisted UI-view metadata section. Hosted PNG is disabled until a
separate native export integration is qualified.

Real source scans have covered 16 owned fixture directories and Juice Shop with
15 fixtures, with unchanged target trees. This does not substitute for 16 real
production repositories, non-HTTP cross-repository extraction, manual Narrator
or 200% text acceptance, macOS parity, or a clean Windows portable installation.
