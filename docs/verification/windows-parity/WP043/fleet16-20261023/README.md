# Fleet 16 — integrated graph checkpoint, 23 October 2026

WP043 and WP044 are **IN_PROGRESS**. This checkpoint implements a common graph
for up to 16 selected repositories in the existing Windows product. It does not
close the entire roadmap, manual acceptance, macOS or public release gates.

**Delivered:** [final handoff](FINAL-HANDOFF.md), [portable archive and checksum
proof](candidate/delivery.json), [packaged runtime](candidate/portable-runtime-02-proof.json).
Local Git code checkpoint `f5247d0`; full portable ZIP is in `C:\Projects`.
Own execution lease is released. No further roadmap tasks are started.

## Implemented behavior

The Python fleet summary now includes a versioned, evidence-backed architecture
object. Every selected root retains its own stable identity, including duplicate
folder names, library-only/disconnected repositories and failed children. HTTP
relationships retain observed/candidate distinctions and explicit proxy legs.
Queue, shared-datastore and RPC cross-repository joins remain **unanalysed**.

The existing Fleet page presents a local Cytoscape overview and a native
Canvas/MSAGL vector view, with repository grouping, collapse/expand, filters,
selection/evidence, complete JSON and entire-projection SVG export. A verified
root/transport-ID map fixes opening a child report when core slugs differ from
desktop GUIDs. The host binds run, generation, summary and child manifest hashes;
stale asynchronous completions cannot replace a newer graph. Partial results are
diagnostic and never become a successful current parent generation.

The page exposes a whole-run allowance (600 seconds by default) and 1–4 workers
(1 by default). Sixteen selected roots does not imply sixteen unrestricted
processes. Memory qualification remains unknown/count-only. This work made no
LM Studio or other AI/provider calls.

See the [contract and safeguards](../../../../fleet-architecture.md) and
[renderer decision](../../../../architecture/ADR-2026-10-23-fleet-graph-rendering.md).

## Evidence, with separate scopes

| Check | Result and boundary |
| --- | --- |
| [Core and real source scans](core/README.md) | 202 integrated Python tests PASS, including 29 architecture tests; actual 16-fixture scans with workers 1/2/4 have equal normalized graph facts; Juice Shop + 15 fixtures completed with all 16 child manifests and unchanged target trees. |
| [Integrated source broker](core/qualification/integrated-source-broker/runs.json) | Actual 2-root and 16-root runs; exact GUID/slug/root/manifest/graph identity mapping. Source runtime, not frozen/native acceptance. |
| [Controlled partial source broker](core/qualification/controlled-partial-source-broker/read-only-verification.json) | 15 completed children, one failed placeholder, hash-bound summary/index, no current parent, fixture fully restored and owned job empty. Two concurrently edited Python files prevent source-checkpoint qualification; the first harness assertion error and corrected read-only proof are both retained. |
| [Native model/layout](native/README.md) | 330 checks in 19 groups PASS, actual MSAGL geometry and cancellation; separate [98 pure fleet-binding checks](native/binding-tests/stdout.log) PASS ([execution and hashes](native/binding-tests/proof.json)). These do not prove manual GUI acceptance. |
| [Web candidate and bridge](web/README.md) | 14 Node tests and 33 bounded export metadata checks PASS; 17 actual browser observations on the same synthetic corpora. Browser timing is distinct from native-host runtime. |
| [PRI packaging fix](web/pri-indexing/README.md) | Installed SDK task A/B verification: web assets excluded from resource qualifier parsing, still explicitly copied to publish output. |
| [Independent candidate harness](qualify_candidate.py) | Captures every locked input, verifies the capture against an unchanged source interval, and builds both binaries from that capture. Native/frozen runtime results are recorded separately under `candidate/`. |

The synthetic oracle contains 16 repositories / 40 nodes / 34 edges / 88 evidence
records. The failure oracle retains all 16 identities with 39 nodes / 33 edges /
85 evidence records. They are not scan results. The core evidence bundle omits
full real scan reports and Juice Shop source contents. Candidate01's original
qualification reports remain in its retained output directory; later candidate
reports use the owned temporary workspace and retain compact durable proof here.

Native client-render previews are recorded under `native/captures/`. They were
created through the running preview's visible commands using Computer Use and
reviewed as images. They are explicitly **RenderTargetBitmap client renders,
not OS screenshots**. OS window capture timed out; manual/Narrator/200% text
acceptance remains open. Dark contrast and a shared WinUI PathGeometry rendering
defect were corrected before the final preview. The long native rows of
disconnected groups motivate the more compact interactive default.

## Candidate provenance

**Final combined source checkpoint 02:** after the user-authorized coordination,
the analyzer lane confirmed [SOURCE FROZEN](../../WP039/sol-ultra-20261023-python/BUILD-HANDOFF.md).
Root captured the current shared checkout after the responsive Fleet correction.
Both new binaries were built from that exact unchanged capture. The self-contained
native publish and new frozen engine passed, followed by **75 native workflow
checks**, all 16 child manifests, child report/back identity, pending vector
navigation regression and both renderer contexts. Full native and engine payload
hashes were identical before/after the actual runtime job, which exited zero with
verified cleanup. Juice Shop scan plus compare passed separately. See
[candidate02 summary](candidate/candidate02-summary.json),
[runtime payload binding](candidate/native-fleet-smoke-02-binding.json),
[native smoke](candidate/native-fleet-smoke-02-proof.json),
[frozen runtime](candidate/frozen-runtime-02/engine-verification.json),
[final closure audit](web/pri-indexing/finalpublish-proof02.json) and
[catalog/ledger non-regression](candidate/final-catalog-ledger-proof02.json).

All eight candidate02 client renders were visually reviewed. The compact command
bar now leaves a graph area visible, with overflow exports and accessible full
interpretation text. Dense native Fit remains small and requires zoom/filter/list
or full SVG; compact size is not universal readability acceptance. WebView2
composition pixels are absent from these client renders. Independent Sky OS
capture, including a foreground retry, timed out. Interactive runtime/page/context
acknowledgment passed, while actual hosted web appearance, Narrator and 200% text
remain open. The earlier layout failure/capture evidence is retained below.

The live checkout is shared with an actively edited analyzer task. The first
freeze (`candidate/engine-final/`) correctly rejected changed native sources;
its process exited 1 with verified owned-tree cleanup. It is not a valid build.

Candidate01 subsequently completed an actual self-contained native publish
(zero warnings), a new frozen engine with 21 effective analyzers, Juice Shop
broker/compare qualification, and the real native 16-fixture scan. All child
manifests, root/transport/snapshot bindings, child navigation/back, vector layout
and current interactive page acknowledgment passed. See
[runtime summary](candidate/candidate01-summary.json),
[native smoke](candidate/native-fleet-smoke-01-proof.json),
[frozen qualification](candidate/frozen-runtime-01/engine-verification.json) and
[exact published payload audit](web/pri-indexing/finalpublish-proof.json).
The caller-owned native job exited zero with verified cleanup after root closed
the kept-open window. AI/provider calls remained zero.

The eight client renders are preserved under
`candidate/native-ui/candidate01-captures/`. Their visual review found that
vertical buttons pushed the compact vector plot below the fold. Candidate01 is
therefore **runtime PASS, compact visual correction required**, not final visual
acceptance. Interactive WebView2 composition pixels are absent from these client
renders; the acknowledgment proves the current runtime/message context, not its
appearance. A new independent OS screenshot attempt again timed out.

The independent candidate uses `.tmp/wp043-fleet16-20261023/candidate-source-01`
and the exact input inventory in `candidate/source-capture-01.json`. Later live
checkout changes are excluded. Both the native publish and frozen engine must
match this same captured source; that is an explicit source checkpoint, not a
claim that the live checkout stayed unchanged throughout the build.

## Remaining gates

- Qualified non-HTTP cross-repository producer/consumer and datastore identity;
  RPC/schema support remains explicitly unanalysed.
- Representative acceptance with 16 real production repositories. The available
  test corpus is 16 generated repository folders, plus Juice Shop in the mixed
  run, as authorized by the user.
- Full native partial-result and edge → both-side evidence → source → back/export
  journeys, keyboard/Narrator, 200% text and independent OS appearance acceptance.
- Actual network-disabled/clean-host WebView2 availability/distribution,
  installation lifecycle, signatures and the relevant release/export gates.
- Independent macOS implementation and evidence. No macOS parity is inferred.

Protective ceilings are documented, not throughput promises: native input up to
10,000 nodes / 30,000 edges, displayed native detail up to 1,000 / 3,000 with a
cooperative 15-second layout allowance; browser detail is similarly bounded and
large fCoSE calls use an explicit grouped fallback. The native 1,000-node expanded
benchmark reached its deadline; no responsive full-detail claim is made.
