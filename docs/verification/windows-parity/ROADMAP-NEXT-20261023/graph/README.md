# WP043 graph evidence and source-location navigation slice

23 October 2026. WP043 remains **IN_PROGRESS**. This directory records a bounded
native Fleet graph navigation change; it is not whole-task, manual, macOS or
release acceptance.

## Current behavior and change

The Fleet graph already emitted canonical underlying edge IDs and exposed raw
evidence JSON. It had no per-record source-location action or explicit evidence
return action; the interactive path did not display unavailable evidence refs.

`FleetGraphPane` now offers **Inspect selected evidence**, a record picker showing
source/target repository role, qualified repository ID and root, the original
relationship IDs and their captured direction/resolution/basis/confidence/proxy
semantics, and **Inspect source location**. Endpoint-only records are labelled
as such and do not become evidence of the relationship. Missing registry entries
remain visible as unavailable, and source files or lines that were not supplied
remain unknown. Raw record details remain inspectable.

`FleetGraphEvidenceNavigation` is a pure projection and request validator. It
recomputes allowed evidence refs from the selected canonical nodes/edges and edge
endpoints. A request includes the host GraphContext, canonical selection, evidence
ID, qualified repository ID, transport child ID, canonical local root, bounded
relative file reference, nullable supplied line and independent child snapshot
identity/time. Equal basenames never establish identity. Requests reject stale
contexts, unrelated records, unavailable/failed children, ambiguous root/child
joins, rooted or traversal paths, URI/stream syntax, controls, device names and
ambiguous Windows path segments. The helper does not touch the filesystem or open
any process, URL or file.

The pane exposes `OpenEvidenceSourceRequested`, `VerifySourceRequest(request)`
and `BackToSelection(request)`. Its `InspectSelectedEvidence(evidenceId)` method
is shared by the user-facing evidence buttons and focused native QA; the
`SelectedSourceRequest` property uses the same canonical helper as the source
button. Verification recomputes the canonical request and
also requires the same current pane selection. Back restores the selected record
and retains the current graph and underlying selected facts. The native shell
owner integrates the event with verified child/manifest identity and the existing
`SourceLocation.Inspect` flow, with a live-source warning and explicit back action.
This slice does not add a source editor or claim a captured source-text preview.

## Focused verification

Command:

```powershell
& ./.tools/dotnet/dotnet.exe run --project desktop/windows/FleetGraphNavigation.Tests/FleetGraphNavigation.Tests.csproj --configuration Release
```

**94 checks PASS.** [Machine proof](semantic-tests.json) records the exact command,
timestamps, output and SHA-256 of the helper, pane and tests at this checkpoint;
[console output](semantic-tests.log) retains the scope statement. The standalone
net8 console project links only `GraphModel.cs` and the pure navigation helper.
It does not compile WinUI/MSAGL, launch the GUI, open source, or call a provider.
The ordinary PATH `dotnet` first reported that no SDK was installed; the existing
repository-local SDK was used successfully without installing anything.
The pane's subsequent shared inspection API and six additional assertions for the
same literal file/line in distinct repositories are recorded separately in
[final source hashes](source-final.json). The six new assertions and a
same-semantics per-record edge lookup optimization await the
root-owned rerun. The root has now reported **100 checks PASS** for those sources;
its separate proof records that run. The original 94-check proof remains the
record of the earlier helper checkpoint; it is not a pass for subsequent source
changes. The WinUI pane awaits the root's combined product build.

The final review added rejection of trailing-dot/space and reserved/device root
components before `Path.GetFullPath`, sharing the same segment policy as relative
source references. Any unsafe root invalidates the graph-to-child join, including
an otherwise valid selected repository beside an unsafe alias of its root.
Twenty-eight additional root-alias/device/substitution assertions await the root's
final rerun (**128 total expected**). This last patch has no separate agent build;
the root owns the final source capture and product verification.

Covered semantics include both endpoint repositories with equal display names,
qualified root/transport/snapshot identity, aggregate original IDs and distinct
resolution, endpoint-only records, unknown and absent refs, nullable/invalid lines,
stale run/generation/report/revision, changed selections, tampered request fields,
duplicate roots/transport IDs, unavailable child/source, and hostile/outside-root
references. These synthetic checks do not prove a real source file was read.

## Integration and remaining gates

Product build, actual verified source-location dialog/back journey, visible native
review, both renderers, offline behavior, keyboard/Narrator, Light/Dark, two actual
window sizes and distribution remain the shell owner's checks. A modal over Fleet
can preserve graph projection/selection; it must revalidate the current request,
summary and child manifests before live-source inspection and again before an
explicit folder action. Existing source path inspection remains responsible for
filesystem/reparse and existence checks. Graph path validation alone is not proof
that live source still matches the captured snapshot.

The broader WP043 gates from the active roadmap remain open, including complete
finding/path journeys and representative 16-production-repository acceptance.
# Integrator result after agent freeze

Root subsequently ran the final helper source: **128 checks PASS**. The corrected
native inspector/source/back integration is in immutable source03 and passes
**94 actual native checks with16 completed test-repository children**. Compact
Light/Dark and large Light/Dark inspector frames were visually reviewed after
replacing the initial inline layout. See [final root handoff](../FINAL-HANDOFF.md),
[focused proof](../focused-verification.json), [runtime](../fleet-smoke-proof-04.json)
and [visual review](../visual-review-04.json). Earlier agent proof below remains
its own dated scope; it is not a claim that the agent ran the later root QA.

