# WP042 functionality and acceptance audit — 2026-10-23

Read-only audit against active WP042 task lines637–648, current source and the
dated batch2 evidence. This is not an update of the shared active plan and does
not inherit release acceptance from a prior binary.

## Implemented behavior

The selected executable supplies effective catalog/profile data. Native stores
the qualified profile identity plus displayed membership; missing/stale
expansion blocks a saved named profile rather than silently changing selection.
Custom and Automatic are explicit user choices. Catalog discovery remains
separate from repository applicability and report-bound execution history.

The batch2 ledger records actual supplied/registered implementation identity,
selection/applicability/execution and safe error/skip reasons, resolves once per
capture and is copied identically into report and run manifest. Its old analyzer
list remains selected-only. The current scoped1.1 extension adds measured
detect/analysis wall durations, extraction counts before merge, bounded ordered
lifecycle and safe live stage labels, while accepting old1.0 ledgers. Native
parser and display fields match the exact additive contract; null is not
converted to success/zero. An isolated request is visibly distinct from proven
analyzer start, and the displayed timing is labelled analysis/host wait.

`ledger-handoff.md` and `ledger-live-stable.xml` prove focused source behavior;
they do not prove new binary/native acceptance. The current native1.1 parser
supports stage `detect|selection|analysis`, all ten producer states including
`requested`, safe error names, finite nonnegative timings, five exact counts
and per-entry monotonic event order. The1.0 test data retained in native tests
is an intentional legacy-loading control.

## Concrete remaining functionality found

At audit time `AnalyzerSelectionModel.ApplyCatalog` processes only `effective`
and `shadowed` candidates and continues past other statuses. As a result native
does not display the catalog's per-candidate load/init/metadata/trusted-policy
failure records; a saved selection may appear merely missing. This differs
from absence and was a real WP042 UI gap. Root authorized the focused native
model/view fix after this audit: source is now released with164 captured console
checks PASS; see `native-discovery-handoff.md` and the exact source hashes.
The new separate bounded discovery issue section closes this functionality gap
at source level. Final current native build/visual acceptance remains root-owned.
Reasons remain tied to discovery, without repository applicability or execution
claims for a candidate that could not load.

Live progress is carried by existing stage labels. It is not a new typed
streaming ledger protocol. Final structured per-analyzer events/counts are
report-bound. Interrupted process termination before a report is published does
not synthesize a completed ledger. These are explicit scope boundaries, not a
claim of live per-analyzer report publication.

## Acceptance still requiring evidence

1. Seal the final current source bytes, fresh frozen executable and its external
   internal payload; inspect actual inventories and profile availability from
   that executable. A prior executable hash is not evidence for newly edited
   Python sources or bundled external files.
2. Run the new core/official-plugin coexistence fixtures and a real source/frozen
   scan, compare report and manifest ledger, and retain Juice Shop
   non-regression. The27 immutable upstream qualification fixtures already
   establish a specific Python pin no-go and a WP039 local alternative; they do
   not establish final new-core behavior or a complete framework runtime.
3. Produce the current package inventory/SBOM and source/pin declarations. Wheel
   origin and normalized source correspondence are separate from immutable Git
   attestation; runtime content_verified remains false unless actually proven.
4. Show and visually review the final changed native control in Light/Dark and
   two sizes, including readable populated timing/count/lifecycle details,
   failure/skip/missing states and discovery failures. A compiled model or older
   batch2 screenshot does not validate the new appearance.
5. Retain manual keyboard/Narrator/UX and C27/C38/representative FP/FN maturity
   gates according to the active plan. Windows evidence does not prove macOS.

The immutable upstream qualification now supports the task's explicit no-go
alternative: candidate/current-observed Python commits improve some Django URL
composition but falsely upgrade foreign wrapper authentication and leave
FastAPI/Flask mounts unsupported. See `upstream-qualification.md`; no pin change
is proposed. Remaining ecosystem maturity is owned by WP031/WP039, not replaced
by a discovery catalog or the ledger's execution_complete flag.
