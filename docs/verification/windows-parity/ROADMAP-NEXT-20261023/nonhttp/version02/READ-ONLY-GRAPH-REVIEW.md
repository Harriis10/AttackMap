# Read-only graph source review after the non-HTTP correction

Reviewed the current source through CodeGraph, without editing native files or
running native tests/builds:

- `MainWindow.FleetGraph.cs`: `FleetSourceIsCurrent`,
  `VerifyFleetGraphSource`, `InspectFleetGraphSource`.
- `Fleet/FleetGraphEvidenceNavigation.cs`: `TryDescribe`,
  `BuildSourceRequest`, `TryValidate`, `TryCanonicalRoot`, `TryRelativeSource`.
- `SourceLocation.cs`: bounded live inspection, reparse rejection and final
  opened path containment/equality checks.

The handler binds the request to the current context and selection, verifies
summary/integrity/child-manifest hashes and the exact child snapshot, and repeats
verification before folder launch. Source inspection accepts structured relative
paths and verifies the final opened file. No additional source-launch or forged
request issue was identified in this static review. This is not runtime proof.

One identity concern was forwarded to the root integrator: at review time
`TryCanonicalRoot` used `Path.GetFullPath` without rejecting Win32 components
ending in a dot or space. Its duplicate-root check could therefore distinguish
`C:/repo` and `C:/repo.` although Win32 can treat them as the same repository.
The recommended focused fix is to reject those root components and add negative
navigation tests. SourceLocation's final opened-path comparison is a separate
gate and should fail closed for such an alias, but it does not establish the
helper's claimed root uniqueness. A native owner must implement/verify any fix;
this agent did not edit those files. Any subsequent native correction must be
documented by its owner separately from this dated review.
