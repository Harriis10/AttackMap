# Compact saved-AI presentation

The full Reports AI component now presents selected generation, a compact
mode/state/provider/backend/model/usage/evidence summary, then the full supplied
narrative. It no longer repeats raw provider configuration, allowance or
consensus JSON above the output. Complete unchanged Notice and Metadata remain
selectable in one default-collapsed "Evidence checks and complete metadata"
Expander below the narrative.

Unknown usage and token counts remain unknown, distinct from reported zero.
Reference validity and claim support are separate visible fields; valid
references do not confirm claims. Partial states, deterministic fallback, jury
abstentions and failed passes remain visible. Model identity and selected
generation remain supplied values, and complete technical data stays available.
Long summary scalar fields are bounded; prose and metadata are not truncated by
this presentation change.

AiArtifactPage's six positional fields and original completion semantics remain
unchanged; Summary is an additional non-positional property. The workspace's
captured-manifest reads, checksums, Stop/revision guards and asynchronous
selection APIs are unchanged. No provider request, artifact regeneration, source
edit or checksum rewrite is performed when displaying a saved section.

Focused verification: AiArtifacts.Tests passed all 61 checks, including the
45 generation/lifecycle checks and 16 compact-summary assertions. New assertions
cover unknown vs zero usage, validity vs unassessed support, jury/failed-pass and
fallback disclosure, bounded complex-provider summaries, complete original
technical data/narrative preservation, and unavailable states. The actual WinUI
library build at `.tmp/AiArtifacts.BuildCheck` linked the exact production files
and completed with exit 0 and zero warnings/errors in 71.54 seconds using local
SDK 8.0.426 and cached Windows App SDK 2.4.0. Scoped diff check passed.

No native application, engine or provider was launched for these component
checks. Appearance/manual acceptance requires root's full I publish and actual
same-generation review capture. No MainWindow, global style, report or artifact
content changed in this slice.
