<!-- ATTACKMAP_DOC_STATUS: HISTORICAL_REFERENCE -->
> **STARÝ DOKUMENT — pro agenty nerelevantní jako aktuální plán nebo zadání (20. 10. 2026).**
> Práci řídí pouze dokumenty v [aktuálním rozcestníku](README.md). Tento text je historická reference: neobnovovat jeho TODO, priority ani statusy dokončení. Technické podklady a kritéria použít jen v rozsahu potřebném pro aktivní WP úkol a ověřit proti aktuálnímu kódu.

# Application service boundary

`scan_service.ScanRequest` and `RunSummary` provide the shared Python application
entry point. The service and `pipeline` no longer import Typer, Click, or desktop
modules. Presentation adapters translate `ScanRequestError` into their own error
UI; the CLI retains its usage-error and exit-code behavior.

Engine configuration errors use `AnalysisConfigurationError`; controlled stops
use `AnalysisExit` and explicit aborts use `AnalysisAborted`. Default output is a
plain injected text callback. CLI adapters may supply their own formatter.
These classes live in `application_errors`, independent of presentation.

The desktop worker additionally turns validated-request startup failures into a
typed failed terminal message and, when the output location is writable and safe,
a redacted terminal diagnostic. Invalid schemas without a trustworthy envelope
produce an actionable generic error without echoing the request contents.

Focused tests cover import boundaries, neutral configuration errors, controlled
exit translation, CLI/fleet usage errors and startup diagnostics. These checks
do not establish all C15 diagnostic coverage, analyzer-version completeness or
cross-platform adapter acceptance.
