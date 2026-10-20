<!-- ATTACKMAP_DOC_STATUS: HISTORICAL_REFERENCE -->
> **STARÝ DOKUMENT — pro agenty nerelevantní jako aktuální plán nebo zadání (20. 10. 2026).**
> Práci řídí pouze dokumenty v [aktuálním rozcestníku](README.md). Tento text je historická reference: neobnovovat jeho TODO, priority ani statusy dokončení. Technické podklady a kritéria použít jen v rozsahu potřebném pro aktivní WP úkol a ověřit proti aktuálnímu kódu.

# Privacy and optional network features

The Windows desktop starts with AI mode **None** and CVE lookup **off**.
Saving a provider credential does not enable AI. A deterministic scan does not
call an AI provider or OSV unless their optional features are enabled. Analyzer
plugins execute Python code locally; this is not a guarantee that arbitrary
third-party plugins cannot access the network. Installing analyzers or other
dependencies can also contact their package hosts.

## What optional features send

| Feature | Destination | Inputs sent |
| --- | --- | --- |
| AI review, hunt, triage | Selected Anthropic or OpenAI provider; OpenAI-compatible endpoint when configured | Repository metadata, paths, architecture/signals, findings and evidence used by the selected prompt |
| AI verification and remediation | Same selected provider/endpoint | Those inputs plus source excerpts around cited locations where available |
| CVE lookup | `https://api.osv.dev` | Dependency ecosystem, package name and version; advisory IDs are requested for details |

Private package names can therefore be disclosed by CVE lookup even when AI is
off. A custom endpoint may be remote. The Windows child environment removes
inherited provider credentials and endpoint overrides before adding the
explicitly selected provider configuration, so an inherited endpoint cannot
silently redirect a desktop scan. The standalone CLI has separate environment
configuration behavior; inspect its provider/backend settings before enabling AI.

AttackMap masks recognized credential patterns in structured evidence and source
excerpts. Masking is best effort, not a guarantee that every secret or sensitive
business detail is removed. Prompts still contain code and repository context;
review the sensitivity of a repository before enabling AI. Provider retention,
processing and billing depend on that provider and your account configuration.
AttackMap cannot enforce the provider's retention policy.

## Windows credentials

Saved Anthropic and OpenAI keys use separate Windows DPAPI-encrypted blobs under
`%LOCALAPPDATA%\AttackMap`. An explicitly named environment API key takes precedence
over a saved key when preparing that selected provider's configuration. Keys are
not command-line arguments. The child environment receives only explicitly
selected provider credentials, rather than every inherited provider credential.
Literal loopback OpenAI-compatible destinations (`localhost`, `127.0.0.1`, `::1`)
receive a placeholder key instead of a saved production key. Remote custom
endpoints receive the configured OpenAI key and must be trusted accordingly.

A secure-store failure must report that the key was not saved. A failed DPAPI
protection operation leaves an existing blob untouched. This Python desktop
credential helper refuses saves outside Windows and does not read plaintext
fallback blobs. Native macOS clients must use their own Keychain implementation;
this document does not certify macOS credential or runtime behavior.

Reports and exports contain repository names, paths, dependencies and evidence,
which can remain sensitive after masking. Review files before sharing. Do not
include keys or raw private source in issue reports or diagnostic attachments.

## Verification scope and remaining acceptance

`tests/test_ui_privacy.py` checks first-launch scan flags, the final process-spawn
environment with sentinel credentials, local endpoint key isolation, secure-store
failure without plaintext fallback, a real Windows DPAPI roundtrip, and a sentinel
source credential at verification-prompt and report serialization boundaries.
`tests/test_redact.py` covers recognized secret forms across generated CLI artifacts.
Tests use fake providers and credentials; they do not send repository content to
a remote AI service.

These checks are scoped evidence, not universal secret-leak proof. C07/AM008 still
requires cross-platform copy review and actual macOS validation; C14 additionally
requires stronger claim/citation support and all diagnostic/error paths to be
verified. Native secure-store refusal UX, a full provider-failure/export matrix,
and provider-side retention controls are not established by these tests.
