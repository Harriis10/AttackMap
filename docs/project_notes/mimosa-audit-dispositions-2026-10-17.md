<!-- ATTACKMAP_DOC_STATUS: HISTORICAL_REFERENCE -->
> **STARÝ DOKUMENT — pro agenty nerelevantní jako aktuální plán nebo zadání (20. 10. 2026).**
> Práci řídí pouze dokumenty v [aktuálním rozcestníku](../README.md). Tento text je historická reference: neobnovovat jeho TODO, priority ani statusy dokončení. Technické podklady a kritéria použít jen v rozsahu potřebném pro aktivní WP úkol a ověřit proti aktuálnímu kódu.

# Mimosa deep-scan finding dispositions — 2026-10-17

**Scan:** `scan-2026-10-17T19-52-20.280Z-3fdd21eef98c`, seal
`sha256:1c46a933204907a0b3a9188169f8c6d18316f095d2df81eac89046ac8bff5a76`,
artifacts under `~/.mimosa/security-scans/project-cedc0adfa67b4b4c6fc36f0e/`.
Coverage was **partial** (`runStatus: inconclusive`, offline advisory DB unavailable), so this
disposition review covers the 54 returned findings only — it is not a completeness claim.

Scope of this review: the **10 findings in maintained engine source** (`src/attackmap`). The
remaining 44 findings point at (a) `desktop/windows/*.Tests/Program.cs` harnesses that spawn
processes by design, (b) `MainWindow` report-path handling exercised by the shipped capture/smoke
modes, (c) eight byte-identical copies of `ui/web/src/api.js` baked into delivered package
artifacts, (d) deliberately vulnerable `evals/`/`examples/` fixtures, and (e) one
`scripts/update_plugin_lock.py` download from pinned URLs — none of these are new code paths
introduced by the 2026-10-17 integration batch.

## Source-finding dispositions

| # | Location | Finding | Disposition | Rationale |
|---|---|---|---|---|
| 1 | `llm_review.py:289` | Hardcoded credential | **Intentional** | `api_key="attackmap-local"` is a non-secret placeholder sent only after `_literal_loopback_url(base_url)` confirms a literal loopback destination; the branch exists so a real cloud key is never forwarded to a local compatibility server. |
| 2 | `ui/secrets.py:66` | Hardcoded credential | **Intentional** | `"lm-studio"` placeholder for `is_loopback_endpoint(base_url)` OpenAI-compatible locals; comment states the no-cloud-credential-to-local property. |
| 3 | `ui/secrets.py:78` | Hardcoded credential | **Intentional** | Same pattern on the Anthropic branch; loopback-gated placeholder. |
| 4 | `evaluation.py:272` | Insecure randomness | **Intentional (not security RNG)** | `random.Random(corpus.split_seed).shuffle` produces the *reproducible* tuning/holdout split the C27 evaluation contract records; determinism is the requirement, not unpredictability. |
| 5 | `analyzers.py:611` | SSRF | **Intentional network lookup, constant destination** | Production caller passes the hardcoded `ANALYZER_ORG_API_URL` (GitHub `mlaify` org registry); `api_url` is parameterized only for test injection. Reached from the informational `attackmap modules` listing, fails soft offline, and never runs during scanning. Optional follow-up (product decision, not a fix): a `--offline` skip for the registry section. |
| 6 | `cve.py:698` | SSRF | **Intentional opt-in network, constant base** | All OSV requests use fixed `_OSV_QUERY_URL`/`_OSV_BATCH_URL`/`_OSV_VULNS_URL` constants; only encoded package coordinates and OSV-returned advisory ids are appended, and CVE enrichment itself is explicit opt-in with disclosed data sending. Optional hardening note: `urllib.parse.quote(vuln_id)` before concatenation. |
| 7 | `taint_flow.py:9` | SSRF | **False positive** | The flagged line is the `requests.get(target, timeout=3)` *example inside the module docstring* explaining what the analyzer detects. |
| 8 | `ui/web/src/api.js:53` | SSRF entry | **By-design local transport** | The web UI calling its own loopback server with relative paths plus the `X-AttackMap-Token` header; the server binds 127.0.0.1 only and rejects unauthenticated/disallowed-origin requests (covered by `test_llm_loopback_privacy.py` and the C30 checks). The eight artifact hits are byte-identical copies of this file inside delivered packages. |
| 9 | `desktop_actions.py:94` | Suspected cross-file taint (request → file write) | **Guarded** | The broker handshake writes `{request_id}.request.json` under the engine-controlled action folder; `request_id` is schema-validated `^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$` (no separators → no traversal), the write is atomic, and the surrounding handler explicitly suppresses payload/secret text in errors. |
| 10 | `desktop_provider.py:57` | Suspected cross-file taint (env credential → key store) | **Guarded, intentional channel** | `ATTACKMAP_ACTION_CREDENTIAL` is the designed credential channel from the native app: passed via environment (never argv), `pop`ped immediately so child processes never inherit it, and stored through protected storage (`save_llm_key`); sentinel-secret and UI-privacy tests cover the no-logging property. |

## Conclusion

No finding in the 10 reviewed engine-source locations represents an actionable vulnerability in
the current threat model: three are loopback-only placeholder keys (privacy safeguards, not
secrets), one is reproducibility RNG, two are opt-in/constant-destination network features, two
are static-analysis false positives (docstring example, local UI transport), and two are
schema-or-channel-guarded desktop paths. Two optional (non-security-blocking) hardening notes
were recorded above (#5 `--offline` listing switch, #6 `quote(vuln_id)`). This disposition review
does not certify the project as free of vulnerabilities — scan coverage was partial and the
offline advisory database was unavailable.
