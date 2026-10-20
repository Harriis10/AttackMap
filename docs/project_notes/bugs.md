<!-- ATTACKMAP_DOC_STATUS: HISTORICAL_REFERENCE -->
> **STARÝ DOKUMENT — pro agenty nerelevantní jako aktuální plán nebo zadání (20. 10. 2026).**
> Práci řídí pouze dokumenty v [aktuálním rozcestníku](../README.md). Tento text je historická reference: neobnovovat jeho TODO, priority ani statusy dokončení. Technické podklady a kritéria použít jen v rozsahu potřebném pro aktivní WP úkol a ověřit proti aktuálnímu kódu.

# Bug Log — AttackMap (Windows GUI)

### 2026-10-13 — GUI scan fails "No such option '-m'" (frozen exe)
- **Issue**: Running a scan from `attackmap.exe ui` failed with `No such option '-m'`.
- **Root Cause**: GUI spawned `sys.executable -m attackmap`; in the frozen exe `sys.executable` IS `attackmap.exe`, which has no `-m` flag.
- **Solution**: `_start_scan` runs `run_scan(AnalyzeOptions)` in-process on a thread.
- **Prevention**: Never subprocess-spawn `python -m attackmap` from the GUI; capabilities/modules calls also run with `child_python_env` only in dev.

### 2026-10-13 — exe crashes on start: missing `taint_sinks.yaml`
- **Issue**: `attackmap.exe --version` → `FileNotFoundError: _internal\attackmap\taint_sinks.yaml`.
- **Root Cause**: PyInstaller datas didn't include the YAML registry.
- **Solution**: `--add-data "src/attackmap/taint_sinks.yaml;attackmap"`.
- **Prevention**: after each build smoke-test `attackmap.exe --version` and `modules --json`.

### 2026-10-13 — White "Loading <url>" page on WebView2 open/resize
- **Issue**: White page with "Loading http://127.0.0.1:…" during window open and after resize.
- **Root Cause**: Window created with `url=` (or `load_url` before splash commit) navigates from about:blank; WebView2 shows its loading interstitial until commit. A dead-server window makes it stick forever.
- **Solution**: window opens with inline dark splash HTML; `load_url` fires on `events.loaded` (2 s fallback timer). `background_color=#141414` → `DefaultBackgroundColor` dark for resize repaints.
- **Prevention**: never navigate before the initial document is committed; keep server alive while window is open (`runner.cancel()` only on close).

### 2026-10-13 — 403 on all API calls after page reload
- **Issue**: After F5, every `/api/*` returned 403 and the UI was dead.
- **Root Cause**: Token was stripped from the URL via `history.replaceState` for secrecy and only lived in memory.
- **Solution**: Persist token to `sessionStorage` on first load; read it back on reload.
- **Prevention**: any auth token removed from the URL must have a same-origin storage fallback.

### 2026-10-13 — LM Studio scan blocked by "No API key stored"
- **Issue**: GUI refused to run LLM mode against LM Studio without a saved OpenAI key.
- **Root Cause**: Key gate applied to all providers; LM Studio needs no key.
- **Solution**: Gate skipped when provider=openai AND base_url set; `child_llm_env` sends placeholder `lm-studio` key. Engine side: `_resolve_openai_client` honors `OPENAI_BASE_URL`.
- **Prevention**: local OpenAI-compatible endpoints (LM Studio, Ollama, vLLM) must not require credentials.

### 2026-10-13 — Review/Diff/AI Review tabs show raw markdown
- **Issue**: `##`, `**bold**`, `- [HIGH]`, tables rendered as literal text.
- **Root Cause**: First renderer was escapeHtml + regex for headings only.
- **Solution**: `markdown.js` rewritten — headings, bold/italic (`*` and `_`), lists, tables, code fences, hr, links, blockquote, escaped `\_`.
- **Prevention**: `test_markdown_renderer_covers_review_syntax` guards the feature set.

### 2026-10-13 — Exploitability tab empty on DVWA
- **Issue**: Exploitability showed nothing even after scans.
- **Root Cause**: Engine limitation, not UI — `taint_chains: 0` for plain-PHP superglobal flows (DVWA), so 0 scores even with `--recall`.
- **Solution**: GUI empty-state now explains the taint-chain requirement. Juice-shop (270 routes) yields 40 rows.
- **Prevention**: keep the empty state informative; engine-side PHP taint coverage is a separate roadmap item.
