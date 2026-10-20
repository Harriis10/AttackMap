<!-- ATTACKMAP_DOC_STATUS: HISTORICAL_REFERENCE -->
> **STARÝ DOKUMENT — pro agenty nerelevantní jako aktuální plán nebo zadání (20. 10. 2026).**
> Práci řídí pouze dokumenty v [aktuálním rozcestníku](../README.md). Tento text je historická reference: neobnovovat jeho TODO, priority ani statusy dokončení. Technické podklady a kritéria použít jen v rozsahu potřebném pro aktivní WP úkol a ověřit proti aktuálnímu kódu.

# Key Facts — AttackMap (Windows GUI)

Current continuation guide: [Agent handoff — 2026-10-16](HANDOFF.md). It records the accepted Windows M3 scope, M4 follow-up, retained build/evidence and development paths after cleanup; older entries below remain historical.

## Workspace cleanup (2026-10-16)

- Retain only Windows package `dev-20261015190038-5667bbbf` (ZIP plus runnable extracted payload). Older root `dist/` and preview runtime copies were removed.
- Local build toolchain: `.tools/dotnet`, `.tools/dotnet-home`, `.tools/nuget-packages`; Python development environment remains `.venv`. Do not store toolchains in `.pytest_cache`.
- Latest real test/report/provenance evidence: `desktop/windows/verification/retained-m3`, with SHA-256 relocation map. Old `.pytest_cache` proof paths are historical, not existing installations.
- Retain maintained regression tests and small fixtures; remove generated caches/QA runs after use. Fixture/fake-provider tests remain distinct from actual LM Studio calls.

## Current source and targeted testing (2026-10-15)

- Current source version: **1.5.1**, from `src/attackmap/__init__.py`. A source version change does not verify or rebuild the frozen executable.
- Existing `dist\attackmap\attackmap.exe --version` was checked on 2026-10-15 and reports **1.5.1**. It was not rebuilt with this M0 patch; this verifies identity only.
- Targeted real-repository integration test: **`C:\tmp\juice-shop`**. Keep reports outside that repository.
- Live AI tests: local LM Studio at **`http://127.0.0.1:1234/v1`**, model **`cyberstag-security-26b-a4b-v1`**. Use the API backend explicitly; do not fall back to a remote provider. Unit tests use fixtures/fake providers where appropriate.
- Windows M3 scope decision (2026-10-15): the user removed C26 Windows performance qualification, including the Windows 11 host requirement. Do not schedule it as a release blocker or replace it with mandatory Windows 10 performance qualification. Historical diagnostics remain; other acceptance criteria are unchanged.
- Windows M3 closure (2026-10-15): user accepted `dev-20261015190038-5667bbbf` as a functional Windows beta with documented limitations. Remaining C19 Windows study and C21/C24/C25 manual UX/accessibility checks move to M4; do not reopen M3 for these or mark them tested. macOS and original evidence limitations remain separate.
- Acceptance baseline: `docs/roadmap-2026-2028.md`; progress and remaining gates: `docs/implementation-todo.md`.
- Subagent preference (2026-10-15): future subagents use **GPT-6.1 Sol** (`gpt-6.1-sol`). Existing agents finish their current assignment and are then stopped before any further delegation.
- Independent supervision preference (2026-10-15): use **GPT-6 Astra** (`gpt-6-astra`) to review implementation agents and actual evidence. This supervisor is the explicit exception to the Sol implementation-agent preference.

## Previously recorded Windows build (not reverified for 1.5.1)

- **Final EXE: `dist\attackmap\attackmap.exe`** (v0.5.1)
- Contains all **19 analyzers** (15 plugins: php-web, php-laminas, omeka-s, python, node-service, iac, rust, go, java-spring, dotnet, terraform, c, cpp, swift, atproto + 4 built-ins: config, default, javascript-web, python-web).
- GUI: `dist\attackmap\attackmap.exe ui`
- Rebuild: `installer\build-installer.bat` (~3–6 min, PyInstaller onedir, entry `installer\entry.py`, spec `installer\attackmap.spec`).
- Stale dirs `dist\attackmap`, `dist\new`, `dist\attackmap-min` are leftovers — deletable when Explorer doesn't hold them (empty/locked).

## Architecture (GUI)

- `attackmap ui` → WebView2 window (pywebview) + loopback HTTP server (127.0.0.1, token in `X-AttackMap-Token` header + sessionStorage).
- Scan runs in a **supervised subprocess worker**. The GUI builds a frozen-aware argv (`python -m attackmap analyze …` in dev, `attackmap.exe analyze …` in PyInstaller), spawns it, streams NDJSON progress, and can terminate it for cancellation. A `run_id` and explicit state machine (`idle → running → cancelling → succeeded|failed|cancelled`) prevent overlapping runs and stale callbacks.
- Reports OUTSIDE the repo: `%LOCALAPPDATA%\AttackMap\scans\<name>-<normcase-sha256-12>\reports`.
- In frozen builds, `ATTACKMAP_TRUSTED_ANALYZERS_ONLY=1` is passed to the worker by default so only official analyzers load.
- Splash-first navigation: window opens with inline dark HTML, `load_url` fires on `events.loaded` (kills white WebView2 "Loading <url>" page; `background_color=#141414` → dark resize repaints).
- LLM keys: DPAPI blobs `%LOCALAPPDATA%\AttackMap\llm-{anthropic,openai}.key`. LM Studio = provider openai + `OPENAI_BASE_URL` (no key needed, placeholder `lm-studio`).
- LM Studio test endpoint: `http://127.0.0.1:1234/v1`, model `cyberstag-security-26b-a4b-v1` (effort low — 26B local is slow on high).

## Verification anchors

- Tests: `python -m pytest tests/test_ui.py tests/test_llm_review.py` (59 passed on 2026-10-13).
- Juice-shop with all analyzers: 40 exploitability rows, 42 taint chains, 270 routes, 176 deps, 19 findings.
- DVWA: 11 findings, 1 attack path, 0 taint chains (plain-PHP superglobal flows not traced — engine limitation, GUI shows explanatory empty state).
- LLM proof: `defensive-review-llm.meta.json` records backend/model/tokens per run.
- Session state doc: `docs/session-state-2026-10-13-windows-gui.md`.

## Gotchas

- Deleting `dist\attackmap` often reports LOCKED even when empty (Explorer/antivirus handle): `taskkill /IM attackmap.exe /F`, wait, `rmdir` again, or build to a different `--distpath`.
- PyInstaller builds hang on `--collect-all attackmap` / `--clean` with heavy deps; excludes needed: `tkinter matplotlib numpy pandas scipy PIL pytest IPython`.
- `pip install` name for Omeka plugin is `attackmap-analyzer-omeka-s` (pyproject `[all]` has a typo `attack-map-analyzer-omeka-s` in the repo URL but package name is attackmap-).
