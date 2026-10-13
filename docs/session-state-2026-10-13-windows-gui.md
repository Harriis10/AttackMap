# Session state — Windows GUI port + LM Studio (2026-10-13)

Durable record before context compaction. Everything below is verified on disk.

## Done

### Windows GUI (port of macOS app, WebView2 + loopback)
- `src/attackmap/ui/` — `server.py` (loopback, token auth, API: state/report/run/cancel/config/pick/watch/settings/reveal/suppress), `config.py` (ScanConfig → CLI args), `runner.py` (stderr tail, `child_python_env` with PYTHONPATH), `output.py` (reports OUTSIDE repo → `%LOCALAPPDATA%\AttackMap\scans\<name>-<hash>\reports`), `secrets.py` (DPAPI keys, separate anthropic/openai blobs), `watch.py` (FindFirstChangeNotificationW), `report.py` (decode report → GuiReport), `launch.py` (WebView2 → browser fallback, prints URL), `suppress_write.py`.
- Views (single frontend copy in `src/attackmap/ui/web/`): Overview, Findings (master-detail + Suppress), Exploitability, Attack paths, Attack surface, Diagrams, Review, AI Review, Diff, Fleet, Dependencies, Secrets, CI workflows, Data flows, Analyzers, Recent scans, Settings. Toolbar: repo path input, Pick folder, +Fleet, LLM mode, Provider, Model, Base URL, CVE, Recall, Analyzers, Watch, Settings, Run/Cancel. Old duplicate `web/` at repo root was deleted.
- `src/attackmap/__main__.py` added (`python -m attackmap` works).
- Tests: `tests/test_ui.py` + `tests/test_llm_review.py` → **55 passed**.

### Installer
- `installer/attackmap.spec`, `installer/entry.py`, `installer/build-installer.bat`.
- Build: PyInstaller onedir → `dist\attackmap\attackmap.exe` (works, `attackmap 0.5.0`).
- Excludes that un-hung builds: `tkinter matplotlib numpy pandas scipy PIL pytest IPython`.
- Plugins bundled via `--collect-all attackmap_analyzer_php_web/python/node_service/iac` (entry_points discovery doesn't survive freezing otherwise). Exe `modules --json` → 8 modules.
- `taint_sinks.yaml` must be in `datas` (exe crashed without it).
- Gotcha: deleting `dist\attackmap` sometimes reports LOCKED with an empty dir — `taskkill /IM attackmap.exe /F`, wait, `rmdir` again.

### LM Studio (local LLM, no API key)
- `src/attackmap/llm_review.py` — `_resolve_openai_client` now honors `OPENAI_BASE_URL` (test `test_openai_api_uses_openai_base_url_for_lmstudio`).
- GUI: Provider option **LM Studio (local)** maps to `openai` + `baseUrl` (default `http://localhost:1234/v1`); no stored key required (`child_llm_env` sends placeholder `lm-studio` key when base_url set). Gate in `_start_scan` skips key check when provider=openai && base_url.
- **In-process scan**: GUI previously spawned `sys.executable -m attackmap`, but in the frozen exe `sys.executable` IS `attackmap.exe` → "No such option '-m'". `_start_scan` now calls `run_scan(AnalyzeOptions(...))` in a thread (llm_backend="api"). This was THE root cause of the recurring `-m` error.
- Verified E2E from rebuilt exe GUI: DVWA scan with LM Studio → **Done — 11 findings**, AI Review rendered.
- Proof of real LLM call: `%LOCALAPPDATA%\AttackMap\scans\DVWA-3bfd048a8581\reports\defensive-review-llm.meta.json` → `{backend: api, model: cyberstag-security-26b-a4b-v1, usage: {input_tokens: 8724, output_tokens: 3460}}`.

### Analyzers
- Installed to user site-packages pinned to pyproject commits: `attackmap-analyzer-php-web`, `-python`, `-node-service`, `-iac`.
- DVWA results: 197 files, 1 route, 11 findings (2 HIGH: hard-coded secrets, MD5/SHA-1), 1 attack path. Without plugins it was 9 findings / 0 routes.
- `-m php-web` alone is WORSE (disables config/crypto/iac) — recommend **Auto**.

## Open / next steps (not done)
- First poll right after `?token=` redirect sometimes 403s once (api.js not loaded yet) — cosmetic.
- `tkinter` folder dialog only runs on main thread; WebView2 uses pywebview bridge, browser fallback must type path (by design now).
- Watch mode: `FindFirstChangeNotificationW` doesn't report which path changed (should_ignore can't filter); fleet watches only repos[0].
- Suppression writer (`suppress_write.py`) doesn't YAML-quote values (newlines can inject keys).
- `capabilities` background load in LoopbackApp is lazy; on first run modules menu may be Auto-only until loaded.
- No code signing / no real .msi/.exe installer wizard — distribution is the onedir folder; bat script rebuilds it.

## Key commands
- GUI from source: `python -m attackmap ui`
- GUI from build: `dist\attackmap\attackmap.exe ui`
- Tests: `python -m pytest tests/test_ui.py tests/test_llm_review.py -q`
- Rebuild exe: `installer\build-installer.bat` (≈3–4 min)
- LM Studio scan (CLI): `set OPENAI_API_KEY=lm-studio && set OPENAI_BASE_URL=http://localhost:1234/v1 && python -m attackmap analyze <repo> --llm --llm-provider openai --llm-model cyberstag-security-26b-a4b-v1 --llm-effort low`
- LM Studio models endpoint: `http://localhost:1234/v1/models` (server must be running)
