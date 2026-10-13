# Key Facts — AttackMap (Windows GUI)

## Final Windows build

- **Final EXE: `dist\final\attackmap\attackmap.exe`** (2026-10-13, v0.5.0)
- Contains all **19 analyzers** (15 plugins: php-web, php-laminas, omeka-s, python, node-service, iac, rust, go, java-spring, dotnet, terraform, c, cpp, swift, atproto + 4 built-ins: config, default, javascript-web, python-web).
- GUI: `dist\final\attackmap\attackmap.exe ui`
- Rebuild: `installer\build-installer.bat` (~4–6 min, PyInstaller onedir, entry `installer\entry.py`, spec `installer\attackmap.spec`).
- Stale dirs `dist\attackmap`, `dist\new`, `dist\attackmap-min` are leftovers — deletable when Explorer doesn't hold them (empty/locked).

## Architecture (GUI)

- `attackmap ui` → WebView2 window (pywebview) + loopback HTTP server (127.0.0.1, token in `X-AttackMap-Token` header + sessionStorage).
- Scan runs **in-process** (`run_scan(AnalyzeOptions)`) — never spawn `sys.executable -m attackmap` from the frozen exe (breaks with `No such option '-m'`).
- Reports OUTSIDE the repo: `%LOCALAPPDATA%\AttackMap\scans\<name>-<normcase-sha256-12>\reports`.
- Splash-first navigation: window opens with inline dark HTML, `load_url` fires on `events.loaded` (kills white WebView2 "Loading <url>" page; `background_color=#141414` → dark resize repaints).
- LLM keys: DPAPI blobs `%LOCALAPPDATA%\AttackMap\llm-{anthropic,openai}.key`. LM Studio = provider openai + `OPENAI_BASE_URL` (no key needed, placeholder `lm-studio`).
- LM Studio endpoint used: `http://localhost:1234/v1`, model `cyberstag-security-26b-a4b-v1` (effort low — 26B local is slow on high).

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
