# STOP handoff — Astra/high, 22. 10. 2026

## Stav při zastavení

Hlídač týdenního využití požádal o okamžitý STOP a ohlásil 75 %. Jde o údaj
z jeho zprávy, nikoli nové měření tohoto chatu. Po této zprávě nebyla spuštěna
další implementace ani test; proveden byl pouze zápis handoffu a kontrola
ukončení vlastních procesů. Pokračovat až po novém pokynu uživatele.

Všichni tři subagenti běželi jako `gpt-6-astra`, reasoning `high`, a potvrdili
ukončení svých procesů i přechod do idle. Nevytvořili jsme automatické pokračování.
Rootovy package/SBOM a WP017 preflight příkazy již skončily s exit 0.
Read-only kontrola Win32_Process po STOP v 11:33–11:34 UTC vrátila prázdný seznam
procesů odpovídajících cestám tohoto checkpointu. První sandboxový dotaz neměl
oprávnění; schválený opakovaný dotaz proběhl úspěšně. Žádný cizí workload ani
uživatelův LM Studio nebyl zastavován.

Base commit `258adf66a9ec3c5a691868ae67c3a73b08b92c4a`. Změny jsou uložené v
pracovním stromu bez nového commitu. Historické balíčky, FINISHED a staré
verification výstupy zůstaly zachované. WP017, WP023 i WP024 zůstávají
`IN_PROGRESS`; žádný celý checkpoint ani release nebyl nově přijat.

## Dokončené ověření

| Oblast | Skutečný výsledek | Evidence |
| --- | --- | --- |
| Python broad | 4423 PASS, 7 SKIP, 20 PASS subtestů, 1 warning, exit 0; všech 7 scan-limit případů s původními limity PASS | `WP023/astra-python-20261022/` |
| PHP follow-up | 2 původně přeskočené dependency případy PASS s existujícími lokálními freeze závislostmi; původní broad souhrn nepřepsán | `WP023/astra-python-20261022/php-dependency-followup/` |
| Runner delta | 39 PASS + 23 PASS subtestů; RequiredBundled manifest/lock/payload podpora | `WP017/astra-review-20261022/` |
| Native consumer matrix | 26 suites, 1134 assertions PASS; další 3 controlled broker suites, 31 cases PASS | `WP023/astra-native-20261022/` |
| Fresh frozen runtime | 13 kontrol PASS, 18 Juice Shop findings, skutečná native/CLI shoda IDs a dodaných priorit | `WP023/astra-frozen-20261022/frozen-approved01/` |
| Cancellation | 50/50 cyklů, 2000 souborů, přesně 20 admission pokusů: 1 přijatý/19 odmítnutých; tree exit p95 3277,8195 ms, max 3362,4195 ms při limitu 5000 ms | stejná frozen evidence |
| Chráněné credentials | 14 DPAPI kontrol PASS, syntetický credential blob odstraněn | stejná frozen evidence |
| Export | 21 kontrol PASS včetně skutečného headless PDF; bez uloženého PDF a bez vizuálního/manual acceptance | `WP023/astra-frozen-20261022/pdf/` |
| Provider connection | 6 kontrol PASS, skutečný lokální `/models` HTTP; žádná generation request | `WP023/astra-frozen-20261022/provider/` |
| Fresh engine qualification | Skutečný frozen Juice Shop scan a compare, canonical generation/manifest/hash proof; 21 discovered modules | `WP024/astra-fresh-20261022/runtime/` |
| Production package | Nový RequiredBundled unsigned package, 821 ověřených inventory entries, SBOM s 56 známými Python dependencies | `WP024/astra-fresh-20261022/packaging/` |
| Packaging guards | Aktuální syntetické stale/missing/sentinel/installer/PS5.1/CMD/rollback kontroly exit 0, 18,44 s, prázdný owned job, source beze změny | `WP024/astra-fresh-20261022/packaging-guards/README.md` |
| WP017 preflight | Pět režimů připraveno na novém source-bound balíčku; exit 0, žádný app process ani provider request | příkaz níže; skutečný live evidence adresář ještě nevznikl |

Broad regression doběhla při změně pouze runneru a jeho testu; core zdroje zůstaly
beze změny. Tyto dvě změny mají následný focused delta důkaz. Nevydávat to za
celou broad suite nad jediným neměnným úplným snapshotem. Fresh freeze a native
publish už vznikly po runner delta, s vlastními unchanged source vstupy.
Pět zbývajících skip případů nebylo provedeno: dva Windows chmod, Windows symlink,
opt-in cancellation stress a opt-in Claude CLI. Frozen 50-cycle test není totožný
s přeskočeným opt-in stress testem.

## Přesné identity

- Package: `desktop/windows/artifacts/astra-packages-20261022/dev-20261022113134-4de136c6/`
- ZIP: stejná cesta s příponou `.zip`; SHA256 `68dc84a3cb6e292138b5fe75d8e2937ece4baf1c724a379613f7ea46cb43df3c`.
- Package manifest SHA256: `d62a6c7f432cfab616cafda64978eb4cfc7a5b0e2167151737c9df848f4af087`.
- Engine: `.tmp/wp024-astra-fresh-20261022-01/dist/attackmap/attackmap.exe`.
- Engine SHA256: `f4ce2e74446198e667cef7e134dbd74654d5e03ec9d9efcaa364235c2cf11107`.
- Release lock: `.tmp/wp024-astra-fresh-20261022-01/release-lock.json`;
  SHA256 `6873ddb1cb00af1dc1a91b6337559e7166b4bc7aea6f914d526616d450f33ade`.
- Source checksum digest: `5d46eec28d565a31e1e82256706dbaf9ab91d238e859fe23a007db55f4577e65`.
- Release inputs digest: `ce7398c65cf4fb2c402c1f0891151ae2e370226546a93fd0a0c5cebd4a619498`.
- Native publish: `desktop/windows/artifacts/integrated-20261022-astra-high/`.
- Native EXE SHA256: `81ed7619e1ce5ebcbdc905f784a57d55234a2b03d416f46a77a0a57ef7e734fc`.
- Native DLL SHA256: `12f5e4231138af1c8922fac7787c4c04a41db94c9cc343ae1641bcfe62584289`.
- Seed report: `docs/verification/windows-parity/WP024/astra-fresh-20261022/runtime/reports/e2b57844b42b488f865ad28736f5b7d1/attackmap-report.json`;
  SHA256 `919619d6ffe6a8ccdf153f83d9b127ae06aa46c1b68351ee770565edbeb5b8c9`.

Freeze ověřil přesné bytes 15 pinned analyzer wheels a přítomnost transport audit
modulu v PyInstaller TOC. Toolchain Python 3.13.15, PyInstaller 6.22.3,
.NET SDK 8.0.426. Samotné payload/pin důkazy nenahrazují širší důvěru v upstream.

## Další krok po výslovném obnovení

1. Přečíst aktuální authority docs a tento handoff; zachovat celý dirty/untracked
   strom. Ověřit nové případné změny zdrojů před použitím existujícího locku.
2. Nezávisle přečíst a syntax/focused ověřit nový
   `verify_installed_native.py` vedle tohoto handoffu. Je **UNREVIEWED / UNEXECUTED**.
   Poté skutečně nainstalovat nový balíček do nového izolovaného workspace rootu
   a provést native bundled static scan bez Pythonu v child PATH.
   Žádná taková instalace ani tento native scan v této dávce ještě neproběhly.
3. QA `--parity-smoke --native-scan` vyžaduje explicitní `--engine`; helper používá
   přesně engine z instalovaného bundle. To nedokazuje automatický normální startup.
   Normální `--verify-portable-startup` je vynechán: Windows .NET known-folder lookup
   nemusí respektovat env LOCALAPPDATA a mohl by číst/zapsat osobní profil.
   Bez ověřené izolace jej nespouštět.
4. Spustit pět skutečných WP017 native model režimů přes nový balíček, výhradně
   sekvenčně. Zachovat 8 calls / 900 s provider / 32000 tokens / 1200 s scan.
   Prohlédnout každý `AI-mode.png`; propojit transport dokončení, generation,
   artefakt, viditelnou sekci a export. Připojení `/models` není model response.
5. Pokračovat chybějícími final-candidate K2/K4 journeys a přesnými dependency gates.
   Rozpracovaný plán: `WP023/astra-frozen-20261022/STOP-HANDOFF.md`.
   Watch small/large snímky vyhodnotit podle skutečných rozměrů, ne názvu souboru.
   WP024 lze uzavřít až po instalovaném bundled scanu; WP017 navíc čeká na WP016.
   Podpis/clean host, OS/a11y, Mac/CI, účastníci a release zůstávají oddělené.

Připravený WP017 příkaz (před spuštěním znovu preflight bez posledních dvou flagů):

```powershell
& .venv/Scripts/python.exe tools/run_wp017_native_modes.py `
  --app C:/Projects/INPROGRESS/AttackMap/desktop/windows/artifacts/astra-packages-20261022/dev-20261022113134-4de136c6/app/AttackMap.NativeSpike.exe `
  --seed C:/Projects/INPROGRESS/AttackMap/docs/verification/windows-parity/WP024/astra-fresh-20261022/runtime/reports/e2b57844b42b488f865ad28736f5b7d1/attackmap-report.json `
  --output C:/Projects/INPROGRESS/AttackMap/docs/verification/windows-parity/WP017/astra-live-20261022 `
  --mode all `
  --release-lock C:/Projects/INPROGRESS/AttackMap/.tmp/wp024-astra-fresh-20261022-01/release-lock.json `
  --manifest-sha256 d62a6c7f432cfab616cafda64978eb4cfc7a5b0e2167151737c9df848f4af087 --run
```

Příkaz s `--run` nebyl proveden. Zůstal pouze úspěšný preflight před STOP.
Budoucí spuštění může potřebovat schválený execution context kvůli doloženému
sandbox ACL problému; nepovolovat plošné ACL změny ani snižování kontrol.

Evidence-only helpery `publish_fresh_native.py`, `qualify_fresh_engine.py` a
`package_fresh_native.py` byly provedeny úspěšně; nezávislé review posledního
package helperu bylo přerušeno STOP. `verify_installed_native.py` nebyl ani
syntax-ověřen. Detailní finální guard hash index a integrátorův souhrnný index
nových důkazů nebyly dokončeny; raw logs/manifests/process records jsou zachovány.
