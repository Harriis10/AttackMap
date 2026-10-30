# AttackMap Windows parity — podrobné TODO pro paralelní agenty

**Scoped integrace 27. 10. 2026:** Nezávisle reviewované řezy WP032/WP039/WP044 jsou integrované; integrátor ověřil 207 PASS pro WP032, 328 PASS + 2 SKIP pro WP039 a 160 PASS pro WP044. WP043 candidate-07 nově dokládá pět skutečných A/R/B trojic bez property mutací: kolo 4 je A blank → R complete → B blank, kolo 2 naopak dokazuje, že RTB není spolehlivý live-presentation oracle, a kolo 5 je pouze korelace recovery. Harness má 49 PASS + 8 subtestů; rendering acceptance zůstává FAILED a root cause není prokázán. Všechny čtyři WP zůstávají IN_PROGRESS; chybí zejména reálný WP044 emitter/fleet runtime, WP039 installed-plugin a maturity gates a WP043 V01–V03. [Vizuální review WP043](../artifacts/diagram-integration-20261024/wp043-continuation-20261025/detail-render-probe-live-27-retry-03/visual-review/manual-review.json). Starší checkpointy níže jsou historické.

**Aktuální scoped checkpoint 23. 10. 2026:** [dávka tří Sol 6.1 / ultra agentů](verification/windows-parity/ROADMAP-NEXT-20261023/FINAL-HANDOFF.md) dokončila přípravu datastore extraction kontraktu WP044, graf/evidence/source/back řez WP043 a startup smoke opravu WP023. 104 Python testů, 128 navigačních kontrol, 94 native kontrol / 16 dokončených test-repo dětí a čtyři compiled startup scénáře PASS; obě témata a dvě velikosti inspektoru vizuálně prohlédnuté. Whole-task statusy se nemění: WP023/WP043/WP044 IN_PROGRESS; nový extractor, reprezentativní produkční fleet, manual/clean-host/macOS a společný fresh package zůstávají dalšími branami. Předchozí portable ZIP zachovaný. Leases této dávky uvolněné; starší odstavce níže nejsou aktivní běhový stav.

**Fleet16 integrován 23. 10. 2026:** WP043/WP044 jsou IN_PROGRESS. Společný model všech 16 roots, interaktivní Cytoscape přehled, nativní Canvas/MSAGL a úplné JSON/SVG exporty jsou začleněné do Fleet. Skutečné source běhy 16 testovacích repozitářů a Juice Shop + 15 fixtures prošly; řízený partial zachoval 15 child výsledků a failed skupinu. Společný source-bound kandidát02 prošel 75 skutečnými native kontrolami, 16 child manifesty, oběma renderery a frozen Juice Shop+compare; kompaktní lišta je opravená. Plný portable ZIP je uložený v `C:\Projects\AttackMap-Windows-x64-fleet16-20261023.zip`; lokální Git checkpoint `f5247d0`. Vlastní lease je uvolněný, další úkoly se nezahajují. Neuzavírá se non-HTTP, reprezentativních 16 produkčních repos, manual/clean-host ani macOS acceptance. [Důkazy a zbývající brány](verification/windows-parity/WP043/fleet16-20261023/README.md). Starší checkpointy níže zůstávají datované. Aktuální součet WP001–WP044: 7 DONE, 5 MANUAL_PENDING, 6 IMPLEMENTED, 16 IN_PROGRESS, 8 OPEN, 2 DEFERRED.

**Druhá implementační dávka ověřena 23. 10. 2026:** Druhá dávka Sol 6.1 ultra ověřena: native profily/request 1.5, per-run ledger, bounded Node/ATProto WS/auth fix; 508 PASS + 2 SKIP, 597 native kontrol, source/frozen/native Juice Shop a scoped vizuální review. WP042/WP039 zůstávají IN_PROGRESS; whole-task/manual/package/maturity brány otevřené. [Výsledky a další krok](verification/windows-parity/WP042/sol-ultra-20261023-batch2/README.md). Leases této dávky jsou uvolněné. Starší checkpointy níže zůstávají datované.

**Povinné upřesnění 23. 10.:** [celkové schéma 16 repozitářů](verification/windows-parity/RESEARCH-2026-10-23-analyzers-graphs/fleet16-requirements.md). WP043 zahrnuje fleet jako povinnou acceptance; nový WP044 vlastní architektonická data/vztahy, WP018/WP019 explicitní scheduling/budget/identity. Aktuální rozsah WP001–WP044: 7 DONE, 5 MANUAL_PENDING, 5 IMPLEMENTED, 15 IN_PROGRESS, 10 OPEN, 2 DEFERRED. Starší počty níže jsou předchozí checkpointy; nový runtime nebo hotový 16-repo graf se netvrdí.

**První implementační dávka ověřena 23. 10. 2026:** WP042 a přípravný PHP řez WP039 zůstávají IN_PROGRESS. Tři agenti GPT-6.1 Sol / ultra dodali katalog kolizí, verzované CLI profily a parent/child routování Laminas/Omeka; 266 cílených testů PASS, 2 SKIP, nový frozen engine s 15 pluginy / 21 účinnými analyzéry a tři shodná celá JSON porovnání Juice Shopu. [Výsledky a zbývající brány](verification/windows-parity/WP042/sol-ultra-20261023/README.md). Celkem 43 úkolů: 7 DONE, 5 MANUAL_PENDING, 5 IMPLEMENTED, 15 IN_PROGRESS, 9 OPEN, 2 DEFERRED. Nativní UI, ledger a whole-task/release acceptance zůstávají otevřené; leases dávky jsou uvolněné.

**Rozšíření 23. 10. 2026:** [výzkum analyzérů a grafů](verification/windows-parity/RESEARCH-2026-10-23-analyzers-graphs/README.md) přidává WP042/WP043 jako OPEN a doplňuje WP039. Aktuálně 43 úkolů: 7 DONE, 5 MANUAL_PENDING, 5 IMPLEMENTED, 13 IN_PROGRESS, 11 OPEN, 2 DEFERRED. Stavy původních 41 úkolů se tím nemění. Nejnovější výzkumní agenti: GPT-6.1 Sol / ultra; níže jsou zachované starší checkpointy.

**Aktuálně znovu obnoveno 23. 10. na výslovný pokyn uživatele:** [dávka GPT-6.1 Sol ultra](verification/windows-parity/RESUME-2026-10-23-sol-ultra/README.md). Scoped řezy WP016 metadata, WP023 window lifetime a WP017 controlled provider faults jsou integrované a cíleně ověřené; whole-task brány zůstávají otevřené. Předchozí pokyn po portable skončit je tímto novým zadáním odvolán; starší odstavce níže jsou datované checkpointy. Žádná nová release/ruční acceptance se tím nepřiznává.

**Závěrečný checkpoint 23. 10.:** [výsledky 7200s kandidáta](verification/windows-parity/RESUME-2026-10-22/checkpoint-2026-10-23.md) obsahují nové runtime/package/installed důkazy, všechny čtyři Hunt+verify HTTP odpovědi (partial kvůli abstenci), Triage scoped PASS a otevřené GUI/obsahové brány. Po požadovaném lokálním Git uložení a full portable buildu se další úkoly nezahajují. Následující starší odstavce jsou předchozí checkpoint, nikoli aktuální běhový stav.

**Nejnovější běh AKTIVNÍ na výslovný pokyn uživatele:**
[obnovený postup](verification/windows-parity/RESUME-2026-10-22/astra-high/RESUMED.md).
Předchozí STOP hlídače využití (ohlášeno 75 %) je historický.
[Astra/high handoff](verification/windows-parity/RESUME-2026-10-22/astra-high/STOP-HANDOFF.md):
4423 Python PASS, native 1134 assertions + 31 controlled cases, frozen13/13,
50/50 cancellation cycles a nový source-bound RequiredBundled package/SBOM.
Historické WP024 DONE zůstává v unsigned-preflight scope. [Checkpoint 23. 10.](verification/windows-parity/RESUME-2026-10-22/checkpoint-2026-10-23.md)
dokládá aplikovaný lokální allowance 7200 s a cílené výsledky 412 Python PASS,
55 runner testů + 120 subtests PASS, 117 native offline assertions PASS.
Starší Hunt+verify retry 02 je partial, Remediate scoped live PASS, Triage retry 02
je přes HTTP 200/pre-close parity true celkově FAIL (`0xC000027B`). Freeze 01 je
interim, finální freeze 02 se připravuje; nový kandidát nemá přenesený runtime
nebo live PASS. WP017/WP023 acceptance zůstává otevřená.

**Baseline 20. 10. 2026; integrační revize 23. 10. 2026.** Číst spolu s [auditem](windows-parity-audit-2026-10-20.md) a [roadmapou/checkpointy](roadmap-windows-parity-2026-10-20.md). JSON protějšek: [windows-parity-backlog.json](windows-parity-backlog.json). Aktuální stav: 7 DONE, 5 MANUAL_PENDING, 5 IMPLEMENTED, 13 IN_PROGRESS, 11 OPEN, 2 DEFERRED. Přidělení ani component testy neuzavírají integraci nebo acceptance. Produktem je původní celé MainWindow; viz [rozhodnutí](verification/windows-parity/RECONCILE-2026-10-21/product-basis.md). WP021 zůstává volitelné rozšíření.

**Obnovený běh:** [rozdělení práce a zbývající brány](verification/windows-parity/RESUME-2026-10-22/README.md). Nejnovější pokyn uživatele nastavuje navazující subagenty na GPT-6.1 Sol s reasoning effort `medium`; [aktuální checkpoint](verification/windows-parity/RESUME-2026-10-22/checkpoint-2026-10-23.md). Předchozí Astra/high a Sol/ultra výsledky zůstávají zachované. Příprava runneru sama neuzavírá pět skutečných režimů ani finální package.


Přípravné implementační a integrační řezy mohou pracovat nad zkontrolovaným, hashově svázaným zdrojovým checkpointem závislosti. Otevřené ruční, živé a release brány závislostí stále blokují přijetí celého úkolu; rozpracování neznamená DONE. Přesný omezený rozsah je uveden v JSON `execution_scope`.

## Pravidla převzetí

1. Integrátor zapíše ownera, base commit a rezervované soubory. Nejdřív aktuální `git status`, AGENTS.md a CodeGraph; nevycházet jen z tohoto datovaného auditu.
2. Implementační agent používá `gpt-6.1-sol`. Maximum jsou tři pracovní agenti vedle integrátora. Nespouštět stejný LM Studio, UI capture nebo package/install výstup ze dvou úkolů.
3. `Zápis` určuje vlastní soubory; `Lease` výhradní dočasné vlastnictví sdílených souborů. Bez přiděleného lease se odevzdá návrh změny, nikoli souběžný edit. Nové soubory níže jsou návrh hranice, ne tvrzení, že již existují.
4. Závislost znamená předpoklad integrace/uzavření. Read-only návrh lze připravit dříve, ale nesmí předjímat nezmrazený kontrakt.
5. Každá karta zahrnuje původní kritéria/AM lineage, funkce Fxx a checkpoint. **Dokončení vyžaduje DoD i důkaz**, včetně explicitních omezení. Při nefunkčním toolu zapsat blocker a pokračovat nezávislými úkoly.
6. Stavy: OPEN → IN_PROGRESS → IMPLEMENTED → VERIFIED → DONE; MANUAL_PENDING/BLOCKED_EXTERNAL mají konkrétní důvod. DONE je v dohodnutém scope, nikoli automatické splnění celého Cxx na obou OS.

### Společné ověřovací příkazy

Z kořene checkoutu PowerShell:

```powershell
& ./.venv/Scripts/python.exe -m pytest tests/test_run_contract.py tests/test_desktop_options.py -q
$env:DOTNET_CLI_HOME = "$PWD/.tools/dotnet-home"
$env:NUGET_PACKAGES = "$PWD/.tools/nuget-packages"
$taskDotnet = "$PWD/.tools/dotnet/dotnet.exe"
& $taskDotnet run --project desktop/windows/EngineProtocol.Tests
```

Konkrétní suite karty níže doplňuje tento vzor; nové test soubory musí agent vytvořit jen pro nové chování. `-m pytest tests -q` a všechny relevantní native consumer suites patří až do WP023 stabilního checkpointu, nikoli po každé změně. UI změna vždy potřebuje viditelný preview a vizuální kontrolu. Výstupy mimo `C:\tmp\juice-shop` a immutable package.

## Kontrakty a základ

<a id="wp001"></a>

### WP001 — Zapečetit výchozí stav a průkaz současného kandidáta

- Priorita: P0; lane: INTEGRATION; checkpoint: K1; stav: DONE.
- Owner: `/root/wp001_baseline`; base: `d45997653970929f5f477c6e2dcd70913cb17fe3`; rozsah převzetí viz JSON backlog.
- Závislosti: žádné.
- Kritéria: C01, C16, C29; původní úkoly: AM001, AM019, AM041; funkce: F23, F25.
- Zápis: `docs/verification/windows-parity/WP001/`, aktuální baseline záznam.
- Lease: žádný; cizí `tools/package_native_windows.ps1` pouze přečíst a popsat.
- Kroky: identifikovat dirty diff; source version/commit, package manifest/engine verification, skutečně nainstalovanou verzi a modules inventory. Ověřit existenci historické evidence před převzetím; oddělit source, packaged a installed identity. Nahradit rozporné „current“ odkazy v provozních docs konkrétním datem/rolí.
- DoD: reprodukovatelný baseline JSON s hashi, seznamem nedoložených claims, aktuálním count modulů z vybraného enginu a přesným rozsahem accepted M3. Žádný reset/rebuild zachovaného balíčku.
- Ověření: read-only `git status`, version/modules přes schválený engine, manifest/payload validation existujícím nástrojem; malý contract test, nikoli nová plná kampaň.
- Důkaz: `docs/verification/windows-parity/WP001/`; root review 20. 10. 2026. Installed strict validation zůstává FAIL kvůli dvěma zachovaným smoke JSON souborům a není vydávána za release acceptance.

<a id="wp002"></a>

### WP002 — Zmrazit společné fixtures a kontrakt parity

- Priorita: P0; lane: CONTRACT; checkpoint: K1; stav: DONE.
- Owner: `/root/wp002_contract`; base: `d45997653970929f5f477c6e2dcd70913cb17fe3`; rozsah převzetí viz JSON backlog.
- Závislosti: WP001.
- Kritéria: C08, C21, C23, C37; původní úkoly: AM009, AM025; funkce: F01–F26.
- Zápis: `fixtures/desktop-parity/` (nové), `docs/desktop-parity-contract.md` (nový).
- Lease: žádný.
- Kroky: fixture manifest s IDs/hash; current/legacy/unknown-major requesty, všechna scan nastavení, mode/provider kombinace; kompletní/empty/partial report; aktivní/suppressed findings, paths, inventory, fleet, AI metadata; dvě generace stejného repo a stejné názvy různých repos.
- DoD: každé Fxx má fixture nebo výslovnou platform/manual proceduru; schema/defaults a expected values odsouhlasené integrátorem. Žádné reálné secrets ani vymyšlené live výsledky.
- Ověření: JSON/schema validation, přesné očekávané ID/count/order; fixtures musí být použitelné Python/C#/Swift. Nepřepisovat již udržované fixture corpus, jen odkázat nebo doplnit.
- Důkaz: `fixtures/desktop-parity/`, `docs/desktop-parity-contract.md`, `docs/verification/windows-parity/WP002/`; root validator 266 PASS. Zmrazen je současný kontrakt a explicitní absence; budoucí fleet/AI options se přidají pouze ve vlastnících WP004/WP014/WP018 a znovu projdou consumers.

<a id="wp003"></a>

### WP003 — Engine capabilities a verzovaný preflight

- Priorita: P0; lane: CORE; checkpoint: K1; stav: DONE.
- Owner: `/root/wp003_capabilities`; base: `d45997653970929f5f477c6e2dcd70913cb17fe3`; lease: `desktop_actions.py`, CLI capabilities registration a relevantní schema pouze tomuto agentovi; úzký lease `desktop_worker.py` jen pro raw fail-fast validaci před parse/dispatch.
- Závislosti: WP002.
- Kritéria: C08, C20, C29; původní úkoly: AM009, AM024; funkce: F03, F23.
- Zápis: `src/attackmap/desktop_capabilities.py` (nový), `tests/test_desktop_capabilities.py` (nový).
- Lease: `src/attackmap/desktop_actions.py`, `schemas/`, příslušné CLI command registration.
- Kroky: navázat na existující `cli.py::capabilities` schema 1 a `modules --json`; sdílený neutral helper rozšířit o desktop schema range, skutečně připojené režimy/volby a omezení. Read-only desktop operation používá stejná data, nikoli druhý seznam CLI flags. Cache identity svázat s executable identity, invalidovat po výměně enginu.
- DoD: starý, kompatibilní, budoucí major, malformed a změněný engine dostanou deterministický preflight výsledek. Explicitní unsupported request nikdy není ignorován ani spuštěn. Žádný provider call při probing.
- Ověření: source/frozen action tests; sentinel-secret kontrola výsledku; chybějící command nesmí spustit GUI či jiný exe.
- Důkaz: `docs/verification/windows-parity/WP003/`; root-reviewed implementace, finální cílená sada 87 PASS. Frozen transport je simulovaný; nový frozen binary nebyl tímto úkolem vyroben ani přijat.

<a id="wp004"></a>

### WP004 — Jednotný převod desktop scan options do core

- Priorita: P0; lane: CORE; checkpoint: K1; stav: DONE.
- Owner: `/root/wp004_options`; base: `d45997653970929f5f477c6e2dcd70913cb17fe3`; výhradní CORE lease podle karty včetně `run_contract.py`, `desktop_worker.py`, `scan_service.py` a relevantních schemas/tests/docs.
- Závislosti: WP003.
- Kritéria: C08, C15, C21; původní úkoly: AM009, AM017, AM028; funkce: F04, F13, F14, F16, F17, F19, F23.
- Zápis: `tests/test_desktop_options.py`, nové focused round-trip fixtures.
- Lease: `src/attackmap/run_contract.py`, `src/attackmap/desktop_worker.py`, `src/attackmap/scan_service.py`, `schemas/`, `docs/run-contract.md`.
- Kroky: navrhnout additive options pro baseline/suppress file/AI mode/tuning/resource knobs a multi-repo identitu; vytvořit explicitní mapování do application service. Implementace fleet dispatch a AI se dokončí ve WP018/WP014; ještě nepodporované volby capability zakazuje.
- DoD: pro každé nové pole non-default sentinel prokazuje správný převod; meze jednotek, absolutní cesty a neplatné kombinace se validují. Starý klient/schema funguje; žádná duplicitní scoring/orchestration policy v adapteru.
- Ověření: `test_run_contract.py`, `test_desktop_options.py`, `test_desktop_worker.py`, `test_application_boundary.py`; failures před dispatch bez ztráty předchozí generace.
- Důkaz: `docs/verification/windows-parity/WP004/`; 169 focused regressions PASS, finálních 10 alias/schema-echo kontrol PASS a nezměněný WP002 validátor 266 PASS. Root doplnil nativní 1.2 consumer seam a `EngineProtocol.Tests` skončil 102 PASS. Žádný live provider, real scan, package rebuild nebo GUI acceptance.

<a id="wp005"></a>

### WP005 — Nativní options, kompatibilita a engine setup

- Priorita: P0; lane: WINDOWS; checkpoint: K2; stav: MANUAL_PENDING.
- Owner: `/root/wp005_native_options`; base: `d45997653970929f5f477c6e2dcd70913cb17fe3`; nové options/capability/settings modely a test/preview/evidence, shared MainWindow integraci drží root.
- Závislosti: WP004.
- Kritéria: C17, C18, C20, C21, C22; původní úkoly: AM020, AM021, AM026, AM028; funkce: F04, F16, F17, F23.
- Zápis: `NativeScanOptions.cs`, `LocalSettings.cs`, nový `EngineCapabilities.cs` v `desktop/windows/AttackMap.NativeSpike/`; příslušné C# tests.
- Lease: `MainWindow.xaml`, `MainWindow.xaml.cs` pouze integrátor.
- Kroky: propojit capabilities, options a migraci settings; jednoduché bundled engine default, advanced explicit path; disabled funkce s důvodem. Request builder nesmí zapomenout uloženou volbu ani obnovit síťový request při startup.
- DoD: round-trip všech povolených nastavení, unknown/old settings zachovají originál; engine switch invaliduje capabilities. Existing self-exe guard a no-download policy zachovány.
- Ověření: `ReportAdapter.Tests`, `EngineLaunchSpec.Tests`, nové options/capability tests; native choose/save/reopen/unsupported journey a preview.
- Důkaz: `docs/verification/windows-parity/WP005/`; agent i root **54 NativeOptions PASS**, regression **71 ReportAdapter PASS** a **24 EngineLaunchSpec PASS**. Preview build je čistý; root skutečně prohlédl opravený light supported a unsupported stav, po dvou nalezených clipping/contrast opravách je finální 1160×960 light stav čitelný bez překryvu. Shell integration, keyboard/Narrator, dark theme a druhá velikost zůstávají otevřené, proto WP005 není DONE.

<a id="wp006"></a>

### WP006 — Progress, ETA a výběr analyzérů

- Priorita: P1; lane: WINDOWS; checkpoint: K2; stav: MANUAL_PENDING.
- Owner: `/root/wp006_resume`; resume base: `a8c4786`; progress/analyzer a session-test recovery lease, bez MainWindow shell editů.
- Závislosti: WP003, WP005.
- Kritéria: C21, C22; původní úkoly: AM028; funkce: F02, F03.
- Zápis: nový `ScanProgressView.cs`, `AnalyzerSelectionView.cs`, `ScanProgressModel.cs`; focused tests.
- Lease: `EngineSession.cs`, `EngineProtocol.cs`, shell composition.
- Kroky: structured progress callback, per-stage done/total a indeterminate; odhad ETA jen s daty; discovery-backed picker s Automatic, experimental/opt-in/missing a chybou analyzéru.
- DoD: out-of-order/stale events nevrátí procenta ani cizí repo; done analyzéru neukončí scan; žádné automatické instalování pluginů. Filtrovaný seznam nezamlčí vybrané nepřítomné moduly.
- Ověření: `EngineProtocol.Tests`, `EngineSession.Tests`, nové model tests; synthetic stage fixtures a jeden skutečný native scan s progress.
- Důkaz: `docs/verification/windows-parity/WP006/`; 73 pure progress/analyzer checks a 102 EngineProtocol checks PASS, tři synthetic light preview snímky root prohlédl. Obnovení v `recovery-2026-10-20.md` opravilo argumenty a privátní fake-broker staging: **9 session scénářů a 2 argument-negative checks PASS**, root potvrdil hash aktuálního EngineSession; cleanup ověřil 21 markerů a nula živých fake/harness procesů. První 180s timeout je zachovaný odděleně od úspěšného běhu s limitem 420s. Checkbox glyph, shell/real scan, keyboard/Narrator, dark a druhá velikost nadále nemají acceptance; WP006 není DONE.

## Výsledky a uživatelská práce

<a id="wp007"></a>

### WP007 — Typed report projections pro chybějící pohledy

- Priorita: P0; lane: REPORTS; checkpoint: K1; stav: DONE.
- Owner: `/root/wp007_reports`; base: `d45997653970929f5f477c6e2dcd70913cb17fe3`; lease: `ReportAdapter.cs` a `StructureAdapter.cs` pouze tomuto agentovi; žádné shell soubory.
- Závislosti: WP002.
- Kritéria: C11, C12, C23; původní úkoly: AM012, AM013, AM030; funkce: F05–F12, F16, F19.
- Zápis: nové `ReportSections.cs`, `ReportSectionAdapter.cs`, focused adapter tests.
- Lease: `ReportAdapter.cs`, `StructureAdapter.cs`; `models.py`/`report.py` jen pro schválenou chybějící referenci.
- Kroky: explicitní projekce exploitability/path/surface/dependency/CVE/secrets/workflow/taint/analyzers/suppressed/fleet sections. Zachovat source IDs, unknown, limits a generation; pokud engine pole nevydává, žádná náhrada inferencí z textu.
- DoD: exact fixture IDs/count/order a partial notices; bezpečně zpracované malformed/oversized/legacy sections, změna hash odmítnuta. Read-only projection bez rescoring.
- Ověření: `ReportAdapter.Tests`, `C23ReportComposition.Tests`, nové golden adapter tests; JSON contract proti canonical report fixtures.
- Důkaz: `docs/verification/windows-parity/WP007/implementation-2026-10-20.md`; nové golden checks 98 PASS (agent i root), existující ReportAdapter 71 PASS a C23 composition 17 PASS. API je připravené pro pozdější UI composition; to není součástí WP007 acceptance.

<a id="wp008"></a>

### WP008 — Exploitability a Attack paths

- Priorita: P1; lane: VIEWS_A; checkpoint: K2; stav: MANUAL_PENDING.
- Owner: `/root/wp008_risk_paths`; base: `d45997653970929f5f477c6e2dcd70913cb17fe3`; zápis pouze nové view/viewmodel/tests/evidence, bez `MainWindow.xaml(.cs)`.
- Závislosti: WP007.
- Kritéria: C21, C23, C25; původní úkoly: AM030, AM034; funkce: F05, F07.
- Zápis: nové `RiskPathsView.cs`, `RiskPathsViewModel.cs`, focused tests.
- Lease: žádný; integrátor připojí navigaci.
- Kroky: ranked list + evidence detail, filtry route/sink/confidence, core score factors a odkazy na source/finding; candidate a speculative zvlášť.
- DoD: každý fixture path má dohledatelný chain; score/order pochází z core. „Exploitable“ není tvrzení o runtime kompromitaci. Empty vs missing vs filtered rozlišeno.
- Ověření: golden projections, actual view selection + keyboard, screenshoty obou témat a dvou velikostí.
- Důkaz: `docs/verification/windows-parity/WP008/`; model 17 PASS, standalone WinUI preview build 0 warnings/errors. Vizuální/keyboard kontrola je otevřená, protože Computer Use initialization třikrát timeoutovala (agent dvakrát, root jednou); žádný screenshot PASS se nepředstírá.

<a id="wp009"></a>

### WP009 — Inventáře surface, CVE, secrets, CI, flows a analyzers

- Priorita: P1; lane: VIEWS_B; checkpoint: K2; stav: MANUAL_PENDING.
- Owner: `/root/wp009_inventory`; base: `d45997653970929f5f477c6e2dcd70913cb17fe3`; pouze nové inventory view/viewmodel/tests/evidence, bez shell nebo shared adapter editů.
- Závislosti: WP007.
- Kritéria: C21, C23, C25; původní úkoly: AM030, AM034; funkce: F04, F08, F09, F10.
- Zápis: nové controls pod `desktop/windows/AttackMap.NativeSpike/Inventory/`, focused tests.
- Lease: žádný; sdílené modely dodává WP007.
- Kroky: postupné podřezy surface → dependencies/CVE → secrets/CI → flows/analyzers. Tabs/filtry zachovají evidence/source/unknown a count.
- DoD: všechny části F08–F10 dostupné bez otevření raw JSON; secret values se nevypisují; „CVE lookup vypnut“ není „žádná CVE“; selhaný/nepoužitý/nepřítomný analyzér se rozlišuje.
- Ověření: WP002 golden counts, sort/filter/selection, empty/partial/long text; preview každého podřezu.
- Důkaz: `docs/verification/windows-parity/WP009/implementation-2026-10-20.md`; model 64 PASS a standalone WinUI preview build 0 warnings/errors. Root CodeGraph review potvrdil source order/IDs, scalar allowlist a secret-safe projection bez UI joinů/scoringu. Shell zapojení, skutečný visual/keyboard/Narrator review zůstávají otevřené.

<a id="wp010"></a>

### WP010 — Offline diagramy s textovou alternativou

- Priorita: P1; lane: VIEWS_C; checkpoint: K2; stav: MANUAL_PENDING.
- Owner: `/root/wp010_diagrams`; base: `d45997653970929f5f477c6e2dcd70913cb17fe3`; pouze nové diagramové view/model/test/preview/evidence soubory, bez shared project/MainWindow editů.
- Závislosti: WP007.
- Kritéria: C21, C23, C24, C25; původní úkoly: AM030, AM032, AM034; funkce: F11.
- Zápis: nový `DiagramView` a lokální renderer/resources, security fixtures a focused tests.
- Lease: projektový soubor/resource registration integrátorem.
- Kroky: porovnat minimální lokální renderer s existujícím offline Mermaid; zapsat rozhodnutí a dependency/license. Rendering jen vybraného manifest-bound artefaktu, zoom/pan/copy/export a accessible text/list alternativa.
- DoD: bez CDN/network; embedded HTML/script/URL se neprovádějí, malformed/large diagram má poctivý fallback. Hrany nepřibývají vlastní heuristikou UI.
- Ověření: hostile diagram fixtures, síť vypnutá, render běžné/empty/large fixture, keyboard/text alternativa a skutečný vizuální review.
- Důkaz: `docs/verification/windows-parity/WP010/README.md`; agent i root 20 parser/manifest/security PASS, test i standalone WinUI preview build bez warning/error. Native Canvas renderer je offline a používá jen inertní bounded subset s kompletní textovou alternativou. Preview startup neprokázal viditelné okno; visual/keyboard/Narrator/network-disabled runtime a shell/export integrace zůstávají otevřené. Všechny tři diagnostické procesy byly ověřeně ukončené.
- Upřesnění podle zdrojového auditu 23. 10.: shell již `DiagramView` připojuje, ale výchozí `architecture.md` neobsahuje Mermaid blok. Dokončení původního řezu zahrne výchozí dostupný diagram cest/topologie a oddělený slovní souhrn; viditelný runtime důkaz tím nevzniká. Nový strukturovaný explorer/layout má vlastní WP043; tento podklad neuzavírá WP010.

<a id="wp011"></a>

### WP011 — Přehled priorit a propojená navigace

- Priorita: P1; lane: INTEGRATION; checkpoint: K2; stav: IMPLEMENTED.
- Owner: `/root/wp011_overview`; base: `d45997653970929f5f477c6e2dcd70913cb17fe3`; připravit pouze nové overview adapter/control/test/preview/evidence soubory. Shell/MainWindow/resource integraci drží root a closure čeká na manuální WP008/WP009.
- Závislosti: WP008, WP009.
- Kritéria: C21, C23, C25; původní úkoly: AM030, AM034; funkce: F06.
- Zápis: `OverviewAdapter.cs`, nový nativní overview control.
- Lease: `MainWindow.xaml`, `MainWindow.xaml.cs`, app resources.
- Kroky: cards s core counts/top risk, strengths, next actions, coverage/partial badge; hluboký odkaz na finding/path/inventory a návrat bez ztráty selection.
- DoD: source values shodné s reportem, unknown se neukáže jako 0; top actions zachovají core order a evidence; všechna nová views dostupná přehlednou Windows navigací.
- Ověření: `OverviewAdapter.Tests`, C23 fixtures, scan→overview→risk→source journey a preview.
- Důkaz přípravného řezu: `docs/verification/windows-parity/WP011/preparation-2026-10-20.md`; agent i root **18 PASS**, standalone WinUI preview build 0 warnings/errors. Exact counts/core order, unknown stavy a generation/hash-bound callback identity jsou zachovány. WP011 není DONE: shell wiring, návrat výběru, visual/keyboard review a otevřené manuální brány WP008/WP009 chybí.

<a id="wp012"></a>

### WP012 — Suppressed findings a explicitní suppression baseline

- Priorita: P1; lane: TRIAGE; checkpoint: K2; stav: IMPLEMENTED.
- Owner: `/root/wp012_suppression`; base: `d45997653970929f5f477c6e2dcd70913cb17fe3`; bounded nové suppression view/model/test/preview/evidence soubory. Native option binding, shared actions a shell zůstávají root-owned; closure čeká na WP005.
- Závislosti: WP005, WP007.
- Kritéria: C13, C21, C23; původní úkoly: AM014, AM031; funkce: F16.
- Zápis: `SuppressionPanel.cs`, nový suppressed list control, focused tests.
- Lease: native option/settings binding; `suppression_actions.py` jen při doložené mezeře.
- Kroky: vybrat/clear explicitní suppress file pro další scan; zobrazit suppressed records s reason/origin/expiry; zachovat preview/apply/undo a baseline migration.
- DoD: no-suppress funguje nezávisle; chybějící/pozměněná baseline blokuje zápis nebo vyžádá nové preview. Report není po editaci suppression prezentován jako přepočítaný scan.
- Ověření: suppression action suite + adapter/native action tests; skutečný dočasný baseline file, apply→undo→rescan; žádný zápis do Juice Shopu.
- Důkaz přípravného řezu: `docs/verification/windows-parity/WP012/preparation-2026-10-20.md`; agent i root **33 PASS**, standalone preview build bez warning/error. Generace/report hash/baseline path+hash a stale response jsou svázané. Současný broker dovoluje zápis jen do repo-root `.attackmap-suppress.yaml/.yml`; arbitrary selected baseline apply zůstává bezpečně disabled a WP012 není DONE bez explicitního contract rozšíření, WP005 bindingu a real apply→undo→rescan/manual evidence.

<a id="wp013"></a>

### WP013 — Recent repos, comparison a scan baseline policy

- Priorita: P1; lane: HISTORY; checkpoint: K2; stav: IMPLEMENTED.
- Owner: `/root/wp013_history`; base: `d45997653970929f5f477c6e2dcd70913cb17fe3`; bounded nové history/comparison model/view/test/preview/evidence soubory. LocalSettings a shell navigation zůstávají root-owned; closure čeká na WP005.
- Závislosti: WP004, WP005, WP007.
- Kritéria: C04, C13, C21, C23, C30; původní úkoly: AM014, AM031, AM043; funkce: F17, F18.
- Zápis: `HistoryComparisonView.cs`, nový `RecentRepositoriesStore.cs`, focused tests.
- Lease: `LocalSettings.cs`, shell navigation.
- Kroky: last repositories bez automatického scan; previous/custom/none baseline pro nový běh; explicitní fail-on-new-high; historický report/compare/pin zůstává read-only.
- DoD: přesná baseline identity přežije rescan i retention, pinned/current se nemažou; policy failure je completed analysis, nikoli execution failure. Nepřítomné repo zobrazí recoverable stav.
- Ověření: `test_comparison.py`, `test_cli_comparison_coverage.py`, native history/selection tests; tři generace, title/line drift a změna repo během load.
- Důkaz přípravného řezu: `docs/verification/windows-parity/WP013/preparation-2026-10-20.md`; agent i root **28 PASS**, standalone preview build bez warning/error. Repository/generation/hash identity, explicitně zachycený previous baseline a stale callback guards jsou zachované. WP013 není DONE bez WP005/LocalSettings+shell integrace, skutečného history→compare/pin/retention journey a visual/keyboard evidence.

## AI

<a id="wp014"></a>

### WP014 — Připojit všechny AI režimy v desktop workeru

- Priorita: P1; lane: CORE_AI; checkpoint: K3; stav: DONE.
- Owner: `/root/wp014_ai_core`; base: `d45997653970929f5f477c6e2dcd70913cb17fe3`; výhradní CORE_AI lease na desktop worker/scan service/provider options a pouze nezbytné pipeline/test/docs změny.
- Závislosti: WP004.
- Kritéria: C07, C14, C15, C21; původní úkoly: AM007, AM015, AM016, AM033; funkce: F13, F14.
- Zápis: nový desktop AI mapping helper a focused tests.
- Lease: `desktop_worker.py`, `scan_service.py`, `provider_options.py`, `pipeline.py` pouze nutná integrační změna.
- Kroky: None/Review/Hunt/Hunt+verify/Remediate/Triage; parametry jury/effort/speed/backend, validace podporovaných kombinací, reuse ledger/citations. CLI backend pouze přes existující hardened adapter; strict output cap na nevymahatelném backendu fail-closed.
- DoD: všechny režimy produkují správný artefakt nebo typed unavailable/fallback; žádná další provider attempt po vyčerpání; deterministic findings byte/hash invariance; fleet AI odmítnuto.
- Ověření: desktop options + AI budget/hunt/narrative citation/CLI isolation suites, fake-provider dispatch matrix; live důkaz až WP017.
- Důkaz: `docs/verification/windows-parity/WP014/`; široký offline checkpoint **389 PASS, 1 deliberate live-CLI skip**, finální citační/mode rerun **72 PASS** a root narativní kontrola **17 PASS**. Všech šest módů zachovalo shodný `findings.json` (4 871 bytes, SHA-256 `ee071c99076fc80af9d1be8e9243bfb75063f5b52c992e6d9fed52561631af49`). Žádný live HTTP/CLI, native UI nebo package claim; ty vlastní WP015–WP017.

<a id="wp015"></a>

### WP015 — Native AI mode/jury/settings UX

- Priorita: P1; lane: WINDOWS_AI; checkpoint: K3; stav: IN_PROGRESS.
- Owner: `/root/wp015_resume`; resume base: `a8c4786`; native AI/provider settings a 1.3 negotiation lease, shell integraci drží root.
- Závislosti: WP005, WP014.
- Kritéria: C07, C14, C21, C25; původní úkoly: AM033, AM034; funkce: F13, F14, F15.
- Zápis: `ProviderSettingsView.cs`, `ProviderConfiguration.cs`, nové mode/jury controls, focused C# tests.
- Lease: `NativeScanOptions.cs`, settings migration, shell pouze integrátorem.
- Kroky: zvolit mode, lokální endpoint/model a supported tuning; vysvětlit skutečný network/usage dopad a premium fast jen při podpoře. Žádné hardcoded remote model-only omezení.
- DoD: AI off na čistém profilu, uložené credentials protected, switch/reset nikdy neposílá request; nepodporované volby jsou vysvětlené. Všechny controls dosažitelné v malém okně/200% textu.
- Ověření: `ProviderConfiguration.Tests`, `ProviderRoundtrip.Tests`, protected-store tests; vizuální preview + keyboard; secrets sentinel.
- Důkaz dosavadního řezu: `docs/verification/windows-parity/WP015/root-visual-review-2026-10-20.md`; fresh **49 Native AI PASS**, dřívější 54 NativeOptions a 16 ProviderConfiguration PASS jsou oddělené. Final-source capture/clip buildy mají 0 warnings/errors. Dvě skutečné synthetic UI capture journeys prošly, root prohlédl všech 14 PNG, ale překryv záhlaví při scrollování zůstává i po bounds-clip pokusu: visual gate není přijatá. Normální preview bylo na žádost uživatele ponecháno otevřené. Shell/protected-store/manual acceptance a live HTTP chybí; WP015 zůstává IN_PROGRESS.

<a id="wp016"></a>

### WP016 — AI artefakty a poctivý stav verifikace

- Priorita: P1; lane: WINDOWS_AI; checkpoint: K3; stav: IN_PROGRESS.
- Závislosti: WP007, WP015.
- Kritéria: C07, C14, C23; původní úkoly: AM016, AM030, AM033; funkce: F12, F13, F14.
- Zápis: `MainWindow.AiReview.cs`, nové AI artifact projection/view a tests.
- Lease: `SelectedArtifacts.cs` jen pro společnou verified read cestu.
- Kroky: přepínat review/hypotheses/remediation/triage; zobrazit provider/model/mode, complete/partial/fallback, budgets/unknown usage, jury abstentions/inconclusive a citation/support zvlášť.
- DoD: žádné načtení z jiné generace, missing/changed metadata viditelné; model judgement není potvrzená zranitelnost. Remediation nikdy automaticky nemění zdrojový repozitář.
- Ověření: AI fixtures, tampered generation/hash, delayed old response; selection→export binding a actual UI preview.

<a id="wp017"></a>

### WP017 — Skutečné lokální AI end-to-end

- Priorita: P1; lane: LIVE_QA; checkpoint: K3; stav: IN_PROGRESS.
- Owner: `/root` pro provider/UI; aktuální pracovní revieweři GPT-6.1 Sol / medium. Starší candidate base `258adf66a9ec3c5a691868ae67c3a73b08b92c4a` a původní příprava runneru `/root/ultra_native_ai_runner`, base `18fc9b2`, zůstávají historickou evidencí; nová acceptance vyžaduje vlastní source/package identitu.
- Závislosti: WP016, WP024.
- Kritéria: C14, C21, C22, C23; původní úkoly: AM033; funkce: F12–F15.
- Zápis: `docs/verification/windows-parity/WP017/`, malý reproduce script pokud potřebný.
- Lease: LM Studio, nativní app session a konkrétní nový test package výhradně.
- Kroky: jeden native→packaged engine běh každého z pěti režimů nad Juice Shopem s izolovaným profilem; odpočítávat budget, uložit request counts a terminal, otevřít výstup a export.
- DoD: skutečný HTTP + dokončená modelová odpověď pro každý režim, validní manifest/generation a viditelná správná sekce. Fallback, timeout či jen spojení neuzavírá mode jako live pass.
- Ověření: endpoint `http://127.0.0.1:1234/v1`, model `cyberstag-security-26b-a4b-v1`; žádný remote fallback; provider-down/cancel/malformed odděleně od live úspěchů. Po běhu ověřit ukončení vlastněných workerů.
- Předchozí live řez 22. 10.: [Review a Hunt](verification/windows-parity/WP017/astra-live-20261022/) dokončily skutečnou HTTP odpověď a hashově shodný export; [výsledek série](verification/windows-parity/WP017/astra-review-20261022/batch-outcome.md) zachovává tehdejší timeout i vizuální/obsahové mezery.
- Aktuální řez 23. 10.: [checkpoint s přesnými důkazy](verification/windows-parity/RESUME-2026-10-22/checkpoint-2026-10-23.md). Hunt+verify retry 02 na starším kandidátu: partial, 4 reserved / 3 HTTP 200 / 1 timeout s unknown usage, 6652 reported output tokens, remaining 0; úplná jury není PASS. Remediate má scoped live PASS; Triage retry 02 má HTTP 200 a pre-close parity true, ale native exit `0xC000027B`, tedy scénář FAIL. Implementovaný 7200s allowance má pouze cílené offline ověření; finální freeze 02 a nový runtime/live/GUI důkaz zůstávají otevřené.

## Fleet, watch a export

<a id="wp018"></a>

### WP018 — Fleet přes desktop kontrakt a supervisor

- Priorita: P1; lane: CORE_FLEET; checkpoint: K4; stav: IMPLEMENTED.
- Owner: `/root/wp018_resume`; resume base: `a8c4786`; výhradní lease na `desktop_fleet.py` a `test_desktop_fleet.py`; shared worker/service/schemas/publisher pouze po koordinaci s root.
- Závislosti: WP004.
- Kritéria: C06, C08, C09, C10, C28; původní úkoly: AM006, AM009–011, AM040; funkce: F19.
- Zápis: nový desktop fleet adapter, `tests/test_desktop_fleet.py` (nový).
- Lease: `desktop_worker.py`, `scan_service.py`, run schemas, publisher pouze při nutnosti.
- Kroky: repo-set identity + per-child identity/progress/terminal/manifest, reuse serial/parallel fleet service, bounded admission a cancel celé vlastněné větve; unsupported mode preflight.
- DoD: source/frozen serial≡parallel ve všech výstupních formátech; Unicode/spaces/duplicate basename; failed child zachová sibling results a zjevný fleet partial stav. Žádný frozen exe spuštěný jako Python.
- Ověření: `test_fleet_parallelism.py`, `test_fleet_publication.py`, `test_unreadable_and_fleet_failures.py`, nové native broker fixtures a procesová kontrola.
- Důkaz: `docs/verification/windows-parity/WP018/resume-verification-2026-10-20.md`; root schválil odstranění dvou nadbytečných fixture `mkdir`, produkční kód se nezměnil. **38 focused + 29 regression PASS, 1 explicit Windows chmod skip**. Source-worker serial/parallel parita prošla pro all/json/markdown s mezerami a Unicode; fresh frozen parita a reálné owned-process cancellation/cleanup acceptance chybí, proto WP018 není DONE.
- Rozsah fleet16: ověřit celý běh 16 roots při concurrency 1/2/4, explicitní overall/per-child budget a status všech 16 požadovaných children. Dnešní UI default 1 worker/600 s není 16-repo kvalifikace; bounded admission a skutečný memory peak koordinovat s WP034. Selhání/cancel zachová správné sibling artefakty a ověřeně ukončí vlastněné procesy.

<a id="wp019"></a>

### WP019 — Native multi-repo picker a Fleet workspace

- Priorita: P1; lane: WINDOWS_FLEET; checkpoint: K4; stav: IN_PROGRESS.
- Závislosti: WP005, WP007, WP018.
- Kritéria: C21, C22, C23, C28; původní úkoly: AM028, AM030, AM040; funkce: F19.
- Zápis: nové `FleetView.cs`, `FleetAdapter.cs`, `FleetWorkspace.cs`, focused tests.
- Lease: shell/navigation/settings composition integrátorem.
- Kroky: přidat/odebrat repos, duplicates validation, rollup + jednotlivý repo, linked contract detail/provenance, flows/gaps/anomalies a graph. Native folder picker lze opakovat, nemusí kopírovat Mac multi-select.
- DoD: uživatel pozná skipped/failed repo a candidate edge; cross-repo link neotevře nesouvisející source; single→fleet→single nezamění generaci. Nepodporované AI/baseline ovládání vysvětlené.
- Ověření: dva/tři repos, host/port ambiguity fixture, actual native fleet scan se zachyceným výstupem.
- Rozsah fleet16: picker → jeden společný běh → přehled všech 16 identit → detail a graf WP043 → evidence → back. Reprodukovat a opravit GUID child ID ↔ summary slug ↔ canonical root mapování, včetně stejných basename. UI ukáže effective concurrency/budget, child partial/failure a časy snapshotů; žádné tvrzení o společném atomickém snapshotu 16 pracovních stromů.

<a id="wp020"></a>

### WP020 — Watch v nativním Windows

- Priorita: P1; lane: WATCH; checkpoint: K4; stav: IN_PROGRESS.
- Závislosti: WP006, WP013.
- Kritéria: C04, C05, C09, C31; původní úkoly: AM004, AM005, AM044; funkce: F20.
- Zápis: nový nativní watch coordinator nebo malý platform adapter se shared policy; focused tests.
- Lease: `src/attackmap/ui/watch.py` jen pro reuse/extrakci, shell lifecycle.
- Kroky: použít existující output exclusion/debounce/pending semantics; koordinovat přes jeden scan slot; previous-baseline diff. Scope výslovně jeden repo; fleet watch zatím disabled.
- DoD: create/edit/rename/delete spustí správný rescan, burst jeden, změny během scan právě jeden follow-up; cancel/off/switch/close odstraní pending. Vlastní report/retention nevyvolá smyčku.
- Ověření: `test_ui_watch.py` jako regrese starého UI + nové native coordinator tests + skutečný Win32 filesystem journey; unsupported FS notice a worker cleanup.

<a id="wp021"></a>

### WP021 — Volitelné sledování všech repos ve fleet

- Priorita: P2; lane: WATCH; checkpoint: K8; stav: IN_PROGRESS.
- Závislosti: WP019, WP020.
- Kritéria: C31; původní úkoly: AM044; funkce: F21.
- Zápis: fleet watch coordinator + multi-root fixtures/tests.
- Lease: watch coordinator z WP020.
- Kroky: jeden watcher na podporovaný root, bounded pending set, stable repo-set epoch, koalescence změn napříč roots; znovu vyhodnotit cross-repo vazby po změně child.
- DoD: změna v druhém/třetím repo nezmizí; jeden následný fleet scan pro burst, žádný orphan watcher. Změna repo-setu invaliduje staré callbacks. Nedostupný root označí omezení.
- Ověření: live multi-root create/edit/rename/delete + output ignore + switch/close; není podmínkou macOS parity K4.

<a id="wp022"></a>

### WP022 — Export SARIF a kompletní selected-artifact workflow

- Priorita: P1; lane: EXPORT; checkpoint: K2; stav: IMPLEMENTED.
- Owner: `/root/wp022_export`; base: `d45997653970929f5f477c6e2dcd70913cb17fe3`; bounded nové SARIF/selected-export helper/test/evidence soubory. Shared `ExportSelection.cs`, `SelectedArtifacts.cs` a shell dialogy zůstávají root-owned.
- Závislosti: WP007, WP013.
- Kritéria: C10, C21, C23; původní úkoly: AM030, AM031; funkce: F22.
- Zápis: `ExportSelection.cs`, `SelectedArtifacts.cs`, `ReportExport.Tests`, nové SARIF tests.
- Lease: shell export menu a dialog wiring.
- Kroky: přímý SARIF export/open/reveal, export vybraného AI/fleet/diagram artefaktu, jednotné hash-bound čtení. Zachovat existující HTML/PDF/Markdown bez regenerace scoring.
- DoD: exportované bytes odpovídají vybranému artefaktu, stale/tampered odmítnuto; cancel/overwrite/save-error zachová originál. PDF bez browseru vysvětlí dependency, nestahuje ji.
- Ověření: native picker + clipboard/reveal procedura; `SelectedArtifacts.Tests`, `ReportExport.Tests`, SARIF parse a skutečná PDF kontrola obsahu/layoutu při změně exportéru.
- Důkaz přípravného řezu: `docs/verification/windows-parity/WP022/preparation-2026-10-20.md`; agent i root **43 PASS**. Deterministická SARIF projekce a generation/hash-bound export intents chrání traversal/reparse/collisions/tamper/secret data. Žádný skutečný export/PDF/clipboard/open/reveal neproběhl a plný externí SARIF schema/consumer validátor nebyl spuštěn; WP022 není DONE bez shell/WP013 integrace a real export evidence.

## Integrace, distribuce a lidé

<a id="wp023"></a>

### WP023 — Stabilní integrační checkpoint Windows

- Priorita: P0; lane: INTEGRATION; checkpoint: K5; stav: IN_PROGRESS.
- Závislosti: WP006, WP008, WP009, WP010, WP011, WP012, WP013, WP017, WP019, WP020, WP022.
- Kritéria: C01, C04–C15, C21–C23; původní úkoly: AM001, AM028, AM030, AM046; funkce: F01–F24.
- Zápis: shared shell composition, integration fixtures a `docs/verification/windows-parity/WP023/`.
- Lease: shared UI files a build slot výhradně.
- Kroky: integrovat malé controls přes event APIs, žádná souběžná náhrada MainWindow; replay stejného corpus starým/native klientem pro sémantiku; scan→inspect→suppress→rescan→compare→export; failure/cancel/repo switch.
- DoD: žádná lost-feature regrese, žádný stale report/secret leak/orphan; K1–K4 kritéria podložená. Jeden identifikovaný source snapshot a odpovídající nový package candidate.
- Ověření: jednou široká relevantní Python suite a native consumer matrix na stabilním snapshotu, source/frozen/native end-to-end; unit/fake/live/manual výsledky zvlášť.
- Řez 22. 10. 2026: intervalový index v Python taint flow; 275 cílených testů prošlo včetně všech sedmi dříve selhávajících timing případů s původními limity. Explicitní reference/current porovnání celého ScanResult pro 6000 rout je shodné a vstupy zůstaly beze změny. Nezávislé ultra review bez blokujícího nálezu. [Důkazy](verification/windows-parity/WP023/resume-scanner-20261022/README.md). Historický řez nenahrazuje navazující integrační brány.
- Checkpoint 23. 10.: [412 Python, 55 runner testů + 120 subtests a 117 native offline assertions](verification/windows-parity/RESUME-2026-10-22/checkpoint-2026-10-23.md) ověřují nový lokální allowance v cíleném rozsahu. Nejde o nový broad/live/GUI PASS. Freeze 01 je interim; finální freeze 02 a příslušný runtime/package/installed důkaz zůstávají otevřené. [Capture mezery](verification/windows-parity/WP023/astra-gui-20261022/smallcapture-diagnosis.md) a Triage abnormal-exit scénář nejsou uzavřené.

<a id="wp024"></a>

### WP024 — Reprodukovatelné balení a unsigned preflight

- Priorita: P0; lane: RELEASE; checkpoint: K5; stav: DONE.
- Owner přijatého kandidáta: `/root`; base `258adf66a9ec3c5a691868ae67c3a73b08b92c4a`, nezávislé review Astra/high. Historický první preflight vedl `/root/wp024_package` nad base `d45997653970929f5f477c6e2dcd70913cb17fe3`.
- Závislosti: WP001.
- Kritéria: C20, C29; původní úkoly: AM024, AM041; funkce: F23, F25.
- Zápis: release tests/procedury, `docs/verification/windows-parity/WP024/`.
- Lease: `tools/package_native_windows.ps1`, `installer/`, package/freeze helpers po vyřešení počátečního dirty diffu.
- Kroky: required bundled-engine profile, source/toolchain/analyzer lock, payload verification a SBOM; nový package ID, PS 5.1 `.cmd` launcher, self-exe guard; připravit signing seam.
- DoD: nelze omylem vydat „standalone“ bez enginu ani použít stale freeze; sentinel tamper selže. Nový unsigned package lze použít pro WP017, ale není vydáván za signed release.
- Ověření: existující packaging/installer tests, `EngineLaunchSpec.Tests`, installed bundled scan bez Python v PATH na izolovaném test rootu. Žádné přepsání retained package.
- Historický důkaz implementačního řezu: `docs/verification/windows-parity/WP024/implementation-verification.json`; 23 Python release testů PASS, 24 launcher guard kontrol PASS a izolovaný syntetický install/repeat/upgrade/rollback/tamper/uninstall smoke PASS. Tehdy chybějící fresh production freeze a installed bundled scan bez Pythonu v PATH dokládá následující přijetí.

- Přijetí 22. 10. 2026: [nový unsigned kandidát a skutečný installed bundled scan](verification/windows-parity/WP024/astra-fresh-20261022/unsigned-acceptance.md), nezávislý audit 821 stage / 822 installed files / 19 artefaktů; CMD/PS5.1 a native exit 0, owned Jobs prázdné. Žádná clean-host, podpisová, normální-startup nebo lidská acceptance se tím nepřebírá.
- Stav DONE tohoto historicky přijatého unsigned řezu se zachovává. [Nový 7200s kandidát](verification/windows-parity/RESUME-2026-10-22/checkpoint-2026-10-23.md) musí doložit vlastní source-bound runtime/package/installed acceptance; freeze 01 je interim a finální freeze 02 se připravuje.

<a id="wp025"></a>

### WP025 — Podpis a čistý Windows instalační cyklus

- Priorita: P0; lane: RELEASE_QA; checkpoint: K5; stav: OPEN.
- Závislosti: WP023, WP024.
- Kritéria: C29; původní úkoly: AM041; funkce: F25.
- Zápis: release evidence, support/prerequisite/rollback docs.
- Lease: signing/installation slot a čistý host.
- Kroky: platný certifikát/podpis, ověřený podpis payloadu; čistá podporovaná Windows x64 bez dev runtime; install/scan/cancel/export/upgrade/rollback/uninstall, včetně PS 5.1/MotW a zachování dat.
- DoD: skutečné záznamy pro každý inzerovaný OS/architecture a předchozí podporovaný upgrade; absence certifikátu/hostu = BLOCKED_EXTERNAL, ne PASS. Windows C26 se nepřidává.
- Ověření: C29 checklist, hash/signature output, screen/diagnostic evidence a funkční rollback s osobními daty zachovanými. Připravená VM procedura není provedený clean-host test.

<a id="wp026"></a>

### WP026 — Ruční nativní UX, vzhled a přístupnost

- Priorita: P1; lane: HUMAN_QA; checkpoint: K6; stav: OPEN.
- Závislosti: WP023.
- Kritéria: C19, C21, C24, C25; původní úkoly: AM022, AM032, AM034; funkce: F01–F26.
- Zápis: manual checklist, screenshots/review evidence a malé opravy podle ownership.
- Lease: interactive desktop session; případný shared UI edit integrátorovi.
- Kroky: všechny core journeys keyboard-only, Narrator names/order/status, focus návraty, Escape/dialogy, clipboard/reveal, high contrast/reduced motion/200% text; původních 72 visual states + nové pohledy.
- DoD: každý check má skutečný tester/build/platform/result; blocker opraven a cíleně zopakován. Auto accessibility audit/kompilace nesmějí uzavřít manual check.
- Ověření: lidský protokol a prohlédnuté snímky. Study C19 podle původních prahů; širší beta ve WP027. M3 se neotevírá.

<a id="wp027"></a>

### WP027 — Implementovaná studie a skutečná beta

- Priorita: P1; lane: HUMAN_PRODUCT; checkpoint: K6; stav: OPEN.
- Závislosti: WP025, WP026.
- Kritéria: C19, C32; původní úkoly: AM045, AM046; funkce: F26.
- Zápis: consent/protokol, anonymizované výsledky a issue dispositions.
- Lease: žádný.
- Kroky: 10 nových účastníků studie, čtyři týdny bety, 12 lidí alespoň 6/platforma, 100 dokončených/záměrně zrušených runs/platforma; převzít C19 task/visual prahy.
- DoD: doložená reálná data a zero unresolved C32 blockers. Windows scoped verdict oddělen od dvouplatformního C32; macOS absence nezmění práh ani nevygeneruje fiktivní účast.
- Ověření: manuální/consented evidence, reprodukce a opravy incidentů; žádná zapnutá telemetrie bez souhlasu, žádná automatická certifikace po čtyřech týdnech.

<a id="wp037"></a>

### WP037 — Release dossier a jednoznačný supported scope

- Priorita: P0; lane: INTEGRATION; checkpoint: K5; stav: OPEN.
- Závislosti: WP023, WP025, WP026.
- Kritéria: C01–C25, C27–C32 v inzerovaném scope; původní úkoly: AM046; funkce: F01–F26.
- Zápis: nový release dossier, current links v README/handoff, gate-status JSON.
- Lease: hlavní roadmap/status dokumenty.
- Kroky: uvést přesný commit/package/platform, K1–K8 stav, proof links, otevřené experimental families, nepodporované režimy a macOS status. Rozlišit candidate readiness od beta/public acceptance.
- DoD: žádné rozporuplné „current build“, žádné veřejné quality tvrzení bez C27; beta pending brání označení plného C32 za hotový. Kandidát reviewovatelný s rollbackem; publikování je následná autorizovaná akce.
- Ověření: nezávislý reviewer zkontroluje skutečné důkazy, ne jen task checkboxes; link/hash/gate validation.

## Samostatná macOS lane

<a id="wp028"></a>

### WP028 — macOS adapter nového engine kontraktu

- Priorita: P1; lane: MAC; checkpoint: K7; stav: OPEN.
- Závislosti: WP002, WP003, WP004.
- Kritéria: C08–C10, C21–C23, C30; původní úkoly: AM027, AM029, AM030, AM043; funkce: F01, F12, F19, F23, F24.
- Zápis: samostatný `mlaify/AttackMap-mac`: Services/Models/ViewModels a Swift tests; core checkout jen evidence odkazy.
- Lease: žádný core soubor.
- Kroky: pinned mac baseline, capabilities a run adapter, progress/terminal outcomes, current generation/manifest, legacy import, selected exports, retence/pin/protected storage integration.
- DoD: současné macOS funkce neztraceny; není raw stale-file fallback při neplatné generaci. Původní CLI kompatibilita výslovně vymezena; vlastní native UI semantics.
- Ověření: Swift fixtures proti WP002, actual Mac process cancellation/publication. Bez Mac hostu lze dodat zdroje/tests, stav zůstává IMPLEMENTED/host pending.

<a id="wp029"></a>

### WP029 — Skutečná cross-client contract CI

- Priorita: P1; lane: CI; checkpoint: K7; stav: IN_PROGRESS.
- Závislosti: WP005, WP007, WP028.
- Kritéria: C01, C08, C37; původní úkoly: AM025, AM051; funkce: F23, F24.
- Zápis: `.github/workflows/client-contract-fixtures.yml`, CI wiring v mac repo, contract evidence.
- Lease: schemas/fixtures pouze se souhlasem CONTRACT ownera.
- Kroky: připnout fixture/core/mac revize, Python+C#+Swift jobs, supported/previous schema a incompatible major, source/frozen artifact test; explicitní required checks a cache identity.
- DoD: odkazy na reálně dokončené CI běhy pro oba consumers; žádný macOS skip se nezamění za PASS. Změna kontraktu má detekovat broken consumer před vydáním.
- Ověření: jedna záměrně nekompatibilní fixture musí job zablokovat; opravená musí projít. Místní YAML validace sama nestačí.

<a id="wp038"></a>

### WP038 — macOS vlastní release a manuální kvalifikace

- Priorita: P1; lane: MAC_QA; checkpoint: K7; stav: OPEN.
- Závislosti: WP028, WP029.
- Kritéria: C09, C10, C19, C21–C26, C29, C32; původní úkoly: AM029, AM032, AM035, AM036, AM042, AM045; funkce: F25, F26.
- Zápis: mac release/qualification evidence a odkazy v core ledgeru.
- Lease: macOS host, signing/notarization a interactive UI.
- Kroky: runtime na podporovaném macOS, VoiceOver/keyboard, C26 jen macOS, process/publication faults, signed+notarized DMG, install/upgrade/rollback; vlastní participant evidence pro WP027.
- DoD: všechny inzerované kombinace kvalifikované; reference DMG 0.2.3 není důkaz nové integrace. Host/certifikát/lidé jsou viditelná externí závislost.
- Ověření: skutečný Xcode build/tests + signed package a manuální journeys; nic nelze uzavřít Windows smoke výsledkem.

## Core kvalita a škálování

<a id="wp030"></a>

### WP030 — Rozšířit a nezávisle revidovat eval corpus

- Priorita: P1; lane: EVALUATION; checkpoint: K8; stav: IN_PROGRESS.
- Owner: `/root`; base: `d45997653970929f5f477c6e2dcd70913cb17fe3`; auditní řez je dokončen, číselný a lidský rozsah úkolu zůstává otevřený.
- Závislosti: WP001.
- Kritéria: C27; původní úkoly: AM037; funkce: žádná nová UI funkce.
- Zápis: `fixtures/evaluation/`, `docs/benchmark.md`, label-review evidence.
- Lease: žádný detector/scoring soubor.
- Kroky: inventura současných 46 očekávání/13 repos; sbírat production-relevant pozitivní/negativní/clean případy s licencí/proveniencí a nezávislým lidským review; před tuningem zmrazit repo holdout ≥20 %.
- DoD: 30 repos, 300 pozitivních, 300 negativních, 10 clean; každá mature family ≥30/30. Případy se nepřejmenují podle výstupu detektoru. Nedostatek labelů zůstává gap.
- Ověření: `test_evaluation.py`, dataset schema/leakage/duplication audit; actual `attackmap evaluate` raw report, nikoli jen počet fixtures.
- Důkaz dosavadního řezu: `docs/verification/windows-parity/WP030/`; inventory PASS, actual evaluate uložen, root `test_evaluation.py` 27 PASS. Zbývá 17 repos / 275 pozitivních / 281 negativních / 8 clean a nezávislé lidské review.

<a id="wp031"></a>

### WP031 — Opravit slabé rodiny podle holdoutu

- Priorita: P1; lane: DETECTORS; checkpoint: K8; stav: OPEN.
- Závislosti: WP030.
- Kritéria: C02, C03, C12, C27; původní úkoly: AM002, AM003, AM013, AM038; funkce: F05, F07, F08.
- Zápis: konkrétní detector modul a paired fixtures podle reprodukovaného FP/FN.
- Lease: `threat_model.py`, `route_auth_fusion.py`, scoring jen výslovně vymezený řez.
- Kroky: prioritně BOLA/unauthenticated state changes; oddělit unrelated auth/control hints, safe/unsafe varianty a source-role counterexamples; žádné broad rewrite.
- DoD: ≥95 % precision / ≥80 % recall per inzerovaná rodina, samostatné held-out results a intervaly. Nesplněná rodina zůstane experimental, nezmizí z tabulky.
- Ověření: focused mutation/golden suites + frozen corpus evaluate; zachovat původní reprodukce a publikovat změnu TP/FP/FN.

<a id="wp032"></a>

### WP032 — Dokončit service identity a evidence links

- Priorita: P1; lane: CORE_GRAPH; checkpoint: K8; stav: IN_PROGRESS.
- Závislosti: WP002.
- Kritéria: C11, C12, C28; původní úkoly: AM012, AM013, AM039, AM040; funkce: F07, F19.
- Zápis: `contracts.py`, `crossrepo.py`, focused deployment/ownership fixtures a docs.
- Lease: `models.py`, `config_scanner.py`, `report.py` pro nutné additive provenance/reference fields.
- Kroky: auditovat zbývající protocol/namespace/multi-backend proxy případy; explicitní finding→score/evidence reference; ambiguous/fuzzy link ponechat candidate, zachovat alias origins.
- DoD: každá modeled reference edge přesně správná; žádná unsupported observed edge, case-sensitive route rozdíl přežije; UI jen čte core facts. Neodhadovat TLS/mTLS z názvu.
- Ověření: `test_contracts.py`, `test_fleet.py`, crossrepo/merge/ranking suites; tříservisová fixture + config-only aliases s negativními kontrolami.

<a id="wp033"></a>

### WP033 — Snapshot enumerace a úplná invalidace cache

- Priorita: P1; lane: CORE_INDEX; checkpoint: K8; stav: IN_PROGRESS.
- Závislosti: WP002.
- Kritéria: C33, C34; původní úkoly: AM047, AM048; funkce: F01, F24.
- Zápis: `index.py`, `incremental.py`, snapshot/cache tests a docs.
- Lease: `scanner.py`, whole-repo passes, `pipeline.py` a `scan_service.py` podle malého řezu.
- Kroky: odstranit zbylou závislost enumerace na live tree; audit plugin/config/dependency/schema invalidace; explicitní API/native threading místo náhodného environment dědění.
- DoD: 100 generated edit sequences full≡incremental pro findings/provenance/coverage, rename/delete/dependency/config/analyzer upgrade/corruption; mutation ve čtyřech fázích poctivě pinned/incomplete.
- Ověření: `test_snapshot_consistency.py`, `test_incremental.py`, `test_cli_incremental.py`, native round-trip; performance claim až 20 repetitions/mode na dokumentované reference platformě dle C34.

<a id="wp034"></a>

### WP034 — Paměťový spike a fleet resource admission

- Priorita: P1; lane: CORE_INDEX; checkpoint: K8; stav: IN_PROGRESS.
- Závislosti: WP033.
- Kritéria: C09, C35; původní úkoly: AM049; funkce: F01, F19.
- Zápis: resource budget policy, stress harness/evidence a `docs/resource-limits.md`.
- Lease: `index.py`, `scanner.py`, merge/scan service/pipeline; výhradně po WP033.
- Kroky: reprodukovat identifikovaný scan-and-merge peak; zmenšit duplicitní živé struktury/streamovat po měřitelných řezech; finite aggregate-byte default a fleet memory reservations. Rozlišit stage deadline a hard worker timeout.
- DoD: C35 10k/50k/100k proof s declared bytes/graphs; při default scope peak <2 GiB nebo předem reviewovaná měřená změna defaultu podle C35. Každý skip/truncation partial/typed; žádná tichá ztráta pokrytí.
- Ověření: stejný engine/hardware pro srovnání, nová 10k reference, 50k/100k po relevantní opravě, cancel-under-load, sibling admission; jednorázová stará 861.5 MiB hodnota není důkaz této verze. Není Windows C26.

<a id="wp035"></a>

### WP035 — Isolated analyzer host a přesné SDK hranice

- Priorita: P2; lane: SDK; checkpoint: K8; stav: IN_PROGRESS.
- Závislosti: WP034.
- Kritéria: C11, C36; původní úkoly: AM050; funkce: F03, F10.
- Zápis: `analyzer_host.py`, `analyzer_contracts.py`, `sdk/`, malicious-behavior fixtures a docs.
- Lease: `analyzers.py`, provenance merge jen po dohodě.
- Kroky: doplnit zbývající OS resource enforcement a protocol compatibility; odmítnutí forged provenance; explicitní trusted policy. Zachovat extraction-only plugin rozhraní.
- DoD: crash/hang/flood/invalid/memory výsledky mají jméno, sibling results zůstanou; filesystem/network restrictions popsané podle reality. Subprocess a pinning nejsou bezpečnostní sandbox/autenticita.
- Ověření: isolated host tests na podporovaných OS, false-negative containment counterexamples; missing OS proof neuzavírá celou C36.

<a id="wp039"></a>

### WP039 — Kvalifikovat tři ekosystémové vrstvy

- Priorita: P2; lane: ECOSYSTEM; checkpoint: K8; stav: IN_PROGRESS.
- Závislosti: WP031, WP032, WP035, WP042.
- Kritéria: C27, C38; původní úkoly: AM052; funkce: F03, F05, F08, F19.
- Zápis: `ecosystem_node_atproto.py`, `ecosystem_php.py`, `ecosystem_python.py`, fixtures a `docs/ecosystem/`.
- Lease: `analyzers.py` registry, core linking pouze samostatný schválený řez.
- Kroky: rozšířit reference coverage Node/ATProto, PHP/Laminas/Omeka S, Python; dořešit deklarované mezery bez přenosu globálního reasoningu do analyzerů. Ověřit kolize jmen plugin/builtin a provenance actual selected analyzer.
- DoD: původní C38 production-like fixtures a capability matrix, unsupported cases explicitní; high-priority maturity až po C27; každá vrstva evidence-backed, general language layer před thin overlay.
- Ověření: contract suites a labeled reference reviews, Juice Shop non-regression; marker applicability nesmí přidat falešné ekosystémy do nesouvisejícího repo.
- Rozšíření 23. 10. podle [auditu](verification/windows-parity/RESEARCH-2026-10-23-analyzers-graphs/analyzers.md): prioritně Python cross-file mount/Django class-view/re_path, rodičovské prefixy Laminas a vztah Node/ATProto subscription/auth. Každou mezeru nejdřív reprodukovat proti efektivní připnuté implementaci; část Go/.NET oprav je již v připnutých verzích a není novým úkolem. Profily a provenienci vlastní WP042, paired detector FP/FN a maturity zůstávají WP031/WP039.
- Dávka 23. 10. Sol / ultra: Statické parent/child Laminas/Omeka routy a default evidence jsou implementované a ověřené; 90 PHP PASS, negativní alias/namespace případy a nový frozen PHP profil. Python/Node auth a maturity/závislosti zůstávají otevřené. [Důkazy a handoff](verification/windows-parity/WP042/sol-ultra-20261023/README.md).
- Druhá dávka 23. 10. Sol / ultra: Node/ATProto streamMethod/WS a konzervativní per-route auth jsou implementované; paired i actual frozen before/after PASS, bez tvrzení úplné deduplikace nebo maturity. [Důkazy](verification/windows-parity/WP042/sol-ultra-20261023-batch2/README.md).
- Třetí dávka 23. 10. Sol / ultra: Bounded Python mount/auth a Django URLconf rozšíření, 17 + 8 actual frozen případů PASS; C27/C38 a unsupported scope otevřené. [Důkazy a balíček](verification/windows-parity/WP039/sol-ultra-20261023-python/README.md).


<a id="wp040"></a>

### WP040 — Contributor a delivery evidence

- Priorita: P2; lane: DX; checkpoint: K8; stav: OPEN.
- Závislosti: WP029.
- Kritéria: C37; původní úkoly: AM051; funkce: žádná nová UI funkce.
- Zápis: `scripts/verify_setup.py`, `docs/delivery-efficiency.md`, onboarding/flaky evidence.
- Lease: contributor docs a CI při nutnosti.
- Kroky: skutečný clean-runner install stage, tři noví contributors, core ≤30 min / desktop ≤90 min bez prerequisite downloads, osm týdnů lead-time/flaky záznamů.
- DoD: doložené trial/CI výsledky; scaffold a YAML nejsou hotový onboarding; recurring flakes mají opravy, nikoli blanket retry.
- Ověření: reálný setup podle docs a cílený test, anonymizované human records; osm týdnů nelze nahradit syntetickým souborem.

## Rozšíření podle výzkumu 23. 10. 2026

<a id="wp042"></a>

### WP042 — Efektivní katalog analyzérů, profily a aktualizace

- Priorita: P1; lane: ANALYZER_CATALOG; checkpoint: K8; stav: IMPLEMENTED.
- Závislosti: WP003, WP006, WP007.
- Kritéria: C11, C20, C22, C38; původní úkoly: rozšíření na výslovný pokyn uživatele 23. 10.; funkce: F03, F10.
- Zápis: nový capability/catalog přehled a profile fixtures/tests, návrh přesně vybraných plugin update diffů a `docs/ecosystem/` capability matrix. Výzkumný podklad: [analyzers.md](verification/windows-parity/RESEARCH-2026-10-23-analyzers-graphs/analyzers.md).
- Lease: `analyzers.py`, plugin catalog/lock, capabilities/scan options, `AnalyzerSelectionView`, packaging/SBOM; shell a shared kontrakty pouze přes integrátora. Zámky: analyzer_registry, analyzer_catalog, engine_contract, native_analyzer_selection, package_inventory.
- Kroky: inventář zvoleného executable (ne host Pythonu), pinned commit/version a efektivní provenance včetně tří kolidujících jmen; přesné `(priority, name)` a first-seen chování včetně místní výjimky doplnění unknown route auth. Definovat Automatic a explicitní Node/ATProto, PHP/Laminas/Omeka S, Python profily jako verzovaný výběr včetně potřebných base modulů; rozlišit installed/missing/shadowed/applicable/opt-in/selected/executed/failed i load/detect error oproti unmatched. Zachovat kompatibilní výchozí politiku nebo její změnu výslovně zdokumentovat. Vybrat první upstream aktualizaci až po source diffu a reprodukované extraction mezeře. Hlubší Kubernetes posture a protobuf/gRPC/OpenAPI vést v capability matrix jako kandidáty s unsupported scope a vlastním go/no-go, ne jako hotovou detekci.
- DoD: source/frozen inventáře a rozdíly jsou reprodukovatelné a svázané s engine identity; UI ukáže účinnou implementaci a skutečný důvod vynechání. Explicitní profil neztratí base coverage a nezamění experimentální/pouze instalovaný modul za proběhlý. Kolize nemá tichý dopad na tvrzení o schopnostech; změna precedence/defaultu je samostatně přezkoumaná. Alespoň jedna vybraná aktualizace prokáže novou structured extraction na paired případech bez regrese, případně je doložené no-go a konkrétní implementační alternativa pod WP039. Žádné automatické síťové instalace; pluginy zůstávají extraction-only.
- Ověření: registry collision/merge-order a profile contract testy, unknown/missing/opt-in/failure i engine-switch cache invalidace; původní vs aktualizovaný commit a pozitivní/negativní extraction diff. Actual source a frozen `modules --json`, packaged inventory/SBOM + real scan s coverage a Juice Shop non-regression; nové UI vizuálně v Light/Dark a dvou velikostech. Testy a předchozí ZIP samy neprokazují nový kandidát. C27/C38 maturity dále podléhá WP030/WP031/WP039.
- Dávka 23. 10. Sol / ultra: Efektivní katalog/provenance a CLI profily implementované; 266 společných PASS, 2 SKIP, nový engine 15 pluginů / 21 účinných / 3 shadowed; tři whole-report Juice Shop porovnání shodná. Native picker a per-run ledger/profil persistence/package-SBOM zůstávají otevřené. [Důkazy a handoff](verification/windows-parity/WP042/sol-ultra-20261023/README.md).
- Druhá dávka 23. 10. Sol / ultra: Native profile picker/persistence/request1.5, aktuální původ/kolize a reportový execution ledger jsou implementované a ověřené; package/SBOM a whole-task/manual brány zůstávají otevřené. [Důkazy](verification/windows-parity/WP042/sol-ultra-20261023-batch2/README.md).
- Třetí dávka 23. 10. Sol / ultra: Podrobný ledger/live activity a native discovery chyby dokončené; stejný engine/UI kandidát prošel runtime, osmi vizuálními kontrolami a package/SBOM inventářem. Stav IMPLEMENTED, závislosti a ruční/release brány otevřené. [Důkazy a balíček](verification/windows-parity/WP039/sol-ultra-20261023-python/README.md).


<a id="wp043"></a>

### WP043 — Strukturovaný graf závislostí a průzkum evidence

- Priorita: P1; lane: GRAPH_EXPLORER; checkpoint: K2; stav: IN_PROGRESS.
- Závislosti: WP002, WP003, WP007, WP010, WP018, WP044.
- Kritéria: C06, C11, C12, C21, C23, C24, C25, C28; původní úkoly: rozšíření na výslovný pokyn uživatele 23. 10.; funkce: F07, F11, F19.
- Zápis: additive graph contract/fixtures a typed C# projekce, oddělené renderer spike controls/ADR, produkční graph control a focused tests. Podklady: [aktuální grafy](verification/windows-parity/RESEARCH-2026-10-23-analyzers-graphs/current-graphs.md), [renderer research](verification/windows-parity/RESEARCH-2026-10-23-analyzers-graphs/graph-renderers.md), [praktické porovnání Canvas/MSAGL a Cytoscape](verification/windows-parity/RESEARCH-2026-10-23-analyzers-graphs/renderer-comparison.md).
- Lease: `models.py`, `report.py`, schemas/capabilities a report adapter; WP032 vlastní změny významu service identity. `Diagram/`, projekt/resources a MainWindow integruje jeden owner. Zámky: engine_contract, engine_models, report_writer, service_graph, native_report_adapter, native_diagrams, native_project, native_fleet.
- Kroky: nejdřív zmrazit renderer-independent graf emitovaný core: version, stabilní node/edge IDs, druh/směr, evidence basis/confidence/provenance a evidence references; run/generation/snapshot/report hash z existujícího envelope. V1 povinně zahrne jeden fleet 16 repozitářů, celkové repo skupiny → služby/komponenty → konkrétní evidence a modelované risk paths; UI nevytváří hrany z textu ani skóre. Zachovat legacy Mermaid/text fallback. Poté stejná data porovnat v cluster-aware Canvas + MSAGL a Cytoscape.js s compound layoutem (fCoSE, Dagre jen pro vhodnou plochou projekci); obě větve stejně prioritně, ELK pouze po cíleném ověření. ADR zvolí verze/licence/transitive closure/offline payload a podporované limity. Archify jen volitelný kurátorovaný export ze stejných faktů, bez instalační závislosti aplikace na agent skillu/Node.js. Fleet je povinný, data vztahů vlastní WP044. Collapse/expand a agregace zachovají underlying IDs/counts, kind/direction/resolution i proxy a neprokážou novou cestu. Package dependency graf až s opravdovými resolver edges, ne s textem `via`. Celý zachycený model má JSON a grafický export celého přehledu; velký výstup má prověřený vektorový nebo stránkovaný způsob, ne jen screenshot viewportu.
- DoD: celý 16-repo fleet přehled s viditelnou identitou/stavem všech požadovaných roots, hierarchií a drill-down; shodné ID/count/direction/evidence mezi core DTO, grafem a text/list alternativou; layout podle hran, fit/zoom/pan, search, filtry s viditelnými skrytými počty a výběr node/edge → evidence → back. Unknown/empty/malformed/partial/oversized nejsou zaměnitelné. Generace/report hash i cancel/stale callback brání cizímu výsledku. Offline běh bez CDN/nepovolených requestů, inertní labels/URL/HTML a keyboard/Narrator alternativa. Pokud vyhraje WebView2, bounded origin/message bridge a skutečná offline runtime distribuce/clean-host brána. Žádná domnělá runtime/exploit reachability ani nové observed hrany; původní CLI/report artefakty zůstávají kompatibilní.
- Ověření: deterministický 16-repo corpus a skutečný reprezentativní 16-repo scan se všemi child manifests nebo explicitní partial/failure skupinou; stejné basename, multi-service/library repo, collapsed overview → dvě rozbalené propojené repo skupiny → edge → evidence obou stran → back a úplný export. Golden source/contract/adapter parity; cykly, multiedges, disconnected, ambiguity, dangling IDs, dlouhé/hostile labels a wrong-generation. Spike změří layout/interakce/paměť/payload pro 100/300 a 1000/3000 node/edge fixtures a 10000/30000 stress na stejném 16-repo členění, včetně collapse/expand, s poctivým fallbackem; limity se zveřejní podle výsledku, nejde o návrat Windows C26. Finální source-bound build: finding/path → graf → zdroj → back, síť vypnutá, keyboard/Narrator, Light/Dark a dvě skutečné velikosti s vizuální kontrolou. Compilation/unit tests neuzavírají GUI ani Mac acceptance; WP022/WP023/WP024 ověří změněné exporty/integraci/distribuci při začlenění do kandidáta.

<a id="wp044"></a>

### WP044 — Architektonická data a vztahy pro fleet 16 repozitářů

- Priorita: P1; lane: CORE_FLEET_GRAPH; checkpoint: K8; stav: IN_PROGRESS.
- Závislosti: WP002, WP003, WP007, WP032.
- Kritéria: C06, C11, C12, C28; původní úkoly: výslovné upřesnění uživatele 23. 10.; funkce: F07, F19.
- Zápis: additive fleet architecture DTO/fixtures, producer/serialization adapters v `fleet.py`, `contracts.py`, `topology.py` a focused tests; extraction-only fields jen při doložené potřebě. Podklad: [fleet16 requirements](verification/windows-parity/RESEARCH-2026-10-23-analyzers-graphs/fleet16-requirements.md).
- Lease: `models.py`, schemas/capabilities, `report.py`, `crossrepo.py` a linker; WP032 vlastní sémantiku identity. Zámky: engine_contract, engine_models, service_graph, fleet_graph, report_writer, analyzer_sdk.
- Kroky: explicitní repository/child identity map a containment repo→service→component, stabilní node/edge IDs a typed observation/source references. Zachovat existující HTTP/proxy resolution; oddělit containment, deployment, call a dependency vztahy. První non-HTTP řezy: prokazatelný producer/consumer a shared datastore podle qualified identity, source evidence a scope, s explicitní ambiguity. Pokud dosavadní signály nestačí, nejprve additive extraction contract a paired fixtures; nerozšiřovat UI heuristiky. RPC/protobuf/OpenAPI a další nepodporované druhy uvést v capability matrix jako unanalysed, dokud nejsou zvlášť kvalifikované. Zahrnout orphan/library repos, externí komponenty a partial/failed children; per-child snapshoty navázat na jeden fleet manifest bez tvrzení globální atomické konzistence.
- DoD: deterministická projekce celých 16 repo identit a dostupných vztahů bez slučování stejného basename/názvu služby nebo rozdílných namespace/port/protocol. Evidence na obou stranách vazby, unknown/ambiguous nepostoupí na observed; proxy se nezmění v přímou hranu. Sbalená prezentační hrana má úplná underlying edge IDs a oddělené kind/direction/resolution counts; cesta v agregovaném repo grafu se nevydává za souvislý detailní tok. Žádná smyšlená queue/datastore/RPC konektivita, secret values v grafech ani maturity claim z pouhé deklarace. JSON/manifest kontrakt dostupný bez Markdown a legacy fallback kompatibilní.
- Ověření: 16-repo oracle corpus, stejné basename, multi-service/library repo, external/shared component, cycle/proxy/candidate/unresolved a negativní queue/datastore identity případy. Přesná ID/count/endpoints/provenance parity mezi core a serializací, žádné dangling refs nebo unsupported observed edges; serial/parallel normalizované facts shodné. Skutečný reprezentativní fleet běh a native mapping ověří WP018/WP019/WP043 na zapečetěném kandidátu; schema/unit PASS tento runtime nenahrazuje.

## Podmíněná budoucnost

<a id="wp036"></a>

### WP036 — Rozhodnutí o týmovém produktu

- Priorita: P3; lane: PRODUCT; checkpoint: K9; stav: DEFERRED.
- Závislosti: WP027, WP033, WP034, WP040.
- Kritéria: C39; původní úkoly: AM053; funkce: žádná parity mezera.
- Zápis: demand evidence a architecture decision.
- Lease: žádný.
- Kroky: osm týdnů workflow od alespoň tří týmů, porovnání lokálních artefaktů/shared read/remote workers, náklady a soukromí.
- DoD: go jen při alespoň dvou týmech s opakovanou neřešitelnou potřebou a měřitelným pilotem; no-go je platné uzavření rozhodnutí.
- Ověření: lidské rozhovory a artefakty; žádné cloud/microservice přepisování před rozhodnutím.

<a id="wp041"></a>

### WP041 — Podmíněný nejmenší týmový pilot

- Priorita: P3; lane: PRODUCT; checkpoint: K9; stav: DEFERRED.
- Závislosti: WP035, WP036; další podmínka: výslovné C39 go.
- Kritéria: C40; původní úkoly: AM054; funkce: žádná parity mezera.
- Zápis: až podle schváleného rozhodnutí WP036.
- Lease: podle následného threat modelu a návrhu.
- Kroky: nejmenší sdílená schopnost, tenant authorization, audit, retence/deletion a izolované remote jobs pouze pokud součást pilotu.
- DoD: původní C40 cross-tenant testy, restore ≤4 h / data loss ≤24 h, 30denní pilot a předem číselný cost ceiling. Při no-go označit NOT_APPLICABLE s decision linkem.
- Ověření: threat model, access matrix, restore/deletion evidence a skutečný pilot; není součást Windows parity release.

## Zadání kopírovatelné pro agenta

```text
Převezmi pouze WPxxx podle docs/windows-parity-todo.md a JSON backlogu.
Přečti AGENTS.md, nový audit, daný checkpoint a aktuální stav souborů.
Použij CodeGraph před hledáním kódu. Zachovej cizí dirty práci.
Zapiš base commit, ownera a získané file leases; závislosti musí být splněné.
Shrň současné chování a nejmenší řez. Měň jen přidělené soubory.
Použij existující core policy/kontrakty, nevytvářej paralelní scoring.
Spusť focused checks, GUI ukaž a skutečně vizuálně zkontroluj.
Live AI jen LM Studio 127.0.0.1:1234/v1 / cyberstag-security-26b-a4b-v1.
Odevzdej diff, příkazy, výsledky, důkazy, omezení a integrační kroky.
Neoznačuj checkpoint ani jinou platformu za hotovou; integrátor ověří DoD.
```

Handoff záznam musí obsahovat `task_id`, `owner`, `base_commit`, `final_commit_or_diff_hash`, `paths_changed`, `leases_released`, `tests_executed`, `tests_not_executed`, `live_provider_calls`, `manual_checks`, `package_id`, `run_ids`, `evidence`, `limitations` a `next_action`. Údaje, které se na úkol nevztahují, označit explicitně; nepředvyplňovat PASS.
