# Audit Windows, macOS a veřejné dokumentace — 20. října 2026

**Závěr:** hlavní mezera Windows je v propojení existujícího enginu s nativním WinUI a v prezentaci jeho výsledků. Fleet, pokročilé AI režimy, rizikové cesty a inventáře se nemají implementovat znovu v UI. Windows již navíc obsahuje práci na důvěryhodnosti, generacích, retenci, lokálním AI a škálování, kterou veřejné stránky nepopisují nebo popisují zastarale.

Navazující výstupy: [nová roadmapa](roadmap-windows-parity-2026-10-20.md), [podrobné TODO](windows-parity-todo.md), [strojový backlog](windows-parity-backlog.json) a [provenience zdrojů](windows-parity-sources-2026-10-20.json).

## 1. Co bylo skutečně prověřeno

| Podklad | Identita a způsob ověření |
| --- | --- |
| Místní zdroje | `main`, HEAD `d45997653970929f5f477c6e2dcd70913cb17fe3`, produktová verze `1.5.1`. Na začátku auditu změněný `tools/package_native_windows.ps1` a neversionované `.zcode/`; zachovat. |
| CodeGraph | Existující index; průchod `EngineSession`, `NativeScanOptions`, `ScanRequest`, `run_request_file`, `run_scan`, `score_exploitability`, `StructureAdapter`, `OverviewAdapter`, `LoopbackApp` a `_sync_watch`. Doplňkové cílené čtení XAML, konfigurace a částí kontraktu, které nástroj nevrátil. |
| Lokální plán | C01–C40 / AM001–AM054, delivery log do 19. 10., scoped acceptance C13/C14/C30, resource limits a M3 handoff. Staré dashboardy nejsou považovány za aktuální implementační inventář. |
| Nejnovější balíček uvedený v delivery logu | Manifest `dev-20261019192050-b678aee2`: `unsigned-development`, `win-x64`, minimum `10.0.19041.0`, bundled frozen engine `1.5.1`, **21 analyzérů**, run schema `1.0–1.1`. Manifest přečten; celý payload ani instalace nebyly v tomto auditu znovu ověřeny. |
| Veřejná wiki | [Home](https://github.com/mlaify/AttackMap/wiki), Roadmap, Architecture, Generated Docs a vybrané engineering stránky; načtené 20. 10. 2026. Home/Roadmap stále uvádějí `v0.4.27`. |
| Veřejný web | [docs.mlaify.io](https://docs.mlaify.io/), zejména GUI, CLI, feature availability, scanning, LLM, analyzers, SDK a CI. Aktuální obsah načten přímo přes HTTPS. |
| Veřejné releases | GitHub API uvádí core [v0.5.1](https://github.com/mlaify/AttackMap/releases/tag/v0.5.1), publikováno 2. 10. 2026, a macOS [v0.2.3](https://github.com/mlaify/AttackMap-mac/releases/tag/v0.2.3), stejné datum, asset `AttackMap-0.2.3.dmg`. |
| macOS zdroje | Samostatný repozitář, HEAD [`5f2e8b4d84f9dff06e0f87c69c861a434981bd6a`](https://github.com/mlaify/AttackMap-mac/tree/5f2e8b4d84f9dff06e0f87c69c861a434981bd6a), commit 12. 10. 2026. Čtena konfigurace, navigace, view model, watcher, exporty a inventáře. Toto je srovnání zdrojů na HEAD, ne tvrzení, že každý řádek je v DMG 0.2.3. |

Audit je **čtení zdrojů a dokumentace**, nikoli nová runtime certifikace. Nebyl spuštěn nový scan, model, aplikace macOS, čistá instalace ani plná regresní matice. Historické výsledky níže mají vlastní datum a rozsah. Validace nových plánovacích souborů ověřuje odkazy, ID, závislosti a úplnost přiřazení, nikoli funkčnost produktu.

[Záznam strukturální kontroly plánu](verification/windows-parity/plan-validation-2026-10-20.json) obsahuje počet úkolů, pokrytí feature matice a kontrolu acykličnosti závislostí.

## 2. Kterým tvrzením dokumentace nevěřit bez upřesnění

1. Wiki označuje lokální AI jako budoucí fázi 11. Windows už má LM Studio endpoint/model, API integraci a historický dokončený modelový běh. Chybí především další režimy v nativním klientu.
2. Wiki počítá 14 pluginů, web 15 pluginů + 4 builtiny. Lokální engine přidal další vestavěné překryvy; přečtený aktuální package manifest uvádí 21 registrovaných analyzérů. Prostý součet balíčků a builtinů není spolehlivý kvůli překryvům jmen. Počet musí pocházet z konkrétního spustitelného enginu.
3. Web má část funkcí stále v sekci „Unreleased after 0.4.31“. Místní kód už obsahuje strict analyzers, secrets history, snapshoty, cache a další změny. Čísla `0.5.1` a `1.5.1` sama o sobě neprokazují kompatibilitu větví.
4. Wiki tvrdí, že LLM nikdy nedostává raw source; místní prompty mohou obsahovat minimalizované a redigované výřezy. Platná reference není důkaz pravdivosti tvrzení. Narativní `claim_support: not_assessed` je očekávané omezení, nikoli chyba, kterou lze odstranit přejmenováním.
5. Web popisuje fleet spojování podle path/method. Lokální C28 přidává autoritu cíle, aliasy a konfigurační důkazy. Kopírovat starší jednodušší matcher by byla regrese.
6. macOS GUI stránka nevypisuje všechny současné sekce: zdroj obsahuje také Diff, Dependencies, Secrets, CI workflows, Data flows a Analyzers. `CLILocator` navíc preferuje strukturované `attackmap capabilities` a teprve potom parsuje help; tuto CLI capability funkci již místní core má.
7. macOS watch je podle `setFleetRepos` výslovně **single-repo**. Celofleet watch není chybějící macOS parita; je samostatné rozšíření.
8. Starý Windows handoff/README označuje balíček z 15. 10. za aktuální. Delivery log a přečtený manifest z 19. 10. jsou novější. Historická M3 acceptance zůstává platná pro svůj balíček, nepřenáší se automaticky na novou binárku.

Veřejné podklady jsou referencí funkcí. Přijaté lokální evidence, bezpečnostní hranice a rozhodnutí uživatele mají při návrhu přednost před marketingovou formulací webu.

## 3. Matice parity

Legenda: **ANO** = nalezená implementace; **ČÁST** = funkce existuje jen v omezeném workflow nebo obecném zobrazení; **CHYBÍ** = chybí zapojení v prohlédnutém nativním klientu. Ani ANO automaticky neznamená aktuální runtime PASS. „Core“ zahrnuje CLI/společný engine, nikoli všechny desktopové adaptéry.

Zkratky lokálních důkazů:

- **N1** [NativeScanOptions](../desktop/windows/AttackMap.NativeSpike/NativeScanOptions.cs), [run contract](../src/attackmap/run_contract.py), [desktop worker](../src/attackmap/desktop_worker.py).
- **N2** [navigace a ovládání](../desktop/windows/AttackMap.NativeSpike/MainWindow.xaml), [obsluha](../desktop/windows/AttackMap.NativeSpike/MainWindow.xaml.cs).
- **N3** [ReportAdapter](../desktop/windows/AttackMap.NativeSpike/ReportAdapter.cs), [StructureAdapter](../desktop/windows/AttackMap.NativeSpike/StructureAdapter.cs), [OverviewAdapter](../desktop/windows/AttackMap.NativeSpike/OverviewAdapter.cs).
- **N4** [provider UI](../desktop/windows/AttackMap.NativeSpike/ProviderSettingsView.cs), [AI review](../desktop/windows/AttackMap.NativeSpike/MainWindow.AiReview.cs), [AI budgets](ai-budgets.md).
- **N5** [History](../desktop/windows/AttackMap.NativeSpike/HistoryComparisonView.cs), [suppression](../desktop/windows/AttackMap.NativeSpike/SuppressionPanel.cs), [selected artifacts](../desktop/windows/AttackMap.NativeSpike/SelectedArtifacts.cs), [export](../desktop/windows/AttackMap.NativeSpike/ExportSelection.cs).
- **E1** [scan service](../src/attackmap/scan_service.py), [pipeline](../src/attackmap/pipeline.py).
- **E2** [starší Windows server](../src/attackmap/ui/server.py), [watcher](../src/attackmap/ui/watch.py).
- **M1** [macOS ScanConfig](https://github.com/mlaify/AttackMap-mac/blob/5f2e8b4d84f9dff06e0f87c69c861a434981bd6a/AttackMap/Models/ScanConfig.swift).
- **M2** [macOS ContentView](https://github.com/mlaify/AttackMap-mac/blob/5f2e8b4d84f9dff06e0f87c69c861a434981bd6a/AttackMap/Views/ContentView.swift).
- **M3** [macOS ScanViewModel](https://github.com/mlaify/AttackMap-mac/blob/5f2e8b4d84f9dff06e0f87c69c861a434981bd6a/AttackMap/ViewModels/ScanViewModel.swift).

| ID / schopnost | Core / starší Windows | Nativní Windows | macOS HEAD / dokumentace | Důkaz a návaznost |
| --- | --- | --- | --- | --- |
| F01 Single-repo scan, cancel, externí output | ANO | ANO; generace, řízené ukončení, starý výsledek označen | ANO, CLI proces | N1/N2/E1/M3; WP023 regresně zachovat |
| F02 Progress po souborech a ETA | Core posílá done/total | ČÁST: broker přenáší jednotky, `EngineSession` z nich do UI skládá jen stav/stage text | ANO, progress/ETA | N1, EngineSession, M3; WP006 |
| F03 Automatické / ručně zvolené analyzéry | ANO, metadata/discovery | ČÁST: textové názvy modulů; chybí seznam instalovaných, dostupnost a důvod nepoužitelnosti | ANO, `modules --json`, picker | N1/N2, M2/M3; WP003/006 |
| F04 CVE, recall, strict, secrets history | ANO | ANO pro přepínače CVE/recall/strict/history; samostatný CVE inventář chybí | CVE/recall ANO; web neprokazuje všechny novější přepínače v GUI | N1/N2/M1; WP005/009 |
| F05 Findings, detail, source, doporučení | ANO | ANO; kontext, nejistota, live source s varováním | ANO | N3/N5/M2; WP008/023 |
| F06 Overview: priority, strengths, top risk | ANO, structured review | ČÁST: bounded text, silné stránky a next actions jsou přítomné; chybí pohodlné top-risk drill-down a souhrnné karty | ANO, headline counts a top route | N3, M2; WP011 |
| F07 Exploitability a Attack paths | ANO, strukturované výsledky | CHYBÍ samostatné interaktivní pohledy; artefakty lze číst jako text | ANO, dvě sekce | E1/N2/N3/M2; WP007/008 |
| F08 Attack surface | ANO | ČÁST: obecné záznamy Architecture/Inventory, nikoli cílená tabulka s filtry | ANO, route inventory | N3/M2; WP009 |
| F09 Dependencies + CVE detail | ANO | ČÁST: dependencies v obecné Inventory; plný vulnerability pohled chybí | ANO, dependency/CVE tabulky | N3, macOS InventoryViews; WP009 |
| F10 Secrets, CI workflows, Data flows, Analyzers | ANO v reportech | CHYBÍ samostatné pohledy; coverage text nenahrazuje inventář | ANO, čtyři sekce | N2/N3, macOS InventoryViews; WP009 |
| F11 Offline diagramy | Core dodává Mermaid/DOT | CHYBÍ vykreslený diagram; raw Markdown není diagram | ANO, lokální Mermaid resource | N2/N5/M2; WP010 |
| F12 Review a AI review | ANO | ANO, Markdown a metadata vybrané generace | ANO | N4/N5/M2; WP016 zachovat |
| F13 AI Review/Hunt/Hunt+verify/Remediate/Triage | ANO pro single repo | ČÁST: pouze review; worker má `llm=enable_ai`, backend `api` | ANO, všech pět režimů | N1/N4/E1/M1; WP014–017 |
| F14 Jury, effort, fast, backend | ANO v core, omezení dle provideru | ČÁST: call/time/output allowance ano; chybí jury/effort/speed a CLI backend | ANO jury/effort, fast jen podporovaný Claude; backend řeší CLI | N4/E1/M1; WP014/015 |
| F15 Lokální model, endpoint, chráněné klíče | ANO | ANO; explicitní LM Studio konfigurace, chráněné uložení, historická HTTP evidence | Keychain ANO; stejný LM Studio workflow nebyl zdroji GUI doložen | N4 a C14/C30 acceptance; nic nepřepisovat podle staré wiki |
| F16 Suppression, undo, explicitní soubor | ANO | ČÁST: preview/apply/undo a no-suppress jsou přítomné; scan request nemá `suppress_file`, importer čte pouze aktivní `findings` | ANO explicitní baseline a collapsed suppressed findings | N1/N3/N5/M1; WP012 |
| F17 Historie, diff, baseline policy gate | ANO | ČÁST: historie generací, pin a ad-hoc compare ano; scan request nemá baseline/fail-on-new-high | ANO previous/custom baseline, Diff, policy flag | N1/N5/M1/M3; WP004/013 |
| F18 Recent repositories | Starší UI ukládá recents | ČÁST: poslední repo v settings + historie výstupů; není ekvivalent seznamu recent repos | ANO RecentScansStore | N2/N5/M3; WP013 |
| F19 Fleet scan a fleet výsledky | ANO core i starší WebView | CHYBÍ: jeden `repository_path`, picker jedné složky, žádný fleet adapter/view | ANO, multi-picker, FleetView | N1/N2/E1/E2/M1/M3; WP018/019 |
| F20 Watch single repo + diff | ANO ve starším Windows: debounce/pending/Win32 | CHYBÍ ve WinUI | ANO FSEvents; při výběru fleet se vypíná | E2/N2/M3; WP020 |
| F21 Watch všech fleet repos | Starší Windows sleduje první a říká „1 of N“ | CHYBÍ | CHYBÍ; single-repo omezení | E2/M3; WP021 je rozšíření, nikoli parity blocker |
| F22 Export JSON/MD/HTML/PDF/SARIF | Core generuje SARIF a další artefakty | JSON/MD/HTML/PDF ANO; PDF vyžaduje místní Edge/Chrome. SARIF nemá přímou exportní akci | Export/reveal SARIF ANO | N2/N5, macOS ReportExporter; WP022 |
| F23 Engine discovery a capabilities | Strukturované `attackmap capabilities` schema 1 + help/modules existují | Explicitní nebo bundled engine + guard; chybí native feature handshake nad novými funkcemi | Strukturované capabilities, fallback help; locator s PATH/Homebrew | N1/N2, `cli.py:733`, macOS CLILocator; WP003/005 rozšíří existující mechanismus. Nekopírovat automatické hledání spustitelných souborů bez rozhodnutí. |
| F24 Publikace, integrita, retence, diagnostika | ANO novější lokální core | ANO pro manifest/selected generation, keep/pin/export | V prohlédnuté Swift aplikaci nenalezen adapter nových run envelopes/current-generation manifestů | N5, C30, M3; WP028/038, ne downgrade Windows |
| F25 Distribuce | Release tooling/SBOM/rollback ANO | Unsigned development; bundled engine a PS 5.1 launcher opraveny 19. 10.; veřejná kvalifikace otevřená | Web deklaruje signed/notarized DMG; API asset potvrzuje existenci, podpis zde neověřen | Package manifest/delivery log, web GUI; WP024/025/038 |
| F26 UX, přístupnost, uživatelská validace | Není vlastnost core | Otevřené ruční C19/C21/C24/C25/C32 | Zde bez runtime kvalifikace | Handoff a původní kritéria; WP026/027/038 |

### Přesné hranice integrace

`ScanRequest` v application service je bohatší než `RunRequest`/`ScanOptions` v desktop protokolu. WinUI → `NativeScanRequest.Serialize` → `desktop_worker.run_request_file` dnes předává jen menší podmnožinu. Přidání přepínače do XAML nebo do `ScanRequest` samo funkci do nativního běhu nepřipojí. `extra="ignore"` navíc dovoluje ignorovat neznámé pole: novou funkci je nutné před dispatch ověřit capabilities a testem skutečného předání hodnoty.

Fleet AI a baseline/diff kombinace core nyní odmítá; macOS je ve fleet arguments neodesílá. Nový Windows klient musí tyto kombinace vysvětlit a odmítnout před spuštěním. Fleet-global AI budget není přislíbenou součástí parity.

## 4. Co už máme proti staré roadmapě

| Původní kritéria / úkoly | Aktuální zjištění | Zbytek práce |
| --- | --- | --- |
| C01–C07 / AM001–008 | Opravy guardů, scoped evidence, freshness, output isolation, fleet interchange a abstention semantics zaznamenány v delivery logu. | Aktuální release matrix na konkrétním kandidátovi; nezahajovat znovu původní M0 jen podle starých checkboxů. |
| C08–C10 / AM009–011 | Schema 1.0/1.1; Windows contract matrix, 50-cycle process evidence a NTFS interrupted-write evidence z 17. 10. | Nové desktop options/fleet kontrakty, skuteční consumers, macOS a aktuální packaged end-to-end. |
| C11–C12 / AM012–013 | Provenience, conflict matrix, ranking factors a unknown/candidate labels existují. | Širší ownership counterexamples, explicitní finding→score reference místo value-match, doložení cross-format parity. |
| C13/C14/C30 / AM014/016/043 | [Scoped acceptance z 17. 10.](criterion-acceptance-2026-10-17.md) existuje; retenci ani citation ledger nestavět znovu. | Nové režimy nesmějí ztratit hranice acceptance; macOS, ruční UX a specifická omezení zůstávají oddělená. |
| C16–C25 / AM019–035 | Windows M3 uzavřeno jako funkční beta; nativní shell a základní workflow implementované. | Rozšířená feature parita dle F02–F23, C19/C21/C24/C25 ruční queue. |
| C26 / AM036 | **Windows odstraněno rozhodnutím uživatele.** | Žádná náhradní Windows performance brána. macOS C26 zůstává samostatně. |
| C27 / AM037–038 | Eval harness a korpus v0.2.0; delivery log uvádí **46 očekávání / 13 repos**, nikoli požadovaných 300+300. | Nezávislá revize labelů, held-out corpus, per-family metriky a opravy; experimentální status do důkazu. |
| C28 / AM039–040 | Autorita, explicitní aliasy, host/port/proxy konfigurace a tříservisová fixture. | Multi-backend/protocol/namespace nejasnosti, source-backed edge detaily a UI fleet projection. |
| C29 / AM041–042 | SBOM/lock/rollback tooling, bundled engine, executable guard a PS 5.1 launcher. | Podpis, čistý host, upgrade/uninstall, skutečný rollback, samostatné macOS důkazy. |
| C31 / AM044 | Win32 watcher a pending-dirty implementovány **ve WebView**. | Napojení do WinUI; explicitní single-repo rozsah; celofleet watch až navazující úkol. |
| C32 / AM045–046 | Není doložena dokončená participant study / čtyřtýdenní beta. | Skuteční lidé a běhy, žádné agentem simulované výsledky. |
| C33–C34 / AM047–048 | Snapshot identity, captured reads, publication drift check, per-file cache, CLI flag a equivalence tests. | Enumerace přes snapshot, plugin/dependency invalidace, explicitní native wiring, reference-corpus qualification. |
| C35 / AM049 | File/graph/time budgets a stress harness. Historicky 50k ≈ 5 166 MiB, 100k ≈ 10 279 MiB. | Paměťový cíl 2 GiB nesplněn na těchto fixtures; aggregate-byte default je podle aktuální dokumentace stále bez capu, fleet admission otevřená. C35 core nezaměňovat za odstraněné C26 Windows UI. |
| C36–C38 / AM050–052 | Isolated analyzer host, protocol, CI/setup scaffolding a tři nové ekosystémové vrstvy. | Host není security sandbox; OS mezery, skutečné CI běhy, lidský onboarding a detekční kvalifikace. |
| C39–C40 / AM053–054 | Podmíněný týmový produkt stále odložený. | Poptávka/go-no-go před implementací. Nezdržuje Windows paritu. |

## 5. Doporučené pořadí

1. Zafixovat kontrakt, capabilities, report fixtures a vlastnictví sdílených souborů.
2. Viditelný užitek: rizikové cesty, inventáře, diagramy, suppressed findings a pohodlná historie.
3. Zapojit AI režimy přes společný budget/citation model; zvlášť doložit skutečné LM Studio odpovědi.
4. Připojit existující fleet a watch ke stejnému lifecycle/generation kontraktu.
5. Kvalifikovat jeden nový balíček, čistou instalaci a ruční UX. Detekční kvalitu a core resource limity vést souběžně s jasnými release claims.

Nová roadmapa neopakuje již dodané enginové funkce a nesnižuje původní kritéria. Upřesňuje, která část je engine, native integration, platform evidence nebo externí lidská závislost.
