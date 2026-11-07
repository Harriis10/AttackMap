# Windows build development

Větev: **`codex/windows-build-development`**. Stav popsaný k **7. 11. 2026**.

Tato větev obsahuje vývoj nativní Windows aplikace, její propojení s enginem
AttackMap a sestavení přenosné Windows distribuce. Jde o vývojový checkpoint
s doloženými dílčími výsledky; celkové přijetí produktu řídí
[aktivní Windows roadmapa](docs/roadmap-windows-parity-2026-10-20.md),
[TODO](docs/windows-parity-todo.md) a [backlog](docs/windows-parity-backlog.json).

## Základ porovnání a původ změn

Cílový repozitář je [Harriis10/AttackMap](https://github.com/Harriis10/AttackMap).
Při přípravě měla jeho větev `main` commit
[`611a37951a998be5e9f072ec2c575ab720b5ffa1`](https://github.com/Harriis10/AttackMap/commit/611a37951a998be5e9f072ec2c575ab720b5ffa1).
Porovnávaný uložený stav implementace je
`2d232cb1a0f292ce93b54b07638b5bceb2b0b472`.

- Rozdíl mezi těmito checkpointy zahrnuje **104 commitů**, **6 948 souborů**,
  **2 025 685 přidaných** a **3 508 odstraněných řádků**.
- **66 commitů je převzatá upstream historie**, do společného základu
  `01ded68d4e5dc0b18a48bf14f0532fc6115fa396`.
- **38 commitů vzniklo po tomto rozdělení na lokální Windows větvi**:
  implementace, integrace, opravy a ukládání ověřovacích checkpointů.
- Lokální referenční `origin/main` (`08ae704`) má dalších 41 commitů,
  které tato větev neobsahuje. Tento checkpoint nepředstavuje sloučení
  nejnovějšího upstreamu.

Většina objemu diffu připadá na dokumentaci, fixtures a zachované výsledky
ověřování. Nejde o dva miliony nových řádků produkčního kódu. Rozsah
`src/`, `schemas/`, `installer/`, `tools/` a `pyproject.toml` má dohromady
181 změněných souborů (+48 692 / −2 982 řádků). Podmnožina Windows desktopu,
build nástrojů a installeru obsahuje 556 nově přidaných souborů; s předchozím
rozsahem se překrývá. Tento přehled a jeho odkaz v dokumentačním rozcestníku
jsou samostatná dokumentační změna nad uloženým stavem implementace.

## Co změny přidávají a mění

| Oblast | Výsledné chování a účel | Hlavní zdroje |
| --- | --- | --- |
| Nativní Windows aplikace | WinUI okno s výběrem repozitáře, spuštěním a zrušením scanu, přehledem nálezů, architektury, inventáře, reportů, historie, rizikových cest, evidence, grafů, fleet běhů a suppressions. | `desktop/windows/AttackMap.NativeSpike/MainWindow*`, `App.xaml.cs` |
| Společný engine a broker | CLI a desktop používají společnou orchestraci analýzy. Typované požadavky, události a identita konkrétního běhu nahrazují závislost UI na parsování textového CLI výstupu. Capabilities vymezují podporované operace a schémata 1.0–1.5. | `src/attackmap/pipeline.py`, `scan_service.py`, `desktop_worker.py`, `desktop_actions.py`, `desktop_capabilities.py`, `schemas/`; nativní `EngineSession.cs`, `EngineProtocol.cs`, `DesktopActionRunner.cs` |
| Publikace výsledků a historie | Manifesty a kontrolní součty vážou výstupy na konkrétní engine, repozitář a generaci. Dokončená generace se publikuje atomicky; neúspěšná nebo částečná diagnostika nepředstírá hotový report. Přidána je práce s historií, compare, pin/prune a diagnostikou. | `src/attackmap/artifact_manifest.py`, `artifact_publisher.py`, `run_contract.py`, `desktop_*`; `HistoryComparisonView.cs`, `MainWindow.Workspaces.cs` |
| Scan options a analyzátory | Ukládání a obnovení voleb, konkrétní executable enginu, profily a moduly, timeout, měkký časový budget, izolované procesy, baseline a suppression policy. Katalog a ledger oddělují instalaci, původ, použitelnost a skutečné provedení analyzátoru. | `NativeScanOptions.cs`, `LocalSettings.cs`, `EngineCapabilities.cs`, `AnalyzerSelectionModel.cs`, `AnalyzerSelectionView.cs`; engine katalog, profily a execution ledger |
| Zachycené vstupy a řízení procesů | Snapshot/index/cache/SDK kontrakty stabilizují vstupy analýzy a invalidaci. Dohled nad procesy zpracovává limity, chyby, zrušení a úklid. Izolované procesy nejsou bezpečnostní OS sandbox. | `src/attackmap/` snapshot, index, cache, SDK a execution moduly; nativní launch/session služby |
| Fleet a architektonické vztahy | Paralelní child běhy zachovávají identitu a výsledky jednotlivých repozitářů. Model rozlišuje namespace a vlastníka Service/Ingress, port a protokol backendu i typované reference. Odděluje pozorované HTTP vazby od kandidátů a deklarovaných messaging/datastore asociací. | `src/attackmap/desktop_fleet.py`, `desktop_graph.py`, `contracts.py`, `config_scanner.py`; `desktop/windows/AttackMap.NativeSpike/Fleet/` |
| Grafy a navigace k důkazům | Projekce, filtry, rozbalování a sbalování, agregace, layout a export společného grafu. Nativní a WebView renderer mají vlastní implementace. Výběr prvku propojuje graf s evidencí odpovídající generace. | `desktop/windows/GraphExplorer.*`, `MainWindow.FleetGraph.cs`, `FleetGraphEvidenceNavigation.cs` |
| Watch a suppressions | Explicitně zapínané sledování repozitáře, koordinované opakování scanu a práce s pravidly potlačení včetně náhledu a změn. | `desktop/windows/AttackMap.NativeSpike/Watch/`, `Suppression/`, `MainWindow.Workspaces.cs`; engine action routing |
| Exporty | JSON a ověřený deterministický Markdown odpovídají vybranému reportu. Přidány jsou HTML/PDF a projekce vybraného SARIF. Export ověřuje vazbu na manifest a artefakt. | `ExportSelection.cs`, `ReviewExport.cs`, `ExportPrep/SelectedSarifProjection.cs`, `MainWindow.xaml.cs` |
| Volitelná AI | Konfigurace provideru/modelu a časových limitů, metadata konkrétní odpovědi a oddělené načtení uloženého AI review. Pouhé zobrazení uloženého textu nový modelový požadavek nespouští. Validita formátu reference není potvrzením správnosti tvrzení či zdrojového místa. | `src/attackmap/desktop_ai.py`, `desktop_provider.py`, `provider_options.py`, `citations.py`, `llm_review.py`; `MainWindow.AiReview.cs`, `ProviderConfiguration.cs` |
| Kompatibilita source/frozen | SARIF používá stejný runtime zdroj verze jako CLI. Opraveno je formátování známých AI referencí včetně interpunkce a zachování odpovídajících omezení validace. | `src/attackmap/sarif.py`, `citations.py` a zaměřené testy |
| Windows distribuce | PyInstaller engine, inventáře a vazby zdrojů/analyzátorů/toolchainu, SBOM a RequiredBundled kontrola. Nativní aplikace lze sestavit jako optimalizovaný Windows x64 Release s vlastním .NET a přibaleným Python enginem. Portable marker při obnově správně vybere přibalený engine i při staré uložené cestě. | `installer/`, `tools/generate_release_lock.py`, `generate_release_sbom.py`, `package_native_windows.ps1`; `AttackMap.NativeSpike.csproj`, `EngineCapabilities.cs` |

Převzatá upstream historie přinesla také obecné změny taint/def-use analýzy,
registry zdrojů a sinků, taxonomii, supply-chain kontroly a rozšíření analýzy
secrets/history a CI workflow. Některé soubory Windows fáze následně upravuje;
tyto schopnosti proto nejsou všechny novou Windows implementací.

## Doložené ověření a jeho rozsah

Při přípravě tohoto diffu se produkční kód nezměnil a testy se neopakovaly.
Následující výsledky pocházejí z již dokončených ověřovacích běhů:

- **WP018 / společná pipeline:** přijatý rozsah DONE zahrnuje source/frozen
  formátovou a serial/parallel paritu, fleet16 s workers 1/2/4, fault/cleanup
  scénáře, skutečný C# consumer a Automatic Juice Shop.
  [Protokol](docs/verification/windows-parity/WP018/closeout-20261106/README.md).
- **WP032 / config a vztahy:** 609 Python testů PASS, source/frozen referenční
  běhy a skutečné headless consumer a Juice Shop běhy; přijatý rozsah DONE.
  [Protokol](docs/verification/windows-parity/WP032/closeout-20261107/README.md).
- **Uživatelský Automatic + lokální AI:** skutečný Juice Shop běh dokončil
  analýzu i odpověď modelu za 421 s, s 18 nálezy a jednou cestou. Běžel na
  dřívějším enginu s SHA začínajícím `e5de74f1`.
  [Podklady WP005](docs/verification/windows-parity/WP005/closeout-20261107/README.md).
- **Poslední portable sestavení:** 72 release testů PASS; 21 analyzátorů;
  pět skutečných příkazů již zabaleného nového enginu: version, modules,
  capabilities, atomický broker scan a compare. Vše dokončilo přirozeně
  s exit 0. Ověřeno bylo všech 807 souborů ZIPu i rozbalené aplikace.
  Headless kontrola s produkčními zdroji ověřila portable výběr enginu.
  [Předání sestavení](docs/verification/windows-parity/RELEASE-PORTABLE-20261107/README.md).

Poslední balíček byl sestaven ze zdrojového commitu `18c87db`; `2d232cb`
přidal předávací dokumentaci. Balíček obsahuje .NET 8.0.32, Windows App SDK
2.4.0 a engine 1.5.1 se SHA-256
`788572853653643fcab399c1ab8457071f32753d7d87594b9bc0f98bf29e387a`.
Archiv má 118 353 499 bajtů a SHA-256
`f6e962b417471f948a2ea5fa4c49e34d7948c1c7511843f16c18f53a2ccc2002`.

Portable archiv a podrobné raw důkazy posledního sestavení jsou lokální
výstupy v ignorovaných adresářích `dist/releases/` a
`artifacts/release-portable-20261107/`. Zdrojová větev obsahuje implementaci,
build nástroje a sledovanou dokumentaci; samostatný GitHub Release asset
vyžaduje vlastní publikaci.

## Co zůstává otevřené

Balíček je nepodepsaná vývojová distribuce. Nové GUI posledního portable
balíčku nebylo spuštěno ani nasazeno přes uživatelovu otevřenou aplikaci.
Headless testy nenahrazují kontrolu vzhledu, ovládání klávesnicí či Narratoru,
clean-host/instalační přijetí ani úplnou kvalifikaci rendererů.

Součet 44 aktivních úkolů je 9 DONE, 5 IMPLEMENTED, 5 MANUAL_PENDING,
16 IN_PROGRESS, 7 OPEN a 2 DEFERRED. Například WP005 zůstává MANUAL_PENDING,
WP022 IMPLEMENTED a celé WP043/WP044 IN_PROGRESS. Statické deklarace nejsou
důkazem runtime konektivity; syntetický corpus není reprezentativní produkční
fleet. Přijatý Windows M3 a odstranění Windows C26 zůstávají zachované.

## Jak zobrazit diff

[GitHub porovnání vůči main](https://github.com/Harriis10/AttackMap/compare/main...codex%2Fwindows-build-development)
zobrazuje také dokumentační commit s tímto přehledem. Přesný implementační
diff před přidáním přehledu lze v klonu získat takto:

```text
git diff --stat 611a37951a998be5e9f072ec2c575ab720b5ffa1 2d232cb1a0f292ce93b54b07638b5bceb2b0b472
git diff 611a37951a998be5e9f072ec2c575ab720b5ffa1 2d232cb1a0f292ce93b54b07638b5bceb2b0b472 -- src/attackmap schemas installer tools
git log --oneline 611a37951a998be5e9f072ec2c575ab720b5ffa1..codex/windows-build-development
```

GitHub může u tak rozsáhlého porovnání omezit náhled diffu. Úplné porovnání
je dostupné přes Git nad konkrétními commity; lokálně byl také připraven
soubor `artifacts/remote-windows-development-20261107/windows-development.patch`
s kontrolním součtem a kompletními binárními změnami.
