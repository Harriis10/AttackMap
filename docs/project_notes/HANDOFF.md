# AttackMap — předání vývoje, 16. října 2026

**Windows M3 je dokončené jako funkční beta s uvedenými omezeními. Další fáze je M4.** Uživatel tento rozsah výslovně přijal 15. října 2026. Poslední práce byla úklid pracovního adresáře; tento dokument předává stav po úklidu, nikoli výsledky nového testování.

## 1. Nejdřív přečti a respektuj rozhodnutí

1. [AGENTS.md](../../AGENTS.md): pravidla projektu, testování a delegování.
2. [Roadmapa](../roadmap-2026-2028.md): aktuální rozhodnutí jsou nahoře; obsahuje kritéria C01–C40 a návaznosti milníků.
3. [Implementation TODO](../implementation-todo.md): pracovní úkoly AMxxx a jejich závislosti.
4. [Windows M3 acceptance](../windows-m3-acceptance.md) a [stav bran](../windows-m3-gate-status.json): rozsah uzavření a důkazy.
5. [Windows development](../../desktop/windows/README.md): aktuální build, nástroje a příkazy po úklidu.

Závazná rozhodnutí uživatele:

- **Windows C26 performance qualification je odstraněna.** Nečekat na Windows 11 a nezavádět náhradní povinnou výkonnostní bránu na Windows 10. Diagnostická měření jsou volitelná. macOS C26 tím není změněna.
- **Do M4 se přesunulo** C19 (studie s pěti Windows uživateli), zbývající ruční C21/C25 (workflow, UX a vzhled) a C24 (přístupnost včetně Narratoru). Jsou neověřené, nikoli splněné. Kvůli nim znovu neotevírat Windows M3.
- Uzavření je omezené na Windows funkční betu. Neznamená splnění všech původních M0/M1/M2 podmínek, dokončený macOS, ověření čistého stroje ani podepsané veřejné vydání.
- macOS je samostatná větev dodávky, také v repozitáři `mlaify/AttackMap-mac`; jeho současný stav zde není potvrzen.

**Pozor na historické záznamy:** JSON obsahuje staré checkpointy i staré `gate_accepted: false`. Aktuální je horní scoped acceptance a `latest_package_checkpoint`. Staré `artifact_freshness.current_package`, historický `current_checkpoint`, výsledky matic a starší seznamy blokátorů nejsou aktuální stav dodávky. Staré odkazy na `.pytest_cache` nebo root `dist/` nemusí existovat. Také historická závislost AM041 na AM036 nesmí obnovit odstraněnou Windows C26.

## 2. Poslední Windows build — zachovat

Jediný ponechaný balíček: **`dev-20261015190038-5667bbbf`**, produktová verze **1.5.1**, Windows x64, nepodepsaná vývojová beta.

- [ZIP balíček](../../desktop/windows/artifacts/development-packages/dev-20261015190038-5667bbbf.zip)
- [Spustitelná aplikace](../../desktop/windows/artifacts/development-packages/dev-20261015190038-5667bbbf/app/AttackMap.NativeSpike.exe)
- [Zabalený engine](../../desktop/windows/artifacts/development-packages/dev-20261015190038-5667bbbf/app/engine/attackmap.exe)
- [Instalace a rollback](../windows-development-package.md)

Kořen checkoutu: `C:\Projects\INPROGRESS\AttackMap`. Balíček obsahuje runtime a frozen engine; LM Studio/model součástí není. Zjištěno 19 modulů analyzérů (15 externích a 4 vestavěné).

| Součást | SHA-256 |
| --- | --- |
| ZIP | `66b93d333e5f0342a1b1fc173e52a7d31986f9a469a44d9409ef2ab78be5003f` |
| Native DLL | `65d3b7d4248696a741cc67b04d1b59023b9cedbb7c858cf2dfb4c5860e6fe690` |
| Engine | `81a304b93e1b4f5ff3c762510c362b5f230749f46a522ff0156fef1c8916e870` |

Balíček ber jako neměnný: žádné QA výstupy uvnitř, žádné přepsání novým `publish`. Nový kandidát musí mít vlastní adresář a identitu. Shodné číslo verze samo neprokazuje shodu zdrojů a binárky.

## 3. Co už bylo integrováno

- Nativní WinUI shell a společný Python engine: sken repozitáře, dohled nad během a zrušení, identita běhu, pokrytí, findings, zdrojové lokace, architektura, inventory, porovnání, suppression/undo, export vybraného výsledku a nastavení provideru.
- Kompaktnější UI po uživatelově kritice: toolbar s přirozenou šířkou tlačítek, textová značka místo štítu, nabídky, nastavení skenu a detaily běhu ve flyoutech, seskupené exporty, sbalená suppression, lepší prázdné stavy a responzivní panely. Původní screenshoty s obřími tlačítky nejsou cílový návrh. Ruční UX a přístupnost přesto zůstávají v M4.
- Otevření uložené generace ověřuje přilehlý manifest a navázané Markdown/AI artefakty. Integrita souborů není automaticky důkaz původu z ověřeného brokeru.
- AI review kontroluje reference proti přesnému vybranému sanitizovanému promptu. Neznámé ID neopravuje odhadem. Reference na zdroj bez snapshotových rozsahů zůstávají neověřené; nepoužívá nově přečtené živé soubory jako náhradu důkazu. `claim_support: not_assessed` není potvrzení pravdivosti textu modelu.
- AI je volitelné a ve výchozím stavu vypnuté; nesmí přepisovat deterministické nálezy. Strukturovaná validace citací hunt/jury je samostatná od narativního review.

## 4. Skutečné ověření a jeho hranice

Poslední skutečný test nainstalovaného balíčku nad Juice Shopem s LM Studiem:

- Běh **`da6b4d5767534bcd859d83b68fab8a7c`**, exit 0, **215,83 s**; dokončená odpověď modelu, nikoli fake provider.
- Terminální stav `completed/succeeded/ready`, revision 108, bez protokolových chyb, validovaná generace a current pointer.
- AI Markdown 7 681 znaků; 6 310 vstupních / 4 520 výstupních tokenů. Osm platných producer ID z devíti povolených; deset neověřených zdrojových referencí; podpora tvrzení neposouzena.
- Nativní kontrola otevření výsledku: 18 findings, ověřený manifest, bez neopodstatněného tvrzení o broker původu.
- Poslední cílená regrese: **51 passed / 25,94 s**. Předchozí čtyři chyby očekávání Markdown prefixu a jejich oprava jsou zachovány v důkazech.
- Dřívější celé Python matice jsou historické výsledky svých snapshotů; neprezentovat je jako čerstvý kompletní test posledního balíčku.
- Po úklidu bylo **3 308 testů pouze sesbíráno** (`collect-only`, 5,97 s). To není 3 308 úspěšně spuštěných testů ani nové volání modelu.

Aktuální důkazy:

- [Souhrn kandidáta](../../desktop/windows/verification/windows-beta-candidate-2026-10-15.json)
- [Skutečný installed LM Studio test](../../desktop/windows/verification/installed-beta-lmstudio-reference-validation-2026-10-15.json)
- [Finální cílená regrese](../../desktop/windows/verification/c14-narrative-wrapper-corrected-regression-2026-10-15.json)
- [Ponechané původní důkazy](../../desktop/windows/verification/retained-m3/README.md) a [mapa přesunutých souborů + hashů](../../desktop/windows/verification/retained-m3/relocation-manifest.json)
- Kompletní reálná generace: `desktop/windows/verification/retained-m3/live/output/da6b4d5767534bcd859d83b68fab8a7c/`.

`retained-m3` obsahuje `live/`, `native/`, `engine/`, `regression/`, `visual/`. Historické skripty a protokoly mohou uvnitř stále uvádět původní cesty; přesun není záruka jejich spustitelnosti beze změny. Screenshoty obsahu nenahrazují Narrator ani ověření OS dialogů. Dřívější pokusy o nativní capture timeoutovaly; tyto kroky jsou neověřené, ne úspěšné. Neopakovat bez změny podmínek stejnou nefunkční capture smyčku.

## 5. Úklid a stav pracovního stromu

Adresář byl zmenšen přibližně z **14,108 GiB na 2,621 GiB** (logické velikosti; počáteční součet měl omezení přístupu). Odstraněno přibližně **11,487 GiB** starých runtime kopií, buildů, cache a opakovaných QA výstupů. [Záznam úklidu](../../desktop/windows/verification/workspace-cleanup-2026-10-16.json).

Zůstaly zdroje, dokumentace, udržované testy a malé fixtures, `.git`, `.codegraph`, `.venv`, aktuální balíček a finální důkazy. Testy mají přibližně 1,4 MiB; nebyly plošně odstraněny jen proto, že používají fake provider. Smazané `bin/obj`, root `build/dist` a generovaná UI fixtures lze obnovit buildem.

Nástroje po přesunu: **`.tools/dotnet`** (SDK 8.0.426), **`.tools/dotnet-home`**, **`.tools/nuget-packages`**; Python v **`.venv`**. Tyto nástroje tvoří většinu zbylého objemu a jsou ponechané pro vývoj. Toolchain neukládat zpět do `.pytest_cache`. Nové QA výstupy průběžně uklízet; uchovat jen potřebný finální důkaz.

Při předání: větev **`main`**, HEAD **`4366b40`**, **179 změněných/neversionovaných položek před přidáním tohoto dokumentu**. Významná část dodané práce je v pracovním stromu, ne v HEAD. Nepoužívat `git reset --hard`, `git clean`, hromadné checkouty ani vyhazování untracked souborů. Před další prací znovu přečíst `git status`; samotný checkout HEAD neobnoví dodanou betu.

## 6. Kde navázat v M4

Jde o plánované návaznosti, ne tvrzení, že v uvedených oblastech není žádná implementace. Před změnou ověř aktuální kód a zvol malý dokončitelný řez.

| Oblast | Úkoly / návaznosti | Další konkrétní výstup |
| --- | --- | --- |
| Přesunuté Windows ověření | C19, C21, C24, C25 | Skutečná uživatelská studie, ruční workflow/dialogy/clipboard, klávesnice, focus/Escape, Narrator, kontrast a 200% text. Nesimulovat účastníky ani výsledky. |
| Detekční kvalita | C27; AM037 → AM038 | Nezávislý označený korpus, oddělené held-out repozitáře, metriky jednotlivých rodin a opravy slabých rodin. Roadmapa stanoví nejméně 30 repozitářů, 300 pozitivních a 300 negativních případů. |
| Identita služeb | C28; AM039 → AM040, po AM012/AM013 | Rozlišit službu/protokol/host/port/namespace, explicitní aliasy a nejisté kandidátní vazby; neslučovat služby jen podle podobné cesty. |
| Podepsané vydání | C29; AM041 Windows / AM042 macOS | Podpis, čistý instalační/upgrade/uninstall cyklus, rollback, přesné release vstupy a SBOM. Windows výkon není blokátor. |
| Retence a soukromí | C30; AM043, po AM011/AM018/AM032/AM033 | Retence generací, ochrana current/pinned/aktivních běhů, diagnostický náhled s redakcí, chráněné credentials. Dobrá kandidátní implementační část po auditu současného stavu. |
| Watch / fleet | C31; AM044, po AM005/AM010/AM028/AM029 | Ignorovat vlastní výstupy, debounce a jeden následný běh při změnách, zastavení watcheru při změně workspace, poctivé pokrytí fleet. |
| Vyhodnocení bety | C32; AM045 → AM046 | Skutečná studie a čtyřtýdenní beta podle roadmapy; žádná vymyšlená telemetrie ani automatické uzavření. |

**Doporučený postup:** začni aktuálním stavem a konkrétními hlášenými UX vadami, potom vyber jeden M4 řez (např. AM043 nebo AM039). Implementaci, UI a nezávislé review lze rozdělit do nepřekrývajících se úkolů. M5 snapshot/cache/resource redesign není potřeba spouštět předčasně. Chybějící účastníci či podpisový certifikát nebrání práci na nezávislých částech M4; jejich splnění ale nelze deklarovat bez důkazu.

## 7. Orientace v kódu a pravidla spolupráce

- `src/attackmap/scan_service.py`, `pipeline.py`: společná orchestrace a pipeline.
- `desktop_worker.py`, `desktop_actions.py`, `run_contract.py`, `execution/` pod `src/attackmap`: desktop kontrakt a dohled nad během.
- `artifact_publisher.py`, `artifact_manifest.py`: publikace a integrita generací.
- `llm_review.py`, `review_prompts.py`, `citations.py`, `ai_budget.py`: AI hranice, reference a rozpočty.
- `comparison.py`, `finding_identity.py`, `suppression_actions.py`: porovnání a triage.
- `desktop/windows/AttackMap.NativeSpike/`: nativní UI; hlavní body `MainWindow.xaml`, `MainWindow.xaml.cs`, `MainWindow.AiReview.cs`, `NativeAccessibility.cs`, `ExportSelection.cs`.
- `tests/`, `desktop/windows/*Tests`, `fixtures/desktop-workflows`, `tools/`: udržované ověření a pomocné nástroje.

`.codegraph/` existuje: při hledání/pochopení kódu nejdříve CodeGraph (`codegraph explore` nebo MCP); pokud konkrétní soubor nepokryje, cíleně přečti zdroj. Scoring, evidence a globální reasoning patří do core; analyzéry poskytují strukturované signály a UI je nepřepočítává. Produkt je obranná analýza, ne generátor exploitů.

Při delegování používej **GPT-6.1 Sol (`gpt-6.1-sol`)** pro implementaci a podle výslovného přání uživatele **GPT-6 Astra (`gpt-6-astra`)** pro nezávislý dohled. Přiděl vlastnictví souborů, kontroluj diffs a skutečné výsledky; souhlas agenta není ověření. Průběžně česky hlas konkrétní pokrok. Uživatel nechce další nekonečné testovací kampaně bez viditelného výsledku.

## 8. Příkazy a testovací prostředí

Z kořene repozitáře, PowerShell:

```powershell
$env:DOTNET_CLI_HOME = "$PWD/.tools/dotnet-home"
$env:NUGET_PACKAGES = "$PWD/.tools/nuget-packages"
$env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
$dotnet = "$PWD/.tools/dotnet/dotnet.exe"
& ./.venv/Scripts/python.exe desktop/windows/generate_fixture.py
& $dotnet publish desktop/windows/AttackMap.NativeSpike/AttackMap.NativeSpike.csproj -c Release -p:Platform=x64 --self-contained true -o desktop/windows/artifacts/native-spike
# Příklady cílených kontrol — spouštět jen pokud souvisejí se změnou:
& ./.venv/Scripts/python.exe -m pytest tests/test_narrative_citations.py -q
& $dotnet run --project desktop/windows/SelectedArtifacts.Tests
```

Generátor fixtures vyrábí syntetická UI data, neskenuje reálný repozitář. Po úklidu se projektové assets obnoví při restore. Nové balení řeší `tools/package_native_windows.ps1`; frozen engine musí mít odpovídající verification metadata. Podrobnosti v aktuálním Windows README a package guide.

**Reálný integrační cíl:** `C:\tmp\juice-shop`. Výstupy vždy mimo něj. **LM Studio:** `http://127.0.0.1:1234/v1`, model **`cyberstag-security-26b-a4b-v1`**; bez souhlasu nepřecházet na vzdáleného providera. Testovací nastavení a credentials izolovat od osobních.

Odděluj unit/fixture výsledky, skutečné HTTP požadavky a dokončené odpovědi modelu. GUI změna vyžaduje viditelný preview a vizuální kontrolu; kompilace ani interní aserce vzhled neprokazují. Spouštěj nejmenší relevantní sadu, širší ověření až při stabilním checkpointu. Tento dokument nevyžadoval rebuild, nový scan ani volání modelu.

## Zadání pro navazujícího agenta

Přečti toto předání a aktuální vršek roadmapy/acceptance, ověř pracovní strom a zachovej dodaný Windows balíček i retained-m3 důkazy. Windows M3 už je uživatelem přijaté; pokračuj konkrétní schválenou částí M4, bez obnovení Windows performance gate. Nejprve popiš současné chování a malý zamýšlený řez, potom implementuj, cíleně ověř a ukaž výsledek. Zaznamenávej omezení pravdivě a nevydávej historické testy za čerstvou validaci.
