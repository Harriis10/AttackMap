# WP018 — dokončeno 7. 11. 2026

**DONE — fleet kontrakt a supervisor.** Práce začala 6. 11. na výslovný nový pokyn uživatele dokončit jeden z implementovaných úkolů. Závislost WP004 je DONE. Výchozí commit: `9b8e12d40d8d19ed5e9d07b7ec4d04b643513796`, větev `main`. Ostatní pozastavené úkoly se tímto pokynem neobnovují.

Strojově čitelný výsledek, identity a SHA-256 důkazů jsou ve [verification.json](verification.json). Raw výsledky zůstávají v `artifacts/wp018-closeout-20261106/` a jednotlivých `artifacts/wp018-20261106-*`.

## Dodaná implementace a ověření

Dosavadní produkční fleet implementace prošla chybějícím skutečným ověřením. Přibyly opakovatelné nástroje:

- `tools/verify_wp018_closeout.py`: skutečné CLI a desktop broker běhy; serial/parallel porovnání reportů, grafu a exportů; přesné identity/hashe; source/schema snapshoty; nezměněné vstupy a OS memory peaks.
- `tools/verify_wp018_native.py`: skutečné failed-child, cancel, EOF a timeout scénáře s platnou předchozí publikovanou generací a procesovým pozorováním.
- `tools/verify_wp018_csharp.py` a testový `LiveFleet.cs`: headless průchod produkčními `FleetSession`/`FleetWorkspace` do skutečného enginu.
- `tests/test_wp018_closeout_verifier.py`: negativní kontroly změn provenance, významu dat, pořadí/počtu záznamů a neplatných časových údajů.

Produkční zdrojové soubory nebylo třeba opravovat. Testový `Program.cs` má nový volitelný přepínač `--real-engine`; původní testovací režim je ověřený.

| Ověření | Skutečný výsledek |
| --- | --- |
| Relevantní source regrese, čtyři soubory | **114 PASS / 1 Windows chmod SKIP**, exit 0, 139,09 s |
| Negativní kontroly důkazů | **19 PASS**, 1,92 s; dřívější překrývající běhy se nesčítají |
| Nativní model/protokol a QA vstupy | **73 + 17 PASS**, console build 0 warnings/errors |
| CLI source a fresh frozen | Každý **6/6 PASS**: all/json/markdown × workers 1/2, tři roots |
| Desktop source a fresh frozen | Každý **3/3 PASS**: 16 roots × workers 1/2/4, všech 48 child výsledků |
| Failure/cancel/EOF/timeout source a frozen | Každý **4/4 PASS**, platná předchozí generace i všechny její bytes zachované |
| Skutečný C# consumer → engine | **Source i frozen PASS**, oba přesné child manifests, přirozený Job active 0 |
| Automatic Juice Shop + 15 fixtures, 120 s | Oba transporty 16/16; Juice Shop explicitně částečný před suppress |
| Automatic Juice Shop + tiny sibling, 600 s | **Oba PASS**, 2/2, ledger dokončený, limit nevyčerpán, bez analyzer/pipeline errors |

Source skutečný dvourepozitářový běh trval 122,33 s, frozen 118,89 s. Oba zachovaly zdroje analyzovaných repozitářů. Dva mediální soubory nad 2 MB byly podle běžné politiky vynechány; agregovaný počet souborů není unikátní pokrytí. Není tvrzeno prohledání všech souborů.

## Fresh frozen původ a shoda

Standardní `WP024/fresh_freeze.py --build` vytvořil nový immutable snapshot, ověřil instalované bytes všech 15 připnutých analyzérů proti lokálním wheels a úspěšně dokončil standardní current-source gate. Všech 284 release inputs a 11 schémat zůstalo shodných i po runtime kampani. TOC dokládá 128 core modulů ze snapshotu. Root znovu přepočítal všech 265 souborů payloadu, celkem 44 082 914 bytes.

Engine: `.tmp/wp018-closeout-freeze-20261106-01/dist/attackmap/attackmap.exe`

SHA-256: `7d9a370d5a1d0f23c8e037039a1a00b29fdeb7e55fdf2541ac9dd81c61f5fba0`

Standardní proof: `.tmp/wp018-closeout-freeze-20261106-01/build-proof.json`. Build log a PyInstaller warnings jsou zachované. Unsigned engine není podepsaný distribuční balíček ani schválení release.

## Přesný význam přijetí

Schema 1.4 nemá volbu output formátu a používá canonical JSON/all artefakty; CLI a desktop matice ověřují své skutečné cesty. Porovnání zachovává celé reporty, provenance, parent fleet graf a obsahy Markdown/DOT/SARIF. Normalizují se pouze tři validované ledger clock paths včetně přesných scan kopií uvnitř reportu a ověřené výstupní adresáře. Změny identity, významu, pořadí a počtu záznamů porovnání neprojdou.

Failure vede na `partial`, cancel/EOF na `cancelled`, overall timeout na `failed`. Incomplete parent se nepublikuje jako ready/current. Dokončení sourozenci mají ověřené manifests. Timeout 3 s nastal před přijetím repo children a dokládá overall deadline supervisoru, nikoli mid-scan soft budget. Samostatné 120s Juice Shop běhy dokládají explicitní částečné pokrytí po soft budgetu.

Ve všech finálních bězích se vyžaduje **přirozený Job active 0 před nouzovým cleanupem**. U fault/C# scénářů navíc pozorované vlastní PID nejsou v následném OS census. Job memory peaks jsou měření konkrétních vstupů, nikoli vynucený paměťový limit nebo uzavření C35.

Nezávislý reviewer znovu kontroloval raw reporty, parent/current a child identity, manifests, všechny bytes předchozích generací, procesové výsledky a source/frozen semantiku. Review a jejich hashe jsou ve `verification.json`.

## Reprodukce a zachované neúspěchy

Veškeré nástroje vyžadují nové výstupní adresáře. Z kořene repozitáře lze spustit:

```powershell
& .venv/Scripts/python.exe -m pytest tests/test_desktop_fleet.py tests/test_fleet_parallelism.py tests/test_fleet_publication.py tests/test_unreadable_and_fleet_failures.py tests/test_wp018_closeout_verifier.py -q -p no:cacheprovider --basetemp artifacts/wp018-repeat-new-temp
& .tools/wp024-freeze-venv/Scripts/python.exe tools/verify_wp018_closeout.py --engine .tmp/wp018-closeout-freeze-20261106-01/dist/attackmap/attackmap.exe --output artifacts/wp018-repeat-new-matrix --suite all --timeout 900 --budget 60
& .venv/Scripts/python.exe tools/verify_wp018_native.py --engine .tmp/wp018-closeout-freeze-20261106-01/dist/attackmap/attackmap.exe --frozen --output artifacts/wp018-repeat-new-faults --large-files 256 --seed-previous
```

Přesné requests, příkazy, výstupy a task-owned dvourepozitářový launcher jsou v raw evidence; nový fresh freeze se připravuje standardním WP024 helperem s novým výstupem a platným analyzer auditem.

Původní temp ACL/encoding setup chyby, chybné porovnání kopií clocks a skripty s neplatným sentinel pointerem zůstaly zachované. Pouze finální seeded scénáře ověřují skutečný `current-generation.json`; staré sentinel pokusy tuto ochranu neprokazují. Schválené opakované testy neměnily ACL. Starý vlastní helper byl ukončen podle ověřené přesné identity PID.

## Samostatné zbývající brány

WP018 neuzavírá WP019 UI/named profiles, produkční reprezentativnost fleet16, C35 paměťové defaulty, C36 OS sandbox/plugin crash-hang containment, C27/C38 kvalitu analyzérů, GUI/manual/clean-host/platform ani release přijetí. WP043 rendering zůstává FAILED. Další roadmapový bod vyžaduje samostatné pověření; uzavření WP018 jej automaticky nespouští.
