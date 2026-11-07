# Windows portable — předání 7. 11. 2026

Uživatelské zadání: uložit aktuální kód lokálním Git commitem, vytvořit plný
přenosný Windows Release balíček s novým enginem a samostatně uklidit nepotřebné
testovací soubory. Zdrojový checkpoint:
`18c87db9e052811bfe80ff336dd65c9f4454f167`.

## Dodávka

Všechny následující cesty jsou relativní ke kořeni repozitáře.

- Archiv: `dist/releases/AttackMap-1.5.1-windows-x64-portable-20261107.zip`
- Rozbalená aplikace: `dist/releases/AttackMap-1.5.1-windows-x64-portable-20261107/AttackMap-Windows/`
- Spouštěč: `dist/releases/AttackMap-1.5.1-windows-x64-portable-20261107/AttackMap-Windows/Spustit-AttackMap.cmd`
- SBOM: `dist/releases/AttackMap-1.5.1-windows-x64-portable-20261107/AttackMap-Windows/release-sbom.json`
- Původ sestavení: `dist/releases/AttackMap-1.5.1-windows-x64-portable-20261107/AttackMap-Windows/provenance/`

Archiv má **118 353 499 bajtů**, **807 souborů**, SHA-256:
`f6e962b417471f948a2ea5fa4c49e34d7948c1c7511843f16c18f53a2ccc2002`.

Jde o optimalizovaný **Release / Windows x64** s vlastním .NET **8.0.32**,
Windows App SDK **2.4.0** a zmrazeným Python enginem AttackMap **1.5.1**.
Engine nabízí **21 analyzátorů**; jeho 265 souborů je přibaleno v úplnosti.
SHA-256 enginu:
`788572853653643fcab399c1ab8457071f32753d7d87594b9bc0f98bf29e387a`.
Samostatná instalace .NET ani Pythonu není pro tento balíček potřeba.
Interaktivní graf může využívat externí WebView2 runtime; balíček nic neinstaluje
ani automaticky nestahuje.

## Skutečně provedené ověření

- **72 release testů PASS**: `artifacts/release-portable-20261107/release-tests02/`.
- Offline nativní publish ze snapshotu 134 vstupů, shoda s uloženým kódem,
  přibalený runtime a úspěšný cleanup vlastních procesů:
  `artifacts/release-portable-20261107/native-release02/build-proof.json`.
- Standardní RequiredBundled stage a přenosná transformace:
  `artifacts/release-portable-20261107/portable-transform-verification.json`.
- Pět skutečných headless příkazů **finálního přibaleného enginu**: verze,
  moduly, capabilities, atomický broker scan a compare. Vše exit 0 a přirozeně
  Job 0; scan ready a compare completed:
  `artifacts/release-portable-20261107/packaged-engine-proof01/engine-verification.json`.
- Nezávislá kontrola ZIP CRC, každého souboru, rozbaleného obsahu, manifestu
  a portable cest SBOM; 531 nativních souborů + 265 engine + 11 doplňků.
  Bez PDB, logů a uživatelských nastavení:
  `artifacts/release-portable-20261107/independent-final-package/verification.json`.
- Headless C# probe s přesně připnutými produkčními zdroji ověřil skutečný
  portable marker: existující zastaralá uložená cesta byla při obnově nahrazena
  přibaleným enginem, pozdější explicitní volba zůstala zachována. Jde o
  source-linked kontrolu, **nikoli skutečný start běžného GUI**. Vazby zdrojů
  a sestavení: `artifacts/release-portable-20261107/independent-final-package/evidence-binding.json`.

Souhrnné předání a navázané hashe:
`artifacts/release-portable-20261107/portable-ready.json`.
Předchozí neúspěšné pokusy zůstaly zachované; jejich záznamy nebyly přepsány.

## Hranice a úklid

Balíček je **nepodepsaná vývojová distribuce**, nikoli podepsané či celkové
roadmapové/release přijetí. Nové GUI nebylo spuštěno; nebyla provedena nová
vizuální, accessibility, instalační ani clean-host akceptace. Nebyl odeslán nový
požadavek modelu. Balíček nebyl nasazen přes otevřenou uživatelskou aplikaci;
její adresář a původní engine zůstaly beze změny.

Úklid byl proveden po ověření portable balíčku. Odstraněno bylo všech **291**
ověřených adresářů: **18 114 souborů / 6 598 493 016 bajtů (6,145 GiB)**,
bez přeskočených cest či chyb. Před odstraněním proběhla kontrola hranic
repozitáře, odkazů, sledovaných souborů a pozorovaných závislostí běžících
procesů. U 14 starých rozbalených aplikací byla znovu ověřena přesná shoda
každého souboru se zachovanou zálohou ZIP.

Samostatně bylo odstraněno **64 adresářových symbolických odkazů** ze starých
pytest běhů a následně tři prázdné kořenové složky. Všechny tyto operace byly
nerekurzivní; cíle odkazů se při unlinku neprocházely. Ověření postupu na
vlastních nových odkazech potvrdilo zachování cílového souboru.

Zachovány zůstaly zdrojové testy a fixtures, potřebné offline závislosti,
reporty a důkazy, záložní ZIPy, nový portable balíček i celý adresář běžící
uživatelské aplikace WP005. Starý balík s dodatečným unikátním souborem nebyl
do úklidu zařazen; neznámý Git bundle také zůstal zachován.

Podrobný skutečný výsledek a přesné cesty:

- `artifacts/release-portable-20261107/cleanup-execution.json`
- `artifacts/release-portable-20261107/pytest-current-unlink-execution.json`
- `artifacts/release-portable-20261107/pytest-current-unlink-plan.json`

Nezávislá kontrola po úklidu prošla: odstraněné cesty skutečně chybějí, všech
807 souborů nového balíčku i archiv mají správné hashe, 285 engine/release
vstupů a 134 nativních vstupů odpovídá sestavení. Původní aplikace, všech 265
souborů jejího enginu a dokončený uživatelský scan
`f2a53980402a46558303d30828cf7287` zůstaly beze změny. Git před uložením
tohoto záznamu neobsahoval žádnou změnu či smazání sledovaného souboru.
Doklad: `artifacts/release-portable-20261107/post-cleanup-verification.json`.
