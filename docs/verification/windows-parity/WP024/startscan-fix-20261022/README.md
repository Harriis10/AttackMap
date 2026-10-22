# Oprava Start scan v portable buildu — 2026-10-22

Opravený build je ve stejné veřejné složce
`C:\Projects\FINISHED\AttackMap-Windows-Portable-20261022`.
Spouštěč zůstává `Spustit-AttackMap.bat`; otevřel opravenou aplikaci také
z pracovního adresáře `C:\Windows`. ZIP vedle složky obsahuje stejnou opravu.

## Příčina a změna

Běžné spuštění načetlo z osobního `NativePreview/settings.json` existující
starý engine z `AttackMapDevelopment/versions/dev-20261017075020-59465a5e`.
Předchozí fallback vybíral přibalený engine pouze tehdy, když uložená cesta
neexistovala. Starý engine sice odpověděl `attackmap 1.5.1`, ale požadavek
`desktop-action` ukončil s exit 1 bez výsledku. Reprodukce je v
`legacy-action-reproduction/`. To vysvětluje zobrazenou chybu
„Desktop action ended without a result“.

Portable instalace s platným manifestem nyní při startu vybere vlastní
`engine/attackmap.exe`. Vadný nebo neúplně rozbalený balíček vrací konkrétní
chybu. Osobní nastavení se nepřepisuje; ruční pozdější volba enginu a běžné
neportable spuštění zachovávají dosavadní chování. BAT nastaví pracovní
adresář na svou složku. Manifest a návod deklarují automatickou volbu enginu
jen pro build ověřený přes běžnou startovací větev bez přepsaných nastavení.

Dřívější testy s explicitním enginem nebo izolovaným nastavením tento stav
neověřovaly. Nový test proto obnovuje skutečný profil s existující starou
cestou a volá skutečný produkční handler Start scan. Nemá přepínač enginu ani
náhradní nastavení a ponechává původně zapnuté AI, CVE a recall.

## Provedené ověření

| Ověření | Výsledek |
| --- | --- |
| NativeOptions.Tests, syntetické regresní případy | 63 kontrol prošlo |
| `pytest tests/test_portable_preview_package.py`, syntetické balení | 15 testů prošlo za 2,94 s |
| Nový kandidát, běžný osobní profil | scan dokončen za 183,594 s; 40 nálezů |
| Nasazená kopie FINISHED, běžný osobní profil | scan dokončen za 153,321 s; 40 nálezů |
| Skutečné HTTP požadavky / dokončené odpovědi modelu | 2 / 2, po jedné v každém scanu |
| Osobní settings.json | zachován; kandidát má i kontrolu hashe před spuštěním a po ukončení procesu |
| Interaktivní spuštění přes veřejný BAT z jiného adresáře | exit BAT 0; otevřené okno AttackMap, PID 5180 |

Oba scany analyzovaly `C:\tmp\juice-shop`; reporty zůstaly mimo cílový
repozitář v běžném AppData výstupu. Použily lokální LM Studio
`http://127.0.0.1:1234/v1`, model `cyberstag-security-26b-a4b-v1`.
Nešlo jen o nastavení příznaku AI: vlastní transportní záznamy dokládají
POST `/v1/responses`, přijetí HTTP odpovědi a neprázdný dokončený text.
Hashy transportních záznamů a výstupů ověřuje existující transportní verifier.
Úplné reporty jsou lokální externí artefakty; zde jsou uchovány jejich
manifesty, metadata a AI review. Ověření lze zopakovat bez sítě:

```powershell
.venv\Scripts\python.exe docs/verification/windows-parity/WP024/startscan-fix-20261022/verify-evidence.py
```

`summary.json` obsahuje generace, cesty a hash reportů. Shodný hash statického
reportu v obou bězích je očekávaný; generace a AI odpovědi jsou samostatné.
Kontrolují se i všechny položky `sections` a `compatibility_exports`.
AI text je poradní; validní reference ani dokončení modelu nepotvrzují
správnost jeho tvrzení (`claim_support: not_assessed`). CVE bylo zapnuté;
tento důkaz samostatně nepotvrzuje nové síťové volání CVE služby.

## Identita a nasazení

Native build: `integrated-20261022-portable-startscan-fix`.
Všech 80 native vstupů zůstalo během publish nezměněných. Engine B-J zůstal
beze změny. ZIP má 117 615 810 bajtů; balíček má 825 souborů včetně manifestu
a 824 položek manifestu. Kopie byla před nasazením porovnána po bajtech.

| Artefakt | SHA256 |
| --- | --- |
| Native EXE | `1796e973b40b37b643a535e80804ab389d84e2191413267b6ce7944539824854` |
| Native DLL | `07b7815e5908f969f20b34719bffcbb0681e14a5807f24698f79ea62249780e0` |
| Přibalený engine | `ee90e44a35d283326fe3821666e71b33fbd0a1eb3aa6844e827d9d4206ea7195` |
| Opravený ZIP | `79a14e259707f89c12a2327798af7365e2da0da85aaaac78ae3dd8e143ef80dd` |

Původní složka a ZIP jsou zachovány vedle veřejné kopie jako
`AttackMap-Windows-Portable-20261022-before-startscan-fix` a stejnojmenný ZIP.
`staged-copy.json`, `replaced.json` a `interactive-bat-launch.json` dokládají
kopírování, výměnu a spuštění. Zdrojový opravený ZIP je
`desktop/windows/artifacts/AttackMap-Windows-Portable-20261022-startscan-fix.zip`.

## Rozsah důkazu

Nativní neprázdné capture obou dokončených běhů byly vizuálně zkontrolovány:
plné tmavé produktové UI, Findings 40 of 40, Engine completed, načtená nová
generace. Jde o WinUI RenderTargetBitmap se scope uvedeným v JSON záznamech.
Computer Use runtime selhal při vytváření kernel assets i po jednom resetu.
Proto netvrdíme fyzické kliknutí myší, manuální OS vizuální akceptaci ani
ověření přístupnosti; handler byl spuštěn opt-in QA instrumentací přes
běžnou startovací větev. `acceptedManualUi` a `acceptedAccessibility` jsou false.

Jde o cílenou opravu vývojového portable preview. Tento záznam neuzavírá
test na druhém čistém PC, podepisování, macOS ani celou roadmapu. Další
scany se po ověření samy nespouštějí; poslední interaktivní okno je ponecháno
uživateli.
