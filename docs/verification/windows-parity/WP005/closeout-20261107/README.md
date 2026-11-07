# WP005 — skutečné uživatelské ověření, 7. 11. 2026

WP005 zůstává **MANUAL_PENDING**; `whole_task_acceptance=false`.

[verification.json](verification.json) a reprodukovatelný `collect-manual-evidence.py` svazují zachované důkazy kontrolními součty. Kolektor pouze čte artefakty a pět výslovně určených osobních JSON souborů; žádné testy, scany, HTTP ani GUI akce neopakuje.

Modelová oprava capabilities je ověřena samostatnými C# sadami: NativeOptions 81, EngineLaunchSpec 46 a ReportAdapter 76 kontrol. Nejde o počet GUI testů. Aktuálních 134 nativních vstupů odpovídá připnutému build snapshotu.

Uživatelský Save3/reopen2 zachoval `config`, timeout120, budget45 a izolaci; screenshot ukazuje obnovené hodnoty. Pozdější Saved4 vznikl úpravou po znovuotevření, proto se u něj netvrdí obnovení. Jeho Automatic/1800/AI požadavek byl nezávisle porovnán s uloženým záměrem, preflightem a skutečným požadavkem workeru.

Skutečný běh `f2a53980402a46558303d30828cf7287` dokončil analýzu za420,921s: katalog21 analyzérů, 7 succeeded a14 skipped, žádné analyzer errors; 18 deterministických nálezů a1 cesta. Platná aktuální generace váže21 artefaktů. Uživatel výslovně povolil zapnutí AI a místní model `recursivesi/flint`; produkt uložil dokončený API výstup s1 rezervovaným voláním a usage5448 vstupních/19692 výstupních tokenů. To dokládají skutečná metadata a neprázdný výstup, nikoli samostatný HTTP wire záznam. Požadavek neobsahoval soft budget; runtime použil výchozích600s bez překročení.

AI text má původní neplatné reference s koncovou dvojtečkou, neověřenou podporu tvrzení a zdrojová umístění. Pozdější source oprava formátování a její100 testů/offline proof jsou oddělená dávka; nemění zachovaný text, metadata ani uživatelův enginee5de. WP022 candidate562d je další samostatný metadata checkpoint.

Light Options je skutečný snímek1266×792. Advanced890×954 je ořez, **nikoli druhá velikost okna**. Dark Reports1903×1039 má uživatelem potvrzený screenshotový artefakt; aplikace je podle uživatele v pořádku a další rendering kontrola se neprovádí. Exportovaný core Markdown má přesných17352 bajtů a SHA256 `99767f71e640efa588d9de5d7f3ca3edb226cdd199211eff87f5462598d63d3e`, shodný s kanonickým artefaktem. Samostatný AI Markdown má7761 bajtů; jeho export se netvrdí.

Oba neúspěšné120s běhy zůstávají zachované. Jejich počáteční AI checkpoint není důkazem, že později neproběhl HTTP požadavek. Pět konkrétních osobních JSON souborů má nezměněný obsah; nejde o obecnou izolaci profilu, historie, credentials či WebView.

Otevřené ruční brány: keyboard/focus, Narrator, unsupported-engine průchod a dosud nepozorované Dark Options/druhá skutečná velikost okna. C27, release a WP026 studie se nepřebírají. Všechny kliky provádí uživatel; ComputerUse/Sky/CUA a nativní automatizace jsou zakázané. Uživatelské okno musí zůstat otevřené; kolektor s procesy nijak nemanipuluje.

Finální společný backend kandidát s opravami SARIF a interpunkce citací je popsán v [WP017 protokolu](../../WP017/citation-label-20261107/README.md). Nebyl nasazen do otevřené aplikace.
