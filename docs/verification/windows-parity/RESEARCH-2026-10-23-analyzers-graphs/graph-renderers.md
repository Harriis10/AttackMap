# Vestavěné grafy závislostí — rešerše 23. 10. 2026

**Následné upřesnění:** [16-repo architektonický celek](fleet16-requirements.md) povyšuje fleet grouping/collapse/evidence na povinnou acceptance. Obě větve mají stejně prioritní spike; původní native-first preference níže není přijetím technologie pro tento rozsah. Cytoscape posoudit také s compound layoutem fCoSE, nikoli jen plochým Dagre.

Stav: **výzkum a návrh spike, bez implementace nebo runtime acceptance**. Nebyl spuštěn build, GUI ani AI provider; nebyly instalovány závislosti. Zdroje byly čteny online 23. 10. 2026. Toto není nový samostatný plán: závazné zařazení práce musí provést integrátor v aktuální roadmapě/TODO/backlogu.

## Doporučení

Pro skutečný prohlížeč závislostí uvnitř AttackMap doporučuji renderer-independent strukturovaná data z core a krátké porovnání **nativní WinUI vizualizace s layoutem MSAGL** proti **Cytoscape.js + Dagre v lokálním WebView2**. Nativní varianta má přednost, pokud splní stejné funkční a výkonnostní brány; Cytoscape je konkrétní kandidát pro bohatší interaktivní průzkum. **ELK přidat pouze tehdy, když spike prokáže potřebu složitější hierarchie/portů.** Konečný výběr knihovny zatím není proveden.

Archify má smysl jako volitelný export vysvětlující architektury, s deterministickým vstupem z již existujících faktů. Jeho veřejné materiály popisují agent skill a renderovací/validační pipeline, nikoli podporovaný SDK kontrakt pro průběžnou aplikací řízenou aktualizaci grafu. Vložit výsledné HTML do aplikace je technicky představitelné, ale host bridge, identita běhu, aktualizace, bezpečnost a produktová integrace by byly prací AttackMap. Jde o závěr z přezkoumané dokumentace, ne o tvrzení, že upstream takovou integraci zakazuje. [Archify README](https://github.com/tt-a1i/archify#readme)

Doložený evidence režim Archify navíc připíná veřejné soubory/řádky ke Git commitu; lokální snapshoty a manifesty AttackMap vyžadují vlastní integraci. [Archify source-evidence popis](https://github.com/tt-a1i/archify#readme)

## Co již existuje a jaký rozsah doplnit

Aktuální [WP010](../../../windows-parity-todo.md#wp010) požaduje offline diagramy, zoom/pan/copy/export, textovou alternativu a poctivý fallback. Jeho stav je `MANUAL_PENDING`; nové rendererové rozhodnutí nesmí samo uzavřít otevřené vizuální/keyboard/Narrator brány. [WP032](../../../windows-parity-todo.md#wp032) vlastní přesnost service identity a evidence links; UI nesmí odvozovat nové závislosti ani měnit candidate na observed.

CodeGraph před čtením kódu ukázal tento zdrojový stav:

- `desktop/windows/AttackMap.NativeSpike/Diagram/DiagramModel.cs`: inertní parser omezené Mermaid syntaxe; limit 120 uzlů / 240 hran; deklarované uzly a hrany ve vstupním pořadí; jednoduchá třísloupcová mřížka. Model nese ID/popisek uzlu a zdroj/cíl/popisek/operátor hrany, nikoli plný kontrakt evidence a selekce grafu.
- `desktop/windows/AttackMap.NativeSpike/Diagram/DiagramSelectionReader.cs`: pouze lokální manifest-bound artefakty `architecture.md`, `attackmap-paths.md`, `attackmap-topology.md`; čtení kontroluje identitu výběru a nesmí načítat sourozence jen podle konvence názvu.
- `desktop/windows/AttackMap.NativeSpike/Diagram/DiagramView.cs`: nativní Canvas/ScrollViewer, tlačítka zoom/pan, úplná textová alternativa a copy/export event; tento průzkum **nepotvrzuje vzhled ani celé propojení do shellu**.

Rozšíření proto znamená skutečný graph explorer se stabilní selekcí, filtry, dohledáním vztahu a otevřením evidence, nikoli pouze vzhledově lepší vykreslení Markdownu. `MainWindow`/sdílené resources musí nadále integrovat jediný owner podle aktivního plánu.

## Porovnání kandidátů

| Kandidát | Ověřená schopnost upstreamu | Použití v AttackMap a omezení | Licence |
| --- | --- | --- | --- |
| Archify | Typed JSON IR → samostatný HTML/SVG artefakt, validace a interakce nad autorsky dodanými vztahy; README popisuje i source-evidence režim a last-good preview. | Vhodný pro vysvětlující export. Agentem zvolená topologie nesmí nahradit core facts. Udržovaný aplikační live-graph SDK kontrakt nebyl v přezkoumaném README doložen. | [MIT](https://raw.githubusercontent.com/tt-a1i/archify/main/LICENSE); zachovat notices a prověřit konkrétní distribuované části. |
| Cytoscape.js + Dagre | Graph API, eventy, viewport, compound nodes a PNG/JPEG/JSON export; Dagre adaptér poskytuje orientovaný layout, zejména DAG/stromy. | Nejsilnější posuzovaný webový kandidát pro přímý průzkum. Filtry a propojení evidence dodá AttackMap. Cykly musí zůstat fakticky zachované i při layoutu; layout není důkaz toku. Canvas sám neprokazuje přístupnost. | [Cytoscape MIT](https://raw.githubusercontent.com/cytoscape/cytoscape.js/master/LICENSE), [Dagre MIT](https://raw.githubusercontent.com/dagrejs/dagre/master/LICENSE), [adaptér MIT](https://raw.githubusercontent.com/cytoscape/cytoscape.js-dagre/master/LICENSE). |
| Cytoscape.js + ELK | ELK je layout engine; vrstvený layout je určen i pro směrové grafy s porty a má podporu Web Workers. Existuje Cytoscape adaptér. | Záložní varianta pro složitější strukturu. Samotný ELK nerenderuje ani nedodává aplikační interakce. Chování compound nodes a přenos portů/routingu přes zvolený adaptér se musí ověřit, nelze je odvodit jen ze schopností ELK. | [elkjs EPL-2.0](https://raw.githubusercontent.com/kieler/elkjs/master/LICENSE.md), [adaptér MIT](https://raw.githubusercontent.com/cytoscape/cytoscape.js-elk/master/LICENSE). |
| Mermaid | Diagram DSL → SVG; přístupné title/description; konfigurovatelné security levels a limity vstupu. | Zachovat kompatibilní reportový/exportní formát. Persistentní produktová selekce, hledání, filtrování a evidence bridge vyžadují aplikační vrstvu. `strict` není náhrada za bezpečný host. | [MIT](https://raw.githubusercontent.com/mermaid-js/mermaid/develop/LICENSE). |
| WinUI + MSAGL core | Oddělený .NET layout engine a drawing model; dokumentované hotové viewery jsou WPF a Windows Forms. Core projekt cílí `netstandard2.0`. | Přirozená cesta zachovávající nativní shell. Layout lze posoudit odděleně od WinUI kreslení; není doložen hotový drop-in WinUI 3 viewer. Hit testing, viewport/virtualizace, selekce, AutomationPeers a export jsou vlastní práce. Kompatibilitu skutečného NuGet closure musí ověřit spike. | [MIT](https://raw.githubusercontent.com/microsoft/automatic-graph-layout/master/LICENSE). |

Podklady schopností: [Cytoscape API](https://js.cytoscape.org/), [Dagre adapter README](https://github.com/cytoscape/cytoscape.js-dagre#readme), [ELK README](https://github.com/kieler/elkjs#readme), [ELK adapter README](https://github.com/cytoscape/cytoscape.js-elk#readme), [Mermaid accessibility](https://mermaid.js.org/config/accessibility.html), [Mermaid configuration](https://mermaid.js.org/config/schema-docs/config.html#securitylevel), [MSAGL README](https://github.com/microsoft/automatic-graph-layout#readme), [MSAGL core project](https://raw.githubusercontent.com/microsoft/automatic-graph-layout/master/GraphLayout/MSAGL/AutomaticGraphLayout.csproj).

**MSAGL kompatibilita ověřená pouze z metadat:** NuGet aktuálně nabízí `Msagl 1.2.1`, layout-only balíček s targetem `.NET Standard 2.0`, bez deklarovaných package dependencies a s vypočtenou kompatibilitou `net8.0-windows`. Lokální `AttackMap.NativeSpike.csproj` má `net8.0-windows10.0.19041.0`/`win-x64`. To je rozumný kandidát ke spike, nikoli důkaz kompilace či runtime v této aplikaci. Release package a aktuální upstream source mohou mít odlišnou dependency closure; vybírat a auditovat přesnou distribuovanou verzi. [MSAGL NuGet metadata](https://www.nuget.org/packages/Msagl/1.2.1)

Licenční rozhodnutí musí pracovat se skutečně zamčenými balíčky a transitive closure, ne jen s touto tabulkou. EPL-2.0 u distribuovaného ELK vyžaduje dostupnost příslušného source a informace, jak jej získat, plus uchování licence/notices; nelze jej označit pouze jako MIT podle licence adaptéru. [EPL-2.0 §3](https://raw.githubusercontent.com/kieler/elkjs/master/LICENSE.md)

## Navržená produktová hranice

Následující body jsou doporučený design AttackMap, nikoli slíbené vlastnosti knihoven:

1. **Graph DTO z core:** verze schema, run/repository/generation/snapshot/manifest identita, stabilní node/edge ID, typ vztahu a směr, observed/inferred/candidate, confidence/provenance a explicitní evidence references. Neznámé hodnoty zůstanou neznámé. Zdrojem nejsou LLM popisky ani HTML.
2. **Renderer je projekce:** node/edge selection, hledání, typové filtry, zvýraznění upstream/downstream a zvolené cesty, legendy a fit/reset. Path trace musí uvádět, zda jde pouze o dosažitelnost v modelu; netvrdit runtime reachability či exploitability bez core evidence. Collapsed group uvádí počty a umožní rozbalení bez ztráty původních ID.
3. **Nativní evidence panel a text/list alternativa:** stejná selekce a data jako v grafu; klávesnicí dostupné uzly/hrany a `Open evidence`. Host ověří allowlisted ID proti právě zvolenému reportu a otevře existující source/evidence cestu. Renderer nesmí zasílat libovolný filesystem path, URL nebo příkaz k vykonání. Chybějící evidence se označí, nedopočítává.
4. **Výměna výsledku je atomická:** request/generation token a cancel; odmítnout opožděný layout/callback starého běhu. Během načítání nebo chyby nesmí starý graf působit jako nový výsledek. Last-good lze ponechat jen pod výslovnou starou identitou. Poloha/filtry se mohou obnovit pouze při kompatibilní identitě a existujícím ID.
5. **Obousměrné propojení:** nález/cesta/inventory → graph selection → evidence → návrat se zachovaným kontextem. Graf nemění core scoring ani service linking. Export váže obraz/DTO/text k témuž běhu a přizná viditelné filtry/omezení.

## Offline host a distribuce

Webová varianta musí používat pouze balené, verzované skripty/fonts/styles/worker files. Microsoft podporuje lokální content mapping ve WebView2; využít jej jako pevný vlastní origin a žádný lokální HTTP server nevyžadovat. [WebView2 local content](https://learn.microsoft.com/en-us/microsoft-edge/webview2/concepts/working-with-local-content)

Navržené požadavky: CSP bez `unsafe-eval`, pracovníci jen z balíčku, žádné externí obrázky/fonty/CDN, blokace neallowlistovaných requests/navigací/nových oken/downloadů/permissions, žádné host objects a žádné reportem dodané HTML/JavaScript. Povolena je pouze aplikací distribuovaná logika; reportové řetězce jsou data. Zprávy mají úzký allowlist (`selectNode`, `selectEdge`, `openEvidence`, stav layoutu), schema/size limity, kontrolu originu a aktuální generation. Posílat serializované JSON pomocí host API, nevkládat řetězce do vykonávaného skriptu. Tyto zásady odpovídají doporučením Microsoftu k originům, validaci zpráv a konkrétním API místo obecných proxy. [WebView2 security](https://learn.microsoft.com/en-us/microsoft-edge/webview2/concepts/security)

Offline JS assets nejsou totéž jako offline dostupný browser runtime. WebView2 musí být přítomný: Evergreen má offline installer; Fixed Version se přibaluje a jeho aktualizace vlastní distributor. Microsoft uvádí u Fixed Version další velikost přes 250 MB. Volba vyžaduje clean-host/offline test a plán bezpečnostních aktualizací; nepatří do tichého přidání knihovny k rendereru. [WebView2 distribution](https://learn.microsoft.com/en-us/microsoft-edge/webview2/concepts/distribution)

Nativní varianta browser runtime nepotřebuje, ale ani nativní Canvas automaticky nezaručuje výkon nebo přístupnost. Zachovat bezpečné čtení manifest-bound artefaktů a omezení práce pro všechny varianty.

## Velké grafy a přístupnost

Cytoscape výslovně upozorňuje, že velké grafy, složité styly, hrany a vysoký pixel ratio zhoršují výkon; doporučuje mimo jiné batching a omezení animací. Žádný počet uzlů zde není upstream garantovanou kapacitou AttackMap. [Cytoscape performance](https://js.cytoscape.org/#performance)

Nejdřív zobrazit souhrn a zvolenou službu/okolí, jasně uvádět skryté počty; uživatel může expandovat nebo přepnout na úplný seznam/export. Layout se počítá mimo UI thread, má timeout/cancel, bounded paměť a cache podle grafové identity + verze layoutu. U ELK je doložena podpora workerů, nikoli to, že vybraný adapter sám splní potřebnou cancel/timeout politiku. [ELK worker API](https://github.com/kieler/elkjs#usage)

Title/description v SVG pomáhají, ale nenahrazují ovladatelný seznam uzlů/hranic/vztahů. Pro obě varianty musí existovat nativní alternativa s úplnými popisky, směrem, typem, confidence a evidence akcí; testovat Narrator, keyboard-only, high contrast, 100/150/200% scale a reduced motion. Nepřebírat a11y PASS z existence ARIA ani `AutomationProperties`.

## Doporučené pořadí práce a brány pro roadmapu

| Řez | Závislosti a samostatné vlastnictví | Měřitelný výstup |
| --- | --- | --- |
| G1 — graph contract | WP007 + WP032, jeden core/schema owner; přezkoumat potřebu additive kontraktu přes WP002/WP003. | Golden parity mezi zvoleným core grafem, DTO a list alternativou: shodná ID, počet, směr, provenance; žádné vymyšlené hrany. Negativní fixtures na fuzzy identity, dangling refs, cykly, case sensitivity a chybějící evidence. |
| G2 — renderer spike/ADR | G1 a WP010; samostatné nové candidate controls, bez paralelní editace shellu. | Stejná data a stejné workflow ve WinUI+MSAGL a Cytoscape+Dagre; měření, skutečné screenshoty/visual review a tabulka tradeoffs. ELK pouze pokud cílený případ odhalí potřebný rozdíl. ADR vybere jednu variantu, inventář licencí/payloadu a odstranitelnost prototypů. |
| G3 — explorer + evidence | G1/G2 + WP009/WP011; shell integrátor. | Klávesnice i pointer dokončí finding → graph node/edge → evidence → back; stejné run/generation a selection. Filtry/collapse přiznávají skryté položky. Stale callback po repo/run switch nepřepíše view. |
| G4 — security/offline/a11y | G2/G3 + WP010/WP022; packaging owner pro případný WebView2. | Hostile labels, HTML/script/URL/directives/paths jako inertní data; invalid/oversized graf má fallback. S odpojenou sítí 0 nepovolených requestů; ověřený start na čistém cíli. Narrator/keyboard/high-contrast/scale evidence oddělená od unit testů. |
| G5 — měření spike a integrace | G3/G4; WP023 + WP024, případně WP025 pro clean-host. | Review měření konkrétního rendererového spike: dokumentovaný corpus, reference stroj, runtime/build identity a počet opakování; cold/warm layout, interakce, peak memory, UI stalls a cancel/fallback. Podporované limity stanoví aktivní plán podle výsledků. Bundle/SBOM/manifests a cílené regression scénáře existujících diagramů. Žádné prohlášení macOS parity bez samostatného ověření. |

**Kandidátní měření rendererového spike, nikoli release brány:** na zdokumentovaném referenčním Windows stroji porovnat například 100/300 a 1 000/3 000 node/edge corpus; zaznamenat první použitelnou interakci po předání DTO, cold/warm layout, latenci selekce/filter, paměť a cancel. Přidat 10 000/30 000 stress corpus, u něhož může být výstupem explicitně omezený subgraf + úplný list/export. Tyto velikosti jsou zátěžové fixtures, nikoli deklarované podporované limity. Husté grafy, disconnected components, multiedges, dlouhé labely a cykly posoudit zvlášť. ADR ze skutečných měření navrhne dosažitelné rozpočty a aktivní plán stanoví podporované limity; rutinní definice benchmarku nepotřebuje nové potvrzení uživatele. Renderer musí mít bounded cancel/timeout a poctivý fallback, žádné zamrznutí nebo tiché zahazování vztahů. Tento spike neobnovuje odstraněnou Windows C26 ani nezavádí širší výkonnostní kampaň.

## Migrace a nejmenší další krok

Zachovat současný bezpečný Mermaid/text fallback a kompatibilní reportové artefakty. První změna má být additive core→graph DTO + parity fixture, nikoli odstranění WP010. Následuje oddělený spike; teprve jeho ADR určí balíčky, přesné verze, hashe, transitive dependencies, runtime distribuci a aktualizační odpovědnost. Graph UI vlastní zobrazení a interakce, core stále vlastní fakta, linking, confidence a scoring. Archify export může vzniknout později ze stejného DTO bez instalační závislosti produktu na agent skillu nebo lokálním Node.js.

Uživatelův [výchozí článek](https://www.ai.joaoqueiros.com/blog/top-10-github-repos-archify-openmaic-omarchy-timesfm#archify) sloužil k identifikaci správného Archify projektu; rozhodnutí výše používá primární projektovou/Microsoft dokumentaci. Žádná knihovna nebyla v této rešerši vykonána nebo benchmarkována.
