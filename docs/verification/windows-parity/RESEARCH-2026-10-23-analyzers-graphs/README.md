# Analyzéry a skutečné grafy — výzkum 23. 10. 2026

**Nejnovější upřesnění uživatele:** [celkové architektonické schéma 16 repozitářů](fleet16-requirements.md) je povinný rozsah. WP043 zahrnuje fleet overview, repo→service/component drill-down a úplný export; WP044 dodá společná architektonická data/vztahy. Obě rendererové větve mají stejně prioritní fleet spike; dřívější native-first preference níže platila před tímto upřesněním. [Kontrola této změny plánu](fleet16-plan-validation.json). Žádný nový scan ani hotová 16-repo podpora se tím netvrdí.

## Rozsah a výsledek

Výslovné zadání uživatele: prověřit veřejnou dokumentaci analyzérů, způsob zobrazení grafů oproti macOS a Archify nebo alternativy; přidat konkrétní práci do aktivní roadmapy. Jde o zdrojový audit, webový výzkum a změnu plánu. Nebyla implementována nová detekce ani nový renderer a nebyl spuštěn scan, LM Studio nebo nový build.

Základ zdrojového auditu je lokální HEAD `507bddacd72a246a136ca2d46faad2aa661806c1` s již rozpracovanými změnami z předchozí dávky. Zdrojový checkout, jeho Python prostředí a dříve zabalený engine jsou různé identity; jejich inventáře nelze zaměnit. Tři paralelní výzkumné řezy používají GPT-6.1 Sol / ultra; aktivní plán upravuje pouze integrátor.

| Oblast | Zjištění | Rozhodnutí pro plán |
| --- | --- | --- |
| Analyzéry | Přibalený engine už obsahuje všech 15 oficiálních pluginů, ale registry řeší kolize s místními built-ins a některé vrstvy jsou opt-in. | WP042: katalog skutečně zvoleného enginu, provenance, explicitní profily a kvalifikované aktualizace. Konkrétní mezery existujících vrstev pokračují pod WP039/WP031. |
| Windows grafy | Nativní Canvas již kreslí omezený Mermaid subset v pevné mřížce. Výchozí `architecture.md` je však slovní souhrn; diagramy cest a topologie jsou jiné artefakty. | WP010: správná výchozí volba a dokončení původních bran. WP043: strukturovaná projekce grafu, rozložení podle hran a procházení evidence. |
| Renderer | Archify je vhodné pro autorské diagramy a samostatné exporty; doložené produktové SDK pro průběžné grafy skenu chybí. | Ve WP043 nejdřív omezený spike nativního Canvas + MSAGL layout proti Cytoscape.js + Dagre; žádná závislost se nepřidává tímto dokumentem. |

## Analyzéry: rozšíření musí změnit skutečné pokrytí

Podrobný audit a přesné inventáře: [analyzers.md](analyzers.md).

Veřejná dokumentace popisuje čtyři built-ins a 15 pluginů. Uvádí společné pořadí `(priority, name)`, first-seen merge a opt-in vrstvy. Explicitní `-m` vybírá jen jmenované moduly; neznamená automatické doplnění ostatních. Tyto podmínky je nutné promítnout do profilu a coverage, nikoli prostě zaškrtnout všechny moduly. [Oficiální dokumentace](https://docs.mlaify.io/analyzers/#run-order), [SDK](https://docs.mlaify.io/sdk/).

Místní zdroj registruje devět built-ins. Dřívější frozen engine registruje 21 efektivních analyzérů: devět built-ins a 15 pluginů po třech kolizích jmen (`php-web`, `php-laminas`, `omeka-s`). Pouhé přidání balíčků tedy tyto tři implementace nevymění. Místní merge navíc umí doplnit původně unknown route auth z pozdějšího záznamu; nelze jej popsat pouze obecným first-seen pravidlem. Místní vývojová prostředí při tomto auditu vracejí pouze devět built-ins. Nejde o nový PASS aktuálního zdrojového portable buildu.

První dodávka má zpřesnit cestu od instalace k výsledku: dostupný modul → zvolená implementace → applicability → výběr → spuštění → výstup nebo důvod vynechání. Profily Node/ATProto, PHP/Laminas/Omeka S a Python musí zachovat potřebné základní vrstvy, rozlišit experimentální výběr a ukázat kolize. Balíček ani startup nesmí samovolně stahovat analyzéry.

Nejbližší detekční zlepšení jsou správné prefixy mountovaných/routerových cest a vazba auth ke konkrétní cestě, následně přesně vybrané změny upstreamu. Issue uvedené na webu není důkaz mezery v připnuté verzi. Aktualizace musí mít před/po extraction diff, pozitivní i negativní příklady, zdrojovou identitu a regresi Juice Shopu. Maturity dál podléhá WP030/WP031/WP039; vyšší počet modulů sám kvalitu nedokazuje.

Hlubší Kubernetes RBAC/NetworkPolicy/workload analýza a protobuf/gRPC/OpenAPI kontrakty jsou kandidáti dalšího rozšíření po capability inventuře, nikoli již slíbené nebo hotové detektory. Současný core už část Kubernetes konfigurace a GraphQL analyzuje.

## Grafy: z artefaktu k procházení skutečných vztahů

Audit implementace a dat: [current-graphs.md](current-graphs.md). Porovnání rendererů a primární zdroje: [graph-renderers.md](graph-renderers.md).

**Navazující praktické porovnání na nový pokyn uživatele:** [Canvas + MSAGL proti Cytoscape.js](renderer-comparison.md), [nativní integrační návrh](msagl-integration.md) a [Cytoscape/WebView2 integrační návrh](cytoscape-integration.md). Obsahují hranice skutečných API, threading/cancel, napojení na evidence a dopad na full portable. Jde nadále o výzkum; neproběhl renderer spike, instalace knihovny ani nový build. MSAGL je první kandidát pro současnou Windows distribuci, konečný výběr zůstává podmíněný stejným praktickým ověřením obou variant.

macOS zdroj používá lokální Mermaid ve WKWebView a přednostně zobrazuje cesty a topologii. Jeho pohled Dependencies je tabulka balíčků; nelze z něj odvodit existenci grafu tranzitivních balíčkových závislostí. Kontrola macOS byla zdrojová, bez běhu na Macu.

Pro Windows je nejmenší viditelný krok otevřít skutečný diagram jako první a zachovat přístup k textu. Cílový pohled však potřebuje rozložení podle závislostí, hledání, zoom/pan/fit, filtr typů hran a přechod z uzlu/hrany k původní evidenci. Canonical JSON dosud neserializuje plný `ServiceGraph`; Mermaid identifikátory jsou prezentační a nejsou automaticky evidence IDs. WP043 proto začíná additive kontraktem dat, nikoli odvozováním vztahů z popisků v UI.

První kontrakt pokryje service/call/datastore topologii a cesty, které core skutečně modeluje. Fleet má vlastní typed cross-repo vazby a naváže po samostatném ověření. Balíčkové dependency hrany budou dostupné jen s reálnými strukturovanými vztahy z resolveru/lockfile; prostý seznam balíčků ani text `via` takový graf nezakládá. Missing, prázdný a omezený graf zůstávají odlišné stavy.

Předběžně dává smysl zachovat WinUI ovládání a vyzkoušet nativní layout. Cytoscape.js s lokálně zabaleným layoutem je alternativa, pokud bude prokazatelně vhodnější pro interakce a rozsah. WebView2 vyžaduje vlastní offline/runtime/distribuční a bezpečnostní ověření. Archify zůstává kandidát pro kurátorované přehledy a exporty; generování grafových faktů modelem není součást tohoto návrhu. [Archify](https://github.com/tt-a1i/archify), [MSAGL](https://github.com/microsoft/automatic-graph-layout), [Cytoscape.js](https://js.cytoscape.org/).

## Pořadí, acceptance a předání

1. WP042 a datový/renderer spike WP043 lze připravovat souběžně v oddělených souborech. Integrátor drží MainWindow, resources, project a kontrakty.
2. WP042 nejdřív zapečetí effective inventory/provenance a definici profilů; až pak vybrané aktualizace. WP039 řeší konkrétní frameworkové mezery pod původními quality gates.
3. WP043 nejdřív zmrazí graph DTO/fixtures a rozhodnutí rendereru. Pak integruje graf a prohlédne skutečné snímky v obou tématech a dvou velikostech; offline, keyboard a Narrator mají vlastní důkazy.
4. Změna modulu, kontraktu nebo závislosti znamená nový source-bound kandidát a odpovídající focused/package kontrolu. Tento výzkum nepřiznává runtime, release ani macOS acceptance.

Aktivní definice a závislosti jsou výhradně v [roadmapě](../../../roadmap-windows-parity-2026-10-20.md), [TODO](../../../windows-parity-todo.md) a [JSON backlogu](../../../windows-parity-backlog.json). Tento adresář obsahuje výzkumné podklady. Původní WP stavy a retained evidence zůstávají zachované.

## Kontrola integrátora

- [Přesný frozen inventář](frozen-module-inventory.json): executable hash ověřen, příkaz `modules --json` exit 0, 21 modulů, tři jmenovité kolize; pouze discovery, žádná analýza.
- [Původní kontrola plánu](plan-validation.json): dřívější checkpoint 43 shodných task IDs, shodné definice nových karet a všechny závislosti TODO/JSON, acyklický graf a místní odkazy bez chyb. Její tehdejší hashe zůstávají zachované; navazující výzkum ověřuje [nový záznam](renderer-comparison-validation.json).
- Dvě nezávislá Sol / ultra review: analyzéry/provenance i grafové doporučení/kontrakty bez materiálních nálezů. Nebyl přijat nový renderer ani plugin pin; `git diff --check` bez whitespace chyb.
