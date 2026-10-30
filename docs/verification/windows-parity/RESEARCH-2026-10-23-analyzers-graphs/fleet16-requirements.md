# Celkové architektonické schéma 16 repozitářů

Upřesnění uživatele 23. 10. 2026: společně skenovat přibližně 16 repozitářů a zhotovit schéma jejich vzájemných vztahů. Toto je **povinný produktový scénář** pro WP043, nikoli pozdější volitelný fleet doplněk. Samotné vykreslení jednoho repozitáře požadavek nesplňuje. Jde o návrh a zdrojový audit; nový 16-repo scan, renderer ani portable build zde neproběhl.

## Co má uživatel dostat

| Úroveň | Obsah a ovládání |
| --- | --- |
| Celá sestava | Všech 16 vybraných repozitářů v jednom přehledu, vztahy mezi nimi a doložené externí komponenty. Každý repo má stav úspěch/partial/failure a identitu svého výsledku. |
| Služby a komponenty | Rozbalení repo skupiny na skutečně modelované služby, datastory a další komponenty; více služeb v jednom repo i knihovní repo bez vlastní služby jsou platné případy. |
| Důkaz a konkrétní cesta | Vybraná vazba otevře jednotlivé podkladové vztahy, jejich důvod/confidence a přesné source references na obou stranách. Návrat zachová výběr a měřítko. |

Overview zobrazí souhrnné orientované vazby s počty, drill-down odhalí jednotlivé callsites. Filtry a skryté počty musí být viditelné. Uživatel může zobrazit upstream/downstream okolí, jen mezi-repo vazby nebo zvolenou cestu. Úplný model se zachová i při omezení aktuálního výřezu.

Výstup pro sdílení zahrne celý zachycený graf jako JSON a grafický export celého přehledu; ADR vybere prověřený vektorový nebo stránkovaný způsob pro velké schéma. Samotný obrázek aktuálního viewportu není úplný export. Export uvádí generaci, zvolené filtry, partial coverage a časy/identity jednotlivých snapshotů.

## Co už zdroj umožňuje a co chybí

CodeGraph a cílené čtení aktuálních zdrojů potvrdily:

- `FleetWorkspace.cs:20–28` a `desktop_fleet.py:48–70` přijímají 2–16 unikátních lokálních roots. Počet repozitářů není limitem počtu uzlů nebo služeb.
- Desktop worker podporuje 1–4 současné children, default 1. `MainWindow.Workspaces.cs:217–233` override neposílá; dnešní UI tedy používá jeden child současně. Výchozí celý fleet deadline je 600 s (`FleetSession.cs:108,126`, `desktop_fleet.py:367–368`). Pro 16 větších repos je nutný výslovný budget a ověřená admission politika; 16 roots není slib 16 neomezených současných procesů.
- `scan_service.py:571–691` má bounded count admission a volitelný odhadový memory ledger. Výchozí cesta hlásí count-only, memory qualification unknown a žádný OS enforcement. Nelze ji prohlásit za paměťově kvalifikovaný 16-repo běh.
- `fleet.py:349–437` již emituje cross-repo HTTP call→route vazby s destination, resolution/reason, alias/proxy provenance a oběma source locations. `contracts.py` zatím nezajišťuje obecné cross-repo publish→consume, shared-datastore nebo RPC/schema propojení. Lokální async-queue hrana není průkaz mezi-repo fronty.
- Současný Mermaid fleet graf (`fleet.py:303–345`) má repo uzly a proxy. Chybí společná repo→service hierarchie, stabilní identity jednotlivých vztahů a typované observation refs; to vlastní nový WP044. Počty a seznam vazeb nejsou samy kompletní architektura všech protokolů.
- Picker přiděluje GUID child identity, summary obsahuje slug repo identity. Statická cesta `FleetView` summary Open → `workspace.Open(slug)` potřebuje explicitní GUID↔slug↔root mapu; nelze bezpečně joinovat podle basename. WP019 musí reprodukovat a opravit případný chybný drill-down před acceptance.

Jeden fleet run sdružuje **samostatné child snapshoty**. Nepředstavuje automaticky současně zachycený globální stav všech 16 pracovních stromů.

## Pravidla společného modelu

WP044 dodá strukturovanou architektonickou projekci z core: repository/child identity, služby a komponenty, containment/ownership vztahy, stabilní node/edge IDs, druh/směr, resolution/basis a přesné evidence refs. Renderer vztahy nevytváří. Neznámé nebo nepodporované vztahy zůstanou explicitně unknown/unanalysed.

HTTP/proxy vazby se převezmou se současnou C28 sémantikou. Doložené producer/consumer a shared-datastore vztahy se kvalifikují odděleně s negativními případy; RPC/protobuf/OpenAPI nebo další protokoly nedostanou claim podpory pouze z výskytu názvu. Sdílená externí komponenta se sjednotí jen podle prokazatelné qualified identity, nikoli shody krátkého názvu, portu nebo balíčku. Secrets se do labelů/exportu nepřenášejí.

Sbalená hrana zachová seznam původních edge IDs a počty podle druhu, směru a resolution. Candidate a observed se neslijí; proxy mezikrok se nevymaže. Collapse/expand je vratná prezentační projekce. Cesta A→B→C v repo overview **sama neprokazuje** souvislý tok mezi konkrétními službami uvnitř B. Detailní cesty musí vycházet z původního sémantického grafu a zachovat uncertainty.

Selhaný nebo přeskočený child zůstane jako stavová repo skupina. Nedostupná evidence není „žádné závislosti“. Úspěšné výsledky sourozenců se zachovají a starý snapshot se nesmí tvářit jako výsledek nové fleet generace.

## Dopad na volbu rendereru

Obě větve mají pro tento scénář **stejně prioritní spike**. Dřívější native-first doporučení bylo předběžné pro jednodušší plochu a portable distribuci; grouping zatím není odzkoušený v žádné variantě.

- MSAGL zdroj obsahuje nested clusters a collapsed boundary stav. To nedodává hotové WinUI ovládání nebo agregaci evidence; přesný release/layout se musí kvalifikovat. [Cluster](https://raw.githubusercontent.com/microsoft/automatic-graph-layout/master/GraphLayout/MSAGL/Core/Layout/Cluster.cs).
- Cytoscape má compound nodes přes `parent`; obecné graph algoritmy automaticky nezahrnují potomky skupiny. Collapse/expand a věrné agregace jsou aplikační práce. Vedle jednoduchého Dagre má spike zahrnout compound-aware fCoSE; jeho konkrétní verze, determinismus a worker/cancel se ověří zvlášť. [Compound model](https://js.cytoscape.org/#notation/compound-nodes), [fCoSE](https://github.com/iVis-at-Bilkent/cytoscape.js-fcose).
- Známý externí expand-collapse plugin uvádí ukončenou údržbu. Nepřebírat jej automaticky; preferovat vlastní vratnou projekci nebo zvlášť kvalifikovaný udržovaný nástupce. [Stav projektu](https://github.com/iVis-at-Bilkent/cytoscape.js-expand-collapse).

Přesnost faktů a použitelnost 16-repo celku rozhodují před preferencí technologie. Offline/portable, nativní focus/Narrator a náklady údržby zůstávají součást stejného rozhodnutí. Žádná knihovna zde nebyla přijata ani benchmarkována.

## Povinné přijetí

1. Deterministický corpus 16 rozdílných roots se známými vazbami plus skutečný reprezentativní 16-repo scan. Zahrnout stejné basename ve dvou kořenech, více služeb v repo, library-only repo a skutečně nepřipojené repo.
2. Všech 16 požadovaných identit je dohledatelných; u úspěšné varianty je 16 správně navázaných child manifests. Chyba jednoho child zachová 15 výsledků a šestnáctou stavovou skupinu bez smyšlených hran.
3. Serial/parallel 1/2/4 má stejné normalizované facts a identities; zveřejnit effective budget, admission, paměť, deadline/cancel a ověřený cleanup. Budgets ani paměťové limity se potichu nezvyšují nebo nevypínají.
4. Celkový přehled → rozbalení dvou propojených repos → služba → konkrétní hrana → správné důkazy na obou stranách → návrat. Sbalení/rozbalení nezmění canonical edge IDs/counts a nevytvoří falešnou průchozí cestu.
5. Na stejném 16-repo členění ověřit 1000/3000 node/edge corpus a 10000/30000 stress s přiznaným omezením detailu. Obecný náhodný graf nenahradí fleet fixture. Změřit zvlášť layout, render, interaction, memory a cancel; supported bounds až podle výsledků.
6. Skutečný Windows produkt a source-bound balíček, Light/Dark a dvě velikosti, keyboard/Narrator/text 200 %, offline a úplný grafický/data export. Testovaný obrázek ani doc diagram nejsou runtime acceptance.

Aktivní práce: WP018 scheduling/budget, WP019 picker/identity/workspace, WP032 sémantika identity, WP034 resource qualification, WP044 architektonická data, WP043 zobrazení a export s WP022. Tento dokument neuzavírá žádný z těchto úkolů.
