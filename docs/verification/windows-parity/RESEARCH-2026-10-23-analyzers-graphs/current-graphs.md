# Aktuální grafy Windows a macOS — zdrojový audit 23. 10. 2026

Výsledek: Windows už má integrované vykreslení skutečně dodaných uzlů a hran. Jeho výchozí položka však vybírá textové `architecture.md`; u běžného reportu tak první pohled ukáže fallback místo existujícího diagramu. Další omezení je pevná mřížka bez uspořádání podle závislostí. macOS zdroj používá plný lokálně přibalený Mermaid renderer pro diagramy cest a služeb. Ani prohlédnutý macOS pohled Dependencies není graf balíčkových závislostí.

Tento soubor je výzkumný podklad, nikoli změna statusu WP010, WP032 nebo akceptačních bran. Aktuální autoritu určuje `docs/README.md` a Windows parity roadmapa/TODO/backlog. WP007 je v přečteném backlogu DONE, WP010 MANUAL_PENDING, WP032 IN_PROGRESS.

## Rozsah a evidence

- Aktuální lokální HEAD při čtení: `507bddacd72a246a136ca2d46faad2aa661806c1`; pracovní strom obsahuje existující změny. Audit čte současné soubory pracovního stromu, nikoli pouze HEAD. Žádná existující změna nebyla vrácena ani upravena.
- CodeGraph byl použit před hledáním/čtením produktového kódu. Nepokryté části a soubory označené jeho upozorněním na pending sync byly přečteny přímo.
- Veřejný macOS HEAD byl znovu ověřen přes GitHub API: `5f2e8b4d84f9dff06e0f87c69c861a434981bd6a`, commit 12. 10. 2026. Odkazy níže jsou připnuté k této revizi.
- Provedena byla kontrola zdrojů a dokumentace. Nebyl spuštěn GUI, build, testovací sada, scan ani LM Studio. Audit nedokládá vzhled, klávesnici, Narrator, offline runtime, přítomnost změny v konkrétním portable ZIPu ani macOS runtime.

## Co je dnes ve Windows

### Produktová integrace existuje

`MainWindow.xaml:40` registruje položku Diagrams a `:183` obsahuje produkční `DiagramView`. `MainWindow.xaml.cs:865–871` přepíná jeho viditelnost. `MainWindow.Parity.cs:56` připojuje export, `:58` zastavuje control při zavření a `BindParityReport:121–128` předává vybraný report do `Diagrams.SetSelection(selected)`.

Proto už není přesné popisovat současný zdroj jako „Windows nemá žádný vykreslený graf“. Dřívější audit z 20. 10. a původní WP010 evidence zachycují stav tehdejšího řezu. Současná integrace sama nepředstavuje nové ruční přijetí a status MANUAL_PENDING zůstává platným omezením.

### Proč se po otevření může objevit pouze text

`DiagramSelectionReader.cs:6` definuje pořadí `architecture.md`, `attackmap-paths.md`, `attackmap-topology.md`. `DiagramView.cs:13` volí `SelectedIndex=0`.

`summarize_architecture` v `src/attackmap/analyzer.py:188–250` vytváří Markdown přehled: počty, jazyky, datastory, externí cíle a maximálně deset textových „Inferred Trust Boundaries“. Nevytváří Mermaid blok. Parser tak u standardního `architecture.md` narazí na nepodporovanou hlavičku a ukáže jeho úplný inertní text. Skutečné diagramy jsou v dalších dvou položkách.

Nejmenší viditelná oprava je vybírat dostupný grafový artefakt vybrané generace a nabídnout srozumitelné typy „Topologie služeb“ a „Rizikové cesty“. Architektonický text patří mezi přehledy nebo k textovému vysvětlení diagramu. Chybějící graf se nesmí nahradit grafem domyšleným z tohoto textu.

### Renderer je funkční, ale má omezenou prezentaci

`DiagramModel.cs:6–11` nese `DiagramNode(Id, Label)` a `DiagramEdge(Source, Target, Label, Operator, Directed)` plus původní source a úplnou textovou alternativu. `DiagramParser:24–73` přijímá omezenou podmnožinu Mermaid flowchart TD/LR, explicitní deklarace uzlů, sousední hrany řetězce a konkrétní operátory/styly core. Nedeklarovaný endpoint, duplicitní ID nebo nepodporovaná syntaxe vedou na fallback; UI nedopočítává chybějící vztahy.

`DiagramLayout.Positions:79–80` umisťuje uzly v pořadí deklarace do tří sloupců: `x=40+(index%3)*300`, `y=40+(index/3)*140`. Přijaté TD/LR neřídí layout. `DiagramView.Show:67–97` kreslí WinUI Canvas, Polyline, šipky, popisky a obdélníky. Směr, přerušované a silné hrany jsou částečně viditelné; nejde o layout podle grafové struktury. Původní `class` a `linkStyle` jsou parserem akceptované, ale tento control z nich nevytváří plnou Mermaid tematiku. Značky rolí `<br/><i>…</i>` z core topologie jsou nativní doslovný text.

Více Mermaid bloků z `attackmap-paths.md` se sbírá do jednoho `DiagramDocument`; jejich nadpisy a oddělené canvasy se nezachovávají. Plné názvy a hrany jsou dostupné v textové alternativě, vizuální popisky se krátí. Zoom, reset, posun, copy a export už existují (`DiagramView.cs:15–41`). Graf nemá události pro výběr uzlu/hrany ani přímý drill-down na evidence/finding/source. Současný `DiagramNode` pro ně nemá typované reference.

Meze jsou explicitní: čtení artefaktu do 4 MiB, reportu do 64 MiB; parser do 120 uzlů, 240 hran, 8192 znaků řádku a 2048 znaků popisku. Větší/neplatný graf má textový fallback nebo hlášení o nedostupnosti, nikoli částečný graf vydávaný za úplný.

### Vazba na konkrétní uložený report

`DiagramSelectionReader.Read:7–29` vyžaduje lokální zvolený `ExportSelection`, odmítá UNC/síťovou cestu, vyhledává pouze manifestem uvedený podporovaný `.md` artefakt a používá `SelectedArtifacts.List/ReadText`. Sourozenecké soubory se nezkoušejí pouze podle názvu. Čte se i příslušný canonical report a jeho limitations/resource events se propíší do upozornění.

`DiagramView.Reload:49–61` při změně výběru okamžitě odstraní minulý graf a inkrementuje revision; výsledek asynchronního načtení se publikuje pouze pro stále platnou revision. `SetSelection` a `Stop` jsou spojeny s životností okna. `MainWindow.Parity.cs:173–189` ukládá zachycenou textovou projekci přes picker, ověří exportní cíl a po dialogu znovu volá `SelectedArtifacts.List(selected)`.

Tato vazba prokazuje příslušnost načteného artefaktu k zachycené generaci a ověřovaným bajtům v rozsahu existujícího manifestu. Sama neprokazuje správnost vztahů, runtime dostupnost služby, kompletní pokrytí nebo čerstvost vůči právě změněnému zdrojovému repozitáři. Text copy je kopie již zobrazeného snapshotu. Nový renderer musí tuto hranici zachovat.

## Co skutečně dělá macOS

[ContentView.swift:475–480](https://github.com/mlaify/AttackMap-mac/blob/5f2e8b4d84f9dff06e0f87c69c861a434981bd6a/AttackMap/Views/ContentView.swift#L475) odděluje Dependencies od Diagrams. [DiagramView.swift:4–39](https://github.com/mlaify/AttackMap-mac/blob/5f2e8b4d84f9dff06e0f87c69c861a434981bd6a/AttackMap/Views/DiagramView.swift#L4) standardně načte `attackmap-paths.md` a `attackmap-topology.md` z outputDirectory. Každý blok zpracuje [MermaidExtractor.swift:12–33](https://github.com/mlaify/AttackMap-mac/blob/5f2e8b4d84f9dff06e0f87c69c861a434981bd6a/AttackMap/Services/MermaidExtractor.swift#L12), včetně nadpisu. Každý pak dostane vlastní Mermaid `<pre>`.

[DiagramHTML.page:42–74](https://github.com/mlaify/AttackMap-mac/blob/5f2e8b4d84f9dff06e0f87c69c861a434981bd6a/AttackMap/Views/DiagramView.swift#L42) vloží `Resources/mermaid.min.js` z bundle, escapuje dodaný text a inicializuje Mermaid s `securityLevel:'strict'`. [MermaidWebView:76–85](https://github.com/mlaify/AttackMap-mac/blob/5f2e8b4d84f9dff06e0f87c69c861a434981bd6a/AttackMap/Views/DiagramView.swift#L76) používá WKWebView přes NSViewRepresentable. Je to nativní SwiftUI shell s vloženou webovou plochou; grafové uspořádání obstarává Mermaid. Samotný prohlédnutý source zde neobsahuje manifest/hash boundary ekvivalentní Windows `ExportSelection`; nelze kopírováním Mac načítání oslabit Windows integritu.

[DependenciesView v InventoryViews.swift:31–140](https://github.com/mlaify/AttackMap-mac/blob/5f2e8b4d84f9dff06e0f87c69c861a434981bd6a/AttackMap/Views/InventoryViews.swift#L31) používá tabulky CVE a závislostí: package, version, ecosystem, kind, declared-in a analyzer. Nepředkládá topologii balíčků. Diagramy služeb/rizikových cest jsou tedy vhodný skutečný referenční cíl; tvrzení „macOS už má interaktivní package dependency graph“ není těmito zdroji podloženo.

## Jaká grafová data už existují

| Oblast | Existující producent/data | Omezení pro evidence workspace |
| --- | --- | --- |
| Topologie služeb | `src/attackmap/topology.py:49–79`: ServiceNode(name, role, files_seen), ServiceEdge(source, target, kind, file, evidence), ServiceGraph(nodes, edges). Druhy http-call/env-configured/analyzer-declared/async-queue. | Jde o heuristický model, zejména host-name a layout fallback; ServiceEdge nemá stabilní ID, line, observation refs ani explicitní confidence/resolution contract. HTTP hint neprokazuje runtime konektivitu. |
| Diagram topologie | `src/attackmap/report.py:140–144` staví ServiceGraph a zapisuje `attackmap-topology.md/.dot`. `diagrams.py:61–122` transformuje uzly a hrany. | Mermaid `S0`/`S1` jsou generovaná prezentační ID. Role a edge evidence skončí v popiscích; `file` se do Mermaid edge reference nepřenáší. |
| Rizikové cesty | `models.py:860–863`: AttackPath(name, steps:list[str], impact). `report.py:119` v JSON. `diagrams.py:33–58` každý seznam transformuje na kroky a impact. | `P1_0` jsou prezentační ID pořadí. Textové steps nemají vlastní source/evidence/finding ID. Uživatel nesmí získat domyšlený evidence join podle shodného názvu. |
| Package závislosti | `models.py:204–231`: DependencyHint(name, version, ecosystem, file, line, dev, resolved, direct, via, evidence_text, source_analyzer). `ScanResult.dependencies` je serializováno. | `via` je text cesty rozlišení, nikoli strukturovaný seznam identity hran. Manifests poskytují i rozsahy; lockfile poskytuje exact/transitive metadata. Pro některé ekosystémy přímé parent→child vazby neexistují. |
| Static data-flow | `ScanResult.taint_chains`, finding.code_flows, ExploitabilityScoreReference(chain, score_id, root, snapshot, scope), finding.exploitability_reference (`models.py:677–735`, `793–826`). | Tyto přesné reference lze znovu použít v nové projekci. Nejsou důkazem runtime reachability a nejsou totéž co inter-service trust edge. |
| Fleet smlouvy | `contracts.py:72–118` a `fleet_summary_json:349–385`: client/server repo, method/path, target, destination, resolution, resolution_reason, scheme, alias_provenance, proxy_host, client/server location. | observed je označení statického spojení podle kontraktu; candidate zůstává candidate. observed_via_proxy se kreslí přes deklarovaný proxy uzel, nikoli jako přímá služba→služba. |

Canonical `attackmap-report.json` sestavuje `report.py:93–121`: scan, architecture/attack-surface/review summaries, defensive_review_json, review_context_pack, attack_surfaces, findings+context, suppressed_findings+context, attack_paths a exploitability. **Není v něm samostatné `service_graph.nodes/edges` nebo obecné `graph` pole.** ServiceGraph se dnes sestavuje až pro Markdown export po větvi `if not emit_markdown: return`. Zdrojové hints jsou v `scan`, ale UI by si jejich samostatným převodem rekonstruovalo core model.

`--format json` nevytvoří diagramové `.md/.dot` soubory (`report.py:52–62`, `134–144`). U takového uloženého reportu je současná nepřítomnost artefaktu očekávaný stav, který nový view musí vysvětlit nebo řešit novou core JSON projekcí. Artifact/run manifesty vážou výstupy přes cesty, hash/checksum, generation/run identity; nejsou schématem grafové semantiky (`schemas/artifact-manifest.schema.json:18–87`, `schemas/run-manifest.schema.json:3–33`).

Windows `ReportSections.cs:6–24` a `ReportSectionAdapter.cs:38–50` nabízejí typované řádky cest, surface, dependencies a raw evidence, ne typovaný GraphDocument. `EvidenceRow.Source` zachovává původní JSON. Existující finding/source navigace v `MainWindow.Parity.cs:130–169` se může použít až pro přesnou core referenci; diagram žádné takové události neposkytuje.

Fleet má navíc skutečný `fleet-graph.md` export (`fleet.py:303–346`). Mac jej předává přes [FleetView.swift:56](https://github.com/mlaify/AttackMap-mac/blob/5f2e8b4d84f9dff06e0f87c69c861a434981bd6a/AttackMap/Views/FleetView.swift#L56) do `DiagramView(filenames:…)`. Windows `FleetView.ShowSummary:87–105` zobrazí repos a jednotlivé linky/flows/gaps/anomalies jako textové expandery. Nevloží diagram a běžný `DiagramSelectionReader` `fleet-graph.md` nepovoluje. Jeho Mermaid edge syntaxe `-->|"label"|` / `-.->|…|` navíc není podporovanou syntaxí současného parseru.

## Doporučený minimální postup pro WP043

Následující řezy jsou návrh pro rozšíření evidence workspace a mají zůstat oddělené od neměněných sémantických bran WP032. Oprava výchozího výběru může jít nezávisle na rozhodnutí o rendereru. Pouhé přidání jiného layoutu nedodá chybějící source identity a klikací evidence.

### G0 — Graf je po otevření skutečně viditelný

- Změnit default na manifestem dostupnou topologii nebo cesty, zachovat původní typ diagramu pouze pokud patří nové vybrané generaci. Architektonický text přestat nabízet jako standardní graf.
- Zachovat jednotlivé Mermaid bloky a jejich nadpisy. U empty/missing/json-only reportu vysvětlit konkrétní důvod; nikdy nezobrazit předchozí generaci.
- Přijetí: standardní uložený report obsahující topologii ukáže topologii prvním otevřením; přepnutí A→B, chybějící/poškozený/změněný artefakt odstraní A. Zdokumentovat ruční průchod v produkčním okně.

### G1 — Core dodá kontrakt nezávislý na rendereru

- Přidat additive core GraphDocument/graph artifact s version, graph kind, repository/run/generation/snapshot identity, completeness/limits a stabilními node/edge ID. Publikovat jej také pro JSON-only report a zahrnout do existujícího manifest/hash boundary.
- Uzly/hrany mají kind, label a přesné source/observation refs, source file/line, basis/resolution/confidence pouze tam, kde je core skutečně zná. Finding/score refs jsou explicitní volitelné reference; chybějící reference znamená unknown. Nevyvozovat je z labelu, pořadí ani hodnoty score.
- Pro současné služby projektovat existující core ServiceGraph; oddělit jeho heuristickou basis od silnějších fleet ContractLink záznamů. Pro proxy a candidate zachovat současnou C28 sémantiku. Mermaid/DOT mohou být další renderery stejné projekce.
- Prezentační Mermaid `S0`/`P1_0` nemapovat na source identity odhadem. Pokud bude potřeba zpětné zobrazení starých Mermaid artefaktů, označit je jako legacy display bez evidence drill-down; případnou mapu musí vydat core.
- Package dependency graph začít pouze pro parser, který dodává prokazatelné parent→child identity včetně verzí, lockfile location a workspace scope. Přímý declared-in vztah manifest→package lze modelovat explicitně. Netvořit transitive hrany parsováním `via` v UI; unresolved/range/multiple-version/cycle zůstávají viditelné.
- Přijetí: serializace a consumer zachovají přesné ID/pořadí/počty, žádné dangling refs; fixtures pro candidate/proxy, duplicate package versions, cycles a missing legacy fields. Nulová nová observed hrana a nulový nový evidence join proti core oracle. Změna hash/generation data odmítne.

### G2 — Krátký srovnávací spike a čitelný embedded graf

- Porovnat nativní WinUI plochu s grafovým layout enginem a embedded grafovou plochu na totožném G1 modelu; při výběru MSAGL/Cytoscape nebo jiné knihovny nejprve ověřit současný balíček, licenci, Windows deployment a offline boundary. Z výzkumu samotného neplyne schválení závislosti.
- Nativní směr může zachovat existující shell a controls; webový směr vyžaduje přesně ohraničenou lokální plochu, lokálně zabalené resources, zákaz navigace/network a úzkou zprávovou smlouvu. Mac Mermaid poskytuje referenční výsledek pro layout, nikoli automatické schválení shodné technologie na Windows.
- Oba spike kandidáty hodnotit podle layered/dependency-aware layoutu, cyklů, disconnected komponent, paralelních hran, zachování direction/kind/candidate/proxy, fit/zoom/pan/search/filter a velkých grafů. Výpočet layoutu nesmí pozměňovat vztahy nebo ranking.
- Přijetí: předem stejný corpus malých/běžných/velkých/hostile grafů; shodný hash sémantických nodes/edges bez ohledu na renderer a layout. Doložit CPU/čas/paměť a zvolený limit; přes limit poctivý přehled/text/export. Schválený zvolený spike integrovat do produkčního Diagrams, ne pouze Preview projektu.

### G3 — Výběr uzlu/hrany otevře správný důkaz

- Přidat výběr a detail panel s kind/basis/uncertainty a přesnými core refs. Připojit na současný finding/source workflow přes run/generation/hash guard. Nejednoznačný nebo chybějící cíl nabídne explicitní unknown stav.
- Pro fleet vložit graf nad existující podrobný seznam, ze stejné zachycené fleet generace; zachovat proxy mezikrok a vizuální rozdíl candidate. Rozšířit reader/projection o fleet kontrakt místo prostého přidání názvu souboru k single-repo whitelistu.
- Přijetí: klik na edge prokáže přesný client/server a zdroj, klik na finding otevře přesné finding ID; žádný fallback podle názvu. Přepnutí reportu během async detailu/export pickeru nepřenese důkaz do jiné generace.

### G4 — Uzavření vyžaduje skutečné desktop ověření

- Fokusované contract/parser/layout testy průběžně; širší suite jednou na stabilním integrovaném checkpointu. Výzkum zde žádný nový testový PASS netvrdí.
- V produkčním Windows okně uložit viditelný náhled a skutečně jej zkontrolovat: světlo/tma, obě stanovené velikosti okna, text 200 %, klávesnice/focus/Escape, Narrator/textová alternativa, reduced motion, copy/export a síť vypnutá. Hostile label/URL/script se neprovede.
- Použít uložený reálný report z `C:\tmp\juice-shop` a samostatný deterministický víceslužbový/fleet corpus. Juice Shop není sám o sobě důkaz celkové distributed/fleet topologie. Pro deterministické grafy není nutná nová AI/modelová výzva.
- macOS zdrojová reference a Windows runtime evidence zůstávají samostatné. Vydání či čistý počítač vyžadují vlastní balíčkovou kvalifikaci.

## Paralelní rozdělení a závislosti

1. **Core/contract owner:** G1, producer a manifest registration; koordinuje sdílené `models.py`, `report.py`, `artifact_manifest.py` a schémata s vlastníkem WP032. Nemění pravidla service identity ani scoring v tomto řezu.
2. **Windows graph owner:** G0 a G2 against frozen G1 fixtures; vlastní nové graph model/view/layout soubory. Výběr závislosti a project/resource registraci provede integrátor po spike rozhodnutí.
3. **Evidence navigation/integration owner:** G3 a finální MainWindow/Fleet wiring; má výhradní shared-shell lease. Do schválení core kontraktu používá fixtures bez odhadovaných vazeb.
4. **Coordinator:** zmrazí corpus/kontrakt, integruje serializaci a consumer, provede G4 a případné zapečetění balíčku. Bez vizuální/accessible/offline acceptance nelze pouze na základě unit/build PASS uzavřít WP010 ani nové rozšíření.

Odhad pořadí: G0 lze dodat jako malou opravu; G1 musí předcházet evidence drill-down a skutečnému package graphu. G2 lze prototypovat paralelně proti zmrazeným fixtures. G3 a G4 uzavírají integrovaný výsledek. Tento audit neurčuje kalendářní termín bez renderer spike a měření velikosti reálných grafů.
