# Výzkum rozšíření analyzérů — 23. 10. 2026

Výzkumný podklad pro aktivní Windows parity plán, zejména WP003, WP006,
WP031–032, WP035 a WP039. Není implementací, acceptance ani novým nezávislým
backlogem. HEAD při průzkumu: `507bddacd72a246a136ca2d46faad2aa661806c1`;
pracovní strom obsahuje další rozpracované změny. CodeGraph použit před čtením
kódu; u nedodaných detailů a hlášených pending-sync souborů doplněno cílené
čtení zdroje. Přístupy k externím zdrojům: **2026-10-23**.

## Hlavní závěr

Největší okamžitý přínos má kvalifikace a zpřehlednění již existujícího
pokrytí. Zdejší frozen engine skutečně objevuje **21 jedinečných modulů**,
zatímco veřejný referenční katalog popisuje čtyři vestavěné analyzéry a
15 oficiálních pluginových balíčků. Místní větev má **devět vestavěných**;
tři jména pluginů kolidují s vestavěnými implementacemi. Pouhé sečtení
balíčků proto nedává počet vybraných ani provedených analyzérů.

Nejdřív navrhnout společný katalog, původ vybrané implementace, průkazný
záznam výběru a profily. Potom kvalifikovat připnuté aktualizace a doplnit
WP039. Nové jazyky/protokoly přidávat po samostatných extraction-only řezech
s pozitivními i negativními referencemi a s bránami C27/C38.

## Ověřený inventář podle prostředí

Read-only discovery bez analýzy repozitáře:

- `C:\Program Files\Python313\python.exe` + zdejší `src`: devět vestavěných,
  žádné externí `attackmap-analyzer-*` distribuce v tomto interpreteru.
- `.venv/Scripts/python.exe` + zdejší `src`: také devět; ověřeno
  `sys.executable`, `sys.prefix` a `importlib.metadata.distributions()`.
- `.tmp/wp024-sol-long-budget-20261023-02/dist/attackmap/attackmap.exe modules --json`:
  **21** modulů a tři varování o duplicitních jménech. Tento konkrétní engine
  se shoduje s uchovaným WP024 záznamem; jeho executable SHA-256 je
  `574497f7c4ae3c8859edb5506c0538c8cba99dc70436f29857dbec6240aa81f5`.
  Nejde o tvrzení o jiném ZIPu, každé uživatelské kopii ani novém releasu.

Zdroj inventáře: `analyzers.py::get_builtin_repository_analyzers` (403),
`discover_installed_analyzers` (446), `get_registered_analyzers` (541),
`get_available_modules` (671); výše uvedený skutečný frozen příkaz.
Souhlasný retained záznam:
`docs/verification/windows-parity/WP024/sol-long-budget-20261023/runtime/engine-verification.json`
(`checks.modules_discovered=21`).

Tabulka je skutečné pořadí frozen discovery. „Auto“ znamená způsobilost pro
Automatic, **stále podmíněnou `detect()`**, nikoli provedení na každém repo.

| Modul | Implementace po deduplikaci | Priorita | Auto | Experimental |
| --- | --- | ---: | --- | --- |
| python | plugin | 10 | ano | ne |
| c | plugin | 20 | ne | ano |
| cpp | plugin | 20 | ne | ano |
| dotnet | plugin | 20 | ano | ne |
| go | plugin | 20 | ano | ne |
| javascript-web | builtin | 20 | ano | ne |
| php-web | builtin; plugin stejného jména potlačen | 20 | ano | ne |
| python-web | builtin | 20 | ano | ne |
| rust | plugin | 20 | ano | ne |
| swift | plugin | 20 | ne | ano |
| terraform | plugin | 20 | ano | ne |
| node-service | plugin | 25 | ne | ano |
| config | builtin | 30 | ano | ne |
| iac | plugin | 40 | ano | ne |
| python-service | builtin | 50 | ano | ano |
| java-spring | plugin | 60 | ano | ne |
| php-laminas | builtin; plugin stejného jména potlačen | 60 | ano | ano |
| atproto | plugin | 90 | ne | ano |
| default | builtin | 100 | ano | ne |
| node-atproto | builtin | 150 | ano | ano |
| omeka-s | builtin; plugin stejného jména potlačen | 160 | ano | ano |

`src/attackmap/plugins_lock.py::OFFICIAL_PLUGINS` (8) a `pyproject.toml`
obsahují stejných 15 oficiálních balíčků: Python, Rust, Go, Java/Spring,
.NET, Terraform, C, C++, Swift, Node service, ATProto, PHP web, PHP Laminas,
Omeka S, IaC. `installer/attackmap.spec::ANALYZER_PKGS` zahrnuje všech 15;
deklarace bundlingu sama nenahrazuje discovery ze skutečného executable.

Kontrola metadata directories v tomto frozen enginu potvrzuje všech 15
oficiálních balíčků. Jejich `direct_url.json` ale odkazuje na lokální wheels
a jejich hashe, nikoli přímo na `vcs_info.commit_id`. Při WP042 proto musí
Git pin doložit řetězec wheel/build/release provenance; samotné metadata
instalované distribuce neprokazuje identitu upstream commitu.

Integrátor zopakoval read-only `modules --json`, ověřil executable hash
a uložil přesných 21 modulů i tři duplicate warnings do
[frozen-module-inventory.json](frozen-module-inventory.json). Neproběhl scan.

## Rozdíly, které musí plán výslovně řešit

1. **Katalog, instalace, registrace, výběr a provedení jsou různé stavy.**
   `desktop_capabilities.py::module_inventory` (34) posílá installed-only
   metadata. Picker správně uvádí, že inventář nedokazuje applicability
   (`AnalyzerSelectionModel.cs`, `AnalyzerSelectionView.cs`). Nemá však
   původ implementace, verzi balíčku, SHA pinu ani kompletní záznam důvodů
   skip/run pro konkrétní scan.
2. **Kolize vyhrává builtin před discovery pluginem.**
   `get_registered_analyzers` deduplikuje jména již při registraci, před
   priority sortem. Upgrade externích PHP balíčků proto nemůže automaticky
   změnit skutečně vybraný `php-web`, `php-laminas` či `omeka-s`. Vyžaduje
   explicitní compatibility policy a pravdivou provenance, nikoli pouhou
   změnu pořadového čísla.
3. **Explicitní výběr je úplný seznam.**
   `resolve_run_analyzers` (922) řadí pouze dodané analyzéry, když je seznam
   explicitní. Samotné `-m node-service -m atproto` nepřidá `config`,
   `javascript-web`, `node-atproto` ani jiné moduly. Případné profily musí
   mít explicitní rozvinutý seznam a viditelnou sémantiku; zachovat nynější
   význam CLI `-m`.
4. **Priority nejsou graf závislostí.**
   Běh/merge má pořadí `(priority, name)`. `node-service` (25) běží až po
   `javascript-web` (20), takže na shodném route klíči obecně vyhraje první
   záznam. Místní `merge.py::_upgrade_route_auth` (60) má důležitou výjimku:
   pozdější známé auth doplní původně `unknown` auth. Nedoplňuje automaticky
   veškerou bohatší strukturu a nerozhoduje konflikt dvou známých auth stavů.
   Route identita je `(path, method, file)`; GET/WS nebo jiný soubor mohou
   ponechat dvě reprezentace téhož povrchu. Nutné sémantické fixtures.
5. **Selhání applicability není totéž co „neshoduje se“.**
   `_should_run_analyzer` (955) při výjimce pouze loguje a vrací false;
   načtení/initializace pluginu mají také skip cesty. `analyze_repository`
   (730) jmenovitě eviduje chyby analýzy. Rozšířený coverage záznam musí
   rozlišit detect/load failure od běžného unmatched/opt-in skipu.
6. **Doporučení pluginů má jiné hranice než analýza.**
   `suggest.py::detect_ecosystems` (280) má `_MAX_DEPTH=3` a vlastní
   markerové detektory; neprokazuje runtime applicability ani kvalitu.
   „Installed“ určuje podle jména registrovaného analyzéru, takže u kolizních
   PHP jmen nerozliší instalaci konkrétního pluginového balíčku.
   `get_available_repository_modules` (691) filtruje prefix
   `attackmap-analyzer-`; skutečný Omeka repo v locku má název
   `attack-map-analyzer-omeka-s`. Org browsing tak není úplný autoritativní
   katalog; vhodnější je lock-backed katalog s explicitní repo mapou.
7. **Instalace a izolace jsou samostatné otázky.**
   `select_requested_analyzers` (556) umožňuje automaticky instalovat jen
   známý oficiální SHA pin při explicitním povolení; desktop picker nic
   neinstaluje. CLI pip mechanismus nelze bez návrhu převzít do frozen app.
   `analyzer_host.py` výslovně neomezuje filesystem ani síť; subprocess a
   pin nejsou sandbox ani publisher authenticity. WP035 zůstává nutný pro
   příslušné containment claims. Builtiny host standardně neizoluje.

## Upstream změny: vybrat piny podle skutečného diffu

Veřejná stránka analyzérů je užitečný rozcestník; její „known gaps“ se nesmí
kopírovat jako aktuální otevřený seznam. GitHub issues níže byly při přístupu
uzavřené. Stav issue není důkazem, že opravu obsahuje zdejší pin nebo že
prošla naším kontraktem.

| Balíček | Zdejší pin | Ověřeno proti upstreamu 23. 10. | Dopad na plán |
| --- | --- | --- | --- |
| Python | `1bcce0dd5d639cb83ada65cc3f5024bb5a1d9782` | `main` je o 5 commitů vpředu; commit `478208fd33b7fa30e2acbb08f184b2e289f7bb0a` přidal 12. 10. Django include/root, aiohttp RouteTableDef, Litestar controllers, Tornado a Sanic route řezy | Nejprve kontraktní diff/upgrade; nevytvářet duplicitní implementaci již dostupných oprav. Ověřit spolužití s místním `python-service`. |
| Go | `e92fc3de5c34485c4ea06032052ad0f6c21fd133` | Tento pin už opravuje falešné `.Get` routes a testdata/test soubory z issue #2. `main` je o 6 commitů vpředu: typed route auth a další route prefix/mux práce | Nepřepisovat issue #2 jako chybějící opravu. Kvalifikovat novější auth/prefix řezy a skutečné negativní případy. |
| .NET | `a1f00d05bc915940ed684f438c678e696f3de53d` | Tento pin už obsahuje opravu templates, MapGroup a route auth hintů z issue #2. `main` je o 5 commitů vpředu, včetně typed `Route.auth/guards/guard_evidence` | Odlišit dostupné route extraction od typed auth propagation a od desktop zobrazení. |

Porovnávané tipy `main` v době přístupu: Python
`87e4a8ac3de74e2a6f459af41ddc7c85cc1f3be5`, Go
`1c4159c88d65c2f82c454ba6c0972843c9f47384`, .NET
`83f01e48185be89815797b382b782ba4ab4a378d`. V tomto výzkumu nebyly instalovány.

Primární zdroje:

- [Python issue #2](https://github.com/mlaify/attackmap-analyzer-python/issues/2),
  [porovnání připnuté verze](https://github.com/mlaify/attackmap-analyzer-python/compare/1bcce0dd5d639cb83ada65cc3f5024bb5a1d9782...87e4a8ac3de74e2a6f459af41ddc7c85cc1f3be5).
- [Go issue #2](https://github.com/mlaify/attackmap-analyzer-go/issues/2),
  [porovnání připnuté verze](https://github.com/mlaify/attackmap-analyzer-go/compare/e92fc3de5c34485c4ea06032052ad0f6c21fd133...1c4159c88d65c2f82c454ba6c0972843c9f47384).
- [.NET issue #2](https://github.com/mlaify/attackmap-analyzer-dotnet/issues/2),
  [porovnání připnuté verze](https://github.com/mlaify/attackmap-analyzer-dotnet/compare/a1f00d05bc915940ed684f438c678e696f3de53d...83f01e48185be89815797b382b782ba4ab4a378d).

## Doporučené detekční řezy v existujících vrstvách

Tyto návrhy doplňují WP039 a vyžadují jeho kvalifikaci; nenahrazují jej.

| Vrstva | Implementováno / relevantní limit | Nejmenší další řez a ověřitelný výstup |
| --- | --- | --- |
| Node/ATProto | Místní overlay parsuje lexicon `defs.main`, wiring a auth signály; nevaliduje celé lexicon schema. `_LEXICON_TYPE_TO_METHOD` mapuje subscription na GET (`ecosystem_node_atproto.py:650`). Připnutý externí ATProto má WS a anonymous/optional verifier hints. | Společná fixture query/procedure/subscription, optional/nullCreds, generated handler i literal NSID, undeclared/unwired a non-ATProto negative. Vyřešit protocol/method a auth identitu mezi třemi vrstvami; žádná domnělá runtime validace ani síťové DID ověřování. |
| Python services | `_extract_django` (577) řeší literal `path`, class-view auth zůstává unknown (1250); `_emit` (898) u FastAPI/Flask přidává mount hints, routy drží lokální prefix. | Importově vyřešená route identity pro cross-file mounts, namespaces a více mountů; nejednoznačnost explicitně. Pak DRF permissions/viewsets a class-view auth po malých sadách. Porovnat novější upstream Python s místním overlay, aby nevznikly dvě neslučitelné URL reprezentace. |
| PHP/Laminas/Omeka | `_extract_laminas` (619) a Omeka route část používají literal `_ROUTE_DEF_RE`; child route parent kontext se neskládá. `.phtml` kontrola je úzká; existence validatoru není důkaz validace konkrétního vstupu. | Nejprve statický strom parent/child routes + explicitní controller/action vazby; následně auth/middleware binding a evidence input→validator→sink. Dynamic route, Twig/Blade a verze aplikace zůstanou označené unsupported, dokud nebude příslušný řez. |
| .NET/Go/Spring/Rust | Oficiální balíčky jsou již v katalogu a frozen discovery. Metadata neprokazují per-framework accuracy. | Prioritně .NET/Go typed route auth a groups přes kvalifikované piny; další rodiny až podle labeled chyb. Nezaměňovat dokončení parseru, core linkingu a native UI exposure. |
| Deployment / IaC | `config_scanner.py::extract_deployment_aliases` (920) již řeší Kubernetes Service/Ingress, compose a nginx. `iac` má Docker/compose/GHA posture; Terraform má infrastrukturu a omezené literal HCL vztahy. | Navázat na WP032: resource identity, port/protocol/namespace a ambiguity. Hlubší Kubernetes RBAC/NetworkPolicy/workload posture nebo statické Terraform reference jsou nové konkrétní řezy; nenazývat je prvním Kubernetes/Terraform supportem. |

Primární upstream kontrakty pro tyto návrhy:

- [Node source v připnutém commitu](https://github.com/mlaify/attackmap-analyzer-node-service/blob/8573b4a8dcefda5518a771c1a84be93b2eb9be05/src/attackmap_analyzer_node_service/analyzer.py):
  heuristická broad extraction; metadata zůstávají experimental/opt-in.
- [ATProto README v připnutém commitu](https://github.com/mlaify/attackmap-analyzer-atproto/blob/d2cb6ed6d5e69adf929a1fd7f66947830ecfd5fc/README.md):
  lexicon endpoint types, WS subscriptions a anonymous verifier hints.
- [IaC README v připnutém commitu](https://github.com/mlaify/attackmap-analyzer-iac/blob/002efc484fc26ead1243aa34b610ccb2230147b0/README.md):
  Docker/compose/GHA extraction; nikoli image/runtime inspection.
- [Terraform README v připnutém commitu](https://github.com/mlaify/attackmap-analyzer-terraform/blob/736f2c22051ffca537785edebf941a2d5ddb2487/README.md):
  literal infrastructure signály; unresolved interpolation a částečné API Gateway v1 path skládání.

## Kandidáti po kvalifikaci stávajícího rozsahu

Následující položky jsou návrhy k dalšímu scope rozhodnutí, ne tvrzení
o implementaci nebo již prokázané poptávce:

- **OpenAPI / protobuf / gRPC kontrakty:** offline declared surface,
  service/method/schema identity a vazba na implementaci; zřetelně odlišit
  declared od observed. Současný deployment helper výslovně uvádí grpc/tcp
  jako neřešené protokoly (`_port_app_protocol`, 581). GraphQL již má
  core BOLA/weakness detektory (`authz.py`, `weaknesses.py`); nový GraphQL
  řez by řešil resolver/schema/authorization vazby, nikoli údajnou úplnou
  absenci GraphQL podpory.
- **Ruby/Rails nebo další JVM/PHP framework:** katalog nyní nemá samostatný
  Ruby/Rails plugin ani plošné pokrytí každého JVM/PHP frameworku. Kandidáta
  vybrat z doložených cílových repos; broad language extraction před thin
  overlay. Existence Ruby sink pravidel v core by sama neprokázala Rails
  routing. Nový registry záznam vyžaduje SDK, packaging a negativní fixtures.
- **Kubernetes posture / Helm vstupy:** rozšíření existující deployment
  seam extraction. Renderované manifesty lze zpracovat offline; provádění
  libovolných Helm/chart hooks nebo buildů není implicitní součást detektoru.

## Navržené pořadí závislostí a brány

1. **Katalog a identita** — navázat na WP003; společný lock-backed katalog,
   selected-engine inventory a additive provenance fields. Zahrnout
   builtin/plugin původ, package/version/pin, shadowed collisions a rozdíl
   mezi static catalog a installed inventory. Zachovat offline probing.
2. **Výběr a coverage ledger** — navázat na WP006; Automatic/profile/explicit
   rozvinutý seznam, detect matched/unmatched/error, opt-in skip,
   load/execution failure, named partial coverage. Žádný skrytý download.
   Ověřit starší engine, chybějící modul, engine swap, filtr pickeru,
   použitý profile a skutečně provedené analyzéry.
3. **Kvalifikované plugin piny a coexistence** — po kontraktním řezu; použít
   `scripts/update_plugin_lock.py`, kontrolovat lock ↔ pyproject ↔ bundled
   metadata. Testovat kolizní jména, všechny kombinace builtins/plugins,
   priority, route identity a provenance; nebezpečné behavior changes mají
   samostatné fixture/corpus review. WP035 je předpoklad containment claims.
4. **WP039 hloubka a kvalita** — WP031, WP032, WP035 zůstávají jeho aktivní
   předpoklady. Node/ATProto, PHP a Python mohou mít samostatné fixture
   vlastníky; `analyzers.py`, `merge.py`, schemas a linking zůstávají
   serializované integrační soubory. Základní kontrakt je extraction-only.
5. **Distribuce a UI acceptance** — samostatný WP024/WP037 package důkaz
   a WP006 native workflow. Source discovery, frozen discovery, parser
   fixture, skutečný scan, viditelná práce v celé app a macOS lane mají
   vlastní důkazy. Žádné automatické dokončení WP006/WP039 z tohoto auditu.
6. **Nový ekosystém** — až po konkrétní volbě rodiny a fixture contractu;
   discovery/selection/SDK/snapshot/resource limits/packaging/presentation
   přijmout jako jeden sledovatelný rozsah. C27 maturity gate: nejméně
   30 repos, 300 pozitivních, 300 negativních, 10 clean repos a ≥20 % repo
   holdout; rodina ≥30/30 případů, precision ≥95 %, recall ≥80 %, TP/FP/FN
   a intervaly. Bez těchto důkazů ponechat experimental maturity.

## Metoda a hranice důkazů

Provedeno: CodeGraph + cílené čtení aktuálního zdroje; read-only discovery
ve dvou Python prostředích a skutečném existujícím frozen executable;
GitHub README/source/issue/compare GET přes GitHub connector; veřejný
rozcestník přes web search. Přímý web open původní stránky vrátil cache miss,
vyhledání [Analyzers / run order](https://docs.mlaify.io/analyzers/#run-order)
obsah zpřístupnilo. [SDK reference](https://docs.mlaify.io/sdk/) podporuje
kontrakt detection/selection/order; konkrétní místní odchylky jsou doloženy
kódem a skutečným discovery výše.

Neproběhly analýzy cílového repozitáře, live LM Studio HTTP, nativní GUI,
build/freeze, instalace nebo aktualizace pluginů, broad regrese ani nové
labeled corpus hodnocení. Žádný z návrhů zde proto není prokázané runtime
pokrytí, accuracy, platform parity nebo release acceptance.
