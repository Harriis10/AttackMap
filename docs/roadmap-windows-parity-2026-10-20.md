# AttackMap — roadmapa Windows parity a dokončení produktu
**Checkpoint 7. 11. 2026 — skutečný scan a opravy:** Uživatelský Automatic běh nad Juice Shopem dokončil analýzu i lokální AI odpověď (421 s, 18 nálezů, 1 cesta). WP005 má ověřené uložení/obnovení a přesný Markdown export, ale zůstává MANUAL_PENDING. Oprava SARIF verze prošla source/frozen gate; formátování známých AI referencí 100 testy a offline původním textem. Nový kandidát zahrnuje obě opravy a není nasazen. [WP005 podklady](verification/windows-parity/WP005/closeout-20261107/README.md) · [WP017 dávka](verification/windows-parity/WP017/citation-label-20261107/README.md) · [WP022 verze](verification/windows-parity/WP022/sarif-version-20261107/README.md). Computer Use je na pokyn uživatele vypnutý, aplikace zůstává otevřená. Ořez posledního snímku uživatel potvrdil jako chybu screenshot programu; další kontrola tohoto místa se neprovádí. Součet 44: 9 DONE, 5 IMPLEMENTED, 5 MANUAL_PENDING, 16 IN_PROGRESS, 7 OPEN, 2 DEFERRED; samostatné release a historické WP043 brány se nemění.

**WP044 kvalifikace — 7. 11. 2026:** Dokončen fyzický fleet16 source/API, skutečné source/frozen CLI, produkční headless consumer a jediný řízený source fault. Přesné IDs/provenance/negativní vazby i exporty mají nezávislé review; 134 nativních vstupů WP005 zůstalo beze změny. Celé WP044 zůstává IN_PROGRESS: syntetický corpus nenahrazuje reprezentativní produkční fleet, GUI ani maturity. [Protokol a přesná omezení](verification/windows-parity/WP044/qualification-20261107/README.md). WP005 ovládá výhradně uživatel; Computer Use je na jeho pokyn zastavený.

**WP005 pokračování — 7. 11. 2026:** Po dokončení WP032 pokračuje autorizovaná práce na nativních options/settings/capabilities. WP004 je DONE; WP005 zatím MANUAL_PENDING. Běží oddělené modelové, build a akceptační rozsahy; skutečný choose/save/reopen/unsupported průchod a vizuální kontrolu provádí integrátor. Samostatné lidské, rendering a release brány se nepřebírají.

**WP032 dokončen — 7. 11. 2026:** Explicitní namespace/service identita, přesný backend port/protokol a typované declaration/evidence reference jsou přijaté DONE. Finální společná sada 609 PASS; source i fresh-frozen 9/9 referenčních běhů, 4+4 skutečné native consumer běhy a oba Automatic Juice Shop běhy PASS. Nezávislé přijetí a závěrečný collector ověřily aktuální zdroje i build. Raw provenance rozdíly zůstávají přiznané; rozdíl SARIF driver.version je samostatný otevřený nález WP022. [Protokol a hranice přijetí](verification/windows-parity/WP032/closeout-20261107/README.md). Součet 44: 9 DONE, 5 IMPLEMENTED, 5 MANUAL_PENDING, 16 IN_PROGRESS, 7 OPEN, 2 DEFERRED. Průběžný uživatelský pokyn dovoluje další dostupnou roadmapovou práci; rendering a release brány zůstávají samostatné.

**WP018 dokončen — 7. 11. 2026:** Source i nový standardně zmrazený engine prošly formátovou paritou, fleet16 s workers 1/2/4, osmi fault/cleanup scénáři, skutečným C# consumerem a Automatic Juice Shop během bez vyčerpání 600 s budgetu. Nezávislé přijetí **DONE**; 114 source PASS / 1 Windows SKIP, 19 verifier PASS, 90 native model kontrol. [Protokol a hranice přijetí](verification/windows-parity/WP018/closeout-20261106/README.md). Součet 44: 8 DONE, 5 IMPLEMENTED, 5 MANUAL_PENDING, 17 IN_PROGRESS, 7 OPEN, 2 DEFERRED. Ostatní zastavené úkoly se neobnovují; rendering/release brány zůstávají samostatné.

**STOP / předání 31. 10. 2026:** Uživatel požádal uložit práci a zastavit pokračování. [Aktuální handoff: izolace, rendering a fleet](verification/windows-parity/HANDOFF-20261031-ISOLATION-RENDER-FLEET/README.md) shrnuje skutečné důkazy včetně live11, dirty tree a další otevřené brány. Bez nového pokynu nepokračovat; WP017/WP019/WP034/WP035/WP043 IN_PROGRESS, rendering FAILED. Následující datované checkpointy jsou zachované předchozí stavy.

**WP035 frozen external plugin — 31. 10. 2026:** Nový běžný frozen CLI běh nad dvěma Python fixtures s workers=2 skutečně spustil PythonAnalyzer 0.1.0 v oddělených analyzer_host procesech. OS observer zachytil oba repo children s isolation flagem i dva analyzer hosts; oba raw ledger uvádějí succeeded/isolated, exit 0, Job active 0 a fixtures beze změny. Nezávislý reviewer ověřil raw důkazy a hashe. Předchozí config-only `in_process` vysvětluje záměrná builtins policy; nešlo o ztrátu flagu. Wheel attestation není verified Git pin: `pin_status=unverified`, `content_verified=false`. Snapshot-bound diagnostic engine ani tento běh neuzavírají OS sandbox, crash/hang containment, celé WP035/C36 či release; všechny failed pokusy zachovány. WP035 **IN_PROGRESS**. [Evidence a hashe](verification/windows-parity/WP035/frozen-plugin-isolation-20261031/README.md).

**WP035 frozen parallel CLI — 31. 10. 2026:** Skutečný běžný CLI běh nad reader/writer fixtures s `--fleet-workers 2 --isolated-analyzers` dokončil oba scany, exit 0. Externí Windows CIM pozorování skutečných OS argv obou dětí potvrdilo právě jeden `--isolated-analyzers`, správný frozen EXE a repo/output/result identity. Fixtures beze změny, Job active 0 a cleanup dokončen. Dva dřívější failed pokusy zůstávají zachovány; úspěch se vztahuje jen na snapshot-bound diagnostický frozen engine a tyto fixtures, ne OS sandbox, external plugin execution/fault containment či whole WP035/C36/release. Ledger `execution_mode=in_process` se vyšetřuje; skutečná izolace analyzéru není prokázána. WP035 **IN_PROGRESS**. [Evidence a raw verification](verification/windows-parity/WP035/frozen-parallel-isolation-20261031/README.md).

**WP019 native fleet transport live-01 — 31. 10. 2026:** Diagnostický native build (session output: exit 0, 0 warnings/errors, 1:14.59; 19 guard tests PASS) provedl skutečný preflight a persisted request: config, isolation=true, budget 30 s, timeout 180 s, 1 worker/2 fixtures. Reader/writer completed a hashované manifests ověřeny, 9/9 PASS, exit 0, fixtures beze změny, Job active 0 a process census čistý. Engine `386324…` je snapshot-bound frozen diagnostic; whole-current-source gate selhala na čtyřech native QA files během freeze, žádný engine/Python/schema input nezměněn. Nejde o same-source release ani důkaz paralelní CLI cesty, OS sandboxu, named profiles, summary UI či production fleet16. WP019/WP034/WP035 IN_PROGRESS. [Raw důkazy a hranice](verification/windows-parity/WP019/native-fleet-transport-20261031/live01.md).

**WP043 live-10 checkpoint 31. 10. 2026:** Source-bound self-contained diagnostický build s SDK task override: exit 0, 0 warnings/errors, 1:46.70; deferred automatic Fit v GraphExplorerView a Grid wrapping Findings mají nezávislé source review clear. Live-10: 75 valid/0 discarded/5 complete rounds/5 diagram activations/clean close; PID 28972 nezůstal. Všech 75 snímků vizuálně prohlédnuto; první dva Findings title jsou celé zalomené, dlouhá metadata mají ellipsis, celý graf je v tomto případě ve viewportu. Labels jsou malé, zoom a ruční Fit netestovány; snímek dokládá automatický Fit. Jeden Dark 1600×1000 report a retained frozen engine neuzavírají běžný non-capture/manual/release běh ani jiná témata/velikosti. Root cause unknown, WP043 **IN_PROGRESS**, obecný rendering **FAILED**. [Evidence, hashes a limity](verification/windows-parity/WP043/live10-fit-wrapping-20261031/README.md).

**WP043 live checkpoint 31. 10. 2026 — live-09:** Diagnostický source-bound self-contained build s task override dokončil 5 kol a 5 diagram activations: 75 captures, 0 discarded, clean close. Všech 75 snímků bylo skutečně vizuálně zkontrolováno (agenti kola 1–4, root kolo 5); mizení textu ani popup nebyly pozorovány, Overview a detail jsou čitelné. Live-08 předtím zachoval 10 snímků/0 kol a activation-failed kvůli chybějícímu enginu. Live-09 používá explicitní retained frozen engine, nejde o nový společný engine/package ani release. Harness `--engine`, timing/fail-fast: 110 unittest PASS a nezávislé review. Rozsah je jediný Dark 1600×1000 report; malý/oříznutý diagram, ořezy Findings a unsupported offline diagram fallback zůstávají, scroll nebyl ověřen a root cause není prokázána. WP043 **IN_PROGRESS**, obecný rendering **FAILED** a V01–V03 zůstávají otevřené. [Detail a omezení](verification/windows-parity/WP043/live09-visual-review-20261031/README.md).

**Aktuální integrační checkpoint 31. 10. 2026:** WP017 dokončil jeden skutečný CLI review nad `C:\tmp\juice-shop` přes lokální LM Studio (`http://127.0.0.1:1234/v1`, `cyberstag-security-26b-a4b-v1`), exit 0 a dokončenou odpověď; jde pouze o bounded evidence, nikoli o přijetí všech AI režimů či nativní cesty. WP019/WP034/WP035 mají ověřené transportní, sémantické a CLI-isolation řezy, ale jejich whole-task resource/native/OS brány zůstávají otevřené. WP043 má nyní přísně svázanou UIA recovery, mitigaci root-tooltipu a 106 testů + 149 podtestů PASS; live-05/live-06 však skončily před nalezením okna a nepřinášejí vizuální důkaz. Neplatný overlay vyvolal bootstrap výzvu Windows App Runtime, byl vyřazen a žádný runtime nebyl instalován. Diagnostický self-contained build s předkompilovaným přesným SDK manifest taskem přes `UsingTask Override` vytvořil `native-candidate-selfcontained-taskoverride` (exit 0, 0 warnings/errors); běžný SDK inline task se stále zasekává v `RoslynCodeTaskFactory`. `live-07` otevřel owned okno (PID 40344, HWND 138840), runId `9d101901c68e497bae4df80699404306`, ale foreground Terminal safety zastavila běh před transient dismissal: 0 captures/0 rounds, bez manual review a visual acceptance. WP017/WP019/WP034/WP035/WP043 zůstávají **IN_PROGRESS**, rendering **FAILED** a V01–V03 blocked. [LM Studio](verification/windows-parity/WP017/lm-studio-review-20261031/README.md), [fleet transport](verification/windows-parity/WP019/native-fleet-transport-20261031/README.md), [ledger parity](verification/windows-parity/WP034/ledger-semantic-parity-20261031/README.md), [WP043 checkpoint](verification/windows-parity/WP043/popup-tooltip-recovery-20261031/README.md).

**Tři navazující core řezy 31. 10. 2026:** WP031, WP032 a WP034 postoupily ve třech bounded, nezávisle revidovaných funkcích bez whole-task tvrzení: literal Express/Sequelize binding resolver je fail-closed na lexical shadowing a neprokazuje žádný nový held-out TP; multi-backend/unresolved proxy fakta nyní blokují direct/proxy identity fallback včetně DNS root-dot ekvivalence; opt-in fleet input quota má deterministic child-only limity, typed partial stav a zachovanou poziční kompatibilitu API. Společná aktuální source kvalifikace **948 PASS, 1 SKIP, 0 failures/errors** s třemi explicitně deselected známými raw-ledger parity scénáři; jejich současný samostatný běh nadále má 3 FAIL. WP031/WP032/WP034 zůstávají IN_PROGRESS, WP043 rendering FAILED; žádný package/release/native/UI claim. [Evidence, JUnit a limity](verification/windows-parity/ROADMAP-THREE-SLICES-20261031/README.md).

**Kampaň core kvality 31. 10. 2026:** WP030/WP032/WP033 dokončily tři navazující bounded řezy bez whole-task tvrzení: oddělený frozen eval corpus s 27 novými provenance-backed očekáváními odhalil 0 TP / 0 FP / 16 FN bez detector tuningu; explicitní `grpc`/`kafka`/`wss`/`ftp` odkazy už nemohou vytvořit observed HTTP ani proxy edge; 100 deterministických full≡incremental sekvencí (300 mutací, 600 porovnání, 200 warm checkpointů) nyní doplňuje fail-closed snapshot-excerpt binding. Společná source kvalifikace **439 PASS, 0 failures/errors/skips**. Žádný package/release/UI rendering claim; WP030/WP032/WP033 jsou IN_PROGRESS a WP043 rendering zůstává FAILED. [Evidence, JUnit a limity](verification/windows-parity/ROADMAP-CAMPAIGN-20261031/README.md).

**Další roadmapový řez 31. 10. 2026:** Tři větší omezené řezy posunuly skutečné otevřené brány bez whole-task tvrzení: test-only frozen A/B Juice Shop kvalifikace dokázala cache invalidaci při změně loader code (658 → 0 → 658 → 0); Django decorator a view-target resolver je fail-closed při package shadowingu, ale zachovává jednoznačné explicitní importy; explicitní Kafka YAML/JSON declarations dodávají jen statickou `declared` producer/consumer fleet hranu. Společná source kvalifikace **620 PASS, 13 SKIP, 0 errors/failures**. Žádný package/release/UI rendering claim; WP033/WP039/WP044 jsou IN_PROGRESS a WP043 rendering zůstává FAILED. [Evidence, JUnit a limity](verification/windows-parity/ROADMAP-NEXT-20261031/README.md).

**Pokračování 31. 10. 2026:** Scoped řezy WP033/WP039/WP044 pokračují bez tvrzení whole-task acceptance: frozen `engine_identity` v PyInstaller layoutu ověřeně hashující loader code provedl na skutečném Juice Shop cold 658 → warm 0 per-file extractions se shodným výsledkem; Python Django pokrývá omezené mounted named-regex a attestované plain class views; Rails `config/database.yml` může vytvořit pouze statický shared-datastore `candidate` s oboustrannou evidencí. Společná aktuální source sada 487 PASS / 7 SKIP; žádný nový native package, GUI ani release. [Důkazy, limity a další brány](verification/windows-parity/ROADMAP-CONTINUATION-20261031/README.md).

**Společná integrace a instalace 30. 10. 2026:** Uzavřen funkční celek WP039/WP044 od kvalifikovaného zdroje přes nově zabalené jádro do nativní aplikace a místní instalace RequiredBundled. Opraven isolated-worker vstup a nesoulad obecných Django signálů; nativní Declared filtr a oboustranné zdroje zachovávají nesměrovaný význam vazby. Core 335 PASS a 5 skutečných installed-plugin testů (překryv a převzaté nezměněné důkazy popsány); finální instalovaná aplikace 71 kontrol, 16 syntetických repo, 6 vizuálně prohlédnutých snímků, všech 796 souborů ověřeno. ZIP, externí SBOM a testovací instalace hotové. WP039/WP043/WP044 IN_PROGRESS; globální rendering FAILED a V01–V03 blocked, produkční/maturity/manual/release brány otevřené. Nově zaznamenána frozen-cache mezera WP033. [Výsledky, balíček a další brány](verification/windows-parity/ROADMAP-CLOSEOUT-20261030/README.md).

**Větší integrační dávka 30. 10. 2026:** Dokončeny dva core funkční celky: přesný původ instalovaného analyzéru v izolovaném workeru (WP039) a explicitní deklarace úložiště až do fleet grafu (WP044). Finální společná core regrese 320 PASS; harness 68 PASS + 20 podtestů. Skutečný instalovaný plugin, Juice Shop a fyzický syntetický 16-repo fleet ověřeny. WP043 candidate-10 používá Ctrl+Alt+Shift+R; live-31 bez F7 dialogu dokončil čtyři kola, páté zastavila prázdná root RTB bitmapa. Všech 19 dostupných cílových obrazů vizuálně prohlédnuto; mizející text nadále reprodukován. WP039/WP043/WP044 zůstávají IN_PROGRESS, rendering FAILED a V01–V03 blocked. [Výsledky, přesné rozsahy a další brány](verification/windows-parity/ROADMAP-BATCH-20261030/README.md).

**WP043 / oprava diagnostiky před dalším během 30. 10. 2026:** Sonda candidate-09 používá Ctrl+Shift+F7; běžná F7 již diagnostiku nespouští. Harness odmítá modální klientský dialog, neověřitelnou modalitu a jiné vnější rozměry než 1600×1000. Nativní i nezávislá PNG kontrola rozlišují prázdný Detail od nepoužitelného prázdného/jednobarevného root rastru; odmítnuté soubory se zachovají a nezahájí B. PNG kontrola ověřuje CRC i dekódované pixely. 65 fake testů + 20 podtestů PASS, nezávislé source review bez blockerů, offline publish candidate-09 PASS; retained engine má všech 308 souborů shodných s candidate-08. Reinterpretace původních čtyř D/T souborů detekuje oba prázdné root rastry. V této dávce nebyl proveden žádný nový živý běh: runtime izolace zkratky, UIA modalita a skutečná kvalita nové sondy čekají na další řízené ověření. WP043 IN_PROGRESS, rendering FAILED, V01–V03 blocked; nejde o opravu produkčního vykreslování ani release. [Build, testy a review](../artifacts/diagram-integration-20261024/wp043-continuation-20261025/probe-hardening-20261030/candidate09.json).

**WP043 / obnovení podle předání 30. 10. 2026:** Tři paralelní agenti prověřili harness, akceptační brány a skutečné snímky. Candidate-08 i retained engine/report mají přesné handoff hashe; cílený fake harness prošel 56 testy a 15 podtesty. Jediný `detail-root-render-probe-live-28-retry-01` skončil timeoutem Architecture ACK ve druhém kole: 20 accepted ordinary captures, 5 discarded a dvě A/D/T/B sady, nikoli celý pětikolový běh. Všech osm dostupných obrazů bylo skutečně prohlédnuto: první A má chybějící tělo Detailu, od prvního B obraz zakrývá F7 dialog procházení pomocí kurzoru; všechny čtyři D/T rastry jsou zcela průhledné. Čistá interpretační matice tedy neplatí a nejde o `not-reproduced`. PID 38136 již neběží; raw `closedCleanly=false` zůstává zachováno. WP043 je IN_PROGRESS, rendering acceptance FAILED a V01–V03 blocked. Další gate je vysvětlit F7/modal interakci a kvalifikaci rastrů před novým řízeným pokusem; příčina mizení textu ani oprava nejsou prokázané. [Částečné vizuální review](../artifacts/diagram-integration-20261024/wp043-continuation-20261025/detail-root-render-probe-live-28-retry-01/visual-review/manual-review.json). Starší checkpointy níže zůstávají historické.

**Scoped integrace 27. 10. 2026:** WP032/WP039/WP044 prošly nezávislým review a cílenými regresemi (207 PASS; 328 PASS + 2 SKIP; 160 PASS); celé úkoly zůstávají IN_PROGRESS. WP043 candidate-07 dokládá v kole 4 A blank → okamžité RenderTargetBitmap complete → B blank při stejné finding revizi a bez property/layout mutací. Kolo 2 ukazuje i opačnou divergenci a kolo 5 pouze recovery korelaci; RTB proto není samostatný live-presentation oracle. Rendering acceptance je FAILED, root cause ani V01–V03 acceptance nebyly prokázány. Další postup je nemutační render/composition diagnostika WP043, skutečný emitter a reprezentativní runtime WP044 a zbývající WP039 plugin/maturity brány. [Vizuální review WP043](../artifacts/diagram-integration-20261024/wp043-continuation-20261025/detail-render-probe-live-27-retry-03/visual-review/manual-review.json). Následující checkpointy jsou historické.

**Aktuální scoped checkpoint 23. 10. 2026:** [dávka tří Sol 6.1 / ultra agentů](verification/windows-parity/ROADMAP-NEXT-20261023/FINAL-HANDOFF.md) dokončila přípravu kvalifikovaného datastore kontraktu WP044, evidence/source/back řez WP043 a opravu startup gate WP023. 104 pytest PASS, 128 navigačních assertions PASS, 94 skutečných native kontrol / 16 completed test-repo children a čtyři compiled startup scénáře PASS. Native source03 + retained frozen source02 je scoped QA, nikoli nový same-source package; předchozí portable beze změny. Non-HTTP produkční extraction, celé WP023/WP043/WP044 a jejich manuální/release/dependency brány zůstávají otevřené. Leases dávky uvolněné, IDLE. Následující checkpointy jsou historické.

**Třetí dávka analyzérů ověřena 23. 10. 2026:** WP042 je IMPLEMENTED: nativní profily/provenance/chyby discovery, podrobný ledger 1.1 a živý průběh, nový source-bound Windows ZIP se SBOM. 338 Python PASS, 164 native kontrol, 17 + 8 skutečných frozen Python případů, tři shodná before/after porovnání Juice Shopu a osm vizuálně zkontrolovaných snímků. WP039 zůstává IN_PROGRESS kvůli C27/C38, závislostem a deklarovaným omezením; ruční/release acceptance se nepřiznává. [Výsledky a balíček](verification/windows-parity/WP039/sol-ultra-20261023-python/README.md). Vlastní lease je uvolněná; souběžná fleet práce zůstává zachovaná.

**Fleet16 integrován 23. 10. 2026:** WP043/WP044 jsou IN_PROGRESS. Společný model všech 16 roots, interaktivní Cytoscape přehled, nativní Canvas/MSAGL a úplné JSON/SVG exporty jsou začleněné do Fleet. Skutečné source běhy 16 testovacích repozitářů a Juice Shop + 15 fixtures prošly; řízený partial zachoval 15 child výsledků a failed skupinu. Společný source-bound kandidát02 prošel 75 skutečnými native kontrolami, 16 child manifesty, oběma renderery a frozen Juice Shop+compare; kompaktní lišta je opravená. Plný portable ZIP je uložený v `C:\Projects\AttackMap-Windows-x64-fleet16-20261023.zip`; lokální Git checkpoint `f5247d0`. Vlastní lease je uvolněný, další úkoly se nezahajují. Neuzavírá se non-HTTP, reprezentativních 16 produkčních repos, manual/clean-host ani macOS acceptance. [Důkazy a zbývající brány](verification/windows-parity/WP043/fleet16-20261023/README.md). Starší checkpointy níže zůstávají datované. Aktuální součet WP001–WP044: 7 DONE, 5 MANUAL_PENDING, 6 IMPLEMENTED, 16 IN_PROGRESS, 8 OPEN, 2 DEFERRED.

**Druhá implementační dávka ověřena 23. 10. 2026:** Druhá dávka Sol 6.1 ultra ověřena: native profily/request 1.5, per-run ledger, bounded Node/ATProto WS/auth fix; 508 PASS + 2 SKIP, 597 native kontrol, source/frozen/native Juice Shop a scoped vizuální review. WP042/WP039 zůstávají IN_PROGRESS; whole-task/manual/package/maturity brány otevřené. [Výsledky a další krok](verification/windows-parity/WP042/sol-ultra-20261023-batch2/README.md). Leases této dávky jsou uvolněné. Starší checkpointy níže zůstávají datované.

**Povinný fleet rozsah doplněn 23. 10. 2026:** jeden společný scan 16 repozitářů a jejich celkové architektonické schéma, přehled repo skupin → služby/komponenty → přesná evidence. [Definice a přijetí](verification/windows-parity/RESEARCH-2026-10-23-analyzers-graphs/fleet16-requirements.md). WP043 již nesmí odložit fleet jako volitelné rozšíření; WP044 dodá strukturované vztahy, WP018/WP019 scheduling/budget/identity. Aktuálně 44 úkolů (7 DONE, 5 MANUAL_PENDING, 5 IMPLEMENTED, 15 IN_PROGRESS, 10 OPEN, 2 DEFERRED); původní stavy zůstávají zachované. Obě rendererové varianty mají stejně prioritní 16-repo spike; samotný jednodušší native prototype o výběru nerozhodne.

**První implementační dávka ověřena 23. 10. 2026:** WP042 a přípravný PHP řez WP039 zůstávají IN_PROGRESS. Tři agenti GPT-6.1 Sol / ultra dodali katalog kolizí, verzované CLI profily a parent/child routování Laminas/Omeka; 266 cílených testů PASS, 2 SKIP, nový frozen engine s 15 pluginy / 21 účinnými analyzéry a tři shodná celá JSON porovnání Juice Shopu. [Výsledky a zbývající brány](verification/windows-parity/WP042/sol-ultra-20261023/README.md). Celkem 43 úkolů: 7 DONE, 5 MANUAL_PENDING, 5 IMPLEMENTED, 15 IN_PROGRESS, 9 OPEN, 2 DEFERRED. Nativní UI, ledger a whole-task/release acceptance zůstávají otevřené; leases dávky jsou uvolněné.

**Rozšíření plánu 23. 10. 2026:** [zdrojový audit a výzkum analyzérů/grafů](verification/windows-parity/RESEARCH-2026-10-23-analyzers-graphs/README.md) přidává WP042 a WP043 jako OPEN. Celkem 43 úkolů: 7 DONE, 5 MANUAL_PENDING, 5 IMPLEMENTED, 13 IN_PROGRESS, 11 OPEN, 2 DEFERRED. Výzkum nezměnil stavy původních 41 úkolů a nepřiznává novou runtime ani release acceptance. Nejnovější výzkumní subagenti používají GPT-6.1 Sol / ultra; níže uvedená jiná nastavení patří datovaným checkpointům.

**Aktuálně znovu obnoveno 23. 10. na výslovný pokyn uživatele:** [dávka GPT-6.1 Sol ultra](verification/windows-parity/RESUME-2026-10-23-sol-ultra/README.md). Scoped řezy WP016 metadata, WP023 window lifetime a WP017 controlled provider faults jsou integrované a cíleně ověřené; whole-task brány zůstávají otevřené. Předchozí pokyn po portable skončit je tímto novým zadáním odvolán; starší odstavce níže jsou datované checkpointy. Žádná nová release/ruční acceptance se tím nepřiznává.

**Závěrečný checkpoint 23. 10.:** [výsledky 7200s kandidáta](verification/windows-parity/RESUME-2026-10-22/checkpoint-2026-10-23.md) obsahují nové runtime/package/installed důkazy, všechny čtyři Hunt+verify HTTP odpovědi (partial kvůli abstenci), Triage scoped PASS a otevřené GUI/obsahové brány. Po požadovaném lokálním Git uložení a full portable buildu se další úkoly nezahajují. Následující starší odstavce jsou předchozí checkpoint, nikoli aktuální běhový stav.

**Běh 22. 10. 2026 je znovu AKTIVNÍ na výslovný pokyn uživatele.**
[Aktuální postup](verification/windows-parity/RESUME-2026-10-22/astra-high/RESUMED.md)
navazuje na historický STOP hlídače využití (ohlášeno 75 %).
[Aktuální handoff Astra/high](verification/windows-parity/RESUME-2026-10-22/astra-high/STOP-HANDOFF.md)
zachycuje dokončenou broad/native/frozen regresi a nový RequiredBundled
package/SBOM. Installed native scan již prošel a [WP024 je DONE v unsigned-preflight rozsahu](verification/windows-parity/WP024/astra-fresh-20261022/unsigned-acceptance.md).
[Checkpoint 23. 10. 2026](verification/windows-parity/RESUME-2026-10-22/checkpoint-2026-10-23.md)
dokládá implementaci explicitního lokálního allowance 7200 s: 412 Python PASS,
55 runner testů + 120 subtests PASS a 117 native offline assertions PASS.
Na starším kandidátu je Hunt+verify retry 02 partial (poslední jury timeout),
Remediate scoped live PASS, Triage retry 02 přes HTTP 200/pre-close parity true
celkově FAIL kvůli exitu `0xC000027B`. Freeze 01 je interim; root připravuje
finální freeze 02. Nový 7200s kandidát nepřebírá runtime/live/GUI PASS.
Pracovní agenti používají GPT-6.1 Sol / medium; WP017/WP023 zůstávají IN_PROGRESS.

**Výchozí stav: 20. října 2026.** Tento dokument řídí další pořadí práce. [Audit](windows-parity-audit-2026-10-20.md) zachycuje srovnání místního HEAD, veřejné dokumentace a zdrojů macOS. [TODO](windows-parity-todo.md) rozepisuje úkoly; [JSON backlog](windows-parity-backlog.json) poskytuje závislosti a vlastnictví pro orchestrace.

Původní [C01–C40](roadmap-2026-2028.md) jsou historickým zdrojem definic kvality, platným pouze v rozsahu převzatém touto roadmapou a konkrétními WP úkoly; původní [AM001–AM054](implementation-todo.md) zůstává historickou stopou. Starší dokumenty nejsou samostatným zadáním pro agenty; autoritu dokumentů určuje [aktuální rozcestník](README.md). Nové `WPxxx` označuje konkrétní zbývající řez, nikoli nový důkaz splnění starého kritéria. Windows M3 se znovu neotevírá; Windows C26 se nevrací. Nová roadmapa nepředstavuje souhlas s automatickým publikováním nebo snižováním kritérií.

## Cíl a hranice

Windows WinUI umožní běžnému uživateli stejnou podstatnou obrannou práci jako prohlédnutý macOS HEAD: nastavit scan, rozumět prioritám a coverage, procházet cesty a inventáře, zobrazit diagram, použít AI režimy, porovnat výsledky, pracovat se suppression, analyzovat fleet a zapnout watch jednoho repozitáře.

Zachovat lokální výhody: identitu generací, integritu artefaktů, řízené procesy, konzervativní evidenci, chráněné credentials, retenci/pinning, diagnostiku a skutečné LM Studio zapojení. Nativní ovládání se má řídit Windows; shodné rozložení macOS není cílem parity. Model/scoring a odvozování vazeb zůstávají v Python core.

Tři samostatné výsledky:

- **Funkční parita Windows**: checkpointy K1–K4 a integrační průkaz, včetně přesně pojmenovaných omezení.
- **Veřejně vydatelná Windows verze**: navíc K5 a Windows část K6; samostatně schválený supported scope.
- **Dvouplatformní produkt a širší quality claims**: K7 a relevantní části K8. Windows implementace může pokračovat bez macOS hostu; macOS PASS se nepředstírá.

## Checkpointy a pořadí

Odhady jsou pracovní intervaly při jednom integrátorovi a nejvýše třech implementačních agentech; nejsou kalendářní slib. Lidská studie a release credentials mají vlastní dostupnost.

| CP | Výsledek | Úkoly | Předpoklady | Odhad |
| --- | --- | --- | --- | --- |
| K0 Audit baseline | Datované porovnání zdrojů a rozdílů | Tento audit a plán | Žádné | Dokončeno jako dokumentační audit; bez nové runtime acceptance |
| K1 Kontrakty pro paritu | Capabilities, options, fixtures, fail-closed kompatibilita | WP001–004, WP007 | K0 | 1–2 integrační cykly |
| K2 Nativní evidence workspace | Scan UX, inventory, risk paths, diagramy, suppression, historie, exporty | WP005–013, WP022; rozšíření WP043 | K1 pro integraci; views lze vyvíjet proti zmrazeným fixtures | 2–4 cykly; nové rozšíření po samostatném spike |
| K3 AI režimy | Pět režimů, jury, budget/citation metadata a skutečný lokální model | WP014–017 | K1; finální UX navazuje na K2 | 2–3 cykly, částečně souběžně s K2 |
| K4 Fleet a watch | Nativní fleet 16 repos, celkové schéma a správný single-repo watch | WP018–020, fleet část WP023; fleet brána WP043/WP044 | K1; K2 pro výsledky; typed architektura z WP044 | 2–3 cykly; fleet graf po stejném integračním spike |
| K5 Windows release candidate | Jeden zapečetěný kandidát, podpis a čistý instalační životní cyklus | WP023–026, WP037 | K2–K4, relevantní core blockers z K8 | 1–2 cykly + host/certifikát |
| K6 Uživatelské přijetí | Ověřené usability/accessibility a beta | WP026–027 | Studie může začít na stabilních journeys K2; beta na kandidátovi K5 | Nejméně 4 týdny skutečné bety dle C32 |
| K7 macOS contract parity | Mac používá kompatibilní kontrakt/artefakty a má vlastní důkazy | WP028–029, WP038 | K1; macOS checkout/host | Samostatná lane, odhad po platform preflight |
| K8 Core quality a scale | Dokončené zbývající C27/C28/C33–C38, volitelný fleet watch, efektivní katalog analyzérů a fleet architektonická data | WP021, WP030–035, WP039–040, WP042, WP044 | Nezávislé části hned po K0; shared-file leases | Po menších měřitelných řezech |
| K9 Podmíněný týmový produkt | Podložené go/no-go, případný samostatný pilot | WP036, WP041 | C39 předpoklady a lidská poptávka | Odloženo; neblokuje paritu |

Jeden cyklus znamená dokončit malý řez, cíleně ověřit, integrovat a ukázat viditelný výsledek. Při jednom člověku se provádí stejné úkoly sekvenčně. **K5 candidate není automaticky veřejné vydání a K0 neuzavírá WP implementace.**

### Nové rozšíření: analyzéry a grafový průzkum

- **WP042 — efektivní katalog, profily a aktualizace analyzérů (P1/K8):** dříve zabalený engine již obsahuje 15 oficiálních pluginů, ale registruje 21 efektivních modulů po kolizích s devíti místními built-ins. Inventář musí patřit zvolenému executable a uvést původ, kolize, default/opt-in, skutečný výběr a důvod vynechání. Profily nesmějí ztratit základní vrstvy při explicitním `-m`. Aktualizace se vybírají podle připnutého zdroje a skutečné změny extraction, nikoli stáří issue v dokumentaci; bez automatických instalací.
- **WP039 + WP031 — skutečné rozšíření detekce:** přednostně mount/router prefixy, per-route auth a souběh Node/ATProto/PHP vrstev; paired pozitivní/negativní případy a non-regression. Hlubší Kubernetes posture a protobuf/gRPC/OpenAPI extrakce jsou další kandidáti k inventuře pod WP042, nikoli tvrzení, že současný core nemá žádné Kubernetes/GraphQL pokrytí. Původní C27/C38 quality gates zůstávají.
- **WP010 → WP043 — skutečné grafy uvnitř aplikace (P1/K2):** Windows již má inertní nativní Canvas renderer, ale omezený parser a pevnou mřížku. Nejdřív opravit výchozí volbu slovního `architecture.md`; následně additive typed graph kontrakt z core, stabilní identity/evidence a layout podle hran. V1 povinně pokryje celé schéma 16-repo fleet: repo skupiny, modelované služby/komponenty a přesnou mezi-repo evidenci z WP044. Collapse/expand zachová druh/směr/resolution a podkladové edge IDs; celý zachycený model má datový i grafický export. Balíčkový graf vyžaduje skutečné dependency hrany z resolveru, nikoli odhad z tabulky.
- **Renderer se vybere důkazem:** stejně prioritně porovnat cluster-aware WinUI Canvas + MSAGL s lokálním Cytoscape.js a compound layoutem fCoSE; Dagre jen pro vhodnou plochou projekci, ELK po cíleném ověření. Archify posuzujeme pro vysvětlující exporty; přezkoumané materiály nedokládají hotové aplikační live-graph SDK. Spike zaznamená interakce, paměť, payload/licence, offline chování a skutečný vzhled; přidání knihovny zatím není schválená implementace. Jde o vymezení podporovaného grafového rozsahu, ne obnovení Windows C26.

WP042 a příprava WP043 mohou běžet souběžně pod oddělenými leases. Kontrakty, registry/report writer a shell integruje vždy jeden owner. Závislosti a měřitelné DoD jsou v [TODO WP042](windows-parity-todo.md#wp042), [WP043](windows-parity-todo.md#wp043) a JSON backlogu. Nové rozšíření se při integraci kandidáta ověří v odpovídajícím scope; výzkum sám neotevírá žádnou síťovou instalaci, provider běh ani publikování.

### Stav po obnovení 22. 10. 2026

Aktuální prováděcí záznam a nezávislý audit všech 41 úkolů jsou v
[obnoveném běhu](verification/windows-parity/RESUME-2026-10-22/README.md).
Aktuální navazující subagentní běhy používají na výslovný pokyn
GPT-6 Astra / `high`; [rozdělení a leases](verification/windows-parity/RESUME-2026-10-22/astra-high/README.md).
Předchozí Sol / `ultra` výsledky zůstávají historicky zachované.

| CP | Současný rozsah a zbývající brána |
| --- | --- |
| K1 | Zachovaný scoped PASS Python/Windows kontraktu; samostatný Mac consumer chybí. |
| K2 | Funkce implementované; final-candidate journeys, dvě skutečné velikosti a ruční ověření zbývají. |
| K3 | Review má skutečné lokální odpovědi; WP017 runner se rozpracoval. Pět režimů přes nový source-bound package dosud neprošlo. |
| K4 | L/B-J má scoped fleet/watch runtime důkazy; finální balíček a odpovídající native matrix zbývají. |
| K5–K7 | Otevřené: stabilní broad checkpoint, nový freeze, podpis/čistý host, UX/a11y, lidé a Mac/CI. |
| K8 | Nový taint intervalový index: 275 cílených PASS včetně původních timing limitů. Topology index: 132 PASS a 346 úplných diferenciálních shod. Corpus, resource/scale a další původní brány tím nejsou uzavřeny. |
| K9 | Podmíněné úkoly zůstávají odložené; neblokují Windows paritu. |

Tracker má 6 DONE, 5 MANUAL_PENDING, 5 IMPLEMENTED, 14 IN_PROGRESS, 9 OPEN
a 2 DEFERRED. Počet není odhadem procenta hotové práce. Původní neúspěšná
široká regrese zůstává zachována; úspěšná cílená oprava ji nepřepisuje.

## Akceptační kritéria checkpointů

### K1 — kompatibilní engine boundary

**Stav 20. 10. 2026: PASS pro společný Python kontrakt a Windows C# consumer.** WP001–WP004 a WP007 jsou DONE. Schema 1.2 je additive k 1.0/1.1; frozen WP002 corpus zůstal byte-stable a Mac consumer zůstává samostatně v K7. Důkazy jsou v `docs/verification/windows-parity/WP001/` až `WP004/`, `WP007/` a v nativních consumer suites; K1 neprokazuje GUI, live AI, fresh package ani macOS acceptance.

- Jeden dokumentovaný request/result/capabilities kontrakt pro nové volby; rozšířit existující strukturované CLI capabilities, nevytvářet soupeřící seznam funkcí. Každé pole má default, rozsah, supported modes, síťový dopad a round-trip fixture.
- Podporované staré schema 1.0/1.1 se neztratí. Nová verze se určí změnovým návrhem; capabilities se vážou k přesnému executable/engine identity, ne k číslu aplikace.
- Unsupported požadovaná funkce skončí vysvětlenou chybou **před spawn/provider dispatch**; nikdy není tiše ignorována. Unknown additive metadata zůstávají kompatibilní.
- Scan options mají společný převod do engine service. Test s odlišnými sentinel hodnotami prokáže každý průchod Windows request → broker → service → pipeline.
- Fixtures: empty/complete/partial/failure/cancel/policy-failed, legacy import, staré/nové schema, missing/unknown fields, pozměněný artefakt a dvě různé generace.
- Důkaz: Python contract suite, C# consumer suite, záznam verzí a přesných payloadů. macOS consumer má vlastní status K7.

### K2 — obsah skutečně dostupný v nativním UI

- V UI jsou risk ranking, attack paths, attack surface, dependency/CVE, secrets, CI workflows, data flows a analyzer coverage. Není požadováno osm nových kořenových položek; sdružené nativní sekce jsou přijatelné.
- Pro všechna fixture data souhlasí počet, ID, core order/score, evidence basis a coverage s canonical reportem. Filtr je odlišitelný od nulových výsledků. Chybějící sekce znamená unknown/unavailable, ne bezpečný systém.
- Každý top finding/path vede na svou evidenci; kandidátní vazba není runtime observation. UI nepřepočítává priority ani nespojuje entity textovou podobností.
- Mermaid/diagram funguje offline, neodesílá zdroje, neprovádí embedded skripty/URL; má textovou alternativu a prázdný/chybový stav.
- Výběr explicitní suppression baseline, collapsed suppressed findings s důvodem, compare/previous/custom baseline a recent repos mají skutečné native journeys. Apply suppression mění pouze uživatelem vybraný soubor podle existujícího preview/undo kontraktu.
- Progress využije reálné completed/total, jinak indeterminate; ETA je odhad pouze při dostatečných datech. Cancel a změna workspace nevrací cizí starý výsledek.
- Export JSON/MD/HTML/PDF/SARIF vychází z právě zvolené generace. PDF závislost je detekovaná a vysvětlená, export neotevírá síť.
- Důkaz: adapter golden tests + viditelný build + prohlédnuté snímky všech změněných pohledů, v obou tématech a alespoň ve dvou velikostech. Celkový manuální C25 rozsah zůstává v WP026.

### K3 — AI parita při zachování důvěry

- UI zpřístupní None/Review/Hunt/Hunt+verify/Remediate/Triage, provider/model/endpoint, podporovaný effort/speed/backend a jury votes/lenses/rounds/budget.
- Žádná nepodporovaná kombinace se nepřepne na jiný backend/provider bez explicitní volby. API zůstává výchozí pro lokální model; CLI backend lze povolit pouze s doloženým hardeningem a poctivými omezeními output capu.
- Všechny pokusy, retry a jury calls používají společnou call/time/output ledger. Unknown usage není nula. Triage fallback je označen jako deterministický, nikoli dokončená modelová odpověď.
- AI výstupy zůstávají oddělené od deterministic findings. Byte/hash test ověří nezměněný deterministický výstup. Citace a podpora tvrzení mají oddělený status; missing votes jsou abstentions.
- Pro každý z pěti režimů proběhne alespoň jeden skutečný běh z nativního UI přes zabalený engine proti `http://127.0.0.1:1234/v1`, `cyberstag-security-26b-a4b-v1`, nad `C:\tmp\juice-shop`. Zaznamenat HTTP call, dokončenou odpověď, artefakt, usage nebo unknown, run/generation a otevření ve správném UI.
- Provider-down, cancel, exhausted budget a malformed output se testují cílenými fault fixtures; samotné jednotkové testy nenahrazují předchozí live důkaz.
- Pokud model některý režim nedokončí, K3 zůstává partial s konkrétní chybou. Nevyrábět odpověď fixture a nevydávat ji za live.

### K4 — fleet a watch

- Dvě i tři repos, Unicode/mezery v cestách, stejná jména složek v různých kořenech, serial/parallel výsledky, selhání jednoho dítěte a cancel mají validované identity.
- Fleet UI ukáže výsledky každého repo, selhání/partial coverage, observed i candidate contract links a jejich důvody, cross-boundary flows, trust gaps, anomalies a graph. Neúspěšné dítě nesmaže úspěšného sourozence.
- AI/baseline kombinace nepodporované core jsou ve fleet režimu vysvětlené a blokované před dispatch.
- Watch vytvoření/edit/rename/delete sloučí do jednoho běhu po debounce; změny za aktivního běhu vytvoří právě jeden follow-up. Cancel, vypnutí watch, změna workspace a zavření okna ukončí odběr i pending práci.
- Vlastní publikace, retence a diagnostika nevytvářejí nekonečné rescany. Nepodporovaný filesystem je viditelně označen.
- K4 může projít se **single-repo watch** a vypnutým fleet watch, stejně jako referenční macOS. WP021 rozšíří pokrytí na všechny repos a musí projít vlastní maticí.
- Důkaz: platform filesystem test, source i frozen broker matrix, skutečný native journey a procesová kontrola cleanup.

### K5 — kandidát a distribuce Windows

- Jeden package ID a hash-bound source/toolchain/analyzer inventory, SBOM, podpis a podporované OS/architecture v release manifestu. Připravené signing skripty nejsou podepsaný release.
- Na čistém podporovaném Windows x64 bez Python/.NET SDK/dev PATH: dvojklik launcheru, instalace, první scan, cancel/retry, otevření historie, export, provider-down, upgrade z posledního podporovaného balíčku, rollback a uninstall.
- Žádný vlastní exe/cmd.exe nesmí být přijat jako engine; přesná bundled cesta funguje po přesunu/upgrade. PS 5.1 cesta a MotW chování mají skutečný záznam.
- Zachovány uživatelské reports/settings/credentials při upgrade/rollback/uninstall; žádné tiché stažení enginu/pluginu nebo síťový request při startup.
- Na stabilním kandidátovi jedna relevantní široká Python/native regrese a packaged smokes; po opravě jen dopadová sada, před označením finálního kandidáta znovu zkontrolovat jeho identitu.
- Známý data-loss, wrong-generation, leaked-secret, uncontrolled-process nebo inaccessible-core-workflow problém blokuje vydání. Windows C26 performance se nevyžaduje.
- WP037 připraví release dossier a supported scope; zveřejnění je samostatná akce. Nezávislé macOS práce neblokují Windows kandidáta, ale nesmějí být označené za hotové.

### K6 — lidská validace

- Přesunuté Windows C19/C21/C24/C25 zůstávají otevřené do skutečné studie a ručního ověření dialogů, clipboardu, reveal, keyboard/focus/Escape, Narratoru, kontrastu, textu 200 % a reduced motion.
- Zachovat původní C19/C25 prahy a matici 72 referenčních snímků; nové pohledy přidat do matice. Snímky musí někdo vizuálně prohlédnout; screenshot generation sama není acceptance.
- C32 znamená 10 nových účastníků implementované studie, čtyřtýdenní betu s alespoň 12 účastníky / 6 na platformu a 100 completed/intentionally-cancelled runs na platformu.
- Windows scoped verdict a kompletní dvouplatformní C32 se zaznamenají odděleně. Není-li macOS účastník/host, celkový C32 se neuzavře. Nový scoped release musí mít výslovně zaznamenaný rozsah, ne tiché snížení prahu.
- Žádná nevyžádaná telemetrie; consented lokální evidence nebo manuální záznamy. Agent může připravit protokol a opravit chyby, nemůže simulovat lidi nebo uběhlé týdny.

### K7 — nezávislá macOS lane

- Mac adapter čte nové run/manifest/capability semantics, správně importuje legacy a drží selected generation. Samotné Swift JSON decode testy nestačí.
- Společné fixtures proběhnou Python + C# + Swift s připnutými revizemi obou repos; CI link je skutečný běh, nikoli pouze YAML.
- Na skutečném macOS hostu samostatně C09/C10, UX/VoiceOver a relevantní C26, signing/notarization/install/upgrade/rollback.
- Dřívější veřejná DMG není důkaz kompatibility s naším engine 1.5.1. macOS práce nesmí nutit Windows zpět na starší raw-file polling.

### K8 — core kvalita, která se nesmí ztratit v UI projektu

- **C27:** nejméně 30 repos, 300 pozitivních, 300 negativních případů, 10 clean repos, ≥20 % repo-level holdout před tuningem. Rodina potřebuje ≥30/30 a ≥95 % precision / ≥80 % recall, jinak experimentální status; zveřejnit TP/FP/FN a intervaly.
- **C28:** zachovat authority/protocol/host/port/namespace, alias provenance a ambiguity; reference system nesmí produkovat unsupported observed edge.
- **C33/C34:** jeden captured snapshot včetně enumerace, žádné skryté live reads, 100 edit sequences full≡incremental včetně provenance/coverage; invalidace podle konfigurace, dependencies, analyzer/schema identity. Výkonnostní tvrzení až podle původní 20-repeat reference campaign.
- **C35:** řešit doložený memory spike a fleet memory admission; finite defaults a každé omezení s partial coverage. Změny default scope vždy explicitně zdůvodnit, ne vydávat méně pokrytí za optimalizaci. Je to core resource gate, nikoli návrat Windows C26.
- **C36–C38:** izolovaný host jako fault containment, explicitní OS omezení; nové analyzéry extraction-only, lidsky ověřená kvalita a skutečné contributor/CI důkazy. C37 tři onboarding trials a osm týdnů metrik nezaměnit za běh skriptu.
- Memory/quality problém blokuje pouze odpovídající release claim/scope, pokud neohrožuje základní bezpečnost výsledku. Jakékoli omezení scope musí být výslovné; žádná automatická výjimka.

## Paralelní realizace

Maximálně **integrátor + tři pracovní agenti**. Implementační agenti `gpt-6.1-sol` podle AGENTS.md. Nezávislé review je oddělená práce se čtením skutečného diffu a evidence; případné zvláštní nastavení review modelu musí respektovat platné rozhodnutí uživatele.

| Vlna | Agent A | Agent B | Agent C | Integrátor |
| --- | --- | --- | --- | --- |
| 0 | WP002 fixtures/spec | WP001 baseline/evidence | WP030 label/corpus audit | Uzamkne baseline, rozdělí soubory, schválí kontrakt |
| 1 | WP003 → WP004 core boundary | WP007 report adapter | WP024 package preflight bez zásahu do cizího dirty diffu | Zmrazí kontrakt K1, přiděluje shared-file leases |
| 2 | WP014 AI engine | WP008 → WP009 views | WP010 offline diagram control | Integruje views, následně WP005/006 v shellu |
| 3 | WP018 fleet broker | WP015 → WP016 AI UI | WP012 → WP013 triage/history | WP011/WP022 shell composition, K2 checkpoint |
| 4 | WP020 watch | WP019 fleet UI | WP032 nebo WP033 core refinement | WP017 live LM Studio výhradně, K3/K4 integrace |
| 5 | WP025 clean-host runner | WP029 CI | WP026 ruční protokol/opravné řezy | WP023/037 kandidát a dossier; skutečné lidské K6 plánuje owner |

Jde o **doporučené balíky**, ne povolení spustit úkol s nesplněnou závislostí. WP024 nesmí editovat packaging soubor, dokud integrátor neidentifikuje existující změnu. K8 index/cache/memory práce s překryvem souborů běží postupně pod stejným ownerem.

### Pravidla proti kolizím

- `MainWindow.xaml`, `MainWindow.xaml.cs` a app resources vlastní výhradně integrátor. Agent dodá samostatný control/adapter, popis event API a malý navržený integrační diff; nepřepisuje shell souběžně.
- `run_contract.py`, schemas a `desktop_worker.py` mají jednoho CORE ownera. AI/fleet owner dostane časově omezený lease po K1; nikdy neprobíhají dvě změny stejného kontraktu.
- `pipeline.py`, `scan_service.py`, `models.py`, `index.py`, `scanner.py`, `report.py` jsou serializované sdílené soubory. Backlog uvádí `leases`; při překryvu se jeden úkol odloží.
- Samostatný worktree až po zapečetění/checkpointu potřebné práce; nový worktree neobsahuje necommitnutý diff. Žádný reset/clean ani archivace pracovního stromu bez zachování cizí práce.
- Každý task má base commit, ownera, paths, fixture contract, focused tests, UI proof pokud relevantní a handoff. Integration/root evidenci ověří; agentovo „hotovo“ není PASS.
- LM Studio, lokální app capture, package output a instalace jsou výhradní zdroje. Testovací konfigurace a výstupy mají task-specific adresář; nezasahují osobní settings ani immutable package.
- Selhání externího hostu/certifikátu/lidského testu blokuje konkrétní úkol. Ostatní nezávislé ready úkoly pokračují.

## Evidence, rollback a ukončení

Evidence každého dokončeného tasku: base/final commit + dirty diff hash, platform/runtime, příkazy/procedura, očekávaný a skutečný výsledek, test count a skip důvody, package/run/generation identity, relativní cesta + hash důkazů, omezení a reviewer. Trvalé malé souhrny ukládat do `docs/verification/windows-parity/<WP-id>/`; raw výstupy mimo analyzovaný repozitář a mimo package.

Rollback: zachovat předchozí package/current pointer i settings; schema změny jsou additive nebo mají explicitní adapter; watch lze vypnout; nové view nesmí měnit canonical artefakty. U změny engine chování porovnat normalizované golden outputs; neopravovat fixtures jen pro zelený test bez věcného důvodu.

Úkol se uzavírá až po splnění vlastního DoD. Checkpoint až po všech povinných úkolech a kritériích. Stav **IMPLEMENTED**, **VERIFIED**, **MANUAL_PENDING**, **BLOCKED_EXTERNAL** a **ACCEPTED_SCOPED** se nemá slučovat do jednoho checkboxu. Původní historická scoped acceptance se uchovává.
