# Zahájení integrace — 20. 10. 2026

Řídí se aktivní roadmapou a WP TODO. Base commit: `d45997653970929f5f477c6e2dcd70913cb17fe3`; checkout obsahuje necommitnuté dokumentační změny a dřívější změnu packaging skriptu. Žádný reset ani vytvoření worktree ze staršího commitu.

## Vlna 0 a vlastnictví

| Owner | Úkol | Povolený zápis |
| --- | --- | --- |
| `/root/wp001_baseline` | WP001 | `docs/verification/windows-parity/WP001/` |
| `/root/wp002_contract` | WP002 — příprava, uzavření čeká na WP001 | `fixtures/desktop-parity/`, `docs/desktop-parity-contract.md`, `docs/verification/windows-parity/WP002/` |
| `/root/wp030_corpus` | WP030 — auditní řez, nikoli splnění C27 | `docs/verification/windows-parity/WP030/` |
| `/root` | Integrace, kontrola důkazů a tracker | Aktuální TODO/JSON backlog, tento záznam |

Pracovní agenti používají `gpt-6.1-sol`. Produktové shared-file leases dosud nebyly uděleny; shell, enginové kontrakty a packaging se souběžně neupravují. Žádný live provider call, instalace ani publikace nebyly v této vlně zadány.

## Výchozí kontrola

CodeGraph byl použit pro průchod action brokerem a jeho vazbami na desktop. Stávající broker přijímá uzavřený seznam operací; nové capabilities nesmějí být pouze samostatným seznamem deklarovaných funkcí.

První příkaz `.venv/Scripts/python.exe -m pytest tests/test_run_contract.py tests/test_desktop_options.py -q`: **40 passed, 3 setup errors**. Chyby jsou `PermissionError` pro sdílený `pytest-of-Mipam` temp adresář; neprokazují chybu produktové implementace. Opakování používá vlastní `--basetemp .tmp-parity-root-20261020 -p no:cacheprovider`; výsledek bude doplněn po dokončení.

WP001 hlásí další zachovaný balíček `dev-20261019201436-7d3584c4`; jeho existenci nelze zaměnit za ověřenou instalaci. Datovaný audit se nepřepisuje na nový runtime důkaz.

Opakování ve workspace také narazilo na sandbox `PermissionError`. Schválený běh mimo sandbox s `-p no:cacheprovider --basetemp C:\Projects\INPROGRESS\AttackMap\.tmp-parity-root-20261020-approved` dokončil stejnou sadu: **43 passed in 20.23s**, exit 0. Jde o výchozí unit/fixture kontrolu, nikoli live AI nebo GUI acceptance.

WP030 předběžně potvrzuje 46 očekávání / 13 lokálních repo identit, 25 pozitivních / 19 negativních / 2 clean. Celý WP030 i C27 zůstávají otevřené.

Agent dokončil auditní řez WP030 bez změny labelů nebo detectorů. Root zopakoval inventory audit (`schema_load: PASS`) a mimo sandbox kvůli ACL dočasných adresářů spustil `tests/test_evaluation.py`: **27 passed in 40.42s**, exit 0. Aktuální evaluator přesto vykazuje zdokumentovaný SSRF false positive v clean fixture a tři injection false negatives v PHP holdoutu; test suite a metriky korpusu dokazují rozdílné vlastnosti a žádný mature-family claim z toho nevzniká.

## Integrační podmínka další vlny

Před přidělením WP003/WP007 integrátor přečte důkazy WP001 a validátor WP002, zkontroluje fixtures proti skutečným modelům a explicitně schválí rozsah kontraktu. Návrh nebo počet vytvořených fixtures sám o sobě neuzavírá K1.

## Výsledek vlny 0 a zahájení vlny 1

WP001 je po root review DONE. Oba retained kandidáti prošli payload/ZIP kontrolou, vybraný engine hlásí 1.5.1 a 21 modulů a 135 relocation hashů souhlasí. Instalovaný payload má shodné listed files, ale strict validace zůstává FAIL kvůli dvěma zachovaným smoke JSON souborům. Jde o přesně zaznamenanou limitation, ne přenesení acceptance.

WP002 je DONE pro zmrazenou současnou boundary. Hash-bound corpus má 30 entries a validátor prošel 266 kontrolami. Neprázdný legacy report zachovává skutečný udržovaný tvar a exact order; chybějící fleet/provider/analyzer-success reprezentace zůstávají explicitně unavailable. Budoucí fields mohou přidat jen WP004/WP014/WP018 s novými fixtures a consumer evidence.

WP030 zůstává IN_PROGRESS. Auditní řez je hotový, ale numerický rozsah a nezávislé lidské review nejsou splněny.

Vlna 1 byla přidělena bez překryvu:

| Owner | Úkol | Lease / omezení |
| --- | --- | --- |
| `/root/wp003_capabilities` | WP003 | Core capabilities/CLI/action contract; žádný provider call. |
| `/root/wp007_reports` | WP007 | Report adapters a nové typed projections; žádný shell/MainWindow edit. |
| `/root/wp024_package` | WP024 preflight | Read-only packaging audit; existující dirty `tools/package_native_windows.ps1` zatím bez lease. |

K1 stále není uzavřen: čeká na WP003, WP004 a WP007 včetně Python/C# consumer důkazů.

## Průběžný integrační stav vlny 1

WP003 je po root review DONE. Capabilities/preflight mají verzované schema 1, přesnou source/executable identitu a fail-fast validaci před parse/dispatch; cílená sada skončila **87 passed in 245.42s** bez provider callu nebo rebuild freeze.

WP007 je po root review DONE. Typed report projections jsou hash-bound, bounded a zachovávají pořadí core. Nová suite skončila **98 PASS**, navazující ReportAdapter **71 PASS** a composition **17 PASS**.

WP008 je implementován, ale stav je **MANUAL_PENDING**. Model suite má 17 PASS a standalone preview se sestavil bez warning/error. Computer-use helper třikrát timeoutoval, proto nebyl připsán screenshot, keyboard ani skutečný vizuální PASS.

WP004 je IN_PROGRESS s výhradním core lease pro run contract/desktop worker/scan service. Zachovává schema 1.0/1.1 a přidává pouze volby, které mají existující service mapping; AI a fleet zůstávají vlastním balíkům.

WP009 je IN_PROGRESS v izolovaných nových inventory souborech bez shell/MainWindow editů. WP010 byl přidělen paralelně v nových diagramových souborech; renderer musí být lokální/offline, bez aktivního skriptu či URL, a musí mít textovou alternativu.

WP024 dokončil implementační řez, zůstává však IN_PROGRESS. Důkaz `WP024/implementation-verification.json` zaznamenává 23 Python PASS, 24 launcher guard PASS a izolovaný syntetický install/upgrade/rollback/tamper/uninstall PASS. Fresh production freeze a skutečný installed bundled scan bez Pythonu v PATH dosud provedeny nebyly.

WP009 je po CodeGraph/root review **MANUAL_PENDING**. Agent i root samostatně získali **64 PASS** modelových kontrol; preview build prošel bez warning/error. Projekce zachovává source order/IDs, používá scalar allowlist a nevystavuje raw secret data. Shell wiring a skutečný visual/keyboard/Narrator review chybí.

Při WP004 integraci byla nalezena nativní schema mezera. `EngineProtocol` nyní přijímá výstupní 1.2 vedle 1.0/1.1 a samostatný 1.2 terminal test zachovává starší golden loop; root běh skončil **102 checks PASS**. Native producer stále vysílá 1.1, dokud WP005 skutečně nepotřebuje nové volby.

WP011 byl zahájen jen jako bounded preparation slice v nových overview souborech. Nemůže se uzavřít před shell integrací a otevřenými manuálními kontrolami WP008/WP009.

WP004 je po root review DONE. Evidence obsahuje 169 focused regressions PASS, 10 finálních alias/schema-echo PASS a frozen WP002 266 PASS; root navíc ověřil nativní schema 1.2 consumer 102 PASS a zapsal additive 1.2 addendum do parity kontraktu. Tím je K1 pro Python + Windows C# **PASS**; macOS consumer je nadále výhradně K7 a žádný GUI/live/package claim se nepřenáší.

WP005 byl přidělen jako další bounded Windows slice. Agent vlastní pouze native options/capability/settings modely a focused test/preview; MainWindow a shared resource integraci drží root.

WP010 je po root review **MANUAL_PENDING**. Agent i root získali **20 PASS** parser/manifest/security kontrol a oba buildy jsou čisté. Preview však nevytvořilo ověřitelné viditelné okno; visual/keyboard/Narrator/network-disabled runtime a shell/export integrace proto zůstávají otevřené. Diagnostické procesy byly ukončené a cleanup ověřený.

WP012 je po bounded root review **IMPLEMENTED**, nikoli DONE. Agent i root získali **33 PASS** a standalone preview build je čistý. Model váže generaci, report hash, baseline path/hash a odmítá stale response. Současný action broker zapisuje pouze repo-root suppression filenames, takže arbitrary selected baseline apply zůstává disabled do explicitního contract rozšíření; real apply→undo→rescan a manual evidence chybí.

WP013 byl zahájen pouze v nových history/comparison souborech. LocalSettings a shell navigation zůstávají root-owned a uzavření čeká na WP005.

WP013 bounded slice je po root review **IMPLEMENTED**, nikoli DONE. Agent i root získali **28 PASS** a standalone preview build je čistý. Exact repository/generation/hash identity, explicitně zachycený previous baseline a stale callback guards drží; žádný scan/settings/report/pin/delete zápis neproběhl. LocalSettings+shell integrace, reálný journey a manual evidence zůstávají otevřené.

WP014 je po root review DONE v core scope. Široký offline checkpoint má **389 PASS / 1 deliberate live-CLI skip**, finální mode/citation rerun **72 PASS** a root zopakoval narativní suite **17 PASS** mimo sandbox kvůli Windows pytest ACL. Šest módů zachovalo byte-identical deterministic findings. Native controls/presentation a skutečné LM Studio HTTP zůstávají výhradně WP015–WP017.

WP022 bounded slice je **IMPLEMENTED**, nikoli DONE. Agent i root získali **43 PASS** pro selected-artifact/SARIF hranici. Žádný skutečný export, PDF render, clipboard/open/reveal ani full external SARIF consumer validace neproběhla; shell a WP013 integrace zůstávají otevřené.

WP005 je po root test/visual review **MANUAL_PENDING**. NativeOptions má agent i root **54 PASS**, navazující regression 71/24 PASS a preview build je čistý. První snímky odhalily nečitelný kontrast a dva clipping problémy; po opravách root ověřil čitelný finální light supported i unsupported stav. Shell, keyboard/Narrator, dark theme a druhá velikost chybí.

Po WP005/WP014 byly paralelně zahájeny WP006 (progress/analyzers), WP015 (native AI/schema 1.3) a WP018 (fleet core). Mají oddělené C# UI a Python core leases; MainWindow zůstává root-owned.

WP006 je **MANUAL_PENDING**. Pure model 73 PASS a EngineProtocol 102 PASS; root prohlédl bounded/indeterminate/cancelling synthetic light preview. Jeden checkbox glyph zůstal nekonzistentní. Chybné spuštění zastaralého `EngineSession.Tests` harnessu bez argumentu otevřelo Windows crash dialog; opravený neinteraktivní pokus potvrdil, že aktuální launch guard odmítá stale fake-broker basename ještě před callbackem. Harness zůstává FAIL, žádný real scan nebyl proveden a všechny vlastněné test/preview/compiler procesy byly ukončené a ověřené.

WP015 zůstává IN_PROGRESS: 49 nových, 54 NativeOptions a 16 ProviderConfiguration checks PASS. Accidental no-arg `ProviderRoundtrip.Tests` skončil před akcí; live HTTP harness nebyl znovu spuštěn. Initial preview build prošel, final-source rebuild byl na uživatelův pokyn zastaven; žádný preview launch ani visual claim. Cleanup ověřil nula vlastněných procesů.

WP018 zůstává **IN_PROGRESS / UNVERIFIED**. Po opravě read-only child collection poslední root rerun prošel 35 kontrolami a poté selhal v test setupu `test_broker_partial_preserves_previous_current_and_rejects_stale_progress`: opakovaný `mkdir` existujícího `output/fleet-fixture` vyvolal `FileExistsError`. Po uživatelově pokynu se test ani kód dále neměnil a nebyl spuštěn další proces.

Checkpoint byl na uživatelův pokyn zastaven bez rozdělení další práce. Všichni tři subagenti skončili; jejich vlastní cleanup hlásil nula zbylých nativních test/preview/compiler procesů. WMI kontrola z root sandboxu byla odmítnuta přístupovými právy, proto se tato poslední věta neopírá o nový úplný systémový process audit.
