# Obnovení 23. 10. 2026 — GPT-6.1 Sol ultra

Nový výslovný pokyn uživatele obnovuje práci po dokončeném portable buildu a odvolává dřívější pokyn potom nic nezačínat. Výchozí commit `507bddacd72a246a136ca2d46faad2aa661806c1`; původní portable a všechny předchozí důkazy zůstávají zachované. Autorita: docs/README.md, aktivní Windows parity roadmapa, TODO a JSON backlog.

## Ověřený poslední stav

Poslední [portable delivery](../WP024/sol-portable-507bdda-20261023/DELIVERY.md): full x64 RequiredBundled, 779 ZIP entries hashově shodných se stage, skutečná instalace a native scan 19 artefaktů, SBOM 56 dependencies. Nejde o signed release ani clean-host/manual acceptance. [Hunt+verify](../WP017/sol-budget7200-20261023-hunt-verify-01/outcome.md) má všechny čtyři HTTP200 odpovědi, exit0/cleanup a zbývající budget; partial kvůli abstenci poroty je zachovaný kontrakt. [Triage](../WP017/sol-budget7200-20261023-triage-01/outcome.md) prošel včetně exit0. Sémantické a GUI mezery jsou stále otevřené.

## Vybraná dávka a leases

| Řez | Agent a úsilí | Samostatný rozsah | Potřebný výstup |
| --- | --- | --- | --- |
| WP016, poctivá AI metadata | /root/ultra_ai_metadata — Sol 6.1 ultra | Native AI controls/projections + jejich testy; desktop_ai.py/test_desktop_ai_modes.py podle potřeby | Pravdivě rozlišit usage scope, reference validation a claim support; zachovat partial/abstentions, focused tests a actual UI preview po integraci. |
| WP023, zavírání okna | /root/ultra_window_lifetime — Sol 6.1 ultra | Hash-bound návrh patchů shared shell; vlastní izolované testy | Malá oprava konkrétní late-continuation mezery, regresní scénář a žádné tvrzení o prokázané příčině historického Triage pádu. |
| WP017, provider fault journeys | /root/ultra_provider_faults — Sol 6.1 ultra | Nový samostatný QA partial/helper a tests; shared startup pouze patch | Oddělené explicitní controlled HTTP fault scénáře, source/package pins a owned cleanup; nikdy fixture jako live model PASS. |
| Integrace a nezávislé review | /root | Tracker/docs, všechny shared shell změny, build/package, GUI/provider slots | Review disjunktních řezů, cílené checks, jedna stabilní integrace a pravdivý nový checkpoint. |

Agentům nejsou povoleny GUI, LM Studio, plný WinUI publish/package ani stage/commit. Root vlastní tyto sloty a přímé změny shared MainWindow/App. Rozdělené scoped řezy neuzavírají nehotové závislosti WP015/WP016 ani celé WP023. Souběžná práce nepřepisuje již přijaté či neúspěšné důkazy.

Live provider zůstává výhradně http://127.0.0.1:1234/v1 a cyberstag-security-26b-a4b-v1 přes směrovaný LM Link. Dlouhý běh není sám o sobě porucha; žádný opakovaný 70minutový Hunt+verify jen kvůli stochastické abstenci. Controlled fault server nesmí obsadit ani upravit port 1234 a není skutečný modelový běh.

Ruční Narrator/keyboard, podpis/certifikát, čistý další Windows host, Mac lane a lidská studie zůstávají samostatné otevřené brány.

## Výsledek dokončené scoped dávky

- **WP016:** integrována poctivá projekce metadat; 86 offline assertions PASS. Artefaktová usage, společné output accounting, reference-validation scope a captured context jsou oddělené, partial/abstentions zůstávají pravdivé. [Agentův důkaz](ai-metadata/README.md).
- **WP023:** integrovány v2 guardy pro pozdní načtení a UI události při zavírání; původní pořadí Cancel/cleanup zachované. [Rootově ověřeno 603 assertions / 132 případů](window-lifetime/v2/root-verified-summary.json) v izolovaném source-extracted C# harnessu. V1 návrh zůstal zachovaný jako odmítnutý pro cleanup ordering. Nejde o prokázanou příčinu/opravou historického0xC000027B. Autor narazil po hotových v2 výsledcích na kapacitní chybu služby; root ověřil raw výsledky a druhý Sol ultra reviewer patch nezávisle schválil.
- **Celý produkt:** integration02 full WinUI publish PASS; [build proof](native-build02/native-build.json). [Čtyři skutečné AI snímky](ai-preview02/summary.json) prošly pixel/bounds/source kontrolou a [root vizuálně prohlédl všechny](ai-preview02/visual-review.md). Původní preview01 neúplný Light snímek se nepřepisoval; QA-only settling/scroll/bounds oprava je doložená zvlášť.
- **WP017 controlled faults:** [21 testů řadiče](provider-faults/unit-tests.json) PASS. Root skutečně provedl [HTTP503](provider-faults/actual01-unavailable/summary.json), [chybnýJSON](provider-faults/actual01-malformed/summary.json) a [pendingcancel](provider-faults/actual01-pending-cancel/summary.json) přes nový native build a explicitně hash-bound starší frozen engine. Každý měl právě1 pozorovaný fixture POST, native exit0, owned cleanup a joined server/handler threads. Deterministické findings zůstaly shodné; cancel zachoval předchozí selected generation. Jde o malý vlastněný fixture repozitář, nikoli nový JuiceShop/modelový úspěch. 503 není TCPrefusal; fixed500ms pozorování neprokazuje časové pořadí late-response callbacku.

Souhrnná strojová evidence je v [results.json](results.json). Nové skutečné modelové odpovědi: **0**. Nepřibyl nový Git commit ani portable; původní distribuovaný507bdda balíček zůstává předchozí samostatnou identitou. Tato dávka je integrovaný source-build checkpoint. WP016/WP017/WP023 zůstávají IN_PROGRESS s otevřenými celkovými kritérii.
