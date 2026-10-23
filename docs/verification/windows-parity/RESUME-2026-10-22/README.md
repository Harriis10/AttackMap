# Obnovení roadmapy — 22. 10. 2026

**Nejnovější checkpoint 23. 10. 2026: [přesné výsledky a další brány](checkpoint-2026-10-23.md).**
7200s kandidát již prošel build/runtime/package/installed kontrolami. Hunt+verify
dokončil všechny čtyři HTTP 200 odpovědi, ale zůstává partial kvůli jedné
abstenci poroty, nikoli kvůli timeoutu. Triage opakování prošlo včetně čistého
exitu. Přesné scoped důkazy a otevřené GUI/sémantické/ruční brány jsou v
checkpointu výše. Následuje lokální Git uložení a finální full portable;
na výslovný pokyn uživatele se potom žádná další práce nezahajuje.

**Běh je výslovně OBNOVEN uživatelem. Následující stav popisuje předchozí dávku; aktuální je checkpoint výše.**
Předchozí STOP hlídače využití (ohlášeno 75 %) je historický:
[Astra/high STOP handoff](astra-high/STOP-HANDOFF.md) obsahuje novou širokou
regresi, native/frozen výsledky a nový RequiredBundled package/SBOM. Po obnovení
prošel nový installed native scan; [WP024 unsigned preflight](../WP024/astra-fresh-20261022/unsigned-acceptance.md)
je DONE ve svém omezeném rozsahu. [První živá série](../WP017/astra-review-20261022/batch-outcome.md)
dokončila Review a Hunt, ale Hunt+verify vyčerpal časový rozpočet bez odpovědi;
Remediate/Triage se nespustily. Procesy skončily a LM Studio hlásí READY.
Vizuální a obsahové brány zůstávají otevřené. Po upozornění uživatele na dlouhé
generování nyní vzniká cílená oprava delšího explicitního lokálního čekání.

**Navazující běh:** nejnovější pokyn uživatele nastavuje všechny nové
subagenty na GPT-6.1 Sol / `medium`. Předchozí Astra/high výsledky zůstávají zachovány. Aktuální rozdělení, leases a výsledky jsou
v [navazujícím záznamu](astra-high/README.md). Níže zůstává předchozí dávka
beze změny jejího modelu, výsledků a akceptačních omezení.

Uživatel výslovně požádal o kontrolu roadmapy, rozdělení práce paralelním
agentům a zahájení implementace. Tím je obnoven dříve pozastavený běh.
Autoritou zůstávají roadmapa Windows parity, TODO a JSON backlog uvedené
v `docs/README.md`; tento záznam je jejich aktuální prováděcí doplněk.

Výchozí commit: `18fc9b2`. Na začátku nebyly změněné tracked soubory;
historické untracked výstupy zůstávají zachované. CodeGraph byl použit jako
první pro hledání kódu; hlásí frozen index, proto se relevantní aktuální
implementace ověřuje také přímo. Index se nepřestavuje.

Tracker při obnovení: 6 DONE, 5 MANUAL_PENDING, 5 IMPLEMENTED,
13 IN_PROGRESS, 10 OPEN a 2 podmíněné DEFERRED. Počty jsou stavy úkolů,
nikoli procento dokončené práce. K1 má doložený Python/Windows kontrakt;
K2–K8 mají konkrétní otevřené integrační, live, ruční nebo externí brány.

## Rozdělení první dávky

| Vlastník | Úkol a konkrétní řez | Výhradní zápis / zdroje |
| --- | --- | --- |
| `/root/resume_r4_config` | WP034 R4: dokončit přerušené ověření provenance při CLI override; poté WP032 R10b review a případná minimální oprava | nejprve pouze `_effective_deployment_aliases` v `scan_service.py` a konkrétní testy; R4 lease následně uvolněn; R10b `contracts.py` / `crossrepo.py` po potvrzení rozsahu |
| `/root/resume_scanner_regressions` | WP023: intervalový index pro hledání vlastníka taint flow, diferenciální důkaz a původní timing testy | `taint_flow.py`, nový diferenciální test; `test_scan_limits.py` spouštět s nezměněnými limity |
| `/root/resume_roadmap_audit` | Nezávislý task-level audit skutečné evidence a zbývajících bran | pouze `audit.md` a `audit.json` zde |
| `/root` | Integrace, aktuální tracker, WP017 navazující packaged ověření, kontrola výsledků agentů | canonical dokumentace, native shell, build/package slot, LM Studio a UI výhradně |

Všichni pracovní agenti používají GPT-6.1 Sol. Maximálně integrátor + tři
pracovní agenti; žádná souběžná mutace stejného sdíleného souboru. Nové
průběžné výsledky patří do datovaných adresářů úkolů, retained důkazy se
nepřepisují. Agentův text „hotovo“ sám neznamená přijetí úkolu.

## Pořadí navazujících bran

1. Přijmout malé opravy teprve po diferenciálním důkazu a cílených testech.
   Nezvyšovat timing limity, nevynechávat případy a nezmenšovat pokrytí.
2. Na stabilním zdrojovém snapshotu dokončit relevantní regresní checkpoint.
   Předchozí broad běh měl 12 chyb, z toho čtyři následně opravené fixture
   případy; sedm timing případů zůstávalo při obnovení nevyřešených.
3. Vyrobit nový immutable engine a native/package identity ze stejného
   zdrojového stavu. Opravený uživatelský portable build ve FINISHED je
   zachován; obsahuje historický B-J engine a neslouží jako důkaz fresh freeze.
4. WP017: postupně skutečně dokončit Review, Hunt, Hunt+verify, Remediate
   a Triage přes celý native klient a přesně tento zabalený engine, s hashi
   artefaktů, transportními záznamy, exportem a prohlédnutým Reports UI.
   Dosavadní dva nové dokončené Review běhy ostatní režimy nenahrazují.
5. Dokončit výsledné K2/K4 native journeys a vizuální matici. Ruční OS
   appearance, keyboard/Narrator a 200 % text zůstávají samostatné WP026.
6. Podpis, čistý druhý Windows host, skutečný macOS host/CI a lidská beta
   mají vlastní důkazy. Chybějící certifikát/host/lidé ani uběhlé týdny se
   nenahrazují simulovaným PASS. Podmíněné WP036/WP041 se samy neaktivují.

Lokální AI používá výhradně `http://127.0.0.1:1234/v1`, model
`cyberstag-security-26b-a4b-v1`; cílový reálný repozitář je
`C:\tmp\juice-shop` a výstupy jsou mimo něj. Běh nepublikuje release a
nepřepisuje aktuální funkční kopii ve FINISHED.

## Výsledky první integrační dávky

Na další pokyn uživatele byly spuštěny tři nové běhy GPT-6.1 Sol s reasoning
effort `ultra`: nezávislé review, vlastnický index a runner pěti AI režimů.
Starší běhy před přepnutím pouze dokončily své rozpracované řezy.

- **WP023:** nový intervalový index vlastníka Python taint flow. Cílená sada
  275 PASS zahrnuje všech sedm původních timing případů s nezměněnými limity.
  Integrátor explicitně porovnal původní lineární lookup s aktuálním indexem:
  celých 6000 rout / 6000 external calls, shodný celý ScanResult a nezměněné
  source/fixture hashe. Ultra review bez blokujícího nálezu. Historický
  neúspěšný broad běh tím není přepsán.
- **WP034 R4:** přerušené ověření provenance dokončeno, 5 PASS. Nebyla nutná
  další změna implementace; nejde o uzavření paměťového C35.
- **WP032:** původní ambiguity-policy prototyp zadržen kvůli doloženému
  nesprávnému povýšení inferred evidence. Místo něj přijat malý kompatibilní
  index názvů pro topology: 132 PASS, 346/346 shodných celých consumer
  výstupů, negativní kontrola odhalila chybu starého kandidáta. Threat model
  zůstal beze změny. Nezávislé ultra review bez blokujícího nálezu.
- **WP020:** skutečně prohlédnuty čtyři retained Repository-watch PNG v obou
  tématech. Všechny mají pouze jeden skutečný viewport 1584×961; jejich
  názvy neprokazují dvě velikosti. Malý viewport a final-candidate journey
  nadále chybí. Nový runtime ani provider se kvůli tomuto review nespouštěl.
- **WP017:** příprava runneru mění stav OPEN na IN_PROGRESS, nikoli DONE.
  Výchozí preflight nevytváří proces ani HTTP požadavek. Reálný FINISHED
  preflight po opravě předpokladu o velikosti písmen WinUI DLL ověřil všech
  824 manifest entries. Pět modelových režimů se v této dávce nespouštělo.

Aktuální stavy po zahájení WP017: **6 DONE, 5 MANUAL_PENDING, 5 IMPLEMENTED,
14 IN_PROGRESS, 9 OPEN, 2 DEFERRED**. Žádný další celý WP ani checkpoint
nebyl uzavřen samotnými cílenými testy.

`source-identity.json` přímo porovnává aktuální source s B-J freeze: ze 136
engine vstupů se liší 12 souborů; všech 80 native vstupů poslední opravy je
beze změny. To je konkrétní důvod pro nový source-bound freeze před finální
WP017/WP024 kvalifikací. Připravované následné kroky zůstávají stabilní broad
checkpoint, nový balíček a pět skutečných režimů; podpis, čistý host,
přístupnost, Mac a lidé mají své samostatné brány.
