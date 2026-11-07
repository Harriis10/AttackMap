# WP017 — interpunkce u AI referencí, 7. 11. 2026

Zdrojová oprava a její zahrnutí v novém kandidátu jsou dokončené.
Celé WP017 zůstává **IN_PROGRESS**. [Kvalifikace společného kandidáta](verification.json)
odděluje source funkční testy od skutečných frozen CLI/SARIF kontrol.

Skutečná uživatelská AI odpověď obsahovala devět tučných popisků tří známých ID
ve tvaru `**finding:1:**`. Tokenizer považoval závěrečnou dvojtečku za část ID,
takže přesné hledání odmítlo `finding:1:`. Oprava rozpoznává pouze úzký případ
tučného popisku s jednou interpunkční dvojtečkou a přesně známým kratším ID.
Původní přesně platné ID má přednost; neznámé, rozšířené a literální reference
se tím nepovolují. Narrative i jednotlivá claim posouzení používají stejný kontext.

## Skutečné ověření

- **100 pytest PASS**: 19 nových a 81 existujících kontrol. Před opravou byly
  zachyceny dvě skutečné RED reprodukce; setup chyby zůstaly uložené odděleně.
- Offline přehrání zachovaného AI textu použilo přesně rekonstruovaný původní
  kontext SHA-256 `53a47cc944e36377031cbfb8437cbf5cc18ccd105b076b563072d9fd7f5515e6`.
  Devět záznamů kontextu a tři používaná ID jsou hashově svázané s reportem.
- Nezávislý reviewer ověřil odmítnutí devíti negativních variant přes API
  i narrative cestu, včetně neznámých/rozšířených ID, code/fence a link targetů.
- Podpora tvrzení zůstává `not_assessed`, zdrojová umístění nevalidovaná
  a dvě původní source reference nevyřešené. Platnost ID nedokazuje pravdivost tvrzení.
- Standardní fresh freeze ověřil 265 payload souborů, 128 původů modulů a shodu
  current/snapshot source. Opravené `citations.py`, `llm_review.py` a `sarif.py`
  jsou svázané s jejich skutečnými bundlovanými origins.
- Skutečné source/frozen CLI a SARIF gate nad ne-prázdnou config fixture
  znovu prošly s verzí `1.5.1` a bajtově shodným raw SARIF. Procesy exit0/Job0.

Finální kandidát:
`.tmp/wp017-citation-freeze-20261107-01/dist/attackmap/attackmap.exe`

SHA-256:
`788572853653643fcab399c1ab8457071f32753d7d87594b9bc0f98bf29e387a`

Funkční citation cesta nebyla spuštěna uvnitř frozen aplikace. Source offline
přehrání a důkaz zahrnutí do balíčku jsou samostatné typy důkazů. Nevznikla nová
odpověď modelu a netvrdí se AI accuracy, C27, release ani whole-task přijetí.
Původní uživatelský Markdown a metadata nebyly přepsány; otevřená aplikace
stále používá původní engine `e5de…`. Kandidát nebyl nasazen a žádné GUI se neovládalo.

Raw podklady včetně nezávislého review jsou v
`artifacts/wp017-citation-label-20261107/`. Souvislost se skutečným uživatelským
během dokumentuje [WP005 protokol](../../WP005/closeout-20261107/README.md).
