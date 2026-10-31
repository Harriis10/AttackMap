# Tři navazující core řezy — WP031, WP032 a WP034 — 2026-10-31

Tato dávka navazuje na [kampaň core kvality](../ROADMAP-CAMPAIGN-20261031/README.md).
Uzavírá tři konkrétní, nezávisle revidované funkční řezy v existujícím dirty
checkoutu. Neuzavírá celé work packages, C27/C28/C35, Windows renderer,
produktový balíček ani release.

## Uzavřené omezené řezy

### WP031 — fail-closed statické Express/Sequelize bindingy

Nový bounded resolver sleduje přesný ESM import do jednoho exportovaného
handleru nebo nulového factory handleru a dává BOLA candidate jen pro
request-ID-only Sequelize `findOne`. Při nejistotě nevytváří candidate:
odmítá shadowing importu v parametrech, default inicializátorech, nested
closures, pozdějších declaratorech/destructuringu a ve stejném jmenném
function/generator/class/enum/namespace binderu. Běžná multiline registrace
zůstává podporovaná; opaque, nevyvážená, escaped nebo širší expression
syntaxe zůstává bez bindingu.

Tento safety řez vědomě snížil coverage: konečný frozen increment je **0 TP /
0 FP / 16 FN**, BOLA **0/0/1**. Dřívější 1/0/15 je superseded pre-fix evidence.
Žádný label, evaluator ani vstup corpusu nebyl změněn; původní baseline zůstává
JSON-identická (**19 TP / 1 FP / 6 FN**). To není maturity ani holdout-success
claim.

- [Oprava, retained RED důkazy a konečný JUnit](../WP031/agent-shadow-fix-20261031/README.md)
- [Konečný execution ledger](../WP031/agent-shadow-fix-20261031/final-binder-spellings/evaluation-execution.json)

### WP032 — multi-backend proxy negativa a DNS root-dot guard

Konfigurační multi-backend/unresolved proxy fakt nyní zanechává
`unresolved_proxies`, který přežije pořadí deklarací i CLI merge/fallback a
blokuje přímý i proxy observed fallback. Navazující P1 korekce porovnává
negative DNS fakt s `host.rstrip(".")`, takže `edge.internal.` nemůže obejít
`edge.internal` přes direct host, proxy ani host:port alias. Pozitivní zápis
destination/provenance zůstává zachován; nejednoznačné vazby jsou `candidate`,
nikoli observed.

Finální guarded sada má 451 PASS a nezávislý post-fix review ověřil 84 PASS,
včetně devíti dřívějších dotted-host bypassů a validních HTTP/HTTPS proxy
kontrol. Tento řez nepřidává obecnou scheme-less URL podporu ani runtime fleet
claim.

- [Multi-backend evidence](../WP032/agent-multibackend-20261031/README.md)
- [Trailing-dot oprava a JUnit](../WP032/agent-dot-host-fix-20261031/README.md)

### WP034 — opt-in fleet captured-input budget

`ScanRequest.fleet_input_byte_budget` je volitelný a nemění default. Pro fleet
rozdělí B deterministicými fixed quotas podle pořadí repo ID, předá cap jen do
child prostředí a zachová výsledky siblings. Nulová kvóta má typed
`fleet_input_capacity`; raw child snapshot/config metadata se validují
fail-closed. Fleet manifest explicitně rozlišuje `input_bytes.capture_status`
`within_quotas` a `partial`; nejde o globální coverage ani OS memory limit.

Nezávislé review našlo a oprava vyřešila kompatibilitu pozičního API: všech 55
původních polí `ScanRequest` zůstalo na původních pozicích a nový parametr je
až za `deployment_aliases`. Samostatný post-fix review znovu ověřil 25 budget
testů a legacy positional call.

- [Budget evidence](../WP034/agent-admission-20261031/README.md)
- [Poziční compatibility oprava](../WP034/agent-compat-fix-20261031/README.md)

## Společné ověření aktuálního zdroje

Primární integrový source běh přes WP031 auth/evaluation, WP032 contracts/
fleet a WP034 admission moduly skončil:

- **948 PASS, 1 SKIP, 0 failures, 0 errors; 3 explicitně deselected**, 99.14 s.
- [Primární JUnit](../../../../artifacts/roadmap-three-slices-20261031/root-final-source-suite-child-temp/results.xml)
- Provider calls: **0**.

První stejný pokus měl 911 PASS, ale 37 fleet chyb z Windows child `tempfile`
ACL před užitečnými asercemi; nepočítá se jako produktový výsledek. Platný běh
nastavil nový child TEMP/TMP uvnitř projektu a použil pouze process-local
mkdir-mode workaround.

Tři záměrně vynechané raw serial≡parallel ledger parity scénáře byly následně
spuštěny samostatně na tomto integrovaném zdroji a stále mají **3 FAIL, 0
errors**. Liší se pouze `analyzer_run_ledger` telemetrie; nejde o green výsledek
ani o waiver. [Aktuální JUnit známé brány](../../../../artifacts/roadmap-three-slices-20261031/root-known-ledger-baseline/results.xml).

## Otevřené brány

- **WP031 / C27:** BOLA zůstává experimental bez prokázané holdout recall;
  conservative resolver nepokrývá širší JS/TS dynamiku. Production diversity,
  human review a maturity prahy jsou otevřené.
- **WP032 / C28:** representative runtime fleet, zbývající protocol/namespace
  surface, native/UI/frozen/package a whole-task acceptance jsou otevřené.
- **WP034 / C35:** neexistuje finite default, 10k/50k/100k measured proof,
  <2 GiB claim ani native/package/release kvalifikace. Tři raw ledger parity
  failures zůstávají otevřené.
- **WP043:** text-disappearance/rendering acceptance je stále **FAILED**;
  V01–V03 jsou blocked.

Žádný ZIP, signing, release, native/UI nebo production-fleet acceptance z této
dávky neplyne. WP031, WP032 a WP034 zůstávají `IN_PROGRESS`.
