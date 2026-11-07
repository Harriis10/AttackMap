# Další roadmapový řez — WP033, WP039 a WP044 — 2026-10-31

Tato dávka navazuje na [pokračování 31. 10.](../ROADMAP-CONTINUATION-20261031/README.md).
Uzavírá tři konkrétní větší funkční řezy, nikoli celé work packages, release
nebo Windows rendering acceptance. Všechny změny zůstávají v dirty checkoutu;
žádný produktový ZIP ani release nebyl vydán.

## Uzavřené omezené řezy

### WP033 — skutečná frozen invalidace mezi buildy

Test-only PyInstaller A/B kvalifikace nad skutečným `C:/tmp/juice-shop`
prokázala, že stejný frozen build umí warm reuse a změněný extractor code
object invaliduje již naplněnou cache:

| Běh | Nové extractor calls |
| --- | ---: |
| build A cold | 658 |
| build A warm | 0 |
| build B nad zachovanou A cache | 658 |
| build B warm | 0 |

Všech šest incremental/no-cache referenčních běhů mělo shodný výsledek i
coverage 658 souborů. Identity A
`8dfb4ef1…11f5` a B `c52f68a4…28a5` se liší pouze po skutečné sémanticky
shodné změně testovací kopie extractoru `scanner`; raw A cache měla před B 658
entries a audit po B ověřil nulový překryv klíčů. Runtime `incremental.py` se
neměnil. [A/B důkaz a příkazy](../../../../artifacts/roadmap-next-20261031/wp033-frozen-ab/README.md)

### WP039 — bezpečné Django decorator/view import bindingy

Django resolver nyní umí bounded import-only reexport exact
`login_required`/`login_not_required` identity pro function view, bez
vykonávání aplikace. Nejdůležitější rozšíření tohoto řezu je bezpečnostní:
stejný AST-aware binding resolver chrání dekorátory i function/class view
target před package-shadow false positives. Rozlišuje explicitní `Import`,
`ImportFrom` fallback a obyčejný attribute traversal; nejednoznačné/dynamické
bindingy, cycles, custom dekorátory, DRF a absent child zůstávají `unknown`.

Nezávislé review našlo a oprava odstranila tři false-positive rodiny; finální
review má 36/36 samostatných scénářů a 187 focused PASS. Aktuální zdrojový
hash je `7a495222378aa6667342e3138e9510ca1524b26b8d5826186775c2d853ec8369`.
Finální související source sada má 316 PASS a actual exact offline installed
pin 13 PASS včetně isolated workeru, kolize a Juice Shop parity.
[Evidence, reprodukce a otevřené omezení](../../../../artifacts/roadmap-next-20261031/wp039-decorator-auth/README.md)

### WP044 — explicitní Kafka producer/consumer declarations

Nový opt-in YAML/JSON kontrakt `attackmap_messaging` vytváří pouze statický
`producer_consumer` vztah, když dvě různé kanonické repository deklarují
stejnou sedmidílnou Kafka identity a opačné `publish`/`consume` operace.
Vztah je směrovaný, ale výhradně `resolution=declared`: neprokazuje runtime
delivery, aktivní subscription, ordering, trust cestu ani HTTP/RPC kontrakt.

Fyzický syntetický 16-repo průchod má shodná serial/parallel fakta: 8
deklarací → 7 topic resources, 1 declared edge, 6 unmatched, 23 nodes, 8
evidence záznamů, 13 completed + 3 partial children a 32 ověřených child
manifestů. Juice Shop + library negative vytvořil nula messaging hran.
Compatibility sada má 348 PASS; finální messaging sada 68 PASS (sady se
překrývají). [Podrobná kvalifikace](../WP044/agent-20261031/README.md) ·
[formát kontraktu](../../../fleet-messaging-declarations.md)

## Společné ověření

Integrátor znovu spustil společnou aktuální zdrojovou sadu přes cache, Django
a fleet kontrakty. Strojově čitelný JUnit výsledek:

- **620 PASS, 13 SKIP, 0 errors, 0 failures, 56.90 s**.
- [JUnit XML](../../../../artifacts/roadmap-next-20261031/root-shared-source-suite-junit-final/results.xml)
- Provider calls: **0**.

První společný pokus byl přerušen před výsledkem kvůli odhalenému WP039
false-positive; další pokus bez auditovatelného JUnit souhrnu se nezapočítává.
Pouze výše uvedený finální JUnit běh je společná kvalifikace této dávky.

## Otevřené brány

- **WP033:** 100 edit/mutation sequences, native round-trip, C34 performance
  a release/clean-host nejsou hotové.
- **WP039:** literal plugin mount duplication, širší framework/DRF/dynamic
  coverage, C27/C38 maturity, frozen/GUI a release brány zůstávají otevřené.
- **WP044:** obecná messaging discovery, runtime delivery, RPC/protobuf/OpenAPI,
  reprezentativní production fleet, native/frozen/UI a whole-task acceptance
  nejsou hotové.
- **WP043:** globální text-disappearance/rendering acceptance je nadále
  **FAILED**; V01–V03 zůstávají blocked a tato dávka ji neměnila.

Všechny lease této dávky jsou uvolněné. Stav WP033/WP039/WP044 zůstává
`IN_PROGRESS`; tento dokument neuděluje release ani whole-task acceptance.
