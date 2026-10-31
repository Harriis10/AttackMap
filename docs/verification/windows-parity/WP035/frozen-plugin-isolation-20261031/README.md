# WP035 — skutečný frozen plugin v běžném paralelním CLI, 2026-10-31

**Scoped PASS:** běžné CLI spustilo dva repository workers a oba spustily skutečný externí Python plugin v odděleném analyzer host procesu. Celé WP035 zůstává IN_PROGRESS. Toto není native Fleet E2E ani OS sandbox, resource-limit, recovery nebo release acceptance.

## Identita a vstupy

Engine: `.tmp/fleet-e2e-engine-20261031-01/dist/attackmap/attackmap.exe`, SHA-256 `38632471645e82c5f20a0e05a413763c4573bf0006b695d2f00668c34d47746c`; hash před a po běhu souhlasí. Snapshot/build původ je v `.tmp/fleet-e2e-engine-20261031-01/diagnostic-build-proof.json`, nikoli tvrzení o novém release.

Plugin `python`, package `attackmap-analyzer-python==0.1.0`, entry point `attackmap.analyzers / python / attackmap_analyzer_python:PythonAnalyzer`. Raw ledger implementation identity SHA-256 je `2405f8ef35d663e54d3230e0f9447b174b766014517f480494488f5c34acc1aa` v obou scans. Build attestation zaznamenává wheel SHA-256 `89723ca15a0c42b4818242bc5c9541a9611de623c7939dd78fc240605a7c6320`. Ledger poctivě zachovává `pin_status=unverified`, `content_verified=false`: declared Git pin není runtime ověřením obsahu wheelu.

Použité existující kořeny: `tests/fixtures/python-service-app/web` a `tests/fixtures/python-service-app/django_site`. Před spuštěním ověřeno `PythonAnalyzer.detect(root)==True` pro oba, s freeze venv instalací a zachyceným core zdrojem. Následný frozen raw ledger potvrzuje applicability i skutečný běh. Nebyla instalace ani síťová volba, AI/CVE nebyly zapnuté; neproběhlo měření síťového provozu.

## Skutečný běh a neúspěšný předchůdce

Raw výstupy jsou v `artifacts/wp035-frozen-plugin-isolation-20261031-02/`; `run.py` obsahuje přesnou orchestraci a `invocation.json` přesný argv: `analyze <web> <django_site> --output <fresh reports> --format json --fleet-workers 2 --module python --isolated-analyzers --no-progress`. Použit vlastní Windows Job, suspended launch před attach/resume, časový limit 75 s a samostatný OS observer. TEMP/TMP/TMPDIR směřují do nového vlastního adresáře. Uživatelská nastavení se nepřepisují.

První pokus `artifacts/wp035-frozen-plugin-isolation-20261031-01/` skončil exit 1 na WinError 5 při vytváření worker temp. Žádný child nebyl zachycen, Job měl 0 aktivních procesů a fixture fingerprint zůstal shodný. Tento výsledek je zachován. Druhý pokus běžel s automaticky schváleným normálním přístupem k adresářům; bez změny ACL, monkeypatchu nebo náhrady produkčního kódu.

OS observer ve druhém pokusu zachytil parent PID 19052 a jeho skutečné CLI children 33504 a 25968. Oba child command lines obsahují přesně jeden `--isolated-analyzers`, explicitní `--module python` a `--fleet-result`. Dále zachytil skutečné potomky 31976 a 33416 s `-m attackmap.analyzer_host --worker`, entry point/distribution identitou výše a sealed snapshot descriptorem.

Oba raw `scan.json` mají plugin `origin=plugin`, `selection=selected`, `applicability=applicable`, `execution=succeeded`, `execution_mode=isolated`, `analysis_started=true`, bez analyzer errors. Web vydal 1 auth hint; Django 5 routes, 1 database hint, 2 auth hints a 2 secret hints. Exit 0, observer exit 0, owned Job active count před close 0. Fingerprint celého `python-service-app` před/po je shodný.

## Přesné automatické kontroly a hashe

`verification.json` vznikl automatickými asercemi: přesně 2 pozorované přímé fleet children; každý právě 1 isolation flag; přesně 2 analyzer host workers; v každém raw scanu právě jeden `python` ledger row, origin plugin, execution succeeded, mode isolated a žádné analyzer errors. Samostatná aserce porovnala engine EXE hash před/po. Job/fixture/observer stav je skutečně zaznamenán v `result.json`; jeho hodnoty byly zkontrolovány při vyhodnocení, runner je pouze zaznamenává a sám neassertuje exit 0 či fingerprint equality. Child `--module`/`--fleet-result`, host ancestry/entry point a počty signálů byly navíc přímo přečteny z raw důkazů.

| Důkaz v attempt02 | SHA-256 |
| --- | --- |
| `verification.json` | `0258a9f14d074086f5d8f278337eb7433b10578d052d385a13d2782abc54b1ae` |
| `observed-processes.jsonl` | `b8df4415029377a83cb172715c66aeea0f48b7e7660cca0159ae8e4d09a43c11` |
| `invocation.json` | `2dc74d43ec5a2623856d49d1ac2db6e55f17845283328b81e558466d4df8b36e` |
| `result.json` | `99a6ce01fcafae5cd2c8a629a109883496ac657ab82238c3892e6297d53e3e6b` |
| `fixture-before.json` a `fixture-after.json` | `678b228bcc4ed5daf687152a6b1d0439673ae9f3cd7a371857ed8884c4386912` |
| `reports/web/scan.json` | `a6d7524fff5c295416176c5c372fd44b5ee19bd9dd62772b2c413379ab62b1af` |
| `reports/django-site/scan.json` | `387202cd7ffddf3999f10704cf8d4b9a4bc916a9d2295e8bd0fdede195771258` |

## Vysvětlení původního zdánlivého rozporu

Předchozí `wp035-frozen-parallel-isolation-20261031-03` použil config-only reader/writer fixtures. V obou child scans běžely jen builtins `python-web`, `config`, `default`; všech 12 externích pluginů bylo unmatched/skipped. Builtins mají dle `analyzers.py:_is_builtin_analyzer` vždy in-process větev; flag cílí na externí pluginy. Jejich `execution_mode=in_process` je tedy očekávaný, nikoli ztráta flagu.

Existující focused regrese builtin-vs-plugin byly skutečně spuštěny: 3 PASS, 30 deselected; důkaz `artifacts/wp035-ledger-diagnostic-20261031-01/focused02.xml`. Plugin host je v těchto jednotkových testech nahrazen testovací odpovědí; skutečný host dokazuje až frozen attempt02 výše. První focused pokus měl 3 setup errors kvůli chybějícímu parent adresáři a zůstává ve `focused.xml`.

Produkční zdroje ani testy se neměnily. Žádné GUI, native Fleet, provider request nebo nový freeze neproběhly v této kvalifikaci. Native typed transport/preflight/UI i širší WP035 resource/fault containment brány vyžadují vlastní důkazy.
