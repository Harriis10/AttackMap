# WP035 — předání izolace analyzérů běžným paralelním CLI fleet workerům

Datum: 2026-10-31. Owner: `/root/fleet_isolation_fix`; integrátor `/root`.
Base commit: `4ea5e49ade229fc0432d68ce0f7e99bcf87b545d`; změny zůstávají v pracovním stromu.
Celé WP035 zůstává **IN_PROGRESS**. Tento záznam uzavírá pouze opravu předání příznaku.

## Příčina a nejmenší oprava

Běžné `analyze repo-a repo-b --fleet-workers 2 --isolated-analyzers` předalo volbu do
`ScanRequest`, ale `_run_fleet_repo_argv` ji přidával pouze pro `fleet_supervised=True`.
Běžné paralelní CLI tak v child argv příznak ztratilo. Sériová větev jej již předávala
přes `AnalyzeOptions`; supervised větev jej již přidávala správně.

Jediná produkční změna v `src/attackmap/scan_service.py` odstranila podmínku
`fleet_supervised` pouze z předání `--isolated-analyzers`. Guard pro
`--time-budget-seconds`, výchozí neizolované chování i výběr serial/supervised cest
zůstaly zachované. Integrátor přidělil výhradní lease jen na tento hunk sdíleného souboru.
Předchozí dirty změny v souboru jsou zachované a nejsou součástí tohoto řezu.

## Ověření a přesné hranice

`tests/test_fleet_parallelism.py` nyní ověřuje běžné paralelní CLI s izolací vypnutou
i zapnutou: CLI parser → fleet dispatch → skutečný pool → per-repo worker → child argv.
Nahrazen je až `_run_supervised_worker`, který dodává manifest-bound testovací výsledek;
test kontroluje přesně jeden příznak u obou child argv, nebo jeho absenci. Samostatné
CLI případy pro `--fleet-workers 1` ověřují obě hodnoty `AnalyzeOptions.isolated_analyzers`
a zakazují spuštění subprocess workeru. Stávající desktop fleet test zachovává důkaz
supervised mappingu včetně izolace a time budgetu.

| Běh | Výsledek | Důkaz |
| --- | --- | --- |
| Nové CLI případy před produkční opravou | **1 FAIL, 3 PASS**, 21 deselected; selže právě parallel + isolation, `0 != 1` v child argv | `baseline-red.junit.xml` |
| Celá dopadová sada `test_fleet_parallelism.py` + `test_desktop_fleet.py` po opravě | **60 PASS, 3 FAIL** | `expanded-with-known-parity-failures.junit.xml` |
| Stejná sada s explicitním vynecháním tří známých raw ledger parity případů | **60 PASS, 3 deselected, 0 failures/errors/skips** | `final-focused.junit.xml` |

Tři červené případy jsou `test_fleet_real_workers_match_serial[all/json/markdown]`:
skutečné child scany dokončily, ale raw `ScanResult` se liší v nedeterministickém
`analyzer_run_ledger`. Jde o dříve zaznamenanou otevřenou bránu; tento řez ji nemění
a zelený výsledek ji neskrývá. Její oprava patří samostatnému ownerovi.

První pokusy narazily na lokální Windows temp ACL a jeden chybějící parent adresář;
jsou zachované v `initial-temp-error.junit.xml`, `missing-parent-error.junit.xml`,
`explicit-temp-acl-error.junit.xml` a `stdlib-temp-acl-error.junit.xml`. Nejsou
produktovým výsledkem. `run_focused_tests.py` používá vlastní temp pod `artifacts/`,
nastaví TEMP/TMP/TMPDIR a **jen v testovacím procesu** nahradí `os.mkdir(0o700)`
režimem `0o777`. Nenahrazuje produkční orchestrace, argv ani výsledky asercí.

## Reprodukce

Python 3.13.15 / Windows 10 10.0.19045 AMD64, existující `.venv`.
Z kořene projektu, s novým vlastním `--basetemp` při každém opakování:

```powershell
.venv/Scripts/python.exe docs/verification/windows-parity/WP035/cli-fleet-isolation-20261031/run_focused_tests.py tests/test_fleet_parallelism.py tests/test_desktop_fleet.py -k 'not test_fleet_real_workers_match_serial' -q -p no:cacheprovider --basetemp=artifacts/wp035-cli-isolation-20261031/final-green-temp --junitxml=docs/verification/windows-parity/WP035/cli-fleet-isolation-20261031/final-focused.junit.xml
git diff --check -- src/attackmap/scan_service.py tests/test_fleet_parallelism.py
```

Validní baseline použil stejný runner před produkční opravou, pouze soubor
`tests/test_fleet_parallelism.py`, selector
`test_cli_fleet_workers_spawns_parallel_subprocesses or test_cli_serial_fleet_preserves_isolation_policy`
a nový `baseline-final-temp`. Rozšířený běh použil oba soubory bez `-k` a nový
`final-focused-temp`. `git diff --check` prošel.

## Předání

- Produkční soubor: `src/attackmap/scan_service.py`, jeden hunk v `_run_fleet_repo_argv`.
- Regrese: `tests/test_fleet_parallelism.py`, rozšíření existujícího CLI testu a serial on/off případy.
- `owned-change.patch` izoluje pouze tento diff od starší dirty práce; SHA-256
  `11a0a3fc6315d35a6d3ad48daf2fa3cc48078452a65744cc5393c43c0969a2e3`.
- `evidence-manifest.json` obsahuje identitu runtime, base commit a hashe zdrojů/důkazů.
- TODO/backlog/index aktualizuje integrátor; žádný společný dokument zde nebyl přepsán.

Nový test neprokazuje skutečné spuštění externího pluginu v izolovaném procesu ani
OS sandbox. Built-ins nadále běží in-process; skutečná plugin isolation/fault containment,
podporované OS, frozen a resource/recovery brány WP035/C36 vyžadují vlastní důkazy.
Žádný LM Studio/provider request, Juice Shop kvalifikace, native/UI/WP043 zásah,
package build ani release nebyly součástí této opravy.
