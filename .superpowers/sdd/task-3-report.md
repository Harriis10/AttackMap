# WP043 Task 3 — Offline Candidate, One Live Run, and Evidence-Led Review

## Status

**BLOCKED — diagnostická/harness chyba occlusion před prvním capture.** Byl proveden právě jeden sériový live pokus; nebyl opakován. Offline candidate-08 byl vytvořen, ale live běh nedokončil žádné kolo a neposkytuje vizuální vzorek ani výsledek `not-reproduced`.

WP043 zůstává `IN_PROGRESS`, celkové rendering acceptance zůstává `FAILED` a V01/V02/V03 zůstávají blokované. Nebyl prokázán root cause, repair, workaround ani candidate promotion.

## Fresh cesty a zachovaný rozsah

Před publish/capture byly obě cílové cesty neexistující:

- `artifacts/diagram-integration-20261024/wp043-continuation-20261025/ordinary-candidate-08`
- `artifacts/diagram-integration-20261024/wp043-continuation-20261025/detail-root-render-probe-live-28`

Frozen engine z `ordinary-candidate-07/engine` obsahuje skutečný executable `attackmap.exe`, nikoli `attackmap-engine.exe`; hash byl proto změřen nad skutečným souborem podle briefu. Původní dirty worktree ani frozen engine nebyly upraveny. Nebyl proveden commit, push, restore, SDK change, provider call, scan, packaging ani paralelní UI/build běh.

## Step 1 — offline publish a frozen engine

Provedený příkaz:

```bash
out="artifacts/diagram-integration-20261024/wp043-continuation-20261025/ordinary-candidate-08"
winpwd=$(pwd -W)
export DOTNET_CLI_HOME="$winpwd/.tools/dotnet-home"
export NUGET_PACKAGES="$winpwd/.tools/nuget-packages"
./.tools/dotnet/dotnet.exe publish desktop/windows/AttackMap.NativeSpike/AttackMap.NativeSpike.csproj -c Release --no-restore -o "$out"
cp -a artifacts/diagram-integration-20261024/wp043-continuation-20261025/ordinary-candidate-07/engine "$out/engine"
./.venv/Scripts/python.exe -B -c "from pathlib import Path; import hashlib; p=Path(r'artifacts/diagram-integration-20261024/wp043-continuation-20261025/ordinary-candidate-08'); print('DLL', hashlib.sha256((p/'AttackMap.NativeSpike.dll').read_bytes()).hexdigest()); print('ENGINE', hashlib.sha256((p/'engine/attackmap.exe').read_bytes()).hexdigest())"
```

Výsledek: publish exit 0, bez restore; `GraphExplorer.Core`, `GraphExplorer.NativeView` a `AttackMap.NativeSpike` se sestavily a publikovaly. Skutečné identity:

| Položka | SHA-256 |
|---|---|
| Candidate-08 `AttackMap.NativeSpike.dll` | `d835577690d759bb2f1eeab114fbb415ca16a1c1fa724efbb112d2c2d730f650` |
| Candidate-08 `AttackMap.NativeSpike.exe` | `e77a93879784f2d71d4ea7dfb2f4bc9300658c516beea38a1e7789b153635b49` |
| Candidate-08 `engine/attackmap.exe` | `792184c584895bab68e4260447fe89543486ae228bd8ad85234ae3ca87ce8bba` |
| Zdrojový frozen `ordinary-candidate-07/engine/attackmap.exe` | `792184c584895bab68e4260447fe89543486ae228bd8ad85234ae3ca87ce8bba` |
| Retained `attackmap-report.json` | `860343835432b3267da81f4b4124925eeae94ea570ed972cb3c4b040875d581d` |

Nezávislé závěrečné přepočtení potvrdilo shodu candidate/source engine hashů a shodu executable/report hashů s `evidence.json`.

## Test evidence

Task 3 žádný testovací příkaz znovu nespouštěl; brief vyžadoval offline publish, jediný live běh a vizuální review. Poslední review-approved Task 2 evidence v `.superpowers/sdd/task-2-report.md` je `56 passed, 15 subtests passed in 5.03s` pro:

```bash
./.venv/Scripts/python.exe -B -m pytest tests/test_wp043_live_capture.py -q
```

Tento historický výsledek není vydáván za čerstvé ověření Task 3 ani za důkaz live Windows/F7 chování.

## Step 2 — jediný live pokus

Provedený příkaz:

```bash
./.venv/Scripts/python.exe -B tools/capture_wp043_live.py \
  --executable artifacts/diagram-integration-20261024/wp043-continuation-20261025/ordinary-candidate-08/AttackMap.NativeSpike.exe \
  --report artifacts/diagram-integration-20261024/source-render-audit-20261025/saved-generation/attackmap-report.json \
  --output artifacts/diagram-integration-20261024/wp043-continuation-20261025/detail-root-render-probe-live-28 \
  --native-only --theme dark --detail-root-render-probe
```

Výsledek: runner exit 1 po přibližně 5,1 sekundy. Manifest `detail-root-render-probe-live-28/evidence.json` obsahuje:

| Pole | Skutečná hodnota |
|---|---|
| `status` | `failed` |
| `runId` | `9045b8cb08a24c9db9b371f6f996371f` |
| `pid` | `53980` |
| `error.type` | `FrameSafetyError` |
| `error.message` | `Visible higher-Z-order occluder intersects target: title='', hwnd=462332, pid=17752, rect=(0, 40, 307, 184), z=34, targetZ=36` |
| `completedRounds` | `0` |
| `captures` | `[]` |
| `discardedCaptures` | `[]` |
| `detailRootRenderProbe` | `[]` |
| `diagnosticInterventions` | `false` |
| `manual_review` | `not-run` |
| `rendering_acceptance` | `not-established` |
| `closedCleanly` | `false` |

`stdout.log` i `stderr.log` jsou prázdné. Output strom neobsahuje žádný PNG. Chyba je klasifikována výhradně jako diagnostická/harness occlusion chyba; není interpretována jako A-blank, jiná vizuální anomálie, reprodukce ani `not-reproduced`.

Dvě nezávislé kontroly `tasklist.exe //FI "PID eq 53980"` po běhu vrátily `INFO: No tasks are running which match the specified criteria.` Vlastněný PID tedy není dále spuštěný; `closedCleanly=false` se nereprezentuje jako čisté ukončení capture.

## Step 3 — vizuální matice

Nebyl vytvořen žádný z 20 požadovaných A/D/T/B obrazů, proto žádný nebyl otevřen ani hodnocen. Nebyla vytvořena `visual-review/manual-review.json`, protože neexistuje vizuální vzorek; závazný manifest správně uvádí `manual_review=not-run`.

| Kolo | A: ordinary | D: Detail RTB | T: root RTB | B: ordinary |
|---|---|---|---|---|
| 1 | Nevznikl — harness occlusion | Nevznikl — harness occlusion | Nevznikl — harness occlusion | Nevznikl — harness occlusion |
| 2 | Nevznikl — harness occlusion | Nevznikl — harness occlusion | Nevznikl — harness occlusion | Nevznikl — harness occlusion |
| 3 | Nevznikl — harness occlusion | Nevznikl — harness occlusion | Nevznikl — harness occlusion | Nevznikl — harness occlusion |
| 4 | Nevznikl — harness occlusion | Nevznikl — harness occlusion | Nevznikl — harness occlusion | Nevznikl — harness occlusion |
| 5 | Nevznikl — harness occlusion | Nevznikl — harness occlusion | Nevznikl — harness occlusion | Nevznikl — harness occlusion |

UIA, diagnostics ani hashe nebyly použity jako náhrada vizuální kontroly glyphů. Nebylo provedeno žádné tvrzení o glyph stavu, model verzi ani render/composition mechanismu.

## Step 4 — aktivní evidence a dokumentované soubory

Protože capture bezpečně nedoběhl, podle stop-podmínky nebyly aktualizovány tyto aktivní dokumenty:

- `artifacts/diagram-integration-20261024/wp043-continuation-20261025/PROGRESS-20261025.md`
- `docs/roadmap-windows-parity-2026-10-20.md`
- `docs/windows-parity-todo.md`
- `docs/windows-parity-backlog.json`

Jejich předchozí obsah/stav byl zachován; Task 3 do nich nepřidal nové runtime ani vizuální acceptance tvrzení. Závěrečné parsování `docs/windows-parity-backlog.json` proběhlo úspěšně a WP043 záznam má nadále `status=IN_PROGRESS`.

Vytvořené artefakty Task 3:

- `artifacts/diagram-integration-20261024/wp043-continuation-20261025/ordinary-candidate-08/`
- `artifacts/diagram-integration-20261024/wp043-continuation-20261025/detail-root-render-probe-live-28/`
- `.superpowers/sdd/task-3-report.md`

## Závěrečná verifikace a omezení

Čerstvý verifikační příkaz přepočetl DLL/engine/executable/report SHA-256, načetl `evidence.json`, ověřil všechny výše uvedené klíčové hodnoty, absenci PNG a validitu backlog JSON; všechny uvedené assertions prošly. Druhý `tasklist` potvrdil exit vlastněného PID `53980`.

Candidate-08 je pouze diagnostický offline kandidát bez live vizuální kvalifikace. Tento běh neposuzuje, zda se cílená anomálie reprodukovala, a nemění dosavadní root-cause ani acceptance stav. Další live pokus vyžaduje bezpečně nepřekrytý foreground desktop, novou fresh output cestu a samostatné explicitní povolení; Task 3 jej záměrně neprovedl.
