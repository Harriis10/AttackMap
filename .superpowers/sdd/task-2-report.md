# WP043 Task 2 — Runner Protocol, Validation, and Regressions

## Status

Dokončeno podle `task-2-brief.md` postupem RED → implementace → GREEN. Nebyl proveden commit, push, build, restore, provider call, scan, packaging ani live UI test. Původní dirty worktree zůstal zachován.

## Implementace

### `tools/capture_wp043_live.py`

- Přidán párový F7 ACK helper `_detail_root_render_terminal(...)`:
  - vyžaduje nový `detail-root-render-capture-started` a odpovídající terminální `completed`/`failed` event;
  - váže `probeId`, `runId`, `displayedReadHash`, `navigationRevision` a `findingRevision`;
  - starý nebo nepárový terminální event nemůže uvolnit B capture.
- Přidán helper `_detail_root_png(...)` pro Detail i root PNG:
  - jednoduché `.png` jméno bez traversal a resolved parent uvnitř `diagnostics`;
  - limity rozměrů, počtu pixelů, scale a velikosti souboru;
  - kontrola PNG signatury, IHDR a shody rozměrů s metadaty;
  - kontrola kanonického koncového IEND chunku, čímž je odmítnut i obsah připojený za platný PNG.
- Přidán režim `--detail-root-render-probe` a mapování `F7` na `{F7}`.
- Exkluzivita je vymáhána pouze v runneru před vytvořením outputu: ani jeden render probe nelze kombinovat s druhým render probem, interventions, spacing/brush probem nebo PrintWindow režimem.
- F7 větev po nezměněné F8 větvi provede bezpečnostní kontrolu, ověří finding revision, počká na párový completed ACK, zvaliduje oba PNG a teprve potom vytvoří `FindingDetailRootRenderAfter`.
- Manifest nově obsahuje `detailRootRenderProbe` a pro každé kolo A/D/T/B metadata včetně cest, bajtů, SHA-256, rozměrů, scale, `afterSequence`, `terminalSequence` a stavu `captured-awaiting-visual-review`.
- F8 větev ani nativní implementace z Task 1 nebyly změněny.

### `tests/test_wp043_live_capture.py`

- FakeBackend nově simuluje F7 started/completed/failed eventy a zapisuje skutečné 1×1 PNG pro Detail i root.
- Přidána hlavní pětikolová A/D/T/B regrese: 80 captures, pět F7, žádné F8, pět manifest položek a hash/rozměrová kontrola obou PNG.
- Přidány regrese pro:
  - zakázané kombinace režimů před vytvořením outputu;
  - Detail/root failed ACK bez B capture a s prázdným manifestem;
  - stale ACK bez odpovídajícího started eventu;
  - změnu finding revision během tripletu;
  - malformed PNG bez B capture.
- Source-gate test z Task 1 `test_detail_root_render_probe_rasterizes_both_targets_without_settling_or_mutation` zůstal zachován a prošel.

## RED

Příkaz:

```text
./.venv/Scripts/python.exe -B -m pytest tests/test_wp043_live_capture.py -q -k "detail_root or stale_detail_root"
```

Skutečný výsledek před implementací runneru:

```text
11 failed, 2 passed, 49 deselected in 3.59s
```

Selhání odpovídala chybějícímu F7 chování: nebyla vyvolána `ValueError` pro kombinace režimů, zůstalo 75 místo 80 captures, chyběl `detailRootRenderProbe`, a failed/stale/malformed scénáře neskočily jako `failed`.

## První implementační GREEN pokus a nutná oprava

Po implementaci přesných helperů a zapojení z briefu byl spuštěn tentýž focused příkaz. Výsledek:

```text
1 failed, 5 passed, 49 deselected, 7 subtests passed in 1.24s
```

Jediným selháním byl `test_malformed_detail_root_png_never_claims_after_capture`: původní 24bajtová IHDR kontrola z briefu neodmítla `b"broken"` připojené za jinak platný PNG, takže běh chybně skončil jako `independent-live-window-captured`.

Drobná implementační oprava: `_detail_root_png(...)` nyní dodatečně čte posledních 12 bajtů a vyžaduje kanonický prázdný IEND chunk (`00 00 00 00 49 45 4e 44 ae 42 60 82`). Tím byla odchylka od reálného chování testu odstraněna bez změny testu, oslabení bezpečnostních podmínek nebo zásahu do F8.

## Finální GREEN

Focused příkaz:

```text
./.venv/Scripts/python.exe -B -m pytest tests/test_wp043_live_capture.py -q -k "detail_root or stale_detail_root"
```

Výstup:

```text
......                                                            [100%]
6 passed, 49 deselected, 7 subtests passed in 0.70s
```

Celý povinný harness:

```text
./.venv/Scripts/python.exe -B -m pytest tests/test_wp043_live_capture.py -q
```

Výstup:

```text
.......................................................   [100%]
55 passed, 15 subtests passed in 5.21s
```

## Změněné soubory

- `tools/capture_wp043_live.py`
- `tests/test_wp043_live_capture.py`
- `.superpowers/sdd/task-2-report.md` (tento report)

## Self-review

- Nové testy byly skutečně sledovány v RED stavu před produkční implementací.
- F7 ACK je vázaný na aktuální run/report/navigation/finding kontext a started/probe pár.
- Žádná failed, stale ani malformed cesta nevytváří B capture ani položku `detailRootRenderProbe`.
- Kombinace režimů jsou odmítnuty před vytvořením output adresáře.
- Hlavní úspěšná cesta obsahuje pět nezávislých pětic A/D/T/B a nemění `diagnosticInterventions`.
- Existující F8 regrese, transient/navigation/diagram regrese i nativní source gate zůstaly zelené v celém harnessu.
- Rozsah změn omezen na povolený runner, test a explicitně požadovaný report; nativní soubor Task 1 ani F8 logika nebyly upraveny.

## Odchylky a rizika

- Jediná implementační odchylka od doslovného kódu briefu je doplňující IEND kontrola popsaná výše; byla nutná pro předepsaný malformed-PNG test.
- Ověření je fake-backend/fixture regrese. Podle zákazu nebyl spuštěn live UI, build ani vizuální review, takže skutečné Windows/F7 chování a vizuální kvalita zde nejsou akceptovány.
- PNG kontrola ověřuje signaturu, IHDR/rozměry a koncový IEND; neprovádí úplnou validaci CRC všech chunků ani dekódování obrazu. To odpovídá zamýšlené strukturově-metadatové kontrole runneru, ne plnému image decoderu.

## Reviewer fix — striktní pořadí F7 started/terminal

### Rozsah a implementace

- **Important:** `_detail_root_render_terminal(...)` nově ukládá pro každé `probeId` sekvenci started eventu místo pouhé přítomnosti v množině. Terminální completed/failed event je přijat pouze tehdy, když jeho `sequence` je striktně větší než `sequence` odpovídajícího started eventu.
- Při duplicitním `probeId` se konzervativně použije poslední started v diagnostics pořadí. Terminál před tímto posledním startem je odmítnut; completed-before-started tedy nemůže uvolnit B capture.
- **Minor:** existující stale F7 regrese nově explicitně kontroluje absenci `FindingDetailRootRenderAfter`.
- Nová regrese `test_detail_root_completed_before_started_cannot_release_after_capture` dodává platné PNG, ale prohodí pořadí completed a started. Ověřuje `status == failed`, prázdné `detailRootRenderProbe` a absenci B capture, takže RED nemůže projít díky chybějícím souborům nebo jiné vedlejší validaci.
- F8 ani žádná jiná bezpečnostní kontrola nebyly změněny.

### RED

Příkaz:

```text
./.venv/Scripts/python.exe -B -m pytest tests/test_wp043_live_capture.py -q -k "detail_root or stale_detail_root"
```

Výstup před opravou helperu:

```text
F......                                                           [100%]
1 failed, 6 passed, 49 deselected, 7 subtests passed in 1.15s
```

Nová regrese skončila jako `independent-live-window-captured` místo `failed`, čímž reprodukovala přijetí completed sekvence před started.

### Focused GREEN

Stejný příkaz po minimální opravě:

```text
.......                                                           [100%]
7 passed, 49 deselected, 7 subtests passed in 0.78s
```

### Celý harness

Příkaz:

```text
./.venv/Scripts/python.exe -B -m pytest tests/test_wp043_live_capture.py -q
```

Výstup:

```text
........................................................  [100%]
56 passed, 15 subtests passed in 5.03s
```

### Změněné soubory a zbylá omezení

- `tools/capture_wp043_live.py` — pouze F7 mapování `probeId → started sequence` a podmínka striktně následujícího terminálu.
- `tests/test_wp043_live_capture.py` — jedna nová ordering regrese a doplněný stale assert.
- `.superpowers/sdd/task-2-report.md` — tento fix report.
- Nebyl proveden commit, build ani live UI. Ověření zůstává na fake-backend regresích; reálné Windows/F7 chování tímto není vizuálně akceptováno.
