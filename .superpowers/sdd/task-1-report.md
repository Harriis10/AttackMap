# Task 1: Native F7 Detail + Root Pair — report

## Stav

DONE podle zadání a briefu. Byl proveden povinný postup RED → implementace → GREEN → self-review. Nebyl proveden commit ani push.

## Implementace

### Nativní diagnostika

V `desktop/windows/AttackMap.NativeSpike/MainWindow.RenderDiagnostics.cs` bylo doplněno:

- aktivní příznak `renderDiagnosticsDetailRootRenderActive` vedle existujícího F8 příznaku;
- opt-in F7 `KeyboardAccelerator` bezprostředně před existující F8 registrací, včetně odpovídajícího cleanupu;
- metadata `f7 = "Non-mutating direct Detail and root RenderTargetBitmap pair; QA observation only"`;
- rozšíření `scope` o `explicit F7 writes D/T PNG pixels`;
- metoda `RenderDiagnosticsDetailRootRender()` bezprostředně před `RenderDiagnosticsSnapshot`, přesně podle briefu.

Nová metoda:

- emituje `detail-root-render-capture-started`, `detail-root-render-capture-completed` a `detail-root-render-capture-failed`;
- sdílí jednu lokální cestu validace, rasterizace, PNG kódování a atomického zápisu pro Detail i root;
- kontroluje dispatcher, načtení a viditelnost obsahu, navázaný finding, rozměry, scale, velikost pixelů a PNG;
- kontroluje `generation`, `findingRevision`, cancellation a stav diagnostics během capture;
- po Detail zachytí root a completed metadata obsahují oba názvy souborů, rozměry, scale, renderingFrames a vázaný kontext;
- neprovádí `UpdateLayout`, `Task.Delay`, `ChangeView` ani mutace Detail/root vlastností;
- odregistrovává `CompositionTarget.Rendering` a uklízí dočasný soubor.

F8 handler ani metoda `RenderDiagnosticsDetailRender()` nebyly změněny. Runner nebyl změněn.

### Source-gate test

V `tests/test_wp043_live_capture.py` byl vedle F8 source gate přidán přesný test z briefu `test_detail_root_render_probe_rasterizes_both_targets_without_settling_or_mutation`.

## RED

Příkaz:

```text
./.venv/Scripts/python.exe -B -m pytest tests/test_wp043_live_capture.py -q -k detail_root_render_probe_rasterizes
```

Výsledek před implementací:

```text
AssertionError: 'private async Task RenderDiagnosticsDetailRootRender()' not found in source
1 failed, 49 deselected in 0.63s
```

Selhání bylo očekávané a způsobené chybějící novou metodou, nikoli chybou testu.

## GREEN a nezměněný F8 source gate

Příkaz:

```text
./.venv/Scripts/python.exe -B -m pytest tests/test_wp043_live_capture.py -q -k "detail_root_render_probe_rasterizes or detail_render_probe_directly"
```

Výstup:

```text
..                                                                       [100%]
2 passed, 48 deselected in 0.27s
```

Plný testovací soubor po změně nebyl znovu spuštěn; brief pro tento krok předepsal cílené dvoutestové GREEN ověření. Východí baseline controlleru byla 49 passed, 8 subtests passed.

## Změněné soubory

- `desktop/windows/AttackMap.NativeSpike/MainWindow.RenderDiagnostics.cs`
- `tests/test_wp043_live_capture.py`
- `.superpowers/sdd/task-1-report.md` (tato zpráva)

Žádné jiné soubory nebyly tímto úkolem upraveny. Nesouvisející dirty worktree byl ponechán beze změny.

## Self-review

- F7 je registrováno pouze uvnitř explicitní opt-in inicializace render diagnostics.
- F7 registrace a cleanup odpovídají kódu briefu a jsou umístěny bezprostředně před F8.
- F8 handler, F8 metoda a původní F8 source-gate test zůstaly beze změny; cílený F8 test prošel.
- Nová metoda je bezprostředně před `RenderDiagnosticsSnapshot` a odpovídá briefu.
- Source-gate test je přesně doplněn vedle F8 testu a prošel po implementaci.
- Completed metadata obsahují všechna pole požadovaná briefem a vázaný kontext.
- V nové metodě nejsou settling/mutační konstrukce zakázané source gatem.
- `git status --short --` pro dva povolené pracovní soubory hlásí `??`; oba jsou v tomto worktree untracked, proto `git diff` pro ně neposkytuje diff. Self-review proto vychází z přímého čtení původního a výsledného obsahu a z cílených testů.
- Nebyly spuštěny build, restore, provider cally, scany, packaging ani live UI.

## Rizika a omezení

- Ověření je záměrně pouze source-gate; C# kompilace a živé WinUI chování nebyly v tomto úkolu ověřeny podle explicitního zákazu a odkladu v briefu.
- Runner zůstává předmětem samostatného pozdějšího úkolu.
- Skutečná vizuální shoda či rozdíl Detail/root PNG nebyla v tomto úkolu posuzována.
