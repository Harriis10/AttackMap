# Aktuální dokumentace pro agenty

**Distribuce Windows, oprava Start scan 22. 10. 2026:** aktuální zdrojový portable ZIP je `desktop/windows/artifacts/AttackMap-Windows-Portable-20261022-startscan-fix.zip`. Opravená uživatelská kopie zůstává v `C:\Projects\FINISHED\AttackMap-Windows-Portable-20261022` a odpovídajícím ZIPu. Přenosný start používá vlastní engine i při existující staré cestě v globálním nastavení. [Důkazy opravy](verification/windows-parity/WP024/startscan-fix-20261022/README.md) a [návod ke spuštění](windows-full-product-launch.md) rozlišují skutečné testy od finálního release a čistého PC. Starší L/B-J ZIP zůstává zachován jako historický podklad. Zadání roadmapy se tím nemění.

**Běh pozastaven kvůli týdennímu limitu 50 %.** [Stav a bezpečné obnovení](verification/windows-parity/RECONCILE-2026-10-21/PAUSED-50PCT-2026-10-21.md). Nespouštět automaticky další práci; tento handoff nemění zadání ani akceptační kritéria roadmapy.

**Platnost od 20. 10. 2026.** Tento rozcestník určuje, které dokumenty řídí další práci. Pravidla repozitáře v [AGENTS.md](../AGENTS.md) zůstávají platná.

| Dokument | Úloha |
| --- | --- |
| [Roadmapa Windows parity](roadmap-windows-parity-2026-10-20.md) | Jediná aktuální roadmapa, checkpointy K0–K9 a akceptační podmínky. |
| [Podrobné TODO](windows-parity-todo.md) | Jediné aktuální zadání implementace: WP001–WP041, rozsah souborů, kroky a ověření. |
| [JSON backlog](windows-parity-backlog.json) | Strojový protějšek TODO: závislosti, vlastnictví a zámky pro paralelní agenty. |
| [Audit Windows/macOS](windows-parity-audit-2026-10-20.md) | Výchozí zjištění a mezery; není průběžným stavem dokončení úkolů. |
| [Provenience zdrojů](windows-parity-sources-2026-10-20.json) | Identita zdrojů a hashe při auditu, před následným přidáním archivních označení. |
| [Ověření plánu](verification/windows-parity/plan-validation-2026-10-20.json) | Dokumentační kontrola původního plánu; není runtime ani release acceptance. |

## Ostatní dokumenty: staré a nerelevantní pro řízení práce

Všechny ostatní dříve existující dokumenty jsou **historické podklady**. Nejsou aktuálním zadáním pro agenty. Platí to pro původní roadmapu, AM tracker, handoffy, architektonické plány, technické poznámky, README, `old_docs/` i staré ověřovací záznamy.

- Nevybírat z nich nové úkoly, priority, pořadí práce ani definici aktuálního releasu.
- Nepřebírat staré statusy PASS/DONE, čísla buildu nebo měření jako důkaz současného stavu.
- Technický kontrakt, původní kritérium C01–C40 nebo historický důkaz číst jen jako referenci potřebnou pro konkrétní aktivní WP úkol. Platnost technických tvrzení ověřit v aktuálním kódu.
- Rozsah převzatých kritérií určuje nová roadmapa. Windows M3 zůstává přijaté v zaznamenaném rozsahu; odstraněná Windows C26 se neobnovuje.
- Nalezený rozpor zaznamenat u příslušného WP úkolu; starý dokument nesmí sám změnit aktuální rozsah.

Archivní označení se týká autority pro plánování, nikoli automatické neplatnosti každého technického tvrzení. Pravidla repozitáře, bezpečnostní a příspěvkové zásady zůstávají platné. Retained evidence, generované reporty a testovací fixtures se kvůli označení nemění; jejich historický status určuje tento rozcestník a `AGENTS.md`.

## Začátek práce agenta

Desktopovým produktem je celé stávající okno `AttackMap.NativeSpike/MainWindow`, nikoli projekty `WPxxxPreview`. Ty slouží pouze k izolovanému ověření komponent. Nové ovládací prvky se musí propojit s původní navigací, službami a identitou zobrazeného běhu. Rozhodnutí a porovnání sestavení jsou v [záznamu integrace](verification/windows-parity/RECONCILE-2026-10-21/product-basis.md). Původní `artifacts/native-spike` se při ověřování nepřepisuje.

1. Přečíst `AGENTS.md`, novou roadmapu a kartu přiděleného WP úkolu.
2. Ověřit závislosti, stav a vlastníka úkolu v TODO a JSON backlogu.
3. Před úpravami převzít příslušný rozsah a zámky podle pravidel paralelní práce v nové roadmapě.
4. Otevírat starší dokumenty pouze jako potřebné reference, nikoli jako další backlog.
5. Předat důkazy a aktualizovat stav podle nové roadmapy a TODO.
