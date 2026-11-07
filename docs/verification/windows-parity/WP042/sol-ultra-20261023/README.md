# WP042 + WP039 — první implementační dávka, 23. 10. 2026

Na výslovný pokyn uživatele pracovaly souběžně tři implementační větve
**GPT-6.1 Sol / ultra**: katalog a kolize, výběrové profily a PHP routing.
Integrátor propojil CLI/capabilities, provedl společné ověření, nový freeze
a skutečné deterministické scany. WP042 a WP039 zůstávají **IN_PROGRESS**.
Tato dávka neuzavírá jejich celé DoD, závislosti ani release/platform acceptance.

Výchozí HEAD: `507bddacd72a246a136ca2d46faad2aa661806c1`.
[Baseline](baseline.json) zaznamenává již rozpracovaný strom a hashe vstupů.
Nevznikl commit, změna oficiálních plugin pinů ani automatická instalace pluginů.
Existující portable a uživatelská instalace nebyly nahrazeny.

## Dodané chování

- `modules --catalog-json` a additive pole v `capabilities` ukazují účinnou
  implementaci, původ, verzi, kandidáty zastíněné kolizí, policy skip a konkrétní
  fáze selhání discovery. Metadata a katalog vznikají z jednoho discovery.
  Katalog je svázaný s executable/source identity; deklarovaný Git pin se
  nezaměňuje za důkaz skutečně nainstalovaného obsahu.
- `modules --profiles-json` a `analyze --analyzer-profile NAME@1.0` poskytují
  Automatic, Node/ATProto, PHP/Laminas/Omeka S a Python. Profily zachovávají
  pojmenované základní vrstvy; chybějící modul znamená chybu bez instalace nebo
  náhrady. CLI zobrazuje experimentální/opt-in výběr. Bare `-m` zůstává přesným
  seznamem; Automatic zachovává původní discovery a detekční cestu.
- Laminas/Omeka statické `router.routes` nyní skládají rodičovské a dětské
  prefixy. Controller/action defaults mají vlastní evidence a inferred/observed
  označení; neznamenají důkaz runtime dispatch. Dynamické, nejednoznačné nebo
  nepodporované struktury dostávají explicitní unsupported hint. Auth zůstává
  unknown, pokud pro konkrétní routu není doložené řízení přístupu.

Příklad opravy: původní `/admin` + odpojené `/item/:id` nyní tvoří
`/admin/item/:id`. Bez `may_terminate` se rodič s potomky samostatně nevydává
za koncový endpoint. Wrong-parent negativní případ zachovává `/public/item/:id`
a nevytváří `/admin/item/:id`. [Paired důkazy a scope](php-routes-handoff.md).

Podrobný kontrakt: [katalog](../../../../ecosystem/analyzer-catalog.md),
[profily](../../../../ecosystem/analyzer-profiles.md).
Agentní předání: [katalog](catalog-handoff.md), [profily](profiles-handoff.md),
[PHP](php-routes-handoff.md).

## Ověření

| Ověření | Výsledek a hranice |
| --- | --- |
| Společná cílená regrese stabilního zdroje | **266 PASS, 2 SKIP**; oba skipy vyžadují PHP plugin absentní v `.venv`. [JUnit](integrated-tests-final.xml), [log](integrated-tests-final.log). |
| Zdrojový katalog | 9 účinných built-ins; dostupné Automatic a PHP. Chybějící Node/Python pluginy nejsou nahrazené. |
| Nový frozen katalog | **15 připnutých plugin balíčků, 24 kandidátů, 21 účinných analyzérů**; přesně tři shadowed kandidáti `php-web`, `php-laminas`, `omeka-s`. Všechny čtyři profily dostupné. [Kontrola](catalog-verification.json). |
| Zdrojový Automatic na Juice Shopu | Celý `attackmap-report.json` shodný před/po bez normalizace; 266 rout, 18 findings. |
| Frozen Automatic na Juice Shopu | Celý report shodný mezi předchozím a novým enginem; 270 rout, 18 findings. |
| Frozen explicitní seznam → Node profil | Celý report shodný pro totožný výběr modulů; 281 rout, 18 findings. Profily nerozšiřují samotné detektory. |
| Frozen PHP profil | Skutečný CLI scan původní syntetické Omeka fixture, 4 správně složené routy, 5 provedených modulů, auth zůstal unknown. [Kontrola](frozen-php-profile-verification.json). |
| Nezávislé review | Katalog/profily + integrace zkontrolovány; PHP review našlo a před finálním freeze odstranilo falešné přijetí namespace/class aliasů. [Review](catalog-independent-php-review.md). |

[Juice Shop důkazy](juice-shop-verification.json) uvádějí hashe a přesné cesty
všech reportů i provedené analyzéry. Target byl `C:\tmp\juice-shop`, commit
`e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4`; reporty leží mimo target. Všechny
porovnávané scany skončily bez analyzer errors, bez překročení časového limitu
a bez AI/provider volání. Existující omezení se neztratila: dva nadlimitní soubory
jsou vynechány a pluginové scany nadále hlásí nedostupné úplné unique-file coverage.
Počet `files_scanned` proto není důkaz počtu unikátních souborů.

Nový engine:
`.tmp/wp042-sol-ultra-20261023/frozen-engine-final/dist/attackmap/attackmap.exe`

SHA-256: `341ae7a9619bbf54b1d4207c468055ff540a2ff20b9295f4b9b1109bd6e6d0fa`.
[Build evidence](engine-build-verification.json) váže neměnný zdrojový snímek,
lokální pinned wheels, kontrolu nainstalovaných bytů a 265 payload souborů.
Nové moduly katalogu/profilů jsou ve frozen TOC. Build proběhl v owned Windows
Job Object a jeho cleanup je ověřený. Jde o **unsigned engine-only kandidáta**,
nikoli nový celý desktop portable, package/SBOM acceptance nebo instalaci.

První freeze byl po review zastaven a není přijatým kandidátem:
[záznam a ověřené ukončení vlastních procesů](superseded-build.json).
Po opravě se sestavilo do jiného adresáře. Sandbox pytest narazil na WinError 5
v task temp; cílené testy prošly s autorizovanou eskalací. Dlouhý pre-existing
checkout self-scan byl v agentní sadě ukončen a výslovně vyřazen; není PASS.

Reprodukční příkazy a kontroly jsou v `build_engine_final.py`,
`verify_catalogs.py`, `verify_scans.py` a agentních handoffech.

## Aktualizace a další brány

Aktualizace externího PHP pinu samotná je pro reprodukovanou chybu **no-go**:
stále by vyhrála místní built-in implementace. Konkrétní alternativou je dodaný
WP039 řez. Precedence zůstává kompatibilní a kolize je nyní viditelná v katalogu.
Vybrané upstream Python/Go/.NET aktualizace stále vyžadují vlastní source diff,
paired extraction a kvalifikaci. V této dávce se žádný pin nezměnil.

Následující práce zůstává v aktivním plánu:

1. Native picker/profil UX, zobrazení skutečné implementace a důvodů vynechání;
   vizuální ověření celé app v Light/Dark a dvou velikostech.
2. Per-run ledger pro applicability/detect errors, selected/executed/failed a skip
   reasons; persistovaná identita profilu a engine-switch chování v native UI.
3. WP039 Python cross-file mounts/Django a Node/ATProto subscription/per-route
   auth, širší PHP middleware/auth binding; C27/C38 corpus a maturity gates.
4. Celý desktop package/SBOM a odpovídající source-bound integrace; manuální,
   signing/clean-host a samostatné macOS brány se tímto neposouvají.

Závislosti WP006 manual a WP031/WP032/WP035/WP042 nebyly prohlášeny za dokončené.
Aktivní lease této dávky jsou po ověření uvolněné; žádný implementační subagent
ani task-owned scan/build nezůstává běžet.
