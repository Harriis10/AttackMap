# Pokračování roadmapy — WP033, WP039 a WP044 — 2026-10-31

Tato dávka navazuje na [common-source closeout](../ROADMAP-CLOSEOUT-20261030/README.md).
Uzavírá tři větší, ale záměrně omezené funkční řezy: skutečné reuse frozen
cache, Django `re_path`/class-view route evidence a Rails datastore kandidáty
ve fleet architektuře. Neuzavírá celé work packages, release ani rendering.

## Co bylo dokončeno

### WP033 — frozen cache identity a real warm reuse

- `engine_identity()` ve frozen procesu nyní hashuje code objects vrácené
  aktivním loaderem/PYZ pro každý extractor modul; běžný source režim zachovává
  dosavadní hashe souborů. Chybějící, nečitelný nebo neplatný code object stále
  znamená fail-closed cache miss, nikoli stabilní placeholder.
- Cílené regresní testy kryjí source-less warm reuse, změnu code identity a
  fail-closed loader. Nezávislé review nenašlo blocking defect.
- Skutečný test-only PyInstaller probe (`onedir`, Python 3.13.15,
  PyInstaller 6.22.3) provedl dva oddělené frozen procesy nad `C:/tmp/juice-shop`:
  cold scan měl 658 extractor calls a warm scan přesně 0. Oba měly stejnou
  identity engine, digest výsledku i počet 658 souborů; v bundle nejsou fyzické
  extractor `.py` soubory. [Úplný záznam](../../../../artifacts/roadmap-continuation-20261031/wp033-frozen-probe-data-02/qualification.json).

První oddělený probe build správně selhal před scanningem, protože testovací
PyInstaller příkaz neobsáhl `taint_sinks.yaml`. Je zachován vedle opraveného
sestavení; opravený test-only bundle přidává tento runtime datový soubor. Nejde o
nový produktový engine ani release/package kvalifikaci.

### WP039 — Django mounted regex a ověřené class views

- URLconf walk umí pouze omezené pojmenované regex segmenty a ukotvené
  `re_path` include prefixy. Parametrizovaná regex route se normalizuje až při
  mounted URLconf walku, takže nevznikne falešná nemountovaná cesta.
- Auth evidence pro class view vznikne pouze pro import-backed plain `View`
  nebo přesně `LoginRequiredMixin, View`, bez argumentů `as_view`, custom
  dispatchu, dekorátorů či konfigurace. Vše ostatní zůstává `unknown` a má
  explicitní limitation.
- Pro čerstvou offline instalaci přesného retained pinu reprodukoval starý
  zdroj chybějící regex route; aktuální řez dává jen mounted
  `/api/items/{pk}/`, `auth=required` a přesnou evidence `app/urls.py:3` /
  `app/views.py:3` v in-process i isolated worker režimu.

### WP044 — Rails konfigurace jako statický candidate

- Pouze `config/database.yml` s doslovným PostgreSQL environment blokem,
  explicitním hostem/portem/database/jediným schema a `replica` je extrahován.
  ERB, aliases, defaults, URL overrides, více databází, chybějící nebo
  credential-shaped identity nevytvářejí žádný vztah.
- Dvě shodné konfigurace vytvoří nesměrovaný vztah `shared_datastore` s
  `resolution=candidate`, oboustrannou zdrojovou evidencí a oddělenou ID
  doménou. Environment je pouze kontext konfigurace, nikdy deployment
  identity. Kandidáty se nesmějí sloučit s dřívějšími owner declarations a
  neprokazují runtime konektivitu ani IO.
- Stávající owner-declaration fleet fixture má proti HEAD shodný celý
  architecture dict (canonical SHA-256
  `3cc2c1e279ffd0d0f49c740333f9b743ee2b2496ae8084e1be585e635408d773`).

## Ověření

Agentní focused sady:

- WP033: 58 PASS (incremental, CLI incremental, snapshot a frozen-worker).
- WP039: 148 PASS pro Django behavior; 219 PASS v širší Python/mount/plugin
  sadě včetně skutečné Juice Shop in-process/isolated parity; finální dva
  actual installed-pin případy PASS. Tyto výsledky se překrývají.
- WP044: 197 PASS pro framework/config/fleet kontrakt a 113 PASS pro
  config/fleet/desktop-graph dopad. Tyto sady se také překrývají.

Root spustil společnou aktuální source sadu se všemi dotčenými testy:
**487 PASS, 7 SKIP, 50.15 s**. První sandboxovaný pokus nedokázal dokončit
cleanup pytest `basetemp` kvůli Windows ACL; platný opakovaný běh používal
izolovaný projektový `basetemp` s příslušným oprávněním. Žádný assertion
failure nebyl maskován ani započten z neúplného pokusu.

`git diff --check` pro změněný scoped source/tests/evidence prošel. Provider
calls: **0**. Žádný nový Windows ZIP, native GUI, clean-host, signing ani
release nebyly pro tuto dávku vydány.

## Otevřené brány

- **WP033:** skutečná invalidace mezi dvěma rozdílnými frozen buildy, celá
  mutation matrix, native round-trip a C34 performance jsou stále otevřené.
- **WP039:** další framework/DRF/dynamic coverage, C27/C38 maturity a
  whole-task/manual/release brány zůstávají otevřené.
- **WP044:** producer/consumer, RPC/protobuf/OpenAPI, reprezentativní
  produkční fleet, native/frozen mapping a whole-task acceptance nejsou
  dokončeny.
- **WP043:** globální text-disappearance/rendering acceptance je nadále
  FAILED; tato dávka jej neměnila ani znovu neinterpretovala.

Aktivní lease této dávky jsou uvolněné. Checkout zůstává záměrně dirty,
necommitovaný a starší evidence i ostatní změny byly zachovány.
