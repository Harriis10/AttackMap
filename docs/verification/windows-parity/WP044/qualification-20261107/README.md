# WP044 — kvalifikace fyzického fleet16 corpus, 7. 11. 2026

Stav úkolu: **IN_PROGRESS**. Dokončený je tento omezený testovací řez;
reprezentativní produkční fleet, nativní GUI mapování a celé WP044 nejsou přijaté.
[Hashově vázaný souhrn](verification.json) odkazuje na skutečné výstupy a review.

## Co bylo ověřeno

Nový fyzický corpus má 16 repozitářů, duplicitní basenames, explicitní
namespaces/porty/protokoly, více služeb, knihovnu, orphan a externí komponenty.
Před finálními běhy byl uložen v2 oracle
`8b63fb1a97184459015969299330058565435177f6e611c7f28e1d4bd609a08b`.

| Brána | Skutečný výsledek |
| --- | --- |
| Source API serial + workers2 | 4 cílené testy PASS; 2 × 16 skutečných child analýz |
| Source CLI + frozen CLI workers2 | Oba PASS; dalších 2 × 16 child analýz, natural exit0 / Job0 |
| Přesný oracle | 16 HTTP linků: 2 proxy positives, 14 candidates; 18 podkladových HTTP hran |
| Další vztahy | 1 směrovaný Kafka `declared` pár a 1 nesměrovaný datastore `declared` pár |
| Source/frozen graf | Celý graf a cross-repo links shodné po ověřené změně výstupních cest |
| Headless produkční GraphExplorer.Core | 2 běhy, každý 11 projekcí/exportů/round-tripů a 2 skutečné SVG exporty |
| Verifier negative gates | Všech 6 mutací odmítnuto; správné actual raw výstupy přijaty |
| Skutečný řízený source fault | 1 failed orphan, 15 platných sourozenců, exit1 očekávaný, natural Job0, parent nezveřejněn |

Native assertion count 1120 na běh není počet nezávislých testů. Překrývající
se kontroly a počty child analýz se nesčítají s počtem pytest případů.
Zdrojové i zabalené výstupy skutečně četl produkční reader/projection/exporter;
prezentační agregace zachovaly podkladové IDs, směry, resolution a evidence.

## Hranice a zachované neúspěchy

- Corpus je syntetický. Deklarované Kafka/datastore vztahy nedokazují běžící
  služby, doručování zpráv ani síťovou konektivitu.
- Headless konzument nedokládá pixely GUI, klávesnici, Narrator ani WP043 rendering.
  Simulované partial/failed projekce jsou oddělené od jediného skutečného fault běhu.
- Fault běžel pouze source cestou. Audit pluginu je spolupracující instrumentace;
  nejde o OS sandbox nebo nezávislý důkaz celé PID ancestry. Přesný název výjimky
  je odvozený z připnutého pluginu; zachované stderr jej neobsahuje. Původní runner
  byl archivován po běhu před offline úpravami, nikoli hashově připnut před startem.
- První JSON Kubernetes fixture, nepodložené frontend9443 očekávání a původní
  singleton-provenance předpoklad selhaly. Raw výsledky a původní oracle zůstaly
  zachované. V2 ponechává9443 jako explicitní negativní případ; nezaměňuje backend
  port8443 s prokázaným frontend listen portem. Nejde o relabeling quality eval.
- Raw report/provenance/SARIF byte parita se neprohlašuje. Důkazy platí pro uvedené
  source/engine hashe, nikoli automaticky pro pozdější změny zdrojů nebo release.

Úplné podklady jsou v `artifacts/wp044-qualification-20261107/` včetně nezávislých
CLI, native a fault review. Během této kvalifikace se nezměnil produkční kód,
frozen engine ani 134 připnutých nativních vstupů WP005; uživatelské okno se
neovládalo. Windows M3 a odstranění Windows C26 zůstávají zachovány.
