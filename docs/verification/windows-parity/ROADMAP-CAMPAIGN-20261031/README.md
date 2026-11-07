# Kampaň core kvality — WP030, WP032 a WP033 — 2026-10-31

Tato dávka navazuje na [předchozí roadmapový řez](../ROADMAP-NEXT-20261031/README.md).
Uzavírá tři konkrétní, auditovatelné funkční řezy. Neuzavírá celé work
packages, Windows rendering, produktový balíček ani release. Všechny změny
zůstávají v existujícím dirty checkoutu.

## Uzavřené omezené řezy

### WP030 — zmrazený provenance-backed eval increment

Nový oddělený corpus increment má 27 očekávání nad třemi identitami:
16 positive, 10 negative a jeden explicitně synthetic clean repository.
Čtrnáct očekávání pochází z přesných Git blobů DVWA (GPL-3.0-or-later) a
dvanáct z Juice Shopu (MIT); každá kopie má revision URL, SHA-256, Git blob
ID, licenci, source anchor a lineage evidence. Původní v0.2.0 corpus se 46
labely nebyl změněn.

Schema/hash/anchor/inventory/lineage/duplicate/leakage audit je fail-closed a
freeze vznikl před prvním score. Skutečný offline `attackmap evaluate` nad
incrementem skončil 0 TP / 0 FP / 16 FN: všech deset explicitních negativů
zůstalo respektováno a clean repo prošlo, ale žádný positive label nebyl
zachycen. To je užitečný, neměněný coverage gap pro WP031, nikoli 100% precision
nebo maturity claim. Neproběhl detector tuning, relabeling po score, provider
call ani nezávislý human review.

[Corpus, audit, raw reports a omezení](../WP030/agent-20261031/README.md)

### WP032 — ne-HTTP(S) contract link fail-closed

`grpc://`, `kafka://`, `wss://` a `ftp://` URL již nemohou vytvořit observed
HTTP kontrakt ani `observed_via_proxy` link. Pokud není dřívější přesnější
`scheme_mismatch`, zůstávají explicitním `candidate` s
`resolution_reason=unsupported_protocol`. HTTP/HTTPS matching a proxy
semantika zůstaly zachovány.

Nový physical three-service config-only corpus ověřil protocol/namespace/
multi-backend/case rule spolu s evidence a score references: 19 linků,
20 graph edges, 30 exact evidence refs a dva snapshot-qualified
finding→score refs. Není to runtime ani produkční fleet scan.

[Kvalifikace, RED reprodukce a JUnit](../WP032/agent-20261031/README.md)

### WP033 — mutation campaign a snapshot-excerpt binding

Seedovaná source-level kampaň pro 100 nezávislých sekvencí provedla 300
mutací, 600 full≡incremental porovnání, 1 200 skutečných scanů a 200
non-vacuous warm checkpointů s nulovým extractor count. Porovnává findings,
provenance a coverage; devět mutation families zahrnuje rename/delete,
dependency/config/analyzer identity a čtyři corruption režimy. Upgrade
exercise mění disposable source-byte identity a deklarovanou producer version,
neinstaluje nový runtime plugin.

Kampaň odkryla transientní false snapshot binding u excerptů. Oprava používá
při aktivním exact-root indexu jen captured raw bytes; chybějící bytes nikdy
nefall backují do live tree. Manifest smí přidat `captured_under_snapshot_id`
jen při shodě raw path/hash. Mismatch nebo legacy absence raw hash zůstane
unbound a report označí `unverified`/`incomplete`. Nezávislé review nenašlo
blocker.

[Mutation campaign](../WP033/agent-20261031/README.md) ·
[excerpt fix](../WP033/agent-excerpt-20261031/README.md)

## Společné ověření

Finální zdrojová sada kombinuje evaluator, corpus integrity, contracts/fleet,
citations/artifact manifest, snapshot/cache/CLI a všechny nové WP033 scénáře:

- **439 PASS, 0 failures, 0 errors, 0 skipped, 129.05 s**.
- [JUnit XML](../../../../artifacts/roadmap-campaign-20261031/root-final-source-suite/results.xml)
- [Strojové shrnutí](../../../../artifacts/roadmap-campaign-20261031/completion.json)
- Provider calls: **0**.

První non-elevated attempts narazily před užitečným během na Windows ACL u
pytest temporary-directory a nejsou započítané. Finální run použil nový
izolovaný Windows temp path. Jeho JUnit je jediný společný výsledek této dávky.

## Otevřené brány

- **WP030 / C27:** stále chybí nezávislý human review, production diversity a
  30 repos / 300 positives / 300 negatives / 10 clean, včetně mature-family
  thresholdů. Nové training-app slices nejsou production acceptance.
- **WP032 / C28:** zbývající protocol/namespace/multi-backend surface,
  reprezentativní runtime fleet, native mapping a whole-task acceptance jsou
  otevřené.
- **WP033 / C33/C34:** native round-trip, 20-repeat performance campaign,
  skutečný plugin-install/upgrade scenario, úplná snapshot enumerace a
  package/release gates nejsou hotové.
- **WP043:** globální text-disappearance/rendering acceptance je stále
  **FAILED**; V01–V03 zůstávají blocked. Tato dávka ji neměnila.

Leases této dávky jsou uvolněné. WP030, WP032 a WP033 zůstávají
`IN_PROGRESS`; žádný release, ZIP, signing, native/UI ani cross-platform
acceptance z tohoto dokumentu neplyne.
