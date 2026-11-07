# WP032 — service identity a evidence links, 7. 11. 2026

Stav: **DONE** — implementace, source i fresh-frozen kvalifikace a nezávislé
přijetí dokončené. [Strojově ověřený závěr](verification.json) váže aktuální
zdroje, build, runtime výsledky a review pomocí SHA-256.

Navazující průběžný pokyn uživatele autorizoval další dostupný roadmapový úkol.
WP032 má jedinou závislost WP002 (DONE). Výchozí commit je
`9b8e12d40d8d19ed5e9d07b7ec4d04b643513796`; současná práce zachovává celý
uzavřený WP018 checkpoint a jeho hashově ověřené důkazy.

## Implementace

- `contracts.py`: explicitní `namespace/service` a přesný normalizovaný root;
  scoped Service/Ingress vazby, konzervativní kandidáti a persistentní negativní
  fakta nepodporovaných nebo konfliktních protokolů. Známý namespace nelze obejít
  pouhou shodou názvu repozitáře. Výslovný operator binding zůstává podporovaný.
- `config_scanner.py`: dvě fáze Service/Ingress extrakce, přesná ownership
  pravidla, stejný explicitní namespace, skutečný Service a odpovídající
  backend port podle čísla nebo přesného jména. Neplatná větev zneplatní celý
  host. ExternalName redirect není kvalifikovaný repo backend.
- `scan_service.py`: zachování scoped i negativních faktů, vlastního původu
  programatických operator deklarací a všech negativních konfiguračních zdrojů
  při merge i konfliktovém fallbacku.
- `fleet.py` a `fleet_architecture.py`: pole `server_namespace`,
  `server_service_name`, `server_port`, `server_protocol` a typované
  `declaration_refs`. Backend fakta se nezaměňují s klientským `destination`
  nebo `scheme`; backend HTTPS neprokazuje frontend TLS.

Původ deklarace obsahuje přesný `repository_root`, bezpečný relativní `file`
a případně `line`. Shodné basenames prod/dev repozitářů neumožní převzít cizí
zdroj. Graph evidence mapuje root přímo na captured repository context.
Neznámý řádek zůstává null a samotná atribuce souboru má výslovně
`snapshot_binding: "unverified"`; neprohlašuje se ověření zachycených bytes.

Scope je statický deployment kontrakt. Neodvozuje se výchozí namespace,
`.svc`/cluster-domain DNS alias, TLS z názvu portu ani runtime dosažitelnost.
Legacy unscoped deklarace a explicitní operator bindings mají zachovaný
deklarovaný rozsah. Nový qualified Service/Ingress subset ověřuje porty a
namespace; neimplementuje další Kubernetes controllery nebo síťový discovery.

## Ověření

| Brána | Skutečný výsledek |
| --- | --- |
| Společná finální source sada | **609 PASS**, 0 failures/errors/skips, 107,83 s |
| Source referenční běhy | **9/9 PASS**: 6 formát/worker případů a 3 negativní varianty |
| Native source consumer | **4/4 PASS** nad skutečnými canonical grafy |
| Standardní fresh freeze02 | PASS, 15 připnutých analyzérů, 265 payload souborů |
| Source Automatic Juice Shop + tiny | PASS, 2/2, 600 s nevyčerpáno, bez analyzer errors, natural Job0 |
| Frozen referenční běhy | **9/9 PASS**, tentýž fyzický oracle a negativní varianty |
| Native frozen consumer | **4/4 PASS** nad skutečnými canonical grafy |
| Frozen Automatic Juice Shop + tiny | PASS, 2/2, 600 s nevyčerpáno, bez analyzer errors, natural Job0 |
| Nezávislé přijetí + závěrečný collector | **DONE**, žádné blokující nálezy; 284 aktuálních release inputs a payload znovu ověřeny |

Počty dílčích 155/232 testů a verifier gates jsou překrývající se řezy společné
sady; nepřičítají se k 609. Nativní assertion counts nejsou Python test cases.

Fyzický třírepozitářový oracle je v
`tests/fixtures/wp032_namespace_reference`: klient a dva stejně pojmenované
`prod/auth-api` a `dev/auth-api`. Skutečné JavaScript fetch calls a Flask routes
se skenují běžnými analyzéry; normalizované observations se nevkládají.
Baseline má 16 přesně očekávaných linků, 2 scoped proxy positives a 14
candidates. Negativní varianty pokrývají GRPC, konfliktní protokoly a nesoulad
Ingress port9999 / Service port8080. Každý link, obě proxy legs, endpoint root,
metadata, observation ID a finding→score/evidence reference mají přesný gate.

`tools/verify_wp032_closeout.py` kvalifikuje skutečné source/frozen CLI
all/json/markdown při workers 1/2. Headless native-reader v task artifacts
používá produkční GraphExplorer.Core, collapse/expand/filter/export a canonical
round-trip; neupravuje vstupní fixture, aby odpovídala projekčním agregacím.
Ověřuje podkladové edge IDs a uchování kandidátů, metadata i evidence.

Source i frozen Juice Shop běhy používají Automatic analyzéry a skutečné nezměněné zdroje.
Při 1 467 totožných source-file digestech jsou findings, attack paths a
suppressed findings přesně shodné s předchozím WP018 během, bez normalizace.
Původ kódu se posuzuje odděleně. Dvě nadlimitní média se standardně vynechají;
legacy agregovaný počet souborů není unikátní pokrytí.

Devět source/frozen dvojic má přesně shodné core grafy, evidence, finding/score
vazby a deterministické výstupy. Celé raw reporty nejsou totožné: frozen ledger
poctivě uvádí nedostupné fyzické `.py` source bytes a odlišný odvozený
implementation digest. Tyto rozdíly byly jednotlivě ověřeny proti zachycenému
zdroji a build origins; provenance se nepřepisovala. Pro srovnání parent grafů
se pouze ověřený output adresář projektuje na přesný child slug; modelová fakta
ani scoring se nenormalizují.

Samostatný otevřený problém **WP022**: SARIF `tool.driver.version` má ve source
`1.5.1`, ve frozen `0.0.0-dev`, protože distribution metadata nejsou přítomná;
obě skutečná CLI hlásí `1.5.1`. Zbývající SARIF obsah je shodný. SARIF byte
parita ani dokončení WP022 se neprohlašují. Raw artefakty zůstávají zachované.

## Původ a zachovaná historie

Finální engine:
`.tmp/wp032-closeout-freeze-20261107-02/dist/attackmap/attackmap.exe`

SHA-256:
`e5de74f18990a0b4d7b37740f219cbc6c9bad03265031d2b8fa4f237ff4bff4c`

Standardní proof, current-source gate a installed-wheel attestation jsou
v `.tmp/wp032-closeout-freeze-20261107-02/`. Root i nezávislý reviewer znovu
přepočítali všech 265 payload souborů, 44 100 868 bytes, 128 core origins a
284 release inputs. Celá evidence je v `artifacts/wp032-closeout-20261107/`.
Finální census nenašel žádný odpovídající WP032 Python/engine/dotnet proces.

První freeze01 byl při svém vzniku platný checkpoint; pozdější prokázaná
backend port chyba jej vyřadila z finálního přijetí. Je zachován spolu
s `build-command01/disposition.json`. Původní skutečné RED reprodukce, setup
chyby a staré assertion/oracle opravy jsou uchované a nepřejmenované na PASS.
Retained fixtures nebyly přepisovány; staré testy, které spoléhaly na namespace
leak, nyní výslovně deklarují operator bindings a nepřebírají falešný config původ.

Kubernetes pravidla jsou opřená o primární
[namespace dokumentaci](https://kubernetes.io/docs/concepts/overview/working-with-objects/namespaces/)
a [Ingress kontrakt](https://kubernetes.io/docs/concepts/services-networking/ingress/).
Přijetí statických core facts nenahrazuje runtime konektivitu, C27 kvalitu,
C33 globální snapshot, GUI/rendering nebo release a podporu dalších platforem.
