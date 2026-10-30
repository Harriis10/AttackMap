# Návrh závěrečného statusového zápisu — 22. 10. 2026

Read-only posouzení aktivního TODO/backlogu; canonical dokumenty nebyly změněny.
Nejde o potvrzení dosud nedodaných důkazů. Níže uvedené přechody jsou podmíněné
skutečným doložením a přezkoumáním výsledků integrátorem.

## Doporučené přechody

| Úkol | Současný stav | Po popsané dodávce | Přesná podmínka / zbývající překážka |
| --- | --- | --- | --- |
| WP024 | IN_PROGRESS | VERIFIED → DONE, **unsigned preflight scope** | WP001 je DONE. Nový source-bound freeze a RequiredBundled package musí projít identity/lock/payload/SBOM kontrolou, stale/missing-engine a sentinel-tamper negativními kontrolami, launcher/self-exe guard ověřením a skutečným scanem z izolované instalace bez Pythonu v PATH. Root musí přijmout tento důkaz. Podpis a druhý čistý host patří do WP025; neblokují vlastní unsigned DoD WP024, ale dál blokují release/K5. |
| WP017 | IN_PROGRESS | VERIFIED pro vlastní prokázaný live řez; **ne DONE při otevřeném WP016** | Všech pět režimů skutečně dokončeno native→tento packaged engine→určené LM Studio; identity, HTTP response, usage/budget, export a prohlédnutá správná Reports sekce ověřeny. Odděleně fault výsledky a cleanup. Pro DONE musí být také přijaty WP024 a WP016 v rozsahu závislostí. Samotných pět response artefaktů bez UI review/exportu/fault důkazu nestačí ani na vlastní úplné VERIFIED. |
| WP023 | IN_PROGRESS | **Ponechat IN_PROGRESS** | Broad/native/frozen smokes a jeden package jsou důležitý dokončený řez, ale nestačí na všechny K1–K4 brány, final-candidate scan→inspect→suppress→rescan→compare→export, failure/cancel/repo-switch a fleet/watch journeys ani vizuální matici. Nezaměnit zbývající runtime práci za pouhé MANUAL_PENDING. |

WP017 může přejít do DONE ve stejném závěrečném zápisu pouze tehdy, pokud root
současně nezávisle uzavře odpovídající DoD WP016 a jeho dependency gates.
Pět režimů může dodat část těchto důkazů; neuzavírá je automaticky.
Pokud po dokončení skutečných runtime/fault/export kontrol zůstane u WP017 jen
konkrétní vlastní vizuální review, je poctivější MANUAL_PENDING s názvem této
brány než VERIFIED. Nedokončený režim, fallback nebo timeout znamená IN_PROGRESS.

## Dependencies, které nelze přeskočit

- WP017 → WP016 (IN_PROGRESS), WP024 (IN_PROGRESS). WP016 → WP007 (DONE),
  WP015 (IN_PROGRESS). WP015 → WP005 (MANUAL_PENDING), WP014 (DONE).
  WP015 stále obsahuje explicitní small-window/200% controls, protected credentials,
  keyboard a nepřijatou dřívější visual gate. Nový runtime/viditelné review musí
  prokázat aktuální stav; starou závadu ani starý PASS nepřenášet bez ověření.
- WP023 → WP006/WP008/WP009/WP010 (MANUAL_PENDING), WP011/WP012/WP013/WP022
  (IMPLEMENTED), WP017/WP019/WP020 (IN_PROGRESS). WP019/WP020 dosud neprokazují
  úplný nový final-candidate fleet/watch průchod. WP020 má explicitně nedoložený
  malý viewport; staré čtyři snímky mají všechny skutečných 1584×961.
- WP024 → WP001 (DONE). Jeho izolovaná instalace na vývojovém hostu se nesmí
  přejmenovat na clean-host test ani na celou C29 acceptance.

## Návrh textu do závěrečného execution_scope / souhrnu

**Doložená regrese:** „Python broad 4423 PASS, 7 existujících SKIP a 20 PASS
subtestů; všech 7 scan-limit případů s původními limity PASS. Dva PHP dependency
skips následně samostatně ověřeny se stávajícími freeze závislostmi: 2 PASS.
Broad souhrn se nepřepisuje. WP017 runner delta 39 PASS + 23 subtestů se shodnými
hashi; native 26 consumer suites / 1134 assertions a 31 controlled případů ve
3 suites PASS. Source/frozen/package identity jsou zaznamenány odděleně.
Nový frozen runtime 13/13 PASS dle předaného runtime důkazu; probíhající
50-cycle cancellation campaign má vlastní výsledek až po dokončení.“

**WP024, použít až po skutečném dokončení uvedených důkazů:** „DONE v rozsahu
reprodukovatelného unsigned preflight: nový hash-bound source/toolchain/analyzer
freeze a RequiredBundled package [package ID, engine SHA, manifest SHA, evidence],
payload/SBOM/guards/tamper kontrola a installed bundled scan v izolovaném rootu
bez Pythonu v PATH prošly. Retained package zachován. Podpis, čistý další Windows
host a celý instalační životní cyklus WP025 ani vydání nejsou přijaty.“

**WP017, použít až po skutečném dokončení uvedených důkazů:** „VERIFIED vlastní
live řez: Review, Hunt, Hunt+verify, Remediate a Triage dokončeny přes celý native
klient a package [ID/SHA], LM Studio 127.0.0.1:1234/v1 / cyberstag-security-26b-a4b-v1,
nad C:\tmp\juice-shop. Pro každý režim propojen HTTP audit, dokončená odpověď,
run/generation/manifest, budget/usage nebo unknown, hash-bound export a skutečně
prohlédnutá správná Reports sekce; fault a process cleanup důkazy odděleně.
DONE čeká na přijetí WP016 a WP024 dependency gates; žádný remote fallback.“

**WP023:** „IN_PROGRESS: broad Python/native checkpoint, dopadové delty a nový
source-bound frozen/package runtime řez doloženy. Full acceptance čeká na zbývající
K2/K4 final-candidate journeys, vizuální matici a otevřené dependency gates.
Pět live AI režimů a static scan nenahrazují suppression/history/export ani
fleet/watch/repo-switch průchody. K5/release nejsou uzavřené.“

Hranaté placeholdery výše musí root nahradit skutečnými identitami a odkazy;
nepřenášet podmíněné věty do canonical jako uskutečněné výsledky.

## Zachované otevřené brány

Z původních sedmi pytest skips zůstává pět případů neprovedených: dva Windows
chmod, jeden Windows symlink, opt-in cancellation stress a opt-in authenticated
Claude CLI. Nezapínat remote CLI ani nenahrazovat Windows permission semantics
fixture PASS. Samostatné frozen cancellation cycles nejsou tentýž opt-in test.

WP026: OS appearance/dialogs, clipboard/reveal, keyboard/focus/Escape, Narrator,
kontrast, 200% text/reduced motion a skutečně prohlédnutá referenční matice.
WP025: podpis, druhý čistý host, instalace/upgrade/rollback/uninstall/MotW.
WP027: lidé a skutečná délka bety. WP028/029/038: Mac/CI a Mac acceptance.
WP037: release dossier a supported scope. Žádný z těchto stavů ani celý K5/K6/K7
se tímto balíkem automaticky nemění. Windows M3 a odstranění Windows C26 zachovat.

## Autoritativní podklad

- `docs/windows-parity-todo.md`: společná dependency/status pravidla, WP015–017,
  WP020/WP022–027.
- `docs/windows-parity-backlog.json`: aktuální status a depends_on týchž úkolů.
- `docs/roadmap-windows-parity-2026-10-20.md`: K2–K7 a pravidla uzavírání.
- Místní `summary.json`, `php-dependency-followup/followup-summary.json`,
  WP017 `astra-review-20261022/focused-result.json`, WP023 native README;
  WP024 fresh freeze checkpoint rozlišuje build identity od runtime acceptance.
