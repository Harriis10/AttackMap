# WP022 — správná verze SARIF, 7. 11. 2026

Konkrétní chyba metadata je **opravená a ověřená**. Celé WP022 zůstává
**IMPLEMENTED**, nikoli DONE: závislost WP013 a zbývající export workflow mají
vlastní přijetí. [Záznam skutečného source/frozen ověření](verification.json).

SARIF nyní používá `attackmap.__version__`, stejnou autoritu jako CLI.
Chybějící nebo zastaralá instalační metadata již nevracejí `0.0.0-dev` či jinou
verzi než běžící kód. Nejde o tvrzení, že byla do balíčku přidána všechna
distribuční metadata; balicí spec ani scoring se neměnily.

- Dva cílené testy nejprve skutečně reprodukovaly obě odchylky. Po opravě
  prošlo 23 testů včetně existujících SARIF/schema/identity kontrol.
- Skutečné source i fresh-frozen CLI hlásily `attackmap 1.5.1` a skutečně
  vygenerované SARIF exporty měly `driver.version=1.5.1`.
- Sdílená fyzická config fixture vytvořila nález i SARIF results. Raw SARIF
  soubory byly bajtově totožné, SHA-256
  `3a154cae58cf4e0811b14b97f35bb92bf7c4b7e386b9d09db299021e6b394caa`.
  Nebyly přepisovány ani normalizovány. Všechny čtyři version/scan procesy
  skončily přirozeně s exit0 a Job0.

Metadata-only frozen checkpoint má engine SHA-256
`562d6b7a02836607eec0a203d7f08198d7892aa9d58bbd866317b3847b8ad5d5`.
Následný společný kandidát s opravou citací a opakovaným skutečným version/SARIF
gate je popsán v [protokolu dávky WP017](../../WP017/citation-label-20261107/README.md).

Staré exporty s `0.0.0-dev`, failed setup/test pokusy a původní uživatelský
engine zůstávají zachované. Kandidáti nebyli nasazeni do otevřené aplikace.
Kontroly pickerů, clipboard/reveal, AI artifact exportu a celého WP022 se tím
nenahrazují; žádný provider ani GUI nebyly při této kvalifikaci spouštěny.

Raw důkazy: `artifacts/wp022-metadata-20261107/` a
`artifacts/wp022-sarif-version-20261107/`. Důkazy platí pro uvedené snapshoty
a jejich kontrolní součty, nikoli automaticky pro pozdější změny zdrojů.
