# WP024 — přijatý unsigned preflight, 22. 10. 2026

**Integrátor přijímá WP024 jako DONE v jeho unsigned-preflight rozsahu.**
Aktivní DoD, závislost WP001 a nezávislé
[acceptance review](resume-review/installed-acceptance-review.md) jsou splněné.
Podpis, release, clean-host a celá C29 acceptance jsou samostatné; WP025,
WP017, WP023 ani jejich závislosti se tím automaticky neuzavírají.

## Identita a ověření

Kandidát `dev-20261022113134-4de136c6`, manifest SHA256
`d62a6c7f432cfab616cafda64978eb4cfc7a5b0e2167151737c9df848f4af087`.
[Packaging summary](packaging/summary.json) obsahuje přesné cesty a ZIP/lock/SBOM
hashe. Nový [freeze](freeze/), [native build](native-build/native-build.json),
[skutečný frozen scan/compare](runtime/engine-verification.json) a RequiredBundled
balíček svazují source/toolchain/analyzátory/payload. SBOM má 56 známých Python
dependencies a explicitní unsigned status; ověřeny bytes 15 pinned analyzer wheels.

Nezávislý audit přepočetl 217 current release inputs, dva další native vstupy,
821 stage entries, 822 instalovaných souborů a 19 generation artefaktů.
[Packaging guards](packaging-guards/README.md) prokázaly refusal chybějícího/stale
enginu a sentinel tamper; také syntetický install/repeat/upgrade/rollback/tamper/
uninstall, PS5.1 a `.cmd` success/failure exit propagation. Aktuální unchanged-source
native checkpoint obsahuje 46 `EngineLaunchSpec.Tests` PASS. Syntetický installer
test není produkční clean-host/upgrade campaign.

## Skutečná instalace a nativní sken

[Úspěšný pokus](installed-profilefix01/summary.json) použil skutečný
`Install-AttackMap.cmd` a Windows PowerShell 5.1, nový root
`.tmp/wp024-astra-installed-20261022-02`. Installer child PATH obsahoval jen
Windows/System32/WindowsPowerShell, native child PATH jen Windows/System32;
samostatný Python ani pwsh nebyly na child PATH.

Celá nativní aplikace z instalovaného adresáře dokončila bundled-engine sken
`C:\tmp\juice-shop` s AI/CVE vypnutými. Výstupy jsou mimo repo.
Run `052035254ea84072a7f679fb16872a04`: 18 findings a 19 ověřených artefaktů;
report SHA256 `919619d6ffe6a8ccdf153f83d9b127ae06aa46c1b68351ee770565edbeb5b8c9`
je totožný s přímým fresh-engine reportem. Atomic current-generation pointer,
manifest a zobrazený report/run/hash odpovídají.

Installer exit 0 za 36,79 s; native app exit 0 za 61,89 s. Oba owned Windows Jobs
uklizené, bez timeoutu. Původní stage i installed payload beze změny. FINISHED,
starší retained balíčky a osobní nastavení zůstaly zachované.

## Zachovaná chyba a meze důkazu

První [neúspěšný pokus](installed/failure.json) je zachovaný se svou instalací.
Chybně rozložený testovací profil vedl k prázdnému Windows known-folder a relativní
action request cestě; guard ji odmítl před spuštěním enginu. Skutečná
[.NET 8 sonda](profile-diagnosis/README.md) příčinu prokázala. Runner nyní vytváří
standardní `profile/AppData/Local` a `profile/AppData/Roaming`; produktové binárky
ani guard se neměnily. [Windows API regresní test](../../WP017/astra-review-20261022/profile-fix/README.md)
byl před opravou RED; následná suite má 30 PASS + 25 PASS subtestů.

QA journey vyžaduje explicitní cestu k instalovanému bundled enginu. Neprokazuje
automatickou volbu při normálním startupu nebo osobní settings/relaunch.
Běh proběhl na vývojovém Windows hostu. Lidské GUI/OS/accessibility, podpis,
další čistý host a produkční instalační lifecycle zůstávají oddělené brány.
