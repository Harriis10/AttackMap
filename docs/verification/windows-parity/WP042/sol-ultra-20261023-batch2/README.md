# WP042 / WP039 — druhá dávka Sol 6.1 ultra, 23. 10. 2026

Dávka dodává nativní výběr verzovaných profilů, záznam skutečného provedení analyzérů a opravu statické extrakce Node/ATProto. Tři paralelní agenti používali `gpt-6.1-sol` / `ultra`; společný kontrakt, shell a ověření integroval `/root`. **WP042 i WP039 zůstávají IN_PROGRESS.** Toto je ověřený dílčí výsledek, nikoli nový release nebo C27/C38 acceptance.

## Změna chování

- **Nativní profily:** Automatic, Custom a dostupné verzované profily pocházejí ze zvoleného enginu. Uložení zachová kvalifikované jméno i členství. Změna enginu, chybějící profil nebo změněné členství blokují použití zastaralé volby. Změna modulu přejde do Custom. Nativní request 1.5 posílá `analyzer_profile` a prázdný `modules`; starší requesty zachovávají své chování. Neprobíhá instalace ani náhradní výběr.
- **Provedení analyzérů:** report a manifest obsahují shodný `analyzer_run_ledger`. Rozlišuje výběr, applicability, spuštění, úspěch, chybu a důvod přeskočení. Pipeline používá jednu zachycenou volbu a neopakuje `detect()`. Automatic pokrývá registrované kandidáty; explicitní profil pouze dodané kandidáty. Staré pole manifestu `analyzers` nadále znamená vybrané analyzéry, nikoli důkaz provedení.
- **Původ a kolize v UI:** aktuální inventář uvádí účinnou implementaci a shadowed plugin. Samostatná část zobrazuje záznam vybraného reportu s identitou generace. Starý report se nespojuje s dnešním inventářem jako důkaz toho, co tehdy běželo.
- **Node/ATProto:** subscriptions používají `WS`; rozpoznává se literální `streamMethod`. `auth: null`, volitelná nebo nevyřešená konfigurace zůstává `unknown`. Neprovázaný middleware nepřisuzuje handleru autentizaci. Nejednoznačné klíče, regex/division syntaxe, nepodporované výrazy a přesažené meze mají konzervativní výsledek. Jde o statickou asociaci, nikoli ověření účinnosti verifieru.

Nezávislé kontroly opravily záměnu runtime jména pluginu za metadata, escapovaný auth klíč a možnost skrýt auth override za nepodporovanou slash syntaxí. Změny precedence, pinů, globálního skórování nebo automatických downloadů nejsou součástí dávky. [Kontrakt profilů](../../../../ecosystem/analyzer-profiles.md), [katalog a ledger](../../../../ecosystem/analyzer-catalog.md), [run kontrakt](../../../../run-contract.md).

## Ověření

| Vrstva | Výsledek a rozsah |
| --- | --- |
| Společné Python testy | **508 PASS, 2 SKIP**, 69,43 s; [JUnit](integrated-tests.xml). Skips jsou chybějící PHP plugin ve zdrojovém prostředí. |
| Adaptéry a fleet předání profilu | **87 PASS**; [JUnit](adapters-tests.xml). Překrývá se se společnou sadou, výsledky se nesčítají. |
| Native console | **597 kontrol** v šesti projektech: 76 + 63 + 121 + 103 + 136 + 98; [výsledky](native-console-summary.json). Modely/settings/protokol, bez vizuálního či provider acceptance. |
| Nový frozen inventář | **15 oficiálních pluginů, 24 kandidátů, 21 účinných analyzérů, 3 shadowed PHP jména**; všechny čtyři profily dostupné. Zdrojové prostředí má 9 built-ins. [Důkazy](catalog-verification.json). |
| Node/ATProto | **68 cílených PASS**, 24 cílených regex PASS; stejné paired vstupy před/po. Nový frozen engine ověřil obě kanonické fixtures. [Handoff](node-handoff.md), [actual frozen after](node-frozen-after.json). |
| Juice Shop | Skutečné source Automatic, frozen Automatic a native frozen Node-profile scany. **266 / 270 / 281 rout**, vždy **18 findings**. [Porovnání](juice-shop-verification.json). |
| Nativní průchod | `native-final4`: skutečný scan, ověřená generace, uložení profilu a invalidace cache; [funkční proof](native-final-run4-proof.json). Nulové AI/provider volání; jeho prázdné PNG nejsou vizuální PASS. |
| Vzhled | `native-final5`: čtyři hlavní Light/Dark záběry a PHP kolize bez nového scanu; [preview proof](native-final-preview5-proof.json). Populovaný ledger pochází z funkčního běhu final4. [Nezávislá vizuální kontrola](native-visual-review.md), [původ každého záběru](capture-origins.json). |

Juice Shop porovnání odstraňuje **jen tři nové, navzájem shodné kopie ledgeru**: `scan.analyzer_run_ledger`, stejnou část pod `defensive_review_json.raw_structured_signals.scan` a pod `review_context_pack.attackmap_review_json.raw_structured_signals.scan`. Zbytek celého parsovaného JSON je shodný s předchozí dávkou; nejde o tvrzení byte-for-byte shody reportu s přidanými poli. Report a manifest mají přesně shodné ledgery, všechny vybrané analyzéry uspěly, bez analyzer errors, překročeného budgetu či AI usage. V nativním Node profilu nad Juice Shopem uspěly čtyři analyzéry a dvě vrstvy byly správně unmatched/skipped.

Nové frozen Node fixtures zachovávají dva oddělené záznamy deklarace a handleru. Subscription změnila konfliktní GET/WS deklarace na WS deklaraci a WS handler. Query `auth: null` již nemá falešný required guard `null`. Není tím vyřešena obecná fúze duplicitních rout ani širší ANY reprezentace externího Node pluginu.

## Sestavení a vizuální důkazy

Engine: `.tmp/wp042-sol-ultra-20261023-batch2/engine-final/dist/attackmap/attackmap.exe`, SHA-256 `487e2f368bcb5323341fc96c9b2a2597cc97d431a4c5377790b60dd9bf7b445c`. Je sestaven z aktuálních Python zdrojů se stávajícími připnutými offline wheels. **121 core originů** odpovídá zachycenému/current source; runtime zabalené třídy míří do nového `_internal`. [Build evidence](engine-build-proof.json), [installed attestation](analyzer-installed-attestation.json), [runtime identity](catalog-runtime-origin-check.json).

Native funkční běh použil `native-final4`; čitelný nový preview použil `.tmp/wp042-sol-ultra-20261023-batch2/native-final5/AttackMap.NativeSpike.exe`, [přesné vstupy a payload hashe](native-final5/build-proof.json). Oba používaly stejný výše uvedený frozen engine. Mapy vstupů final4/final5 se liší pouze QA selektory/čekáním v `MainWindow.AnalyzerSmoke.cs` a volitelnou kontrolou prázdných pixelů v `NativeCaptureProbe.cs`. Produktové modely, views, shell/protokol a Python mají shodné bajty. Nejde o tvrzení, že jediný finální kandidát prošel všemi kroky najednou; nový release-lock/package/SBOM zůstává otevřený.

Přehled a ledger v běžícím skutečném hlavním okně byly zachyceny pomocí WinUI `RenderTargetBitmap`. Jde o klientský obsah aplikace, nikoli OS screenshot nebo lidskou accessibility studii. Nominální okna 1024×700 a 1600×1000 mají zachycený klientský obsah 1008×661 a 1584×961. Menší viewport vyžaduje scroll pro inventář; neviditelné řádky nejsou vizuálně potvrzené samotným horním záběrem. PNG důkazy jsou v [captures](captures/).

Předběžné `native-final-run` a `native-final-run2` dokončily scan a pět záběrů, ale QA selektor `Single` narazil na více prvků vizuálního stromu, včetně interních textových polí WinUI. Oprava vyhledává filtr podle placeholderu a konkrétní řádek `php-laminas`. Původní domněnka, že příčinou byly ponechané vybrané checkboxy, se nepotvrdila. `native-final-run4` dokončil funkční průchod, ale pět PNG mělo pouze nulové RGBA pixely; jako vizuální důkaz je přijat pouze jeho čitelný ledger. `native-final-run5` už prázdný render správně odmítl a celý QA průchod selhal. Následující `native-final-preview5` se stejným binárním final5 dodal šest čitelných PNG bez retry, při discovery/profile/persistence průchodu bez nového scanu. Kombinovaný post-scan capture na final5 zůstává omezením; úspěšný preview jej nezastírá. Starší `native-preview2` používal engine první dávky a není finální runtime důkaz.

## Reprodukce a handoff

`verify_batch.py` obaluje buildy a scany vlastním Windows Job, konečným timeoutem a izolovanými settings. Každá složka příkazu obsahuje přesný `command.json`, logy a `process.json`; cleanup se ověřuje pouze pro vlastní procesový strom. [Finální zdroje, integrita a cleanup](final-verification.json), [strojový handoff](handoff.json).

```powershell
.venv/Scripts/python.exe docs/verification/windows-parity/WP042/sol-ultra-20261023-batch2/verify_batch.py build-engine --label <fresh-engine-label>
.venv/Scripts/python.exe docs/verification/windows-parity/WP042/sol-ultra-20261023-batch2/verify_batch.py build-native --label <fresh-native-label>
.venv/Scripts/python.exe docs/verification/windows-parity/WP042/sol-ultra-20261023-batch2/verify_batch.py native-smoke --label <fresh-run-label> --native <absolute-native-directory> --engine <absolute-engine-exe>
```

Ověřené pytest soubory, výsledky a přesné build/scan příkazy jsou zachyceny v [handoffu](handoff.json); source/frozen scan porovnání řídí `verify_scans.py`. Existující složky důkazů se nepřepisují novým během. Selhání sandbox temp ACL byla vyřešena novým cíleným pytest temp adresářem s povoleným spuštěním, nikoli úpravou fixtures.

## Zbývající brány

WP042 stále vyžaduje finální package/SBOM a návazné whole-task/manual gates. Runtime `content_verified: false` není nahrazen tvrzením o autenticitě Git pinů; cached-wheel attestation a build původ jsou samostatné. Stávající ATProto plugin už WS umí a PHP pluginy jsou shadowed: samotná jejich aktualizace neopraví tyto built-in chyby. No-go a konkrétní lokální alternativa jsou doloženy; žádná nová upstream aktualizace nebyla kvalifikována.

Další inkrement: reprodukovat Python cross-file mount/Django class-view/re_path mezeru proti účinné připnuté implementaci a vybrat odůvodněnou upstream nebo lokální opravu. WP031/WP039 nadále vyžadují reprezentativní FP/FN corpus, labeled review a C27/C38. Generated/dynamic Node/PHP konstrukce, úplná identita duplicitních rout, ruční UX/Narrator/keyboard a macOS důkazy zůstávají otevřené. Windows M3, odstraněné Windows C26 a současný fleet rozsah WP044 se nemění.
