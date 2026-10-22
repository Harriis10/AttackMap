# Skutečný test lokálního LM Studia — 22. 10. 2026

Uživatelem vyžádané doplnění testu přenosného balíčku. Původní test
`../native-scan` měl AI vypnutou. Tento důkaz se týká konkrétního distribuovaného
preview native L / frozen B–J, nikoli dokončení roadmapy nebo finálního releasu.

## Co skutečně proběhlo

- LM Studio na `http://127.0.0.1:1234/v1`: HTTP 200 ze seznamu modelů.
- Přibalený `engine/attackmap.exe` provedl produkční `provider_check`:
  `connected`, `selected_model_listed=true`. Samotný tento test ověřuje seznam,
  nikoli generování.
- Samostatná skutečná generace přes `/v1/responses` modelem
  `cyberstag-security-26b-a4b-v1`: HTTP 200, `completed`, text
  `Confirmed: LM_STUDIO_CYBERSTAG_OK.`
- Přenosná native aplikace se svým frozen enginem dokončila reálný scan
  `C:\tmp\juice-shop` v režimu `review`, exit 0 za 141,119 s.
- Generace `00314695009e41ca9a6045245a6b142e`: dokončený scan, dokončené AI
  review, ověřený výsledek načtený v native aplikaci a shodný export review.
- HTTP observer zaznamenal právě jeden skutečný požadavek scanu a jednu
  dokončenou odpověď požadovaného modelu. Pořadí událostí, nonce, HTTP stav,
  ID odpovědi a hashe uloženého textu ověřil offline gate.
- Kontrolní součty všech 21 výstupů artifact manifestu souhlasí. Text modelu
  je přesně obsahem výsledného review, doplněným pouze dvěma produkčními
  upozorněními o rozsahu důkazů a koncovým LF.
- Stejný model dokončil samostatnou kontrolu reportu a testovacích důkazů:
  HTTP 200, `completed`, 223,453 s, 44 468 vstupních / 3 176 výstupních tokenů.
  Celkem jsou zachovány tři dokončené odpovědi: probe, review scanu a poradní
  kontrola kvality. Dřívější velký pokus skončil timeoutem klienta a nepočítá se.

Model při review scanu vykázal 6 310 vstupních a 3 232 výstupních tokenů.
Jde o údaje poskytovatele, ne rezervaci rozpočtu. Identita enginu:
`ee90e44a35d283326fe3821666e71b33fbd0a1eb3aa6844e827d9d4206ea7195`.
Native a engine binárky zůstaly beze změny. Child PATH obsahovala pouze
Windows/System32 a Windows, bez Pythonu; generované reporty jsou mimo cílový
repozitář. Nebyl použit vzdálený AI provider. Osobní settings nebyly načteny.

`lms status`, `lms ps --json` a `lms runtime ls` jsou zachovány v `connection/`.
CLI při kontrole uvádělo vybraný GGUF CUDA runtime
`llama.cpp-win-x86_64-nvidia-cuda-avx2@2.61.0` a načtený CyberStag Q4_K_M.
Samotný tento seznam nenahrazuje provedenou generaci.

## Důkazy a opakování

- [Souhrnná kontrola integrace a HTTP důkazů](evidence-verification.json).
- [Přesná vazba odpovědi modelu na výsledný text](model-output-binding.json).
- [Výsledek spojení a samostatné generace](connection/verification.json).
- [Produkční native průchod](native-scan/parity-smoke.json) a
  [exit a doba procesu](native-scan/process.json).
- [AI review vytvořené scanem](native-scan/defensive-review-llm.md).
- [Rozsah druhého pokusu kontroly reportu](report-quality-review-readable/input-scope.json).
- [Nedokončený původní pokus](report-quality-review/failure.json).
- [Dokončená poradní revize CyberStagem](report-quality-review-readable/output.md).
- [Kontrola pravdivosti některých připomínek modelu](review-assessment.md).
- [Souhrn přesného rozsahu dokončení](summary.json).

Spouštěcí skript je [verify-live.py](verify-live.py). Fáze se spouštějí z rootu
repozitáře pomocí `.venv\Scripts\python.exe -X utf8 <skript> <fáze>`:
`connection`, `scan`, `evidence`, `binding`, `review`, případně `review_readable`,
a `finalize`. Skript vyžaduje nové
výstupní složky; existující důkazy se nepřepisují. Pro další běh je třeba
použít nový caller-owned proof root a upravit přesnou cestu k seed reportu.
Produkční native průchod vytváří také provozní snapshoty akcí v AppData.

## Hranice výsledku

Integrace a dokončená odpověď neprokazují pravdivost AI tvrzení. Reference na
ID vybraných nálezů prošly, ale sedm odkazů na soubory/řádky zůstává
`unresolved`; `claim_support=not_assessed`. Model nedostal ověřené zdrojové
snapshoty těchto řádků. Tyto stavy jsou zachovány v metadatech, nikoli skryty.

První samostatná kontrola dostala všech 18 kompletních nálezů, textové přehledy,
AI review a testovací důkazy: 446 915 B kontextu. Klient po 900 sekundách
neobdržel HTTP odpověď a skončil `TimeoutError`. Tento pokus není PASS.
Jednorázový údaj `idle` z CLI po timeoutu neprokazuje, že se serverové
generování ukončilo; uživatel následně správně upozornil na viditelný progress.
Timeout klienta se nesmí zaměňovat za dokončení nebo ukončení práce LM Studia.

Druhý pokus používá 123 633 B kontextu. Obsahuje všech 18 nálezů se všemi
jejich běžnými poli, důkazy, mitigacemi a všemi dvojicemi soubor/řádek v
původním pořadí. Vynechává interní per-finding `context` a fingerprinty lokací;
toto omezení je výslovně uvedeno v promptu i scope souboru. Zahrnuje celý
architektonický přehled, attack-surface shrnutí, deterministický review text,
attack paths, celé AI review a souhrn testovacích důkazů. Surový scan, inventáře
a další vyjmenované JSON sekce nejsou součástí této kontroly. Scope a hashe
jsou zachovány; nejde o nový scan nebo úplné ověření všech zdrojových tvrzení.

Interní `AI-mode.png` byl skutečně otevřen a zkontrolován, ale je prázdný
RenderTargetBitmap snímek. Nedokládá vizuální správnost okna; programové
navázání review na generaci prošlo nezávisle. Manuální UI, accessibility,
čistý druhý počítač, podpis a ostatní AI režimy tímto nejsou přijaty.
