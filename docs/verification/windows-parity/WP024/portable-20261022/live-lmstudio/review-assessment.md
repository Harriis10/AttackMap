# Kontrola připomínek modelu

CyberStag skutečně dokončil samostatnou poradní revizi reportu a testovacích
důkazů: HTTP 200, `completed`, odpověď
`resp_19e249d8ccf67862686dfbeb18148c408e0d73e076fee809`, 223,453 s.
Výstup je zachován beze změn v
[report-quality-review-readable/output.md](report-quality-review-readable/output.md).
Model vykázal 44 468 vstupních a 3 176 výstupních tokenů.

Toto je následná deterministická kontrola některých jeho tvrzení, nikoli další
AI požadavek. Nebyly podle nich automaticky měněny nálezy, skórování ani kód.

| Připomínka / tvrzení modelu | Kontrola proti zachovaným datům |
| --- | --- |
| Zdrojové odkazy a tvrzení vyžadují ověřené snapshoty. | Metadata skutečně uvádějí sedm unresolved odkazů na soubory/řádky a `claim_support=not_assessed`. Platnost ID nálezu sama neprokazuje pravdivost jeho tvrzení. |
| Nepozorovaný auth guard neprokazuje úplnou absenci autentizace. | Relevantní připomínka pro následnou zdrojovou validaci. Tento běh neověřoval globální middleware ani skutečnou zneužitelnost; nejde o potvrzení konkrétního auth bypassu. |
| Všechna zjištění mají score 100. | Nesprávně. Distribuce všech 18 nálezů: 100×4, 75×4, 50×4, 37×4, 10×1, 7×1. Tato připomínka není podklad pro změnu skórování. |
| Path-traversal ID `8aaf120...`. | Nepřesný přepis. Skutečné ID je `8aaf129af4503df9`. Ostatní zkrácené reference vyžadují navázání na skutečné ID. |
| AI narativ dodává konkrétní dotazy `method IN (...) AND route IN (...)`. | Tato syntaxe není v dodaném `defensive-review-llm.md`. Pochvala konkrétních dotazů je pro tento artefakt nepodložená. |
| Explicitně zapsaná taint chain umožňuje okamžitou validaci. | Zapsaná cesta pomáhá při review; její pravdivost však tento test nepotvrdil. Sám model současně upozorňuje na chybějící snapshoty. |

Doplňující lokální kontrola původních nálezů zjistila, že agregát hard-coded
secrets `b0d5f3e1c33ca417` zahrnuje také lokace v `*.spec.ts` a různé druhy
literálů. Je potřeba rozlišit testovací zdroje, veřejné hodnoty a skutečné
credential materiály. Samotná agregovaná klasifikace high/high toto rozlišení
neprokazuje. Zdrojové cesty upload → snippet/deserialization je rovněž nutné
ověřit proti skutečným call paths, než se přijme silnější tvrzení narativu.

Výsledek spojení a provedeného scanu je doložen samostatně. Poradní revize
obsahu včetně jejích nepřesností není release acceptance ani automatické
ověření nálezů. Původní rozsáhlý pokus skončil timeoutem klienta a není započten
mezi tři skutečně dokončené a zachované odpovědi modelu.
