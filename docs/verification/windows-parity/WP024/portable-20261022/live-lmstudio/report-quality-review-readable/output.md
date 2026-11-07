### **Ocenění QA revize AttackMap Reportu**

**Rozsah (Scope):**
Revize se týká pouze dodaných sekcí: `architecture_summary`, `attack_surface_summary`, `defensive_review` (včetně findings a AI narativu) a `test_evidence`. Vyloučeny jsou surové inventáře, chybějící kanonické klíče a zdrojové kódy (snapshots), které nebyly v rámci promptu poskytnuty.

---

### **Silné stránky (Strengths)**
*   **Struktura Taint Chainů:** Zjištění jako `8aaf129af4503df9` (Path Traversal) a `ab9895debc4fcf01` (Eval RCE) jsou vynikající díky explicitnímu mapování cesty: *Source $\to$ Propagation $\to$ Sink*. To umožňuje okamžitou validaci bez nutnosti manuálního trasování.
*   **MITRE ATT&CK Mapování:** Každé zjištění obsahuje relevantní techniky a taktiky, což transformuje surová data na strukturovaný inteligenční produkt pro SOC/IR týmy.
*   **Detekční pravidla (Detection Opportunities):** AI narativ nekončí pouze u identifikace chyb, ale nabízí konkrétní logické dotazy (např. `method IN (...) AND route IN (...)`) pro SIEM/WAF implementaci.
*   **Diferenciace důvěry:** Správné rozlišení mezi „static_observed“ (zjištěno z kódu) a „inferred_protocol“ (hypotéza na základě patternu).

---

### **Problémy v kvalitě reportu (Concrete report-quality issues)**

#### **1. [Kritická] Absence důkazu pro negativní tvrzení (Negative Evidence Fallacy)**
*   **ID:** `d61e734cd10b1dcb` (Admin auth bypass), `3d087c2f6f6af934` (Unauth state change).
*   **Problém:** Zjištění spoléhají výhradně na *absenci* signálů (`no auth signals observed`). Bez přístupu k globální konfiguraci routeru nebo middleware v `server.ts` nelze konstatovat, že ochrana neexistuje (může být definována v jiném souboru/modulu).
*   **Důsledek:** Report prezentuje hypotézu jako faktickou zranitelnost ("Admin routes **are** reachable").

#### **2. [Vysoká] Unverified Taint Chains (Chybějící snapshots)**
*   **ID:** `8aaf120...` (Path Traversal), `f91e7d54...` (Deserialization).
*   **Problém:** Report uvádí kritické sinky (`fs.writeFile`, `yaml.load`), ale v `test_evidence` není potvrzeno, že tyto řádky skutečně existují v poskytnutém kontextu (snapshots chybí). Revizní engine sám přiznal: `source_reference_validity: unvalidated`.
*   **Důsledek:** Auditovatel nemůže potvrdit validitu zranitelnosti bez externího zdroje.

#### **3. [Střední] Kontradikce v inventáři aktiv (Asset Inventory Fragmentation)**
*   **ID:** `defensive_review -> Asset Inventory` vs `findings: b0d5f3e1...`.
*   **Problém:** Sekce *Asset Inventory* uvádí pouze několik klíčových cest, ale zjištění o hardcoded secrets (`b0d5f3e1`) identifikuje stovky souborů v `.github/workflows` a `data/static/users.yml`, které jsou v hlavním inventáři zcela opomenuty.
*   **Důsledek:** Neúplný obraz kritických dat (Crown Jewels) v reportu.

#### **4. [Nízká] Nejasná váha skóre vs. důvěry (Score/Confidence Mismatch)**
*   **ID:** Všechna zjištění s `score: 100`.
*   **Problém:** Agregované skóre `100` u všech zjištění (i pro `path-traversal` o střední důvěře a `hardcoded-secret` o vysoké) maskuje skutečnou prioritu oprav. Skóre neodráží rizikovou hodnotu kovu (impact), ale pouze shodu s pravidlem.

---

### **Doporučená oprava (Recommended corrections)**

1.  **Refaktoring negativních zjištění:** Místo *"Admin routes are reachable without auth"* použít *"No authentication middleware observed at route definition in provided scope; verify global interceptors."*
2.  **Inkluze Code Snippets:** Do artefaktu reportu musí být vložen `selected_snapshots` obsahující pouze řádky relevantní pro identified sinks (`eval`, `yaml.load`, `fs.writeFile`).
3.  **Harmonizace inventáře:** Asset Inventory musí automaticky agregovat všechny `entity_id` a `locations_file_line` ze všech findings, nejen ty s nejvyšší prioritou.
4.  **Re-weighting skóre:** Zavést pro pole `score` metriku založenou na `severity * confidence`. Tím se zřidí Findings, kde je kontext pouze inferenční.

---

### **Omezení verifikace (Verification limitations)**
*   **Žádný přístup k runtime:** Nelze potvrdit exploatabilitu (např. zda WAF blokuje `../` dříve, než se dostane do `fs.writeFile`).
*   **Neznámá infrastruktura:** Nessoudím role GITHUB_TOKEN v rámci organizace; mohu posoudit pouze to, co je v `.github/workflows/ci.yml`.
*   **Unresolved references:** Všechny souborové cesty (`routes/...`) jsou v tomto review považovány za **hypotetické**, dokud nebudou dodány jako součást snapshot artefaktu.