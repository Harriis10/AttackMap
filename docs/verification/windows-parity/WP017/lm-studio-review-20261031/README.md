# WP017 — živý LM Studio review běh, 31. 10. 2026

## Rozsah

Jeden skutečný CLI review běh nad `C:\tmp\juice-shop`, výhradně přes lokální
OpenAI-compatible endpoint `http://127.0.0.1:1234/v1` a model
`cyberstag-security-26b-a4b-v1`. Nešlo o remote provider, fixture ani fake
client.

Příkaz používal `--llm --llm-provider openai --llm-backend api`, jeden AI call,
`--ai-timeout-seconds 3600` a `--ai-output-tokens 32000`. Výstup byl vytvořen
mimo cílový repozitář v:

`artifacts/lm-studio-live-20261031/run-001/20261031T114233-7ea7279b6f714f35915a0d0e51ac61aa/`

## Skutečný výsledek

- CLI skončilo kódem `0`.
- Deterministická část naskenovala 862 souborů; zapsala canonical report,
  manifest a běžné reporty.
- `defensive-review-llm.meta.json` uvádí `backend: api`, požadovaný model a
  `stop_reason: completed`.
- Reported usage je 6 306 input tokenů a 5 933 output tokenů.
- AI review, jeho metadata i canonical report existují a jejich hashe jsou:

  | Artefakt | SHA-256 |
  | --- | --- |
  | `attackmap-report.json` | `b4248b903b3ca3759dd13ec563bea6f078dba9e321e7b6d4ef35b8a288fe1d2c` |
  | `defensive-review-llm.md` | `44f49c893cbdd4af7e5cd8f49ba5a2221e86d354961c47abb75150c5e53cbf01` |
  | `defensive-review-llm.meta.json` | `e09a423f102a15eadfaf88c195dd470a3093ec86d2a6f4f3df6b14edd22edf00` |
  | `run-manifest.json` | `4c6da6b21b455dd18130b2a0dd56ab37a6c7d80e591d088f74c302a8f795f5f6` |

## Hranice výsledku

Výstup modelu je správně označen jako partial selected-evidence review. Kontrola
referencí potvrzuje platnost povolených identifikátorů, ale neprokazuje claim
support ani source-location validity: selected prompt neobsahoval snapshot
spans a živé zdrojové soubory se k výrobě podpory nepoužily. Modelový prose proto
není důkazem runtime reachability, exploitability ani úplnosti review.

Tento běh prokazuje pouze skutečnou lokální HTTP/API integraci režimu `--llm`
a dokončenou modelovou odpověď. WP017 zůstává `IN_PROGRESS`: Hunt, verify,
remediate, triage, nativní UI/packaged engine, viditelná správná sekce a další
whole-task acceptance brány nejsou tímto jediným během uzavřené.
