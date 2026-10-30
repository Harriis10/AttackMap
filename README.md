<!-- ATTACKMAP_DOC_STATUS: HISTORICAL_REFERENCE -->
> **STARÝ DOKUMENT — pro agenty nerelevantní jako aktuální plán nebo zadání (20. 10. 2026).**
> Práci řídí pouze dokumenty v [aktuálním rozcestníku](docs/README.md). Tento text je historická reference: neobnovovat jeho TODO, priority ani statusy dokončení. Technické podklady a kritéria použít jen v rozsahu potřebném pro aktivní WP úkol a ověřit proti aktuálnímu kódu.

# AttackMap

> [!IMPORTANT]
> **Active development, slow pace.** AttackMap is under active development, but
> progress may be slow until more contributors or co-maintainers join. Help is
> very welcome with the core engine, an analyzer, the macOS app, or the docs —
> see [CONTRIBUTING.md](CONTRIBUTING.md) or open an issue on
> [mlaify/AttackMap](https://github.com/mlaify/AttackMap/issues) to say hello.
> Security reports are still welcome at [security@mlaify.io](mailto:security@mlaify.io).

**Local-first, AI-assisted defensive security analysis for codebases.** AttackMap
reads a repository (or a whole fleet of them), reconstructs the attack surface —
routes, data stores, external calls, auth signals, trust boundaries — traces
request-to-sink data flow, and produces an evidence-grounded, prioritized security
review. Deterministic analysis runs locally. Optional AI sends evidence and may
include source excerpts to the selected provider; optional CVE checks send package
names and versions to OSV. See [privacy disclosures](docs/privacy.md).

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/)

> **Status: beta (v1.5.1).** Core engine + 15 analyzer plugins, installed straight
> from GitHub and validated on real codebases. AttackMap is heuristic by
> design — findings are confidence-tiered evidence, not proof. Current delivery plan:
> [2026–2028 roadmap](docs/roadmap-2026-2028.md) and [implementation tracker](docs/implementation-todo.md).

Full documentation: **[docs.mlaify.io](https://docs.mlaify.io)** ·
architecture & internals: **[wiki](https://github.com/mlaify/AttackMap/wiki)**.

### The macOS app

Prefer a GUI? A native macOS front-end drives this CLI and renders every result
view. Install it with Homebrew (this also installs the CLI), or build it from
source at [mlaify/AttackMap-mac](https://github.com/mlaify/AttackMap-mac):

```bash
brew install --cask mlaify/tap/attackmap-app
```

| Overview | Exploitability |
|---|---|
| [![AttackMap macOS app — overview](https://raw.githubusercontent.com/mlaify/AttackMap/main/docs/screenshots/04-overview.png)](https://docs.mlaify.io/gui/) | [![AttackMap macOS app — exploitability](https://raw.githubusercontent.com/mlaify/AttackMap/main/docs/screenshots/06-exploitability-ranked.png)](https://docs.mlaify.io/gui/) |

*Scanning OWASP Juice Shop. Walkthrough in the [macOS app docs](https://docs.mlaify.io/gui/); source at [mlaify/AttackMap-mac](https://github.com/mlaify/AttackMap-mac).*

### The Windows GUI

A Windows front-end is bundled in this repo (`src/attackmap/ui/`) and ships with
the PyInstaller build. Build it with:

```powershell
installer\build-installer.bat
.\dist\attackmap\attackmap.exe ui
```

Or run from source: `python -m attackmap ui`.


The separate [native Windows development preview](docs/windows-development-package.md)
keeps AI off by default. To try local narration, start LM Studio with
`cyberstag-security-26b-a4b-v1` served at `http://127.0.0.1:1234/v1`. In the native
provider settings, choose `openai`, enter that endpoint and model, enable AI review,
and then scan. Leave the credential empty for this local server; saving provider
settings is not required to try the current configuration. Allow enough output
tokens for both model reasoning and the final review (8,192 was used in the example
below). Other models may behave differently.

In the native preview, **Reports → Open selected run AI review** reads the saved
review for the selected, verified generation without making another provider
request. It shows the supplied model/backend and full scope notice as selectable
text. A run without an AI artifact shows an explicit unavailable state.
Reopening a report beside its matching artifact manifest preserves access to
that saved run's review and exports. A bare legacy JSON still opens without
adjacent-artifact access; an invalid manifest produces an import error.

Local API narrative reviews select whole evidence records within a 14,000-character
evidence JSON budget, preserving finding IDs and locations. This budget excludes
the surrounding instructions and is not a token limit. The prompt records included
and omitted counts; omitted evidence and controls remain unknown. The returned
review is labeled partial. Reasoning-only responses are rejected as missing final
text, and output near its allowance carries a possible-truncation notice. A provider
reporting completion does not establish a complete or correct review.
Review instructions distinguish source observations, static inferences and
unverified runtime effects; model compliance still requires human review.

An [actual local Juice Shop review](desktop/windows/verification/real-lmstudio-production-review-2026-10-15.json)
returned nine finished sections in 122.5 seconds using selected evidence for 9 of
18 findings. This is a bounded integration example, not whole-repository AI coverage
or independent verification of the model's claims.

## Quickstart

```bash
brew install mlaify/tap/attackmap         # Homebrew: CLI + all 15 analyzer plugins
# or: pip install "attackmap[all] @ git+https://github.com/mlaify/AttackMap.git"
attackmap analyze /path/to/repo           # heuristic review → reports/
attackmap analyze /path/to/repo --llm     # + AI-narrated review (Claude or OpenAI)
attackmap analyze ./svc-a ./svc-b ./gw    # cross-repo / fleet scan
```

Read `reports/defensive-review.md` for the heuristic review, and (with `--llm`)
`reports/defensive-review-llm.md` for the AI narration. `--llm` resolves auth
automatically (`ANTHROPIC_API_KEY`, or your Claude/`codex` CLI subscription); add
`--llm-provider openai` for OpenAI/Codex.

Other install paths: `pip install git+https://github.com/mlaify/AttackMap.git` (core
only), or the `[llm]` extra for AI narration. Not sure
which analyzer plugins a repo needs? `attackmap suggest ./repo`. Full install and
CI setup: **[install guide](https://docs.mlaify.io/install/)**.

## What it finds

- **Attack-surface recon** — routes, data stores, external calls, auth signals,
  secrets, frameworks, entrypoints; every signal carries a `file:line` citation,
  evidence snippet, and confidence.
- **Data-flow / injection taint** (Python, JS/TS, Go, PHP, Java, C#, Ruby) —
  SQL, shell, eval/code and expression (SpEL/OGNL) injection, JNDI, SSRF, SSTI,
  NoSQL, LDAP, XPath, path traversal and zip-slip, deserialization, open
  redirect, header and regex injection — traced source → variable → sink
  inside each handler, with flow-bound sanitizers, SARIF `codeFlows`, a
  plugin-extensible sink registry (`taint_sinks.yaml`), and a deterministic
  0–100 **exploitability score**.
- **Novel vuln classes** — prototype pollution, mass assignment, JWT, XXE, ReDoS,
  insecure upload, GraphQL exposure; **BOLA/IDOR** authorization; insecure-crypto
  & web-hardening; anomaly/outlier + signature-free **invariant mining**.
- **Dependency CVEs** (`--cve`) — SBOM + lockfile resolution against OSV.dev,
  folded into the exploitability score.
- **Unknown-bug discovery** — `--hunt --verify` (a multi-pass, majority-vote LLM
  jury), verifier-gated `--recall`, and **cross-repo / fleet** analysis:
  confused-deputy flows, trust-assumption gaps, and the sibling service that omits
  a control its peers enforce.
- **Workflow** — `--triage`, `--remediate`, finding suppression, baseline diff
  gating, SARIF + Mermaid/Graphviz output, and a GitHub **Action + PR bot**.

Each run writes Markdown, JSON (`attackmap-report.json`), **SARIF 2.1.0**, and
diagram artifacts; fleet runs add `fleet-summary.{md,json}` + `fleet-graph.md`.
The fleet JSON also includes a versioned `fleet_architecture` model with repository
groups, components, typed relationships and evidence IDs. The native Windows
preview can explore up to 16 selected repositories, distinguish observed and
candidate links, and export the captured model or an entire SVG diagram.
See the [fleet graph contract and current limits](docs/fleet-architecture.md).
See the [outputs reference](https://docs.mlaify.io/scanning/) for the full list.

CLI and desktop runs publish validated generations under the output directory.
`current-generation.json` identifies the authoritative result; its manifest binds
artifact checksums and, for fleets, each successful child generation. Failed or
cancelled runs preserve the previous current result and record separate diagnostics.
Flat files remain compatibility exports in the requested format; an export warning
does not invalidate a successfully published generation. Partial fleet summaries
and successful siblings remain in the failed run directory without becoming current.
See [atomic artifacts](docs/atomic-artifacts.md) for the storage contract.

New finding IDs use stable detector rules and explicit entity keys, so changing
a title or recommendation does not create a new finding. Old baselines with
recorded rules can migrate deterministically; ambiguous legacy references remain
visible for review. See [finding identity](docs/finding-identity.md), including
the explicit suppression-reference migration and SARIF compatibility notes.

Static route evidence is labeled `static_observed`, protocol declarations
`inferred_protocol`, and test/fixture/example evidence `low_quality`. These labels
do not establish runtime exposure. `/internal` and `/debug` names alone leave
exposure unknown; same-file datastore/outbound hints remain context until a
route-linked chain supports the relationship. Nearby auth hints are indicators,
not proof that authentication is enforced.

Guard-based suppression currently recognizes fixed-string equality and Python
membership in a literal string collection, with branch polarity and an unchanged
sink value. Named allow-lists, custom predicates, regexes, and derived host checks
remain uncertain and can still produce findings even when the application is
safe. Flow-bound sanitizer support is unchanged.

Repeated scans exclude generated artifacts using manifest checksums or recognized
legacy report structures. A matching artifact filename alone does not exclude
ordinary configuration, and a changed checksum makes a replaced file analyzable.

## Supported ecosystems

Fifteen analyzer plugins (each installable on its own; `[all]` installs every one):
**Python**, **JavaScript/TypeScript** (Node services), **Go**, **Java/Kotlin**
(Spring), **C#** (ASP.NET Core), **Rust**, **PHP** (web / Laminas / Omeka-S),
**C**, **C++**, **Terraform**, **IaC** (Docker / compose / GitHub Actions),
**AT Protocol**. Specialty and experimental analyzers are opt-in: when one
matches a repo, `analyze` says so, and `-m <name>` runs it (`attackmap modules`
shows which). Details: [analyzers reference](https://docs.mlaify.io/analyzers/).
Write your own against the documented [analyzer SDK](docs/external-analyzers.md).

## CLI cheat-sheet

```bash
attackmap analyze <path>                  # review a repo (--output dir, --format all|json|markdown)
attackmap analyze repoA repoB …           # multi-repo fleet scan
attackmap analyze <path> --cve            # dependency CVEs (OSV.dev)
attackmap analyze <path> --recall         # widen taint discovery (extra reach = SPECULATIVE)
attackmap analyze <path> --llm            # AI narrative (--llm-provider claude|openai)
attackmap analyze <path> --hunt --verify  # LLM exploit-hypothesis hunt, adjudicated vs. source
attackmap analyze <path> --triage         # cluster/dedupe/rank existing findings
attackmap analyze <path> --remediate      # review-first fix suggestions
attackmap analyze <path> --baseline prev.json --fail-on-new-high   # PR gate
attackmap suggest ./repo                  # recommend analyzer plugins    · attackmap modules  # list installed
```

Verify-jury knobs (`--verify-votes` / `--hunt-lenses` / `--hunt-rounds` /
`--hunt-budget`) and suppression (`--no-suppress` / `--suppress-file`) are
documented in the [CLI reference](https://docs.mlaify.io/cli/).

## What AttackMap is *not*

- **Not a runtime detector.** It's static; its detection hints are leads for your
  SIEM team, not deployable rules.
- **Not a replacement for dedicated SCA.** `--cve` folds CVE signal into an
  architecture-aware narrative; Trivy/Grype/Dependabot go deeper on resolution.
- **Not a sound taint engine.** Taint follows local assignments *within* one
  function (intra-procedural def-use) and a call-graph-refined import walk
  *across* files; it does not follow a value into a helper it is passed to, and
  branches are not distinguished. Precision over recall; findings are evidence,
  not proof. See the limits in `src/attackmap/taint_flow.py`.
- **Not exhaustive.** Heuristic by design, with explicit confidence tiers and
  guardrails for stale signals.

## Documentation & links

- **[docs.mlaify.io](https://docs.mlaify.io)** — user guide, install, CLI,
  analyzers, SDK
- **[Wiki](https://github.com/mlaify/AttackMap/wiki)** — architecture, roadmap,
  contributor references
- **[Roadmap / Bug Triage / Kanban](https://github.com/orgs/mlaify/projects)** —
  project boards · [Road to 1.0](https://github.com/mlaify/AttackMap/issues/209)
- [`CHANGELOG.md`](CHANGELOG.md) · [`CONTRIBUTING.md`](CONTRIBUTING.md) ·
  [`SECURITY.md`](SECURITY.md) · [`VISION.md`](VISION.md)

## Special thanks

AttackMap is built by its contributors.

<a href="https://github.com/mlaify/AttackMap/graphs/contributors"><img src="https://contrib.rocks/image?repo=mlaify/AttackMap" alt="AttackMap contributors" /></a>

## Contributing

Issues and PRs welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). By contributing
you agree your contributions will be MIT-licensed.

## License

[MIT](LICENSE). Copyright (c) 2026 Matthew Davis and AttackMap Contributors.
