# Node / ATProto ecosystem overlay — capability matrix

Module: `src/attackmap/ecosystem_node_atproto.py` (`scan_node_atproto`,
`looks_like_atproto_repo`). Built-in registration: `node-atproto` (see the
registration patch delivered with AM052/C38).

This is a **thin application/protocol overlay** over the broad built-in
`javascript-web` analyzer. It adds only what per-file JS/TS scanning
structurally cannot see, it is extraction-only, and every signal carries
`file` + `line` + evidence text. It introduces **no scoring of its own**:
severity, ranking and findings remain in core. Observed facts (regex or
JSON-parse evidence at a cited location) are emitted at confidence 0.9;
inferences (absence-of-evidence claims) at 0.6.

Fixture validation: `tests/fixtures/atproto-service/` (15 production-like
files: lexicons, PDS gateway wiring, identity/PLC helpers, service client,
firehose subscription, feed generator, blob handling). Tests:
`tests/test_ecosystem_node_atproto.py`.

## What `javascript-web` + core already cover (pre-AM052 baseline)

- Express/Koa route extraction, including same-file `app.use()` prefixes
  (`scanner.py` `EXPRESS_*` patterns) — but nothing about XRPC/lexicons.
- Per-file auth-middleware regex hints (`requireAuth`, `passport`,
  `.use(...auth...)`) and auth-hint pass (`scanner.py` AUTH_PATTERNS).
- ORM/database keyword hints, `process.env` secret references, hardcoded
  secret literals, axios/fetch outbound calls (scanner per-file passes).
- `/xrpc/<nsid>` route *paths* are recognized downstream — `authz.py`
  treats them as RPC methods for BOLA object-reference scoping, and
  `contracts.py` keeps ANY-method XRPC routes in cross-repo contract
  linking — but nothing ever **discovered** an XRPC surface: a repo that
  defines lexicons or wires `server.method(...)` produced no routes.
- `context_pack.py` tags an `atproto` LLM-context tag when
  `/xrpc/`, `com.atproto.` or `app.bsky.` strings appear (context only,
  no structured signals).

## Capabilities

| Capability | Signal (family) | Basis | Notes |
|---|---|---|---|
| Lexicon NSID declarations (`query`/`procedure`/`subscription`) | `Route /xrpc/<nsid>` | observed | JSON-parsed `lexicons/**/*.json`; `id` line cited; query→GET, procedure→POST, subscription→GET |
| XRPC handler wiring (`server.method('<nsid>', cfg, handler)`) | `Route` at registration site | observed | Cross-file: the route cites the handler file even when the lexicon lives elsewhere; first registration wins |
| Per-method auth verifier | `Route.auth="required"`, guards, `xrpc_auth_verifier:<nsid>` | observed | `auth: <verifier>` (or compound verifier token) inside the registration's config object only — bounded balanced-paren scan, so the next registration or the handler body cannot leak in |
| Missing per-method auth | `xrpc_no_auth_observed:<nsid>` | inferred (0.6) | Wired handler with no verifier in the config and no auth middleware mount covering the path |
| Cross-file auth middleware chains | `Route.auth="required"` + `node:auth_middleware_mount:<mw>` | mount observed / coverage inferred | `app.use('<mount>', authishMiddleware)` collected repo-wide; segment-boundary prefix match (express semantics); `guard_evidence` cites the middleware file:line |
| Declared-but-unwired lexicon | `atproto:xrpc_unwired:<nsid>` | inferred (0.6) | Lexicon declares a method no registration wires |
| Wired-but-undeclared method | `atproto:xrpc_no_lexicon:<nsid>` | inferred (0.6) | Registration without a lexicon file in the repo |
| DID references | `atproto:did_reference` | observed | `did:plc:` / `did:web:` literals |
| DID resolution | `atproto:did_resolution` | observed | `DidResolver`, `resolveDid/Handle/Identity`, `@atproto/identity`, `plc.directory` |
| PLC operations | `atproto:plc_operation` | observed | `rotateSigningKey`, `PlcClient`, `@atproto/plc`, `updateDidDocument` |
| Signing key handling | `atproto:signing_key` | observed | `Secp256k1Keypair`, `signOperation`, `verifyOperationSig`, `did:key:z…`, `signJwt`/`verifyJwt` |
| Service auth | `atproto:service_auth` | observed | `createServiceAuth`/`getServiceAuth`/`serviceAuthJwt`/`verifyServiceAuth`, `Authorization: Bearer` construction |
| Session / refresh flows | `atproto:session_flow` | observed | `createSession`/`refreshSession`/`getSession`/`deleteSession`/`refreshToken`, `com.atproto.server.*Session` |
| DID-doc service entries | `atproto:did_service:{pds,appview,feedgen,chat}` | observed | `#atproto_pds`/`#bsky_app`/`#feed_generator`/`#bsky_chat` ids and `AtprotoPersonalDataServer`/`BskyAppView`/`BskyFeedGenerator`/`BskyChatService` types |
| Named service endpoints | `atproto:service_url:{kind}` + `atproto:service_call:{kind}` edge | observed | `pdsUrl`, `relayHost`, `appviewUrl`, `serviceEndpoint`, … identifier → https literal |
| Inter-service XRPC calls | `ExternalCall` | observed | Full URL literals (`https://host/xrpc/<nsid>`) keep the URL; template literals (`${pds}/xrpc/<nsid>`) emit the `/xrpc/` path as target (cross-repo contract linking matches on method+path). Verb read from the same line; `None` when unknown |
| Repo event stream / firehose | `atproto:repo_event_stream` | observed | `subscribeRepos`, `com.atproto.sync.subscribeRepos`, `firehose`, `#commit`/`#account`/`#identity` |
| Blob upload endpoints | `atproto:blob_upload` | observed | `uploadBlob`/`putBlob`/`getBlob`/`BlobRef`, `com.atproto.repo.uploadBlob`, `com.atproto.sync.{get,put}Blob` |
| Feed generator surface | `atproto:feed_generator` | observed | `getFeedSkeleton`, `feedGenerator`, `BskyFeedGenerator` |
| app.bsky namespace usage | `atproto:app_bsky_namespace` | observed | `app.bsky.*` tokens, once per file |
| ATProto SDK imports | `node:atproto-sdk:<name>` | observed | `'@atproto/xrpc-server'` etc. (DependencyHints are not re-emitted — core already parses package.json) |

## Applicability (conservative by design)

`looks_like_atproto_repo` runs `detect()` **and** is re-checked at the top of
`scan_node_atproto`, so even a direct call stays silent on non-ATProto repos.
A repo qualifies via any of:

1. a `package.json` whose name/keywords/dependency names match
   `@atproto/`, `atproto`, `bluesky`, or `bsky`;
2. a `lexicons/` (or `lexicon/`) directory containing at least one `.json`;
3. a non-test, non-vendored JS/TS file containing `@atproto/`, `did:plc:`,
   `did:web:`, `com.atproto.`, or `app.bsky.`.

Test files, vendored/minified trees and SKIP_DIRS never count toward
applicability and are excluded from extraction (source-quality weighting).
Coverage enumeration stays with the broad analyzers: the overlay reports
`files_scanned == 0` / `scanned_files is None` so merges never double-count.

## Explicitly unsupported (honest gaps)

- **No lexicon schema validation.** Lexicons are read for their NSID, main
  type and location only. Record/object/token lexicons are ignored, and
  malformed schema bodies inside an otherwise-valid lexicon are not
  diagnosed.
- **No DID resolution over the network.** Analyzers are offline by contract;
  `did:plc`/`did:web` references are extracted as text, never fetched or
  verified.
- **No lexicon ↔ wire-format conformance checking** (e.g. whether a handler
  actually validates inputs against the lexicon's schema).
- **No dataflow into handlers.** Whether a handler *uses* the verified
  identity is out of scope; `xrpc_no_auth_observed` reflects only the
  registration config and middleware mounts, not the handler body.
- **No dynamic wiring.** Registrations built from variables
  (`server.method(nsidVar, …)`) are invisible; only literal NSIDs match.
  Wiring in workspace siblings or monorepo packages outside `root` is out
  of scope.
- **Auth-by-middleware is prefix/segment based.** Auth enforced inside a
  shared handler, by a guard library, or by an API gateway in front of the
  repo is not seen — absence of a verifier is reported as an *inference*
  (0.6), never as a finding.
- **No PLC operation semantics.** Rotation/creation are flagged as
  hotspots; the operation payloads, alsoKnownAs/target relationships and
  key precedence are not modeled.
- **Subscriptions are approximate.** `subscription` lexicons map to GET;
  the SSE/streaming nature is not modeled further.
- **No blob content inspection** — endpoints are mapped, bytes/mime handling
  are not analyzed.
- **`app.bsky.` namespace detection is string-level**: it identifies
  AppView-surface usage, not which AppView semantics a call relies on.

## Maturity

Experimental. Detectors are heuristic and must pass the C27 labeled-corpus
policy (human label review; a family leaves experimental only at ≥30
positive and ≥30 negative labeled cases) before any claim of production
accuracy. Labeled cases for this fixture are contributed separately to
`fixtures/evaluation/corpus.json` (merged by the corpus owner — that file is
shared and not edited by this overlay).
