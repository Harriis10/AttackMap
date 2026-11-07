# AttackMap detector evaluation — corpus `attackmap-detector-seed` v0.2.0

Schema 1.0.0. 46 labeled expectations across 13 repositories (25 positive, 19 negative, 2 clean-repository cases).

**Matching unit** (fixed in advance, per C27): a labeled expectation is matched when a finding of the same canonical family cites the case's repository-relative file, confirmed by exact route + method, or a line within `line_window` when the finding cites no route. Findings are deduplicated by stable `finding_id` before counting. TP = matched positive, FN = unmatched positive, FP = violated negative expectation or clean repo with any same-family finding. This is stricter than `bench` precision: a grouped finding that over-cites a labeled-clean twin is penalized here.

## Split (repository-level, frozen)

- seed `20261011`, holdout fraction 30%
- tuning repositories (9): atproto-service, bola-ownership-pair, clean-flask-demo, clean-node-demo, express-docs-demo, orders-api-demo, sql-param-pair, webhook-billing-demo, webhook-verify-pair
- holdout repositories (4): auth-gate-pair, flask-admin-demo, php-omeka-app, python-service-app

## Distance to C27 targets

| Dimension | Target | Delivered | Short |
|---|---|---|---|
| Repositories | 30 | 13 | 17 |
| Positive cases | 300 | 25 | 275 |
| Negative cases | 300 | 19 | 281 |
| Clean repositories | 10 | 2 | 8 |

Every advertised family is listed below regardless of score or sample count. A family is **experimental** below 30 positive and 30 negative labeled cases (C27); per-family corpus totals:

| Family | Positive cases | Negative cases | Gap to 30/30 |
|---|---|---|---|
| `bola` | 4 | 4 | +26 positive / +26 negative |
| `crypto` | 1 | 1 | +29 positive / +29 negative |
| `injection` | 9 | 7 | +21 positive / +23 negative |
| `unauth_state_change` | 8 | 6 | +22 positive / +24 negative |
| `webhook_exposure` | 3 | 1 | +27 positive / +29 negative |

## Tuning side

| Family | TP | FP | FN | Precision [95% CI] | Recall [95% CI] | P/N/clean samples | Status |
|---|---|---|---|---|---|---|---|
| `bola` | 2 | 0 | 1 | 100% [34%, 100%] | 67% [21%, 94%] | 3/2/2 | experimental |
| `crypto` | 0 | 0 | 1 | — | 0% [0%, 79%] | 1/1/2 | experimental |
| `injection` | 6 | 1 | 0 | 86% [49%, 97%] | 100% [61%, 100%] | 6/4/2 | experimental |
| `unauth_state_change` | 3 | 0 | 1 | 100% [44%, 100%] | 75% [30%, 95%] | 4/1/2 | experimental |
| `webhook_exposure` | 2 | 0 | 0 | 100% [34%, 100%] | 100% [34%, 100%] | 2/1/2 | experimental |

## Holdout side

| Family | TP | FP | FN | Precision [95% CI] | Recall [95% CI] | P/N/clean samples | Status |
|---|---|---|---|---|---|---|---|
| `bola` | 1 | 0 | 0 | 100% [21%, 100%] | 100% [21%, 100%] | 1/2/0 | experimental |
| `crypto` | 0 | 0 | 0 | — | — | 0/0/0 | experimental |
| `injection` | 0 | 0 | 3 | — | 0% [0%, 56%] | 3/3/0 | experimental |
| `unauth_state_change` | 4 | 0 | 0 | 100% [51%, 100%] | 100% [51%, 100%] | 4/5/0 | experimental |
| `webhook_exposure` | 1 | 0 | 0 | 100% [21%, 100%] | 100% [21%, 100%] | 1/0/0 | experimental |

## Per-case results

- `webhook-billing-webhook-positive` [tuning] positive (webhook_exposure): matched
- `webhook-billing-refund-unauth-positive` [tuning] positive (unauth_state_change): matched
- `webhook-billing-customer-bola-positive` [tuning] positive (bola): matched
- `webhook-billing-customer-injection-negative` [tuning] negative (injection): respected (no finding fired)
- `flask-admin-cancel-unauth-positive` [holdout] positive (unauth_state_change): matched
- `flask-admin-role-unauth-positive` [holdout] positive (unauth_state_change): matched
- `flask-admin-order-bola-positive` [holdout] positive (bola): matched
- `flask-admin-order-injection-negative` [holdout] negative (injection): respected (no finding fired)
- `flask-admin-login-unauth-negative` [holdout] negative (unauth_state_change): respected (no finding fired)
- `orders-api-create-injection-positive` [tuning] positive (injection): matched
- `orders-api-search-injection-positive` [tuning] positive (injection): matched
- `orders-api-reindex-injection-positive` [tuning] positive (injection): matched
- `orders-api-create-unauth-positive` [tuning] positive (unauth_state_change): matched
- `orders-api-reindex-unauth-positive` [tuning] positive (unauth_state_change): matched
- `express-docs-raw-injection-positive` [tuning] positive (injection): matched
- `express-docs-preview-injection-positive` [tuning] positive (injection): matched
- `express-docs-view-injection-negative` [tuning] negative (injection): respected (no finding fired)
- `express-docs-status-injection-negative` [tuning] negative (injection): respected (no finding fired)
- `bola-pair-profile-positive` [tuning] positive (bola): matched
- `bola-pair-record-negative` [tuning] negative (bola): respected (no finding fired)
- `auth-gate-digest-unauth-positive` [holdout] positive (unauth_state_change): matched
- `auth-gate-notes-unauth-negative` [holdout] negative (unauth_state_change): respected (no finding fired)
- `sql-param-find-injection-positive` [tuning] positive (injection): matched
- `sql-param-lookup-injection-negative` [tuning] negative (injection): respected (no finding fired)
- `webhook-verify-imports-positive` [tuning] positive (webhook_exposure): matched
- `webhook-verify-payments-negative` [tuning] negative (webhook_exposure): respected (no finding fired)
- `clean-flask-demo-clean` [tuning] clean (any family): clean (no scored-family findings)
- `clean-node-demo-clean` [tuning] clean (any family): VIOLATED: injection: Request-reachable server-side request forgery (SSRF)
- `atproto-service-moderation-report-unauth-positive` [tuning] positive (unauth_state_change): MISSED (positive expectation)
- `atproto-service-status-post-unauth-negative` [tuning] negative (unauth_state_change): respected (no finding fired)
- `atproto-service-status-list-bola-positive` [tuning] positive (bola): MISSED (positive expectation)
- `atproto-service-profile-checked-bola-negative` [tuning] negative (bola): respected (no finding fired)
- `atproto-service-dev-signing-key-crypto-positive` [tuning] positive (crypto): MISSED (positive expectation)
- `atproto-service-signing-key-env-crypto-negative` [tuning] negative (crypto): respected (no finding fired)
- `php-omeka-ajax-sqli-positive` [holdout] positive (injection): MISSED (positive expectation)
- `php-omeka-ajax-shell-positive` [holdout] positive (injection): MISSED (positive expectation)
- `php-omeka-redirect-header-positive` [holdout] positive (injection): MISSED (positive expectation)
- `php-omeka-submit-validated-negative` [holdout] negative (injection): respected (no finding fired)
- `php-omeka-admin-identity-negative` [holdout] negative (unauth_state_change): respected (no finding fired)
- `php-omeka-admin-item-bola-negative` [holdout] negative (bola): respected (no finding fired)
- `python-service-webhook-stripe-positive` [holdout] positive (webhook_exposure): matched
- `python-service-admin-rebuild-unauth-positive` [holdout] positive (unauth_state_change): matched
- `python-service-orders-create-unauth-negative` [holdout] negative (unauth_state_change): respected (no finding fired)
- `python-service-orders-delete-unauth-negative` [holdout] negative (unauth_state_change): respected (no finding fired)
- `python-service-orders-get-bola-negative` [holdout] negative (bola): respected (no finding fired)
- `python-service-note-search-injection-negative` [holdout] negative (injection): respected (no finding fired)

## Corpus notes

Frozen seed corpus v0.1.0: 28 expectations over 10 repositories (17 positive, 9 negative, 2 clean-repository cases). v0.2.0: +18 expectations over three AM052 ecosystem fixtures (atproto-service, php-omeka-app, python-service-app) from the Node/ATProto, PHP/Laminas/Omeka S and Python-service lanes (8 positive, 10 negative; 46 total over 13 repositories). Case paths are relative to the repository root of an AttackMap checkout. Labels were written from the fixture sources, independently of tool output; the four example apps reuse the hand-labeled expectations from evals/benchmark/benchmark.json. The v0.2.0 labels await the C27 human label review; the two negative unauth_state_change python-service entries are only correct with the python-service overlay registered.

