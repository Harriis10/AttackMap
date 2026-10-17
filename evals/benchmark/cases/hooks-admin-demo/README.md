# hooks-admin-demo

Tiny FastAPI app for the AM038 detection-benchmark case. Hand-labeled from
this source, independently of tool output, following the same conventions as
the other benchmark cases.

Vulnerable routes (labeled in `evals/benchmark/benchmark.json`):

- `GET /docs/{doc_id}` — bola: doc fetched by client-supplied id, parameterized
  SQL but no ownership scoping anywhere in the handler.
- `DELETE /docs/{doc_id}` — unauth state change: doc deleted with no
  authentication. (Also id-keyed, but the missing control is authentication —
  the BOLA write claim defers to this finding.)
- `POST /admin/bulk` — unauth state change: privileged reindex with no
  authentication.
- `POST /jobs/run` — unauth state change: job inserted with no authentication.
- `POST /hooks/github` — webhook exposure: accepts inbound events and writes
  with no signature verification.

Safe twins (NOT labeled — firing on them is a false positive):

- `POST /hooks/verified` — same shape, but HMAC-SHA256 verified with
  `hmac.compare_digest` before the write.
- `POST /admin/sync` — same admin prefix, but guarded by a
  `dependencies=[Depends(require_admin)]` on the route decorator.
- `GET /hooks/events` — webhook-style path but read-only.

All SQL is parameterized — no injection labels.
