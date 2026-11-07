# Second publication design — C encoding per top-level report value

Design only. The first completed prototype and its source/data remain immutable. No second candidate writer, canonical patch or full scan has been run.

First prototype ABBA medians: baseline CPU 2.21094s / wall 3.31708s / owned-job lifetime peak 160,958,464 bytes; Python `iterencode` candidate CPU 17.96094s / wall 29.13190s / peak 123,793,408 bytes. Exact bytes and encoder/write/close/replace failure isolation passed. This material CPU regression prevents promotion on memory alone.

The actual Python 3.13.15 stdlib `JSONEncoder.encode` calls `iterencode(..., _one_shot=True)`, which selects `c_make_encoder` even with indent=2. The first prototype's default `_one_shot=False` selects `_make_iterencode` in Python. Do not use private accelerator internals or claim changing `_one_shot` produces a bounded streaming encoder: `encode` still joins the resulting chunks.

One bounded owned-child **measurement only** encoded each existing top-level value using ordinary C-backed `json.dumps(value, indent=2)`, recorded scalar lengths/timings, then released that text. It decoded the same retained 36,895,649-byte report (SHA256 `eb9e4639b570133e7801c110c466b020e841d9e3e36ef4d7ed06e228c36ea349`). Session 98689 exited 0, cleanup verified, whole-child job peak 122,163,200 bytes. It did not concatenate/reindent/write a report, so that peak does not qualify a second writer.

| Top-level value | C-encoded characters | Characters after adding two spaces after each literal newline | C dumps CPU seconds |
|---|---:|---:|---:|
| scan | 7,961,643 | 8,461,763 | 0.421875 |
| defensive_review_json | 11,824,991 | 12,468,973 | 0.453125 |
| review_context_pack | 12,472,284 | 13,116,464 | 0.421875 |
| attack_surfaces | 2,270,782 | 2,390,784 | 0.093750 |
| findings | 423,369 | 449,977 | 0.015625 |

Total section C dumps CPU was 1.40625s; this excludes indentation transformation, staging, text encoding and writes. Concurrent-host single diagnostic, no speed or end-to-end memory claim. Raw data: `C:/tmp/attackmap-wp034/publication-section-design-20261021-01/section-sizes.json`, controller `.tmp/wp034-section-design-measure.py`.

Proposed report-only second candidate: keep the existing constructed/returned `json_report` dictionary, use its exact insertion order, emit root braces/separators and string keys with existing default JSON rules, then C-dump one value at a time. Prefix two spaces after each actual JSON formatting newline so nested indentation exactly matches the original root object. JSON-escaped newlines inside strings remain escaped. Release the value text before encoding the next value. Keep the same exclusive stage/close/recheck/replace boundary and encoder-error protection. Add explicit raw-descriptor cleanup if fdopen fails.

The narrow initial design could use `text.replace("\n", "\n  ")`; this creates a second whole-section string. Encoding/writing that string can create another byte buffer. Those copies can consume much of the benefit and must be measured against the actual report before review. A bounded newline transform would avoid the replacement copy but adds Python iteration overhead; do not implement both or choose it without measurement. The largest section remains unbounded by this design, and a single dominant value can erase the saving. It establishes no 50k/100k admission bound.

Before coding, root should choose whether this tradeoff merits the smallest second prototype. If authorized: new independently sealed copy; exact all-byte and return/order checks; reject unsupported top-level forms or retain baseline behavior deliberately; eight JSON fixture goldens plus mixed nested/empty/scalar/Unicode/default-float edge cases; actual retained report ABBA with CPU/wall/OS counters separate. Inject encode, write, close, replace and fdopen failures; preserve prior bytes/current-generation validation and owned-stage cleanup. Review replacement metadata/ACL behavior separately from content atomicity. No source-model dropping, validator bypass, score/coverage/default changes or full pipeline.
