# Remediate / Triage-02 source corroboration — 2026-10-23

Independent read-only Sol review of three priority claims per saved mode. Read the prior [Hunt semantic observations](../semantic-observations.md), then inspected current `C:\tmp\juice-shop` sources. That repository still has no `.codegraph` directory, so no indexing was performed. No model, GUI, test, build, source/fixture/helper edit or tracker change. Original outputs remain immutable.

**Verdict:** Remediate's transport/evidence consistency PASS does not establish safe or correct proposed fixes. Its first three recommendations contain material policy/control/path assumptions. Triage's highest-ranked eval lead has concrete static support but conditional reachability; its deserialization and administrative-exposure wording overstates what the cited facts establish. This is not a complete audit of either output or the target application.

## Identity and scope

| Saved artifact | Generation | SHA-256 |
| --- | --- | --- |
| [Remediate Markdown](../../sol-long-local-20261023-remediate/remediate/reports/d2ee2327a28e468bae62ff0542d3e12f/remediation.md) | `d2ee2327a28e468bae62ff0542d3e12f` | `3b967d50b922d28a489173ed46fa4f94677590db5f649cb1141b0c871511c0aa` |
| [Remediate metadata](../../sol-long-local-20261023-remediate/remediate/reports/d2ee2327a28e468bae62ff0542d3e12f/remediation.meta.json) | same | `c3ada268f94c4b8c74bcdbde4df20fa8178882ed0705e9f6617b70b64ebfec07` |
| [Triage Markdown](../../sol-long-local-20261023-triage-02/triage/reports/06a52eed4c6a4981a3b3a12b73cb07ae/triage.md) | `06a52eed4c6a4981a3b3a12b73cb07ae` | `2ff740752d275bf22b60e81185c895a44dcb5ec1f6748a0378ba4e51b020e535` |
| [Triage metadata](../../sol-long-local-20261023-triage-02/triage/reports/06a52eed4c6a4981a3b3a12b73cb07ae/triage.meta.json) | same | `d0efa28d7e67954ea528e37181bda09af82e2497e8a53ad1f2a8452b76951ce4` |

Both canonical reports have SHA `919619d6ffe6a8ccdf153f83d9b127ae06aa46c1b68351ee770565edbeb5b8c9` and snapshot `cd026dcf5b345dbe43113ffd83bcf994813df268d7b12d75a2c5c76f8f9d2935`. All **14 inspected source files** match both snapshots' raw-byte and normalized UTF-8 text hashes. [hashes.json](hashes.json) records exact current/snapshot hashes, source paths, metadata/report/run-manifest identities. This correspondence removes source drift as an explanation for the narrow contradictions below; it does not establish runtime behavior.

Both metadata sidecars explicitly report `reference_validity=valid` and `claim_support=not_assessed`. Remediate records source references as unresolved; Triage supplies none. Reference membership is not source corroboration. The saved Triage response remains usable as model evidence despite that journey's abnormal native exit; this content review does not repair the scenario FAIL.

## Remediate — first three high-severity recommendations

### R1: require an admin role for every `/rest/admin` route

Output lines 11–19 recommend an admin-role middleware and require both unauthenticated and low-privileged requests to version/config endpoints to return401/403.

- **Observed:** `server.ts:634-635` registers both GET routes without a route-level authorization middleware. The global functions at `server.ts:381-382`, `routes/verify.ts:86-96`, and `lib/insecurity.ts:186-198` do challenge evaluation/token-cache maintenance and call `next`; these are not a blanket authorization requirement. `routes/appVersion.ts:11-16` returns a version or empty string according to `showVersionNumber`. `routes/appConfiguration.ts:9-16` returns a cloned configuration after removing `chatBot.llmApiUrl`.
- **Inferred:** a public-configuration disclosure review is warranted. The frontend `Services/configuration.service.ts:113-124` reads this endpoint as application configuration, so an unconditional admin-role restriction may affect ordinary configuration retrieval. No frontend workflow was executed.
- **Unsupported:** the namespace establishes a required admin-only policy, both endpoints perform privileged administration, or every response is sensitive. The provided code does not establish those claims. Calling the configuration clone safe does not establish that every retained field is safe either.
- **Smallest proposed correction:** describe the observed anonymous/public configuration surface, enumerate actually sensitive response fields before recommending redaction or authorization, and require confirmation of endpoint intent. Do not prescribe a universal401/403 rule solely from the `/admin` prefix. Record this as conditional policy advice pending review.

### R2: make Feedbacks POST and 2FA verify use their siblings' full-session guard

Output lines 21–27 call the missing sibling middleware broken access control and recommend requiring the same authentication tokens on both routes.

- **Observed:** `server.ts:388-389` explicitly documents anonymous Feedbacks POST as intended and guards individual feedback resources. `server.ts:430-434` adds challenge/captcha checks to POST; `:460-461` denies PUT entirely. A sibling PUT denial is not evidence POST must have an equivalent authenticated-user policy.
- **Observed:** `server.ts:486-488` uses rate limiting and `twoFactorAuth.verify`. `routes/2fa.ts:16-49` verifies the temporary token, checks its second-factor token type, loads its user, validates TOTP, returns401 on invalid inputs, and issues the final authentication token only after verification.
- **Inferred:** adding the ordinary completed-session guard to this pre-session second-factor step may prevent completing normal login. A runtime login journey is needed before claiming an observed regression.
- **Unsupported:** absence of the sibling guard means absence of authentication controls or a common policy across these routes. This is a control-discovery false negative combined with an invalid policy analogy, not a supported fix.
- **Smallest proposed correction:** mark the route cohort as a review candidate, incorporate handler-level temporary-token/TOTP checks and explicit anonymous intent, and withhold automatic guard recommendations. The anomaly heuristic should require comparable authentication lifecycle stages, not just a shared URL prefix.

### R3: sanitize an uploaded filename at the profile-image write sink

Output lines 29–36 describe an `upload_filename` flow and recommend basename/path joining/containment checks at this sink.

- **Observed:** `routes/profileImageFileUpload.ts:16-31` derives type from uploaded buffer bytes and checks image MIME. `:34-37` requires a logged-in user. `:40-42` constructs the destination from that user's ID and the detected extension, then **writes** the buffer. It does not construct this destination from `file.originalname` or an `upload_filename` request field.
- **Inferred:** uploaded bytes reach filesystem content, but that alone does not establish arbitrary path control. The recommendation may originate in the static heuristic's over-broad `req.file` source classification noted in the prior Hunt audit.
- **Unsupported:** the proposed filename parameter controls this destination or the cited sink proves traversal. Furthermore, a lexical `startsWith(UPLOAD_DIR)` check does not establish symlink-safe containment as output line34 implies.
- **Smallest proposed correction:** withdraw this particular filename-control mechanism unless an exact source-to-path-component flow is supplied. Distinguish buffer content, detected extension and original filename in taint records. Keep snippet-key file access and uploaded-content processing as separate flows; do not apply one generic path fix to all enumerated sinks.

## Triage — ranks 1, 2 and 3

### T1: highest-ranked eval RCE in userProfile

Output lines 9–10 and54 call this a primary/direct code-execution entry point, with exploitability100.

- **Observed:** `server.ts:694-695` registers the profile handlers. `routes/updateUserProfile.ts:17-38` requires a logged-in user and stores `req.body.username`. `routes/userProfile.ts:34-49` again requires a valid logged-in user; `:57-65` reaches `eval(code)` from the stored username only inside the enabled username-XSS challenge branch and matching template-like username condition. This gives a concrete static authenticated source-to-eval relationship.
- **Inferred:** this is a credible high-priority dangerous-sink lead under the observed preconditions; prioritize eliminating evaluation of user-controlled data in a non-training product. The educational challenge intent does not make the code nonexistent.
- **Unsupported:** unconditional/unauthenticated reachability, exact exploitability100 as a runtime probability, or demonstrated compromise. No runtime test, deployment challenge configuration or impact measurement was performed here.
- **Smallest proposed correction:** retain the lead but carry the login/challenge prerequisites beside its priority. Label exploitability as supplied heuristic scoring, not measured exploitation; do not turn the ranking into an unconditional RCE conclusion.

### T2: unsafe deserialization via file-upload and snippet routes

Output lines 11–12 and54 calls this critical and a direct code-execution path across multiple routes.

- **Observed:** `routes/vulnCodeFixes.ts:72-85` and `routes/vulnCodeSnippet.ts:70-90` read local challenge `.info.yml` content selected via challenge keys, then call `js-yaml`. `server.ts:698-701` registers the snippet handlers separately. `routes/fileUpload.ts:103-132` separately parses uploaded YAML inside a challenge-enabled branch, a VM context, and a2000ms execution timeout. `package.json:128` declares `js-yaml ^3.14.0`; this audit did not resolve installed dependency versions or parser gadget semantics.
- **Inferred:** request-influenced file selection and uploaded-YAML processing deserve separate parsing/path/resource analysis. The VM/time limit is an observed control, not a proof of complete sandbox security.
- **Unsupported:** request bodies directly become serialized objects at all cited snippet sinks, all these handlers share one flow, or these facts alone establish direct RCE. The same over-association documented in the prior Hunt audit remains uncorrected by this ranking.
- **Smallest proposed correction:** split local metadata-file reads from actual uploaded YAML; preserve the challenge/VM/time controls and uncertainty. Require concrete controllable serialized bytes, dependency semantics and actual reachable sink before promoting the deserialization lead into direct-RCE wording.

### T3: critical admin configuration/version exposure

Output lines 21–22 and54 elevate absent route-level signals into critical exposure and suggest sealing the routes before pivoting.

- **Observed:** the same two public-facing GET registrations and limited handlers described in R1 exist.
- **Inferred:** rank public configuration according to actual sensitive fields, intended audience and deployment exposure. It is reasonable to request that review; namespace alone is weak privilege evidence.
- **Unsupported:** privileged administrative capability, critical sensitivity, or a demonstrated pivot chain from these handlers. The exact score100 is a supplied heuristic, not proof of impact.
- **Smallest proposed correction:** keep the observed route and handler output, qualify impact, and avoid a confirmed administrative-access narrative until privilege policy and sensitive returned content are established.

## Narrow follow-up after root releases source verification

Do not change the immutable model artifacts. Attach this review and preserve `claim_support=not_assessed` where support is absent. A focused later correction should first improve the static evidence/prompt preconditions: handler-level auth/lifecycle controls, route-to-sink ownership, exact taint source kind and controllable destination components. Require recommendations to name the actual language/API and avoid removing existing policy/control distinctions. Add small regression cases for these observed patterns only after a source lease is granted; do not replace correctness checks with prompt disclaimers or another successful model response. No correction was applied by this review.
