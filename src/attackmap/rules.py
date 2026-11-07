"""Finding-rule registry: spec tables and catalog-backed Rule records.

``threat_model`` orchestrates findings; this module owns the dictionaries that
name each detector (id, title, severity, mitigation, ATT&CK). Taxonomy stays
in ``taxonomy.py``.
"""

from __future__ import annotations

from dataclasses import dataclass

from .taint_sinks import SINK_KINDS, kind_label


@dataclass(frozen=True)
class Rule:
    rule_id: str
    title: str
    severity: str
    mitigation: str = ""
    tags: tuple[str, ...] = ()


TAINT_SINK_LABEL: dict[str, str] = {
    "sql_execute": "database (SQL execute)",
    "subprocess_shell": "command execution",
    "eval": "code eval",
    "exec": "code exec",
    "dynamic_open": "filesystem open",
    "unsafe_deserialization": "unsafe deserialization",
    "ssti": "template injection",
    "ssrf": "outbound request (SSRF)",
    "nosql_injection": "NoSQL query",
    "open_redirect": "redirect target",
}
for _kind in SINK_KINDS:
    TAINT_SINK_LABEL.setdefault(_kind, kind_label(_kind))


TAINT_FINDING_SPEC: dict[str, dict[str, str]] = {
    "eval": {
        "severity": "high",
        "title": "Request-reachable code execution via eval",
        "mitigation": "Never pass request-derived data to eval. Use a domain-specific parser or an explicit allow-list of operations.",
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
    },
    "exec": {
        "severity": "high",
        "title": "Request-reachable code execution via exec",
        "mitigation": "Never pass request-derived data to exec. Refactor to call named functions selected via a validated allow-list.",
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
    },
    "subprocess_shell": {
        "severity": "high",
        "title": "Request-reachable OS command execution",
        "mitigation": "Prefer argv-list subprocess calls with shell=False. Never interpolate request data into a shell string; validate and constrain any external command inputs.",
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
    },
    "unsafe_deserialization": {
        "severity": "high",
        "title": "Request-reachable unsafe deserialization",
        "mitigation": "Do not deserialize attacker-controlled data with pickle/marshal/yaml.load/ObjectInputStream/unserialize. Use a data-only format (JSON) with a schema, or a safe loader (yaml.safe_load).",
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
    },
    "ssti": {
        "severity": "high",
        "title": "Request-reachable server-side template injection",
        "mitigation": "Never render request-derived strings as templates. Pass untrusted data as template *variables* (auto-escaped), not as the template source.",
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
    },
    "ssrf": {
        "severity": "medium",
        "title": "Request-reachable server-side request forgery (SSRF)",
        "mitigation": "Validate and allow-list outbound destinations, resolve and pin DNS, block link-local/metadata ranges (169.254.0.0/16, fd00::/8), and disable redirects to internal hosts.",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
    },
    "nosql_injection": {
        "severity": "medium",
        "title": "Request-reachable NoSQL injection",
        "mitigation": "Never pass a raw request object as a query filter. Cast and validate each field, reject operator keys ($where, $gt, ...) in user input, and disable server-side JavaScript execution.",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
    },
    # --- #240 sink catalog expansion -------------------------------------
    "zip_slip": {
        "severity": "high",
        "title": "Request-reachable archive extraction without path checks (zip-slip)",
        "mitigation": "Extract only after validating every member path resolves inside the destination (tarfile: `extractall(filter=\"data\")` on Python 3.12+; adm-zip/unzipper: check `path.resolve(dest, entry)` starts with `dest`). Reject absolute paths, `..` segments and links.",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
    },
    "code_injection": {
        "severity": "high",
        "title": "Request input selects or builds code to run (code injection)",
        "mitigation": "Never build code (new Function, vm.run*, string setTimeout) or pick modules/methods (import_module, getattr, send, constantize) from request input. Map an allow-listed key to a fixed callable instead.",
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
    },
    "expression_injection": {
        "severity": "high",
        "title": "Request input evaluated as an expression (SpEL/OGNL/MVEL/script injection)",
        "mitigation": "Do not parse or evaluate request-derived strings with SpEL, OGNL, MVEL or a ScriptEngine. Use a SimpleEvaluationContext / sandbox if expressions are a feature, and pass user data only as variables.",
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
    },
    "jndi_injection": {
        "severity": "high",
        "title": "Request input reaches a JNDI lookup (JNDI injection)",
        "mitigation": "Never pass request-derived names to `Context.lookup`. Look up fixed, configured names only, and disable remote codebases (`com.sun.jndi.*.object.trustURLCodebase=false`).",
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
    },
    "ldap_injection": {
        "severity": "medium",
        "title": "Request input reaches an LDAP search filter (LDAP injection)",
        "mitigation": "Escape every request-derived value with an LDAP filter encoder (ldap.filter.escape_filter_chars, ldap_escape(..., LDAP_ESCAPE_FILTER), Spring LdapEncoder.filterEncode) or build filters with a parameterized API.",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
    },
    "xpath_injection": {
        "severity": "medium",
        "title": "Request input reaches an XPath expression (XPath injection)",
        "mitigation": "Use XPath variables (XPathVariableResolver, lxml `xpath(expr, name=value)`) instead of concatenating request data into the expression.",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
    },
    "header_injection": {
        "severity": "low",
        "title": "Request input sets an HTTP response header (header injection)",
        "mitigation": "Most frameworks now reject CR/LF in header values, but a caller-controlled value can still steer Location, Content-Disposition or cookies. Allow-list or encode the value before setting the header.",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
    },
    "regex_injection": {
        "severity": "low",
        "title": "Request input compiled as a regular expression (ReDoS)",
        "mitigation": "Escape request input before embedding it in a pattern (re.escape, escapeStringRegexp, Pattern.quote, regexp.QuoteMeta, preg_quote), or match it as a literal. Use a linear-time engine (RE2) where user patterns are a feature.",
        "technique_id": "T1499.004",
        "technique_name": "Endpoint Denial of Service: Application or System Exploitation",
        "tactic": "Impact",
    },
    "open_redirect": {
        "severity": "medium",
        "title": "Request-reachable open redirect",
        "mitigation": "Never redirect to a request-derived URL directly. Redirect only to a server-side allow-list of paths/hosts, or map an opaque key to the destination; reject absolute URLs and protocol-relative (`//`) targets.",
        "technique_id": "T1204",
        "technique_name": "User Execution",
        "tactic": "Execution",
    },
}

FLOW_FINDING_SPEC: dict[str, dict[str, str]] = {
    "sql_execute": {
        "rule_id": "sql-injection",
        "severity": "high",
        "title": "Request input flows into a raw SQL query (SQL injection)",
        "mitigation": "Use parameterized queries / bound parameters for every request-derived value. Never build SQL with f-strings, concatenation, .format or %; allow-list identifiers (table/column names) that can't be bound.",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
    },
    # `dynamic_open` chains are folded in here as an alias (#240).
    "path_traversal": {
        "rule_id": "path-traversal",
        "severity": "high",
        "title": "Request input flows into a filesystem path (path traversal)",
        "mitigation": "Never build filesystem paths from request input directly. Reduce it to a basename (secure_filename / path.basename), resolve it against a fixed base directory and verify the result stays inside it, or map an opaque id to a server-side path.",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
    },
}

CRYPTO_FINDING_SPEC: dict[str, dict[str, str]] = {
    "weak_password_hash": {
        "severity": "high",
        "title": "Weak password hashing (MD5/SHA-1)",
        "mitigation": "Hash passwords with a memory-hard KDF — argon2id, scrypt, or bcrypt — never a bare MD5/SHA-1/SHA-256 digest. Migrate existing hashes on next login.",
        "technique_id": "T1110.002",
        "technique_name": "Brute Force: Password Cracking",
        "tactic": "Credential Access",
    },
    "weak_cipher": {
        "severity": "high",
        "title": "Weak or broken cipher (DES/3DES/RC4/Blowfish)",
        "mitigation": "Replace legacy ciphers with AES-256-GCM (or ChaCha20-Poly1305). DES/3DES/RC4 are cryptographically broken.",
        "technique_id": "T1600",
        "technique_name": "Weaken Encryption",
        "tactic": "Defense Evasion",
    },
    "ecb_mode": {
        "severity": "medium",
        "title": "Insecure ECB block-cipher mode",
        "mitigation": "ECB leaks plaintext structure. Use an authenticated mode (AES-GCM) with a unique per-message nonce; in Java, always specify the transformation explicitly (e.g. \"AES/GCM/NoPadding\").",
        "technique_id": "T1600",
        "technique_name": "Weaken Encryption",
        "tactic": "Defense Evasion",
    },
    "static_iv_salt": {
        "severity": "medium",
        "title": "Hard-coded IV or salt",
        "mitigation": "Generate the IV/nonce and salt randomly per operation with a CSPRNG and store/transmit them alongside the ciphertext. A static IV/salt defeats the primitive's security.",
        "technique_id": "T1600",
        "technique_name": "Weaken Encryption",
        "tactic": "Defense Evasion",
    },
    "insecure_random": {
        "severity": "medium",
        "title": "Insecure randomness for a security value",
        "mitigation": "Use a CSPRNG for tokens/keys/salts/nonces/OTPs: `secrets` (Python), `crypto.randomBytes` (Node), `crypto/rand` (Go). `Math.random`/`random`/`rand`/`mt_rand` are predictable.",
        "technique_id": "T1600",
        "technique_name": "Weaken Encryption",
        "tactic": "Defense Evasion",
    },
    "insecure_tls": {
        "severity": "high",
        "title": "TLS certificate/hostname verification disabled",
        "mitigation": "Never disable certificate or hostname verification (`verify=False`, `rejectUnauthorized: false`, `InsecureSkipVerify: true`) or use deprecated TLS/SSL versions. Fix the trust store instead of turning off validation.",
        "technique_id": "T1557",
        "technique_name": "Adversary-in-the-Middle",
        "tactic": "Credential Access",
    },
}

WEB_HARDENING_FINDING_SPEC: dict[str, dict[str, str]] = {
    "cors_wildcard_credentials": {
        "severity": "high",
        "title": "CORS allows credentials with a wildcard/reflected origin",
        "mitigation": "Never combine `Access-Control-Allow-Credentials: true` with a `*` or reflected origin. Allow-list explicit trusted origins; if credentials aren't needed, drop the credentials flag.",
        "technique_id": "T1539",
        "technique_name": "Steal Web Session Cookie",
        "tactic": "Credential Access",
    },
    "cors_wildcard_origin": {
        "severity": "low",
        "title": "CORS allows any origin (without credentials)",
        "mitigation": "A wildcard or reflected origin lets any site read these responses. That is fine for genuinely public, unauthenticated data; otherwise allow-list the trusted origins. Never add credentials to this policy.",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
    },
    "cors_untrusted_origin": {
        # high when the file also allows credentials, else medium
        "title": "Origin allow-list admits untrusted origins (unanchored regex, partial match or null)",
        "mitigation": "Compare the Origin against an exact allow-list of scheme://host[:port] values. Anchor origin regexes with `^` and `$` and escape dots; check subdomains with `.endsWith('.example.com')` (leading dot), never `includes`/`endsWith('example.com')`. Never allow the `null` origin, which sandboxed iframes and `file:` pages send.",
        "technique_id": "T1539",
        "technique_name": "Steal Web Session Cookie",
        "tactic": "Credential Access",
    },
    "csrf_disabled": {
        "severity": "medium",
        "title": "CSRF protection disabled or exempted",
        "mitigation": "Keep CSRF protection on for cookie-authenticated, state-changing routes. If an endpoint is a token-authenticated API that legitimately doesn't need it, scope the exemption narrowly and document why.",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
    },
    "csrf_unprotected_session": {
        "severity": "medium",
        "title": "Cookie-session auth with state-changing routes and no CSRF protection",
        "mitigation": "Cookie-authenticated state-changing routes need a CSRF defence: CSRF-token middleware (`csrf-csrf`/`csrf-sync`, Django `CsrfViewMiddleware`, Flask-WTF `CSRFProtect`) or a session cookie with `SameSite=Strict` (or `Lax`, if no state changes on GET).",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
    },
    "insecure_cookie": {
        "severity": "medium",
        "title": "Session cookie set without secure flags",
        "mitigation": "Set `HttpOnly`, `Secure`, and `SameSite=Lax` (or `Strict`) on session cookies. `SameSite=None` must always be paired with `Secure`.",
        "technique_id": "T1539",
        "technique_name": "Steal Web Session Cookie",
        "tactic": "Credential Access",
    },
    "weak_csp": {
        "severity": "medium",
        "title": "Content-Security-Policy allows unsafe-inline/unsafe-eval",
        "mitigation": "Remove `'unsafe-inline'` and `'unsafe-eval'` from the CSP; use nonces or hashes for inline scripts. These directives largely defeat CSP's XSS protection.",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
    },
    "debug_enabled": {
        "severity": "medium",
        "title": "Debug mode or unrestricted management endpoints enabled",
        "mitigation": "Never ship with debug mode on (Flask/Django `DEBUG`, Rails `consider_all_requests_local`) or Spring actuator endpoints exposed with `*`. Debug consoles leak internals and can enable RCE.",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
    },
}

CODE_WEAKNESS_FINDING_SPEC: dict[str, dict[str, str]] = {
    "prototype_pollution": {
        "severity": "high",
        "title": "Prototype pollution",
        "mitigation": "Never write attacker-controlled keys to `__proto__`/`constructor.prototype` or deep-merge a raw request object. Use a null-prototype object (`Object.create(null)`), a Map, or a merge that rejects `__proto__`/`constructor` keys.",
        "technique_id": "T1059.007",
        "technique_name": "Command and Scripting Interpreter: JavaScript",
        "tactic": "Execution",
    },
    "mass_assignment": {
        "severity": "high",
        "title": "Mass assignment / overposting",
        "mitigation": "Never bind a whole request body to a model. Explicitly allow-list assignable fields (serializers, DTOs, strong params with a field list) so attackers can't set privileged attributes (is_admin, role, owner_id).",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
    },
    "jwt_weakness": {
        "severity": "high",
        "title": "JWT verification weakness (alg=none / signature not verified)",
        "mitigation": "Pin an explicit allow-list of signing algorithms (never include `none`), always verify the signature, and reject tokens whose header `alg` isn't expected. Don't decode without verifying.",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
    },
    "xxe": {
        "severity": "high",
        "title": "XML external entity (XXE) processing enabled",
        "mitigation": "Disable DTD/external-entity resolution in the XML parser (lxml `resolve_entities=False`, Java `disallow-doctype-decl`/secure processing, PHP keep `libxml_disable_entity_loader` default). Prefer a data format without entities where possible.",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
    },
    "redos": {
        "severity": "medium",
        "title": "Regular expression vulnerable to catastrophic backtracking (ReDoS)",
        "mitigation": "Rewrite the pattern to avoid nested quantifiers ((a+)+, (.*)*) and ambiguous alternation; use possessive quantifiers/atomic groups, a linear-time engine (RE2), or cap the length of user-supplied strings matched against it.",
        "technique_id": "T1499",
        "technique_name": "Endpoint Denial of Service",
        "tactic": "Impact",
    },
    "insecure_upload": {
        "severity": "high",
        "title": "Uploaded file persisted with a client-controlled name/path",
        "mitigation": "Never derive the stored path from the client filename. Generate a server-side name, store outside the web root, validate content type/size, and strip path separators before use.",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
    },
    "graphql_exposure": {
        "severity": "low",
        "title": "GraphQL introspection / playground enabled",
        "mitigation": "Disable introspection and the GraphiQL/playground UI in production, and add query depth/complexity limits to prevent schema disclosure and expensive-query DoS.",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
    },
    "graphql_no_query_limits": {
        "severity": "low",
        "title": "GraphQL server without query depth or complexity limits",
        "mitigation": "Bound query cost at the server: a depth limit (`graphql-depth-limit`, Strawberry `QueryDepthLimiter`, graphene `depth_limit_validator`), a complexity or cost limit (`graphql-query-complexity`, gqlgen `FixedComplexityLimit`), or GraphQL Armor. Deeply nested or aliased queries otherwise exhaust the server.",
        "technique_id": "T1499.003",
        "technique_name": "Endpoint Denial of Service: Application Exhaustion Flood",
        "tactic": "Impact",
    },
    "graphql_batching": {
        "severity": "medium",
        "title": "GraphQL HTTP batching enabled",
        "mitigation": "Disable batched HTTP requests unless clients need them. If they do, cap the batch size and rate-limit per operation, not per HTTP request, so one request can't carry thousands of login or OTP attempts.",
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
    },
    "prompt_injection_attempt": {
        "severity": "low",
        "title": "Text aimed at automated reviewers (possible prompt injection)",
        "mitigation": "Review who added these lines. Text addressed to automated (LLM-based) reviewers, instructions to disregard earlier rules, chat-template role tags or invisible/bidirectional Unicode in source are attempts to steer automated review (or hide code from humans, as in Trojan Source). AttackMap fences such content as untrusted and strips flagged lines from LLM excerpts; remove them from the code.",
        "technique_id": "T1027",
        "technique_name": "Obfuscated Files or Information",
        "tactic": "Defense Evasion",
    },
}

WORKFLOW_FINDING_SPEC: dict[str, dict[str, str]] = {
    "script_injection": {
        "title": "CI script injection via untrusted context in a run: step",
        "mitigation": "Never interpolate `${{ github.event.* }}` / `github.head_ref` directly into a run: script — a crafted issue/PR title or branch name runs arbitrary shell. Bind the value to an `env:` variable and reference it as `\"$ENVVAR\"` so it's passed as data, not expanded into the command.",
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
    },
    "pr_target_checkout": {
        "title": "pull_request_target checks out untrusted PR code",
        "mitigation": "`pull_request_target` runs with the base repo's secrets in scope. Don't check out and build the PR head ref in that context. Use `pull_request` for untrusted code, or check out only the base ref and never run fork-supplied build/test scripts with secrets available.",
        "technique_id": "T1195",
        "technique_name": "Supply Chain Compromise",
        "tactic": "Initial Access",
    },
    "unpinned_action": {
        "title": "Unpinned GitHub Action (not pinned to a commit SHA)",
        "mitigation": "Pin third-party actions to a full 40-character commit SHA (`uses: org/action@<sha>`), not a moving tag or branch. A tag/branch lets the action owner — or anyone who compromises them — change what runs in your pipeline. Dependabot can keep the pinned SHAs updated.",
        "technique_id": "T1195.001",
        "technique_name": "Supply Chain Compromise: Compromise Software Dependencies and Development Tools",
        "tactic": "Initial Access",
    },
    "secret_in_run": {
        "title": "Secret interpolated into a run: shell step",
        "mitigation": "Don't expand `${{ secrets.* }}` directly into a run: script — it can leak via the command line (`ps`), step logs, or a child process. Pass the secret through the step's `env:` block and reference it as an environment variable.",
        "technique_id": "T1552",
        "technique_name": "Unsecured Credentials",
        "tactic": "Credential Access",
    },
    "broad_permissions": {
        "title": "Over-broad GITHUB_TOKEN permissions (write-all)",
        "mitigation": "Set least-privilege `permissions:` per job (default to `contents: read` and grant only what a job needs). `write-all` gives a compromised step or action full write access to the repo, releases, packages, and more.",
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "tactic": "Privilege Escalation",
    },
    "self_hosted_pr": {
        "title": "Self-hosted runner exposed to pull-request code",
        "mitigation": "Self-hosted runners on a `pull_request`/`pull_request_target` trigger let fork PRs run arbitrary code on your infrastructure (and persist between jobs). Use ephemeral GitHub-hosted runners for public-repo PR workflows, or gate self-hosted jobs behind an environment/approval and never on `pull_request_target`.",
        "technique_id": "T1584.004",
        "technique_name": "Compromise Infrastructure: Server",
        "tactic": "Resource Development",
    },
    # #246
    "workflow_run_artifact_poisoning": {
        "title": "workflow_run consumes untrusted artifacts or code from the triggering run",
        "mitigation": "A `workflow_run` job runs with the base repo's token and secrets, but the triggering run's artifacts and head commit come from the (possibly forked) PR. Treat downloaded artifacts as untrusted data: extract them outside the workspace, never execute or `source` them, validate their contents, and don't check out `github.event.workflow_run.head_sha` in a privileged job.",
        "technique_id": "T1195.002",
        "technique_name": "Supply Chain Compromise: Compromise Software Supply Chain",
        "tactic": "Initial Access",
    },
    "issue_comment_pr_checkout": {
        "title": "issue_comment workflow checks out and runs pull-request code",
        "mitigation": "`issue_comment` workflows (\"/ok-to-test\", \"/deploy\") run with the base repo's token and secrets. Checking out `refs/pull/N/head` or running `gh pr checkout` there executes fork code with those privileges — and the PR can change after the comment. Gate on `author_association`, pin the checkout to the commit SHA the maintainer reviewed, and run untrusted code in an unprivileged `pull_request` workflow instead.",
        "technique_id": "T1195.002",
        "technique_name": "Supply Chain Compromise: Compromise Software Supply Chain",
        "tactic": "Initial Access",
    },
    "github_script_injection": {
        "title": "CI code injection via untrusted context in actions/github-script",
        "mitigation": "`actions/github-script`'s `script:` is JavaScript evaluated with the token in scope; `${{ github.event.* }}` inside it is spliced in before evaluation. Pass the value through `env:` and read it as `process.env.NAME`, or read it from `context.payload` inside the script.",
        "technique_id": "T1059.007",
        "technique_name": "Command and Scripting Interpreter: JavaScript",
        "tactic": "Execution",
    },
    "github_env_injection": {
        "title": "Untrusted value written to $GITHUB_ENV / $GITHUB_PATH",
        "mitigation": "A newline in an attacker-controlled value written to `$GITHUB_ENV` defines arbitrary variables (`LD_PRELOAD`, `NODE_OPTIONS`, `BASH_ENV`) for every later step; `$GITHUB_PATH` hijacks executables. Don't write untrusted input to these files; if you must, strip newlines and use a random heredoc delimiter, or pass it via `env:` on the step that needs it.",
        "technique_id": "T1574",
        "technique_name": "Hijack Execution Flow",
        "tactic": "Persistence",
    },
    "default_token_permissions": {
        "title": "Workflow relies on default GITHUB_TOKEN permissions",
        "mitigation": "Add a top-level `permissions:` block (e.g. `permissions: { contents: read }`) and grant extra scopes per job. Without it the token gets the repository/organization default, which is read/write on many older repositories and organizations.",
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "tactic": "Privilege Escalation",
    },
    "oidc_on_untrusted_trigger": {
        "title": "OIDC token (id-token: write) available to pull-request-triggered workflow",
        "mitigation": "`id-token: write` lets any step mint an OIDC token your cloud trusts. Don't grant it on `pull_request_target`, `issue_comment` or `workflow_run` workflows that touch PR input; move deployment to a `push`/`release` workflow behind a protected environment, and scope the cloud trust policy to `ref:refs/heads/main`.",
        "technique_id": "T1078.004",
        "technique_name": "Valid Accounts: Cloud Accounts",
        "tactic": "Privilege Escalation",
    },
    "secrets_inherit": {
        "title": "Reusable workflow receives every secret (secrets: inherit)",
        "mitigation": "`secrets: inherit` passes all repository and organization secrets to the called workflow. List only the secrets it needs (`secrets: { NPM_TOKEN: ${{ secrets.NPM_TOKEN }} }`) and pin the reusable workflow to a commit SHA.",
        "technique_id": "T1552",
        "technique_name": "Unsecured Credentials",
        "tactic": "Credential Access",
    },
    "checkout_persist_credentials": {
        "title": "actions/checkout leaves the token in .git/config for untrusted code",
        "mitigation": "`actions/checkout` persists the `GITHUB_TOKEN` in `.git/config` by default. On `pull_request_target` / `issue_comment` / `workflow_run` jobs that later run PR code or artifacts, set `persist-credentials: false` so that code can't read the write-capable token.",
        "technique_id": "T1552.001",
        "technique_name": "Unsecured Credentials: Credentials In Files",
        "tactic": "Credential Access",
    },
    "cache_poisoning_pr_target": {
        "title": "Actions cache written from untrusted PR context (cache poisoning)",
        "mitigation": "Caches saved in a `pull_request_target` job land in the base branch's cache scope, so PR code (or a PR-chosen key) can poison what `push`/release builds restore. Don't use `actions/cache` or `setup-*` `cache:` in jobs that run PR code; use `actions/cache/restore` only, or run untrusted builds under `pull_request`.",
        "technique_id": "T1195.002",
        "technique_name": "Supply Chain Compromise: Compromise Software Supply Chain",
        "tactic": "Initial Access",
    },
    "docker_action_unpinned": {
        "title": "Docker action image not pinned by digest",
        "mitigation": "`uses: docker://image:tag` (or a docker `action.yml` image) follows a mutable tag. Pin it by digest (`docker://image@sha256:<digest>`) so a re-pushed tag can't change what runs in the pipeline.",
        "technique_id": "T1195.001",
        "technique_name": "Supply Chain Compromise: Compromise Software Dependencies and Development Tools",
        "tactic": "Initial Access",
    },
    "curl_pipe_shell": {
        "title": "Remote script piped into a shell in CI (curl | sh)",
        "mitigation": "`curl … | sh` runs whatever the server returns at build time, with the job's token and secrets in scope. Download to a file, verify a pinned checksum or signature, then execute — or use a pinned action/package instead.",
        "technique_id": "T1105",
        "technique_name": "Ingress Tool Transfer",
        "tactic": "Command and Control",
    },
}

SUPPLY_CHAIN_FINDING_SPEC: dict[str, dict[str, str]] = {
    "dependency_confusion": {
        "title": "Dependency confusion risk: internal package names resolvable from a public registry",
        "mitigation": "Install private packages from a single index that proxies the public one (`--index-url`, not `--extra-index-url`); publish npm packages under an owned scope with an `@org:registry=` mapping; register placeholder names on the public registry for internal packages.",
        "technique_id": "T1195.001",
        "technique_name": "Supply Chain Compromise: Compromise Software Dependencies and Development Tools",
        "tactic": "Initial Access",
    },
    "typosquat_candidate": {
        "title": "Possible typosquatted dependency (one edit from a popular package)",
        "mitigation": "Confirm the dependency is the package you meant (check the registry page, maintainers and download counts). If it's a typo of the popular package, replace it and audit any machine that installed it.",
        "technique_id": "T1195.001",
        "technique_name": "Supply Chain Compromise: Compromise Software Dependencies and Development Tools",
        "tactic": "Initial Access",
    },
    "mutable_vcs_dependency": {
        "title": "Dependency pinned to a mutable git ref, URL or fork",
        "mitigation": "Pin VCS dependencies to a full commit SHA (`git+https://…@<sha>`, `github:user/repo#<sha>`, Cargo `rev = \"<sha>\"`), add a hash to archive URLs (`#sha256=` / `--hash=`), and prefer published registry releases over forks.",
        "technique_id": "T1195.001",
        "technique_name": "Supply Chain Compromise: Compromise Software Dependencies and Development Tools",
        "tactic": "Initial Access",
    },
    "install_script": {
        "title": "Dependency install scripts run code at install time",
        "mitigation": "Install with `--ignore-scripts` in CI and allow-list the packages that need build steps. Never pipe a download into a shell from an install hook; vendor or checksum-verify the script instead.",
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
    },
    "unlocked_manifest": {
        "title": "Dependencies resolved without a lockfile or integrity hashes",
        "mitigation": "Commit the lockfile (`package-lock.json`, `composer.lock`, `Pipfile.lock`) and install with the frozen/ci mode (`npm ci`, `composer install`); regenerate lockfile entries that lack an `integrity` hash.",
        "technique_id": "T1195.001",
        "technique_name": "Supply Chain Compromise: Compromise Software Dependencies and Development Tools",
        "tactic": "Initial Access",
    },
    "insecure_registry": {
        "title": "Package registry reached over plain HTTP or without TLS verification",
        "mitigation": "Use `https://` for every registry and index URL, and remove `strict-ssl=false` / `--trusted-host` so a network attacker can't substitute packages in transit.",
        "technique_id": "T1557",
        "technique_name": "Adversary-in-the-Middle",
        "tactic": "Credential Access",
    },
}

ANOMALY_FINDING_SPEC: dict[str, dict[str, str]] = {
    "auth_outlier": {
        "severity": "high",
        "title": "Authorization outlier — route missing an auth check its siblings enforce",
        "mitigation": "Confirm whether the flagged route is intended to be public. If not, apply the same auth/authorization guard its sibling routes use (decorator, middleware, or policy). Inconsistent enforcement across a resource cohort is a common source of broken access control.",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
    },
    "validation_outlier": {
        "severity": "medium",
        "title": "Validation outlier — handler skips input validation its peers apply",
        "mitigation": "Apply the same input validation/schema its sibling handlers use. An unvalidated state-changing endpoint among validated peers is a likely gap for injection or malformed-input bugs.",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
    },
    "method_outlier": {
        "severity": "medium",
        "title": "Method outlier — lone state-changing endpoint in a read-only cohort",
        "mitigation": "Verify the state-changing endpoint is intended and adequately protected. A single write method among an otherwise read-only resource cohort can indicate an accidentally-exposed mutation.",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
    },
    "invariant_violation": {
        "severity": "high",
        "title": "Invariant violation — handler reaches a dangerous sink without the guard its peers apply",
        "mitigation": "Confirm whether the flagged handler should reach this sink unguarded. If not, apply the same auth/validation guard its sibling handlers place before the sink. A mined invariant broken by a single site is a common shape for a forgotten check on an injection or access-control path.",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
    },
}


RULES: dict[str, Rule] = {}

_HAND_RULES: list[tuple[str, str, str]] = [
    ("public-webhook", "Public webhook endpoint may trust attacker-controlled events", "high"),
    ("exposed-admin-route", "Administrative routes appear reachable from the main application surface", "high"),
    ("upload-route", "Upload or import routes expand attacker-controlled input handling", "medium"),
    ("weak-auth-route", "Authentication routes were detected without strong nearby auth controls", "medium"),
    ("unauth-outbound-integration", "Public routes appear to influence outbound integrations without clear auth signals", "medium"),
    ("hardcoded-secret", "Hard-coded secret literals were found in source or config", "high"),
    ("secret-in-git-history", "Hard-coded secrets were found in git history", "high"),
    ("secret-env-reference", "Secret-bearing environment variables are referenced in executable paths", "medium"),
    ("public-data-route", "Public routes likely sit close to sensitive data operations", "medium"),
    ("atproto-trust-chain", "AT Protocol XRPC surface chains into a downstream trust boundary", "medium"),
    ("service-trust-chain", "Inter-service trust chain reaches a sensitive downstream sink", "medium"),
    ("framework-sink-chain", "Framework route-to-service chain reaches a sensitive sink", "medium"),
    ("vulnerable-dependency", "Vulnerable dependency: <package>@<version> (<ecosystem>)", "varies"),
    ("limited-surface", "Heuristic scan found only a limited attack surface", "low"),
    ("bola-modify", "Possible broken object-level authorization (BOLA/IDOR) on modify routes", "high"),
    ("bola-read", "Possible broken object-level authorization (BOLA/IDOR) on read routes", "medium"),
    ("unauth-state-change", "State-changing routes are reachable without an authentication control", "high"),
]


def _rule_slug_kind(kind: str) -> str:
    return kind.replace("_", "-")


def spec_tables() -> dict[str, dict[str, dict[str, str]]]:
    return {
        "taint": TAINT_FINDING_SPEC,
        "flow": FLOW_FINDING_SPEC,
        "crypto": CRYPTO_FINDING_SPEC,
        "web_hardening": WEB_HARDENING_FINDING_SPEC,
        "code_weakness": CODE_WEAKNESS_FINDING_SPEC,
        "workflow": WORKFLOW_FINDING_SPEC,
        "supply_chain": SUPPLY_CHAIN_FINDING_SPEC,
        "anomaly": ANOMALY_FINDING_SPEC,
    }


def rule_catalog() -> list[tuple[str, str, str]]:
    """Every core rule id with its finding title and severity."""
    rules: list[tuple[str, str, str]] = list(_HAND_RULES)
    for spec_table in (
        TAINT_FINDING_SPEC,
        CRYPTO_FINDING_SPEC,
        WEB_HARDENING_FINDING_SPEC,
        CODE_WEAKNESS_FINDING_SPEC,
        WORKFLOW_FINDING_SPEC,
        ANOMALY_FINDING_SPEC,
        SUPPLY_CHAIN_FINDING_SPEC,
    ):
        for kind, spec in spec_table.items():
            rules.append((_rule_slug_kind(kind), spec["title"], spec.get("severity", "varies")))
    for spec in FLOW_FINDING_SPEC.values():
        rules.append((spec["rule_id"], spec["title"], spec["severity"]))
    for kind in TAINT_FINDING_SPEC:
        label = TAINT_SINK_LABEL.get(kind, kind)
        rules.append(
            (f"speculative-{_rule_slug_kind(kind)}", f"Speculative reach to a {label} sink (recall mode)", "low")
        )
    return sorted(rules)


def _mitigation_for(rid: str) -> str:
    for table in spec_tables().values():
        for kind, spec in table.items():
            if spec.get("rule_id") == rid or _rule_slug_kind(kind) == rid:
                return spec.get("mitigation", "")
    return ""


def _populate() -> None:
    RULES.clear()
    for rid, title, sev in rule_catalog():
        RULES[rid] = Rule(rid, title, sev, _mitigation_for(rid))


def registry() -> dict[str, Rule]:
    if not RULES:
        _populate()
    return RULES


_populate()
