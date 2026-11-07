# Django helper independent review — 2026-10-23

This is source-bound, deterministic WP039/WP042 Python preparation. It does not
prove execution of Django, a complete repository scan, provider integration,
native UI acceptance, or release readiness. No plugin pin, dependency, shared
schema, merge precedence, native file, or main overlay file was changed by this
review agent.

## Result

The bounded local Django helper closes all nine observed mismatches in the
original fourteen-case overlay oracle: the same first fourteen cases improve
from **5/14 to 14/14**. Three additional wrapper-binding negatives bring the
final overlay oracle to **17/17**. See [before](python-django-before.json) and
[stable-source after](python-django-after-stable-profile.json). The original fourteen
must not be described as a seventeen-case baseline.

The exact `python@1.0` selection was exercised with the installed pinned Python
plugin and these explicit members: `python`, `python-web`, `config`,
`python-service`, `default`. `python-service` remains experimental. Selection
is not a claim that every member applied or executed successfully on a real
project. The probe calls the local deterministic analyzer pipeline over inert
specimens and records the concrete implementation classes.

All seventeen profile results preserve unknown auth in the fake decorator,
foreign wrapper, spoof middleware, fake public wrapper and canonical public
wrapper cases. The helper does **not** claim anonymous access merely because
`login_not_required` is observed.

## Important remaining profile limitations

The pinned plugin still contributes routes that the overlay now rejects:
`/not-registered/` from a commented declaration and `/not-django/` from a
foreign `path` function. The local overlay cannot retract another analyzer's
different route identity. The profile also retains the plugin's raw
`^literal/$` alongside normalized `/literal/`, and local include stubs such
as `/v1/`, `/v2/`, `/item/` alongside correctly expanded `/v1/item/` and
`/v2/item/`. These are retained, measured limitations, not fixed profile-wide
false positives. No merge-policy change was made to hide them.

An imported class `.as_view()` route remains extractable with **unknown** auth.
The baseline already extracted the representative class case; do not describe
all class-route extraction as newly added. The helper does not certify mixins,
DRF permissions, class dispatch, dynamic factories or arbitrary decorators.

## Helper contract and review

`extract_django_url_entries(rel, text)` returns the established list of
`(normalized_path, target_string, line)` entries plus explicit limitations.
It accepts literal top-level `urlpatterns` assignments and bounded literal
`+=`, exact import-bound Django `path`/`re_path`/`include` aliases, literal
include modules and safe namespace tuples. Only exact anchored literal
regular expressions are normalized. Groups, classes, wildcards, optional
segments and dynamic expressions are not guessed.

Comments, strings and private function bodies do not create URL entries.
Foreign/rebound factories, indirect list writes, module-level list references
that may escape, and dynamic namespaces become unsupported limitations. A
subsequent known literal assignment can restore a known final list. This is
a conservative static subset; it does not execute or fully model arbitrary
Python side effects.

`DjangoAuthResolver(files, max_modules=32).resolve(urls_file, target,
target_line=...)` returns `(auth, guards, evidence, middleware_eligible)`.
It snapshots the source mapping and keeps at most thirty-two parsed modules
in a per-instance LRU cache, including failed parses. One hundred routes
sharing two files parse those two modules only once. There is no process-wide
cache. `django_view_auth(...)` remains the compatible single-route wrapper.

Positive function auth requires exact import-backed Django decorators or URL
wrappers and a uniquely resolved plain function, including bounded relative
reexports. Rebinding, wildcard imports, duplicate definitions, reexport cycles,
foreign decorators, local Django namespace shadows and unknown wrappers stay
unknown. Module-level `with`, exception and pattern captures, assignment
expressions, defaults and annotations cannot silently replace an imported
framework decorator. Unrelated function-local assignment does not invalidate
an independent module decorator. Evidence cites the actual definition or
supplied URL-entry line; an unparsed target is not assigned a fabricated line.

## Main overlay integration inspected read-only

The current integration scopes ordered middleware to each resolved root,
requires exact `AuthenticationMiddleware` before exact `LoginRequiredMiddleware`,
and only applies it to the helper's eligible functions. An unresolvable root
falls back to explicitly inferred URLconf roots without a middleware auth
claim. The URLconf walk uses branch-local cycle tracking, a sixteen-module
depth limit and a shared 4096-expansion limit; repeated mounts no longer
mistake the second branch for a cycle. Admin hints use the helper's exact
framework marker rather than a target substring.

The first adversarial settings probe found deletion could leave a false
middleware claim. The root agent fixed deletion and additional binding forms.
The final retained probe passes **8/8**: valid ordered middleware control,
deleted middleware/root, function/import rebinding, exception capture, pattern
capture and mapping-rest capture. See
[initial](python-django-settings-adversarial-initial.json),
[final](python-django-settings-adversarial-final.json) and the
[reproducer](python-django-settings-adversarial.py).

## Independent upstream and sibling checks

The catalog agent's four-version, twenty-seven-fixture qualification establishes
the installed plugin/pinned archive equivalence and records candidate commit
`478208fd33b7fa30e2acbb08f184b2e289f7bb0a` and observed main commit
`87e4a8ac3de74e2a6f459af41ddc7c85cc1f3be5`. Both newer versions turn a foreign
`login_required` wrapper into required auth and a fake `login_not_required`
wrapper into anonymous auth. These are credibility regressions; the proposed
pin advance remains a **no-go**. The newer versions' literal-regex and repeated
include improvements do not compensate for those false claims. See
[direct comparison](upstream-direct-comparison.json),
[installed/pin byte comparison](installed-pin-byte-comparison.json) and
[immutable fetch record](upstream-fetch.json). Raw CRLF/LF differences are
documented separately from normalized source equivalence.

An independent read of the sibling mount helper produced four additional
adversarial failures: a constant local credential, JWT signature verification
explicitly disabled, and default-expression rebinding of the router constructor
or exception import. The initial probe emitted required auth for each and was
sent to its owner for correction. See
[initial mount probe](python-django-mount-independent-initial.json) and
[reproducer](python-django-mount-independent.py). The independent
[corrected-source rerun](python-django-mount-independent-final.json) preserves
the blocking positive and removes all four service-overlay auth upgrades.
The negatives produce no service-overlay route; this is not a claim that a
full profile omits the route or that no other analyzer can contribute auth.
The corrected helper SHA-256 is
`53e61053dc955ae06de865ab39307153c4ed6391f687a095f6eda34e4df549c9`;
the main overlay SHA-256 is
`fc0f091d9ffc7c43eac6001e0ca4ae99d399a7e0ec48d40690b4171b1a9dc722`.
Initial failures remain retained rather than being overwritten.

A bounded [frozen-executable runner](python-django-frozen-oracle.py) and its
[prepared command plan](python-django-frozen-plan.json) preserve the commands.
Preparing the plan did not invoke the executable. After the parent released
the candidate, the independent actual frozen run passed **17/17** in
**105.708 seconds**, exit 0. See the complete
[summary](python-django-frozen-final/summary.json), retained per-case process
logs and authoritative published generation directories beside it.

The frozen route semantics equal the retained source-profile semantics in all
seventeen cases. Every report/run ledger agrees on explicit `python@1.0`, its
five supplied candidates and terminal resolution/execution. All **85 analyzer
entries** record succeeded execution; this count is not an additional test
count or an assurance of complete application coverage. Analyzer errors and
deterministic time-budget breaches are absent. Known pinned-plugin comment and
foreign-factory residual routes remain present and separately recorded; the
scoped pass does not relabel them correct.

The executed image SHA-256 is
`6045194b77c0957166a6eb9fece45dbfd9c42441bb9e32cec6d040db6c419b05`.
The exact frozen build-proof SHA-256 is
`6e63500be47a21b46d6d3f9d21602d7f8af85d8b1cd268432a6f5720119a828e`.
[Provenance](python-django-frozen-final/freeze-provenance.json) retains copies
and hashes of the build proof, source checksums, release lock and installed
analyzer attestation. All **135 captured core files** match the recorded
snapshot. The live checkout has since diverged in `desktop_fleet.py` and
`fleet.py` through the concurrent fleet lane; the three reviewed Django/router
files still match. This result belongs to the released frozen image, not to
an assertion that the entire current checkout is identical. The parent's
separate full release-input qualification investigation is not closed by this
oracle. No AI, install or CVE/network option was requested, and Django fixture
code itself was never imported or executed.

## Verification and source freeze

Authored helper tests: **93 passed**, exit 0, using:

```text
.venv/Scripts/python.exe -m pytest tests/test_ecosystem_python_django.py -q -p no:cacheprovider --basetemp=.tmp/wp039-python-20261023/django-pytest-05
```

The frozen helper SHA-256 is
`faabbe10d84c4366c1891e6a2f93b2268a0121237c6af682170fe56af1ae6fd7`;
the authored test file SHA-256 is
`b8faf444abc1f86f87619203547abeabbb02ee6331a4e91f3861d993b2ad683b`.
The seventeen-case manifest SHA-256 is
`de57a15a5593bbd6455ddbab1445f4030240d871eb0843be7ad9687dd52c8769`.
The final stable oracle records its concrete main-overlay and installed-plugin
hashes and was rerun after the sibling guard corrections: **17/17 passed**.
The parent owns integration-suite verification and wider task acceptance.
