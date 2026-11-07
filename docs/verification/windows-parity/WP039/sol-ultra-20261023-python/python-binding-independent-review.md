# Independent Python binding/auth review

Final reviewed source:

- python_route_binding.py: `53e61053dc955ae06de865ab39307153c4ed6391f687a095f6eda34e4df549c9`
- ecosystem_python.py: `fc0f091d9ffc7c43eac6001e0ca4ae99d399a7e0ec48d40690b4171b1a9dc722`
- scanner.py: `5be41db7b72246efe048b01267bac008ed14119e65f9d1f896aa725502ead8ff`

Read-only CodeGraph/source review and retained adversarial probes found and
verified corrections for positive-credential rejection misclassified as a
missing-credential guard, validation in dead/optional branches, swallowed decode
errors, truthy missing-header defaults, and rebinding/name collisions in route
decorators. The implementation owner made all product changes. This agent only
wrote evidence/probe files for this review.

`python-binding-independent-review-final.json` contains ten guard controls/
negatives and three bounded prefix graph probes. All ten guard expectations
match; conflicting prefixes, a two-node cycle and a self-cycle terminate and
retain local prefixes. Two additional overlay negatives formerly emitted false
required auth: local identity `login_required` and a foreign custom decorator
colliding with a real wrapper in an unrelated file. Final overlay output contains
no false auth upgrade. Earlier raw reports are retained with their earlier source
hashes, including the failures that prompted corrections.

`python-decorator-profile-probe.py` then created two inert repositories with the
same decorator negatives and ran the **actual installed offline python@1.0
profile** through the real one-use selection, analysis and merge APIs. The Python
plugin class was verified under `.tools/wp024-freeze-venv/Lib/site-packages`.
In both cases the profile's five analyzers (python, python-web, config,
python-service, default) matched and succeeded. `/public` remained **unknown**,
with no guards; its representative source analyzer was python-web. Complete
structured scans, ledger1.1, class origins and fixture hashes are retained in
`python-decorator-profile-probe.json`. Process exit0.

Commands:

```powershell
.venv/Scripts/python.exe -B docs/verification/windows-parity/WP039/sol-ultra-20261023-python/python-binding-independent-review.py --label final
.tools/wp024-freeze-venv/Scripts/python.exe -B docs/verification/windows-parity/WP039/sol-ultra-20261023-python/python-decorator-profile-probe.py
```

These are bounded source qualification and installed-plugin coexistence checks.
They do not prove full Python semantics, framework runtime execution, a fresh
frozen/native artifact, manual acceptance or C27/C38 maturity. No provider call,
package installation or pin mutation occurred.
