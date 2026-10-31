"""Acquire a bounded, offline corpus from exact local Git objects before scoring.

This is preparation evidence, not a downloader or a detector-tuning tool.
Refuse to overwrite the frozen data. External source remains under its license.
"""
from __future__ import annotations

from collections import Counter
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[5]
BASE = ROOT / "fixtures/evaluation/increment-20261031"
sys.path.insert(0, str(ROOT / "src"))
from attackmap.evaluation import load_corpus, split_corpus


def git(path: Path, *args: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(path), *args])


def save(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8", newline="\n")


def main() -> None:
    if BASE.exists():
        raise SystemExit("Frozen increment already exists; preparation refuses to overwrite it")
    BASE.mkdir(parents=True)
    sources = []
    upstreams = [
        ("dvwa", Path("C:/tmp/DVWA"), "d45ba3c4e7efa7f023f25f58ab4af9912c887057",
         "https://github.com/digininja/DVWA", "GPL-3.0-or-later", [
             "COPYING.txt", "README.md", "vulnerabilities/api/src/Token.php",
             *[f"vulnerabilities/{name}/source/{level}.php" for name, levels in (
                 ("sqli", ("low", "medium", "impossible")),
                 ("sqli_blind", ("low", "medium", "high", "impossible")),
                 ("exec", ("low",)),
                 ("open_redirect", ("low", "medium", "high", "impossible")),
             ) for level in levels],
         ]),
        ("juice-shop", Path("C:/tmp/juice-shop"), "e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4",
         "https://github.com/juice-shop/juice-shop", "MIT", [
             "LICENSE", "server.ts", "lib/insecurity.ts", "routes/search.ts",
             "routes/login.ts", "routes/redirect.ts", "routes/basket.ts",
             "routes/address.ts", "routes/changePassword.ts",
         ]),
    ]
    for name, local, revision, url, license_id, files in upstreams:
        assert git(local, "rev-parse", "HEAD").decode().strip() == revision
        assert not git(local, "status", "--porcelain", "--untracked-files=no").strip()
        origin = git(local, "remote", "get-url", "origin").decode().strip()
        assert origin.removesuffix(".git") == url
        entries = []
        for relative in sorted(files):
            data = git(local, "show", f"{revision}:{relative}")
            target = BASE / "repos" / name / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            entries.append({"file": relative, "sha256": sha256(data).hexdigest(),
                            "git_blob": git(local, "rev-parse", f"{revision}:{relative}").decode().strip(),
                            "source_url": f"{url}/blob/{revision}/{relative}"})
        sources.append({"source_id": name, "repository": f"{name}-upstream-slice",
                        "path": f"fixtures/evaluation/increment-20261031/repos/{name}",
                        "lineage": url, "kind": "upstream-training-application-source-slice",
                        "source_revision": revision, "source_url": url,
                        "local_acquisition_path": str(local), "origin": origin,
                        "tracked_worktree_clean_at_acquisition": True,
                        "acquisition": "git show REV:PATH; exact committed bytes, no source edits",
                        "license": license_id,
                        "license_evidence": ["README.md", "COPYING.txt"] if name == "dvwa" else ["LICENSE"],
                        "redistribution": "Separate unmodified source fixture data with upstream license and notices retained; not a runtime dependency",
                        "files": entries})

    clean = BASE / "repos/clean-catalog"
    clean.mkdir(parents=True)
    (clean / "app.py").write_text('''# SPDX-License-Identifier: MIT
# Copyright (c) 2026 AttackMap Contributors
"""Synthetic, read-only public catalog fixture; never a production sample."""
from flask import Flask, abort

app = Flask(__name__)
CATALOG = {"intro": {"title": "Public introduction"}}


@app.get("/catalog/<slug>")
def catalog(slug):
    item = CATALOG.get(slug)
    if item is None:
        abort(404)
    return item


@app.get("/health")
def health():
    return {"status": "ok"}
''', encoding="utf-8", newline="\n")
    (clean / "LICENSE").write_bytes((ROOT / "LICENSE").read_bytes())
    sources.append({"source_id": "clean-catalog", "repository": "attackmap-clean-catalog",
                    "path": "fixtures/evaluation/increment-20261031/repos/clean-catalog",
                    "lineage": "attackmap-authored-evaluation-fixtures", "kind": "synthetic",
                    "source_revision": "content-addressed-local-authorship-20261031",
                    "source_url": None, "license": "MIT", "license_evidence": ["LICENSE"],
                    "acquisition": "Authored by Codex for this bounded evaluation slice before running any detector",
                    "redistribution": "Project-authored synthetic fixture under repository MIT license",
                    "files": [{"file": p.name, "sha256": sha256(p.read_bytes()).hexdigest()}
                              for p in sorted(clean.iterdir())]})
    by_id = {s["source_id"]: s for s in sources}
    cases = []

    def case(cid, source, family, expectation, file, line, rationale, *, route=None, method=None, context=()):
        src = by_id[source]
        anchors = [{"file": file, "line": line}, *[{"file": f, "line": n} for f, n in context]]
        for anchor in anchors:
            lines = (ROOT / src["path"] / anchor["file"]).read_text(encoding="utf-8").splitlines()
            text = lines[anchor["line"] - 1].strip()
            assert text, f"Blank source anchor: {cid} {anchor}"
            anchor["text_sha256"] = sha256(text.encode()).hexdigest()
        label = {"case_id": cid, "repository": src["repository"], "path": src["path"],
                 "family": family, "expectation": expectation, "file": file, "line": line,
                 "rationale": rationale, "source_id": source, "source_anchors": anchors,
                 "label_review": "pending_independent_human_review"}
        if route is not None:
            label.update(route=route, method=method)
        cases.append(label)

    def dv(cid, file, line, expectation, rationale):
        case("dvwa-" + cid, "dvwa", "injection", expectation,
             "vulnerabilities/" + file, line, rationale)

    dv("sqli-low", "sqli/source/low.php", 11, "positive", "Request id is interpolated into quoted SQL at line 10 and executed by mysqli_query; no binding or validation protects this SQL sink.")
    dv("sqli-medium", "sqli/source/medium.php", 12, "positive", "mysqli_real_escape_string does not make an unquoted SQL expression safe: POST id remains an expression interpolated at line 11, then executed.")
    dv("sqli-impossible", "sqli/source/impossible.php", 18, "negative", "The id is numeric-checked, integer-converted and bound as PDO::PARAM_INT before execution; the SQLite branch also uses a bound integer. This label concerns SQL injection only.")
    dv("sqli-constant-query", "sqli/source/medium.php", 55, "negative", "This separate SELECT COUNT(*) query has constant SQL, independent of the vulnerable request-interpolated query earlier in the same file.")
    dv("blind-sqli-low", "sqli_blind/source/low.php", 13, "positive", "GET id enters interpolated SQL at line 11 and mysqli_query at line 13 without parameter binding; error suppression does not prevent SQL injection.")
    dv("blind-sqli-medium", "sqli_blind/source/medium.php", 15, "positive", "POST id is escaped but interpolated unquoted as an SQL expression at line 13; escaping string delimiters does not enforce a numeric value.")
    dv("blind-sqli-high", "sqli_blind/source/high.php", 13, "positive", "Cookie id is untrusted request data interpolated into SQL at line 11 and executed; LIMIT and hidden errors provide no input binding.")
    dv("blind-sqli-impossible", "sqli_blind/source/impossible.php", 19, "negative", "Numeric validation and integer conversion precede a prepared statement with bound integer id; the SQLite alternative is also parameter-bound.")
    dv("exec-low", "exec/source/low.php", 10, "positive", "Request ip is concatenated into shell_exec on both OS branches with no shell argument escaping or constrained parser.")
    dv("redirect-low", "open_redirect/source/low.php", 4, "positive", "GET redirect is copied into a Location header with no destination allowlist.")
    dv("redirect-medium", "open_redirect/source/medium.php", 11, "positive", "The guard excludes only explicit HTTP/HTTPS text, then forwards the request target to Location; network-path references remain unrestricted.")
    dv("redirect-high", "open_redirect/source/high.php", 5, "positive", "A destination merely containing info.php passes the substring check; it does not enforce an internal origin or a fixed destination.")
    dv("redirect-impossible", "open_redirect/source/impossible.php", 18, "negative", "The request selects a numeric switch branch but every possible Location target is a fixed literal; arbitrary request text never becomes the destination.")
    case("dvwa-static-token-key", "dvwa", "crypto", "positive", "vulnerabilities/api/src/Token.php", 10,
         "A public hardcoded ENCRYPTION_KEY is passed directly to token encryption/decryption. The authenticated cipher does not compensate for a publicly known key.", context=(("vulnerabilities/api/src/Token.php", 25),))

    js = "juice-shop"
    case("juice-search-sqli", js, "injection", "positive", "routes/search.ts", 23,
         "Request q is inserted into raw SQL after only length truncation, without query parameters; the source marks the same raw SQL as an injection challenge.")
    case("juice-login-sqli", js, "injection", "positive", "routes/login.ts", 34,
         "Request email is embedded directly in the raw login SQL string. Hashing the password does not constrain the email expression.")
    case("juice-redirect-substring", js, "injection", "positive", "routes/redirect.ts", 18,
         "The destination guard accepts any URL containing an allowed URL substring (lib/insecurity.ts:133-138); the route redirects to the complete untrusted destination.", context=(("lib/insecurity.ts", 136),))
    case("juice-basket-ownership", js, "bola", "positive", "routes/basket.ts", 19,
         "The basket lookup filters only by request id. Authentication is mounted in server.ts, but the user/basket mismatch only solves a challenge and does not deny the read.",
         context=(("server.ts", 384), ("routes/basket.ts", 24), ("routes/basket.ts", 32)))
    case("juice-search-fixed-query", js, "injection", "negative", "routes/search.ts", 47,
         "This separate sqlite_master metadata query has constant SQL and no request interpolation, despite the vulnerable search query earlier in the file.")
    case("juice-address-orm-query", js, "injection", "negative", "routes/address.ts", 18,
         "The address query passes id and trusted user id as ORM where values, not interpolated SQL text.", context=(("lib/insecurity.ts", 178), ("server.ts", 480)))
    case("juice-address-owner", js, "bola", "negative", "routes/address.ts", 18,
         "The read requires both object id and UserId; server.ts mounts appendUserId, which overwrites UserId from the authenticated token map and returns 401 on failure.",
         context=(("server.ts", 480), ("lib/insecurity.ts", 178), ("lib/insecurity.ts", 181)))
    case("juice-address-delete-auth", js, "unauth_state_change", "negative", "routes/address.ts", 29,
         "Delete uses both id and UserId; the actual route mounts appendUserId which rejects a missing/invalid token-map entry before the delete handler.",
         context=(("server.ts", 479), ("lib/insecurity.ts", 178), ("lib/insecurity.ts", 181)))
    case("juice-password-update-orm", js, "injection", "negative", "routes/changePassword.ts", 51,
         "The update passes password as an ORM attribute value; no request-derived SQL expression is constructed by this update.")
    case("juice-password-update-auth", js, "unauth_state_change", "negative", "routes/changePassword.ts", 51,
         "The handler rejects absent or unknown authorization tokens before loading and updating the logged-in user's record. Other password-policy weaknesses are outside this absent-auth label.",
         context=(("routes/changePassword.ts", 28), ("routes/changePassword.ts", 34), ("routes/changePassword.ts", 45)))
    case("juice-password-md5", js, "crypto", "positive", "lib/insecurity.ts", 41,
         "The password hash function uses unsalted single-pass MD5 and is used for password comparison in the login and password-change handlers.", context=(("routes/login.ts", 34), ("routes/changePassword.ts", 39)))
    case("juice-static-jwt-key", js, "crypto", "positive", "lib/insecurity.ts", 21,
         "A complete RSA private key is embedded as a source literal and used by authorize to sign service JWTs.", context=(("lib/insecurity.ts", 54),))
    cases.append({"case_id": "clean-public-catalog", "repository": "attackmap-clean-catalog",
                  "path": by_id["clean-catalog"]["path"], "expectation": "clean",
                  "rationale": "The entire synthetic repository has only public read-only catalog/health routes over constant in-memory data; no database, outbound, filesystem, mutation, cryptography or private object access.",
                  "source_id": "clean-catalog", "label_review": "pending_independent_human_review"})
    manifest = {"schema_version": "1.0.0", "corpus_name": "attackmap-local-increment-20261031",
                "corpus_version": "0.1.0", "split_seed": 20261011, "holdout_fraction": 0.5,
                "line_window": 4,
                "description": "Separate bounded source-slice increment; upstream training apps and one authored synthetic clean repository. Not production or human-reviewed acceptance.",
                "notes": "Labels and membership frozen from source before the first evaluation of this increment. Original v0.2.0 corpus and its split are unchanged. Source slices preserve exact Git objects but omit app dependencies and are not runnable full upstream repositories. All labels await independent human review; no mature-family claim.",
                "cases": cases}
    save(BASE / "corpus.json", manifest)
    _, _, split = split_corpus(load_corpus(BASE / "corpus.json"))
    save(BASE / "provenance.json", {"schema_version": "1.0.0", "sources": sources,
         "label_author": "Codex agent /root/wp030_eval_corpus, source inspection before detector evaluation",
         "independent_human_review": {"status": "pending", "reviewer": None, "reviewed_at": None},
         "limitations": ["Both upstreams are intentionally vulnerable training applications, not production-diverse repositories",
                         "Slices omit dependencies; scanning them does not prove full-application behavior",
                         "Near-twins from one upstream remain on the same split side; labels are correlated",
                         "Juice Shop was a prior integration target; this is a frozen future regression split, not a previously unseen blind benchmark"]})
    save(BASE / "freeze.json", {"schema_version": "1.0.0", "frozen_before_first_increment_evaluation": True,
         "frozen_at": "2026-10-31", "manifest_sha256": sha256((BASE / "corpus.json").read_bytes()).hexdigest(),
         "provenance_sha256": sha256((BASE / "provenance.json").read_bytes()).hexdigest(),
         "baseline_manifest_sha256": sha256((ROOT / "fixtures/evaluation/corpus.json").read_bytes()).hexdigest(),
         "split_seed": split.seed, "holdout_fraction": split.holdout_fraction,
         "tuning_repositories": list(split.tuning_repos), "holdout_repositories": list(split.holdout_repos),
         "policy": "Do not edit frozen labels, source, seed or membership in response to detector output. Disputes need a versioned adjudication; detector fixes belong to WP031."})
    print(json.dumps({"cases": len(cases), "counts": dict(Counter(c["expectation"] for c in cases)),
                      "split": {"tuning": split.tuning_repos, "holdout": split.holdout_repos}}))


if __name__ == "__main__":
    main()
