"""Tests for unauthenticated-route synthesis (#140)."""

from __future__ import annotations

from pathlib import Path

from attackmap.analyzer import identify_attack_surfaces
from attackmap.models import AttackSurface, Route, ScanResult
from attackmap.route_auth_fusion import synthesize_unauthenticated_routes
from attackmap.scanner import scan_repo
from attackmap.threat_model import generate_findings

_TAG = "state-changing"


def _unauth_findings(scan: ScanResult):
    return [f for f in generate_findings(scan) if _TAG in f.tags]


def _write(tmp_path: Path, name: str, body: str) -> ScanResult:
    (tmp_path / name).write_text(body, encoding="utf-8")
    return scan_repo(tmp_path)


# ---------------------------------------------------------------------------
# Express (JS) — end to end through the scanner
# ---------------------------------------------------------------------------


def test_express_unauthenticated_mutating_route_one_finding(tmp_path: Path) -> None:
    scan = _write(
        tmp_path,
        "server.js",
        "const app = require('express')();\n"
        "function requireAuth(req,res,next){ next(); }\n"
        "app.post('/orders', (req, res) => { db.insert(req.body); res.send('ok'); });\n"
        "app.put('/profile', requireAuth, (req, res) => { db.update(req.body); res.send('ok'); });\n",
    )
    findings = _unauth_findings(scan)
    assert len(findings) == 1
    evidence = "\n".join(findings[0].evidence)
    assert "/orders" in evidence
    assert "/profile" not in evidence  # guarded by the requireAuth middleware arg


def test_express_route_behind_middleware_arg_is_clean(tmp_path: Path) -> None:
    scan = _write(
        tmp_path,
        "server.js",
        "const app = require('express')();\n"
        "function requireAuth(req,res,next){ next(); }\n"
        "app.post('/orders', requireAuth, (req, res) => { db.insert(req.body); });\n",
    )
    assert _unauth_findings(scan) == []


def test_express_global_use_middleware_is_clean(tmp_path: Path) -> None:
    scan = _write(
        tmp_path,
        "server.js",
        "const app = require('express')();\n"
        "function requireAuth(req,res,next){ next(); }\n"
        "app.use(requireAuth);\n"
        "app.post('/orders', (req, res) => { db.insert(req.body); });\n",
    )
    assert _unauth_findings(scan) == []


def test_get_route_is_never_flagged(tmp_path: Path) -> None:
    scan = _write(
        tmp_path,
        "server.js",
        "const app = require('express')();\n"
        "app.get('/orders', (req, res) => { res.json(db.all()); });\n",
    )
    assert _unauth_findings(scan) == []


# ---------------------------------------------------------------------------
# FastAPI (Python) — end to end through the scanner
# ---------------------------------------------------------------------------


def test_fastapi_unauthenticated_mutating_route_one_finding(tmp_path: Path) -> None:
    scan = _write(
        tmp_path,
        "main.py",
        "from fastapi import FastAPI, Depends\n"
        "app = FastAPI()\n\n"
        '@app.post("/items")\n'
        "def create_item(item: dict):\n"
        "    return db.save(item)\n\n"
        '@app.put("/secure")\n'
        "def secure(item: dict, user=Depends(get_current_user)):\n"
        "    return db.save(item)\n",
    )
    findings = _unauth_findings(scan)
    assert len(findings) == 1
    evidence = "\n".join(findings[0].evidence)
    assert "/items" in evidence
    assert "/secure" not in evidence


def test_flask_login_required_decorator_is_clean(tmp_path: Path) -> None:
    scan = _write(
        tmp_path,
        "app.py",
        "from flask import Flask\n"
        "app = Flask(__name__)\n\n"
        '@app.route("/orders", methods=["POST"])\n'
        "@login_required\n"
        "def create():\n"
        "    return db.save(request.json)\n",
    )
    assert _unauth_findings(scan) == []


# ---------------------------------------------------------------------------
# Spring (Java) — via the fusion directly (the java-spring analyzer that
# supplies routes is a separate plugin, not part of the core scanner).
# ---------------------------------------------------------------------------


def _java_scan(tmp_path: Path, source: str, routes: list[Route]) -> tuple[ScanResult, list[AttackSurface]]:
    (tmp_path / "OrderController.java").write_text(source, encoding="utf-8")
    scan = ScanResult(root=str(tmp_path), routes=routes)
    surfaces = [
        AttackSurface(
            route=r.path,
            method=r.method,
            file=r.file,
            category="public_api",
            exposure="public",
            risk="medium",
            line=r.line,
        )
        for r in routes
    ]
    return scan, surfaces


_SPRING_SRC = """package com.x;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.access.prepost.PreAuthorize;

@RestController
@RequestMapping("/api")
public class OrderController {

    @PostMapping("/orders")
    public String create(@RequestBody Order o) {
        return repo.save(o);
    }

    @PreAuthorize("hasRole('ADMIN')")
    @DeleteMapping("/secure")
    public void del(@PathVariable Long id) {
        repo.delete(id);
    }
}
"""


def test_spring_method_annotation_distinguishes_routes(tmp_path: Path) -> None:
    scan, surfaces = _java_scan(
        tmp_path,
        _SPRING_SRC,
        [
            Route(path="/api/orders", method="POST", file="OrderController.java", line=9),
            Route(path="/api/secure", method="DELETE", file="OrderController.java", line=15),
        ],
    )
    findings = synthesize_unauthenticated_routes(scan, surfaces)
    assert len(findings) == 1
    evidence = "\n".join(findings[0].evidence)
    assert "/api/orders" in evidence  # no @PreAuthorize
    assert "/api/secure" not in evidence  # guarded by @PreAuthorize


def test_spring_class_level_annotation_protects_all(tmp_path: Path) -> None:
    src = """package com.x;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.access.prepost.PreAuthorize;

@RestController
@PreAuthorize("isAuthenticated()")
public class AdminController {
    @PostMapping("/things")
    public String create(@RequestBody Thing t) { return repo.save(t); }
}
"""
    (tmp_path / "OrderController.java").write_text(src, encoding="utf-8")
    scan = ScanResult(
        root=str(tmp_path),
        routes=[Route(path="/things", method="POST", file="OrderController.java", line=8)],
    )
    surfaces = [
        AttackSurface(
            route="/things", method="POST", file="OrderController.java",
            category="public_api", exposure="public", risk="medium", line=8,
        )
    ]
    assert synthesize_unauthenticated_routes(scan, surfaces) == []


# ---------------------------------------------------------------------------
# Scope + regression
# ---------------------------------------------------------------------------


def test_admin_route_with_control_not_flagged(tmp_path: Path) -> None:
    # /admin/* guarded by a middleware arg stays out of the unauthenticated
    # pass — no duplicate of the dedicated (architectural) admin finding.
    scan = _write(
        tmp_path,
        "server.js",
        "const app = require('express')();\n"
        "function requireAuth(req,res,next){ next(); }\n"
        "app.post('/admin/wipe', requireAuth, (req, res) => { db.wipe(); });\n",
    )
    assert _unauth_findings(scan) == []


def test_unguarded_admin_mutation_is_flagged(tmp_path: Path) -> None:
    # AM038: an admin mutation with no resolved auth control carries the
    # precise missing-auth claim here — the dedicated admin finding is
    # architectural and never asserts it (labeled ground truth: the bench
    # corpus holds e.g. POST /admin/refund as an unauth_state_change).
    scan = _write(
        tmp_path,
        "server.js",
        "const app = require('express')();\n"
        "app.post('/admin/wipe', (req, res) => { db.wipe(); });\n",
    )
    findings = _unauth_findings(scan)
    assert len(findings) == 1
    assert "/admin/wipe" in "\n".join(findings[0].evidence)


def test_get_admin_route_is_never_flagged(tmp_path: Path) -> None:
    # Only mutations carry the state-change claim, whatever the category.
    scan = _write(
        tmp_path,
        "server.js",
        "const app = require('express')();\n"
        "app.get('/admin/status', (req, res) => { res.json(db.stats()); });\n",
    )
    assert _unauth_findings(scan) == []


def test_internal_mutation_flagged_only_with_observed_state_change(tmp_path: Path) -> None:
    # AM038: an internal-named mutating route counts only when a route-linked
    # chain observes an actual state change — the path name alone is not
    # evidence (exposure stays honestly "unknown" in the evidence text).
    (tmp_path / "app.py").write_text(
        "from flask import Flask\n"
        "app = Flask(__name__)\n\n"
        '@app.route("/internal/reindex", methods=["POST"])\n'
        "def reindex():\n"
        '    return db.execute("reindex")\n',
        encoding="utf-8",
    )
    surfaces = [
        AttackSurface(
            route="/internal/reindex", method="POST", file="app.py",
            category="internal", exposure="unknown", risk="medium", line=4,
            data_store_interaction=True, relationship_basis="inferred_route_chain",
        )
    ]
    unlinked = surfaces[0].model_copy(update={"data_store_interaction": False, "relationship_basis": "unknown"})

    def scan_with(surface: AttackSurface) -> ScanResult:
        return ScanResult(
            root=str(tmp_path),
            routes=[Route(path="/internal/reindex", method="POST", file="app.py", line=4)],
        )

    evidenced = synthesize_unauthenticated_routes(scan_with(surfaces[0]), [surfaces[0]])
    assert len(evidenced) == 1
    text = "\n".join(evidenced[0].evidence)
    assert "/internal/reindex" in text
    assert "no network boundary is established" in text

    bare = synthesize_unauthenticated_routes(scan_with(unlinked), [unlinked])
    assert bare == []


def test_in_handler_session_gate_is_a_control(tmp_path: Path) -> None:
    # AM038: a handler that rejects unauthenticated callers with 401 before
    # the write is guarded — decorators are not the only enforcement point.
    scan = _write(
        tmp_path,
        "app.py",
        "from flask import Flask, abort, request, session\n"
        "app = Flask(__name__)\n\n"
        '@app.route("/notes", methods=["POST"])\n'
        "def create_note():\n"
        '    if "user_id" not in session:\n'
        "        abort(401)\n"
        "    db.save(request.json)\n"
        "    return {'created': True}\n",
    )
    assert _unauth_findings(scan) == []


def test_in_handler_gate_in_sibling_does_not_guard_this_route(tmp_path: Path) -> None:
    # The gate is resolved on the route's own handler, not file-wide.
    scan = _write(
        tmp_path,
        "app.py",
        "from flask import Flask, abort, session\n"
        "app = Flask(__name__)\n\n"
        '@app.route("/notes", methods=["POST"])\n'
        "def create_note():\n"
        '    if "user_id" not in session:\n'
        "        abort(401)\n"
        "    db.save({})\n\n"
        '@app.route("/digest", methods=["POST"])\n'
        "def refresh_digest():\n"
        "    db.update()\n"
        "    return {'refreshed': True}\n",
    )
    findings = _unauth_findings(scan)
    assert len(findings) == 1
    evidence = "\n".join(findings[0].evidence)
    assert "/digest" in evidence
    assert "/notes" not in evidence


def test_auth_hints_still_emitted(tmp_path: Path) -> None:
    # #140 must not change auth_hints emission for downstream consumers.
    scan = _write(
        tmp_path,
        "server.js",
        "const app = require('express')();\n"
        "function requireAuth(req,res,next){ next(); }\n"
        "app.post('/orders', requireAuth, (req, res) => { jwt.verify(req.headers.authorization); });\n",
    )
    assert scan.auth_hints, "auth_hints should still be emitted"


def test_finding_carries_technique_and_evidence(tmp_path: Path) -> None:
    scan = _write(
        tmp_path,
        "main.py",
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n\n"
        '@app.post("/items")\n'
        "def create_item(item: dict):\n"
        "    return db.save(item)\n",
    )
    findings = _unauth_findings(scan)
    assert len(findings) == 1
    assert findings[0].attack_techniques
    assert findings[0].attack_techniques[0].technique_id == "T1190"
    assert "chain" in " ".join(findings[0].evidence).lower()


# ---------------------------------------------------------------------------
# Webhook exposure (AM038)
# ---------------------------------------------------------------------------

_WEBHOOK_PAIRS = Path(__file__).parent / "fixtures" / "webhook_pairs"


def _webhook_findings(scan: ScanResult):
    return [f for f in generate_findings(scan) if f.rule_id == "public-webhook"]


def test_unverified_webhook_hook_path_flagged() -> None:
    # `/hooks/*` never gets the analyzer's webhook category; the synthesis
    # recognizes the path shape and the missing signature verification.
    scan = scan_repo(_WEBHOOK_PAIRS)
    findings = _webhook_findings(scan)
    assert len(findings) == 1
    evidence = "\n".join(findings[0].evidence)
    assert "POST /hooks/orders" in evidence
    assert "/hooks/signed" not in evidence   # HMAC twin: verified
    assert "/hooks/status" not in evidence   # read-only twin


def test_verified_webhook_twin_not_flagged() -> None:
    scan = scan_repo(_WEBHOOK_PAIRS)
    evidence = "\n".join(_webhook_findings(scan)[0].evidence)
    assert "compare_digest" not in evidence


def test_webhook_style_paths_stay_out_of_the_unauth_pass() -> None:
    # A webhook's auth model is signature verification, not middleware — the
    # unauthenticated pass must not double-claim the route (verified or not).
    scan = scan_repo(_WEBHOOK_PAIRS)
    unauth = _unauth_findings(scan)
    assert len(unauth) == 1
    evidence = "\n".join(unauth[0].evidence)
    assert "/sync/run" in evidence
    assert "/hooks/" not in evidence


def test_webhook_secret_read_without_verification_called_out(tmp_path: Path) -> None:
    scan = _write(
        tmp_path,
        "app.py",
        "from fastapi import FastAPI\n"
        "import os, sqlite3\n"
        "app = FastAPI()\n\n"
        '@app.post("/webhook/stripe")\n'
        "def stripe_webhook():\n"
        '    secret = os.getenv("STRIPE_WEBHOOK_SECRET")\n'
        '    db = sqlite3.connect("billing.db")\n'
        '    db.execute("insert into events values (?)", (bool(secret),))\n'
        "    return {'processed': True}\n",
    )
    findings = _webhook_findings(scan)
    assert len(findings) == 1
    evidence = "\n".join(findings[0].evidence)
    assert "POST /webhook/stripe" in evidence
    assert "webhook secret is read" in evidence
