import re
import json

from attackmap.models import AttackPath, AttackSurface, Finding, Route, ScanResult
from attackmap.review_prompts import render_review_prompts, render_system_prompt, render_user_prompt


def test_system_prompt_contains_grounding_rules() -> None:
    prompt = render_system_prompt()

    assert "evidence-first" in prompt.lower()
    assert "do not invent findings" in prompt.lower()
    assert "observed vs inferred" in prompt.lower()
    assert "defensive" in prompt.lower()


def test_rendered_user_prompt_includes_evidence_pack() -> None:
    scan = ScanResult(
        root=".",
        languages=["typescript"],
        routes=[
            Route(path="/admin/reindex", method="POST", file="services/api/src/admin.ts"),
            Route(path="/xrpc/com.atproto.repo.putRecord", method="ANY", file="lexicons/com/atproto/repo/putRecord.json"),
            Route(path="/debug/fixture", method="GET", file="tests/api/debug.test.ts"),
        ],
        files_scanned=9,
    )
    surfaces = [
        AttackSurface(
            route="/admin/reindex",
            method="POST",
            file="services/api/src/admin.ts",
            category="admin",
            exposure="public",
            risk="high",
            auth_signals=["jwt"],
            data_store_interaction=True,
        ),
        AttackSurface(
            route="/xrpc/com.atproto.repo.putRecord",
            method="ANY",
            file="lexicons/com/atproto/repo/putRecord.json",
            category="public_api",
            exposure="public",
            risk="medium",
            auth_signals=["atproto_namespace:com.atproto"],
            outbound_integration=True,
        ),
        AttackSurface(
            route="/debug/fixture",
            method="GET",
            file="tests/api/debug.test.ts",
            category="public_api",
            exposure="public",
            risk="low",
        ),
    ]
    findings = [
        Finding(
            title="Administrative routes appear reachable from the main application surface",
            severity="high",
            evidence=["POST /admin/reindex in services/api/src/admin.ts"],
            mitigation="Require strict server-side authorization on admin actions.",
            confidence="high",
        )
    ]
    paths = [
        AttackPath(
            name="Administrative service trust-chain abuse",
            steps=["Entry: Attacker reaches POST /admin/reindex in services/api/src/admin.ts"],
            impact="Privileged operations can be triggered from a public foothold.",
        )
    ]

    rendered = render_review_prompts(scan, surfaces, findings, paths)
    user_prompt = render_user_prompt(scan, surfaces, findings, paths)

    assert "Evidence pack (JSON):" in user_prompt
    assert rendered.system
    # The rendered prompt fences the evidence pack in nonce markers (#233);
    # with the fence removed it is the plain user prompt.
    fence = re.search(r"<<UNTRUSTED-([0-9a-f]{16})>>\n", rendered.user)
    assert fence is not None
    nonce = fence.group(1)
    assert f"<<END-UNTRUSTED-{nonce}>>" in rendered.user
    assert f"<<UNTRUSTED-{nonce}>>" in rendered.system
    unfenced = rendered.user.replace(fence.group(0), "").replace(f"\n<<END-UNTRUSTED-{nonce}>>", "")
    assert unfenced == user_prompt

    payload = json.loads(rendered.evidence_json)
    assert payload["evidence_counts"]["static_observed"] == 1
    assert payload["evidence_counts"]["inferred_protocol"] == 1
    assert payload["evidence_counts"]["low_quality"] == 1
    assert any(item["id"].startswith("surface:") for item in payload["attack_surfaces"])
    assert any(item["id"].startswith("finding:") for item in payload["findings"])
    assert any(item["id"].startswith("path:") for item in payload["attack_paths"])


def test_review_distinguishes_static_signals_from_runtime_exploitation():
    scan = ScanResult(root='.', files_scanned=1)
    finding = Finding(title='Potential unsafe evaluation', severity='high',
        evidence=['A request-derived value is passed to eval in handler.ts'],
        mitigation='Validate input and use a safer parser.', confidence='medium')
    ordinary = render_review_prompts(scan, [], [finding], [])
    bounded = render_review_prompts(scan, [], [finding], [], max_evidence_chars=14000)
    for rendered in (ordinary, bounded):
        assert 'SOURCE OBSERVATION' in rendered.system
        assert 'STATIC INFERENCE' in rendered.system
        assert 'RUNTIME UNVERIFIED' in rendered.system
        assert 'not proof that authentication is absent globally' in rendered.system
        assert 'not demonstrated RCE' in rendered.system
        assert 'A citation establishes a reference, not claim support' in rendered.system
        assert 'Cite only exact IDs present' in rendered.system
        assert 'never use a blanket OBSERVED label' in rendered.user
    before = json.loads(ordinary.evidence_json)['findings'][0]
    after = json.loads(bounded.evidence_json)['findings'][0]
    assert after == before  # Prompt strengthening does not rewrite observed evidence or IDs.
    assert len(bounded.evidence_json) <= 14000
