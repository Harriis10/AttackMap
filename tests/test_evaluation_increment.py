"""Integrity failures that must not silently improve a frozen WP030 corpus."""
from hashlib import sha1, sha256
import importlib.util
import json
from pathlib import Path
import shutil

import jsonschema
import pytest

ROOT = Path(__file__).resolve().parents[1]
RELATIVE = Path("fixtures/evaluation/increment-20261031")
spec = importlib.util.spec_from_file_location(
    "wp030_audit_increment", ROOT / "docs/verification/windows-parity/WP030/agent-20261031/audit_increment.py"
)
audit_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit_module)


@pytest.fixture
def copy_corpus(tmp_path):
    root = tmp_path / "repo"
    shutil.copytree(ROOT / RELATIVE, root / RELATIVE)
    baseline = Path("fixtures/evaluation/corpus.json")
    shutil.copy2(ROOT / baseline, root / baseline)
    raw = json.loads((ROOT / baseline).read_text(encoding="utf-8"))
    for relative in {case["path"] for case in raw["cases"]}:
        shutil.copytree(ROOT / relative, root / relative, ignore=shutil.ignore_patterns("__pycache__"))
    return root


def rewrite(root, name, change):
    base = root / RELATIVE
    path = base / f"{name}.json"
    raw = json.loads(path.read_text(encoding="utf-8"))
    change(raw)
    path.write_text(json.dumps(raw, indent=2) + "\n", encoding="utf-8")
    # Re-sealing deliberately bypasses the simple content lock so these tests
    # exercise semantic cross-checks, not just hash inequality.
    if name in {"corpus", "provenance"}:
        freeze_path = base / "freeze.json"
        freeze = json.loads(freeze_path.read_text(encoding="utf-8"))
        freeze["manifest_sha256" if name == "corpus" else "provenance_sha256"] = sha256(path.read_bytes()).hexdigest()
        freeze_path.write_text(json.dumps(freeze), encoding="utf-8")


def test_frozen_increment_integrity_and_review_limits():
    result = audit_module.audit(ROOT)
    assert result["increment"]["counts"] == {"positive": 16, "negative": 10, "clean": 1}
    assert result["split"]["holdout_repositories"] == ["attackmap-clean-catalog", "juice-shop-upstream-slice"]
    assert result["independent_human_review"] == "PENDING" and result["c27_accepted"] is False


def test_source_tampering_and_uninventoried_code_are_rejected(copy_corpus):
    target = copy_corpus / RELATIVE / "repos/clean-catalog/app.py"
    original = target.read_bytes()
    target.write_bytes(original + b"\n# changed\n")
    with pytest.raises(audit_module.AuditError, match="source hash mismatch"):
        audit_module.audit(copy_corpus)
    target.write_bytes(original)
    target.with_name("extra.py").write_text("print('unlabeled code')", encoding="utf-8")
    with pytest.raises(audit_module.AuditError, match="untracked or missing"):
        audit_module.audit(copy_corpus)


def test_anchor_drift_is_rejected_even_if_manifest_resealed(copy_corpus):
    rewrite(copy_corpus, "corpus", lambda raw: raw["cases"][0]["source_anchors"][0].update(text_sha256="0" * 64))
    with pytest.raises(audit_module.AuditError, match="source anchor mismatch"):
        audit_module.audit(copy_corpus)


def test_relabel_or_split_changes_cannot_bypass_freeze(copy_corpus):
    manifest = copy_corpus / RELATIVE / "corpus.json"
    raw = json.loads(manifest.read_text(encoding="utf-8"))
    raw["cases"][0]["expectation"] = "negative"
    manifest.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(audit_module.AuditError, match="frozen hash mismatch"):
        audit_module.audit(copy_corpus)
    rewrite(copy_corpus, "corpus", lambda raw: raw.update(split_seed=raw["split_seed"] + 1))
    with pytest.raises(audit_module.AuditError, match="frozen split settings"):
        audit_module.audit(copy_corpus)


def test_license_claim_and_repository_alias_are_cross_checked(copy_corpus):
    rewrite(copy_corpus, "provenance", lambda raw: raw["sources"][0].update(license="MIT"))
    with pytest.raises(audit_module.AuditError, match="MIT license evidence"):
        audit_module.audit(copy_corpus)
    rewrite(copy_corpus, "provenance", lambda raw: raw["sources"][0].update(license="GPL-3.0-or-later"))
    rewrite(copy_corpus, "provenance", lambda raw: raw["sources"][0].update(path=raw["sources"][1]["path"] + "/."))
    with pytest.raises(audit_module.AuditError, match="aliases resolve"):
        audit_module.audit(copy_corpus)


def test_case_mapping_and_duplicate_entity_are_rejected(copy_corpus):
    rewrite(copy_corpus, "corpus", lambda raw: raw["cases"][0].update(source_id="juice-shop"))
    with pytest.raises(audit_module.AuditError, match="label source mapping"):
        audit_module.audit(copy_corpus)
    rewrite(copy_corpus, "corpus", lambda raw: raw["cases"][0].update(source_id="dvwa"))
    rewrite(copy_corpus, "corpus", lambda raw: raw["cases"].append(dict(raw["cases"][0], case_id="duplicate-entity")))
    with pytest.raises(audit_module.AuditError, match="duplicate same-family entity"):
        audit_module.audit(copy_corpus)


def test_review_claim_and_path_escape_fail_schema(copy_corpus):
    rewrite(copy_corpus, "provenance", lambda raw: raw["independent_human_review"].update(status="approved"))
    with pytest.raises(jsonschema.ValidationError):
        audit_module.audit(copy_corpus)
    rewrite(copy_corpus, "provenance", lambda raw: raw["independent_human_review"].update(status="pending"))
    rewrite(copy_corpus, "corpus", lambda raw: raw["cases"][0].update(file="../../outside.php"))
    with pytest.raises(jsonschema.ValidationError):
        audit_module.audit(copy_corpus)


def test_same_upstream_cannot_cross_repo_split_under_different_ids(copy_corpus):
    def same_lineage(raw):
        first, other = raw["sources"][:2]
        first.update(lineage=other["lineage"], source_url=other["source_url"], origin=other["origin"])
        for entry in first["files"]:
            entry["source_url"] = f"{first['source_url']}/blob/{first['source_revision']}/{entry['file']}"
    rewrite(copy_corpus, "provenance", same_lineage)
    with pytest.raises(audit_module.AuditError, match="lineage split leakage"):
        audit_module.audit(copy_corpus)


def test_cross_split_code_copy_is_rejected_after_valid_reinventory(copy_corpus):
    base = copy_corpus / RELATIVE
    data = (base / "repos/dvwa/vulnerabilities/sqli/source/low.php").read_bytes() + b"\n\n"
    (base / "repos/juice-shop/copied.php").write_bytes(data)
    def record_copy(raw):
        src = raw["sources"][1]
        src["files"].append({"file": "copied.php", "sha256": sha256(data).hexdigest(),
            "git_blob": sha1(f"blob {len(data)}\0".encode() + data).hexdigest(),
            "source_url": f"{src['source_url']}/blob/{src['source_revision']}/copied.php"})
    rewrite(copy_corpus, "provenance", record_copy)
    with pytest.raises(audit_module.AuditError, match="code duplication across split"):
        audit_module.audit(copy_corpus)
