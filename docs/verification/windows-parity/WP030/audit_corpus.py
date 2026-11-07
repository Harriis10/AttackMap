"""Read-only WP030 seed-corpus inventory; does not relabel detector output."""
from collections import Counter, defaultdict
from hashlib import sha256
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "src"))
from attackmap.evaluation import load_corpus, split_corpus

manifest = ROOT / "fixtures/evaluation/corpus.json"
raw = json.loads(manifest.read_text(encoding="utf-8"))
corpus = load_corpus(manifest)
tuning, held, split = split_corpus(corpus)
counts = Counter(case.expectation for case in corpus.cases)
families = defaultdict(Counter)
missing = []
anchors = defaultdict(list)
trees = defaultdict(list)
sources = []
for case in corpus.cases:
    families[case.family or "clean"][case.expectation] += 1
    target = ROOT / case.path
    source = target / case.file if case.file else target
    if not source.exists():
        missing.append(case.case_id)
    if case.file:
        anchors[(case.path, case.file, case.line, case.route, case.method, case.family)].append(case.case_id)
for repo in corpus.repositories:
    path = next(case.path for case in corpus.cases if case.repository == repo)
    tree = ROOT / path
    files = sorted(p for p in tree.rglob("*") if p.is_file() and "__pycache__" not in p.parts)
    entries = [{"file": p.relative_to(tree).as_posix(), "sha256": sha256(p.read_bytes()).hexdigest()} for p in files]
    digest = sha256(json.dumps(entries, sort_keys=True).encode()).hexdigest()
    trees[digest].append(repo)
    sources.append({"repository": repo, "path": path, "files": entries, "tree_sha256": digest})
result = {
    "scope": "Current local seed inventory only; no independent human label review or production-diversity claim",
    "manifest_sha256": sha256(manifest.read_bytes()).hexdigest(),
    "corpus_version": raw["corpus_version"],
    "repositories": len(corpus.repositories), "expectations": len(corpus.cases),
    "counts": dict(counts), "families": {k: dict(v) for k, v in sorted(families.items())},
    "deficits": {"repositories": max(0, 30-len(corpus.repositories)), "positive": max(0,300-counts["positive"]), "negative": max(0,300-counts["negative"]), "clean": max(0,10-counts["clean"])},
    "split": {"seed": split.seed, "holdout_fraction": split.holdout_fraction, "tuning_repositories": list(split.tuning_repos), "holdout_repositories": list(split.holdout_repos), "tuning_cases": len(tuning), "holdout_cases": len(held)},
    "schema_load": "PASS", "missing_source_cases": missing,
    "duplicate_same_family_anchors": [v for v in anchors.values() if len(v)>1],
    "identical_repository_trees": [v for v in trees.values() if len(v)>1],
    "provenance_fields_present": {key: sum(key in case for case in raw["cases"]) for key in ("source_url", "source_revision", "license", "reviewer", "reviewed_at")},
    "sources": sources,
    "limitations": ["Tree hashes detect exact copies only; semantic/template duplication requires review", "Seeded repository split prevents identical repository IDs crossing sides; does not prove independent lineage or freeze before prior tuning", "Case provenance fields are absent; repository LICENSE must not be assumed to establish external-source provenance", "Labels retained unchanged; manifest states v0.2 labels await C27 human review"],
}
assert not missing
assert set(split.tuning_repos).isdisjoint(split.holdout_repos)
assert len(split.holdout_repos)/len(corpus.repositories) >= .2
output = Path(__file__).with_name("corpus-audit.json")
output.write_text(json.dumps(result, indent=2)+"\n", encoding="utf-8")
print(json.dumps({key: result[key] for key in ("repositories", "expectations", "counts", "deficits", "split", "schema_load")}))
