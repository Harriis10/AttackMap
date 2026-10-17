"""Deterministic tests for the AM037 / C27 evaluation harness.

No AI, no network: engine-facing tests run the heuristic analyzers over the
shipped seed corpus; everything else uses hand-built corpora with injected
analyzer functions and temporary fixture roots.
"""

import json
import math
from pathlib import Path

import pytest

from attackmap.bench import SCORED_CATEGORIES
from attackmap.evaluation import (
    C27_TARGETS,
    EXPERIMENTAL_MIN_PER_SIDE,
    FAMILIES,
    Corpus,
    CorpusCase,
    CorpusError,
    FamilyMetrics,
    load_corpus,
    render_markdown,
    report_json,
    run_evaluation,
    split_corpus,
    wilson_interval,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
SEED_MANIFEST = REPO_ROOT / "fixtures" / "evaluation" / "corpus.json"


def _finding(title, tags, evidence, fid=None):
    f = {"title": title, "tags": tags, "evidence": evidence}
    if fid is not None:
        f["id"] = fid
    return f


def _case(cid, repo="solo-a", path="solo-a", family="injection", expectation="positive",
          file="app.py", route="/x", method="POST", line=10):
    clean = expectation == "clean"
    return CorpusCase(
        case_id=cid, repository=repo, expectation=expectation, path=path,
        family=None if clean else family, file=None if clean else file,
        line=None if clean else line, route=None if clean else route,
        method=None if clean else method, rationale="test fixture",
    )


def _mini_corpus(cases, seed=1, fraction=0.5, window=4):
    return Corpus(name="mini", version="0.1.0", schema_version="1.0.0",
                  cases=cases, split_seed=seed, holdout_fraction=fraction,
                  line_window=window)


def _root_with(tmp_path, *dirs):
    """A corpus root containing real (empty) fixture directories, so the
    runner's path checks pass and the injected analyzer gets called."""
    for d in dirs:
        (tmp_path / d).mkdir(exist_ok=True)
    return tmp_path


def _write_manifest(tmp_path, payload):
    p = tmp_path / "corpus.json"
    p.write_text(json.dumps(payload), encoding="utf-8")
    return p


VALID_MANIFEST = {
    "schema_version": "1.0.0",
    "corpus_name": "t",
    "corpus_version": "1",
    "split_seed": 1,
    "holdout_fraction": 0.5,
    "cases": [
        {
            "case_id": "c1", "repository": "r", "family": "bola",
            "expectation": "positive", "path": "r", "file": "app.py",
            "route": "/o", "method": "GET", "line": 3, "rationale": "why",
        },
        {
            "case_id": "c2", "repository": "r2", "expectation": "clean",
            "path": "r2", "rationale": "clean repo",
        },
    ],
}


# --- manifest validation ------------------------------------------------------


def test_load_corpus_accepts_valid_manifest(tmp_path):
    corpus = load_corpus(_write_manifest(tmp_path, VALID_MANIFEST))
    assert [c.case_id for c in corpus.cases] == ["c1", "c2"]
    assert corpus.repositories == ["r", "r2"]
    assert corpus.cases[0].family == "bola" and corpus.cases[1].family is None


def test_load_corpus_rejects_unknown_schema_version(tmp_path):
    bad = dict(VALID_MANIFEST, schema_version="9.9.9")
    with pytest.raises(CorpusError, match="schema_version"):
        load_corpus(_write_manifest(tmp_path, bad))


def test_load_corpus_rejects_unknown_family(tmp_path):
    bad = json.loads(json.dumps(VALID_MANIFEST))
    bad["cases"][0]["family"] = "fontender_injection"
    with pytest.raises(CorpusError, match="unknown family"):
        load_corpus(_write_manifest(tmp_path, bad))


def test_load_corpus_rejects_bad_expectation(tmp_path):
    bad = json.loads(json.dumps(VALID_MANIFEST))
    bad["cases"][0]["expectation"] = "maybe"
    with pytest.raises(CorpusError, match="expectation"):
        load_corpus(_write_manifest(tmp_path, bad))


def test_load_corpus_rejects_case_without_entity_anchor(tmp_path):
    # positive/negative cases need a route or line to pin the entity
    bad = json.loads(json.dumps(VALID_MANIFEST))
    del bad["cases"][0]["route"], bad["cases"][0]["line"]
    with pytest.raises(CorpusError, match="anchor"):
        load_corpus(_write_manifest(tmp_path, bad))


def test_load_corpus_rejects_clean_case_with_family(tmp_path):
    bad = json.loads(json.dumps(VALID_MANIFEST))
    bad["cases"][1]["family"] = "bola"
    with pytest.raises(CorpusError, match="clean"):
        load_corpus(_write_manifest(tmp_path, bad))


def test_load_corpus_rejects_missing_rationale_and_duplicate_ids(tmp_path):
    bad = json.loads(json.dumps(VALID_MANIFEST))
    bad["cases"][0]["rationale"] = "  "
    with pytest.raises(CorpusError, match="rationale"):
        load_corpus(_write_manifest(tmp_path, bad))
    bad2 = json.loads(json.dumps(VALID_MANIFEST))
    bad2["cases"][1]["case_id"] = "c1"
    with pytest.raises(CorpusError, match="duplicate"):
        load_corpus(_write_manifest(tmp_path, bad2))


def test_load_corpus_enforces_minimum_holdout_fraction(tmp_path):
    bad = dict(VALID_MANIFEST, holdout_fraction=0.1)
    with pytest.raises(CorpusError, match="holdout_fraction"):
        load_corpus(_write_manifest(tmp_path, bad))


# --- split --------------------------------------------------------------------


def test_split_is_deterministic_and_repository_separated():
    corpus = load_corpus(SEED_MANIFEST)
    t1, h1, s1 = split_corpus(corpus)
    t2, h2, s2 = split_corpus(corpus)
    assert [c.case_id for c in t1] == [c.case_id for c in t2]
    assert s1.holdout_repos == s2.holdout_repos
    # repository-level separation: no repo on both sides, union covers all
    assert not (set(s1.tuning_repos) & set(s1.holdout_repos))
    assert set(s1.tuning_repos) | set(s1.holdout_repos) == set(corpus.repositories)
    tuning_repos = {c.repository for c in t1}
    holdout_repos = {c.repository for c in h1}
    assert not (tuning_repos & holdout_repos)
    # C27: at least 20% of repositories held out (10 repos -> 3 at 30%)
    assert len(s1.holdout_repos) == math.ceil(len(corpus.repositories) * corpus.holdout_fraction)
    assert len(s1.holdout_repos) / len(corpus.repositories) >= 0.2


def test_split_seed_changes_the_split():
    base = load_corpus(SEED_MANIFEST)
    other = Corpus(name=base.name, version=base.version, schema_version=base.schema_version,
                   cases=base.cases, split_seed=base.split_seed + 1,
                   holdout_fraction=base.holdout_fraction, line_window=base.line_window)
    _, _, s1 = split_corpus(base)
    _, _, s2 = split_corpus(other)
    assert s1.holdout_repos != s2.holdout_repos


# --- statistics ---------------------------------------------------------------


def test_wilson_interval_hand_computed():
    # Verified against the closed-form Wilson formula at z=1.95996.
    lo, hi = wilson_interval(8, 10)
    assert lo == pytest.approx(0.4902, abs=1e-3)
    assert hi == pytest.approx(0.9433, abs=1e-3)
    lo, hi = wilson_interval(3, 5)
    assert lo == pytest.approx(0.2307, abs=1e-3)
    assert hi == pytest.approx(0.8824, abs=1e-3)
    assert wilson_interval(0, 0) is None
    lo, hi = wilson_interval(0, 10)
    assert lo == 0.0 and hi == pytest.approx(0.2775, abs=1e-3)
    lo, hi = wilson_interval(10, 10)
    assert hi == 1.0 and lo == pytest.approx(0.7225, abs=1e-3)


def test_experimental_flag_threshold():
    supported = FamilyMetrics(family="injection", positives=30, negatives=30)
    assert not supported.experimental
    few_pos = FamilyMetrics(family="injection", positives=29, negatives=30)
    few_neg = FamilyMetrics(family="injection", positives=30, negatives=29)
    empty = FamilyMetrics(family="crypto")
    assert few_pos.experimental and few_neg.experimental and empty.experimental


# --- metric math on a hand-computed mini corpus -------------------------------


def test_metrics_hand_computed(tmp_path):
    # solo-a: 4 injection positives (/p1../p4), 2 injection negatives (/n1,/n2).
    # seed 1, fraction 0.5 over 2 repos -> holdout = solo-b, tuning = solo-a.
    cases = (
        [_case(f"p{i}", route=f"/p{i}", line=i) for i in range(1, 5)]
        + [_case(f"n{i}", route=f"/n{i}", line=10 + i, expectation="negative") for i in (1, 2)]
        + [_case("clean", repo="solo-b", path="solo-b", expectation="clean")]
    )
    corpus = _mini_corpus(cases, seed=1, fraction=0.5)
    root = _root_with(tmp_path, "solo-a", "solo-b")

    def fake_analyze(path):
        if Path(path).name == "solo-b":  # clean repo: one stray injection finding
            return [_finding("SQL injection sink", ["injection"], ["sink at z.py:5"])]
        # positives p1..p3 matched, p4 missed; negative n1 violated, n2 respected.
        return [
            _finding("SQL injection via query", ["injection"],
                     [f"POST /p{i} in app.py:{i} — concatenated" for i in (1, 2, 3)],
                     fid="grouped"),
            _finding("SQL injection via query", ["injection"],
                     ["POST /n1 in app.py:11 — concatenated"], fid="n1-fire"),
        ]

    report = run_evaluation(corpus, root, analyze=fake_analyze)
    tuning = report.sides["tuning"]["injection"]
    holdout = report.sides["holdout"]["injection"]
    assert tuning.tp == 3 and tuning.fn == 1 and tuning.fp == 1
    assert tuning.precision == pytest.approx(3 / 4)   # 3 TP / (3 TP + 1 FP)
    assert tuning.recall == pytest.approx(3 / 4)      # 3 matched / 4 positives
    assert tuning.precision_ci == wilson_interval(3, 4)
    assert tuning.recall_ci == wilson_interval(3, 4)
    assert tuning.missed == ["p4"] and tuning.violated == ["n1"]
    assert tuning.clean_repos == 0 and tuning.positives == 4 and tuning.negatives == 2
    # clean repo on the holdout side: 1 FP, counted as a clean-repository sample
    assert holdout.fp == 1 and holdout.clean_repos == 1
    assert holdout.positives == 0 and holdout.negatives == 0
    assert holdout.experimental  # far below 30/30


def test_out_of_corpus_finding_is_not_penalized(tmp_path):
    # A finding that matches no expectation and sits in a repo with no matching
    # negative label for its file is out of corpus — no FP (expectation unit).
    corpus = _mini_corpus([_case("p1", route="/p1", line=1)])
    root = _root_with(tmp_path, "solo-a")

    def fake_analyze(path):
        return [
            _finding("SQL injection via query", ["injection"], ["POST /p1 in app.py:1 — x"]),
            _finding("SQL injection via query", ["injection"], ["POST /zz in other.py:9 — x"]),
        ]

    report = run_evaluation(corpus, root, analyze=fake_analyze)
    fm = report.sides["holdout"]["injection"]  # single repo -> holdout side
    assert fm.tp == 1 and fm.fp == 0 and fm.fn == 0


# --- matching-unit semantics ---------------------------------------------------


def test_route_and_method_must_match_exactly(tmp_path):
    corpus = _mini_corpus([_case("p1", route="/orders", method="POST", line=10)])
    root = _root_with(tmp_path, "solo-a")

    def wrong_route(path):
        return [_finding("SQL injection", ["injection"], ["POST /orders/search in app.py:10"])]

    def wrong_method(path):
        return [_finding("SQL injection", ["injection"], ["GET /orders in app.py:10"])]

    for analyze in (wrong_route, wrong_method):
        report = run_evaluation(corpus, root, analyze=analyze)
        assert report.sides["holdout"]["injection"].recall == 0.0


def test_negative_violated_only_by_same_family_same_entity(tmp_path):
    corpus = _mini_corpus([_case("n1", family="bola", route="/o", method="GET", line=3,
                                 expectation="negative")])
    root = _root_with(tmp_path, "solo-a")

    def no_violation(path):
        # injection finding on the same file/route must not violate a bola negative
        return [_finding("SQL injection", ["injection"], ["GET /o in app.py:3 — x"])]

    def violation(path):
        return [_finding("Possible broken object-level authorization (BOLA/IDOR) on read routes",
                         ["broken-authorization"], ["GET /o in app.py:3 — no ownership check"])]

    clean = run_evaluation(corpus, root, analyze=no_violation)
    assert clean.sides["holdout"]["bola"].fp == 0
    dirty = run_evaluation(corpus, root, analyze=violation)
    assert dirty.sides["holdout"]["bola"].fp == 1
    assert dirty.sides["holdout"]["bola"].violated == ["n1"]


def test_repo_relative_file_prevents_cross_file_match(tmp_path):
    corpus = _mini_corpus([_case("p1", route="/x", method="POST", line=10,
                                 file="services/b/app.py")])
    root = _root_with(tmp_path, "solo-a")

    def analyze(path):
        return [_finding("SQL injection", ["injection"], ["POST /x in services/a/app.py:10"])]

    report = run_evaluation(corpus, root, analyze=analyze)
    assert report.sides["holdout"]["injection"].recall == 0.0


def test_grouped_finding_matches_two_positives_and_duplicates_count_once(tmp_path):
    cases = [_case("p1", route="/a", line=10), _case("p2", route="/b", line=20),
             _case("n1", route="/n", line=30, expectation="negative")]
    corpus = _mini_corpus(cases)
    root = _root_with(tmp_path, "solo-a")

    def analyze(path):
        return [
            # one grouped finding legitimately cites both true positives
            _finding("SQL injection", ["injection"],
                     ["POST /a in app.py:10 — x", "POST /b in app.py:20 — x"]),
            # exact duplicate finding (same stable id) firing on the negative
            _finding("SQL injection", ["injection"], ["POST /n in app.py:30 — x"], fid="dup"),
            _finding("SQL injection", ["injection"], ["POST /n in app.py:30 — x"], fid="dup"),
        ]

    report = run_evaluation(corpus, root, analyze=analyze)
    fm = report.sides["holdout"]["injection"]
    assert fm.tp == 2 and fm.matched == ["p1", "p2"]
    assert fm.fp == 1  # duplicated finding deduplicated by id -> one violated expectation
    assert fm.fn == 0


def test_advisory_findings_never_violate_clean_or_negatives(tmp_path):
    cases = [_case("n1", route="/x", line=1, expectation="negative"),
             _case("clean", repo="solo-b", path="solo-b", expectation="clean")]
    corpus = _mini_corpus(cases)
    root = _root_with(tmp_path, "solo-a", "solo-b")

    def analyze(path):
        return [
            _finding("Secret-bearing environment variables are referenced",
                     ["secret-exposure"], ["KEY in app.py:5"]),
            _finding("Public routes likely sit close to sensitive data",
                     ["exposed-endpoint", "data-risk"], ["GET /x in app.py:1"]),
        ]

    report = run_evaluation(corpus, root, analyze=analyze)
    for fam in FAMILIES:
        assert report.sides["tuning"][fam].fp == 0
        assert report.sides["holdout"][fam].fp == 0


def test_clean_repo_violation_counted_once_with_visibility(tmp_path):
    corpus = _mini_corpus([_case("clean", expectation="clean")])
    root = _root_with(tmp_path, "solo-a")

    def analyze(path):
        return [
            _finding("SQL injection sink", ["injection"], ["sink at app.py:5"]),
            _finding("SQL injection sink", ["injection"], ["sink at app.py:9"], fid="other"),
        ]

    report = run_evaluation(corpus, root, analyze=analyze)
    fm = report.sides["holdout"]["injection"]
    assert fm.fp == 1 and fm.clean_repos == 1  # expectation unit: one clean repo, one FP
    case = next(r for r in report.results if r.case.case_id == "clean")
    assert len(case.clean_violations["injection"]) == 2  # both findings still visible


def test_missing_case_path_is_an_error_not_a_clean_pass(tmp_path):
    corpus = _mini_corpus([_case("ghost", path="no/such/dir", expectation="clean")])
    calls = []
    report = run_evaluation(corpus, tmp_path, analyze=lambda p: calls.append(p) or [])
    case = report.results[0]
    assert case.error and "not found" in case.error
    assert case.matched is None
    assert not calls, "analyzer must not run on a missing case path"


def test_scan_failure_is_recorded_not_raised(tmp_path):
    corpus = _mini_corpus([_case("boom")])
    root = _root_with(tmp_path, "solo-a")

    def boom(path):
        raise RuntimeError("scan exploded")

    report = run_evaluation(corpus, root, analyze=boom)
    assert report.results[0].error and "exploded" in report.results[0].error
    # the errored case contributes no samples
    assert report.sides["holdout"]["injection"].positives == 0
    assert "ERROR" in render_markdown(report)


# --- reports ------------------------------------------------------------------


def test_report_keeps_every_family_visible_even_unsampled_or_failing(tmp_path):
    # A corpus with only injection cases: crypto and friends must still appear
    # in markdown tables and JSON with zero samples and experimental status.
    corpus = _mini_corpus([_case("p1", route="/p1", line=1)])
    root = _root_with(tmp_path, "solo-a")
    report = run_evaluation(corpus, root, analyze=lambda p: [])
    md = render_markdown(report)
    payload = report_json(report)
    for family in FAMILIES:
        assert f"`{family}`" in md, f"{family} disappeared from the markdown report"
        for side in ("tuning", "holdout"):
            assert family in payload["sides"][side]
    assert payload["sides"]["holdout"]["injection"]["recall"] == 0.0


def test_report_json_records_split_counts_and_c27_gap(tmp_path):
    cases = [_case("p1", route="/p1", line=1),
             _case("n1", route="/n", line=9, expectation="negative"),
             _case("clean", repo="solo-b", path="solo-b", expectation="clean")]
    corpus = _mini_corpus(cases, seed=1, fraction=0.5)
    root = _root_with(tmp_path, "solo-a", "solo-b")
    report = run_evaluation(corpus, root, analyze=lambda p: [])
    payload = report_json(report)
    assert payload["corpus"]["positive_cases"] == 1
    assert payload["corpus"]["negative_cases"] == 1
    assert payload["corpus"]["clean_cases"] == 1
    assert payload["corpus"]["repositories"] == 2
    assert payload["split"]["seed"] == 1
    assert payload["split"]["holdout_repos"] == ["solo-b"]
    assert payload["split"]["tuning_repos"] == ["solo-a"]
    gap = payload["c27_gap"]
    assert gap["repositories_short"] == C27_TARGETS["repositories"] - 2
    assert gap["positive_cases_short"] == C27_TARGETS["positive_cases"] - 1
    assert payload["matching_unit"] and "expectation unit" in payload["matching_unit"]


def test_markdown_lists_sample_counts_and_experimental_status(tmp_path):
    corpus = _mini_corpus([_case("p1", route="/p1", line=1)])
    root = _root_with(tmp_path, "solo-a")
    report = run_evaluation(corpus, root, analyze=lambda p: [])
    md = render_markdown(report)
    assert "P/N/clean samples" in md
    assert "experimental" in md
    assert str(EXPERIMENTAL_MIN_PER_SIDE) in md  # threshold stated explicitly
    assert "## Tuning side" in md and "## Holdout side" in md


# --- shipped seed corpus (real analyzers, deterministic, offline) --------------


def test_shipped_seed_corpus_manifest_is_valid():
    corpus = load_corpus(SEED_MANIFEST)
    assert (len(corpus.cases), len(corpus.repositories)) == (28, 10)
    counts = {"positive": 0, "negative": 0, "clean": 0}
    for c in corpus.cases:
        counts[c.expectation] += 1
        assert c.rationale.strip()
    assert counts == {"positive": 17, "negative": 9, "clean": 2}
    for c in corpus.cases:
        if c.expectation != "clean":
            assert c.family in SCORED_CATEGORIES
    assert corpus.holdout_fraction >= 0.2


def test_shipped_seed_corpus_runs_end_to_end():
    corpus = load_corpus(SEED_MANIFEST)
    report = run_evaluation(corpus, REPO_ROOT)
    assert all(r.error is None for r in report.results), \
        [r.error for r in report.results if r.error]
    payload = report_json(report)
    # honest gap reporting: far below every C27 target, never silently met
    assert payload["c27_gap"]["repositories_short"] == 20
    assert payload["c27_gap"]["positive_cases_short"] == 283
    assert payload["c27_gap"]["negative_cases_short"] == 291
    assert payload["c27_gap"]["clean_repositories_short"] == 8
    # every family visible and experimental on both sides of the split
    for side in ("tuning", "holdout"):
        assert set(payload["sides"][side]) == set(FAMILIES)
        for fam in FAMILIES:
            assert payload["sides"][side][fam]["experimental"] is True
    md = render_markdown(report)
    for family in FAMILIES:
        assert f"`{family}`" in md
    # frozen split: 3 holdout repositories, recorded by name
    assert len(payload["split"]["holdout_repos"]) == 3
    assert len(payload["split"]["tuning_repos"]) == 7
