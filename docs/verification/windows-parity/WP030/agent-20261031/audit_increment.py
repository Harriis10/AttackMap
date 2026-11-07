"""Fail-closed offline source/label/split audit for one frozen WP030 increment.

No detector is called. Human label adjudication and unseen-benchmark claims are
deliberately outside this integrity audit.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from hashlib import sha1, sha256
import json
from pathlib import Path
import re
import sys

import jsonschema

ROOT = Path(__file__).resolve().parents[5]
BASE_RELATIVE = Path("fixtures/evaluation/increment-20261031")
sys.path.insert(0, str(ROOT / "src"))
from attackmap.evaluation import load_corpus, split_corpus


class AuditError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AuditError(message)


def contained(base: Path, relative: str) -> Path:
    require(not Path(relative).is_absolute() and ".." not in relative.replace("\\", "/").split("/"),
            f"unsafe relative path: {relative}")
    target = base / relative
    require(target.resolve().is_relative_to(base.resolve()), f"path escape: {relative}")
    require(not target.is_symlink(), f"symlink source: {relative}")
    return target


def normalized_hash(data: bytes) -> str:
    return sha256(re.sub(r"\s+", " ", data.decode("utf-8")).strip().encode()).hexdigest()


def audit(root: Path = ROOT) -> dict:
    root = root.resolve()
    base = root / BASE_RELATIVE
    raw = {name: json.loads((base / f"{filename}.json").read_text(encoding="utf-8"))
           for name, filename in (("corpus", "corpus"), ("provenance", "provenance"), ("freeze", "freeze"))}
    schema = json.loads((base / "bundle.schema.json").read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.Draft202012Validator(schema).validate(raw)
    corpus = load_corpus(base / "corpus.json")
    baseline_path = root / "fixtures/evaluation/corpus.json"
    baseline = load_corpus(baseline_path)
    freeze = raw["freeze"]
    for key, file in (("manifest_sha256", base / "corpus.json"),
                      ("provenance_sha256", base / "provenance.json"),
                      ("baseline_manifest_sha256", baseline_path)):
        require(sha256(file.read_bytes()).hexdigest() == freeze[key], f"frozen hash mismatch: {key}")
    tuning, held, split = split_corpus(corpus)
    require(split.seed == freeze["split_seed"] and split.holdout_fraction == freeze["holdout_fraction"],
            "frozen split settings changed")
    require(list(split.tuning_repos) == freeze["tuning_repositories"] and
            list(split.holdout_repos) == freeze["holdout_repositories"], "frozen membership changed")
    require(set(split.tuning_repos).isdisjoint(split.holdout_repos), "repository split leakage")
    require(len(split.holdout_repos) / len(corpus.repositories) >= .2, "holdout below 20 percent")
    require(not set(baseline.repositories).intersection(corpus.repositories), "baseline repository identity reused")
    require(not {c.case_id for c in baseline.cases}.intersection(c.case_id for c in corpus.cases),
            "baseline case id reused")
    sources = raw["provenance"]["sources"]
    source_of = {s["source_id"]: s for s in sources}
    require(len(source_of) == len(sources), "duplicate provenance source_id")
    require(len({s["path"].casefold() for s in sources}) == len(sources), "repository aliases share a source path")
    require(len({str(contained(root, s["path"]).resolve()).casefold() for s in sources}) == len(sources),
            "repository aliases resolve to one source path")
    require(len({s["repository"] for s in sources}) == len(sources), "duplicate provenance repository")
    require({s["repository"] for s in sources} == set(corpus.repositories), "source coverage mismatch")
    lineage_sides = defaultdict(set)
    code_hashes = defaultdict(list)
    tree_hashes = defaultdict(list)
    file_count = 0
    for src in sources:
        side = "holdout" if src["repository"] in split.holdout_repos else "tuning"
        lineage_sides[src["lineage"]].add(side)
        tree = contained(root, src["path"])
        require(tree.is_dir(), f"source repository absent: {src['repository']}")
        inventory = {entry["file"]: entry for entry in src["files"]}
        require(len(inventory) == len(src["files"]), "duplicate file inventory entry")
        physical = {p.relative_to(tree).as_posix() for p in tree.rglob("*") if p.is_file()}
        require(physical == set(inventory), f"untracked or missing snapshot files: {src['repository']}")
        require(set(src["license_evidence"]) <= inventory.keys(), "license evidence absent from inventory")
        license_text = "\n".join(contained(tree, p).read_text(encoding="utf-8") for p in src["license_evidence"])
        if src["license"] == "MIT":
            require("Permission is hereby granted, free of charge" in license_text, "MIT license evidence mismatch")
        else:
            require("either version 3 of the License" in license_text and "any later version" in license_text,
                    "GPL-3.0-or-later license evidence mismatch")
        if src["kind"] != "synthetic":
            require(src["lineage"] == src["source_url"].removesuffix(".git"), "upstream lineage/URL mismatch")
            require(src["origin"].removesuffix(".git") == src["source_url"], "upstream origin/URL mismatch")
        for name, entry in inventory.items():
            path = contained(tree, name)
            require(path.is_file(), f"missing source: {name}")
            data = path.read_bytes()
            file_count += 1
            require(sha256(data).hexdigest() == entry["sha256"], f"source hash mismatch: {name}")
            if src["kind"] != "synthetic":
                blob = sha1(f"blob {len(data)}\0".encode() + data).hexdigest()
                require(blob == entry["git_blob"], f"git blob mismatch: {name}")
                require(entry["source_url"] == f"{src['source_url']}/blob/{src['source_revision']}/{name}",
                        f"source URL/revision mismatch: {name}")
            if path.suffix in {".py", ".js", ".ts", ".php"}:
                code_hashes[normalized_hash(data)].append({"repository": src["repository"], "file": name, "side": side})
        tree_entries = sorted((entry["file"], entry["sha256"]) for entry in src["files"])
        tree_hashes[sha256(json.dumps(tree_entries).encode()).hexdigest()].append(src["repository"])
    require(all(len(sides) == 1 for sides in lineage_sides.values()), "upstream lineage split leakage")
    cross_duplicates = [v for v in code_hashes.values() if len({p["side"] for p in v}) > 1]
    require(not cross_duplicates, "exact or whitespace-normalized code duplication across split")
    require(all(len(v) == 1 for v in tree_hashes.values()), "duplicate repository trees")
    baseline_duplicates = []
    seen_baseline_files = set()
    for case in baseline.cases:
        tree = contained(root, case.path)
        require(tree.is_dir(), f"baseline repository absent: {case.repository}")
        for path in tree.rglob("*"):
            if not path.is_file() or path.suffix not in {".py", ".js", ".ts", ".php"} or path in seen_baseline_files:
                continue
            seen_baseline_files.add(path)
            digest = normalized_hash(path.read_bytes())
            if digest in code_hashes:
                baseline_duplicates.append({"baseline_file": path.relative_to(root).as_posix(), "increment": code_hashes[digest]})
    require(not baseline_duplicates, "code duplicated from the baseline corpus")
    anchors = set()
    families = defaultdict(Counter)
    for label in raw["corpus"]["cases"]:
        src = source_of.get(label["source_id"])
        require(src is not None, f"unknown source_id: {label['case_id']}")
        require((label["repository"], label["path"]) == (src["repository"], src["path"]),
                f"label source mapping mismatch: {label['case_id']}")
        families[label.get("family", "clean")][label["expectation"]] += 1
        if label["expectation"] == "clean":
            require(sum(c["repository"] == label["repository"] for c in raw["corpus"]["cases"]) == 1,
                    "clean repository has contradictory extra labels")
            continue
        key = tuple(label.get(k) for k in ("repository", "family", "file", "line", "route", "method"))
        require(key not in anchors, f"duplicate same-family entity: {label['case_id']}")
        anchors.add(key)
        require(any(a["file"] == label["file"] and a["line"] == label["line"] for a in label["source_anchors"]),
                f"primary entity not anchored: {label['case_id']}")
        for anchor in label["source_anchors"]:
            require(anchor["file"] in {f["file"] for f in src["files"]}, "anchor file not in source inventory")
            lines = contained(root / src["path"], anchor["file"]).read_text(encoding="utf-8").splitlines()
            text = lines[anchor["line"] - 1].strip() if anchor["line"] <= len(lines) else ""
            require(bool(text) and sha256(text.encode()).hexdigest() == anchor["text_sha256"],
                    f"source anchor mismatch: {label['case_id']}")
    counts = Counter(c.expectation for c in corpus.cases)
    baseline_counts = Counter(c.expectation for c in baseline.cases)
    total = baseline_counts + counts
    return {"integrity_audit": "PASS", "detector_calls": 0, "provider_calls": 0,
            "scope": "Frozen increment integrity and source-linked machine-authored labels; not independent human adjudication or C27 acceptance",
            "increment": {"repositories": len(corpus.repositories), "expectations": len(corpus.cases), "counts": dict(counts),
                          "source_files": file_count, "families": {k: dict(v) for k, v in sorted(families.items())}},
            "split": {"seed": split.seed, "holdout_fraction": split.holdout_fraction,
                      "tuning_repositories": list(split.tuning_repos), "holdout_repositories": list(split.holdout_repos),
                      "tuning_expectations": len(tuning), "holdout_expectations": len(held),
                      "actual_holdout_ratio": len(split.holdout_repos) / len(corpus.repositories)},
            "checks": {"json_schema": "PASS", "frozen_manifest_provenance_and_baseline_hashes": "PASS",
                       "source_hashes_git_blobs_and_line_anchors": "PASS", "repository_and_lineage_disjointness": "PASS",
                       "complete_source_inventory_and_licenses": "PASS", "duplicate_same_family_entities": "PASS",
                       "cross_split_normalized_code_duplicates": cross_duplicates, "baseline_code_duplicates": baseline_duplicates},
            "combined_arithmetic_inventory_only": {"repositories": len(baseline.repositories) + len(corpus.repositories),
                "expectations": len(baseline.cases) + len(corpus.cases), "counts": dict(total),
                "numeric_deficits": {"repositories": max(0, 30 - len(baseline.repositories) - len(corpus.repositories)),
                                     "positive": max(0, 300 - total["positive"]), "negative": max(0, 300 - total["negative"]),
                                     "clean": max(0, 10 - total["clean"])}},
            "independent_human_review": "PENDING", "c27_accepted": False,
            "limits": raw["provenance"]["limitations"] + [
                "Exact and whitespace-normalized hashes cannot establish semantic independence or absence of unrecorded shared lineage",
                "Freeze is reproducible integrity evidence, not a cryptographically attested historical timestamp",
                "Combined counts are logical source-slice identities, not 16 accepted independently reviewed production repositories"]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = audit(args.root)
    serialized = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(serialized, encoding="utf-8", newline="\n")
    print(serialized)
