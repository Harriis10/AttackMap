"""Actual CLI/SARIF version gate on one physical offline config fixture."""
from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path

from verify_wp018_closeout import ROOT, launch, production_inputs, read, require, save, sha
from attackmap.artifact_publisher import current_generation, validate_generation

ARTIFACTS = ROOT / "artifacts/wp022-sarif-version-20261107"
FIXTURE = ARTIFACTS / "fixture"
CONFIG = "database:\n  url: postgresql://synthetic_user:wp022SyntheticOnlyPassword@db.example.invalid:5432/sample\nauth:\n  api_key: wp022SyntheticOnlyKey1234567890\n"


def expected_version():
    tree = ast.parse((ROOT / "src/attackmap/__init__.py").read_text(encoding="utf-8"))
    values = [node.value.value for node in tree.body if isinstance(node, ast.Assign)
              and any(isinstance(target, ast.Name) and target.id == "__version__" for target in node.targets)
              and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)]
    require(len(values) == 1 and values[0] not in ("", "0.0.0-dev"), "Require exact canonical version literal")
    return values[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    engine = parser.add_mutually_exclusive_group(required=True)
    engine.add_argument("--python", type=Path)
    engine.add_argument("--engine", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve(); output.mkdir(parents=True, exist_ok=False)
    FIXTURE.mkdir(parents=True, exist_ok=True)
    fixture_file = FIXTURE / "config.yaml"
    if fixture_file.exists():
        require(fixture_file.read_text(encoding="utf-8") == CONFIG, "Shared fixture changed")
    else:
        fixture_file.write_text(CONFIG, encoding="utf-8")
    require(list(FIXTURE.iterdir()) == [fixture_file], "Unexpected physical fixture input")
    executable = (args.engine or args.python).resolve(strict=True)
    identity = {"path": str(executable), "sha256": sha(executable), "kind": "Frozen" if args.engine else "SourcePython"}
    version = expected_version()
    before = {"production": production_inputs(), "spec_sha256": sha(ROOT / "installer/attackmap.spec"),
              "fixture_sha256": sha(fixture_file), "fixture_root": str(FIXTURE.resolve()), "engine": identity,
              "verifier_sha256": sha(Path(__file__)), "expected_version": version, "modules": ["config"]}
    save(output / "inputs-before.json", before)
    result = {"passed": False, "scope": "Actual offline CLI/SARIF version only; no whole WP022/export UI or bundled-distribution-metadata acceptance", "engine": identity}
    try:
        prefix = [str(executable)] if args.engine else [str(executable), "-m", "attackmap"]
        version_dir = output / "version"; version_dir.mkdir()
        launch([*prefix, "--version"], version_dir, 60)
        raw_version = (version_dir / "stdout.jsonl").read_text(encoding="utf-8").strip()
        require(raw_version == "attackmap " + version, "CLI version differs from canonical running-code authority")
        scan = output / "scan"; scan.mkdir()
        argv = [*prefix, "analyze", str(FIXTURE.resolve()), "--module", "config", "--format", "all", "--output", str(scan / "reports")]
        save(scan / "command.json", argv)
        launch(argv, scan, 180)
        generation = current_generation(scan / "reports")
        require(generation is not None, "No valid published generation")
        manifest = validate_generation(generation)
        require(Path(manifest["run_identity"]["repo_root"]).resolve() == FIXTURE.resolve(), "Manifest root differs")
        report = read(generation / "attackmap-report.json")
        require(Path(report["scan"]["root"]).resolve() == FIXTURE.resolve() and report["findings"], "Require nonempty actual fixture findings")
        sarif_paths = list(generation.glob("*.sarif"))
        require(len(sarif_paths) == 1, "Require one actual SARIF export")
        sarif = read(sarif_paths[0])
        require(sarif["version"] == "2.1.0" and len(sarif["runs"]) == 1, "Unexpected SARIF envelope")
        run = sarif["runs"][0]
        require(run["tool"]["driver"]["name"] == "AttackMap" and run["tool"]["driver"]["version"] == version,
                "Actual SARIF driver.version differs from exact CLI/canonical version")
        require(run["results"] and run["tool"]["driver"]["rules"], "Version proof must include actual nonempty finding emission")
        after = {"production": production_inputs(), "spec_sha256": sha(ROOT / "installer/attackmap.spec"),
                 "fixture_sha256": sha(fixture_file), "engine_sha256": sha(executable), "verifier_sha256": sha(Path(__file__))}
        save(output / "inputs-after.json", after)
        require(before["production"] == after["production"] and before["spec_sha256"] == after["spec_sha256"]
                and before["fixture_sha256"] == after["fixture_sha256"] and identity["sha256"] == after["engine_sha256"]
                and before["verifier_sha256"] == after["verifier_sha256"], "Qualification inputs changed")
        result.update(passed=True, expected_version=version, actual_cli_version=raw_version,
            actual_sarif_driver_version=run["tool"]["driver"]["version"], sarif_path=str(sarif_paths[0]), sarif_sha256=sha(sarif_paths[0]),
            report_path=str(generation / "attackmap-report.json"), manifest_path=str(generation / "artifact-manifest.json"),
            manifest_sha256=sha(generation / "artifact-manifest.json"), findings=len(report["findings"]), sarif_results=len(run["results"]),
            inputs_unchanged=True, version_normalization_performed=False)
    except Exception as error:
        result["error"] = str(error)
    save(output / "verification.json", result)
    print(json.dumps(result, indent=2))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
