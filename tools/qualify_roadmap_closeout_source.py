"""Physical corpus integration evidence; never representative production acceptance."""
from __future__ import annotations
import hashlib
import json
import os
import sys
import time
from pathlib import Path

import argparse
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--source-root', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
parser.add_argument('--installed-target', type=Path)
parser.add_argument('--installation-proof', type=Path)
parser.add_argument('--archive', type=Path)
parser.add_argument('--pipeline-worker', action='store_true')
args = parser.parse_args()
ROOT = args.source_root.resolve()
sys.path.insert(0, str(ROOT / "src"))
from attackmap.scan_service import ScanRequest, execute_scan_request

OUT = args.output.resolve()


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")


def declaration(**identity):
    return {"attackmap_datastores": {"schema_version": "1.0", "declarations": [{
        "identity": {"scope": "production-eu", "protocol": "postgresql",
                     "host": "db.example.internal", "port": 5432,
                     "namespace": "public", "resource": "orders", **identity},
        "operation": "read"}]}}


def run(paths, name, workers):
    start = time.perf_counter()
    errors = []
    def echo(message, **kwargs):
        if kwargs.get("err"):
            errors.append(str(message))
    request = ScanRequest(repo_paths=paths, output=OUT / name, output_format="json",
        modules=["config"], max_workers=workers, no_progress=True, echo=echo,
        llm=False, cve=False, install_missing=False, run_id=name)
    cached = OUT / f"{name}-info.json"
    if "--reuse" in sys.argv and cached.is_file():
        info = json.loads(cached.read_text())
        summary_path = OUT / info["summary"]
        duration = info["duration_seconds"]
        exit_code = info["exit_code"]
    else:
        result = execute_scan_request(request)
        if result.exit_code != 0:
            raise RuntimeError(f"{name} exited {result.exit_code}: {errors}")
        summary_path = result.fleet_summary_path
        duration = round(time.perf_counter()-start, 3)
        exit_code = result.exit_code
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    fleet_manifest = json.loads((summary_path.parent / "artifact-manifest.json").read_text())
    assert len(fleet_manifest["children"]) == len(paths)
    rows = []
    for child in fleet_manifest["children"]:
        path = summary_path.parent / child["path"] / "artifact-manifest.json"
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        assert digest == child["manifest_sha256"]
        manifest = json.loads(path.read_text())
        assert manifest["exit_state"]["status"] == "succeeded"
        for section in manifest["sections"]:
            section_path = path.parent / section["path"]
            assert hashlib.sha256(section_path.read_bytes()).hexdigest() == section["checksum"]
        rows.append({"path": str(path.relative_to(OUT)), "sha256": digest})
    return summary, {"exit_code": exit_code, "duration_seconds": duration,
                     "summary": str(summary_path.relative_to(OUT)), "manifests": rows,
                     "provider_enabled": False, "network_install_enabled": False}


def main():
    corpus = OUT / "physical-corpus"
    paths = [corpus / "team-a" / "service", corpus / "team-b" / "service"]
    paths += [corpus / f"repo-{i:02}" for i in range(2, 16)]
    for i, path in enumerate(paths):
        path.mkdir(parents=True, exist_ok=True)
        data = declaration()
        if i == 1:
            data["attackmap_datastores"]["declarations"][0]["operation"] = "write"
        elif 2 <= i <= 7:
            field, value = [("scope", "staging"), ("protocol", "mysql"),
                ("host", "other.example.internal"), ("port", 5433),
                ("namespace", "private"), ("resource", "users")][i-2]
            data = declaration(**{field: value})
        elif i == 8:
            data = {"DATABASE_URL": "postgresql://db.example.internal:5432/orders"}
        elif i == 9:
            data = declaration(host="db")
        elif i >= 10:
            data = {"library": "No qualified declarations"}
        write(path / "config.json", data)
        if i == 10:
            write(path / "tests" / "config.json", declaration())
        if i == 11:
            write(path / "examples" / "config.json", declaration())
    serial, serial_info = run(paths, "serial", 1)
    write(OUT / "serial-info.json", serial_info)
    parallel, parallel_info = run(paths, "parallel", 2)
    write(OUT / "parallel-info.json", parallel_info)
    left, right = serial["fleet_architecture"], parallel["fleet_architecture"]
    write(OUT / "serial-architecture.json", left)
    write(OUT / "parallel-architecture.json", right)
    assert serial["repo_count"] == parallel["repo_count"] == 16
    assert not serial["failed"] and not parallel["failed"]
    # These production fields are stable facts, independent of run generation.
    stable = ("nodes", "edges", "evidence", "shared_datastore_unresolved", "coverage", "limitations")
    differences = [key for key in stable if left[key] != right[key]]
    assert not differences, differences
    edges = [row for row in left["edges"] if row["kind"] == "shared_datastore"]
    assert len(edges) == 1 and edges[0]["resolution"] == "declared" and not edges[0]["directed"]
    assert len(edges[0]["evidence_refs"]) == 2
    node_ids = {row["id"] for row in left["nodes"]}
    evidence = {row["id"]: row for row in left["evidence"]}
    assert all(edge["source"] in node_ids and edge["target"] in node_ids for edge in left["edges"])
    assert all(ref in evidence for edge in left["edges"] for ref in edge["evidence_refs"])
    assert all(evidence[ref]["line"] == 5 for ref in edges[0]["evidence_refs"])
    juice = Path("C:/tmp/juice-shop")
    assert juice.is_dir()
    # Pair with an existing corpus child to exercise the real fleet runner.
    real, real_info = run([juice, paths[-1]], "juice-shop-negative", 1)
    real_edges = [row for row in real["fleet_architecture"]["edges"] if row["kind"] == "shared_datastore"]
    assert not real_edges
    write(OUT / "juice-shop-info.json", real_info)
    result = {"result": "PASS", "corpus_kind": "synthetic physical 16-repository corpus",
        "real_pipeline": True, "serial_parallel_fact_parity": True, "completed_children_per_run": 16,
        "qualified_declarations": left["coverage"]["protocols"]["shared_datastore"]["declaration_count"],
        "shared_datastore_edges": len(edges), "edge_resolution": "declared", "edge_directed": False,
        "both_endpoint_evidence": True, "source_line": 5, "juice_shop_completed": True,
        "corpus_repository_statuses": left["coverage"]["repository_statuses"],
        "juice_shop_shared_edges": len(real_edges), "provider_calls": 0,
        "representative_production_16repo_acceptance": False, "native_gui_acceptance": False,
        "serial": serial_info, "parallel": parallel_info, "juice_shop": real_info}
    write(OUT / "pipeline-result.json", result)
    print(json.dumps(result, indent=2))


def inventory(root):
    result = {str(p.relative_to(root)).replace('\\', '/'): hashlib.sha256(p.read_bytes()).hexdigest()
            for folder in ('src', 'tests', 'tools', 'schemas', 'installer')
            for p in sorted((root / folder).rglob('*'))
            if p.is_file() and '__pycache__' not in p.parts}
    for name in ('pyproject.toml', 'requirements.txt', 'pytest.ini', 'setup.cfg'):
        path = root / name
        if path.is_file():
            result[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def qualify():
    import subprocess
    import xml.etree.ElementTree as ET
    OUT.mkdir(parents=True, exist_ok=False)
    before = inventory(ROOT)
    write(OUT / 'source-before.json', before)
    target = args.installed_target.resolve()
    proof = json.loads(args.installation_proof.read_text(encoding='utf-8'))
    archive_digest = hashlib.sha256(args.archive.read_bytes()).hexdigest()
    assert archive_digest == proof['archive_sha256'] == '913c102365d5b9e4b902683edc022aa6a281cd4d77990f71abbddf6c0bccf536'
    assert proof['pin'] == '1bcce0dd5d639cb83ada65cc3f5024bb5a1d9782'
    assert proof['installed_source_identical']
    import zipfile
    with zipfile.ZipFile(args.archive) as archive:
        for name, digest in proof['source_hashes'].items():
            archived = archive.read('attackmap-analyzer-python-' + proof['pin'] + '/src/' + name)
            assert hashlib.sha256(archived).hexdigest() == digest
            assert (target / name).read_bytes() == archived
    target_before = inventory_target(target)
    write(OUT / 'installed-before.json', target_before)
    write(OUT / 'installation-proof.json', proof)
    base_env = dict(os.environ, PYTHONPATH=str(ROOT / 'src'), PYTHONDONTWRITEBYTECODE='1', PYTHONUTF8='1')
    for key in ('ATTACKMAP_INCREMENTAL', 'ATTACKMAP_INCLUDE_TESTS', 'ATTACKMAP_INCLUDE_VENDORED', 'WP039_PINNED_TARGET'):
        base_env.pop(key, None)
    checks = []
    def execute(name, command, environment, expected=None):
        started = time.monotonic()
        result = subprocess.run(command, cwd=ROOT, env=environment, capture_output=True, text=True, timeout=600)
        (OUT / (name + '.log')).write_text(result.stdout + result.stderr, encoding='utf-8')
        row = dict(name=name, command=command, exit_code=result.returncode, seconds=round(time.monotonic()-started,3))
        if expected is not None:
            suites = list(ET.parse(OUT / (name + '.xml')).getroot().iter('testsuite'))
            row['tests'] = sum(int(s.get('tests', 0)) for s in suites)
            row['skipped'] = sum(int(s.get('skipped', 0)) for s in suites)
            row['minimum_required_tests'] = expected
            assert row['tests'] >= expected and row['skipped'] == 0, row
        checks.append(row)
        write(OUT / 'commands.json', checks)
        assert result.returncode == 0, row
    affected = ['test_analyzer_host_origin', 'test_analyzer_host', 'test_analyzer_isolation', 'test_analyzer_run_ledger', 'test_ecosystem_python_plugin_routes', 'test_pipeline_analyzer_ledger', 'test_config_datastores', 'test_config_scanner', 'test_fleet_architecture', 'test_fleet_resource_identity', 'test_desktop_graph', 'test_fleet']
    def pytest_command(name, tests):
        return [sys.executable, '-B', '-m', 'pytest', *['tests/' + t + '.py' for t in tests], '-q', '-p', 'no:cacheprovider', '--basetemp', str(OUT / (name+'-temp')), '--junitxml', str(OUT / (name+'.xml'))]
    try:
        execute('affected', pytest_command('affected', affected), base_env, 320)
        installed_env = dict(base_env, PYTHONPATH=str(target)+os.pathsep+str(ROOT/'src'), WP039_PINNED_TARGET=str(target), WP039_EVIDENCE=str(OUT))
        execute('installed', pytest_command('installed', ['test_wp039_installed_python']), installed_env, 5)
        execute('pipeline', [sys.executable, '-B', str(Path(__file__).resolve()), '--source-root', str(ROOT), '--output', str(OUT/'wp044'), '--pipeline-worker'], base_env)
    finally:
        after = inventory(ROOT)
        write(OUT / 'source-after.json', after)
        target_after = inventory_target(target)
        write(OUT / 'installed-after.json', target_after)
        result = dict(passed=len(checks)==3 and all(r['exit_code']==0 for r in checks) and before==after and target_before==target_after,
            source_unchanged=before==after, installed_target_unchanged=target_before==target_after, checks=checks,
            source_root=str(ROOT), installed_target=str(target), provider_calls=0,
            scope='Final-source bounded WP039/WP044 qualification; not GUI, release or maturity acceptance',
            wp033_gap='Frozen installs lacking physical .py modules cannot prove engine_identity; scanner silently disables incremental cache. Equality alone does not prove warm cache reuse.')
        write(OUT / 'qualification.json', result)
    assert result['passed'], result


def inventory_target(root):
    return {str(p.relative_to(root)).replace('\\', '/'): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(root.rglob('*')) if p.is_file() and '__pycache__' not in p.parts}


if __name__ == '__main__':
    if args.pipeline_worker:
        main()
    else:
        qualify()
