"""Actual installed python@1.0 merged auth projections, with role attribution."""
from pathlib import Path
import hashlib
import importlib.metadata
import inspect
import json

ROOT = Path(__file__).resolve().parents[5]
OUT = Path(__file__).resolve().parent


def main():
    from attackmap.analyzers import analyze_repository, get_registered_analyzers
    from attackmap.analyzer_profiles import resolve_analyzer_profile
    from attackmap.index import clear_pinned_index
    inventory = get_registered_analyzers()
    selection = resolve_analyzer_profile('python@1.0', [item.metadata for item in inventory])
    selected = [item for item in inventory if item.name in selection.module_names]
    assert {item.name for item in selected} == set(selection.module_names)
    review = json.loads((OUT / 'python-binding-independent-review-decorators.json').read_text())
    fixtures = {'constant-credential': ROOT / '.tmp/wp039-python-20261023/mount-independent/constant-credential'}
    for case in ['shadowed-known-route-decorator', 'foreign-custom-decorator-collision']:
        row = review['probes'][case]
        folder = ROOT / '.tmp/wp039-python-20261023/python-mounts-profile-fixtures' / case
        folder.mkdir(parents=True, exist_ok=True)
        for name, text in row['files'].items():
            path = folder / name
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.exists():
                assert path.read_bytes() == text.encode('utf-8')
            else:
                path.write_bytes(text.encode('utf-8'))
        fixtures[case] = folder
    fixtures['bound-wrapper-positive'] = ROOT / 'tests/fixtures/python-service-app'
    output = {'selection': selection.as_dict(),
              'installed': [{'name': item.name, 'priority': item.metadata.priority,
                             'source': inspect.getfile(type(item)),
                             'sha256': hashlib.sha256(Path(inspect.getfile(type(item))).read_bytes()).hexdigest()}
                            for item in selected], 'cases': {}}
    for case, folder in fixtures.items():
        roles = {}
        for analyzer in selected:
            clear_pinned_index()
            scan = analyzer.analyze(folder)
            roles[analyzer.name] = [route.model_dump(mode='json') for route in scan.routes]
        clear_pinned_index()
        scan = analyze_repository(folder, analyzers=selected, incremental=False)
        output['cases'][case] = {
            'fixture': str(folder),
            'sha256': {str(path.relative_to(folder)): hashlib.sha256(path.read_bytes()).hexdigest()
                       for path in sorted(folder.rglob('*.py'))},
            'roles': roles, 'merged_routes': [route.model_dump(mode='json') for route in scan.routes],
            'analyzer_errors': scan.analyzer_errors,
            'ledger': scan.analyzer_run_ledger.model_dump(mode='json') if scan.analyzer_run_ledger else None,
            'limitations': scan.limitations,
        }
    path = OUT / 'python-mounts-installed-profile.json'
    assert not path.exists()
    path.write_text(json.dumps(output, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({name: [(route['path'], route['auth']) for route in row['merged_routes']]
                      for name, row in output['cases'].items()}, indent=2))


if __name__ == '__main__':
    main()
