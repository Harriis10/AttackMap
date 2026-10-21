"""Unknown auth evidence and complete hostname labels remain distinct."""

import itertools

import pytest

from attackmap.crossrepo import find_cross_repo_anomalies
from attackmap.models import ExternalCall, Route, ScanResult, ServiceHint
from attackmap.topology import _service_from_url, build_service_graph


def cohort(values):
    repos, auth = [], {}
    for name, flags in values.items():
        routes = [Route(method='GET', path=f'/users/{{id{i}}}', file=f'{i}.py') for i in range(len(flags))]
        repos.append((name, ScanResult(root=name, routes=routes)))
        auth[name] = {(route.file, route.method, route.path): flag for route, flag in zip(routes, flags) if flag is not None}
    return repos, auth


@pytest.mark.parametrize('flags', [[None], [True, None], [False, None]])
def test_incomplete_repo_neither_omits_nor_enforces(flags):
    repos, auth = cohort({'a': [True], 'b': [True], 'unknown': flags})
    assert find_cross_repo_anomalies(repos, auth) == []


@pytest.mark.parametrize('unknown_flags', [[None], [True, None], [False, None]])
def test_unknown_repo_does_not_supply_enforcing_majority(unknown_flags):
    repos, auth = cohort({'a': [True], 'unknown': unknown_flags, 'omits': [False]})
    assert find_cross_repo_anomalies(repos, auth) == []


@pytest.mark.parametrize('invalid', ['false', 'true', 1, 0, [], {}, [True]])
def test_non_boolean_auth_cannot_establish_enforcement_or_omission(invalid):
    repos, auth = cohort({'a': [True], 'b': [True], 'invalid': [invalid]})
    assert find_cross_repo_anomalies(repos, auth) == []
    repos, auth = cohort({'a': [True], 'omits': [False], 'invalid': [invalid]})
    assert find_cross_repo_anomalies(repos, auth) == []


def test_exact_false_remains_a_known_omission():
    repos, auth = cohort({'a': [True], 'b': [True], 'omits': [False]})
    assert [item.repo for item in find_cross_repo_anomalies(repos, auth)] == ['omits']


@pytest.mark.parametrize('order', list(itertools.permutations(['a', 'b', 'omits', 'unknown'])))
def test_complete_cohort_still_flags_known_omission_independent_of_unknown(order):
    values = {'a': [True], 'b': [True], 'omits': [False], 'unknown': [None]}
    repos, auth = cohort({name: values[name] for name in order})
    anomalies = find_cross_repo_anomalies(repos, auth)
    assert [(a.repo, a.peers) for a in anomalies] == [('omits', ('a', 'b'))]


@pytest.mark.parametrize('url,expected', [
    ('https://AUTH-API.internal:8443/users', 'auth-api'),
    ('http://auth-worker.internal/users', 'auth-worker'),
    ('http://worker.internal/users', 'worker'),
    ('http://localhost:1234/users', 'local-service'),
    ('http://127.0.0.1:1234/users', 'local-service'),
    ('not-a-url', None),
])
def test_complete_dns_label_and_existing_special_cases(url, expected):
    assert _service_from_url(url) == expected


def test_distinct_hyphenated_peer_edges_do_not_collapse_to_auth():
    file = 'services/frontend/app.py'
    scan = ScanResult(root='.', service_hints=[ServiceHint(hint='service_name:frontend', file=file)],
                      external_calls=[ExternalCall(target=f'https://{host}.internal/users', file=file)
                                      for host in ['auth-api', 'auth-worker']])
    graph = build_service_graph(scan)
    edges = [edge for edge in graph.edges if edge.kind == 'http-call']
    assert {(edge.source, edge.target) for edge in edges} == {('frontend', 'auth-api'), ('frontend', 'auth-worker')}
    assert all(edge.target != 'auth' for edge in edges)
