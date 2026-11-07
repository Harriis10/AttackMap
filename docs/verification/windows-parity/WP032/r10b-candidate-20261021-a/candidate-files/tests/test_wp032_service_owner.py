import itertools

import pytest

from attackmap.models import AuthHint, DatabaseHint, ExternalCall, ProtocolHint, Route, ScanResult, ServiceHint
from attackmap.topology import build_service_graph, explicit_file_service_owners, file_service_owner, _file_service_map, _service_owning_file
from attackmap.threat_model import _build_service_chains, _build_atproto_chains, _file_service_map as threat_map

FILE = 'services/layout/app.py'


def scan(names, target='https://peer.internal/users'):
    return ScanResult(root='.',
        service_hints=[ServiceHint(hint='service_name:'+name, file=FILE) for name in names],
        auth_hints=[AuthHint(hint='service_role:privileged', file=FILE)],
        routes=[Route(method='POST', path='/xrpc/com.atproto.repo.createRecord', file=FILE)],
        databases=[DatabaseHint(kind='postgresql', file=FILE)],
        external_calls=[ExternalCall(target=target, file=FILE)],
        protocol_hints=[ProtocolHint(hint='atproto_namespace:com.atproto', file=FILE)])


@pytest.mark.parametrize('names', list(itertools.permutations(['alpha', 'beta', 'alpha'])))
@pytest.mark.parametrize('target', ['https://peer.internal/users', 'env://PEER_URL', 'queue://kafka/events'])
def test_conflicting_explicit_names_block_derived_edges_roles_layout_and_chains(names, target):
    value=scan(names,target)
    owners=explicit_file_service_owners((name,FILE) for name in names)
    assert file_service_owner(FILE,owners).state == 'ambiguous'
    assert file_service_owner(FILE,owners).names == ('alpha','beta')
    assert _service_owning_file(FILE,_file_service_map(value)) is None
    assert threat_map(value)[FILE] is None
    graph=build_service_graph(value)
    assert graph.edges == []
    assert graph.node_names() == {'alpha','beta'}
    assert all(node.role == 'service' for node in graph.nodes)
    assert _build_service_chains(value) == []
    assert _build_atproto_chains(value) == []


@pytest.mark.parametrize('names', [('alpha',), ('alpha','alpha'), ('Auth','auth')])
def test_unique_explicit_owner_overrides_layout_and_same_name_duplicates(names):
    value=scan(names)
    expected=names[0].lower()
    graph=build_service_graph(value)
    assert {(edge.source,edge.target) for edge in graph.edges} == {(expected,'peer')}
    assert 'layout' not in graph.node_names()
    assert next(node for node in graph.nodes if node.name==expected).role=='privileged'
    assert threat_map(value)[FILE]==expected
    assert _build_service_chains(value)[0].entry_service==expected
    assert _build_atproto_chains(value)[0].entry_service==expected


def test_only_absent_explicit_owner_uses_existing_layout():
    value=scan([])
    owners=explicit_file_service_owners([])
    assert file_service_owner(FILE,owners).state=='absent'
    assert _service_owning_file(FILE,_file_service_map(value))=='layout'
    assert threat_map(value)[FILE]=='layout'


def test_atproto_note_cannot_revive_explicit_ambiguity():
    value=scan(['alpha','beta'])
    value.protocol_hints.append(ProtocolHint(hint='atproto_service_note:revived',file=FILE))
    value.auth_hints.append(AuthHint(hint='atproto_service_note:revived',file=FILE))
    assert _build_atproto_chains(value)==[]


def test_ambiguous_sink_is_not_assigned_to_unique_route_owner():
    value=scan(['alpha','beta'])
    route_file='services/entry/route.py'
    value.routes[0].file=route_file
    value.service_hints.append(ServiceHint(hint='service_name:entry',file=route_file))
    chains=_build_service_chains(value)
    assert len(chains)==1
    assert not any('database sink in service' in item for item in chains[0].evidence)
    assert any('elsewhere in repo' in item for item in chains[0].evidence)


def test_owner_collector_does_not_strip_names_or_normalize_paths():
    owners=explicit_file_service_owners([('Auth', 'x\\app.py'), ('auth ', 'x\\app.py')])
    assert file_service_owner('x\\app.py',owners).names==('auth','auth ')
    assert file_service_owner('x/app.py',owners).state=='absent'
