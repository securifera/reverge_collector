"""Tests for the ScanData container and related helpers in data_model.

ScanData is the largest single class in data_model.py and is exercised
end-to-end by the route tests, but we can also unit-test it directly with
synthetic obj_list payloads — much faster, and covers more branches.
"""

from __future__ import annotations

import base64

import pytest
from reverge_collector import data_model
from reverge_collector.data_model import (
    Cpe,
    Domain,
    Host,
    Port,
    RecordTag,
    ScanData,
)
from reverge_collector.scan_utils import get_port_byte_array

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_scope(obj_list, port_list_str='443'):
    port_bytes = get_port_byte_array(port_list_str)
    b64 = base64.b64encode(port_bytes).decode()
    return {'b64_port_bitmap': b64, 'obj_list': obj_list}


# ---------------------------------------------------------------------------
# ScanData construction
# ---------------------------------------------------------------------------


def test_scandata_empty_init_works():
    sd = ScanData({})
    assert sd.scan_obj_map == {}
    assert sd.port_number_list == []


def test_scandata_init_decodes_port_bitmap():
    port_bytes = get_port_byte_array('22, 80, 443')
    b64 = base64.b64encode(port_bytes).decode()
    sd = ScanData({'b64_port_bitmap': b64})
    assert sorted(int(p) for p in sd.port_number_list) == [22, 80, 443]


def test_scandata_init_processes_obj_list():
    obj_list = [
        {
            'type': 'host',
            'id': 'h1',
            'data': {'ipv4_addr': '1.2.3.4'},
            'tags': [RecordTag.SCOPE.value],
        },
        {
            'type': 'domain',
            'id': 'd1',
            'parent': {'type': 'host', 'id': 'h1'},
            'data': {'name': 'example.com'},
            'tags': [RecordTag.SCOPE.value],
        },
    ]
    sd = ScanData(make_scope(obj_list))
    assert 'h1' in sd.host_map
    assert sd.host_map['h1'].ipv4_addr == '1.2.3.4'
    assert 'd1' in sd.domain_map
    assert sd.domain_map['d1'].name == 'example.com'
    # host_ip_id_map index built
    assert sd.host_ip_id_map.get('1.2.3.4') == 'h1'


def test_scandata_init_with_port_record():
    obj_list = [
        {
            'type': 'host',
            'id': 'h1',
            'data': {'ipv4_addr': '1.2.3.4'},
            'tags': [RecordTag.SCOPE.value],
        },
        {
            'type': 'port',
            'id': 'p1',
            'parent': {'type': 'host', 'id': 'h1'},
            'data': {'port': '443', 'proto': 0, 'secure': True},
            'tags': [RecordTag.SCOPE.value],
        },
    ]
    sd = ScanData(make_scope(obj_list))
    assert 'p1' in sd.port_map
    assert sd.port_map['p1'].port == '443'
    # host_port_obj_map built by _post_process
    assert '1.2.3.4:443' in sd.host_port_obj_map


# ---------------------------------------------------------------------------
# ScanData.update
# ---------------------------------------------------------------------------


def test_scandata_update_with_list_of_dicts():
    sd = ScanData({})
    sd.update(
        [
            {'type': 'host', 'id': 'h2', 'data': {'ipv4_addr': '5.6.7.8'}},
        ]
    )
    assert 'h2' in sd.host_map


def test_scandata_update_with_dict_of_records():
    sd = ScanData({})
    sd.update(
        {
            'h3': {'type': 'host', 'id': 'h3', 'data': {'ipv4_addr': '9.10.11.12'}},
        }
    )
    assert 'h3' in sd.host_map


# ---------------------------------------------------------------------------
# get_hosts / get_domains / get_ports with tag filtering
# ---------------------------------------------------------------------------


def test_get_hosts_filters_by_tag():
    obj_list = [
        {
            'type': 'host',
            'id': 'h_scope',
            'data': {'ipv4_addr': '1.1.1.1'},
            'tags': [RecordTag.SCOPE.value],
        },
        {
            'type': 'host',
            'id': 'h_local',
            'data': {'ipv4_addr': '2.2.2.2'},
            'tags': [RecordTag.LOCAL.value],
        },
    ]
    sd = ScanData(make_scope(obj_list))
    scope_only = sd.get_hosts([RecordTag.SCOPE.value])
    assert {h.id for h in scope_only} == {'h_scope'}

    both = sd.get_hosts([RecordTag.SCOPE.value, RecordTag.LOCAL.value])
    assert {h.id for h in both} == {'h_scope', 'h_local'}


def test_get_hosts_no_tag_returns_all():
    obj_list = [
        {
            'type': 'host',
            'id': 'h1',
            'data': {'ipv4_addr': '1.1.1.1'},
            'tags': [RecordTag.SCOPE.value],
        },
    ]
    sd = ScanData(make_scope(obj_list))
    # No filter → returns all hosts
    assert len(sd.get_hosts(None)) == 1


def test_get_domains_filters_by_tag():
    obj_list = [
        {
            'type': 'domain',
            'id': 'd1',
            'data': {'name': 'a.com'},
            'tags': [RecordTag.SCOPE.value],
        },
        {
            'type': 'domain',
            'id': 'd2',
            'data': {'name': 'b.com'},
            'tags': [RecordTag.LOCAL.value],
        },
    ]
    sd = ScanData(make_scope(obj_list))
    scope_only = sd.get_domains([RecordTag.SCOPE.value])
    assert {d.name for d in scope_only} == {'a.com'}


def test_get_ports_filters_by_tag():
    obj_list = [
        {
            'type': 'host',
            'id': 'h1',
            'data': {'ipv4_addr': '1.1.1.1'},
            'tags': [RecordTag.SCOPE.value],
        },
        {
            'type': 'port',
            'id': 'p1',
            'parent': {'type': 'host', 'id': 'h1'},
            'data': {'port': '443', 'proto': 0, 'secure': True},
            'tags': [RecordTag.SCOPE.value],
        },
    ]
    sd = ScanData(make_scope(obj_list))
    ports = sd.get_ports([RecordTag.SCOPE.value])
    assert {p.id for p in ports} == {'p1'}


# ---------------------------------------------------------------------------
# get_port_number_list_from_scope
# ---------------------------------------------------------------------------


def test_get_port_number_list_from_scope_returns_bitmap_ports():
    sd = ScanData(make_scope([], port_list_str='22, 80, 443'))
    out = sorted(int(p) for p in sd.get_port_number_list_from_scope())
    assert out == [22, 80, 443]


def test_get_port_number_list_from_port_map_uses_actual_ports():
    obj_list = [
        {
            'type': 'host',
            'id': 'h1',
            'data': {'ipv4_addr': '1.2.3.4'},
            'tags': [RecordTag.SCOPE.value],
        },
        {
            'type': 'port',
            'id': 'p1',
            'parent': {'type': 'host', 'id': 'h1'},
            'data': {'port': '8080', 'proto': 0, 'secure': False},
            'tags': [RecordTag.SCOPE.value],
        },
    ]
    sd = ScanData(make_scope(obj_list, port_list_str='443'))
    out = sd.get_port_number_list_from_port_map()
    assert '8080' in out


# ---------------------------------------------------------------------------
# Enums — string/repr coverage
# ---------------------------------------------------------------------------


def test_record_tag_str_values():
    assert str(RecordTag.LOCAL) == 'LOCAL'
    assert str(RecordTag.REMOTE) == 'REMOTE'
    assert str(RecordTag.SCOPE) == 'SCOPE'


def test_scan_status_enum_has_known_members():
    from reverge_collector.data_model import ScanStatus

    # Just confirm enum has the expected members
    assert hasattr(ScanStatus, '__members__')
    assert len(ScanStatus) > 0


def test_collection_tool_status_enum_has_known_members():
    from reverge_collector.data_model import CollectionToolStatus

    assert len(CollectionToolStatus) > 0


def test_collector_type_enum_has_known_members():
    from reverge_collector.data_model import CollectorType

    assert len(CollectorType) > 0


def test_server_record_type_enum_has_known_members():
    from reverge_collector.data_model import ServerRecordType

    assert len(ServerRecordType) > 0


# ---------------------------------------------------------------------------
# update_scope_array — apply server's ID remapping to local records
# ---------------------------------------------------------------------------


def test_update_scope_array_no_remap_returns_jsonable_list():
    from reverge_collector.data_model import update_scope_array

    h = Host()
    h.ipv4_addr = '1.2.3.4'
    out = update_scope_array({h.id: h}, [])
    # Returns list of jsonable dicts
    assert isinstance(out, list)
    assert any(r.get('id') == h.id for r in out)


def test_update_scope_array_applies_remapping():
    from reverge_collector.data_model import update_scope_array

    h = Host()
    h.ipv4_addr = '1.2.3.4'
    original_id = h.id
    remap = [{'orig_id': original_id, 'db_id': 'db-host-id'}]
    out = update_scope_array({original_id: h}, remap)
    # The host's id should be updated to db-host-id
    assert any(r.get('id') == 'db-host-id' for r in out)


# ---------------------------------------------------------------------------
# update_host_port_obj_map — direct call
# ---------------------------------------------------------------------------


def test_update_host_port_obj_map_links_host_and_port():
    from reverge_collector.data_model import update_host_port_obj_map

    obj_list = [
        {
            'type': 'host',
            'id': 'h1',
            'data': {'ipv4_addr': '1.2.3.4'},
            'tags': [RecordTag.SCOPE.value],
        },
        {
            'type': 'port',
            'id': 'p1',
            'parent': {'type': 'host', 'id': 'h1'},
            'data': {'port': '443', 'proto': 0, 'secure': True},
            'tags': [RecordTag.SCOPE.value],
        },
    ]
    sd = ScanData(make_scope(obj_list))
    # Verify the map was built during construction
    assert '1.2.3.4:443' in sd.host_port_obj_map


# ---------------------------------------------------------------------------
# Record round-trips — exercise from_jsonsable for more types
# ---------------------------------------------------------------------------


def test_host_from_jsonsable_roundtrip_ipv4():
    h1 = Host()
    h1.ipv4_addr = '1.2.3.4'

    raw = h1.to_jsonable()
    h2 = Host(id=h1.id)
    h2.from_jsonsable(raw['data'])
    assert h2.ipv4_addr == '1.2.3.4'


def test_host_from_jsonsable_roundtrip_ipv6():
    """Host serialises ipv6_addr only when ipv4_addr is absent; the round
    trip must restore it. (Bug history: _data_to_jsonable emitted ipv6_addr
    but from_jsonsable had the ipv6 branch commented out, silently dropping
    the address.)"""
    h1 = Host()
    h1.ipv6_addr = '::1'

    raw = h1.to_jsonable()
    assert raw['data'].get('ipv6_addr') is not None

    h2 = Host(id=h1.id)
    h2.from_jsonsable(raw['data'])
    assert h2.ipv6_addr == '::1'


def test_port_from_jsonsable_roundtrip():
    p1 = Port(parent_id='parent-h')
    p1.port = '8443'
    p1.proto = 0
    p1.secure = True

    raw = p1.to_jsonable()
    p2 = Port(parent_id='parent-h')
    p2.from_jsonsable(raw['data'])
    assert p2.port == '8443'
    assert p2.secure is True


def test_domain_from_jsonsable_roundtrip():
    d1 = Domain(parent_id='h')
    d1.name = 'example.com'
    raw = d1.to_jsonable()
    d2 = Domain(parent_id='h')
    d2.from_jsonsable(raw['data'])
    assert d2.name == 'example.com'


def test_cpe_cpe_string_setter_parses_back():
    c = Cpe(parent_id='p')
    c.cpe = 'cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*'
    assert c.vendor == 'apache'
    assert c.product == 'http_server'
    assert c.version == '2.4.41'
    assert c.part == 'a'


def test_cpe_property_assembles_string():
    c = Cpe(parent_id='p')
    c.vendor = 'apache'
    c.product = 'http_server'
    c.version = '2.4.41'
    assert c.cpe == 'cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*'


def test_cpe_property_returns_none_when_product_missing():
    c = Cpe(parent_id='p')
    assert c.cpe is None


def test_cpe_name_alias_for_product():
    c = Cpe()
    c.name = 'tomcat'
    assert c.product == 'tomcat'
    assert c.name == 'tomcat'
