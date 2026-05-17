"""Tests for ScanData.get_url_metadata_map fallback branches and the
_process_http_endpoints / _add_endpoint_data_urls / _is_likely_http_port
helpers."""

from __future__ import annotations

import base64

from reverge_collector import data_model
from reverge_collector.data_model import RecordTag, ScanData
from reverge_collector.scan_utils import get_port_byte_array


def _scope(obj_list, port_list_str='80'):
    return {
        'b64_port_bitmap': base64.b64encode(get_port_byte_array(port_list_str)).decode(),
        'obj_list': obj_list,
    }


# ===========================================================================
# get_url_metadata_map: _process_http_endpoints (port w/ explicit endpoints)
# ===========================================================================


def test_url_metadata_for_explicit_http_endpoint_with_path():
    """A port with HttpEndpoint + ListItem path → URL ending in that path."""
    obj_list = [
        {
            'type': 'host',
            'id': 'h1',
            'data': {'ipv4_addr': '10.0.0.1'},
            'tags': [RecordTag.SCOPE.value],
        },
        {
            'type': 'port',
            'id': 'p1',
            'parent': {'type': 'host', 'id': 'h1'},
            'data': {'port': '443', 'proto': 0, 'secure': True},
            'tags': [RecordTag.SCOPE.value],
        },
        {
            'type': 'listitem',
            'id': 'path-admin',
            'data': {'path': '/admin', 'path_hash': 'h-admin'},
            'tags': [RecordTag.SCOPE.value],
        },
        {
            'type': 'httpendpoint',
            'id': 'ep1',
            'parent': {'type': 'port', 'id': 'p1'},
            'data': {'web_path_id': 'path-admin'},
            'tags': [RecordTag.SCOPE.value],
        },
        {
            'type': 'httpendpointdata',
            'id': 'epd1',
            'parent': {'type': 'httpendpoint', 'id': 'ep1'},
            'data': {'status': 200},
            'tags': [RecordTag.SCOPE.value],
        },
    ]
    sd = ScanData(_scope(obj_list, port_list_str='443'))
    out = sd.get_url_metadata_map()
    paths = {meta.get('path') for meta in out.values()}
    assert '/admin' in paths


def test_url_metadata_with_endpoint_data_domain():
    """HttpEndpointData carrying a domain_id → URL uses the domain name."""
    obj_list = [
        {
            'type': 'host',
            'id': 'h1',
            'data': {'ipv4_addr': '10.0.0.5'},
            'tags': [RecordTag.SCOPE.value],
        },
        {
            'type': 'port',
            'id': 'p1',
            'parent': {'type': 'host', 'id': 'h1'},
            'data': {'port': '443', 'proto': 0, 'secure': True},
            'tags': [RecordTag.SCOPE.value],
        },
        {
            'type': 'domain',
            'id': 'd1',
            'parent': {'type': 'host', 'id': 'h1'},
            'data': {'name': 'example.com'},
            'tags': [RecordTag.SCOPE.value],
        },
        {
            'type': 'listitem',
            'id': 'path-api',
            'data': {'path': '/api', 'path_hash': 'h-api'},
            'tags': [RecordTag.SCOPE.value],
        },
        {
            'type': 'httpendpoint',
            'id': 'ep1',
            'parent': {'type': 'port', 'id': 'p1'},
            'data': {'web_path_id': 'path-api'},
            'tags': [RecordTag.SCOPE.value],
        },
        {
            'type': 'httpendpointdata',
            'id': 'epd1',
            'parent': {'type': 'httpendpoint', 'id': 'ep1'},
            'data': {'status': 200, 'domain_id': 'd1'},
            'tags': [RecordTag.SCOPE.value],
        },
    ]
    sd = ScanData(_scope(obj_list, port_list_str='443'))
    out = sd.get_url_metadata_map()
    assert any('example.com' in url for url in out)


# ===========================================================================
# get_url_metadata_map: _process_likely_http_ports (no endpoints)
# ===========================================================================


def test_url_metadata_likely_http_port_8080():
    """Port 8080 is in the likely-HTTP allowlist → produces a URL even
    without HttpEndpoint records."""
    obj_list = [
        {
            'type': 'host',
            'id': 'h1',
            'data': {'ipv4_addr': '10.0.0.1'},
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
    sd = ScanData(_scope(obj_list, port_list_str='8080'))
    out = sd.get_url_metadata_map()
    assert any('10.0.0.1' in url for url in out)


def test_url_metadata_non_http_port_produces_no_urls():
    """Port 22 not in the likely-HTTP allowlist + no http component → no URL."""
    obj_list = [
        {
            'type': 'host',
            'id': 'h1',
            'data': {'ipv4_addr': '10.0.0.1'},
            'tags': [RecordTag.SCOPE.value],
        },
        {
            'type': 'port',
            'id': 'p1',
            'parent': {'type': 'host', 'id': 'h1'},
            'data': {'port': '22', 'proto': 0, 'secure': False},
            'tags': [RecordTag.SCOPE.value],
        },
    ]
    sd = ScanData(_scope(obj_list, port_list_str='22'))
    out = sd.get_url_metadata_map()
    assert out == {}


def test_url_metadata_http_component_marks_port_likely():
    """A Cpe whose name contains 'http' on a non-standard port → still
    marked as likely HTTP."""
    obj_list = [
        {
            'type': 'host',
            'id': 'h1',
            'data': {'ipv4_addr': '10.0.0.1'},
            'tags': [RecordTag.SCOPE.value],
        },
        {
            'type': 'port',
            'id': 'p1',
            'parent': {'type': 'host', 'id': 'h1'},
            'data': {'port': '9999', 'proto': 0, 'secure': False},
            'tags': [RecordTag.SCOPE.value],
        },
        {
            'type': 'cpe',
            'id': 'comp-nginx-http',
            'parent': {'type': 'port', 'id': 'p1'},
            'data': {'name': 'nginx-http', 'vendor': 'nginx', 'product': 'nginx-http'},
            'tags': [RecordTag.SCOPE.value],
        },
    ]
    sd = ScanData(_scope(obj_list, port_list_str='9999'))
    out = sd.get_url_metadata_map()
    assert any('10.0.0.1' in url for url in out)


def test_url_metadata_likely_port_with_domain_variant():
    """A port with no explicit endpoint but a domain on the host → URLs
    include both the IP form and the domain form."""
    obj_list = [
        {
            'type': 'host',
            'id': 'h1',
            'data': {'ipv4_addr': '10.0.0.1'},
            'tags': [RecordTag.SCOPE.value],
        },
        {
            'type': 'port',
            'id': 'p1',
            'parent': {'type': 'host', 'id': 'h1'},
            'data': {'port': '443', 'proto': 0, 'secure': True},
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
    sd = ScanData(_scope(obj_list, port_list_str='443'))
    out = sd.get_url_metadata_map()
    urls = list(out)
    assert any('10.0.0.1' in u for u in urls)
    assert any('example.com' in u for u in urls)


# ===========================================================================
# get_url_metadata_map: subnet-port fallback
# ===========================================================================


def test_url_metadata_subnet_fallback_expands_to_hosts():
    """No host data but subnet + port_list → expand subnet to candidate URLs."""
    obj_list = [
        {
            'type': 'subnet',
            'id': 's1',
            'data': {'subnet': '10.0.0.0', 'mask': 30},
            'tags': [RecordTag.SCOPE.value],
        },
    ]
    sd = ScanData(_scope(obj_list, port_list_str='80,443'))
    out = sd.get_url_metadata_map()
    # /30 → 2 usable hosts × 2 ports = 4 URLs
    assert len(out) >= 2
    # Both ports represented
    secure_flags = {meta['secure'] for meta in out.values()}
    assert secure_flags == {True, False}


def test_url_metadata_subnet_fallback_falls_back_to_port_map_when_no_port_list():
    """No b64_port_bitmap but ScanData has port records → use port_map for
    the port_str_list fallback."""
    obj_list = [
        {
            'type': 'host',
            'id': 'h1',
            'data': {'ipv4_addr': '10.0.0.5'},
            # LOCAL only — host won't show up in scope-tagged maps
            'tags': [RecordTag.LOCAL.value],
        },
        {
            'type': 'port',
            'id': 'p1',
            'parent': {'type': 'host', 'id': 'h1'},
            'data': {'port': '8080', 'proto': 0, 'secure': False},
            'tags': [RecordTag.LOCAL.value],
        },
        {
            'type': 'subnet',
            'id': 's1',
            'data': {'subnet': '10.0.0.0', 'mask': 30},
            'tags': [RecordTag.SCOPE.value],
        },
    ]
    # Empty port bitmap → fallback to port_map
    sd = ScanData({'b64_port_bitmap': '', 'obj_list': obj_list})
    out = sd.get_url_metadata_map()
    # Should have at least one URL from the subnet expansion
    assert len(out) >= 1


# ===========================================================================
# Cpe._component_name_key (used by ScanData index)
# ===========================================================================


def test_cpe_component_name_key_includes_version_when_set():
    from reverge_collector.data_model import Cpe, Port

    c = Cpe(parent_id='p1')
    c.product = 'nginx'
    c.version = '1.21.0'
    key = Cpe._component_name_key(c)
    # Key shape: (product[:version], parent_id)
    assert key == ('nginx:1.21.0', 'p1')


def test_cpe_component_name_key_no_version():
    from reverge_collector.data_model import Cpe

    c = Cpe(parent_id='p1')
    c.product = 'nginx'
    key = Cpe._component_name_key(c)
    assert key == ('nginx', 'p1')


def test_cpe_component_name_key_no_product_returns_none():
    from reverge_collector.data_model import Cpe

    c = Cpe(parent_id='p1')
    assert Cpe._component_name_key(c) is None
